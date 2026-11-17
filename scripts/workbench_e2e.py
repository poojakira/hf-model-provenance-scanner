"""Real Chromium upload/compare/export/retry and stale-selection acceptance."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import TimeoutError as BrowserTimeout
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    port = 8763
    root = Path(__file__).resolve().parents[1]
    log = (evidence / "server.log").open("w")
    process = subprocess.Popen(
        [sys.executable, "-m", "scanner.workbench.server", "--port", str(port)],
        cwd=root,
        stdout=log,
        stderr=log,
    )
    try:
        for _ in range(80):
            if process.poll() is not None:
                raise RuntimeError("Server exited; inspect server.log")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/health", timeout=1
                ) as response:
                    health = json.load(response)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Server startup deadline")
        (evidence / "health.json").write_text(
            json.dumps({key: health[key] for key in ("status", "source", "limits")}, indent=2)
        )
        assert health["csrf_token"] not in (evidence / "health.json").read_text()
        with (
            tempfile.TemporaryDirectory(prefix="hf-browser-") as temporary,
            sync_playwright() as playwright,
        ):
            first, second = Path(temporary) / "synthetic-a.py", Path(temporary) / "synthetic-b.py"
            first.write_text("# SYNTHETIC benign source\nweights = [1, 2]\n")
            second.write_text("""# SYNTHETIC suspicious source; never executed
import os
os.system("echo synthetic")
""")
            browser = playwright.chromium.launch(
                executable_path=os.environ.get("HF_BROWSER_EXECUTABLE"),
                headless=True,
                args=["--no-sandbox"],
            )
            context = browser.new_context(
                viewport={"width": 1440, "height": 1100}, accept_downloads=True
            )
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{port}")
            expect(page.locator("#version")).to_contain_text("Engine 0.3.0")
            page.screenshot(path=str(evidence / "desktop.png"), full_page=True)
            page.locator("#first").set_input_files(first)
            page.locator("#second").set_input_files(second)
            page.get_by_role("button", name="Inspect files").click()
            expect(page.locator("#status")).to_contain_text("Completed", timeout=15000)
            expect(page.locator("#files")).to_contain_text("HFS-001")
            expect(page.locator("#files")).to_contain_text(
                hashlib.sha256(second.read_bytes()).hexdigest()
            )
            expect(page.locator("#comparison")).to_contain_text('"bytes_equal": false')
            expect(page.locator("#results-title")).to_be_focused()
            assert page.locator("#first").get_attribute("id") == page.locator(
                "label[for=first]"
            ).get_attribute("for")
            with page.expect_download() as downloaded:
                page.get_by_role("button", name="Download report").click()
            downloaded.value.save_as(str(evidence / "download.json"))
            # Browser JSON.stringify formatting is the canonical report checksum input.
            bundle = json.loads((evidence / "download.json").read_text())
            canonical = page.evaluate(
                "JSON.stringify(JSON.parse(document.getElementById('report').textContent),null,2)"
            )
            assert (
                hashlib.sha256(canonical.encode()).hexdigest()
                == bundle["manifest"]["report_sha256"]
            )
            assert (
                bundle["report"]["input_manifest"][1]["sha256"]
                == hashlib.sha256(second.read_bytes()).hexdigest()
            )
            page.screenshot(path=str(evidence / "desktop-results.png"), full_page=True)
            # Delay only checksum completion; actual engines still process both reviews.
            page.evaluate(
                """() => {window.originalDigest=crypto.subtle.digest.bind(crypto.subtle);
                crypto.subtle.digest=async function(...args){
                  document.body.dataset.pendingDigest='yes';
                  await new Promise(resolve=>window.releaseDigest=resolve);
                  return window.originalDigest(...args);
                };}"""
            )
            page.locator("#download").click()
            expect(page.locator("body")).to_have_attribute("data-pending-digest", "yes")
            second = Path(temporary) / "synthetic-edited.py"
            second.write_text("# SYNTHETIC edited source\nweights = [1, 2]\n")
            page.locator("#second").set_input_files(second)
            expect(page.locator("#output")).to_be_hidden()
            page.get_by_role("button", name="Inspect files").click()
            expect(page.locator("#status")).to_contain_text("Completed", timeout=15000)
            expect(page.locator("#files")).not_to_contain_text("HFS-001")
            try:
                with page.expect_download(timeout=2000):
                    page.evaluate("window.releaseDigest()")
            except BrowserTimeout:
                pass  # An obsolete export must not produce any download.
            else:
                raise AssertionError("Changed review retained obsolete download authority")
            page.evaluate("() => {crypto.subtle.digest=window.originalDigest;}")
            with page.expect_download() as changed:
                page.locator("#download").click()
            changed.value.save_as(str(evidence / "changed-download.json"))
            current = json.loads((evidence / "changed-download.json").read_text())
            canonical = page.evaluate(
                "JSON.stringify(JSON.parse(document.getElementById('report').textContent),null,2)"
            )
            assert (
                current["manifest"]["report_sha256"]
                == hashlib.sha256(canonical.encode()).hexdigest()
            )
            assert (
                current["report"]["input_manifest"][1]["sha256"]
                == hashlib.sha256(second.read_bytes()).hexdigest()
            )
            # Hold a real backend response and check old evidence disappears immediately.
            page.evaluate(
                """() => {window.originalFetch=fetch.bind(window);
                window.fetch=async function(...args){const response=await window.originalFetch(...args);
                  if(args[0]==='/api/inspect'){
                    document.body.dataset.pendingInspection='yes';
                    await new Promise(resolve=>window.releaseInspection=resolve);
                  }
                  return response;
                };}"""
            )
            page.locator("#sample").click()
            expect(page.locator("#status")).to_contain_text("Inspecting")
            expect(page.locator("#output")).to_be_hidden()
            expect(page.locator("body")).to_have_attribute(
                "data-pending-inspection", "yes", timeout=15000
            )
            page.evaluate("window.releaseInspection()")
            expect(page.locator("#status")).to_contain_text("Completed", timeout=15000)
            page.evaluate("() => {window.fetch=window.originalFetch;}")
            # Delay browser File.arrayBuffer, then select a newer file before it resolves.
            page.evaluate(
                "() => {window.originalRead=File.prototype.arrayBuffer; File.prototype.arrayBuffer=async function(){await new Promise(r=>setTimeout(r,600)); return window.originalRead.call(this);};}"
            )
            page.get_by_role("button", name="Inspect files").click()
            first = Path(temporary) / "synthetic-newer.py"
            first.write_text("# SYNTHETIC newer selection\nnewer = True\n")
            page.locator("#first").set_input_files(first)
            expect(page.locator("#inspect")).to_be_enabled(timeout=10000)
            expect(page.locator("#output")).to_be_hidden()
            expect(page.locator("#status")).to_contain_text("Selection changed")
            page.evaluate("() => {File.prototype.arrayBuffer=window.originalRead;}")
            # Delay an actual backend response, change selection, ensure it cannot render stale evidence.
            page.route("**/api/inspect", lambda route: (time.sleep(0.6), route.continue_()))
            page.get_by_role("button", name="Inspect files").click()
            page.locator("#first").set_input_files(second)
            expect(page.locator("#inspect")).to_be_enabled(timeout=15000)
            expect(page.locator("#output")).to_be_hidden()
            page.unroute("**/api/inspect")
            page.get_by_role("button", name="Try synthetic comparison").click()
            expect(page.locator("#status")).to_contain_text(
                "Completed clearly synthetic", timeout=15000
            )
            expect(page.locator("#files")).to_contain_text("synthetic-b.py")
            bad = Path(temporary) / "corrupt.safetensors"
            bad.write_bytes(b"bad")
            page.locator("#first").set_input_files(bad)
            page.locator("#second").set_input_files([])
            page.get_by_role("button", name="Inspect files").click()
            expect(page.locator("#status")).to_contain_text("Completed", timeout=15000)
            expect(page.locator("#assessment")).to_contain_text("UNKNOWN")
            expect(page.locator("#files")).to_contain_text("Truncated")
            # A selection/upload with a dangerous name yields an actionable API error, then recovery.
            page.locator("#first").set_input_files(
                {"name": "bad name.py", "mimeType": "text/x-python", "buffer": b"pass"}
            )
            page.get_by_role("button", name="Inspect files").click()
            expect(page.locator("#status")).to_contain_text("Inspection failed", timeout=15000)
            page.locator("#first").set_input_files(first)
            page.get_by_role("button", name="Inspect files").click()
            expect(page.locator("#status")).to_contain_text("Completed", timeout=15000)
            mobile = browser.new_context(
                viewport={"width": 390, "height": 844}, is_mobile=True, device_scale_factor=1
            )
            mpage = mobile.new_page()
            mpage.goto(f"http://127.0.0.1:{port}")
            expect(mpage.locator("#version")).to_contain_text("Engine 0.3.0")
            assert mpage.evaluate("document.documentElement.scrollWidth <= innerWidth")
            mpage.get_by_role("button", name="Try synthetic comparison").click()
            expect(mpage.locator("#status")).to_contain_text("Completed", timeout=15000)
            assert mpage.evaluate("document.documentElement.scrollWidth <= innerWidth")
            mpage.screenshot(path=str(evidence / "mobile.png"), full_page=True)
            assert not errors, errors
            (evidence / "browser.json").write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "browser": browser.version,
                        "source": health["source"],
                        "checks": [
                            "actual file upload",
                            "real findings",
                            "hash comparison",
                            "edit/rerun",
                            "download checksum",
                            "obsolete pending checksum cancels download",
                            "new review export checksum and input hashes",
                            "new scan removes old export authority",
                            "delayed file read",
                            "delayed response",
                            "synthetic label",
                            "UNKNOWN malformed",
                            "filename error/recovery",
                            "keyboard focus/labels",
                            "390px overflow",
                        ],
                        "page_errors": errors,
                    },
                    indent=2,
                )
            )
            browser.close()
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
