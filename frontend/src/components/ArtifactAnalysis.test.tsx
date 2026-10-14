import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ArtifactAnalysis } from "./ArtifactAnalysis";
import type { FileAnalysis, IngestionAnalysis } from "../lib/types";

const file: FileAnalysis = {
  filename: "shipment.zip",
  extension: ".zip",
  size: 1400,
  kind: "zip",
  mime: "application/zip",
  md5: "m",
  sha1: "s",
  sha256: "abc123",
  dangerous: false,
};

describe("ArtifactAnalysis", () => {
  it("lists macros with auto-run entry points and archive members", () => {
    const ingestion: IngestionAnalysis = {
      file,
      macros: [
        {
          file: "shipment.zip/Invoice.docm",
          present: true,
          modules: ["Module1"],
          autoexec: ["AutoOpen"],
          suspicious: ["shell execution: WScript.Shell"],
        },
      ],
      archives: [
        {
          path: "shipment.zip",
          depth: 1,
          entries: 2,
          members: [
            { name: "Invoice.docm", size: 1300, dangerous: true },
            { name: "scan.js", size: 1, encrypted: true },
          ],
          encrypted: ["scan.js"],
          dangerous: ["Invoice.docm", "scan.js"],
          nested_archives: 0,
          limits_exceeded: ["compression ratio suggests a decompression bomb"],
        },
      ],
    };
    render(<ArtifactAnalysis ingestion={ingestion} />);

    const macro = screen.getByTestId("macro");
    expect(within(macro).getByText("auto-run")).toBeInTheDocument();
    expect(within(macro).getByText(/entry points: AutoOpen/)).toBeInTheDocument();
    expect(within(macro).getByText("shell execution: WScript.Shell")).toBeInTheDocument();

    const archive = screen.getByTestId("archive");
    expect(within(archive).getByText(/2 entries · 1 password-protected/)).toBeInTheDocument();
    expect(within(archive).getByText("scan.js")).toHaveClass("text-fail");
    expect(within(archive).getByText(/decompression bomb/)).toBeInTheDocument();
  });

  it("shows QR codes found in PDF images and hides the embedded panel when empty", () => {
    const pdfFile: FileAnalysis = {
      ...file,
      filename: "fine.pdf",
      kind: "pdf",
      pdf: {
        pages: 1,
        metadata: {},
        links: [],
        active_content: [],
        images: { scanned: 1, qr_payloads: ["https://pay-parking-fine.top/ticket"], ocr_characters: 0 },
      },
    };
    render(<ArtifactAnalysis ingestion={{ file: pdfFile }} />);
    expect(screen.getByText("1 embedded image(s) scanned")).toBeInTheDocument();
    expect(screen.getByText("https://pay-parking-fine.top/ticket")).toBeInTheDocument();
    expect(screen.queryByText(/Macros & embedded files/)).not.toBeInTheDocument();
  });

  it("renders nothing for plain text investigations", () => {
    const { container } = render(<ArtifactAnalysis ingestion={{}} />);
    expect(container).toBeEmptyDOMElement();
  });
});
