import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

function getRisk(vulns: Array<{ label: number }>) {
  if (!vulns.length) return "SAFE";
  if (vulns.some((v) => v.label === 0)) return "CRITICAL";
  if (vulns.some((v) => v.label === 2)) return "HALLUCINATED";
  return "HIGH";
}

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return new NextResponse("Unauthorized", { status: 401 });
    }

    const scans = await prisma.scanResult.findMany({
      where: { userId: session.user.id },
      include: { vulnerabilities: true },
      orderBy: { createdAt: "desc" },
    });

    const header = [
      "scan_id",
      "created_at",
      "risk",
      "vulnerability_count",
      "fixed_code_available",
    ];

    const rows = scans.map((scan: { id: string; createdAt: Date; fixedCode: string | null; vulnerabilities: Array<{ label: number }> }) => {
      const vulnCount = scan.vulnerabilities.filter((v: { label: number }) => v.label !== 1).length;
      return [
        scan.id,
        new Date(scan.createdAt).toISOString(),
        getRisk(scan.vulnerabilities),
        String(vulnCount),
        scan.fixedCode ? "yes" : "no",
      ];
    });

    const csv = [header, ...rows]
      .map((row) => row.map((cell: string) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
      .join("\n");

    return new NextResponse(csv, {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename=codetrust-forensic-report-${Date.now()}.csv`,
      },
    });
  } catch (error) {
    console.error("HISTORY_EXPORT_ERROR", error);
    return new NextResponse("Internal Error", { status: 500 });
  }
}
