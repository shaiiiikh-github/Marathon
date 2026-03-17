import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

export async function POST(req: Request) {
    try {
        // 1. Verify the user is logged in
        const session = await auth();
        if (!session?.user?.id) {
            return new NextResponse("Unauthorized", { status: 401 });
        }

        const body = await req.json();
        const { scanId } = body;

        if (!scanId) {
            return new NextResponse("No scanId provided", { status: 400 });
        }

        // 2. Fetch the original scan and its vulnerabilities from the database
        const scanResult = await prisma.scanResult.findFirst({
            where: {
                id: scanId,
                userId: session.user.id,
            },
            include: {
                vulnerabilities: true,
            }
        });

        if (!scanResult) {
            return new NextResponse("Scan not found", { status: 404 });
        }

        // 3. Format the data for your Flask /fix endpoint
        const payload = {
            code: scanResult.originalCode,
            scan_results: scanResult.vulnerabilities.map((v: any) => ({
                line_number: v.lineNumber,
                code: v.codeSnippet,
                label: v.label,
                label_name: v.labelName,
            }))
        };

        // 4. Send to the local Flask server (which talks to Ollama)
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:7860";
        const flaskResponse = await fetch(`${apiUrl}/fix`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        if (!flaskResponse.ok) {
            throw new Error("Failed to communicate with ML Backend for fixing");
        }

        const mlData = await flaskResponse.json();
        
        // Handle cases where Ollama is down or fails
        if (mlData.error) {
             return new NextResponse(mlData.error, { status: 500 });
        }

        const fixedCode = mlData.fixed_code;

        // 5. Update the scan result in Prisma with the newly fixed code
        const updatedScan = await prisma.scanResult.update({
            where: { id: scanId },
            data: { fixedCode: fixedCode }
        });

        return NextResponse.json(updatedScan);

    } catch (error) {
        console.error("FIX_ERROR", error);
        return new NextResponse("Internal Error", { status: 500 });
    }
}