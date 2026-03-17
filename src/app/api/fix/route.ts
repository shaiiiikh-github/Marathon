import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { prisma } from "@/lib/prisma";

export async function POST(req: Request) {
    try {
        const session = await auth();
        if (!session?.user?.id) {
            return new NextResponse("Unauthorized", { status: 401 });
        }

        const body = await req.json();
        const { code, scan_results, scanId } = body;

        if (!code || !scan_results || !scanId) {
            return new NextResponse("Missing required fields", { status: 400 });
        }

        // 1. Define the API URL exactly ONCE
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || "https://shaiiiikh1305-backend.hf.space";
        
        // 2. Send the code and vulnerabilities to the ML Backend
        const flaskResponse = await fetch(`${apiUrl}/fix`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, scan_results }),
        });

        if (!flaskResponse.ok) {
            throw new Error("Failed to communicate with ML Backend");
        }

        const mlData = await flaskResponse.json();
        const fixedCode = mlData.fixed_code;

        // 3. Save the fixed code back to the Prisma database
        if (fixedCode) {
            await prisma.scanResult.update({
                where: { id: scanId },
                data: { fixedCode: fixedCode },
            });
        }

        return NextResponse.json({ fixed_code: fixedCode });

    } catch (error) {
        console.error("FIX_ERROR", error);
        return new NextResponse("Internal Error", { status: 500 });
    }
}