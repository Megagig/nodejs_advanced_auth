import QRCode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
    throw new Error("Pass OTP Auth URL as argument");
}

async function main() {
    await QRCode.toFile(
        "2fa-qr.png",
        otpAuthUrl
    );
    console.log("QR code saved as 2fa-qr.png");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
