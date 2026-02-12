import type { Metadata } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space",
});

export const metadata: Metadata = {
  title: "NullProtocol | Advanced Recon Automation",
  description: "Automated reconnaissance and attack pipeline for security professionals. Integrate Nmap, Hydra, and Metasploit into a single, deadly workflow.",
  openGraph: {
    title: "NullProtocol | Automated Pentesting Pipeline",
    description: "Seamlessly integrate Nmap, Hydra, and Metasploit into a single workflow. Automated recon, vulnerability scanning, and reporting.",
    url: "https://nullprotocol.com",
    siteName: "NullProtocol",
    images: [
      {
        url: "https://nullprotocol.com/og-image.png", // Placeholder
        width: 1200,
        height: 630,
        alt: "NullProtocol Dashboard",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "NullProtocol | Advanced Recon Automation",
    description: "Automated reconnaissance and attack pipeline for security professionals.",
    creator: "@koffandaff",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.variable} ${spaceGrotesk.variable} font-sans antialiased`}>
        {children}
      </body>
    </html>
  );
}
