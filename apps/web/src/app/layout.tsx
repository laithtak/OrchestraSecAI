import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OrchestraSecAI",
  description: "Passive web security scanner",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
