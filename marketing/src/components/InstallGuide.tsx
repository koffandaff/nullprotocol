"use client";

import { motion } from "framer-motion";
import { Check, Clipboard } from "lucide-react";
import { useState } from "react";

export default function InstallGuide() {
    const [copied, setCopied] = useState(false);

    const code = `git clone https://github.com/koffandaff/NullProtocol
cd NullProtocol

# Create and activate virtual environment (Recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Run the installer
./install.sh`;

    const copyToClipboard = () => {
        navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <section id="install" className="py-20 px-6 relative overflow-hidden">
            <div className="absolute inset-0 bg-blue-900/5 -z-10" />

            <div className="max-w-4xl mx-auto text-center">
                <motion.h2
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-4xl font-bold mb-8 text-gradient"
                >
                    Get Started in Seconds
                </motion.h2>

                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    className="glass-card rounded-2xl overflow-hidden text-left mx-auto max-w-2xl"
                >
                    <div className="flex items-center justify-between px-4 py-3 bg-black/40 border-b border-white/10">
                        <div className="flex gap-2">
                            <div className="w-3 h-3 rounded-full bg-red-500/50" />
                            <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                            <div className="w-3 h-3 rounded-full bg-green-500/50" />
                        </div>
                        <button
                            onClick={copyToClipboard}
                            className="text-xs text-gray-400 hover:text-white flex items-center gap-1 transition-colors"
                        >
                            {copied ? <Check className="w-3 h-3" /> : <Clipboard className="w-3 h-3" />}
                            {copied ? "Copied!" : "Copy"}
                        </button>
                    </div>

                    <div className="p-6 font-mono text-sm overflow-x-auto bg-[#0d1117]">
                        <div className="flex gap-4">
                            {/* Line numbers hidden on small screens for cleaner copy */}
                            <div className="hidden md:flex flex-col text-gray-600 select-none text-right">
                                <span>1</span><span>2</span><span>3</span><span>4</span><span>5</span><span>6</span><span>7</span><span>8</span><span>9</span><span>10</span><span>11</span>
                            </div>
                            <pre className="text-gray-300 whitespace-pre font-mono">
                                {code}
                            </pre>
                        </div>
                    </div>
                </motion.div>

                <p className="mt-6 text-gray-500 text-sm">
                    Requires Linux / Kali / WSL. Python 3.8+ recommended.
                </p>
            </div>
        </section>
    );
}
