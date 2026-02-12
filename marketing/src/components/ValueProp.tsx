"use client";

import { motion } from "framer-motion";
import { XCircle, CheckCircle } from "lucide-react";

export default function ValueProp() {
    return (
        <section className="py-20 px-6">
            <div className="max-w-7xl mx-auto grid md:grid-cols-2 gap-12 items-center">

                {/* Production Problem */}
                <motion.div
                    initial={{ opacity: 0, x: -50 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    className="glass p-8 rounded-3xl border border-red-500/20 relative overflow-hidden"
                >
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-500/0 via-red-500/50 to-red-500/0" />
                    <h3 className="text-2xl font-bold mb-6 text-red-400 flex items-center gap-3">
                        <XCircle className="w-6 h-6" />
                        The Manual Struggle
                    </h3>
                    <ul className="space-y-4 text-gray-400">
                        <li className="flex gap-3">
                            <span className="text-red-500/50">✖</span>
                            <span>Running Nmap, saving output, then parsing it manually.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-red-500/50">✖</span>
                            <span>Guessing which Hydra flags to use for each service.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-red-500/50">✖</span>
                            <span>Wasting hours configuring Metasploit for simple exploits.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-red-500/50">✖</span>
                            <span>Drowning in terminal tabs and lost text files.</span>
                        </li>
                    </ul>
                </motion.div>

                {/* NullProtocol Solution */}
                <motion.div
                    initial={{ opacity: 0, x: 50 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    className="glass p-8 rounded-3xl border border-green-500/20 relative overflow-hidden"
                >
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-green-500/0 via-green-500/50 to-green-500/0" />
                    <h3 className="text-2xl font-bold mb-6 text-green-400 flex items-center gap-3">
                        <CheckCircle className="w-6 h-6" />
                        The NullProtocol Way
                    </h3>
                    <ul className="space-y-4 text-gray-300">
                        <li className="flex gap-3">
                            <span className="text-green-500">✓</span>
                            <span><b>One command</b> to orchestrate the entire kill chain.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-green-500">✓</span>
                            <span>Auto-detects services and launches optimized brute force.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-green-500">✓</span>
                            <span>Generates ready-to-fire Metasploit resource scripts.</span>
                        </li>
                        <li className="flex gap-3">
                            <span className="text-green-500">✓</span>
                            <span>Delivers a clean PDF report with zero effort.</span>
                        </li>
                    </ul>
                </motion.div>

            </div>
        </section>
    );
}
