"use client";

import { motion } from "framer-motion";
import { ArrowRight, FileText, Globe, Server, Shield } from "lucide-react";

export default function HowIBuiltIt() {
    return (
        <section id="how-it-works" className="py-24 px-6 bg-black/50">
            <div className="max-w-7xl mx-auto">
                <div className="text-center mb-16">
                    <h2 className="text-4xl font-bold mb-4 text-gradient">How I Built It</h2>
                    <p className="text-gray-400">From concept to code: The architecture behind the automation.</p>
                </div>

                {/* SIMPLE FLOW */}
                <div className="mb-20">
                    <h3 className="text-2xl font-bold mb-8 text-center text-white">The Concept (Simple Flow)</h3>
                    <div className="flex flex-col md:flex-row items-center justify-center gap-6 md:gap-4 overflow-x-auto pb-4">

                        <FlowStep icon={Globe} label="Target Input" />
                        <FlowArrow />
                        <FlowStep icon={Server} label="Auto Recon" />
                        <FlowArrow />
                        <FlowStep icon={Shield} label="Vulnerability Scan" />
                        <FlowArrow />
                        <FlowStep icon={FileText} label="PDF Report" />

                    </div>
                </div>

                {/* COMPLEX FLOW */}
                <div>
                    <h3 className="text-2xl font-bold mb-8 text-center text-white">The Architecture (Deep Dive)</h3>
                    <div className="glass p-8 rounded-3xl border border-white/10 max-w-5xl mx-auto">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center relative">

                            {/* Recon Layer */}
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/5">
                                <h4 className="font-bold text-blue-400 mb-4">1. Recon Layer</h4>
                                <div className="space-y-3 text-sm text-gray-400">
                                    <div className="bg-black/40 p-2 rounded">Nmap (Service Detection)</div>
                                    <div className="bg-black/40 p-2 rounded">Masscan (Port Sweep)</div>
                                    <div className="bg-black/40 p-2 rounded">Crawler (URL Extraction)</div>
                                </div>
                            </div>

                            {/* Attack Layer */}
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/5 relative">
                                <h4 className="font-bold text-red-400 mb-4">2. Attack Layer</h4>
                                <div className="space-y-3 text-sm text-gray-400">
                                    <div className="bg-black/40 p-2 rounded">Hydra (Brute Force)</div>
                                    <div className="bg-black/40 p-2 rounded">SQLMap (Injection)</div>
                                    <div className="bg-black/40 p-2 rounded">Metasploit (Exploits)</div>
                                </div>
                                {/* Visual Connection */}
                                <div className="hidden md:block absolute top-1/2 -left-6 w-8 h-0.5 bg-gradient-to-r from-blue-500/50 to-red-500/50" />
                            </div>

                            {/* Reporting Layer */}
                            <div className="p-6 rounded-2xl bg-white/5 border border-white/5 relative">
                                <h4 className="font-bold text-green-400 mb-4">3. Reporting Layer</h4>
                                <div className="space-y-3 text-sm text-gray-400">
                                    <div className="bg-black/40 p-2 rounded">Data Aggregation</div>
                                    <div className="bg-black/40 p-2 rounded">HTML Template</div>
                                    <div className="bg-black/40 p-2 rounded">PDF Generation</div>
                                </div>
                                {/* Visual Connection */}
                                <div className="hidden md:block absolute top-1/2 -left-6 w-8 h-0.5 bg-gradient-to-r from-red-500/50 to-green-500/50" />
                            </div>

                        </div>
                    </div>
                </div>

            </div>
        </section>
    );
}

function FlowStep({ icon: Icon, label }: { icon: React.ElementType, label: string }) {
    return (
        <motion.div
            whileHover={{ scale: 1.05 }}
            className="flex flex-col items-center gap-3 p-6 glass rounded-2xl border border-white/10 w-40 h-40 justify-center"
        >
            <Icon className="w-8 h-8 text-white" />
            <span className="text-sm font-medium text-gray-300 text-center">{label}</span>
        </motion.div>
    );
}

function FlowArrow() {
    return (
        <div className="text-gray-600 rotate-90 md:rotate-0">
            <ArrowRight className="w-6 h-6" />
        </div>
    );
}
