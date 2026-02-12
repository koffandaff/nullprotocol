"use client";

import { motion } from "framer-motion";
import { Search, ShieldAlert, Cpu, Database, Zap, FileText } from "lucide-react";

const features = [
    { icon: Search, title: "Smart Recon", desc: "Automated Nmap & Masscan with intelligent deduplication." },
    { icon: ShieldAlert, title: "Metasploit Integration", desc: "Auto-generates resource scripts for verified vulnerabilities." },
    { icon: Cpu, title: "Parallel Execution", desc: "Multi-threaded attacks optimized for your CPU cores." },
    { icon: Zap, title: "DoS Stress Testing", desc: "Integrated hping3 flood capabilities for stability testing." },
    { icon: Database, title: "SQL Injection", desc: "Automated SQLMap targeting based on crawler data." },
    { icon: FileText, title: "Professional Reports", desc: "Export findings to PDF with executive summaries." },
];

export default function Features() {
    return (
        <section id="features" className="py-20 px-6">
            <div className="max-w-7xl mx-auto">
                <motion.h2
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    className="text-4xl font-bold text-center mb-16 text-gradient"
                >
                    Powerful Capabilities
                </motion.h2>

                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
                    {features.map((f, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.1 }}
                            className="glass p-8 rounded-2xl hover:bg-white/5 transition-colors group cursor-default"
                        >
                            <div className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center mb-4 group-hover:scale-110 transition-transform duration-300">
                                <f.icon className="w-6 h-6 text-purple-400 group-hover:text-blue-400 transition-colors" />
                            </div>
                            <h3 className="text-xl font-bold mb-2 text-white">{f.title}</h3>
                            <p className="text-gray-400 text-sm leading-relaxed">{f.desc}</p>
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
}
