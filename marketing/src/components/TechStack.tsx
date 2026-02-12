"use client";

import { motion } from "framer-motion";

const technologies = [
    { name: "Python", color: "text-blue-400" },
    { name: "Nmap", color: "text-green-400" },
    { name: "Metasploit", color: "text-blue-600" },
    { name: "Hydra", color: "text-purple-400" },
    { name: "SQLMap", color: "text-orange-400" },
    { name: "Masscan", color: "text-red-400" },
    { name: "Rich CLI", color: "text-pink-400" },
    { name: "Next.js", color: "text-white" },
];

export default function TechStack() {
    return (
        <section className="py-10 border-y border-white/5 bg-black/50">
            <div className="max-w-7xl mx-auto px-6">
                <div className="flex flex-wrap justify-center gap-8 md:gap-12">
                    {technologies.map((tech, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, y: 10 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            transition={{ delay: i * 0.1 }}
                            viewport={{ once: true }}
                            className={`text-lg font-bold ${tech.color} opacity-70 hover:opacity-100 transition-opacity flex items-center gap-2 cursor-default`}
                        >
                            <span>{tech.name}</span>
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
}
