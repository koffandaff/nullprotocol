"use client";

import { motion } from "framer-motion";

const groups = [
    "Penetration Testers",
    "Bug Bounty Hunters",
    "Security Researchers",
    "Red Team Operations"
];

export default function TargetAudience() {
    return (
        <section className="py-20 px-6 border-y border-white/5 bg-white/[0.02]">
            <div className="max-w-7xl mx-auto text-center">
                <h2 className="text-3xl font-bold mb-10 text-white">Built For Professionals</h2>

                <div className="flex flex-wrap justify-center gap-4">
                    {groups.map((group, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, scale: 0.9 }}
                            whileInView={{ opacity: 1, scale: 1 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.1 }}
                            className="px-6 py-3 rounded-full glass text-gray-300 font-medium hover:text-white hover:bg-white/10 cursor-default transition-all"
                        >
                            {group}
                        </motion.div>
                    ))}
                </div>
            </div>
        </section>
    );
}
