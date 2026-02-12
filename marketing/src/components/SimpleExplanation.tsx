"use client";

import { motion } from "framer-motion";

export default function SimpleExplanation() {
    return (
        <section id="what-it-is" className="py-16 px-6 text-center">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                className="max-w-3xl mx-auto"
            >
                <span className="px-3 py-1 rounded-full bg-blue-500/10 text-blue-400 text-sm font-medium border border-blue-500/20 mb-6 inline-block">
                    Simply Put
                </span>
                <h2 className="text-3xl md:text-4xl font-bold mb-6 text-white">
                    It&apos;s like an Autopilot for Ethical Hackers
                </h2>
                <p className="text-xl text-gray-400 leading-relaxed">
                    Imagine if you had a robot assistant. You just point at a server and say
                    <span className="text-white font-medium"> &quot;Check that.&quot;</span>
                    <br /><br />
                    The robot goes and knocks on every door (Nmap), tries the keys (Hydra),
                    checks for unlocked windows (Metasploit), and then comes back with a
                    neats report written on a piece of paper.
                    <br /><br />
                    That robot is <b>NullProtocol</b>.
                </p>
            </motion.div>
        </section>
    );
}
