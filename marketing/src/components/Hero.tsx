"use client";

import { motion } from "framer-motion";
import { ArrowRight, Terminal } from "lucide-react";
import Link from "next/link";

export default function Hero() {
    return (
        <section className="relative min-h-screen flex items-center justify-center pt-20 overflow-hidden">
            {/* Background Blobs */}
            <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10">
                <div className="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] bg-purple-900/20 rounded-full blur-[100px] animate-pulse" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[500px] h-[500px] bg-blue-900/20 rounded-full blur-[100px] animate-pulse delay-1000" />
            </div>

            <div className="max-w-7xl mx-auto px-6 grid lg:grid-cols-2 gap-12 items-center">

                {/* LEFT: Content (Flipped) */}
                <motion.div
                    initial={{ opacity: 0, x: -50 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.8 }}
                    className="flex flex-col gap-6 order-2 lg:order-1"
                >
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass w-fit">
                        <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                        <span className="text-xs font-medium text-gray-400">v1.2.0 Released</span>
                    </div>

                    <h1 className="text-5xl md:text-7xl font-bold tracking-tight">
                        <span className="text-white">Null</span>
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-blue-400">Protocol</span>
                    </h1>

                    <p className="text-lg text-gray-400 leading-relaxed max-w-lg">
                        Advanced reconnaissance and attack pipeline automator.
                        Seamlessly integrate Nmap, Hydra, and Metasploit into a single, deadly workflow.
                    </p>

                    <div className="flex flex-wrap items-center gap-4 pt-4">
                        <Link
                            href="#install"
                            className="px-8 py-4 bg-white text-black font-bold rounded-xl hover:bg-gray-200 transition-all flex items-center gap-2 group"
                        >
                            Start Hacking
                            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                        </Link>

                        <a
                            href="https://github.com/koffandaff/NullProtocol"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-8 py-4 glass rounded-xl hover:bg-white/10 transition-all text-white font-medium flex items-center gap-2"
                        >
                            <Terminal className="w-4 h-4" />
                            View Source
                        </a>
                    </div>
                </motion.div>

                {/* RIGHT: YouTube Video (Flipped) */}
                <motion.div
                    initial={{ opacity: 0, x: 50 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.8, delay: 0.2 }}
                    className="relative group order-1 lg:order-2"
                >
                    <div className="absolute -inset-1 bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                    <div className="relative glass-card rounded-2xl overflow-hidden aspect-video shadow-2xl">
                        <iframe
                            width="100%"
                            height="100%"
                            src="https://www.youtube.com/embed/HDynNk_2W1U?autoplay=0&mute=0&controls=1&rel=0"
                            title="NullProtocol Demo"
                            frameBorder="0"
                            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                            allowFullScreen
                            className="w-full h-full"
                        ></iframe>
                    </div>
                </motion.div>

            </div>
        </section>
    );
}
