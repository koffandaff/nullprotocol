"use client";

import { motion } from "framer-motion";

export default function Demo() {
    return (
        <section id="demo" className="py-24 px-6 overflow-hidden">
            <div className="max-w-7xl mx-auto text-center relative">
                <h2 className="text-4xl md:text-5xl font-bold mb-16 text-gradient relative z-10">Watch it in Action</h2>

                {/* Impact Wrapper */}
                <div className="relative max-w-5xl mx-auto group">

                    {/* Animated Glow Background - "Cool AF" Impact */}
                    <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 via-purple-500 to-pink-500 rounded-2xl opacity-75 blur-xl group-hover:opacity-100 transition duration-1000 group-hover:duration-200 animate-pulse"></div>

                    {/* Rotating Border Effect */}
                    <motion.div
                        className="absolute -inset-[2px] rounded-2xl bg-gradient-to-r from-transparent via-white/50 to-transparent"
                        animate={{ rotate: 360 }}
                        transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
                        style={{ zIndex: 0 }}
                    />

                    {/* Static Video Container */}
                    <div className="relative rounded-2xl overflow-hidden shadow-2xl border border-white/10 bg-black z-10">
                        <div className="aspect-video relative">
                            <iframe
                                width="100%"
                                height="100%"
                                src="https://www.youtube.com/embed/HDynNk_2W1U?rel=0"
                                title="NullProtocol Demo Walkthrough"
                                frameBorder="0"
                                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                                allowFullScreen
                                className="w-full h-full"
                            ></iframe>

                            {/* Overlay Scanning Line Effect (Pointer Events None) */}
                            <motion.div
                                className="absolute inset-0 bg-gradient-to-b from-transparent via-cyan-500/10 to-transparent pointer-events-none"
                                initial={{ top: "-100%" }}
                                animate={{ top: "100%" }}
                                transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                            />
                        </div>
                    </div>
                </div>

            </div>
        </section>
    );
}
