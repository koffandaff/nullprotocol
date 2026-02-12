"use client";

import { motion } from "framer-motion";
import { Terminal, Github, Menu, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

export default function Navbar() {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <nav className="fixed top-0 left-0 right-0 z-50 px-6 py-4">
            <div className="max-w-7xl mx-auto">
                <div className="glass rounded-2xl px-6 py-3 flex items-center justify-between">
                    {/* Logo */}
                    <Link href="/" className="flex items-center gap-2 group">
                        <div className="p-2 bg-white/10 rounded-lg group-hover:bg-white/20 transition-colors">
                            <Terminal className="w-5 h-5 text-white" />
                        </div>
                        <span className="font-bold text-lg tracking-tight">NullProtocol</span>
                    </Link>

                    {/* Desktop Nav */}
                    <div className="hidden md:flex items-center gap-8">
                        <Link href="#what-it-is" className="text-sm text-gray-400 hover:text-white transition-colors">What It Is</Link>
                        <Link href="#features" className="text-sm text-gray-400 hover:text-white transition-colors">Features</Link>
                        <Link href="#how-it-works" className="text-sm text-gray-400 hover:text-white transition-colors">How it Works</Link>
                        <Link href="#demo" className="text-sm text-gray-400 hover:text-white transition-colors">Demo</Link>
                        <Link href="#about" className="text-sm text-gray-400 hover:text-white transition-colors">About</Link>
                    </div>

                    {/* CTA */}
                    <div className="hidden md:flex items-center gap-4">
                        <a
                            href="https://github.com/koffandaff/NullProtocol"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 hover:bg-white/10 rounded-full transition-colors"
                        >
                            <Github className="w-5 h-5" />
                        </a>
                        <Link
                            href="#install"
                            className="px-5 py-2 bg-white text-black font-medium rounded-full hover:bg-gray-200 transition-colors text-sm"
                            onClick={(e) => {
                                e.preventDefault();
                                const element = document.getElementById('install');
                                element?.scrollIntoView({ behavior: 'smooth' });
                            }}
                        >
                            Get Started
                        </Link>
                    </div>

                    {/* Mobile Menu Button */}
                    <button
                        className="md:hidden text-gray-400 hover:text-white"
                        onClick={() => setIsOpen(!isOpen)}
                    >
                        {isOpen ? <X /> : <Menu />}
                    </button>
                </div>
            </div>

            {/* Mobile Menu */}
            {isOpen && (
                <motion.div
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="md:hidden absolute top-24 left-6 right-6 glass-card bg-black/90 backdrop-blur-xl rounded-2xl p-6 flex flex-col gap-4 border border-white/10 z-50 shadow-2xl"
                >
                    <Link href="#what-it-is" onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white py-2">What It Is</Link>
                    <Link href="#features" onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white py-2">Features</Link>
                    <Link href="#how-it-works" onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white py-2">How it Works</Link>
                    <Link href="#demo" onClick={() => setIsOpen(false)} className="text-gray-400 hover:text-white py-2">Demo</Link>
                    <a href="https://github.com/koffandaff/NullProtocol" className="text-gray-400 hover:text-white py-2">Github</a>
                    <Link
                        href="#install"
                        onClick={() => setIsOpen(false)}
                        className="px-5 py-3 bg-white text-black font-medium rounded-xl text-center mt-2"
                    >
                        Get Started
                    </Link>
                </motion.div>
            )}
        </nav>
    );
}
