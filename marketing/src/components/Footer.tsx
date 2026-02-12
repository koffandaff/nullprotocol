import { Github } from "lucide-react";

export default function Footer() {
    return (
        <footer id="about" className="py-12 border-t border-white/10 bg-black">
            <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6">

                <div className="text-center md:text-left">
                    <h3 className="text-xl font-bold text-white mb-2">NullProtocol</h3>
                    <p className="text-gray-500 text-sm">Advanced Recon Automation</p>
                </div>

                <div className="flex flex-col items-center md:items-end gap-4 text-sm text-gray-400">
                    <a
                        href="https://github.com/koffandaff"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-4 py-2 glass rounded-full hover:bg-white/10 text-white transition-all group"
                    >
                        <Github className="w-4 h-4 group-hover:scale-110 transition-transform" />
                        Connect on GitHub
                    </a>
                    <p className="opacity-50">Built by Dhruvil</p>
                </div>

            </div>
        </footer>
    );
}
