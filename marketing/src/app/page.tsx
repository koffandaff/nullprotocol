import Navbar from "@/components/Navbar";
import Hero from "@/components/Hero";
import SimpleExplanation from "@/components/SimpleExplanation";
import ValueProp from "@/components/ValueProp";
import Features from "@/components/Features";
import HowIBuiltIt from "@/components/HowIBuiltIt";

import InstallGuide from "@/components/InstallGuide";
import Demo from "@/components/Demo";
import TargetAudience from "@/components/TargetAudience";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white selection:bg-purple-500/30 font-sans">
      <Navbar />
      <Hero />
      <SimpleExplanation />
      <ValueProp />
      <Features />

      <HowIBuiltIt />
      <TargetAudience />
      <InstallGuide />
      <Demo />
      <Footer />
    </main>
  );
}
