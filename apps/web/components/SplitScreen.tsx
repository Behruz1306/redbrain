"use client";

interface SplitScreenProps {
  left: React.ReactNode;
  right: React.ReactNode;
  bottom?: React.ReactNode;
  ratio?: [number, number];
}

export function SplitScreen({ left, right, bottom, ratio = [1, 1] }: SplitScreenProps) {
  const [leftW, rightW] = ratio;
  const total = leftW + rightW;

  return (
    <div className="flex flex-col h-full gap-3">
      <div
        className="flex-[3] grid gap-3 min-h-0"
        style={{ gridTemplateColumns: `${leftW}fr ${rightW}fr` }}
      >
        <div className="min-h-0 overflow-hidden">{left}</div>
        <div className="min-h-0 overflow-hidden">{right}</div>
      </div>
      {bottom && <div className="flex-[1] min-h-0">{bottom}</div>}
    </div>
  );
}
