import { Json } from "./components";

export default function BenchmarkResult({ value }: { value?: any }) {
  const b = value?.result;
  return b ? <span>{b.framework} · {b.task} · {b.status} · reward {b.reward ?? "未产生"}
    <div className="muted small">外部判分报告，平台未重新运行判题；与模型 completed、连接关闭及传输证明分别判断。</div>
    <details><summary>判分来源与产物摘要</summary><Json v={value} max={250} /></details>
  </span> : <span className="muted">未关联独立判分；不能从模型 completed 或进程 exit 推断任务通过。</span>;
}
