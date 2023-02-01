using System;
using System.Collections.Generic;
using System.Linq;
using Confuser.Core;
using Confuser.Core.Helpers;
using Confuser.Core.Services;
using Confuser.Renamer;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections {
	[BeforeProtection("Ki.ControlFlow")]
	internal class AntiDumpProtection : Protection {
		public const string _Id = "anti dump";
		public const string _FullId = "Ki.AntiDump";

		public override string Name {
			get { return "Anti Dump Protection"; }
		}

		public override string Description {
			get { return "This protection prevents the assembly from being dumped from memory."; }
		}

		public override string Id {
			get { return _Id; }
		}

		public override string FullId {
			get { return _FullId; }
		}

		public override ProtectionPreset Preset {
			get { return ProtectionPreset.Maximum; }
		}

		protected override void Initialize(ConfuserContext context) {
			//
		}

		protected override void PopulatePipeline(ProtectionPipeline pipeline) {
			pipeline.InsertPreStage(PipelineStage.ProcessModule, new AntiDumpPhase(this));
		}

		class AntiDumpPhase : ProtectionPhase {
			public AntiDumpPhase(AntiDumpProtection parent)
				: base(parent) { }

			public override ProtectionTargets Targets {
				get { return ProtectionTargets.Modules; }
			}

			public override string Name {
				get { return "Anti-dump injection"; }
			}

			protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {

				//获取Confuser.Runtime中的AntiDump类
				TypeDef rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.AntiDump");

				var marker = context.Registry.GetService<IMarkerService>();
				var name = context.Registry.GetService<INameService>();

				foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {

					//将Confuser.Runtime.AntiDump类注入到目标程序集，返回目标程序集中的所有IDnlibDef
					//什么是IDnlibDef?
					IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);

					//寻找<Module>::.cctor
					MethodDef cctor = module.GlobalType.FindStaticConstructor();
					var init = (MethodDef)members.Single(method => method.Name == "Initialize");

					//插入call void Confuser.Runtime.AntiDump::Initialize()这条IL指令
					cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));

					//注入的方法标记为需要重命名的
					foreach (IDnlibDef member in members)
						name.MarkHelper(member, marker, (Protection)Parent);
				}
			}
		}
	}
}
