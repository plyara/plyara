rule _PcShare__v40___
{
	meta:
		description = "PcShare 文件捆绑器 v4.0 -> 无可非议"
	strings:
		$0 = {55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1}
	condition:
		$0 at entrypoint
}