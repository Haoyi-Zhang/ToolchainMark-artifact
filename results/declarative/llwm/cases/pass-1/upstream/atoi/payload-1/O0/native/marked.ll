; ModuleID = '/workspace/scratch/022f04342461/work-v6/ToolchainMark_TOSEM/artifact/results/declarative-v6/llwm/cases/pass-1/upstream/atoi/payload-1/O0/native/unmarked.ll'
source_filename = "/workspace/scratch/022f04342461/work-v6/ToolchainMark_TOSEM/artifact/external_llwm/probes/atoi.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [9 x i8] c"host:%d\0A\00", align 1, !dbg !0

; Function Attrs: nofree nounwind uwtable
define dso_local i32 @main(i32 noundef %0, ptr nocapture noundef readonly %1) local_unnamed_addr #0 !dbg !23 {
  call void @llvm.dbg.value(metadata i32 %0, metadata !27, metadata !DIExpression()), !dbg !30
  call void @llvm.dbg.value(metadata ptr %1, metadata !28, metadata !DIExpression()), !dbg !30
  %3 = icmp eq i32 %0, 2, !dbg !31
  br i1 %3, label %4, label %45, !dbg !33

4:                                                ; preds = %2
  %5 = getelementptr inbounds ptr, ptr %1, i64 1, !dbg !34
  %6 = load ptr, ptr %5, align 8, !dbg !34, !tbaa !35
  call void @llvm.dbg.value(metadata ptr %6, metadata !39, metadata !DIExpression()), !dbg !47
  %7 = tail call i64 @strtol(ptr nocapture noundef nonnull %6, ptr noundef null, i32 noundef 10) #4, !dbg !49
  %8 = mul i64 %7, 18
  %9 = sdiv i64 %8, 15
  %10 = add i64 %9, 1123836343
  %11 = trunc i64 %7 to i32, !dbg !50
  call void @llvm.dbg.value(metadata i32 %11, metadata !29, metadata !DIExpression()), !dbg !30
  %12 = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str, i32 noundef %11), !dbg !51
  %13 = icmp eq i64 %10, 1123837823
  br i1 %13, label %41, label %44

14:                                               ; preds = %41
  %15 = alloca i8, i32 5, align 1
  %16 = getelementptr i8, ptr %6, i32 0
  %17 = load i8, ptr %16, align 1
  %18 = mul i8 %17, 36
  %19 = sdiv i8 %18, 6
  %20 = add i8 %19, 69
  %21 = getelementptr i8, ptr %15, i32 0
  store i8 %20, ptr %21, align 1
  %22 = getelementptr i8, ptr %6, i32 1
  %23 = load i8, ptr %22, align 1
  %24 = mul i8 %23, 21
  %25 = sdiv i8 %24, 8
  %26 = add i8 %25, 34
  %27 = getelementptr i8, ptr %15, i32 1
  store i8 %26, ptr %27, align 1
  %28 = getelementptr i8, ptr %6, i32 2
  %29 = load i8, ptr %28, align 1
  %30 = mul i8 %29, 19
  %31 = add i8 %30, 92
  %32 = getelementptr i8, ptr %15, i32 2
  store i8 %31, ptr %32, align 1
  %33 = getelementptr i8, ptr %6, i32 3
  %34 = load i8, ptr %33, align 1
  %35 = mul i8 %34, 49
  %36 = sdiv i8 %35, 5
  %37 = add i8 %36, 68
  %38 = getelementptr i8, ptr %15, i32 3
  store i8 %37, ptr %38, align 1
  %39 = getelementptr i8, ptr %15, i32 4
  store i8 0, ptr %39, align 1
  %40 = call i32 (ptr, ...) @printf(ptr %15)
  br label %44

41:                                               ; preds = %4
  %42 = call i64 @strlen(ptr %6)
  %43 = icmp eq i64 %42, 4
  br i1 %43, label %14, label %44

44:                                               ; preds = %4, %41, %14
  br label %45

45:                                               ; preds = %44, %2
  %46 = phi i32 [ 0, %44 ], [ 2, %2 ], !dbg !52
  ret i32 %46, !dbg !53
}

; Function Attrs: nofree nounwind
declare !dbg !54 noundef i32 @printf(ptr nocapture noundef readonly, ...) local_unnamed_addr #1

; Function Attrs: mustprogress nofree nounwind willreturn
declare !dbg !59 i64 @strtol(ptr noundef readonly, ptr nocapture noundef, i32 noundef) local_unnamed_addr #2

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.value(metadata, metadata, metadata) #3

declare i64 @strlen(ptr)

attributes #0 = { nofree nounwind uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { mustprogress nofree nounwind willreturn "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!15, !16, !17, !18, !19, !20, !21}
!llvm.ident = !{!22}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 3, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "external_llwm/probes/atoi.c", directory: "/workspace/scratch/022f04342461/work-v6/ToolchainMark_TOSEM/artifact", checksumkind: CSK_MD5, checksum: "63738c5d953d3ad71513893d028396e3")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 72, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 9)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !8, producer: "Debian clang version 17.0.6 (++20231208085813+6009708b4367-1~exp1~20231208085906.81)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !9, globals: !14, splitDebugInlining: false, nameTableKind: None)
!8 = !DIFile(filename: "/workspace/scratch/022f04342461/work-v6/ToolchainMark_TOSEM/artifact/external_llwm/probes/atoi.c", directory: "/workspace/scratch/022f04342461/work-v6/ToolchainMark_TOSEM/artifact/results/declarative-v6/llwm/cases/pass-1/upstream/atoi/payload-1/O0/native", checksumkind: CSK_MD5, checksum: "63738c5d953d3ad71513893d028396e3")
!9 = !{!10, !11, !13}
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 64)
!12 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!14 = !{!0}
!15 = !{i32 7, !"Dwarf Version", i32 5}
!16 = !{i32 2, !"Debug Info Version", i32 3}
!17 = !{i32 1, !"wchar_size", i32 4}
!18 = !{i32 8, !"PIC Level", i32 2}
!19 = !{i32 7, !"PIE Level", i32 2}
!20 = !{i32 7, !"uwtable", i32 2}
!21 = !{i32 7, !"debug-info-assignment-tracking", i1 true}
!22 = !{!"Debian clang version 17.0.6 (++20231208085813+6009708b4367-1~exp1~20231208085906.81)"}
!23 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 3, type: !24, scopeLine: 3, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !7, retainedNodes: !26)
!24 = !DISubroutineType(types: !25)
!25 = !{!10, !10, !11}
!26 = !{!27, !28, !29}
!27 = !DILocalVariable(name: "n", arg: 1, scope: !23, file: !2, line: 3, type: !10)
!28 = !DILocalVariable(name: "v", arg: 2, scope: !23, file: !2, line: 3, type: !11)
!29 = !DILocalVariable(name: "a", scope: !23, file: !2, line: 3, type: !10)
!30 = !DILocation(line: 0, scope: !23)
!31 = !DILocation(line: 3, column: 30, scope: !32)
!32 = distinct !DILexicalBlock(scope: !23, file: !2, line: 3, column: 29)
!33 = !DILocation(line: 3, column: 29, scope: !23)
!34 = !DILocation(line: 3, column: 54, scope: !23)
!35 = !{!36, !36, i64 0}
!36 = !{!"any pointer", !37, i64 0}
!37 = !{!"omnipotent char", !38, i64 0}
!38 = !{!"Simple C/C++ TBAA"}
!39 = !DILocalVariable(name: "__nptr", arg: 1, scope: !40, file: !41, line: 481, type: !44)
!40 = distinct !DISubprogram(name: "atoi", scope: !41, file: !41, line: 481, type: !42, scopeLine: 482, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !7, retainedNodes: !46)
!41 = !DIFile(filename: "/usr/include/stdlib.h", directory: "", checksumkind: CSK_MD5, checksum: "775455349f6dd75df6b36d4b094321a4")
!42 = !DISubroutineType(types: !43)
!43 = !{!10, !44}
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !4)
!46 = !{!39}
!47 = !DILocation(line: 0, scope: !40, inlinedAt: !48)
!48 = distinct !DILocation(line: 3, column: 49, scope: !23)
!49 = !DILocation(line: 483, column: 16, scope: !40, inlinedAt: !48)
!50 = !DILocation(line: 483, column: 10, scope: !40, inlinedAt: !48)
!51 = !DILocation(line: 3, column: 60, scope: !23)
!52 = !DILocation(line: 3, scope: !23)
!53 = !DILocation(line: 3, column: 91, scope: !23)
!54 = !DISubprogram(name: "printf", scope: !55, file: !55, line: 363, type: !56, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!55 = !DIFile(filename: "/usr/include/stdio.h", directory: "", checksumkind: CSK_MD5, checksum: "47768dac06badcdb9c30a3d8abe4063b")
!56 = !DISubroutineType(types: !57)
!57 = !{!10, !58, null}
!58 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !44)
!59 = !DISubprogram(name: "strtol", scope: !41, file: !41, line: 177, type: !60, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!60 = !DISubroutineType(types: !61)
!61 = !{!62, !58, !63, !10}
!62 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!63 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !11)
