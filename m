Return-Path: <kasan-dev+bncBAABB7N532SQMGQEIVA6KFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AA31759046
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 10:29:50 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-56364632e59sf9087265eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 01:29:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689755389; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OTATDMUZ6AftxmmihUybazp/P/ravoSQgyGTWNxSt5zKpu7DwvYitHMKcTzSdE3Ez
         MonyQ2b/kxta4Q9Xo0KYEqUDGAvQWKQqHMzKYBtcYNmnFH8gMNvz4r9FsvbRdgVd4F83
         eMQxNg/yNUQvfUDJx1ttIJSdzkHpJ+gGaNUbgSOSCu0MbrEpKr9MZ/+/C3mwHnz1nLiN
         FrEAczuRnXmRsWvoZoB/4aR1M2hONpYRkdJHNPbfGnVHROwfONl3x6FEChugNz8JkQfB
         5J/PFoBUSTzQ4Rk2zWblYuMZF1ugb0MJm2D2wVqeVmQrvplDns/4f//wgpb8oXPUG+AQ
         sWAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uIDvn3JDhbUG6HulGfFSbC5sglp4QUyUOu2XGAts7MI=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=XEjXCaWcCyUzx8bijFiJq08PHxK/XZChxEVvmXdFPCnkSf1n6aIHEmU6kR/rS2KNQY
         qJMkLtOkhmCJFgeASqqyQFAfnIliPiaHuW9SsXox0EK3Fb9Gxkb6OM80anK+acVuOhrQ
         S8DmpUkdM8tOjQGIxV3GWWUBBbFDmNI7eDh/7z1pfxcxzwr2zZC6MmjZ14Ha0G2jFWR3
         Ml12n8xAj6u8Zu8s4iRgePr/yczXx2+P41nRDOrz40btV8vAV8po0hSU6tZgl4xTBtIu
         phPamWSjLbw1kIFNVbR6B+6ePnaPulGaRrKy9s3ZfRtNZxEp/CjSI4/mPXPve12I4A5h
         uZLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689755389; x=1692347389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uIDvn3JDhbUG6HulGfFSbC5sglp4QUyUOu2XGAts7MI=;
        b=IDlPKhg2q6ZkjEiFJ8RDxkXT5w37YQ4s0eShogHnZV7T9dakgi924kpJPX/MY/K7XH
         XcLKnxqZsL+B8WD4gjI+YvSVxlDuUu13rDWHcbUYnCvNloz5qCqQuNTXs+h2rLr9TnHe
         0AxsOyniKdoDg3fXDIrFx84G/4OoQgp8cDAlAt6h+mRHigy5O0S7gwpab58t2lJPWwjc
         gSz7BrVcF9oKzswOlQMaIQTIfcK9zxxAsVEF5dxrPdOhXRYPosffQatrKRHJLbMZIW0v
         hbdWofEiGRC+00huUXYT+pUDjnLYqxwqfG7tjKBQjoZ9e1sz855+2wqqbEDjC2JmncAD
         o0yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689755389; x=1692347389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uIDvn3JDhbUG6HulGfFSbC5sglp4QUyUOu2XGAts7MI=;
        b=URyJD0m60WrR9qzC71QTQw1rSsyB08UKE+at20VwmXxg8tPO5fMmGaHkDpt3MuRXmI
         6FrXJXVWUsdFHkEhC56SW0iHAg2w3ESrr2PcjtnFD4zoRC7gVIwgBNVg+ZIdb3GEtHJo
         i+UarSqEDerX7E7XfK473ilCU/IlEPMbRXUN8wv2ZbIkzMFw0qVjZvBN2YJ4bwBbRZZK
         cNImbwF7fnSDHHhCd0KO7PZ7cK1umj0Z6UAjmyHPhWDiz+mn23Xlm/8JNbjT/dZmjXCP
         Bke4q2LCyXLx2r6RBJuhKST6bjjcuxYUx531mKb/dVA6E/tkLN/zPN6kTxVUY/9cThcA
         tuIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaLNGrzH9Tr7lB2v9IL3+jKAcjOLPnO9c3ttK2GZO4d8DH1HjrV
	8vL8EC+QKdq1zuRMDts25k4=
X-Google-Smtp-Source: APBJJlHepABfivbW9+lGOa3HFKOqcW/Evy9NqNqo8YJvg4GUitpz73BtCh8nC/00Wv1ohQJAbDJkAg==
X-Received: by 2002:a4a:4e83:0:b0:566:f69c:a6e4 with SMTP id r125-20020a4a4e83000000b00566f69ca6e4mr1148786ooa.9.1689755389236;
        Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49c4:0:b0:560:abe3:c26a with SMTP id z187-20020a4a49c4000000b00560abe3c26als5362252ooa.2.-pod-prod-03-us;
 Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
X-Received: by 2002:a05:6808:1292:b0:3a4:31c9:6849 with SMTP id a18-20020a056808129200b003a431c96849mr1890678oiw.54.1689755388742;
        Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689755388; cv=none;
        d=google.com; s=arc-20160816;
        b=RRgvncO93nySbjR/DJs+DHcnqLuTvCAMVbYlS1mOzsLre1S32JgxE9EzE5uoia+bX7
         yozoEetgA4AWVPS/QL4Cug1y8M/5D18KMR7nDExdpTCfKt3UoOXso10umoDKnvHqDvic
         A36OXmc2fk4zYdM9ZsypyNp7cMOG5ntYbgS9frzLANp2arwuo/NPwvuAIy53VIhXqvt8
         +ihTDDwrYs6+JLUVpbSW+UafUIdzTem4ILOt0Zu55huI6MzgVhaCjhoreCz1EvY1AHke
         p1AvxlCwPEfnw6W1SxcI5Yar7IrLQtcItKB7Aakb8S7brmRvDNcTx2YAGWHHGztA2SvV
         v5uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=is/o2XlXfziPQYbVwed6ZpOrsYYBjuEMJmcxzrFssG8=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=gYvMgyzzp+KyYwrgmuW5t/2yOd25XMxfpEkbvno0IFfpFgLPy4mV72tMghAur9Tj0r
         Y81MYIc2t81gesrV/7hRK1LpngnS/JRfPpmlB+wx7bHuJpR/7H7GCwhqvx/IIjUvUSqr
         mQxRc/jqjfkX+heXx/P6s51Cm3ip7Qx/+tljwsquVKwG579YnR2JdQQHGtVmm0qJHHaG
         Wi3ojXeq29IXSnciYQQlxbTeC8GR5+NLuMcK6P4AW4r4wcBErJFa4iO1VpkNMpnnKp1h
         vRhTrtzWKVvmFnKmXuRMbjRGiz1J3pMKCgQ/5eD0AJ4lowse3hki+uNZ4qB2HCulsgRg
         LVaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id cp14-20020a056808358e00b003a4257a3cc8si217536oib.0.2023.07.19.01.29.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jul 2023 01:29:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 25f9113b33364f9c9293b35a713a92b1-20230719
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:e4294bf5-82fa-43da-a7e8-27813948fcc4,IP:25,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:10
X-CID-INFO: VERSION:1.1.28,REQID:e4294bf5-82fa-43da-a7e8-27813948fcc4,IP:25,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:10
X-CID-META: VersionHash:176cd25,CLOUDID:caf5d58e-7caa-48c2-8dbb-206f0389473c,B
	ulkID:230719161451V1QFHYNV,BulkQuantity:1,Recheck:0,SF:19|44|38|24|17|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 25f9113b33364f9c9293b35a713a92b1-20230719
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 2096309486; Wed, 19 Jul 2023 16:28:18 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 2/4] LoongArch: Get stack without NMI when providing regs parameter
Date: Wed, 19 Jul 2023 16:27:30 +0800
Message-Id: <20230719082732.2189747-3-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230719082732.2189747-1-lienze@kylinos.cn>
References: <20230719082732.2189747-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Currently, executing arch_stack_walk can only get the full stack
information including NMI.  This is because the implementation
of arch_stack_walk is forced to ignore the information passed by the
regs parameter and use the current stack information instead.

For some detection systems like KFENCE, only partial stack information
is needed.  In particular, the stack frame where the interrupt occurred.

To support KFENCE, this patch modifies the implementation of the
arch_stack_walk function so that if this function is called with the
regs argument passed, it retains all the stack information in regs and
uses it to provide accurate information.

Before the patch applied, I get,
[    1.531195 ] ==================================================================
[    1.531442 ] BUG: KFENCE: out-of-bounds read in stack_trace_save_regs+0x48/0x6c
[    1.531442 ]
[    1.531900 ] Out-of-bounds read at 0xffff800012267fff (1B left of kfence-#12):
[    1.532046 ]  stack_trace_save_regs+0x48/0x6c
[    1.532169 ]  kfence_report_error+0xa4/0x528
[    1.532276 ]  kfence_handle_page_fault+0x124/0x270
[    1.532388 ]  no_context+0x50/0x94
[    1.532453 ]  do_page_fault+0x1a8/0x36c
[    1.532524 ]  tlb_do_page_fault_0+0x118/0x1b4
[    1.532623 ]  test_out_of_bounds_read+0xa0/0x1d8
[    1.532745 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
[    1.532854 ]  kthread+0x124/0x130
[    1.532922 ]  ret_from_kernel_thread+0xc/0xa4
<snip>

With this patch applied, I get the correct stack information.
[    1.320220 ] ==================================================================
[    1.320401 ] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa8/0x1d8
[    1.320401 ]
[    1.320898 ] Out-of-bounds read at 0xffff800012257fff (1B left of kfence-#10):
[    1.321134 ]  test_out_of_bounds_read+0xa8/0x1d8
[    1.321264 ]  kunit_generic_run_threadfn_adapter+0x1c/0x28
[    1.321392 ]  kthread+0x124/0x130
[    1.321459 ]  ret_from_kernel_thread+0xc/0xa4
<snip>

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/kernel/stacktrace.c | 16 ++++++++++------
 1 file changed, 10 insertions(+), 6 deletions(-)

diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/stacktrace.c
index 2463d2fea21f..21f60811e26f 100644
--- a/arch/loongarch/kernel/stacktrace.c
+++ b/arch/loongarch/kernel/stacktrace.c
@@ -18,16 +18,20 @@ void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
 	struct pt_regs dummyregs;
 	struct unwind_state state;
 
-	regs = &dummyregs;
-
 	if (task == current) {
-		regs->regs[3] = (unsigned long)__builtin_frame_address(0);
-		regs->csr_era = (unsigned long)__builtin_return_address(0);
+		if (regs)
+			memcpy(&dummyregs, regs, sizeof(*regs));
+		else {
+			dummyregs.regs[3] = (unsigned long)__builtin_frame_address(0);
+			dummyregs.csr_era = (unsigned long)__builtin_return_address(0);
+		}
 	} else {
-		regs->regs[3] = thread_saved_fp(task);
-		regs->csr_era = thread_saved_ra(task);
+		dummyregs.regs[3] = thread_saved_fp(task);
+		dummyregs.csr_era = thread_saved_ra(task);
 	}
 
+	regs = &dummyregs;
+
 	regs->regs[1] = 0;
 	for (unwind_start(&state, task, regs);
 	     !unwind_done(&state) && !unwind_error(&state); unwind_next_frame(&state)) {
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230719082732.2189747-3-lienze%40kylinos.cn.
