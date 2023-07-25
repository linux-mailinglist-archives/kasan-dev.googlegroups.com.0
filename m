Return-Path: <kasan-dev+bncBAABBN6R7WSQMGQEGWHFFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0152D760A1C
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jul 2023 08:16:25 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-786a6443490sf269469139f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jul 2023 23:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690265783; cv=pass;
        d=google.com; s=arc-20160816;
        b=N/o11+UBJpBVzqkx50QsNpg68PKeMDQJLe3+nzhABgb6T9nlCMwUYuDdjbtWsa85tV
         WobqBm55Sy08S0Go8C61d6ZKe08E9ku4ML0b06LVIvjjN9ygZL5QpVCb4dPPo92CrUz2
         WxRgU+7kzTggQx2Z7DEqQvplmrffNH/GOiQW6v8A0oR69bsID3yew2UJUSJCp99KVamj
         1A6DEpIE0bLHiJAqeVjMOGWjdBHAozxZibNP+p6bHxKguyNzuvSPD/ZOHv9uYkBemuRY
         PolmQKUVApPUpKGiQIea/XJbxGibY6GrjlFCZmuNCQcsrgjMT6uw9jtDJlPpt/BCZAq1
         0aLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gCJ95olqTdqbfvMN1QiGqyDqVr+JPew5owp1H3I5e00=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=WFfveiIUzv7tW0y/PGpvvmgrhB8UwKTJkpddKiirVAnyxpM/k33aLoegp3VBJsoJ5E
         hL5mNct8SKXGrwAuPCcUKLmaeRFMs84A90RoaLqBYRdRJ2GHURn/yYTKJ94UJCJ43FQO
         2mHtliVD5FrTFcBZ2gdTUFu8qMQtg3n6mkMtHl2J/0XpbG78YtQFIRaQU/BmvmVFnKqK
         rmfq4KpYu5+EblzaTQ8OhmcVtascJe53vgg8U34kuZaHhFWMUpcXLhs3CoaYmEUzuXYs
         uR9+UhAZWjpvrJ97Op/d7WnycHT4kbRYt/EEpqb3ZL9nfwSR2/FN6qk8JF6Dh5j/duuA
         E8aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690265783; x=1690870583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gCJ95olqTdqbfvMN1QiGqyDqVr+JPew5owp1H3I5e00=;
        b=WcF/ORoNDTniA8sp7Cg5a9aAKcpkuSxK3OPUk/EiDsxZnGECwALzQw6UX+3qj3QWZm
         YzzhStPWKGr+VQHl6y3bvOKygqzmm9vQ4ryGDJzVOCfvbbxA4+ien1nE3ol7RClojVjx
         8AehWpUWY2wMt3Q/0kT547W3eXmtEwPdKIC4M0bAqstyTg2WrZgSr9GrtbB8WfjXkGQM
         srrhDW7lV/HfxhJGs/0VwblnSy0Up1A5OXPcCgTbUmEZIaot2ksxrI6AmWBvGK8sP7Vn
         +YnUk+3iXzDGU9dnESLgzn8gK3i/FYAL+lQ1vP+kQrkRQaaE8nEE6LWIDQMpzi83/9PR
         LzRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690265783; x=1690870583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gCJ95olqTdqbfvMN1QiGqyDqVr+JPew5owp1H3I5e00=;
        b=RUlDmotG6JUM0w+f7C9x7uBYJ4WDZ12RBfGOVrIkbYIujBMwK2brRoMEhvIpFfImrS
         qUtHoA9DpT5uvG5XsHu1v//a6/s9NLPbpVofNkLdrFzJgwAxbhRBJI/FaUHXbmP7IL4l
         1sQdGwd3Agnkc1iRgLmWHSPs1UkzaPd2s5RBCFtmdlCCm+YveQnjPQkxGW7+ddgqDRLs
         A5Ozk72ubeQnj/Xm6weY3j81EKS5fF9MFQCIyyyr3QEHz68nYxpa1qtSM4kIVHVArxxy
         E9D+qtIwEihlCaGmcIscENbfqnsN3dE7iirQ081D1QhuqQ5WvYC/m8dGZ/BpYq5RQMGi
         Xm8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZIVnfJiPjzstt2xopRDu+Xcg6rD4bpGtOl/Cx0yMiJUxckEusK
	yZ2U9W4yVEUBbMhFMbeOuQk=
X-Google-Smtp-Source: APBJJlE6ZQxUPvpr8/z8B3eZI3V8TTG+JYcI9f2zHeMkaPSE/ajBmhAiudMo9EJT8SAujGKmthz+Ag==
X-Received: by 2002:a05:6e02:e08:b0:346:61c4:3da0 with SMTP id a8-20020a056e020e0800b0034661c43da0mr1832458ilk.19.1690265783355;
        Mon, 24 Jul 2023 23:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:950b:0:b0:33b:3259:cfa9 with SMTP id y11-20020a92950b000000b0033b3259cfa9ls3312711ilh.1.-pod-prod-03-us;
 Mon, 24 Jul 2023 23:16:22 -0700 (PDT)
X-Received: by 2002:a05:6602:2984:b0:783:69e0:57a7 with SMTP id o4-20020a056602298400b0078369e057a7mr1803825ior.16.1690265782843;
        Mon, 24 Jul 2023 23:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690265782; cv=none;
        d=google.com; s=arc-20160816;
        b=zpvA5/DAPuRb6x7SBe0qaLM6+1hDhB00gRt39SFeYY7mK4ycY2v8MRTtK6jlPBxzSD
         lCqXlKUp7Z+2DihiYfMJ+Ep8nWwkL6R+DiGpMNXPszOsw3r8sF/HrAoOKEV3BEviXaGi
         yY663f1xS4AJKqkhsFPLuXKrK9kTcfEBR4+BM2vEm/6DImZIh11DoyxrqLIiPHQR0Xst
         3Y4OfkmgnC+UIu81zFwr5Pr5e7nw6xIrpZuBLac09YxABNFzDcgsVNfIL/MmBkRoTsxW
         ZaiG297PVOr9sypPigdcla8QNAkgAkTl6rrhAj6ByWNw7F7vCdX7IUIiMDNHZhGRGKi8
         lt1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Zt1iNttuBXY1BSNtMsh+aChBU07iLpi+OG55pqc1lzQ=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=d8U9yXT30hCWFRRQ3WPJqbKN7xTAqMr24xakze9eFCPlTyRTHw+rummLKQZEnyoXtM
         ULkrZEhYD8s5IKRSdjc8XBNgtPGd0bpwg1UpkyJgI90O45TeE8g27VDTLKlI6Ox0fpQu
         PFFy+zmsupLaOHTfZ6vCuHbbjrcBa803AWKwFzad/Min93YAel9UmAJGJxcBDg12R/qc
         altMsNeSCW0vGRcvcXw5bfVh4k0h875rQ+DaHtQXGDUPmV3lFuvUni0KUcz3QzqMsfms
         ak72TECJ2KGRqI8l9rrxUXb+lxrrs1dPfxtiS9T4KVfT41nBWhnyeF49KruBiIfz5X5Y
         ldEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id by22-20020a0566023a1600b007836de802c0si714272iob.1.2023.07.24.23.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jul 2023 23:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 900e072e26d147c683372e81b498ccb9-20230725
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:100611cf-fe0a-44aa-acb6-86579ba34183,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:100611cf-fe0a-44aa-acb6-86579ba34183,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:1d3b7fa0-0933-4333-8d4f-6c3c53ebd55b,B
	ulkID:230725141514IM3WVZYC,BulkQuantity:0,Recheck:0,SF:44|38|24|17|19|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 900e072e26d147c683372e81b498ccb9-20230725
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1616501915; Tue, 25 Jul 2023 14:15:11 +0800
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
Subject: [PATCH 2/4 v2] LoongArch: Get stack without NMI when providing regs parameter
Date: Tue, 25 Jul 2023 14:14:49 +0800
Message-Id: <20230725061451.1231480-3-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230725061451.1231480-1-lienze@kylinos.cn>
References: <20230725061451.1231480-1-lienze@kylinos.cn>
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

Currently, arch_stack_walk() can only get the full stack information
including NMI.  This is because the implementation of arch_stack_walk()
is forced to ignore the information passed by the regs parameter and use
the current stack information instead.

For some detection systems like KFENCE, only partial stack information
is needed.  In particular, the stack frame where the interrupt occurred.

To support KFENCE, this patch modifies the implementation of the
arch_stack_walk() function so that if this function is called with the
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
 arch/loongarch/kernel/stacktrace.c | 20 ++++++++++++++------
 1 file changed, 14 insertions(+), 6 deletions(-)

diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/stacktrace.c
index 2463d2fea21f..9dab30ae68ec 100644
--- a/arch/loongarch/kernel/stacktrace.c
+++ b/arch/loongarch/kernel/stacktrace.c
@@ -18,16 +18,24 @@ void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
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
+		if (regs)
+			memcpy(&dummyregs, regs, sizeof(*regs));
+		else {
+			dummyregs.regs[3] = thread_saved_fp(task);
+			dummyregs.csr_era = thread_saved_ra(task);
+		}
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230725061451.1231480-3-lienze%40kylinos.cn.
