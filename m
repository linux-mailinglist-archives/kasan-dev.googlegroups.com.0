Return-Path: <kasan-dev+bncBAABB47JUGTAMGQEWGQBCSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0855B76A73F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Aug 2023 04:59:01 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-55e16833517sf8982489eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690858739; cv=pass;
        d=google.com; s=arc-20160816;
        b=MrKtcPdepGugfdMtfeKOw/msVX5CAB2nwHt8SOAfCkJ/paLB6KH8SXiwSvu7hMhCTA
         jfEJY+uSDpjprg0sIor06RKLXpzBdB+21BkLgO6C7hGDThGQzURz9FpNwEyp+gMCNP58
         4AoSDEG6rN7pJ/+dJU+SKzIW4ngz8qSc44S8smyXYmqAWvbTcQHjbS+ljC+Papg8jkrZ
         GRvvLZ64hDyb1kBZUafknwrGLIX3jhZKD3nDbzvzvlgMUHfaz3CqBoN0mJrkx8xSrqh5
         RBntC3vC8Hckavld0afgv7CODXc76Z1iFoAZh+5k9HKe8JU/+7puiv9tonrhYpJbHRvA
         Hd6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=13NsrwuL7PKLhobM2VgBz91TqpH5oCVdMmfr4YCdlxg=;
        fh=5Ak/orCUNoJHBLn3w/zIcu/MsLJUa+ny7ZtfJx9Ps04=;
        b=N47p++TdAy5jPSmVbU6SUcSGgifSOAdsNxAcA2UFhLSLjzP2hPPgVJ51gaR2giSbnn
         aomwBkWBzhITH94g1ylFeWQ8wc8+55NLrsT60TdCBBN5VxuAgXGnsz4izbw4Lf4OFVVg
         R/qMBsQe7+9CsC72aXYJl5s4LUiXJgjqo/RLSwEhlkq5GerAZDMs6EA5xgeqrvk9n5Kr
         wExu1tGAlJSC1orsbfIB18ZHYLh13tCaLZ/pRkuMzplyD1Uzm65PcqN3SW/TwCyN1o+I
         bGj67LtcOPH8rZf13RvIwzpZ+kWCtF7CZzpbq2UySm2SDnHK2D9W84v0cN5BHUIP7/r/
         y4uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690858739; x=1691463539;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=13NsrwuL7PKLhobM2VgBz91TqpH5oCVdMmfr4YCdlxg=;
        b=gAISktfjBXiu9DXxs7O7aoMUeDOtsJum9Go7x1kOUwNzhAsDCtCbtN/LnxZ3SW7SkA
         0Dq+UtEd1rwqX+VZw2n4/3QoIR5kQVvlllc27WOUW8wIU2URO+yj1X4qHUzUU7ShZn4F
         xHv7i8yGcHGVJ1BWvlq9kpsdoqlu8eG/pP0gSvkXCm9p41PYSe/Bfo74iAJNTHYiqePJ
         U6B/8ogkkC8gQ65+xl18aGYXbgbEORz44C3ZQJEFMfCj8kaQ/+ozq7ACywEv4GwtjsVc
         I5wbPnflayewfzUlySSuqYrkXzX66q611jGwmnx6uyn5nm5kzRwCWQIB3Pf9HHqkekOZ
         tTmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690858739; x=1691463539;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=13NsrwuL7PKLhobM2VgBz91TqpH5oCVdMmfr4YCdlxg=;
        b=U7GaaY4rZIFmRTlNzVeGey8UxFHKNoyeEtos28COWgWS6Hu83iIb9zV23QzxC/oA+j
         3PPwdvqGZCDzQeWaKpclMVez3QfSCAAlUKAPky4W7yDJcip+Y6tpHDHTEVvYpUi4M/yZ
         vfopHFQFWpm+n521pjbNrW2Q18cWWgurKS6qcW7n6A45TsO0j9GJUInHNmWpD0fXenas
         No6Vtlr+PkMdoeUA7g/lpbscJDuEFwOlP/AGRXwJ0Q+k9JRLofkhiJcQbtShztcw9kvx
         G5X7bHNuKZWpRNwk8BolxzGTILvsZTCsGzjrGHchvCzns8Y0TJj+HGhm2akbK48KALG6
         Z0hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbQRMQuU4tfkI9q3/Jv25qHiZ5nz4N2v8inJFEGGO433iZVPf6G
	AgO9tEoKhT+ojoHHP48ZMCE=
X-Google-Smtp-Source: APBJJlGsJy6QPLv4dZ56ZYrvLOMLZ55IyQg4vro8vUK5aL8c+lCiTI4lyYnrVHDLWQb1GXbxSApYJA==
X-Received: by 2002:a4a:d2c8:0:b0:56c:7120:835f with SMTP id j8-20020a4ad2c8000000b0056c7120835fmr8962632oos.5.1690858739343;
        Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3388:0:b0:563:492f:3514 with SMTP id q130-20020a4a3388000000b00563492f3514ls2569732ooq.0.-pod-prod-09-us;
 Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
X-Received: by 2002:a05:6808:48b:b0:3a4:2829:326d with SMTP id z11-20020a056808048b00b003a42829326dmr12128974oid.14.1690858738876;
        Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690858738; cv=none;
        d=google.com; s=arc-20160816;
        b=A+cV/Lbm1sBhFCjH0D7Rqz1l9hTVtGSbLs7Cu0U+UQYstr7JsKKi9VeIYcPMJowVz4
         VublTuYr1qbHzD8jUow41gCnRvd6b+RXHQx1FpDqJpQh0NSaBNf3APrkj0wL5kkveGKZ
         y0EdNrIIQqcqFWoSQKTqhm7b0Nzhd+OpOO89amFL6O79rDRvrJtvrtl3o9BTHLwThnD4
         lGVNKnAw4RPXBJ60q4aXMBs5N3+hG0BsCtORSGRMPEbEgZFMs7tVc4QEsSaLILSwTKHJ
         5Nw1XJ3PF3hQVSCsYc17AXuK9Mwxg9xCtdtPffOSLD2YqgT0dx3dj4IUYiHMh07TK+Xx
         a5DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=HbmjEkCG/Gluq3NmseIYaINXkJ0ULNrvz36rHv07DD4=;
        fh=5Ak/orCUNoJHBLn3w/zIcu/MsLJUa+ny7ZtfJx9Ps04=;
        b=R5cT41X8kBnp7CBAihfPqwOfQN98EbZSdnqbL/e5EsmUgZGcfzEKlc7z33omvcBWtP
         bNTj4dipqURi0bSoEQAMrrYSlULw2fLlKUArOSFDQe4A7IQJrdtlLnzqclikgxR9HIAP
         BJ21b6vgtE0XpLRZreszL/EhcN/sT8rWebDI+SHR6K3tQZFhWdLd9/4bGfI3n5Lefufn
         qoLNBUCTl8dNXQ+lxnok2yR21jRAES+lpNISEwaWS75mojBUSI7J/D6ajCOKhigYBeeV
         VXxTc2Wp+YRPJ0GizfRqa1q/tnih5hcqIxtDmLw2PvOhKFlzHrMa5viu7yU+CDvRX078
         mtTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id w17-20020a17090a8a1100b00262c6d85bdbsi482022pjn.0.2023.07.31.19.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Jul 2023 19:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 41ffdf2160a04e229baabc2604a40ff5-20230801
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:0ce1f64f-6f9f-47bd-b73a-093f8ba3474a,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:0ce1f64f-6f9f-47bd-b73a-093f8ba3474a,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:2dbeab42-d291-4e62-b539-43d7d78362ba,B
	ulkID:230801105842XBL3QNGZ,BulkQuantity:0,Recheck:0,SF:17|19|44|38|24|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI
X-UUID: 41ffdf2160a04e229baabc2604a40ff5-20230801
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 138458878; Tue, 01 Aug 2023 10:58:42 +0800
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
	Enze Li <lienze@kylinos.cn>,
	Jinyang He <hejinyang@loongson.cn>
Subject: [PATCH 3/4 v3] LoongArch: Get stack without NMI when providing regs parameter
Date: Tue,  1 Aug 2023 10:58:14 +0800
Message-Id: <20230801025815.2436293-4-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230801025815.2436293-1-lienze@kylinos.cn>
References: <20230801025815.2436293-1-lienze@kylinos.cn>
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

Co-authored-by: Jinyang He <hejinyang@loongson.cn>
Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/kernel/stacktrace.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/arch/loongarch/kernel/stacktrace.c b/arch/loongarch/kernel/stacktrace.c
index 2463d2fea21f..92270f14db94 100644
--- a/arch/loongarch/kernel/stacktrace.c
+++ b/arch/loongarch/kernel/stacktrace.c
@@ -18,17 +18,19 @@ void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
 	struct pt_regs dummyregs;
 	struct unwind_state state;
 
-	regs = &dummyregs;
+	if (!regs) {
+		regs = &dummyregs;
 
-	if (task == current) {
-		regs->regs[3] = (unsigned long)__builtin_frame_address(0);
-		regs->csr_era = (unsigned long)__builtin_return_address(0);
-	} else {
-		regs->regs[3] = thread_saved_fp(task);
-		regs->csr_era = thread_saved_ra(task);
+		if (task == current) {
+			regs->regs[3] = (unsigned long)__builtin_frame_address(0);
+			regs->csr_era = (unsigned long)__builtin_return_address(0);
+		} else {
+			regs->regs[3] = thread_saved_fp(task);
+			regs->csr_era = thread_saved_ra(task);
+		}
+		regs->regs[1] = 0;
 	}
 
-	regs->regs[1] = 0;
 	for (unwind_start(&state, task, regs);
 	     !unwind_done(&state) && !unwind_error(&state); unwind_next_frame(&state)) {
 		addr = unwind_get_return_address(&state);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230801025815.2436293-4-lienze%40kylinos.cn.
