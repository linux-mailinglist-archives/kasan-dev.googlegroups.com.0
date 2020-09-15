Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQH7QL5QKGQEZXGZWWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B097426A627
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:05 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id u8sf2566479ilc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176064; cv=pass;
        d=google.com; s=arc-20160816;
        b=XOTx+06pwm37pYdNyuSlUslC5BhSarMzr5KVuO/WhWyfbbJG1h6PzjUWP7dszlLTbp
         JoVdJSau8QnbblpSyzUJDzEDPiMB4B2cruKQK6X4wt5ZmiXLpUkqZ9leEQHwM3ZVeHRT
         BNmCcLHYM9IAyySVHHK5CQnSyXoQzxuSf7J4lqpR0wuvsFKQU0Ul9RzEvI/EM1qxSsbP
         XmhxFqfnGpDrAghrj+2yT5cvk5UxZIUfb6KkXalZNmuao82ZNRAsqcivHpAmkLM6QUlO
         Gyb8fExFx751wGJLYs2TXiFjx/NyamAC/l0M2l50+QGJ5Rx69bAEOUiHRd5is38e8Bdj
         uZ3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yjLQ4NXdas7xD37JajE1OOShL6jUZHkGajjpFSoFZbU=;
        b=AtPOj9VzocEOxgzcpSoxSwrNfIQEj1GWqODuJYUdXHngeeFeSewfEnhB2dzS7FgX0X
         VCnYKkHgg8jUzIY7Z9VU1TyJYP94Z44/vJ25WY3ST8dpYrvtqmF8ky7CkUyyz00gUrzH
         9IoS6tAt4gpEu+Kw0FjZH+7Qersnyir639J5kEbUkrPYzP/VMQ+CIJEr6f0X+5HokI7f
         I450o/+z3SsurBiakHfbeABu2chjoeLmUcq6ZhRdjcO7tkQYTndk+Mn/G4l1Y6LtWHx3
         pK7F95PunerxiQ5K7tAXAEPBZLIxsPZTaBUnx4oXwlVJtJvgSaPvt2InOaBGHYMyGGHC
         /bTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ic5gm/5J";
       spf=pass (google.com: domain of 3v79gxwukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v79gXwUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yjLQ4NXdas7xD37JajE1OOShL6jUZHkGajjpFSoFZbU=;
        b=d/6aFc9i1TZgvytUZ2zjsioldR8+Meml4ImnBBugntGmluMNcQEdaZVTgchQgvr/YB
         Zp/HGOg7lk12bfX9TnSi8cNyoLE1XQmiuY3jUNitqvtx3VweHuXYDbISeIDgpRfbRFKT
         OFFMnDyfNpx0RaKthH0BxdS2WWZaFrLbmwJ/lUcCgRaMmLH7xxbbkw0TZ+F1Lfhlu//V
         JzSibXI6O2wGk7OUs5jm7V9XXk87s05wrchJ5gRvjhqRWz2blosIb3KgTHmQmF7w15KM
         PNyoIsfJNCYtsnyN8qrzw6ucmJMb1Hz+X8y05wu0DJ+ktLV52ec34Jxdc+IuxIRK7Mu8
         1yQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yjLQ4NXdas7xD37JajE1OOShL6jUZHkGajjpFSoFZbU=;
        b=mR8CouA0Xldtdk83GLt5ftDTclgY5VSV3/LGIHR1ShkxY0ZNDgJGCR/lKBFH/rwS4/
         qy2DJ3L4pIxbI43oZMsy5IzhIK77vq4oGqgSTgXR5nFkN6/dguyCJbm9wmW06bhAttTm
         KygsTQcXN1y3fUW/oLkHfgwn9ZIqc2JDOZlVli5qr5tMdJmtyVoAQEZOww+UKPVfTskw
         4eqe0vziwTdUlN1gEEEoaEbYqvW+vUmDO6flcebugAnwOftq7rQIkJzplLvoEmy8EZyC
         VkgJyoFGwYeoPjOt+P3owBvHy33Q5TRajNjmwZAMEMB/t8tIsXtb2dleUQV/E9iPbai2
         rWvg==
X-Gm-Message-State: AOAM5328y2Tg9Sdgl9dTUTu2fzS3Yzaksoi4Uji7xNOdvQTbD5h4Bssb
	ZkDpPw9X9z23kRIABePRG1o=
X-Google-Smtp-Source: ABdhPJwpWkSl2Euh7r3eLYbhNulqlhJEHGnZqIxuUoZs0wb7rkQCviFNagU0Jm4UZ3bVmJHBbXnjnA==
X-Received: by 2002:a92:d091:: with SMTP id h17mr9659203ilh.264.1600176064398;
        Tue, 15 Sep 2020 06:21:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:12d0:: with SMTP id v16ls1784198jas.8.gmail; Tue,
 15 Sep 2020 06:21:04 -0700 (PDT)
X-Received: by 2002:a02:234c:: with SMTP id u73mr17967272jau.141.1600176063992;
        Tue, 15 Sep 2020 06:21:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176063; cv=none;
        d=google.com; s=arc-20160816;
        b=oJsjAXU65vIR+zvAiWmcuCCjaISJkuTFmS5ZhRB9oK/vlNj7+aCmaVF2hBzdYe4SI6
         MykPWQb6NDXTzaWu78+LeOjObXsphjWVrcbjsqchvIUFfOcifFSBomRPBJlXAnNHCc/O
         4KLl9oXk3y8rR5pTbfUEN2rpSZKhsXGPd0o88EqaYPbOmzQBMCkNadZVnGnzlCt0p4s+
         FjapB5oYPcYz1msYHa21JlDh7Zu+Mlk25ZERMAIMeEPH1w+G7eZLIJoqWuB/xWCLKruR
         n1FTZ/iJj3KwqJdipVgyc8kGG2vmEOKVwyaMspGsY3aa//Mg0wCQNtvv6Qlid/SZbNjl
         QujA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=odW0Nb/rci20hhf4qlLrsuqbfMVKw2n0jytc4nSfGLw=;
        b=ZrE8eIJg8xt+PZAjKKcZCVCjVZyvwbMZ+aSVd6qY8t0hGaaUN6EAW0PdQS1gMorWTS
         1tEF5a9Qiv8ZD72HF2+Yc8QCYpQ+B1U7pXEMkXsNuWaBdzcNvZK96+pbV2A5EmlDCRpV
         6NnwdcckU7KS57xYHRiMht8LMoidne/WWK6W3lymfnG+6Uwl7M277NPnOH32QrgkEZ/z
         xmhx6kTsVEnsX8pvkcz6u73cbhBCKfCnnLR2oXSIZoOkdCOk6xRHXil9wH+qpQWSUanW
         f6B8dvbiuQA2InUdN9vrFPSHMf3b0G7D2JhbeiJocG9Oa7k2It+gKNFEqDaAH2ugLvxW
         fjOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ic5gm/5J";
       spf=pass (google.com: domain of 3v79gxwukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v79gXwUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id c10si63789iow.3.2020.09.15.06.21.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3v79gxwukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id m203so2805023qke.16
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:03 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:b902:: with SMTP id u2mr17508718qvf.7.1600176063190;
 Tue, 15 Sep 2020 06:21:03 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:38 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-3-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 02/10] x86, kfence: enable KFENCE for x86
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ic5gm/5J";       spf=pass
 (google.com: domain of 3v79gxwukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v79gXwUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

Add architecture specific implementation details for KFENCE and enable
KFENCE for the x86 architecture. In particular, this implements the
required interface in <asm/kfence.h> for setting up the pool and
providing helper functions for protecting and unprotecting pages.

For x86, we need to ensure that the pool uses 4K pages, which is done
using the set_memory_4k() helper function.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/Kconfig              |  2 ++
 arch/x86/include/asm/kfence.h | 60 +++++++++++++++++++++++++++++++++++
 arch/x86/mm/fault.c           |  4 +++
 3 files changed, 66 insertions(+)
 create mode 100644 arch/x86/include/asm/kfence.h

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 7101ac64bb20..e22dc722698c 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -144,6 +144,8 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KFENCE
+	select HAVE_ARCH_KFENCE_STATIC_POOL
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
new file mode 100644
index 000000000000..cf09e377faf9
--- /dev/null
+++ b/arch/x86/include/asm/kfence.h
@@ -0,0 +1,60 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef _ASM_X86_KFENCE_H
+#define _ASM_X86_KFENCE_H
+
+#include <linux/bug.h>
+#include <linux/kfence.h>
+
+#include <asm/pgalloc.h>
+#include <asm/pgtable.h>
+#include <asm/set_memory.h>
+#include <asm/tlbflush.h>
+
+/* The alignment should be at least a 4K page. */
+#define KFENCE_POOL_ALIGNMENT PAGE_SIZE
+
+/*
+ * The page fault handler entry function, up to which the stack trace is
+ * truncated in reports.
+ */
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "asm_exc_page_fault"
+
+/* Force 4K pages for __kfence_pool. */
+static inline bool arch_kfence_initialize_pool(void)
+{
+	unsigned long addr;
+
+	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
+	     addr += PAGE_SIZE) {
+		unsigned int level;
+
+		if (!lookup_address(addr, &level))
+			return false;
+
+		if (level != PG_LEVEL_4K)
+			set_memory_4k(addr, 1);
+	}
+
+	return true;
+}
+
+/* Protect the given page and flush TLBs. */
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	unsigned int level;
+	pte_t *pte = lookup_address(addr, &level);
+
+	if (!pte || level != PG_LEVEL_4K)
+		return false;
+
+	if (protect)
+		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
+	else
+		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
+
+	flush_tlb_one_kernel(addr);
+	return true;
+}
+
+#endif /* _ASM_X86_KFENCE_H */
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 6e3e8a124903..423e15ad5eb6 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -9,6 +9,7 @@
 #include <linux/kdebug.h>		/* oops_begin/end, ...		*/
 #include <linux/extable.h>		/* search_exception_tables	*/
 #include <linux/memblock.h>		/* max_low_pfn			*/
+#include <linux/kfence.h>		/* kfence_handle_page_fault	*/
 #include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
 #include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
 #include <linux/perf_event.h>		/* perf_sw_event		*/
@@ -701,6 +702,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
 	}
 #endif
 
+	if (kfence_handle_page_fault(address))
+		return;
+
 	/*
 	 * 32-bit:
 	 *
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-3-elver%40google.com.
