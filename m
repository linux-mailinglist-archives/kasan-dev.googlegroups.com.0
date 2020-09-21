Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEWUUL5QKGQEHZCAXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 88D9227255D
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:43 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id n19sf6889629oof.4
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694802; cv=pass;
        d=google.com; s=arc-20160816;
        b=K+Zfzx8JKvECEFXba7LctsPkS2ftuoweY28Aej+XLIv3HcQg4ZQDm0In77Gtvl/naW
         OJ+5sLRlhH3c26lHowGBDaWwE+x/WUXzy1glq7LGfNEGjkJeoLPmjn6ioDS18SvZ1tYT
         OonzXPg4zAbIW1oyUTHx/yWmHbsV8IhHWlnARn02amlmuexDDPUdWWXYZrOcHaEW+8O6
         HGfDwPHRvI0Qjm1C4KeoxYtXhBymXoXbuwj0fboetP6f/dTDf21TUA5bhKJBepLHnxgG
         e5dFQJcjiRxVU4cQ8dMt7P9bzOhcjZN68mvqcouPt57t2mObPzOwAdWVpZAjXAA/b5tp
         dCCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kivxr8pTgZwCxf4NdhVauhnrYBghsy7/FThSGU8ZSzw=;
        b=iCbi7aAE3Hh47wpDTjYS4gLnc+79MJIgXrNxWfeuwiWn8K7BPlDGifSz2cRgo5IZdP
         qdMEWc3IYagZ/Q1D3XYTXoGjxkErGqeUrBhrKq+ZgiG6EFDobMqVN9ccVAz/doKT1MJo
         5J+DzmhTAnWtK3jPW2P0z40GWgElSA4FGWvijUtZLzQseCGroyAeitO/7WIvN5ZcuRcH
         gpdKfoU8CQkrCh7i1ITlkHIr7BApRvHDKdDnKURp3LXpmsZIPcyPNaJhOGrtQwk5fjFA
         D6aYOkwpqouRqpiUU8FK14ecwedcGTA5MMGIg/u8ZG9tfIBDMOg/vbsiF6NNEKTjpyVr
         GKzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qL2wY6WB;
       spf=pass (google.com: domain of 3eapoxwukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3EapoXwUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kivxr8pTgZwCxf4NdhVauhnrYBghsy7/FThSGU8ZSzw=;
        b=K/ZB7/VKivCuICcu7T8ikFvvbHEXfX+pNbyZHZCR8BXAzvMrRPLfcCAmjC0pOtj9TN
         OD8IqvCafjwYJbteZZR3EXiWHXirird1bOLV0V6NJvfWPpXE7+36OxV+if8qw6QQVIxw
         y0WFecfS0Np1hwXVuXF6wOMYFyUD8N8vFk95MwT4UO9DXnpjCcUW/Gvcp0MphWD6RRgE
         rUmqfAEfCwVyHfuSlCChQh52TIQmmD7PVU1mhB21GcqKXKq2HS3y++ZK7zEA+BY5nGVt
         qfeoprc8rgiIE0Fr0fd6zdGHgxir9quycvZJCg2faWgr1PVh7zeXKuExf1R7UtiIznFV
         Y8og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kivxr8pTgZwCxf4NdhVauhnrYBghsy7/FThSGU8ZSzw=;
        b=hIn4KbuAUpo87TgGTyZ/OwkDf+a/G1P6Bfp4IYrqvGH41Ep73OLOwrwZH4rtXZH50w
         boU9AWKDJ4d/YgKVW0RhoqiS2BGnszTXYXW3Y49UEdsocyu6t1baKgPuXwuCzp19AEzh
         02YyCk60aP3o9O+Eyfv6rjJoNR0cnWikZBafqpTa8QCKernyG5j3yQRgqkaQy1BH5rak
         XnGrksTY7Ugx826tZarPnfk/OkcnYHKadYTw/KllnihyBpgcGVpc8lR6EQa4xaNgKoU0
         dcwqT4kGHNkbY/eyOXDNueN+IaDURf913uIDqBNF7n91EosvrI79QHqFxi78U+lVOTWd
         uQGw==
X-Gm-Message-State: AOAM533aJZfbL5P2NI6aHwDFyDKV0R2hjpNWxclppT0VEFrPqxzCLptk
	NL6JlskU8xZfUbwxpCrzDVk=
X-Google-Smtp-Source: ABdhPJxS52hmRt6tnBeAPoeAjUxMMSKdP0cgMwaM7Mu39V5u8/TAkBmo+4WrI2WhHlUw0Pk4X1OomA==
X-Received: by 2002:aca:50c2:: with SMTP id e185mr16559380oib.111.1600694802303;
        Mon, 21 Sep 2020 06:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:85:: with SMTP id a5ls2867213oto.10.gmail; Mon, 21
 Sep 2020 06:26:41 -0700 (PDT)
X-Received: by 2002:a9d:491:: with SMTP id 17mr29006122otm.338.1600694801882;
        Mon, 21 Sep 2020 06:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694801; cv=none;
        d=google.com; s=arc-20160816;
        b=kEm904GI9oD9RljhR0TkxnBpjfj+yH/pzSZ/ty26Ad2m92dmFK3du/tHM+KsYSEJs0
         OoRYSBoRmCPVRI4dK8yuozvX1UaHa0vM7gfgy4sthkPRthWaIIQYlMOsP7Lf93p23bxc
         GCbH3e34vzFK+BrV3U90uwmtA165cP6e1226wpMEueI5DxmlVoCaGkRTgPtUQXLzD4rD
         NtzHSn5qbpnmtJN1r62O8tI/QcmBhevqdvJ2L11UJSz6Kqz9qxmuAmj+trFIYsXp1swi
         Te060Gu0YomEQKaILAnJVK/2CELc1SC0EB5X05wrs6qqsqufxRD3QEMy5CDkxAjHRS7y
         Degw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=wt63fMbRtF63+v7/GuudoZYJcaqBUfqT28LRHuRusC0=;
        b=bCccKQ6CLsaDhJrCljSV0b58sk4OrzKThiDBN2CaPzSzxjofy5Yv1R1ynIQ4tTEDAR
         lFTiYai3QArPvfiGlAYBkUa8wEDtDdMVHK9z6O2hTCeYsEUDo9JLnQhUzkYjLZivGAfK
         5v9VQthBdI6bL9wn3wgRtxVNlhGV+Iw4E/0e81DZtz6d66EM+Syv161TZkn1EFNCoIqz
         4OH7rLbfJpU3MkpfUKRpZEyhoXjBRxcXAw+cQYw8fi3NxfXpijCpxvVcjv6hxmLtoFxb
         I+dcNcLJlZ/ixrazQbeP1PPLL0UlFx6Y7xaBfJd145P7e24qx8RVqdChVGq5iTsumJ57
         fW3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qL2wY6WB;
       spf=pass (google.com: domain of 3eapoxwukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3EapoXwUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id w202si290492oif.4.2020.09.21.06.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eapoxwukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id f185so12905384ybf.17
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:41 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a25:69cb:: with SMTP id e194mr49735261ybc.243.1600694801234;
 Mon, 21 Sep 2020 06:26:41 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:03 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-3-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 02/10] x86, kfence: enable KFENCE for x86
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qL2wY6WB;       spf=pass
 (google.com: domain of 3eapoxwukcqoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3EapoXwUKCQoov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-3-elver%40google.com.
