Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ7RZT5QKGQEKGDICHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A25F27CF58
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:49 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id e2sf4771088ybc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386728; cv=pass;
        d=google.com; s=arc-20160816;
        b=WMp4znHC9pkmTVf6tZq2wV3EsdWtEb/ks6NVSQnGfQhKWbs7i8SMi+ckiJj292XA8+
         jbVb3AtsXIUZpwJqjXNcDlPBIc1JbyZF4/wiiOkQp7ONQ9dxV9PmX7sGNgn/8B9A3jza
         bgoPyh2YU9RDI7rbyypu3oSHp8etivnfVBOeseDtJQL8tneJs59oD9x8t9z3qLuRdRQm
         kc8Di2sh0UqlOHZB4RxocVpLyQNMEyhcTrD4mTwA6TOirM02UNlzwTJ0dHJpnTapSAWg
         VyrVJJFfBOCRWHMhcqRJml602QNNxS/MeAytJpATVre6b8mmhTyawLE9mOJb9Md3YN45
         GdNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EDo72bzxPsyN2tuB8H9WAMhT9yH9GBKI1/KVgc+EECI=;
        b=O/QAw3VC56RvFWp+KPfKbeI1dzPMRGQGJbcTbkodddF+e1RuL1sD+mqR2CCqMJCX+6
         k6pcYpUDqtptOnoKpIZDaQkheeVFpHe/01vp3PO9uPuaekUZh30vQ+eYhe9XBLnkkqeh
         VwvQNm0IhRISaSc4rUvYnpvuIRxMmxudWrrmyqGuoIi/7jTteShZvIiadalL/GE1W6Lh
         LfXhClGVXKNE9dmRI7FuzAX6sjYmHn47wpLDiDwbe+KjEZUaSLE6zh8qSdpjUZB+1jk0
         5GFMbSf0mxKDtKrfTxU5+WRkb0fEkCxBLG4F7MXs2F+jLd8zU1dEi95A8LKJcr51wU2p
         AQmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d25sdqTR;
       spf=pass (google.com: domain of 35jhzxwukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35jhzXwUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EDo72bzxPsyN2tuB8H9WAMhT9yH9GBKI1/KVgc+EECI=;
        b=F77T0FzZLcoriZQaXd5wWiDShBCEsd6d2yiHEGzLFEcQmsP6YzCZKGn8r/4PclDgOo
         RxVqm9sX3D353wRpLUuI7eydECZqG09S7UcB8wSPlggB8aRmiW5HQifWHSFpRW1Sf1tB
         7NF9SVlKu/tzThhwFhS8KkHDqSC6xGA+sJnHCgwgIGxC8od7grKMCAbWLeIj8/gWZMxQ
         9B3FWHmc7aYqKmTzvElyFtVSMVaJAfhHNeewDm3bQ2ldefvO7M9F/FwrfBhqBK305kSq
         tz0LSjjssk1vNEUOlwgVpf7NNd2sDKF2/PAMbYY/bJBIC42rajavtQ2dExt1tTc/tQ0D
         wOzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDo72bzxPsyN2tuB8H9WAMhT9yH9GBKI1/KVgc+EECI=;
        b=QhY4uNXz/nV8/7R4Yx0yIOG+IM5NJUdKMo/umvKc1rm4NpVlPgI3syfc6luxGcjtN0
         pzX0x2hTMoXOUfHJq0u5aD9XvpuqZkOQfqyW1BZgwfjkaRAQhxw3/HXCWhoiBnt2k7vJ
         uBUtZzf3cOi7+E2FFjUd/V/krkk1BwxVvS1Y/8DQY4NKu7DppwwORsf/tzr7PsHI6N+1
         7DaTq0qVs4AQguDR+gvcmOmj+bVJF0RCyu1d/audBzrmF3crBi0AcNVuC78lsi7Hf91O
         noE0i9PUOAwQvquxaQ4Zz0scXl75ztooOvMZcVQfjIGLa6zKrbQJ45t1O34aoMByuCwP
         W+gg==
X-Gm-Message-State: AOAM5304ifkcQhAHcPBcP0pV+Vh67KjwK4N5Y6dBZ8PwKnndM+BOEVnZ
	86Bl5Y/bzUCtMDOcCVN3jnM=
X-Google-Smtp-Source: ABdhPJyTvFSkfC7xjYBagKduU7egGBQQOnV4mxGBCdw17PXrN0yQwmhUiBzvMfkffJ/yrbSpEGRDQA==
X-Received: by 2002:a25:1381:: with SMTP id 123mr6476799ybt.406.1601386728008;
        Tue, 29 Sep 2020 06:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:546:: with SMTP id r6ls2152242ybp.1.gmail; Tue, 29 Sep
 2020 06:38:47 -0700 (PDT)
X-Received: by 2002:a25:ba81:: with SMTP id s1mr6612409ybg.0.1601386727480;
        Tue, 29 Sep 2020 06:38:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386727; cv=none;
        d=google.com; s=arc-20160816;
        b=RDRlEUV7cAG4iKiqhaPhzBwbIvYsXKUcJnqc4GdPI7Ks3bIfcWBFa1+Hfoh5klaZTA
         EkkF2uUPh2Yh5NnnmiiWqEmpQMNL6RwIuWwuqpNtfQ9UJtXjyh41IAAFx/P9HC8VuZaa
         1IBVa8mtul4VnVEPztW9mWp2By6WgvkOReZB8e52vGHsES6XUz9cA5ih91HB6aoojsvW
         M7Iar435Zd5xJFEBN2asnjnRzYijTdwGxg4HWPx6z6Owldc0YScYVq1ZHjOMx0tugp/w
         8W4pSz71pV31oQT8DPgSayVTcqkiKWp8ISpb7S2X/nMQb7PszycpcTLYK+IPHB5a8s6H
         nAzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1b8StUxuKVuYd1wam6EMRlTfs7xw+c/0eMbKAsoXFrU=;
        b=H7lepmQ7EFmjqGITsA9GxcySY40qrZDVlmUnK/tZd0YGUTAmqd2jytea6KRNH9O+k6
         cSdP+dA3qEYnd+my+EzQuY2e/98GlpJHTUQpLjJYFT4r0F3dCYsmHo+18HiXrqdVrAp2
         6h53tU8KyjVSEiJxoL1UkabRvs1xsmP+mB/ajuUR67XnrlrjIWMn+iNxJ1qYTQY6N7Wo
         PIadfeg2TDukio6duUWjBs+GX3Gi0RVGpFCgj3sKXokmgADtnmfVgaNjSEL1FgrPLEsB
         bZHCJhmQxLYJpxX7Tmxu+kTjMJ8NCTeMmCARzsEAy0Ud+SXN1TLVBI6dfheH2IbD2pkj
         tOag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d25sdqTR;
       spf=pass (google.com: domain of 35jhzxwukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35jhzXwUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id l203si286944ybf.0.2020.09.29.06.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35jhzxwukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 7so2973085qtp.18
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:47 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4e4e:: with SMTP id eb14mr4552265qvb.41.1601386726953;
 Tue, 29 Sep 2020 06:38:46 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:05 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-3-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
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
 header.i=@google.com header.s=20161025 header.b=d25sdqTR;       spf=pass
 (google.com: domain of 35jhzxwukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=35jhzXwUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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
v4:
* Define __kfence_pool_attrs.
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
index 000000000000..98fb1cd80026
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
+#define __kfence_pool_attrs __aligned(PAGE_SIZE)
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-3-elver%40google.com.
