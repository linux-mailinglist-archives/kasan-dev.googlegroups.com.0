Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7HQ3D5AKGQEJAQOD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D3B1925FB8D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:16 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id a144sf2849386wme.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486076; cv=pass;
        d=google.com; s=arc-20160816;
        b=f/Ly+5IHdLi4vw9nayBrdH7I10IwKsZDqW6B2l8Ys2VqigEMc5fM02eewKw+qrzLNW
         RMZwub5OlujDvE0JCURzsRl5VcIXJZXn4m8lSuTTFkH2VKgTKNYeWH66eDzu2RVswuNb
         kK7NAzVFIOGFKUaKKIUH4TunYEkXg4Ak0YmGku8x7P2MRQmpFhqngnVOxplKjmc1aKdU
         9qVojyDSUS2waP+NIFU0shczaj7y94yulEitbEpWzshv5tI/Ik7Ft9RjtrAwC1sRBrf9
         U+yfDWeLl7HQD12PiEWgVqhiy499kTgVycs7sSjHZeMpl+axn5MvFqIwnisHeott56QV
         Zxgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=rFn06p2i8nr7x8X3r5i0b8KsKzufNWZJirtNIr8B+G0=;
        b=zEYQFA7YNRBNPSrzH+2Oux1ProsjKyNwWAY4KOcj3XZ/yrjWj3LrS4l69TYpB6K80+
         J3BMxkcDY9Ct7ulfHYgjI2gZ4rmn1GzlIKOC1hENqDi9uYoRJleWIOaIQ7oAAOa5CncL
         MYIH0rNb4lqp0TNqEBA3vWwfunrujvfpuVWzuCZB5Pa9CaLCog9iOwX2IVkLDQ0x1lUx
         lFGMYSRfkTjEH7KFiRPRsGG4Cj+Vx5ylz45iLD2pKopl1tKzV3VxXSWnZImPJ5/Q2RhU
         gU4V0gT1y2SY8PNOuJpPzK2KP8XTc1JGiAe4fj9j/bdNn3Fct/Kdxp6SsoB4upOUiYP/
         Hsew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qrzGpgAI;
       spf=pass (google.com: domain of 3ejhwxwukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ejhWXwUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rFn06p2i8nr7x8X3r5i0b8KsKzufNWZJirtNIr8B+G0=;
        b=hsqUdIcMbNmki3O+wands6QFQJByU1FmdJv6z3S4I9pDf98+UugMWlHyyLtxwjyN1P
         GkQalqoHKx9fn72wUeZp9rrERQ/QQDRYQHgwDVtn48Vc4fDn1CcOMO6ZhyXZN91VvwNP
         CdEnzmrYCJKR8D4c3AGEkn24Er9POOqEDAO9D4JoN86TIgrkufAGSxgSmsVWqdzXwSNj
         7ISXfyaIxizABO8wq+pGyhn7k9djV0tfA1/nBpUDY6N1x4KgBDL7mmgGez1L7g34MS2z
         pXxbMAVs5oD3+sa1JPMmNwUc+X8OJVrmEa7FhRc1uTE3/mJ8PRVAXntMFa0AfnNoeamC
         0VMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rFn06p2i8nr7x8X3r5i0b8KsKzufNWZJirtNIr8B+G0=;
        b=hJHMqqwrRcimffXUQGByiK2Q0Q8aa7/OLoMKRioujWAFL22xMfeJSjtl7dyDije4EQ
         W74geNtDMv0oTsdDShISiE4QTdn+GG0flaNdL9+vV4eKQsoT/s/fqdFucsZzUWaeOR4I
         NZJT4NpB7y+SoM/w+Moz2cdMB/HkeZ0RDvxKeA9JliJpkFzJZA6Qi84rkJBfWv6PNJM6
         rb+jGSaIefZjfyeQUXDANmz7RTRGJ6+Di6pAp40MC5XG648ClwzQZldp+gIpf6iQW8Gg
         FUBmbEC76CTEOgG4sU7IeuiXxE2GLxmZ1Lg93ThasQHKDGYVg9jpxlXhrojSK12rohKA
         r3EA==
X-Gm-Message-State: AOAM530aZ9WpG8njOmLNQelX2zXw23I58+gHOWd1DapB4ZzMhzRBVnJ2
	995XFWmNkIxHuC9imIbcbhE=
X-Google-Smtp-Source: ABdhPJxLNrBurGd+9N/xoz+gtJsZOf0PIazdWSI2d05X/uZDrt+4rV2/Tm+eVsKm5/bO1yo7pWPQeQ==
X-Received: by 2002:adf:f203:: with SMTP id p3mr22124381wro.339.1599486076603;
        Mon, 07 Sep 2020 06:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:81d4:: with SMTP id c203ls8190135wmd.1.gmail; Mon, 07
 Sep 2020 06:41:15 -0700 (PDT)
X-Received: by 2002:a05:600c:214e:: with SMTP id v14mr21707719wml.118.1599486075621;
        Mon, 07 Sep 2020 06:41:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486075; cv=none;
        d=google.com; s=arc-20160816;
        b=Rv2Rv8rMIgo/mk1ifm89hEU4ZyAwEnGV1SUnfPUkraQaoC1h0whjDplWuRuVvTBxkm
         5M+Yf1v6rWmZpZsdH1Mo/sraphnxtTPYtZncSN4sH7qWdeWoCHXaSghQL/zr/vQ6sbHl
         7OwwVVexOkweYWwzyJvDMCkUfEfdfsZClJvLtmpbeXj/XkH1cwMetMdNZRTUKODGWvjZ
         hYfOit071aSXTQsAOxbbbnJM4J+EQG/5zEiwt0P6LQLksvdXqQ6zkmVuG9sqHfGp8EmA
         D95VjlZ6UXHNirqOIhqSwWGvWeupJZjYZ82X5bHL+s28Z2HZW9LMRdUsDw/UNZcPKjRa
         OTfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5z/J5FmpUih5AunXUZcBxXMftgMmrnQQb5zqsYk89+U=;
        b=b21e8DSItK2F/L622h6BBSEOYpgs5DBpsf5Q8rpFKWKOZvdnqoXc1sH9C28Z+ejAo9
         nJQY7XGAJl06qaT1nMJQHy0mOQv8T6cPuHIVLjaGOP09B4VznPDs5URYmennpZQYBHAy
         j0dkuM1K6h4IM9kigfQipA0zVjPZH5bv74OE0jsw1S5p7Yb/S+EDNvixRKgjooHCLqlN
         A82czI1/MM2CJQPtIFs5x4v+McgqWBknV1sA0/0wl9DmcqJ//zgBrJkPXB92quWgsVGn
         O/03NMHOSWU+DLKHs9a6AgCym9BXnlmZAcmgCDb2ux+M1o7d7WU0MQRhe8DnNeKf4dPa
         +vUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qrzGpgAI;
       spf=pass (google.com: domain of 3ejhwxwukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ejhWXwUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y206si281292wmd.2.2020.09.07.06.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ejhwxwukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id y3so5707530wrl.21
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:15 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c14f:: with SMTP id z15mr9137wmi.1.1599486074403;
 Mon, 07 Sep 2020 06:41:14 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:47 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-3-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 02/10] x86, kfence: enable KFENCE for x86
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qrzGpgAI;       spf=pass
 (google.com: domain of 3ejhwxwukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ejhWXwUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-3-elver%40google.com.
