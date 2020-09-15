Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ77QL5QKGQELWHTBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4771026A628
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:08 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id s11sf1068264ljh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176068; cv=pass;
        d=google.com; s=arc-20160816;
        b=qu0ZQUCM4slG8uULdhdjH/i1ZUCDNHHHu8RfB8brjkm1OubnmNWDqHb+BSiYKHJGQL
         GVlYryoTzrzgaMom4Q05cUMvMJoXj4D8emGnWt6LZG0mtvOVE0P5wVyjcjlcPBth0zRL
         zmMV711lsfAcjarVbnAyafMrWJDLQguJ9c49bDZknBfjkVZuy0BilsJjuaUPtyFh4AR0
         NZB8rI6MYAOaWM+KdHrRhxMbwLzAC/yDO3F5ag23CRUtKyMs6ctcdKo/TkM4YjpRMtYM
         IdvtELt4I1DOLcA3Id1eNlAPCOaYYIvvK8aCt5EwS+ElFXw61VHEFDa0RLovQ+ZhA1PY
         wvcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ojeJL6jhm2fcb3FAQjmsBq5Ju64DYggyRSS8r9ZGXQg=;
        b=0Rj0w1BS4GxAGCWMcK5iaAGkcz9YSmDTmzys+Kac69BxLwmbaWvfmAYrgun5QNOxwS
         ScdZ7wafLCsZpjzjcjEvaG/3MRYwttnEMTr18aNYST5TXkmR0LKhx9jo0krI/WwXoSXH
         2xfvH53fLiMNRcB9KrQ0JCY9tZS2ZnmHOdpIeQW2A0EYltDv1s+EQjC5pD6x2/Sqkv/G
         XB0CrmLxm+td6Cnd4AfNS+mGU/A1m+BEkjfdkUaAtx3gPvoXtDdEihchYZePbd9tG3E4
         Sh4MaesqnTHkkouX2D9bF1bVfS9KQBPEzhnD6cIdypeddJyyI9Ks4y01Wmm2zu3PXou1
         IYXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o71HNdv6;
       spf=pass (google.com: domain of 3wb9gxwukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wb9gXwUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ojeJL6jhm2fcb3FAQjmsBq5Ju64DYggyRSS8r9ZGXQg=;
        b=qe+q4cScJXm4j3Ct15q/WktohW4L10Qb062hC98oj31Gq/OgFLKc5K/TjsTchPu4zX
         F+M9RWslFhiSUFM5UJGjaiqaModUyjwzd5+HWQU6jFK7cr6Qi4ow1eMOvKsTwU3R6Qzg
         D8Ub75hjM6RQYfQuOskIersUERpKMtzaWGhk8hsaqUReY4kPym+++xsZtVZF4lgOmDu5
         XvSBfMlrj5fHHaX+tapQ+AXX9Uc2YfsSfadHY1P3zXJoAwj/f+R2ESQFCUlPM9DudARY
         hoB28gJJpxYfa8MN0Uw0tDkZXWOQhps2gkVxWxMBYl1kCq/bnYkBdND9efRzjnY3qo8c
         5Mqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ojeJL6jhm2fcb3FAQjmsBq5Ju64DYggyRSS8r9ZGXQg=;
        b=N73vX/ZbpEBRRpr2YG5dpPDE0Nd8OKK6LD9QM4aap0xhVkxXUrhubhdLAyFGgenLfu
         6rOA+NYS3eusqaG5jQ17+s0R/T8ilvrzTtK+A3upDvbLkLSSilP22+XUQn6P/siK31b+
         47rgf44rOBC/IRtQ3ikbXWl2UlT3hnCjbut734mapREa49eDS9p7a38Mqq11WryJnRyI
         mwD0LQPtMUChIJefMsB8K0RIfAjI0ngM5FbPwki0Vjqu5/y6khTPuIZapuMOI5kMAPwd
         C0h5IxW97GkpsNHYZzq+gVPFlJe8PCBWkAv+3QININxJASfBtBhRoHblppRbp9ifcrU/
         PL+w==
X-Gm-Message-State: AOAM530XY9XcE2mI1kZXMZzI3gMZYRbYnUl2VjHzgf68l9SZH4ekzrk3
	zo1XodpiZB6HfhxqQTqj8wg=
X-Google-Smtp-Source: ABdhPJwlkGyT/JrPgWDT/rAYe4U0+zTs0RWhrvwIh752X93QhdyxXjbSjtBZu7GWtZt68aiZDvtBvQ==
X-Received: by 2002:a19:23c6:: with SMTP id j189mr6958458lfj.79.1600176067774;
        Tue, 15 Sep 2020 06:21:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:93:: with SMTP id 19ls1947924ljq.4.gmail; Tue, 15
 Sep 2020 06:21:06 -0700 (PDT)
X-Received: by 2002:a05:651c:28c:: with SMTP id b12mr6899612ljo.8.1600176066592;
        Tue, 15 Sep 2020 06:21:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176066; cv=none;
        d=google.com; s=arc-20160816;
        b=yQK+z4yhgZWti8uhpWX0Sb7kcxu7E/SA+CeJxvJbhIm5v/KRGd3mg9r5tWdxq6tg7Q
         vKVpNXV/U1Glyb/afCoK+yvyR1yOAfbd5zYJcfb+56PUShLFVZGP0rF1uR369v3MBZv6
         1YraOFeXQM70zr2K/GXkcyV/vW7D+a7o/aq/zHrgZQJsFEwSOuAL4VXL98hOAI/ns5Ez
         j5M7o9Ir4hsS8EXbK48/9Hex95sXvY5wmd0Dhlg2+3/HdGy4WFvjWemBi4SYKyKbaFni
         TRWW05ovAlrWR1CQ/R4ViGfW+yvX7P3j8R1BRJxkNlzblPWp6yklRdUR/am85tJaY3Kc
         GEYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SxvDeyNmcNMA+Gji2vA/rr03EMZqbUrEGQF/tm1mQmw=;
        b=DSZfSoQTH5w4esBMaGniBBQF8/AQdhktvWKkDkGlNOGFpElt63dUgXr/zCTDB75emL
         mt3Nu/nnN1I1AxYBHJEDWdQCBX3Ul79+VjDYx44LOrR6gKwGe6mecUDmL4G/mOPCgoZu
         yQH7bO1/UHRynDld2ZiSvpqp4/d4Haf2LJ2qlV3Pke99durbE7CpBylIO8CTtK1G1fgA
         GNFhJFbDv3ZuXLEvdwW8WwXzqqh6SiV6gmtDjZg2Aoa1gxRkLtmYldTdHZG7f39bz9CS
         Q9BAF0EExxr0CySeXWp2QmgrB5woPgjm/RTL40aVmJSF4Q2SRhnHdSs4ESsgH42jc0MC
         i8zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o71HNdv6;
       spf=pass (google.com: domain of 3wb9gxwukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wb9gXwUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r6si386505lji.4.2020.09.15.06.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wb9gxwukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id k13so1234528wrl.4
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:06 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:adf:8b1d:: with SMTP id n29mr20637102wra.383.1600176065852;
 Tue, 15 Sep 2020 06:21:05 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:39 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-4-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 03/10] arm64, kfence: enable KFENCE for ARM64
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
 header.i=@google.com header.s=20161025 header.b=o71HNdv6;       spf=pass
 (google.com: domain of 3wb9gxwukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wb9gXwUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the arm64 architecture. In particular, this implements the
required interface in <asm/kfence.h>. Currently, the arm64 version does
not yet use a statically allocated memory pool, at the cost of a pointer
load for each is_kfence_address().

Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
For ARM64, we would like to solicit feedback on what the best option is
to obtain a constant address for __kfence_pool. One option is to declare
a memory range in the memory layout to be dedicated to KFENCE (like is
done for KASAN), however, it is unclear if this is the best available
option. We would like to avoid touching the memory layout.
---
 arch/arm64/Kconfig              |  1 +
 arch/arm64/include/asm/kfence.h | 39 +++++++++++++++++++++++++++++++++
 arch/arm64/mm/fault.c           |  4 ++++
 3 files changed, 44 insertions(+)
 create mode 100644 arch/arm64/include/asm/kfence.h

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6d232837cbee..1acc6b2877c3 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
new file mode 100644
index 000000000000..608dde80e5ca
--- /dev/null
+++ b/arch/arm64/include/asm/kfence.h
@@ -0,0 +1,39 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_KFENCE_H
+#define __ASM_KFENCE_H
+
+#include <linux/kfence.h>
+#include <linux/log2.h>
+#include <linux/mm.h>
+
+#include <asm/cacheflush.h>
+
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
+
+/*
+ * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically allocated
+ * __kfence_pool, to avoid the extra pointer load for is_kfence_address(). By
+ * default, however, we do not have struct pages for static allocations.
+ */
+
+static inline bool arch_kfence_initialize_pool(void)
+{
+	const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
+	struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
+
+	if (!pages)
+		return false;
+
+	__kfence_pool = page_address(pages);
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	set_memory_valid(addr, 1, !protect);
+
+	return true;
+}
+
+#endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index f07333e86c2f..d5b72ecbeeea 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -10,6 +10,7 @@
 #include <linux/acpi.h>
 #include <linux/bitfield.h>
 #include <linux/extable.h>
+#include <linux/kfence.h>
 #include <linux/signal.h>
 #include <linux/mm.h>
 #include <linux/hardirq.h>
@@ -310,6 +311,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (kfence_handle_page_fault(addr))
+		return;
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-4-elver%40google.com.
