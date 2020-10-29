Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUUB5P6AKGQEF4GIGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 06FFD29EC9E
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:08 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id h65sf1136287oia.14
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977427; cv=pass;
        d=google.com; s=arc-20160816;
        b=AFdzaPzX6r0PtbixG+u5a2n4EsJiVY1Z1plvEQAdHCRZCERDkxgfYrjdPpuYkRx3Qg
         JxRm2D9Gsb5SrXF3r/DEU27bQq16wYPs900J3/jQts6ve7gjY6YVKPCJIBtkwJTs6c7Q
         HozI33q59H/G+IN8E8TID5JOM3vAFXLoFGtYrFNLbMyeFxgPe6XwtlRoMFTag52bTema
         fObh+fWCDU6lU5b0ZqjJaG6Z0427tRko1g/blurYIOgR7NH54crhiorhOHZVNLnd7J8Y
         7Jec/pSw6iXzRuLFc93tizYZ+zHT7iggT2k+DEb1VWV1Bglb9X9B5raJRXupoqzoXosW
         Lj6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=2KtnA9oNQ82cBTRekstHkt+ZmVvlQtr0L7uM42wrCMs=;
        b=C9O9xtK4zFWjCRwMINlV7mszWRhfdG+8c9+Ecu9I7rYsndQBOiOYeW1puSCrSYVSHY
         nTooxvJdiOmdSeYs+ScHzybVQYzpXBsr0TELrYm8aZr57Ke7gNJia7nMAWVaExh7DEt0
         APCjJK+Oe9b8pBVciN2+RAzVNOoyCDzZZTr0gvxDI1mKDT/s12UHZcSl57C5sne5TpcY
         fkhkIJRark5U3geAzTJhWwIo5Apu0xOL+1nyJMW2VBfxReR8CUIaC7ldLFUZtkt34fVk
         q55laiV7q9+yK9xpVStVqNtP3P680rTMO9cOFznOaJnsMfZKUxk2xeJkhlDbkEMyNSAa
         23Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vv8xlOjp;
       spf=pass (google.com: domain of 30scaxwukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30sCaXwUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2KtnA9oNQ82cBTRekstHkt+ZmVvlQtr0L7uM42wrCMs=;
        b=ON7v6j8zuwOgP9Hsd1mpO6TlV1lA2fRobGhYCJ8evkbvXvgEBhw+1Hb4AMj20rp9Qh
         jX3cbTsl3ZPSJxw/ZzFCwo7G1k97q2zho9EBL0O7FW1d1Y+UrxVM6Iiqfjy3OZ72CVvd
         VkiOjuIM56dHZRtlQUZ9DeDKqL8DyPCemdW/gr0ChiB315QKf/o9BnAlei7911+jcyyK
         HW218x+OOVC3pu/KUQm+MP5eN2eEghtKJWAV0Da7V7CGzCqjp8zrQ2JRVGG5im800mFW
         LNVQ1l4s17IDzaxbmVMpBW6ZxzsU5W9KkoINndO3fyOXIEg+C/ZS6eiTSPDdJy22qtCM
         VaVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2KtnA9oNQ82cBTRekstHkt+ZmVvlQtr0L7uM42wrCMs=;
        b=ZnLJXTeDp5fCH/ZcUvCSXDVsHp050ZYnLJgaMw+2EzaRWsQAyrCbRxL5XPq42v4CCi
         W/aLIVCcl1Do5y7S2sSPHc7Mox8wQkzZ3tM4pghVjOpD/Gz59JsuSgZM4W86N/wBJdMI
         LUN4ze8B2MEhHO1Mi8qkl4YLfrYH46HtPncwYCgUH5WjOxvuFI9wyt6jQEUTJSBWXK38
         214cq2KVdh1POvyHAeyNCw17Ek1FQq9EoYe+8y8Qb5xBKwubY4f/0501oK0kcFIwLzZ7
         5LBNMEf7xUY+CR9aGt0GX+xAdgI/jvb+nKAfscol4izN/1elMWuO2s3dl1e2y7CoaIpl
         FJOw==
X-Gm-Message-State: AOAM532P3fP1D17UMSW/ItLyG1K5N1qIDhSByepWKVubHkzNebEsaQBF
	jbG6+CNiw/81eyy6htOQT1E=
X-Google-Smtp-Source: ABdhPJx1rHUU9Z7JzCpNb60+CI9kzxUs8uTPPHS+9fXG1+3th2svWnuaFXG88A2kAmuW7MTw+K4TsQ==
X-Received: by 2002:a4a:ce90:: with SMTP id f16mr3161375oos.55.1603977426962;
        Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1a04:: with SMTP id a4ls678141oia.6.gmail; Thu, 29 Oct
 2020 06:17:06 -0700 (PDT)
X-Received: by 2002:aca:4a46:: with SMTP id x67mr2968612oia.171.1603977426552;
        Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977426; cv=none;
        d=google.com; s=arc-20160816;
        b=i6fkUBbMwvcDYytC4ejq2xk9AT5G+6ya0DOIQ/VwoTGF3qOdEVovHX/SD/xgp7UacQ
         3QTy9Gi29XOhpQA4UVM+E1TyC5Y4KnYk4r2URLy1FQ8e+xr6iijEN2ODQq0pd8bj49/X
         Elk1TDDF5ZhnDaZhESKYMG92PtsYOmDfo/kqGRxSR2p4lSekLoFeGfuSGr2kT1dylEjI
         pW34gbi2ga/TOnVt9nYsT49/3Fzx8uL06z/1/qikrTmkjv8s2UNH+4k0H9k5asZKi0ua
         gkqxG05jSagLhP1M2EQObZJVCMboo60+IUwJOjl3sV99Co0/Vz3Aobpde97OE0lVOb9M
         WQxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GWngeZwd6f7CJumkHrxbAv00f43BJNV4xZN7qIwQfB0=;
        b=DqFwKmVWDiNpPWQaz5yUs8HuGeuoRKvDmQOZX5TztmRJoDYvtPVKKD1VCO6bqed2PW
         KAUQDhEYaPkSTDa8nVyLZ+ZCNRVnA2bzJsnYVijCKA/zAIJyd6iL1Tdk2RebmHe744dI
         jUaI9DEy/sscOEGCOYj9npRLyofVcxXo51seKfmy8fwg2iVrU8P7nABcJzwykiIjaoGC
         bkWg9di7UYr1gIMhnXeGVqrj0j9zydT5iuTFO/okciglTISKoVX/j2/aD7gkAjAz5MAG
         UiXR0KzijakJU8ySYb8QM6gMHHupGuPxuDtMnrKAYyaES7zopzrERriy2JNDyyaRbmv9
         DThQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Vv8xlOjp;
       spf=pass (google.com: domain of 30scaxwukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30sCaXwUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id m127si209997oig.2.2020.10.29.06.17.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30scaxwukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id f126so1720106qke.17
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:308:: with SMTP id
 i8mr4127419qvu.46.1603977426032; Thu, 29 Oct 2020 06:17:06 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:43 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-4-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 3/9] arm64, kfence: enable KFENCE for ARM64
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Vv8xlOjp;       spf=pass
 (google.com: domain of 30scaxwukccels2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30sCaXwUKCcEls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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
required interface in <asm/kfence.h>.

KFENCE requires that attributes for pages from its memory pool can
individually be set. Therefore, force the entire linear map to be mapped
at page granularity. Doing so may result in extra memory allocated for
page tables in case rodata=full is not set; however, currently
CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
is therefore not affected by this change.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Move generic page allocation code to core.c [suggested by Jann Horn].
* Remove comment about HAVE_ARCH_KFENCE_STATIC_POOL, since we no longer
  support static pools.
* Force page granularity for the linear map [suggested by Mark Rutland].
---
 arch/arm64/Kconfig              |  1 +
 arch/arm64/include/asm/kfence.h | 19 +++++++++++++++++++
 arch/arm64/mm/fault.c           |  4 ++++
 arch/arm64/mm/mmu.c             |  7 ++++++-
 4 files changed, 30 insertions(+), 1 deletion(-)
 create mode 100644 arch/arm64/include/asm/kfence.h

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index f858c352f72a..2f8b32dddd8b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
new file mode 100644
index 000000000000..5ac0f599cc9a
--- /dev/null
+++ b/arch/arm64/include/asm/kfence.h
@@ -0,0 +1,19 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_KFENCE_H
+#define __ASM_KFENCE_H
+
+#include <asm/cacheflush.h>
+
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
+
+static inline bool arch_kfence_init_pool(void) { return true; }
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
index 94c99c1c19e3..ec8ed2943484 100644
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
@@ -312,6 +313,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (kfence_handle_page_fault(addr))
+		return;
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 1c0f3e02f731..86be6d1a78ab 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -1449,7 +1449,12 @@ int arch_add_memory(int nid, u64 start, u64 size,
 {
 	int ret, flags = 0;
 
-	if (rodata_full || debug_pagealloc_enabled())
+	/*
+	 * KFENCE requires linear map to be mapped at page granularity, so that
+	 * it is possible to protect/unprotect single pages in the KFENCE pool.
+	 */
+	if (rodata_full || debug_pagealloc_enabled() ||
+	    IS_ENABLED(CONFIG_KFENCE))
 		flags = NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
 	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-4-elver%40google.com.
