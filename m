Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FUQ36QKGQEXWZKVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 808AE2A4DA4
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:05 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id h14sf7447022ljj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426345; cv=pass;
        d=google.com; s=arc-20160816;
        b=dB0+CG18djrZYf3G60CH36ukqLior0tFFL+b3tbCR0aum3C5nuZhcfSpMdcEDNvdTo
         AC2dkNzYjX4zrxSx/g9wrUCMOlHDbJb6RdJ36vLWoAOLg8Ttkms6QKsqg94bj2EkBQRF
         ++Ga3+JjINGR3sK+4ODxNhNuIeNjCqiwK1bxEVfjp3/NeA/e9TG5E4LERjl0A+NBxVUx
         pEbYqFN4ajqk9qQE3s7kX1UzhQpFe51kkatuodn3ksnf2We409nPXRzhNqSrm6pjD846
         K/00R9+umT7+iQ5FrB530MB70d1XjZuc1fQ0OrKap/sStTuHtxwS+Fw4z6bXjpGyNaee
         G0Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MzrqaOJ+k34/Goh0awODlUGGBdNZV059JxcKNKTMTi0=;
        b=iU22B9h5VgNaGbQd87OaYXvnMjoeqGpmVovbIJ18C2oWtaQ/md8R/se3XXEoWJiTcC
         PmNbp5WP6P9MYcMr7ULPLVRatVQGQBqtdlWhrD24ttDW+vA2NjPMDoo0V55+UxUeY+u+
         5Bmr9uDjGVs6yZYKmSVrRtxqmb3P/gkO5HPtsbfE+2iJ2EjrNagf9azPx+LaAMBdQ8A8
         dBb4WWZydmuTj54yvWOCUN3w0cqPABhX9ZiJsiz5Q5PzwPuGre/U9gLbwcudr2WNAagR
         RbZpXwK5BPlYMAvdOJ19X8vAxDDaWeQpwNFWXTCxatrm3Vf6SVYHr7xIq9dkAj0CiRrF
         ztKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rhyK8dme;
       spf=pass (google.com: domain of 3z5qhxwukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z5qhXwUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MzrqaOJ+k34/Goh0awODlUGGBdNZV059JxcKNKTMTi0=;
        b=lU4X4XOX9xZjSAJHb3Cpr7VhsMe+2TTkrK8IpT0leEoLsrzAm9edxwjkfGkq3Z9M1A
         nF7HClMJ27P4wRxqRvk/oV14+dX1LBoV+uWDd9fDWoaFtWLQSK6uJiM1wXFaGHbxzeZL
         0BRAkcRMxpts3sZpc4SS6zbQ15c6VQ52dFaSwX8CxxlYBv81MKWBlUd6RUkNYJE80uQX
         dNJYzLUtXXD6R21EzcGmPzoYSQvuEXne88xexgEZvcaGuDNEM52ViY6049a0LJFIZML6
         MKJy9769Mg4ztx0qkH7u+8GygN1b56vOr3Gpp2SoRlE2GYrdUJk2GAv1hGF/QxQUCdnS
         TcAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MzrqaOJ+k34/Goh0awODlUGGBdNZV059JxcKNKTMTi0=;
        b=Uv8iwKEHRj4JmGfM3SVb7zXm73HxV71nXku8I/ap5VmCs0646p3DHSVLmfv0Vnj83J
         bti7QkjEdGFhpmwoww55b9YbTp9+IxHjcJtRu4sD3BsmfX8vaMziY4wFn7MrNT6ctGFI
         jC1HLv/ucsefiExjhliBNKEUfFUAp/K1O141AM00L1Cf9wWglnUaVJFu59ye6xXe0fvj
         pwkfxKrtn0pLs9BHgCd+O/krxm7x2TnJzQEJnw4gxonAnF2E9XzymG6+jmXrLhvPOk+T
         KU3YHttjsDqodtJtvEKUTPEkHbi1sCmxHF740qJva307PjgVyblncd4CSzp8Yo9MREag
         KXWA==
X-Gm-Message-State: AOAM531PCjcjrgHAbpK5YV5rmZdXQikSz4Gl9tlkQBPA2yMok9Psys2f
	wh1vYEwiPULmSnNt3VGL04E=
X-Google-Smtp-Source: ABdhPJx0hTN3ySX+7hKSvPaYjvtC2c51ajo967/VJa5Olbbr9MrdY/dtiVOH1QtAqjygcxaCorKbPg==
X-Received: by 2002:a2e:9449:: with SMTP id o9mr7970609ljh.457.1604426345054;
        Tue, 03 Nov 2020 09:59:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c15:: with SMTP id x21ls490172ljc.8.gmail; Tue, 03 Nov
 2020 09:59:03 -0800 (PST)
X-Received: by 2002:a2e:8ec8:: with SMTP id e8mr8754700ljl.140.1604426343791;
        Tue, 03 Nov 2020 09:59:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426343; cv=none;
        d=google.com; s=arc-20160816;
        b=K0CaHU+ZcA6PpyCo8dkuIaPMWeuUaeZU9OE9Z78pJCG/6NLdJYBKh0N3mcg+aQWzHD
         2ANzlpY6cs8qQHupNYlFd9UCOv+wBTC0teJ1dxMo3KQrofmBm76xGi3fVUQAVH6Z7fK4
         9+9vm40GiOLhVjwiIaUkp/TAeMJTPh22nOhpYPedZQAny9A/HkGY+zPgaRcFFVcuoewm
         Wh5Ha+urPjAHlYsFF5Rx9JdaL/HZESXQtaqM0wUcKYlbN2pjzaPTT0PhSRLvl61PhY3r
         +udwOu4JnBHQVjhWhWqkEzKlaizJDlT3LgkAMyVnMZGl9C8Qs/8Fs9onExJHIn3nxQfD
         Pvtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EipKG0yUMWWV8YDScCe0e6tWyMQpyXBYPjRJqBhcvjE=;
        b=cavzTJTwJxXf/Dww0uTC66oeVPGeqeENuiP4oCXveQLEeJN2UqvJEP60KSPsYsEet5
         w9Vi449O29/xoGaItEKSk+5rg8zdvz8/KnR4EjyBciU/arc+e2JPFf9uuQNlI0zRk9Rm
         kuiGTPbl0XjjG47RdHmXDFs/Pfy7MKZK1qb4mWSxksFE7KHNxSIEkSC2CBLVv0o6KNw1
         qtjzIqWKB8xEV32xgiWphjQeU/ulceCKKs+bwDbJBHvG2LsVl88yf738SGucbpKClD6t
         sqj7Fc7jH+9A1drPxa9Z59M75j9vQG7NHLx9E1conKoaMUTPSACaCuizkyZNfI5uE+Li
         zD1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rhyK8dme;
       spf=pass (google.com: domain of 3z5qhxwukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z5qhXwUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t13si582337lfr.13.2020.11.03.09.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3z5qhxwukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s85so52088wme.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:03 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c401:: with SMTP id k1mr353453wmi.120.1604426343066;
 Tue, 03 Nov 2020 09:59:03 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:35 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-4-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 3/9] arm64, kfence: enable KFENCE for ARM64
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
 header.i=@google.com header.s=20161025 header.b=rhyK8dme;       spf=pass
 (google.com: domain of 3z5qhxwukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z5qhXwUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
v7:
* Remove dependency on page size [reported by Mark Rutland].
* fault normally on permission faults [reported by Jann Horn].

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
index 1d466addb078..e524c07c3eda 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,6 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE
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
index 1ee94002801f..2d60204b4ed2 100644
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
@@ -322,6 +323,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	} else if (addr < PAGE_SIZE) {
 		msg = "NULL pointer dereference";
 	} else {
+		if (kfence_handle_page_fault(addr))
+			return;
+
 		msg = "paging request";
 	}
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-4-elver%40google.com.
