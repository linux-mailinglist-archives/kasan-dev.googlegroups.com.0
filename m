Return-Path: <kasan-dev+bncBDXY7I6V6AMRBW7SXCVAMGQEOWRWPZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E14D7E7CD7
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 15:08:30 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5079fd9754csf2259092e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Nov 2023 06:08:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699625309; cv=pass;
        d=google.com; s=arc-20160816;
        b=rtYrkOSAwGDp5lh+EFiMmLshk433Z/iXVSa4MpnJLL5hGK1gAYveYSLqxQBIl8Y3nB
         tLHlXny9bpKpqclYBWbktFDbREb1QhDQzuPnfwkxoDRG9G/HA/2Oa5+3qfo6S3PAQxaL
         dCXL98EBMYMlc5GG8X7aHW3C4ZXQbdg9IaqdySYi60Cef0ObnlvPkNly5ln9DblFvvi1
         XBQrhv22V59J5RyNfayl2sd4mw2uKzepsT8q5nvdtLuTgYJxOlIcIp0elnPwHdTC1Zfv
         Dc8SML2B6Za30rTZp9bEVvaJKwU9Dl2YpJ5/LCin/kMaIb6c4L8e2bvi0gErj9sec1Yn
         yWyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cTSvoeoCfZ3BBfp1JLLzkEMWyY7xYOQy/IlrPirMaY0=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=jZ8Pa4UmIbRLYojvIGNsClOCXG5qr6NEGDJYlAYJQLcCrnqhG5Bzys8BroyeMPRdvy
         Ds275ugDFVEU8eLzr6gfOnrf5D/NZm9qy+G8qLNS9OPRvQ93pmROTdFYLQdSuW3lDqoW
         9yTfnDQssbNVng6bgf96KAuarQDQ+1ZcdHsVCFxFIozT7UiET3voM34Y3t+8izkCK6ZR
         5J4ifosyRusGFQ3354XxRbH3Xn8jL4E6CVZVzosvqRWrg0FNoD2wLLqBNiWgwtWd0Ijv
         6LCY4QK13wMMCBzl49sT+NFJ9ybiej3oBiu7PrDMWDyUhmd+5a4vG0nFMPfcfyq62h6y
         oZxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=SqvuVLvD;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699625309; x=1700230109; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cTSvoeoCfZ3BBfp1JLLzkEMWyY7xYOQy/IlrPirMaY0=;
        b=LjCbw1JScS7BBK/oCG9+4jSRhZkWEiH8y6eX4G8y7rksqKYVrxcYs5lnSgZVHrAIyh
         BHqxzrg10Ci673oOh4IF9KhbSo6bVtxv1lYmrmXUgfZBaFhd/gG4j91F7BOdzerdo9U+
         XRIQWdfWxhMFb3//XZjavbzfhBAtqR6Hv6Trf/VDmALbKqwJMf11DChPloq/vfqhdWn9
         tu+FhePQWmOj/4swKwTS17rUxl2K4kT71w51guARKvBc48H72wMwp77bgp63KaCks9uu
         dQVXH0dcG2hq2jITpP6730f+GiXXhv399qqN1y6bEcL98Dmvem8UAM7KpPOGraz1+FUn
         6XaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699625309; x=1700230109;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cTSvoeoCfZ3BBfp1JLLzkEMWyY7xYOQy/IlrPirMaY0=;
        b=JxHOpMtInO5MlPx0f0cVz253oqUuW+ofOUVAfJebLmwy/3uKw58Pb5rKDXzTlCd9dQ
         5Mxd6oJADWFa/jSZzn4a7wgnz2zPvXIHktSqDCi1ddQP+i1pnZknUQ9PLnEfV19ZJgDW
         pzDyjKn5B8Ncpp2of7J6fWT/ttkGSgxxOkyV60Qip9j7X1Xoav06YTltmCx1Hg8B3rPU
         PC7x9dDpDLnsUkucdwWwgj2d/eB551Z0bgbq261fxhr+ANt3OY7W+G5DU2f7THkflWHs
         WZDBCfuHX/pnvvE5nZeWOgWyc5FOZduiwa9KVwSjsip3difqPAiXkNkEv5vjGvDHxVFq
         wfXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwqQG6JnP8zgX3KGrMUR0a5eR1gENV9N+pr3mVlCME/Vuxb8c0v
	vmyMClU+oXNVK7WHRbEqRYI=
X-Google-Smtp-Source: AGHT+IG/BHaRSaBxkYKhLbNcC6Sq534SyGOjYgp/+dkwxCwgmwvtUa3rwvImxkRZzpYRuGY1iYr8Bw==
X-Received: by 2002:a2e:98c7:0:b0:2c6:f3fd:7f0 with SMTP id s7-20020a2e98c7000000b002c6f3fd07f0mr6761274ljj.19.1699625308190;
        Fri, 10 Nov 2023 06:08:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5a3:0:b0:2c2:9016:aa8f with SMTP id f3-20020a2eb5a3000000b002c29016aa8fls893811ljn.2.-pod-prod-07-eu;
 Fri, 10 Nov 2023 06:08:26 -0800 (PST)
X-Received: by 2002:a2e:9256:0:b0:2c8:32da:7c34 with SMTP id v22-20020a2e9256000000b002c832da7c34mr1420750ljg.24.1699625306182;
        Fri, 10 Nov 2023 06:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699625305; cv=none;
        d=google.com; s=arc-20160816;
        b=B0n4Vhwv0WvzlvrOiEyCoz/YiX8Et4jUioiuNuWazRAIgiBisJbi+mYYhD+AFe2Rxq
         Lc9yFpSzT7A+SUXBBlPOXhdc2PlDefPyD3cKQ32CUlsW+FGUOkC2mU7KxizUSo5UjQ/U
         wPSXCvRWVkT62CkCuE5hQla6kj8z3jN8oeTHgdu44zIqH2u8ooFs2H/q7Kkfi7DLGhe7
         JfLdHda4ODvwgXG0bYeHkdvrh7gVMPu8iQqS2ulZgJDCUJrC0zy6RIsriEOwZNhNP+9O
         RmPrhHTgnQvn4niVzHYlP8FxyvJWLUAKlkzX1x0nYB90zRoa6E/zCVI+wgB+gpqb9xFU
         Ui6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2AMKJOgOBU+36iIxGMD9Trqw8IVdjZaTyhAA3F26Egw=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=pbkJSKulghidmHee2KlQXKdlAdrLl1WaELNUjzOE+eppsqf+MtSmmvenG+2Y9bfiOw
         G/0IH56Ky5FnCGjILNAOe3VszJCbwjsmkKNPwfg+18Swa0sCekVQLdo8NYcvgY/f9iNB
         OF5nFcMAMMOjfEGlCutpRSuEDo4ki0PxUfDmm9NpvlfcbpOYqmkzQhW5Ibz8gaJKnNV8
         RKiMsRRAeprCJsab4ovYxmZa9tPK3nbkOUi2BmQxcU3PCrKLuCL7OZ9TSu00Es9vQkZl
         8t8RhnhDMdT6VCYhcb+dyB2jdw8HAXXKUG4FIj55+To/mQS5wA7as/IxqpP13lKWdaEQ
         4wfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=SqvuVLvD;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id o18-20020a05600c511200b004047a45b541si299123wms.0.2023.11.10.06.08.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Nov 2023 06:08:25 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-50a71aac023so653406e87.3
        for <kasan-dev@googlegroups.com>; Fri, 10 Nov 2023 06:08:25 -0800 (PST)
X-Received: by 2002:ac2:5209:0:b0:503:1783:d5a9 with SMTP id a9-20020ac25209000000b005031783d5a9mr3895555lfl.3.1699625304483;
        Fri, 10 Nov 2023 06:08:24 -0800 (PST)
Received: from alex-rivos.home (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id t18-20020a05600c451200b004076f522058sm5366438wmo.0.2023.11.10.06.08.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Nov 2023 06:08:24 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 1/2] mm: Introduce flush_cache_vmap_early() and its riscv implementation
Date: Fri, 10 Nov 2023 15:07:20 +0100
Message-Id: <20231110140721.114235-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231110140721.114235-1-alexghiti@rivosinc.com>
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=SqvuVLvD;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The pcpu setup when using the page allocator sets up a new vmalloc
mapping very early in the boot process, so early that it cannot use the
flush_cache_vmap() function which may depend on structures not yet
initialized (for example in riscv, we currently send an IPI to flush
other cpus TLB).

But on some architectures, we must call flush_cache_vmap(): for example,
in riscv, some uarchs can cache invalid TLB entries so we need to flush
the new established mapping to avoid taking an exception.

So fix this by introducing a new function flush_cache_vmap_early() which
is called right after setting the new page table entry and before
accessing this new mapping. This new function implements a local flush
tlb on riscv and is no-op for other architectures (same as today).

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/include/asm/cacheflush.h | 3 ++-
 arch/riscv/include/asm/tlbflush.h   | 2 ++
 arch/riscv/mm/tlbflush.c            | 5 +++++
 include/asm-generic/cacheflush.h    | 6 ++++++
 mm/percpu.c                         | 8 +-------
 5 files changed, 16 insertions(+), 8 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index 3cb53c4df27c..a129dac4521d 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -37,7 +37,8 @@ static inline void flush_dcache_page(struct page *page)
 	flush_icache_mm(vma->vm_mm, 0)
 
 #ifdef CONFIG_64BIT
-#define flush_cache_vmap(start, end)	flush_tlb_kernel_range(start, end)
+#define flush_cache_vmap(start, end)		flush_tlb_kernel_range(start, end)
+#define flush_cache_vmap_early(start, end)	local_flush_tlb_kernel_range(start, end)
 #endif
 
 #ifndef CONFIG_SMP
diff --git a/arch/riscv/include/asm/tlbflush.h b/arch/riscv/include/asm/tlbflush.h
index 8f3418c5f172..f0d6328076b6 100644
--- a/arch/riscv/include/asm/tlbflush.h
+++ b/arch/riscv/include/asm/tlbflush.h
@@ -41,6 +41,7 @@ void flush_tlb_page(struct vm_area_struct *vma, unsigned long addr);
 void flush_tlb_range(struct vm_area_struct *vma, unsigned long start,
 		     unsigned long end);
 void flush_tlb_kernel_range(unsigned long start, unsigned long end);
+void local_flush_tlb_kernel_range(unsigned long start, unsigned long end);
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
 #define __HAVE_ARCH_FLUSH_PMD_TLB_RANGE
 void flush_pmd_tlb_range(struct vm_area_struct *vma, unsigned long start,
@@ -64,6 +65,7 @@ static inline void flush_tlb_kernel_range(unsigned long start,
 	local_flush_tlb_all();
 }
 
+#define local_flush_tlb_kernel_range(start, end) flush_tlb_kernel_range(start, end)
 #define flush_tlb_mm(mm) flush_tlb_all()
 #define flush_tlb_mm_range(mm, start, end, page_size) flush_tlb_all()
 #endif /* !CONFIG_SMP || !CONFIG_MMU */
diff --git a/arch/riscv/mm/tlbflush.c b/arch/riscv/mm/tlbflush.c
index e6659d7368b3..8aadc5f71c93 100644
--- a/arch/riscv/mm/tlbflush.c
+++ b/arch/riscv/mm/tlbflush.c
@@ -66,6 +66,11 @@ static inline void local_flush_tlb_range_asid(unsigned long start,
 		local_flush_tlb_range_threshold_asid(start, size, stride, asid);
 }
 
+void local_flush_tlb_kernel_range(unsigned long start, unsigned long end)
+{
+	local_flush_tlb_range_asid(start, end, PAGE_SIZE, FLUSH_TLB_NO_ASID);
+}
+
 static void __ipi_flush_tlb_all(void *info)
 {
 	local_flush_tlb_all();
diff --git a/include/asm-generic/cacheflush.h b/include/asm-generic/cacheflush.h
index 84ec53ccc450..7ee8a179d103 100644
--- a/include/asm-generic/cacheflush.h
+++ b/include/asm-generic/cacheflush.h
@@ -91,6 +91,12 @@ static inline void flush_cache_vmap(unsigned long start, unsigned long end)
 }
 #endif
 
+#ifndef flush_cache_vmap_early
+static inline void flush_cache_vmap_early(unsigned long start, unsigned long end)
+{
+}
+#endif
+
 #ifndef flush_cache_vunmap
 static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 {
diff --git a/mm/percpu.c b/mm/percpu.c
index a7665de8485f..d287cebd58ca 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3306,13 +3306,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_to_node_fn_t
 		if (rc < 0)
 			panic("failed to map percpu area, err=%d\n", rc);
 
-		/*
-		 * FIXME: Archs with virtual cache should flush local
-		 * cache for the linear mapping here - something
-		 * equivalent to flush_cache_vmap() on the local cpu.
-		 * flush_cache_vmap() can't be used as most supporting
-		 * data structures are not set up yet.
-		 */
+		flush_cache_vmap_early(unit_addr, unit_addr + ai->unit_size);
 
 		/* copy static data */
 		memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231110140721.114235-2-alexghiti%40rivosinc.com.
