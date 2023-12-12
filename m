Return-Path: <kasan-dev+bncBDXY7I6V6AMRBQVE4OVQMGQEJC4U2TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B999780F97E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 22:36:04 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40c295f59cesf28535875e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 13:36:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702416964; cv=pass;
        d=google.com; s=arc-20160816;
        b=a42r12ELe4Vcl7ipGHrrstpht+nDHwpFFr33OsPPOET6gEUkivCWPXnBob2XMhtPeo
         YtB1wdqbW1Pacdm2XQW/sQsmNPbd4Z9XqPyUWVTKL6Dvld9U8+Q7HM6GDKGDCN8krdhq
         Ofjqh0y7wBqPJchpZhSfxBBQ3vALpaud+fj65dL0Ry8q7RMvOyjdwZEaZZg0n827PaOL
         ZKz9BSGGJiZvXV7vNE8mQ3wXxKfMoBPW7y5d9AQvsFBs6cy0O+SmHH4vlIaIS6AK4eJZ
         h5QaiumhIzL9RVpXTNMxsLjAw16ppXvc13qsZYJGICJZwTE28K5IqJAAhJlq4S9eUsfC
         mcaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M3FHP+7Aq/f+SOtBzDVyRnTXG1cuiFxPy5ilVa0/UvM=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=F3tiU5dp/b/nyKVb4I5ytlwC0jf3LcnXUYZkYSJI6KvPjuHrJJ4K9LEtrQFcrvCD2j
         mum7LPfhztNCWqNWLRV7+mH2pMCDTFfWpdq+7+0oTLM6i8ALAVF0g5yXJHb5ojenLcDw
         UBY0gRVao0Jda/Biaql2cqrgfOnVvEY8hMLAnTnYxuN0XD/SxJ3fiJ5BKQ6IrWskvx/c
         89qKc0Sj3KxxUBCQ0m/hraYtnsJQrg0yOHBPT+pP6s0hV6XrdddV2xX/UaqdyWgZA0WE
         99CqPruytuAUH0eGD/IIfBHPhx6wunUYYxrCmQe0Eu7BUBj/SuSSpJsnhSv7qb8B6XqD
         2zvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=TjyuJvz8;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702416964; x=1703021764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M3FHP+7Aq/f+SOtBzDVyRnTXG1cuiFxPy5ilVa0/UvM=;
        b=jrkp0RemiLzta8R23hkP8AIi0qXAwLfwqS12KKfOJ/ZquqrjmwNyeNMISR6VhsarfX
         DyBqmcvirgbR+22SsvLLQz0+Hez0sq+iZveaAlNZ4GsCc4HmwfILZxsUvpeO20nqz5tt
         hL/gsQA+C8bVmA3uqUBmy0SZWICiDOKAGSsIOjmMSEKsvR9vZZ102zP1Wp6JhuaTtd6K
         8gpg5Zgz2Opl3q4N0EfL/bml50PhgSjz7SeSD1LvgbtV4L3ctEYoR0JpzrHPzHwRqT63
         VbFMWwD3OmNE/9zb0To2QvZYPqCdsft090hv9XYr3r7U5QYzn+6wtiIYo4nfb5mHqd3F
         cw5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702416964; x=1703021764;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M3FHP+7Aq/f+SOtBzDVyRnTXG1cuiFxPy5ilVa0/UvM=;
        b=GTDMHsBKx1T1xjwNGj+u6K5ZRv5tNKD9tIu3fv9EByQZu9lPrBLE7KDV/oWKYVa29m
         YfpQzJHVST82Lmx508HhKjOmVxSWetH2kGHQBQ2CujDZVKI7QusMlwUjy9K53JKydo8t
         cTx5l7bs2ge3wLqLfOF+2NcmOw0WzHMmzQE2bh4KjhGhYxQRAhEJI7ja0SuubYyJ0pKr
         5wGSwh14m9+d7zbitEI8uzCU38tLyM1rMrdRZZkrnmavRhwjxwB3ssWmSEa7xpPGIxvA
         mfBUtGELtsS7Bt6hbVwq19B0VAHFyrIFRPQHUffK0TnpYQ54Kj87tSZsbbnm3o3haskv
         IqBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwAtdeUJggY7qy58SyNw8n8jCk6wfixMoVuKuI45kBaFcdqODLK
	zFyovPfX7Ox6ZG8kONPukDY=
X-Google-Smtp-Source: AGHT+IFlRxCWSa3kOV+TgFcAM0srjrTlEu38KP5AYPU5qkduMlnA7i5WKZ2twJeY3urtrCWqTvmMdQ==
X-Received: by 2002:a05:600c:4f11:b0:40c:3172:acae with SMTP id l17-20020a05600c4f1100b0040c3172acaemr3621689wmq.37.1702416963116;
        Tue, 12 Dec 2023 13:36:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca54:0:b0:409:5426:9d6a with SMTP id m20-20020a7bca54000000b0040954269d6als2042789wml.1.-pod-prod-00-eu;
 Tue, 12 Dec 2023 13:36:01 -0800 (PST)
X-Received: by 2002:a05:600c:4897:b0:40c:1de7:41d5 with SMTP id j23-20020a05600c489700b0040c1de741d5mr3695576wmp.87.1702416961215;
        Tue, 12 Dec 2023 13:36:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702416961; cv=none;
        d=google.com; s=arc-20160816;
        b=YpOoutkmt9ePkYAkr0nrbcxdIBI0F8gTa4z65u/7+xegsJJZwHgepy9GM3ZPZOVpRF
         NAGzH5TGdzDJnaOWXLBF795EORVlRgZHy3zChDCC1Oxu++rDx+gCKGIXNJGIpFEBH65p
         5NE+80TmdlbJ9g11PXVcW1voW23RauHJj58eyUtb0AvqkxA1fboZHoRQdmGGZ4pGosyv
         hCR7dbTjfY0t4Nx7PHW4pldHV5J6/9LpwqIWOe5Uba+Iohr4228BgBonGPd2ecwN4b3L
         x3GBbbpxleQgDtINGvgN29re2BKKpQ/PxrDOHr+SFGrQeegVyKxrDEFnjAHBmtHYpXFH
         bfiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BLS75Mo77acz6k4jx++nul4Z+bTVnVv2nm8SBcxb6zo=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=o6inmoFqjVVKWXvvUBr4fqx/EYVz8yai+7i5bZXcGX0fJG9HzNntb9tSQ3w/1clBUG
         exOF0MYWK+PyWneU1KyJx8q6nIvCfVyK08yB26roX1uasrxDSFmvqvWqTEcmb8Z65uLZ
         ThZdF5FWdtPdCxPT5xYR6t2rgXqr6ro4nFhMJnSJYsvvQYh64TeQ/XaT1MfbS4P/bvVs
         rEE6Fuv/lmbIUE3MWTyXOE4dhcBpCA7CRtWCR6OlujafC+DBxvFbnwkhEhX5gvSNJZil
         XGocaTgI6Wn/j7T1t8g398xzN6NJ2/ObaOpVOdyAZ81eRrhnYJnTBbYaB3qkR2B96a6Q
         gswQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=TjyuJvz8;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id m30-20020a05600c3b1e00b0040a25ec1cfesi86173wms.0.2023.12.12.13.36.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 13:36:01 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-40c55872d80so5120615e9.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 13:36:01 -0800 (PST)
X-Received: by 2002:a7b:c456:0:b0:40b:5e4a:2365 with SMTP id l22-20020a7bc456000000b0040b5e4a2365mr3632834wmi.103.1702416960633;
        Tue, 12 Dec 2023 13:36:00 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id u21-20020a05600c139500b00405d9a950a2sm19994483wmf.28.2023.12.12.13.35.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 13:36:00 -0800 (PST)
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
Subject: [PATCH v2 1/2] mm: Introduce flush_cache_vmap_early()
Date: Tue, 12 Dec 2023 22:34:56 +0100
Message-Id: <20231212213457.132605-2-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231212213457.132605-1-alexghiti@rivosinc.com>
References: <20231212213457.132605-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=TjyuJvz8;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
 arch/arc/include/asm/cacheflush.h      | 1 +
 arch/arm/include/asm/cacheflush.h      | 2 ++
 arch/csky/abiv1/inc/abi/cacheflush.h   | 1 +
 arch/csky/abiv2/inc/abi/cacheflush.h   | 1 +
 arch/m68k/include/asm/cacheflush_mm.h  | 1 +
 arch/mips/include/asm/cacheflush.h     | 2 ++
 arch/nios2/include/asm/cacheflush.h    | 1 +
 arch/parisc/include/asm/cacheflush.h   | 1 +
 arch/riscv/include/asm/cacheflush.h    | 3 ++-
 arch/riscv/include/asm/tlbflush.h      | 1 +
 arch/riscv/mm/tlbflush.c               | 5 +++++
 arch/sh/include/asm/cacheflush.h       | 1 +
 arch/sparc/include/asm/cacheflush_32.h | 1 +
 arch/sparc/include/asm/cacheflush_64.h | 1 +
 arch/xtensa/include/asm/cacheflush.h   | 6 ++++--
 include/asm-generic/cacheflush.h       | 6 ++++++
 mm/percpu.c                            | 8 +-------
 17 files changed, 32 insertions(+), 10 deletions(-)

diff --git a/arch/arc/include/asm/cacheflush.h b/arch/arc/include/asm/cacheflush.h
index bd5b1a9a0544..6fc74500a9f5 100644
--- a/arch/arc/include/asm/cacheflush.h
+++ b/arch/arc/include/asm/cacheflush.h
@@ -40,6 +40,7 @@ void dma_cache_wback(phys_addr_t start, unsigned long sz);
 
 /* TBD: optimize this */
 #define flush_cache_vmap(start, end)		flush_cache_all()
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		flush_cache_all()
 
 #define flush_cache_dup_mm(mm)			/* called on fork (VIVT only) */
diff --git a/arch/arm/include/asm/cacheflush.h b/arch/arm/include/asm/cacheflush.h
index f6181f69577f..1075534b0a2e 100644
--- a/arch/arm/include/asm/cacheflush.h
+++ b/arch/arm/include/asm/cacheflush.h
@@ -340,6 +340,8 @@ static inline void flush_cache_vmap(unsigned long start, unsigned long end)
 		dsb(ishst);
 }
 
+#define flush_cache_vmap_early(start, end)	do { } while (0)
+
 static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 {
 	if (!cache_is_vipt_nonaliasing())
diff --git a/arch/csky/abiv1/inc/abi/cacheflush.h b/arch/csky/abiv1/inc/abi/cacheflush.h
index 908d8b0bc4fd..d011a81575d2 100644
--- a/arch/csky/abiv1/inc/abi/cacheflush.h
+++ b/arch/csky/abiv1/inc/abi/cacheflush.h
@@ -43,6 +43,7 @@ static inline void flush_anon_page(struct vm_area_struct *vma,
  */
 extern void flush_cache_range(struct vm_area_struct *vma, unsigned long start, unsigned long end);
 #define flush_cache_vmap(start, end)		cache_wbinv_all()
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		cache_wbinv_all()
 
 #define flush_icache_range(start, end)		cache_wbinv_range(start, end)
diff --git a/arch/csky/abiv2/inc/abi/cacheflush.h b/arch/csky/abiv2/inc/abi/cacheflush.h
index 40be16907267..6513ac5d2578 100644
--- a/arch/csky/abiv2/inc/abi/cacheflush.h
+++ b/arch/csky/abiv2/inc/abi/cacheflush.h
@@ -41,6 +41,7 @@ void flush_icache_mm_range(struct mm_struct *mm,
 void flush_icache_deferred(struct mm_struct *mm);
 
 #define flush_cache_vmap(start, end)		do { } while (0)
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		do { } while (0)
 
 #define copy_to_user_page(vma, page, vaddr, dst, src, len) \
diff --git a/arch/m68k/include/asm/cacheflush_mm.h b/arch/m68k/include/asm/cacheflush_mm.h
index ed12358c4783..9a71b0148461 100644
--- a/arch/m68k/include/asm/cacheflush_mm.h
+++ b/arch/m68k/include/asm/cacheflush_mm.h
@@ -191,6 +191,7 @@ extern void cache_push_v(unsigned long vaddr, int len);
 #define flush_cache_all() __flush_cache_all()
 
 #define flush_cache_vmap(start, end)		flush_cache_all()
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		flush_cache_all()
 
 static inline void flush_cache_mm(struct mm_struct *mm)
diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
index f36c2519ed97..1f14132b3fc9 100644
--- a/arch/mips/include/asm/cacheflush.h
+++ b/arch/mips/include/asm/cacheflush.h
@@ -97,6 +97,8 @@ static inline void flush_cache_vmap(unsigned long start, unsigned long end)
 		__flush_cache_vmap();
 }
 
+#define flush_cache_vmap_early(start, end)     do { } while (0)
+
 extern void (*__flush_cache_vunmap)(void);
 
 static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
diff --git a/arch/nios2/include/asm/cacheflush.h b/arch/nios2/include/asm/cacheflush.h
index 348cea097792..81484a776b33 100644
--- a/arch/nios2/include/asm/cacheflush.h
+++ b/arch/nios2/include/asm/cacheflush.h
@@ -38,6 +38,7 @@ void flush_icache_pages(struct vm_area_struct *vma, struct page *page,
 #define flush_icache_pages flush_icache_pages
 
 #define flush_cache_vmap(start, end)		flush_dcache_range(start, end)
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		flush_dcache_range(start, end)
 
 extern void copy_to_user_page(struct vm_area_struct *vma, struct page *page,
diff --git a/arch/parisc/include/asm/cacheflush.h b/arch/parisc/include/asm/cacheflush.h
index b4006f2a9705..ba4c05bc24d6 100644
--- a/arch/parisc/include/asm/cacheflush.h
+++ b/arch/parisc/include/asm/cacheflush.h
@@ -41,6 +41,7 @@ void flush_kernel_vmap_range(void *vaddr, int size);
 void invalidate_kernel_vmap_range(void *vaddr, int size);
 
 #define flush_cache_vmap(start, end)		flush_cache_all()
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		flush_cache_all()
 
 void flush_dcache_folio(struct folio *folio);
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
index 8f3418c5f172..a60416bbe190 100644
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
diff --git a/arch/sh/include/asm/cacheflush.h b/arch/sh/include/asm/cacheflush.h
index 878b6b551bd2..51112f54552b 100644
--- a/arch/sh/include/asm/cacheflush.h
+++ b/arch/sh/include/asm/cacheflush.h
@@ -90,6 +90,7 @@ extern void copy_from_user_page(struct vm_area_struct *vma,
 	unsigned long len);
 
 #define flush_cache_vmap(start, end)		local_flush_cache_all(NULL)
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		local_flush_cache_all(NULL)
 
 #define flush_dcache_mmap_lock(mapping)		do { } while (0)
diff --git a/arch/sparc/include/asm/cacheflush_32.h b/arch/sparc/include/asm/cacheflush_32.h
index f3b7270bf71b..9fee0ccfccb8 100644
--- a/arch/sparc/include/asm/cacheflush_32.h
+++ b/arch/sparc/include/asm/cacheflush_32.h
@@ -48,6 +48,7 @@ static inline void flush_dcache_page(struct page *page)
 #define flush_dcache_mmap_unlock(mapping)	do { } while (0)
 
 #define flush_cache_vmap(start, end)		flush_cache_all()
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		flush_cache_all()
 
 /* When a context switch happens we must flush all user windows so that
diff --git a/arch/sparc/include/asm/cacheflush_64.h b/arch/sparc/include/asm/cacheflush_64.h
index 0e879004efff..2b1261b77ecd 100644
--- a/arch/sparc/include/asm/cacheflush_64.h
+++ b/arch/sparc/include/asm/cacheflush_64.h
@@ -75,6 +75,7 @@ void flush_ptrace_access(struct vm_area_struct *, struct page *,
 #define flush_dcache_mmap_unlock(mapping)	do { } while (0)
 
 #define flush_cache_vmap(start, end)		do { } while (0)
+#define flush_cache_vmap_early(start, end)	do { } while (0)
 #define flush_cache_vunmap(start, end)		do { } while (0)
 
 #endif /* !__ASSEMBLY__ */
diff --git a/arch/xtensa/include/asm/cacheflush.h b/arch/xtensa/include/asm/cacheflush.h
index 785a00ce83c1..38bcecb0e457 100644
--- a/arch/xtensa/include/asm/cacheflush.h
+++ b/arch/xtensa/include/asm/cacheflush.h
@@ -116,8 +116,9 @@ void flush_cache_page(struct vm_area_struct*,
 #define flush_cache_mm(mm)		flush_cache_all()
 #define flush_cache_dup_mm(mm)		flush_cache_mm(mm)
 
-#define flush_cache_vmap(start,end)	flush_cache_all()
-#define flush_cache_vunmap(start,end)	flush_cache_all()
+#define flush_cache_vmap(start,end)		flush_cache_all()
+#define flush_cache_vmap_early(start,end)	do { } while (0)
+#define flush_cache_vunmap(start,end)		flush_cache_all()
 
 void flush_dcache_folio(struct folio *folio);
 #define flush_dcache_folio flush_dcache_folio
@@ -140,6 +141,7 @@ void local_flush_cache_page(struct vm_area_struct *vma,
 #define flush_cache_dup_mm(mm)				do { } while (0)
 
 #define flush_cache_vmap(start,end)			do { } while (0)
+#define flush_cache_vmap_early(start,end)		do { } while (0)
 #define flush_cache_vunmap(start,end)			do { } while (0)
 
 #define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 0
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
index 7b97d31df767..4e11fc1e6def 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3333,13 +3333,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_to_node_fn_t
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231212213457.132605-2-alexghiti%40rivosinc.com.
