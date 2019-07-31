Return-Path: <kasan-dev+bncBDQ27FVWWUFRBOMAQXVAKGQEXZE3CUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FA2A7BA7F
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 09:16:11 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id h3sf42273916pgc.19
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 00:16:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564557369; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQojAIxSe7ayWMDQuTau/D3vpIMuK+qKuIsSKBQZ5hTX/KoOr5a88yHbFFtePhEZeP
         hw/el/j7rqHHcaMO8wTtl3HlAoa9wO5kRUfIxC3S+dcydwHMzDsPaQ3EEXMfx+XvBlR8
         eenlQ8gKCLIKsw+sO691zkt9lT7wb99cnb/X7nofDTG9lxo81XEVIC5Cst5PcS3EYa3i
         1iy1Si/sGRRyk+vWAvxuDvT2tTBk+5BeZI/qu4TLdD3KIRNyBhkviQ4003uo6arr4Elt
         mxO0o8416VhN2Xy2OASVuN4AzLIQmaB+ef0l5FY+wXR6pmseDcZKOU0M+PaFNp1aqDiJ
         xq8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wTHjPlvhn0j720XofoCnBYvvOOlFIsPJjDuDD22qZzw=;
        b=HFW3adOaNeIBtcMZXt0GH+QLniJ1VOgYw8YOfBcoVUJuuodGY9tZLbWXKk0aJvI2eT
         Uz4dPc3oCXtPT5xc5aJwGgnmbEDfeqt2r2yLLbivUXQvK8O2hDpkBWmUDfyQc8Yqp94A
         TA7IS1eZ1fTzCysxH+J4Zx1d8vee+Z4soLiD8vC/vsoFxYHEvh7KkRPgcv+bgIDhMpR+
         gamC05zVIHmE/y2RfgZ09WUMW7BixqQDMb0detfZj0bxtIWfyUDZoUkr1cLG7Xr+0nt0
         siCdKlP5cmb1X5b4br7i5v73dKVgzcafRqHWZ17BTUAbmHFrEzg7Ur/cwmKIQjMygCQQ
         /f7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ClaBu1v6;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wTHjPlvhn0j720XofoCnBYvvOOlFIsPJjDuDD22qZzw=;
        b=UFY2TbM32VCPPKrsx7Wekx+0PuB5s/K6GMooRFc/6TrfF5PJWIEhHpjLo9Wb7rMMSm
         sjZe4g8I+JHTwYyLqIbNMlxa1E6nF5WNO4S1m8Z9X9fT1GBzXM63IYXTkDa31g5mBVqH
         8Xr4beLO4lwDSx214hz+dVNbehIGrC5a188uIwNvdYgYa6mrxFBqGQVqPnYn6zoKbEEr
         es4LJyBm35qeMPlt+oUD+M87qzr+KfSK6VZLBitUlOucizriMOjcW0l/u/8S+w6XRW98
         JYNQaHM3nGIJJMuypHluCERbEi82yN2l4NkF/UfwxUjIT6M1Yhl2K1xcQQJAr3s/9AoK
         23Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wTHjPlvhn0j720XofoCnBYvvOOlFIsPJjDuDD22qZzw=;
        b=bnSgxzNab7VDAWU/y5WZauANVc/11vvIHQTnNcWjky2VfwO571/WqVcuaSqohTRvmD
         4Z04TxdHpRmMvs94HmXSDnxvqLZshkXh+TYp6nyzz80Uo2CEW0gitKSn0nom+OxQPnn1
         CnmHExnzxzp0SG7GcdV7B5agRfgQt949Yx/5ZmfF8d+EyObwIKKhmIGUlkMkmqFtQk6R
         ThGsO2LxfxiPFYDS0dtYi9Ixv4hRGkz+VWkk8sm40oA3WCWhbg10p5IOXn/bNKfQcu3Z
         qSUInidE8V/4TYAZEayuNlwmHNTbHK3dxyQSr/VTzbAxcTFkjv8c4w4htmrIiwF/0uyO
         CvMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWwGlJSIuLkP6GKrwe2jlnfMme3vu4kNKdrtcvg0bmPz4LJz5At
	PsKzk1bSaVnRNN082/dLJtA=
X-Google-Smtp-Source: APXvYqx8xU1YdKIFLYjLOQiJobZ6tjQWWrX0htuo2wbmHu09s/EZXT9e2EnH9Zqhr//SR0eXUZWjSg==
X-Received: by 2002:aa7:8b10:: with SMTP id f16mr46512327pfd.44.1564557369658;
        Wed, 31 Jul 2019 00:16:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:740a:: with SMTP id g10ls19369686pll.0.gmail; Wed,
 31 Jul 2019 00:16:09 -0700 (PDT)
X-Received: by 2002:a17:90a:33c4:: with SMTP id n62mr1489584pjb.28.1564557369385;
        Wed, 31 Jul 2019 00:16:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564557369; cv=none;
        d=google.com; s=arc-20160816;
        b=jyR2lHSH/Ft2MOgH8mul81Ov3jVKnQE+xk5zLlCCaC6CCnRqixbZBYRcCWXx9Jr4Zl
         4b7tcNQ331HUiydi/mepX6+jHxNEebNHe/2x2bdxaSDRFKD3SWWd4UfB1P8BjivvqcYx
         jv+OLsXdnuFDwZPozVKgXGZ0uHnt2bks/XsiVAQNU3tsj1xvuevc6LxyMjYnRPQNZf85
         1iYCpHZ3nuRSSDwRiFSeMJPZZiPqQyqhf36ynAwLYtwDrQhZzUjRds/Y15+lRQsOROK4
         wpzQ6WFnC0m79ZGZtIl+S7DtvMVg62VMSjgsAJGPuE24+eyjqJy3ODcuL4xHyNMbHeEl
         2ZlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UahEbtdXwZNAU+KwZPeJAGjgE2lYz0Dt6XczqvKwLUQ=;
        b=fQaRWDqJ06NWW2VvqJ4R7CJdvjV2O7R95g3c2N0DeadTAXXsqw8GCShFGr1Cv1ft2C
         4El0rNW/EvAj1eU8Cb/cOrFoumexLIjXyDWpbAjrgjZZXCD5h8OpkIUNeiIRvIiP7n4t
         jKCpddbHPJaQCMcNghyT+ROwQhe7r5H9eWhmHPQIK9iQYASYD9Yp0HU5VaJzTeDiJEDC
         X50eDKSY9Up/QvfXVL7/JuazPlPdJrS31+Uxav9qgkPa/awduaPTrqtY7celUyG/lN5k
         lPbxld8kY4mnKY1IPWS9K1twG4XkolBoD2+DD0orchUMqC344vZcVaZofC/E/RtROGIx
         Gu/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ClaBu1v6;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id m23si2344511pls.5.2019.07.31.00.16.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Jul 2019 00:16:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id i18so31478363pgl.11
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2019 00:16:09 -0700 (PDT)
X-Received: by 2002:a63:fd57:: with SMTP id m23mr47211876pgj.204.1564557368818;
        Wed, 31 Jul 2019 00:16:08 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i14sm104075707pfk.0.2019.07.31.00.16.07
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 31 Jul 2019 00:16:08 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 3/3] x86/kasan: support KASAN_VMALLOC
Date: Wed, 31 Jul 2019 17:15:50 +1000
Message-Id: <20190731071550.31814-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190731071550.31814-1-dja@axtens.net>
References: <20190731071550.31814-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ClaBu1v6;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

In the case where KASAN directly allocates memory to back vmalloc
space, don't map the early shadow page over it.

We prepopulate pgds/p4ds for the range that would otherwise be empty.
This is required to get it synced to hardware on boot, allowing the
lower levels of the page tables to be filled dynamically.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v2: move from faulting in shadow pgds to prepopulating
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/kasan_init_64.c | 61 +++++++++++++++++++++++++++++++++++++
 2 files changed, 62 insertions(+)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 222855cc0158..40562cc3771f 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -134,6 +134,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..2f57c4ddff61 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,6 +245,52 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
+static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
+		unsigned long addr,
+		unsigned long end,
+		int nid)
+{
+	p4d_t *p4d;
+	unsigned long next;
+	void *p;
+
+	p4d = p4d_offset(pgd, addr);
+	do {
+		next = p4d_addr_end(addr, end);
+
+		if (p4d_none(*p4d)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			p4d_populate(&init_mm, p4d, p);
+		}
+	} while (p4d++, addr = next, addr != end);
+}
+
+static void __init kasan_shallow_populate_pgds(void *start, void *end)
+{
+	unsigned long addr, next;
+	pgd_t *pgd;
+	void *p;
+	int nid = early_pfn_to_nid((unsigned long)start);
+
+	addr = (unsigned long)start;
+	pgd = pgd_offset_k(addr);
+	do {
+		next = pgd_addr_end(addr, (unsigned long)end);
+
+		if (pgd_none(*pgd)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			pgd_populate(&init_mm, pgd, p);
+		}
+
+		/*
+		 * we need to populate p4ds to be synced when running in
+		 * four level mode - see sync_global_pgds_l4()
+		 */
+		kasan_shallow_populate_p4ds(pgd, addr, next, nid);
+	} while (pgd++, addr = next, addr != (unsigned long)end);
+}
+
+
 #ifdef CONFIG_KASAN_INLINE
 static int kasan_die_handler(struct notifier_block *self,
 			     unsigned long val,
@@ -352,9 +398,24 @@ void __init kasan_init(void)
 	shadow_cpu_entry_end = (void *)round_up(
 			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
 
+	/*
+	 * If we're in full vmalloc mode, don't back vmalloc space with early
+	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
+	 * the global table and we can populate the lower levels on demand.
+	 */
+#ifdef CONFIG_KASAN_VMALLOC
+	kasan_shallow_populate_pgds(
+		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
+		kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
+		shadow_cpu_entry_begin);
+#else
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
 		shadow_cpu_entry_begin);
+#endif
 
 	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
 			      (unsigned long)shadow_cpu_entry_end, 0);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190731071550.31814-4-dja%40axtens.net.
