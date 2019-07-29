Return-Path: <kasan-dev+bncBDQ27FVWWUFRB24B7TUQKGQECKVTNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 907F678DB4
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 16:21:32 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id r4sf26509264vkr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 07:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564410091; cv=pass;
        d=google.com; s=arc-20160816;
        b=BkhdMU+yKawK1m1LoKik0NewhVitCsJJotSN3Z5jaLGZr8/27/hiIs4ULycPwKhPBo
         n5Fpmz1A1jDg+YXCVsgHB/Jte4IZGs5VOjlKGPl6jo5n+ZP1dx4lsSgdzPilvkmn6TWp
         mkBFvZ8LHIyGOyIHGtteWQhMAGIUJ+KNUCeSOdcPT3OacxfBcOH1RMKz16H0BsfoZNAi
         ES7GlcxTfFDNmWaBez2xC2vx5pUyFPaQVAYdZxGT/ew4/KfIOVWCwdp1h+CrfvchTo3V
         8zLLEgwyybiQpgTHtEdDJEFlNjsiG2nLV2SR82RGNXzA4rV0XMiZ0yqmXhjz9RULDEgK
         2q1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6sEZ9IkMGBCYP7jKsaIs8U66XAcR2MKrEuPaMbB30hQ=;
        b=NMZ10zNMs6RmDUVBRmeDSe5frob5JPGFU6B0CllKqo7HWqtRdtp2qsA2KwW0RxvPT/
         Z1T7RzYzaWO/y8PRO8aA9LpkuPhksPhixaY+ETQmIoSzQ3Jh+JdLsiaeNZwN0gp6dPB6
         JN9wOryhVyNftd7TtmBMYI0+bkGqCCuc2qRK9TXQVtX6R3e/YKeW84cT7TeUdtR96xXf
         QtvkQfmlUIYd1z2B9fpaXpSEjsJcMycW9DYTtB7Vi/TCxfZMyn0FZ+AlXUAANuvRCVAS
         JzFQzirm53tm3O9fdyReKnwpJXRfB/EiOEv6x0ppyc0tu+1steblReOeX2l4bss3wSjK
         vSMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fzL9e9NG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6sEZ9IkMGBCYP7jKsaIs8U66XAcR2MKrEuPaMbB30hQ=;
        b=FHoPGQjmHk+1hCmXMNx+CqQl/7V2xoemWPsPV5CCFweXk9lxVgQYKSbf0GVSqYanMD
         K7rYU5/M23UntvyjJZN6atPYPveTUEJ4Ry4t7zIvKuN1fp8qXuyc1BDtnrg7tbIK8hBQ
         MkBrzNeWaLUiNmcCgeHGtp30pNLYqeUywTmR16eSOnIi1cDmVMiJTdJh7SJlfR5tQLah
         CRtJAq3+BQALozjAZ8b9NTOcNEDES+jr0hC6caQSuy8EGgaX8iEfJZ/cbfY4wpkAVjiN
         M0D4LuTmeMDIAVXPRb2YVtgeo3Y1myMSDzHo36lxBWU9LKKc2hKEl+Mh+WhyQLXIasv9
         2LbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6sEZ9IkMGBCYP7jKsaIs8U66XAcR2MKrEuPaMbB30hQ=;
        b=Ep7uDGcheSVWaO5CGvjo96VHPp8lCkZV3cp/F+nTkvShDAFMtf6rU8AFtJz7fobT/L
         Z6Jz3O/h7u79llHL0HZfCtfyce5vc9im2YMjmTfa89BAcM2SFdwdcygbBHolJwH0n1WS
         l6VTfyoIiNZJJV0Vysz56XIt00CJXgfuglr5Wu0U1HqRKFehE8EYNXlH/THdSUV8xKVp
         Tz/iqkKtJTC/K72H6YtLeKjOlt8AlgbtZfwpQ46ollaKo1WVqOzfIs3MJ8jIAt/5ao9x
         Rgdkps48BJvuWEUhBQC8sdTooB1oqEIuXUTEppSe6AxCND00cBOGUPbESiolZ9erGCc9
         F2xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUTLTJml5exmSyFMnMr0MdfjAAKp6j+y75HwRYO0w4WCURXOinG
	Ew8rjIQtP9SNMq98gW02CTI=
X-Google-Smtp-Source: APXvYqwXRn6l0jEHal2dm+24Vipq/e7I6PCNMjA8AYOfHq0z2Tilqw1jLJrIaeF5z1Wij3U5L+sgSw==
X-Received: by 2002:ab0:2e99:: with SMTP id f25mr27426256uaa.133.1564410091650;
        Mon, 29 Jul 2019 07:21:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8d08:: with SMTP id p8ls7717315vsd.10.gmail; Mon, 29 Jul
 2019 07:21:31 -0700 (PDT)
X-Received: by 2002:a05:6102:3c5:: with SMTP id n5mr29312707vsq.56.1564410091369;
        Mon, 29 Jul 2019 07:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564410091; cv=none;
        d=google.com; s=arc-20160816;
        b=IHbrZiQjofhBYpsJoC3YNvEQAZ0E8gbZJ/YRT0SUCE3JGrw8cEgCsMohuVT5Nc7Epe
         AJtHCHDoBTbW0Gy89qWrZSDk/m11+7xndv3BPWR4qi0ZrXIj4EsWjAyI+c6thtQcNzX2
         woKriG+1shY1b+kYoo5U+Je+uVgLgBIdSa76r65K3gEpQ1w6FqLIGaSpAv/GVmBEgWON
         4m1d8SX1wz9M/g1DWnqsdoH0IwsJSnUMY90W2jFlr08Vx7P0vSor8Kj+EqrtTM3prIPl
         ZRtCdIwhMkD1wJFubwziTp+44CFND1gDfHfcxf8Mg2+jIx1HzqYIDJ+PN/DRA6xbGWsl
         ep5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UahEbtdXwZNAU+KwZPeJAGjgE2lYz0Dt6XczqvKwLUQ=;
        b=gR7xirBoGajf2YJ7pRkwyhjZma8wzARksbsFnhnEybO6l8QR8VvgD3s9Rwje0RR/cY
         HkyRPeCLNI86eOLwlUaHFduv8KOyZRNCPFXQDj0dt4bAGLbKwi9XUBToaPXobysVN81d
         /a8u3oTA+5l7BnUNS4EfzHlSPSWwuSoyUzScLwQuXJbYAHn2dCeAYQWA68ZHXpojBWMN
         UGJ3wDKGY1yMBcqZ8ZnsiVeZZxtcaYQ4iHyJ2XbiPNS/0IAeG895DMHza3tNx65UfJrw
         wL2ANl8rFczpj3BLbicUIFM5vtLfenTxCXZocz16oZb7VZ6ammCIwOhbJ1RqviMz3Lnn
         WrIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fzL9e9NG;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id s72si2814611vkd.3.2019.07.29.07.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jul 2019 07:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id o13so28331336pgp.12
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 07:21:31 -0700 (PDT)
X-Received: by 2002:a63:2026:: with SMTP id g38mr98776818pgg.172.1564410090185;
        Mon, 29 Jul 2019 07:21:30 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id s66sm65997285pfs.8.2019.07.29.07.21.28
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 29 Jul 2019 07:21:29 -0700 (PDT)
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
Subject: [PATCH v2 3/3] x86/kasan: support KASAN_VMALLOC
Date: Tue, 30 Jul 2019 00:21:08 +1000
Message-Id: <20190729142108.23343-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190729142108.23343-1-dja@axtens.net>
References: <20190729142108.23343-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fzL9e9NG;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729142108.23343-4-dja%40axtens.net.
