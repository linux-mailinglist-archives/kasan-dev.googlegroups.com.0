Return-Path: <kasan-dev+bncBCCJX7VWUANBB4EM437QKGQEGM4ZSDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 85CC72EFEF4
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:33:21 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id y187sf11306050qke.20
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:33:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610188400; cv=pass;
        d=google.com; s=arc-20160816;
        b=jAYQ4lJMKXsfdJnWvrYDitbEVdcs7UJ1VT0WPlch0yIpHo06D+3maqX1evPfAr9VDU
         qLPBMFbulTblUDaTP85154lzg5GE2Kk9WOHXu2tbBoZKRLwIUgqmA970cDeJwgaF7Diy
         +MJfANkX60fRsKZtaM3GtsHv2eCk6hWD7ph2RrYEyXsS3BoCIOfol6VTBbJv4pE191nr
         zbtbu9PggrroKCQnFfzklkjZ5EKJ2pTOL7G/WPKZLCGNgDFr27ETn64wdX9hqXNPO+qO
         J7aBPOl0nayuV/aF884Rj8XLORrJZId+GeC1FHtNB31hq7wZEe72AFo4EqDJ9SX3vJCO
         Iocw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=E7l05Uk5FXVvQtZX77BR9eNsauN58wIYX7MW6htoUbE=;
        b=wg91hTpZpbnjsh1UVBpa1uQR/LcFNMaVzEz0oxCySne+pyj5tpey+PhYGI31DG69qa
         EFKLe6S1Ju9B+wsDfjm0N1Na3p416CrR2j98yciQ2admatIxlqlJMEDs5KmzYnmUkOb+
         S5W51IiYzbzDssFjmPkdCQ8BnfrxWao9G6OIG+QUgWyKxx/6zdYmI3Ju0PB3Y0DIPUZa
         UL+5Xm9+8tQJZ33znX5bJWlATUOMm75Fr+g+xKugYj+Ula2XiRMUHGPSDGwAhOl5bFrK
         oIVb/YQ/GLdYy8xb59uimMMdlC2DndtiszQXi+blSTdvB0ICqFrRUQfDptdn8+6OKI1N
         B7AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tznSyNRi;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7l05Uk5FXVvQtZX77BR9eNsauN58wIYX7MW6htoUbE=;
        b=qMXXWl5KGqSpIIBt6LoTv45vXTbn8CgIlQ+PqP15Sus7O1qu5QhnToXOKZR6J0l16Z
         BJXZhHbTc9P87X7KH4F3aLkj6WC7ukCwbmZstzXKBYKV5DO4ETy6bx1I9ame1/KCUCgU
         xhqaYJxYCinRp31ZxVJvajoDfnzX53Zz94c6Qfd2Y32TU32TmssVO8zwkkm9ntoQdNe3
         FhARTpHmv7Hd+O1J0rismJ9N8e7f5n3qCKOjtrprAAmLOZp33z4oYBXFbHnAITjOW3LD
         KPKAS4kr+/9gpITDnwfDpridJf5vPiiMVO/tovtRT5uK7wAN/GEYMxkhX/VmFvRe+Lv3
         tSJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7l05Uk5FXVvQtZX77BR9eNsauN58wIYX7MW6htoUbE=;
        b=ic9letY6W+tL9HWfGcH8E+acfVvk0pCjHo9IbGw45EL1lbrZpLFYqsF+FfYDdDDaDZ
         GBy5LMJgqRH5ETxxjJ00z0YdmdaWUcqvTmZixVuvN93+4wNGehWSt1b7KKrkeaVrnbYG
         vKjVLzM8Cn9i/3oTTwd2LE+h+4lhmXJw0eLUqUlc8E0+qdD5Up63ToJu4cNZuI7uyp1N
         38nZr1gPuOxj5+PVJckPev7EYSuzkqQzmeR1qpujADR0dolkXjKdJpRG8ZK5jUcxPmGg
         2xKOIxh0u3A09h52NWNs7LKDmgj9UOmsZVsNqvMC3lcsY8BSFZfcaQCoRMKAAEawqXQO
         yYQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7l05Uk5FXVvQtZX77BR9eNsauN58wIYX7MW6htoUbE=;
        b=ilGaHDuVR2a4rm1Z88BbhaR9AmlImqyfCF4F3XLb9rJVM0IJ66Tff8ABce7hNP4fgv
         rvZVLS9C+b0Fn/SU2a+vPAyaVIwReG4joqVA6GiJEK8/wtb80Ep1debWI1af+06shHva
         jieqUkOrs1Ak8xOjsLPfWcw2H3j28vwX2i0N7qE82goL7Ox+mv+nxLseFOb8OBd0YEml
         y/lzbRhwKeJIdj+Z+l63hFW/1iN/dmJqIpqZBK4fJ1G9Xa6xrr9QPt3ywTsSQdDLdo7I
         wSXCA0DmJjd8sW4av/HS9hLXHIJ99frAUfFsz5a/09yOAo+NuAQqphfQy1IEb7/TGtbE
         +sug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dyMiqtycoxrXAJo+5zBqSl0yGmTkAaRC1DIUQyz9EqIP27uRR
	T+wBkppHirUE32+XQ2WJgvE=
X-Google-Smtp-Source: ABdhPJwDn503KiTm8RDL3mtTWRbOlKEmVxJ6kWoXueRYNCwu53eg94mwiinuiNLZOkImZ0LQWskn4w==
X-Received: by 2002:a0c:fcc5:: with SMTP id i5mr7756944qvq.48.1610188400627;
        Sat, 09 Jan 2021 02:33:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5ece:: with SMTP id s14ls5260234qtx.4.gmail; Sat, 09 Jan
 2021 02:33:20 -0800 (PST)
X-Received: by 2002:ac8:7190:: with SMTP id w16mr7396540qto.134.1610188400178;
        Sat, 09 Jan 2021 02:33:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610188400; cv=none;
        d=google.com; s=arc-20160816;
        b=TFLm90VrSr6nrAxCfxtAlfVU4T3k4W0j1k3aOw7POujMN7Beu7COBvj/SQTohB9jrJ
         uEQkqFqBccGSMNVE/TNAbqLxd0XxWK1qO2WjaH1/N4acTRfoTWKF6+66+LeOzQ44RHDo
         qzWQgtVRk9ahAGzeCf5nsNjQyOzF4vMQiuv2gjItZOd7hwt7b0nVwoB0K2CfrOMEvsFh
         Gn3qJnrLFz82ZIRbbYAVmhLgw8IGQJKIPKI1Jmqyr/hKCSNsJNaUBeos7nd8MEYoGWdq
         ikgV9ek3nFGlHhrYO0DBNkOlM0gnYUPiIfXU/zj/nsejJBrUdrtYq6vBb99L6rBXZdig
         oR3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0xLmuarIgQdWn84D3wx5rQsfGRtDVE6UQliEht6Oq48=;
        b=riVM29cIeqEfKM4hS4AYl5XbT5vy2d+oTRmvsn/I2OI0SmAM0y0+8+nNH5x+9wQBQJ
         qHEB7dhYYofLrODBBhXT07t4G1cvjnD3BEwWvM8uxreHjuqsbN3ScATJE0cmtxrjr9ng
         WgmLdRGKNHQOjC1YgvkRKuW8KzvGCM/kKP6GdzgaBaLXBCzUyaYc6NR8dVGhXKkyz/ul
         ZFtRkouQDcCDto+ouOeihGmqi3a94cOy/m2xvpxfJc6u388Ghg+c7MpZRub37thHRVJg
         RTWpBqBP5EFBCmpDSrgu8Rhv+42l5OR6ReAuX8CrH17dOjg14d5elwJXQ/Rtp51SOm7b
         JtVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tznSyNRi;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id q66si849270qkd.3.2021.01.09.02.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 02:33:20 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id x18so7022590pln.6
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 02:33:20 -0800 (PST)
X-Received: by 2002:a17:902:b189:b029:dc:4102:4edf with SMTP id s9-20020a170902b189b02900dc41024edfmr8031040plr.80.1610188399222;
        Sat, 09 Jan 2021 02:33:19 -0800 (PST)
Received: from localhost.localdomain (61-230-13-78.dynamic-ip.hinet.net. [61.230.13.78])
        by smtp.gmail.com with ESMTPSA id w200sm11691572pfc.14.2021.01.09.02.33.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Jan 2021 02:33:18 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	ardb@kernel.org,
	andreyknvl@google.com,
	broonie@kernel.org,
	linux@roeck-us.net,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	robin.murphy@arm.com,
	vincenzo.frascino@arm.com,
	gustavoars@kernel.org,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Sat,  9 Jan 2021 18:32:49 +0800
Message-Id: <20210109103252.812517-2-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tznSyNRi;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Like how the MODULES_VADDR does now, just not to early populate
the VMALLOC_START between VMALLOC_END.
similarly, the kernel code mapping is now in the VMALLOC area and
should keep these area populated.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
 1 file changed, 18 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d8e66c78440e..39b218a64279 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
+	u64 vmalloc_shadow_start, vmalloc_shadow_end;
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
@@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
 
+	vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
+	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
+
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 * At first we should unmap early shadow (clear_pgds() call below).
@@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-	kasan_populate_early_shadow((void *)kimg_shadow_end,
-				   (void *)KASAN_SHADOW_END);
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
+		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
+					    (void *)KASAN_SHADOW_END);
+		if (vmalloc_shadow_start > mod_shadow_end)
+			kasan_populate_early_shadow((void *)mod_shadow_end,
+						    (void *)vmalloc_shadow_start);
+
+	} else {
+		kasan_populate_early_shadow((void *)kimg_shadow_end,
+					    (void *)KASAN_SHADOW_END);
+		if (kimg_shadow_start > mod_shadow_end)
+			kasan_populate_early_shadow((void *)mod_shadow_end,
+						    (void *)kimg_shadow_start);
+	}
 
-	if (kimg_shadow_start > mod_shadow_end)
-		kasan_populate_early_shadow((void *)mod_shadow_end,
-					    (void *)kimg_shadow_start);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
 		void *start = (void *)__phys_to_virt(pa_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109103252.812517-2-lecopzer%40gmail.com.
