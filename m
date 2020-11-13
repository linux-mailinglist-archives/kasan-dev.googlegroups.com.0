Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRMLXT6QKGQELZA7SWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC1292B2803
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:38 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id 144sf7654943pfv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305797; cv=pass;
        d=google.com; s=arc-20160816;
        b=VS5PV4aMqu+uMsjFD2qFohHtJ3lHtPBsVJ/45jFG8u0sbAWZMGskNovz2CbccaRpHh
         PufIY3XVjnLRtfr/BcYdVdsrLfQsZu/KegZYAw7pKVXHfUngY+yfczRu/gnFdN3nnMT8
         r01DDoqqRm11zo8My4HKTouo7PiqXcYv/GJOuNgXReQS7gGEh4ZvJA2+TY1Hhvz+ikBC
         y8uHQ6PRdJJ6csL5W8DjUSLUUeH+DnrIsYeE7NJCGA5cXaTqklY5rGu2usi5m3a99pmz
         38CfcXFCv47XV0ibLOiICVSlm3vb9uQG79CmiCRSezZUiedBmV664LRTvLF14IKvFmfU
         HstQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qgeqwmhCTf6iG7wK+MjKY4aPKWLaZb5eHP+6UpeCXoE=;
        b=z+iHBUuUaCtptO6bFKNeD/pYah7mfF2dVVRVEIzlAvJwia46sSvOVLynoOUi0sJ3a6
         64fkzYcxQE3r8OtkFidtdGzdNybTDR6qRuIOCEiFsU9JJ8hmfYVL1sNr1UrPOARc3/wo
         giTPwi/HJzHFfiG7EuDvdm2EfCTm6f9wdCgt/9bfBapGrNXzPid6uIwrilaPHnkasPsE
         fwqpZZp2YhZHXDCPPqocvOLH2xoXYBR8agwMC1w7BlMrD7infYjbNU6gjLuB5Z171Q3r
         e2w1+OU4qfYB+MxVifWl+adv4PjhNejQUE/zCepjYHEuuNG2R2ETp7Ok5O4n+vsiWo+U
         dayA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A+gL+E2K;
       spf=pass (google.com: domain of 3xawvxwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xAWvXwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qgeqwmhCTf6iG7wK+MjKY4aPKWLaZb5eHP+6UpeCXoE=;
        b=pUWNxIIg4HLrHprT16KPaA9zJDRQeJW3jTXnzFt+J5QjdSmDaHMXayeQRz4lG+zZ5v
         IU3ZmikrmeijTeQR8y2nWdwtuAnKnkw0CZ9dIRinZB9IcJkeYt+igznd4L9EGsMmshRr
         ZQFayUaIWyjKr6pNnCld4cciaAKwKIL/GSc6BQsZEF/RRGXrrnRC058dEQ1cW1K4nxAr
         dNg5lgo/JEWrYLvlsR33h3VUKHvmSHMx6/G32mZrEult2m3RRhN508lQWawyzK43c046
         7M+p/rJDujRARfHm+rySFn1Hbn01Xvf7ZF5+5jqbMqHTZEg4c6obEYKdtwKPqF5gCMz7
         DU8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qgeqwmhCTf6iG7wK+MjKY4aPKWLaZb5eHP+6UpeCXoE=;
        b=BcpzI0nNpM+iCCPcDacc6YEPxNaQDbhRNYJgxNvCtEPe9ZaAFGmZ3b5B7Ayv96Qtxn
         IUKWWpoYsKcqFnkem5olDUo6Ibu7sqrANYxaxQcXTpE7MS0P+PeGY0Pp2rhl5lmgoQTH
         8QYEoij0a2Ang+cApbcUmLaeA6vlU7J8+kPBD/H1vFJDPN9a1I7ny6amkT+Oafewxlh2
         433nCQo0M+LZPIuquzF1b0AiyNZJgqFmo405QX/wcYDruUWFCaGTflUJeSA1hulXCQZY
         Dk/LVmeO50W05uxbGY+xcujTvc8Kjz9WqpTyVs4bzaFSfKlrQ+tzA7c0C0YcZO4cs8LT
         mqTQ==
X-Gm-Message-State: AOAM530a3Tcwdo1NMDFY8aP5eYKr2ll/MIIH2pLFUALdu+R4Pq7/UwRF
	hswignFmNVVPuyIhLL1J6BU=
X-Google-Smtp-Source: ABdhPJyh1SIFDx8+IqjPimOPqbjWEfdrb5ZXoiOlZ32IcPoeXsbZ/0vgFgmB6B2fnsfcGdF6FSEdog==
X-Received: by 2002:a17:902:7b90:b029:d6:ad06:d4c0 with SMTP id w16-20020a1709027b90b02900d6ad06d4c0mr3636575pll.35.1605305797406;
        Fri, 13 Nov 2020 14:16:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b82:: with SMTP id y2ls3648044plp.5.gmail; Fri, 13
 Nov 2020 14:16:37 -0800 (PST)
X-Received: by 2002:a17:90a:940f:: with SMTP id r15mr5083789pjo.219.1605305796873;
        Fri, 13 Nov 2020 14:16:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305796; cv=none;
        d=google.com; s=arc-20160816;
        b=N8ZhzoYQmHBAUuitv4M8KSwRcWJcHGWvyDvmQu1cNfKcJ5FyYq198YGiH0hRFWdwhD
         74cxXDLieu2HZdTSKBTmlKMgLNz35ksCJRm3jwzmFhcLAvHBR+c8ofd84aV91q0GowTF
         uLTW0yG+p/IXKxxHn1/1T9R+tbFfeSAGVv0vogD0N46ezt4cXZWFTXq4ILhV0wI+3jKR
         3xGFWVY9ICrBuOPprfGa9qHPATGvimgFoa5ErewZoD8tgZLEF+BMKEBSh1sdqPV7hlcI
         FJKkDScr7Ed0KWR9IK1SI4CIsUilLaXNhyCofX/K1OCEBGKROJ2665zacpxa+UwT8KXD
         j5BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DCS5SBsJzS3y9SMPHdgCSO0YkPjeiiQV5TNLKbwTzYQ=;
        b=Nesim4gew9844bhI3I1KTR27EVB3FewnAcCVKFic1H4Jm0mwlxY3XRXATVllMlIP88
         Td9wfnVR1AWGEREwVIQVcM3LLmiLucRTs9atTMWOQolh3d2XvkEZ2W80+JsPF1y0R4Tg
         CZQrhKJzz+TAW41YLjbd3VdC728qv5PnweP1IdTE8u7kRZnpBmJaMUmgizXmIrY0H1gM
         kzjuHIDoyezFVCHn0stE0YePC+MBGuPegzKh8piN60xSvqjFbXaccGK4Yw0Y2TaIU7U+
         pnbw//DiwxYt5Cu8Mu8SiHsNUJ7f9GKIsuav7jS3axUizQfVFBeOPgRPkJ7SSPJuu1YE
         j+NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A+gL+E2K;
       spf=pass (google.com: domain of 3xawvxwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xAWvXwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id b26si753635pfd.5.2020.11.13.14.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xawvxwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id n12so6645510qta.9
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:36 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4e13:: with SMTP id
 dl19mr4516709qvb.24.1605305796028; Fri, 13 Nov 2020 14:16:36 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:37 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <19601c2110760228adf7594385db4508f62a5721.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 09/42] kasan: define KASAN_MEMORY_PER_SHADOW_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A+gL+E2K;       spf=pass
 (google.com: domain of 3xawvxwokcy8t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xAWvXwoKCY8t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Define KASAN_MEMORY_PER_SHADOW_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT),
which is the same as (KASAN_GRANULE_SIZE * PAGE_SIZE) for software modes
that use shadow memory, and use it across KASAN code to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  2 ++
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 13 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..bc0ad208b3a7 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) ||
+	    WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_MEMORY_PER_SHADOW_PAGE) ||
+	    WARN_ON(size % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 53b095f56f28..eec88bf28c64 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -8,6 +8,8 @@
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
+#define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
+
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
 #define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4264bfbdca1a..80522d2c447b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -174,7 +174,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_MEMORY_PER_SHADOW_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -445,22 +445,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_MEMORY_PER_SHADOW_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_MEMORY_PER_SHADOW_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_MEMORY_PER_SHADOW_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/19601c2110760228adf7594385db4508f62a5721.1605305705.git.andreyknvl%40google.com.
