Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA7ORT6QKGQEPCZVO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E45A2A711D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:32 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id w79sf107834lff.8
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531972; cv=pass;
        d=google.com; s=arc-20160816;
        b=NwrhObf9LqQ9xa+0V9sVuBVtpkHrsYINHgyJvhu1zkZd1qsqN8Gei/FCePh1SD4hd5
         qCpyJ9tm0W/Yo6CpyHEATJUIioMaI03THoNPRVy35rbmlCGtBfmjDJPbgNTxCyX/FVkz
         fn1aEHOV3LEPeXa3tVPu3cG23QcQTUx94VVFxRMeCJbuct274pvA+il5JIbGUanMjEDh
         WI8YEd7kon7wTcrLmCTWsPaukGVVV299JK8hwicYV+ucmvfNJ+Bb2dPcT+LIq8XnD2cb
         quHcvXGqaHQnu6dBe4cGVJTD3kik+awdK7SfgMm/UZF4v831kbJ+3ibnr7NTWm5AkDvy
         ZZdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fH7dObbC022PvXGnsR/I88ewD9C+rKruTjmOEq2KoAg=;
        b=smx5Oo/Vhl+lDNUdetoMADwR3kKhbyt91hb8Wghiu3Yp8n8e4DCnf01UEuQ9bJboto
         NzO6A/RHl4/Jz6pIXfhWwj/ReykE0ki5O9FWLi1/zres9zBGydCqXOYFAV3i4TMknk9E
         gK4lXJexl5U0dTlfukso+MgPk68gEBFH2Nhal5Tn/ZaEq2cViDBwo7nJPlCHwhZRafVs
         prcchNz537EWsxgAFXgGgKaH4LM+uILcwI3Zh22jSRl3x9p9BvC5nXbB92TaN/LgOdAJ
         UVdo1LZEoIO9ioMH3zNq8qOq2GdfGOB8aQ6K0LV0PCClLc4XpgUppdP1wi607NDOxtHg
         +Hvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pZCGPEAL;
       spf=pass (google.com: domain of 3ajejxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3AjejXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fH7dObbC022PvXGnsR/I88ewD9C+rKruTjmOEq2KoAg=;
        b=hk+AiVyG0hhpKPKG/0aQW1NuCO/B4KXko688bVwX/LdVWonsseFFVRVePalnxCY4Nj
         B9jry7oiV4imSHHx48AOZzQ9HMhpJctFv5YLlW8YFJ/DdBPXvhk3AIvDvO94cyuqE2Tw
         PZKGwhmHzSOOb111PfcmJwwrp9bKmo/WpQ5Gqn0kUBUT8WzFC1Rt/DWK1Smnyv34GhXG
         FVbAnOvOnbvqMLbMfvXDqB1S8Zm+lKKKxXupa1kEd3Vzp0MrlJmU5hiBw9YswiFzYG3C
         LZM455AxOwtKHk9xfatWlL93eZhOwJneyuP/Eg4KRHHkdBwbFduLw7wj6TRyUHwAhX8S
         1KIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fH7dObbC022PvXGnsR/I88ewD9C+rKruTjmOEq2KoAg=;
        b=aFG3fihxvmw9/vjvRNnuhmrirSnOiPBaec3wadXhQcqm2EzQmsYeJpjZdsSXl1PK3h
         5lN62JYa+lknErecFOQ36QiZv5EfMKNO3xcbvNym4u3V0zYgJfqxIwGYxJN3fMRZmz4S
         XHE8i4ys2kTAGbSHtwTNXXQffc6vFb/WCxITIp56j+U9o2TDPscvBB4Mh9iPQK4gUJ0v
         ivOIBwEyz4A6gNXZXqFxyuPyO0o/YROLagAwBn7gXTBiSij0j0tEqbM7kE9Jtm1ZQ8D1
         p2yOHSmZP6iz3EmZfXzpZJsyK70WunYOdJsqY6FXmms7Xyq0ZDm5PBLudQXnDCQFMO+F
         6odw==
X-Gm-Message-State: AOAM532rWpgGMMfmLE4LUTQ0ozh0cjWCPguNltwn+EU+MCRu/qBJ1LrJ
	2Lk7UE/pFjA2GEs+xlWluX0=
X-Google-Smtp-Source: ABdhPJzUqI0JEGnxr0pu1y6NN2KqaclTDC8CFVXaFM0MCuBzYdBh8kVMrmxQiV4DvfvFVgInxVmcew==
X-Received: by 2002:a05:651c:1205:: with SMTP id i5mr110963lja.283.1604531972163;
        Wed, 04 Nov 2020 15:19:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2255336lff.1.gmail; Wed, 04 Nov
 2020 15:19:31 -0800 (PST)
X-Received: by 2002:a05:6512:360c:: with SMTP id f12mr23385lfs.566.1604531971272;
        Wed, 04 Nov 2020 15:19:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531971; cv=none;
        d=google.com; s=arc-20160816;
        b=1LBXgRGY2vjPaYGwBWmiRxSCoglWi1D1+J/HPc1Z4Ew+noaCf8jhy3o7sXBElwLEyw
         mlz9cYdY9mGFyoP05wwotJbMA1Qfr1P0caGwHVCimVu7dHIcPvofdmyGU6LMSE5YEg5j
         feb+VZxrbZE22Wg7N6H4+rrLSegYmvab996Kif5LDU3fv6LtAt7+2+YK0ghthkeVx4Mo
         +pMu0eY0IExKpbwQL018rPfPaiy6bTtI2DoJzthvrAgaTeuP0v8sLCqgPoyxTMl/OJH2
         jBGgBoyyVehfUv3PEscRyp50esW33iR3AJkXICN7ot/Kt10GfIqp1wju6qIB2VBEwCuo
         oK7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iTj7fpm+BobKW7u0A61d/nWdaAxx5isZjXZgphVDAO4=;
        b=nGlmZ2vC5qyT/tzyVG9P7RZ2LQhmFt5dp/Ip7IxO/yg+ms6Wn0dQlG58c5ZxAnU5ZP
         JNuo3yeHFhFKowb7FNuu8061T+rskqwZzbuAM3pIjAmKlQo08m2zn0A62SNb3YM6b6CD
         eob8dpeZh1F/i/icIJR82/ao9J8AYtQoTuHmJP/a+HXDOG12XTTXoHWaXD1oPbxWqej4
         hfZdUfPDgnAS7mmGSiz3ySATOxorhbG08aoI7pNwZPzxwoWbT0qzKBNAE0G2AsI7If3A
         ZOvT7NZE9fzqCEtI0cy0jEK4UWbaZRlAfqt++u9VcBuPmMI96PyceElLeDsDmJBR9L37
         bLqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pZCGPEAL;
       spf=pass (google.com: domain of 3ajejxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3AjejXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y84si106737lfa.6.2020.11.04.15.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ajejxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h11so32769wrq.20
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:ce0e:: with SMTP id
 m14mr76917wmc.17.1604531970440; Wed, 04 Nov 2020 15:19:30 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:25 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <0f3b5013869f74b2d8e74aba5ec816c117129f9c.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 10/43] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pZCGPEAL;       spf=pass
 (google.com: domain of 3ajejxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3AjejXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  1 +
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 12 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..26b2663b3a42 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c31e2c739301..1865bb92d47a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,7 @@
 
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
+#define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index ca0cc4c31454..1fadd4930d54 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_GRANULE_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_GRANULE_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_GRANULE_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_GRANULE_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0f3b5013869f74b2d8e74aba5ec816c117129f9c.1604531793.git.andreyknvl%40google.com.
