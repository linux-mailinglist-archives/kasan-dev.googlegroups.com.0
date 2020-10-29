Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7NO5T6AKGQESCGXDDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C39429F4F4
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:54 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id r4sf2815342pgl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999613; cv=pass;
        d=google.com; s=arc-20160816;
        b=c5jV4uWwMlLzAXodyhIZ9rfK67ILJP3G4qmxYXVLM3HL4LXmx5FbyO0cH3hgbOxzpC
         FpWD+9Ijcina5kxky52+Si9tlrTQMWNdLcvgAyWDPDJw1K67jVB5jH6xFb9kp0PusmDx
         gT9GW6N/S1BnnDRYhBDg5fM/IDmCwTT7f8zh9ifU97cVvUOHjkxIt0R8SXQj3wfD10Ar
         5KWSk45dwF4QuwN3vXuINTcrWvXHqdcZmUHx3ugNfuYfz0FZcF6AH0dUbwLvlRZXiBPn
         bgbtsWcpzyE8rtCHMMroJZCcHaPVJ4Me3X8BskbvXtUobT66wLCneS9F+5yEf6uhMvTf
         r1bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nl+wThCkpmZCM5NAVfgGhZQHAlLYLO1ilgM9V2shVzo=;
        b=Go9L4hIkSj4L5RdccI7rdLK5fyc/Ztp8hWaSPTFTmd8xJKrWvS7geqWv67vvS/avZz
         WS3ZQMOvjyLlYNc9WKqxZK0xy1uGbzscUctOcJfVYaWU5l69In6+5Tm0leT813dQuDOL
         OhW48IzshiAv2aFXf4kPhrcb0Y8e/GlMTBvl1yhfHAyd+Je+RZ65dAbqKm0IoaaC/AUh
         uqObAeJvbEG7dNLW5HA/qygTS+fCIjqMlTQ9dyzKAHr+z8xHkTKYOmzzbOw4mhzqJL/6
         rvh7HovPCgnUNfT5J83bCR2e7wyyOxqG++bQBXur65AuoTUvUb02A6nP8DabjC6vtcTC
         YAJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BO08Bavj;
       spf=pass (google.com: domain of 3exebxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3exebXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nl+wThCkpmZCM5NAVfgGhZQHAlLYLO1ilgM9V2shVzo=;
        b=o+JjMTkKTrMc53zDKs4oFQtTPrXJBm6aZocefyu3/Z9z2N/B/0jrobnAaUhgH8yEHE
         5wNLTXf2pxaBd+Jenl3a07nA3PCgnLY9XvkdEpyDKc6rE/Jt12qQPuc4yDh5lPIWVfpB
         yT68rY3KeZG8TYMMU6okE5BvDccXpOcunp6/fs9bFl/bndnuWHib6L9wStlgUBmnbCSu
         GS6IzzADEJRa5vzGnkqOxRx8KRscZhnydMkrwILP3tPH1hAt2bmY40yIYgQgvckO5Dzf
         VaZ0p6jUp1AhPqsWb65vg0mCdiMD4qlyDoDoi2oZ7yvCU8SzkCjFhVK7bAyhlMm4cU+1
         ENzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nl+wThCkpmZCM5NAVfgGhZQHAlLYLO1ilgM9V2shVzo=;
        b=OnuKBPlp5TD6svEALuLFyKCXBwsNhDznLXvi4WJ+kLdA4bZBgpWAQqacgaynvegf1Z
         swiVVRsP+Hez93wmLUiEpvF94hkydgn9uNxGpEPGG0aP8tMoQs0WoE0gZT/OKlaITWQo
         H+xaGEEoHDQU5+5oRdUz3oZLWbLyeGjXHcW+rdUjF3USpmy4bWQqXIJmlEEtJAdb/dOI
         uNCveJUN/UhdDBsMoAmoVW6NLmeJ67aXNj7Ugi7PF2NQGmhX4K4zi4BF/THiN0VC+1Jx
         Xuz7ZcBoVljvYvi1xOc0ifrngcDO/q62y/dinUW1tfkOnBVaozzdK/TiaXZmiriqTpOp
         QsZg==
X-Gm-Message-State: AOAM531nZFJzv8yP55+Ru1dI4M6sEHp6eHIHj3DcOZIwDd9419Hiti/a
	1+SDW2VggIkF+lObDCh2OFg=
X-Google-Smtp-Source: ABdhPJznMv8SiuXfY3banspNpYhCsylhKVRpDpQhnyDARX7TMaJ+5zx4+y75CTTfBS5llBDFma5WXg==
X-Received: by 2002:a17:90a:4f05:: with SMTP id p5mr734580pjh.52.1603999613164;
        Thu, 29 Oct 2020 12:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b05:: with SMTP id w5ls1398158pfc.11.gmail; Thu, 29 Oct
 2020 12:26:52 -0700 (PDT)
X-Received: by 2002:aa7:8a01:0:b029:15c:de46:5b2f with SMTP id m1-20020aa78a010000b029015cde465b2fmr5829420pfa.81.1603999612605;
        Thu, 29 Oct 2020 12:26:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999612; cv=none;
        d=google.com; s=arc-20160816;
        b=fjuUkm+7rE+fMNS6h1/jcICfEP2QOvFXw1IRpu0OsD94jpcyLdnQ6fvL+fPRfCm7TO
         Imt7H42FhXjBqcr5/oBTi/aANdj8Uu602KmJXvjmrv1RRAaSGm+if07aw/vxvu1SgcM2
         rkWmLeJOt1C0NSfkYyuIu8DvemCT8n0fx3qdAhFZMJY9aUq03FKX5yNW2iIrWN8cLLk1
         5WVe2eJOOpTF83I7H0vmFBY4U59+waM+ljvyoZ+iVZ8EKn8BneY6HbDOFxtvWVUSP+UE
         bWb8kUUWQ/zmGvFZts8rBlQerk4+HQh67EB+YVaP0wzD1FY60Um2QmMt7c+8yiqbCrYm
         hC8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=rH4NCfU1Con/RDQh3hUSJEAvc0XuqAftmfv9Fl3051c=;
        b=cDQbJ+hOnmosYk6MZJKciMhJqT1+zH7NAXW4rJQfVLfgzlgVdpNdiEyDmr0QEpROkQ
         h7PhVA1JAWMSpTItvythyvIgmY1jb1+7GWxpmqKJbWnUE8YwPDdpgyK3v+cHlsX9FyDN
         lM5azcBE4CRGQWzla7LK7HSBStdZoDav9uBabKIQQzgShUKUuPayl1LYYl9RFEwCVQfV
         rkkx0NNWrmGZKNkf421xZbyjFjY+z1A6UNBnvEyTL5U5XJ2rZevjYv/OYovrbz35YLJ4
         LGLd0OlXHloP81n5sFH14JTw1A0t+7izsPnNyy9dd/TaZWpzDQKtRQd5xHSPtkNAo7OW
         pkjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BO08Bavj;
       spf=pass (google.com: domain of 3exebxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3exebXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 100si34567pjo.3.2020.10.29.12.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3exebxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id t13so2385970qvm.14
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9ccc:: with SMTP id
 j12mr5896542qvf.29.1603999611671; Thu, 29 Oct 2020 12:26:51 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:39 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <aef69540d85e41644e3d76c3bba01c32ceec5861.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 18/40] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BO08Bavj;       spf=pass
 (google.com: domain of 3exebxwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3exebXwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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
index e5c28d58ed6a..a2e71818d464 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aef69540d85e41644e3d76c3bba01c32ceec5861.1603999489.git.andreyknvl%40google.com.
