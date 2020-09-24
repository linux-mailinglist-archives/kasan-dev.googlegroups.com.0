Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYOFWT5QKGQEACUE3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F551277BCA
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:14 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id j125sf319931vsc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987873; cv=pass;
        d=google.com; s=arc-20160816;
        b=oiIybuAe+DfbQDQVZA4nDK18vTgpSdRqA8A/FdIs3zqED1Dng737KAgpeVwNNjvaMC
         v+CF/o7vv/DxNt9Cn64Oa88Sjcx/Y0mu0J4DgH7YzyS9Cog1+5N9YU+C2+iDNxxVofCZ
         10kxgPClWsfOkq4Zm83j3caXBunLvBCKhatTlULzjUReWBm1t0XbH4T3moka2/HT43TW
         EDvDPOlIs1Yppvq05oIRGZu4CeIn3wEPmDqQxD2goZ1oL0iKRZhexofBfampvCF1Zn/8
         5bG+3/qJURhRO8Q9nLHaaPXlm/D9slI9xmYNjlIX9k2FpL5uwD7M+FpC+emzxcMw38DE
         hitg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UvOQo2bIy+De50FoH3iNwVbfaPAE7wy9rxRXcY8TcMA=;
        b=S6T6KDCVYa4YdG9FHVYoAwXAQkYlbtHxvMghAQ2BXbLv2MAgQ7bxubl5ZfgELwlEpv
         M/BZuslBoYWAJdtqB6p+GNmp8c7c/P66ZqXePJnNTUxME9vTQ03Uqsx/xWWpJvHN08W1
         zHDUpqGDDqLHe+kEJVlBVeX8cXp+rRR4DFnEIA/cAAOloonnxh8bYZsO39tHeCio7Hn4
         lYhgVnOalM2VzuRLVdQR8sbJ/4+z3SurxXODmLUxvFWI5KJYBsKiI4sVEXWc6Dx+m2gF
         0e0vctcIdfmSEUaQDqQf2kEduvWFjvHLyf+pWQ4PhXcucaj1GNL/l0GwXdzBpq8GKyhF
         MqIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GsfYVtNs;
       spf=pass (google.com: domain of 34cjtxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34CJtXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UvOQo2bIy+De50FoH3iNwVbfaPAE7wy9rxRXcY8TcMA=;
        b=jUcPs1+Y+t6d+2VUmaNSrEeLrq4NK3AyBwrFyriKALk0BaLWF9lhcVGCRYuXsum67n
         Wfl4Smy5ut/SOqFCxTzrmTLwI2bljTNp/0ctapx1vTtoXYxDLl+OT2fctQ0jU6SZMGMV
         /sbPpXPFC+JIjFXz/qHssis7L/LCdB8l71yI2yZuCZDidaWfLhhD52o3dPZmzHyhJLt/
         r034uT80YqyjrJZkIIrY5YTSgbG8ZNpX7qyvZBXli06KohED617byH5jqquOzF8PSzLf
         p71zr3IGyhX2eDucTLy6br6tPtQIatJQawh4a4PFeDbKvwisM75XQOfpPeCvYz8i/Wyt
         M/HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UvOQo2bIy+De50FoH3iNwVbfaPAE7wy9rxRXcY8TcMA=;
        b=R1x1s1O2tjlPLCiytFW27lUhaHGUf+i3db9vTNXnXp17+txtEUsgiRoU5wTdh6GisC
         +cj0A0Tg8mXvIeOdyWK8DH8n4WLt+xiONAkj/DNJWzQcdi1d7ORGwOuYGsg0xODZnXYz
         6qAjqtasHkqq1GvjZ1tOqr6r+F7cizBsAATgq+KJI4whFmZ60QnYccMDw9PAmy88Ps3B
         rdbNiJBaHmDgKjrWiw+3fTNtESTeVyp0RaEiqkc9Ct9QSd/7GWkOB9avFXz+mD3EFHBc
         eQ0HQTbGSLXdI8NlhaorobPJnVsCIvrejVhIe1+PlJKqRAn9E8uYkMF2XTPeimv698uC
         5I3w==
X-Gm-Message-State: AOAM532FSjgAq4k5AaFVajcZImu2kLJgFF4XMvZSS8c5Zd7xIiJd+I9A
	Lp0b+M6NKPrtQzz07ZgoPTA=
X-Google-Smtp-Source: ABdhPJzO3DJYdUdtwRRclFu/bI0kT0HTIkX8FPhMAJezQfzpqqP+ZBHlKDMgq6waH70kzgdvKWlMUQ==
X-Received: by 2002:a05:6102:11b:: with SMTP id z27mr1309392vsq.6.1600987873518;
        Thu, 24 Sep 2020 15:51:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:: with SMTP id j6ls135799vsj.1.gmail; Thu, 24
 Sep 2020 15:51:13 -0700 (PDT)
X-Received: by 2002:a67:7dcb:: with SMTP id y194mr1330510vsc.26.1600987873068;
        Thu, 24 Sep 2020 15:51:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987873; cv=none;
        d=google.com; s=arc-20160816;
        b=Zc5e5a0fHfGXbDVJ0pE1+uyKfReikJ1llYdafK5oUnZGs17OTQ59lhF34eJBCyWBde
         vVaghW8j1sLqnKxxTKCvm+Dm9S8eHKY96PwN4zW14cb6nEA+bonOuIGN02PRr0M3Zqpj
         ehi6/bCUebt1Ys2K4n6yPxGY0gkipOJhiBZpd8FeA5xczEWyqjWQpvbKc/T7DWtklKG7
         zwWi6bBfMyUH9tAyW8kzq2vz/74tT3p+WS9JEvzqdRRia++4toOlusSorZied0axJUHy
         64fpPdF3HVZjlo7e5n3x8Mzk+u+EebyBZowSWK8vE4mlAsv+ullqdxI13Z5c8mHAxVAB
         4bpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8lI1T777zki9DPHBd/TgnqCLsJFyKced7GzofNI8hcw=;
        b=yumrSkNVFThpJF3F6q/PMRrPoclS2UFHiCVXBrRXcyigvS2eiV4tbWwSmLZa9Xk3D6
         LFgxq/hrpywByj+hQWJkCNJLJ5b/GTYMY3viS/jpdHRLCChgQYPpfjFdrQMlAMmXKb4K
         6Z+ZlXf42R7zTew4ljqmcSIxz1BhnIKghKphlwwhIXL83uDdEyK8HIJKWbRFBNfTL4RD
         zK3VxAGacxwvk+Y13IPcWH6Brt+pPo5Zw0zOsFe/j6I0LOqDzxJFZGtpiZqxfNx9iibL
         ZUnA+yGrV+qNgsTo4QRT5Y6d1MiYGoQHzy2WFtgIYFgZehdI6Ynr8V+CEWC/042M+59/
         ISQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GsfYVtNs;
       spf=pass (google.com: domain of 34cjtxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34CJtXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 134si45946vkx.0.2020.09.24.15.51.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34cjtxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id w64so683843qkc.14
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:13 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f48e:: with SMTP id
 i14mr1648496qvm.9.1600987872649; Thu, 24 Sep 2020 15:51:12 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:16 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <92a351d2bc4b1235a772f343db06bedf69a3cec9.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 09/39] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GsfYVtNs;       spf=pass
 (google.com: domain of 34cjtxwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34CJtXwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/92a351d2bc4b1235a772f343db06bedf69a3cec9.1600987622.git.andreyknvl%40google.com.
