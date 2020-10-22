Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCUOY36AKGQEXVHIPRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E01295FBC
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:11 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id w23sf426247wmi.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372811; cv=pass;
        d=google.com; s=arc-20160816;
        b=F6+GPjFKKv4uvEH6kqFYNX3wKjSkbkYZddyxy/K+u4TQvULMam/2pOyGiVlQKezvrm
         IRyCQJhhmdLRPgI/yefeH47e8G4AL0ePerlEiWzUdVDa0BEXrUA7dbJg1TOTzFFNqIMP
         F/PxNus6h6Z0eklH6F1pUlC/7McS5hnFiEmpIqNVOsx0uWkF3mgG+MFrhEkjAqSY0Q/e
         cbguNKYXsX5edWJxYCrl35bp+7THHBtSb3v7SVRLU/AZZ5q9RAhcCqWumzrLnwroFX6p
         GXbHkVLWPP4g/f51qq655IKzM0PYve683MRUSrx+65/l7SBEFADRy9qjC7KUr6OvFZez
         c4sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fQ5+aXxKT2ez71UE7+qj7K0EdWBby6Eprhd5YtuXJpI=;
        b=Qt2ZWVa5Roi8qisWGxImgn2Mu2RUJxSd8PrPfk0+oRHRypbkwk4J/6ONTQFmZZZPcE
         5yxn89DOVzB9SKiIS1uAJe//QAHPwbeAAlcvfxrcxcluBA11rHqRquZCiNEOstDomsy/
         pFUs/4EGwpSNJRgGYIMKNRxIGkHLhNsTPi+rSbiFqwjrJ032BV1n4YnOa6+cZnYsQWXg
         3B4d9QoDJiSRuv/giLmq2GnDjlm8CrJF5oIq2Alj9n7APluJ3mQc7jwvGp7djgQUqFAV
         EeiO4rcNId0T9/P5B1VPaOkcnUjIMU/mWyC5NVE7XXPA8tNrTm7aeVZ3BFhbeggLPdt8
         8urw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ChsOlRrZ;
       spf=pass (google.com: domain of 3cyerxwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CYeRXwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fQ5+aXxKT2ez71UE7+qj7K0EdWBby6Eprhd5YtuXJpI=;
        b=qE1nL2KSDaiVTb8BRSipwyVpi7FVBbRLOYs1c/gqhiKFnmu9MuJCEclCVmMxfOtYjm
         Oq/Cy0BTprvW8fJXhW+kVcspyjHg6WZ8foC/KXK5B0Cn4a0KhmBeFUCsM24V5dnXSFLN
         1HJa26gJixxTERBklfOjAR14M4B3VAouiXtjLMadMX5lyeyClXf+Rt1hv9JYI0uryFVA
         WauULo5Dygon1cAmBuF1j8QA7hJMWe2C5A1EOole/eQ3FlsBTeyaVBC+S1pcEIuArtnW
         4Q64sL+KjD09qkyUy9dR8EfI/CxNXV+SkXaNaFgWdwrnxtNI1Mgd9ZlCbqc1IGniWhsI
         6bsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQ5+aXxKT2ez71UE7+qj7K0EdWBby6Eprhd5YtuXJpI=;
        b=YoIdXZvhYXQOgK9VClmHKgAjeHvbliOJU89UF6UF0wXseTTIrMY1zynp25TrDW5M3a
         BRmkXnzFQoOJhQYQ5eazrbMt7gLr9+Md/BtO1EVJCe8ZQu6H9YQ2FaGvErNjfz/twj8/
         9wyC6jaFpE/eqx3i388B0/63qwNyHCqjPG0HmfPgTeYu7FHuVGJ1ud1nB1jQkuyfbsPv
         vpRi0NY36EwZTHlhwoTyBwXHwpml2rUxC9wD9jnmWs6HzlUdnkYzbhK5HanIZCX92taj
         wFlc3rPDEPyXft61wg9eO6PuVt7VcBZeo/u2kenq5o63KRNYO/mck14brFHOqkLvS3+Z
         nMFg==
X-Gm-Message-State: AOAM532GkcAfQnfI6gOhJrOnTwCYOYJULUrPcyhXpbf8rDInOmZd3wKD
	/upC1XpHOwzXfAD3zCgZ0kY=
X-Google-Smtp-Source: ABdhPJxeWj0sxpxpScth6jv4nL+/wcDy7+KY6jQ/0QEHh0hqHcz3BgothbYMQ6DrugDsoGel2IxqwA==
X-Received: by 2002:a1c:4d13:: with SMTP id o19mr2699628wmh.185.1603372811164;
        Thu, 22 Oct 2020 06:20:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4184:: with SMTP id o126ls1005230wma.0.gmail; Thu, 22
 Oct 2020 06:20:10 -0700 (PDT)
X-Received: by 2002:a7b:c3da:: with SMTP id t26mr2683581wmj.154.1603372810255;
        Thu, 22 Oct 2020 06:20:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372810; cv=none;
        d=google.com; s=arc-20160816;
        b=dS30e9EJaX0B8GlLNkgIEtwFrk9xVRNUbrqxb0CbvB9CBmy9nzb1DiBgydmF/CG0ph
         8NP0g8xeNn7skk7x1pns43t8szWrH37H5UXwOcY5ggVSvutjRDySip/9VgN94+k/MhFc
         Mony7Wca3Zhbja7mSUiuyVUb0oZicyHeZDswg2wYekMyG2ftPBQMFhazWoVtHzceWqUA
         j422dzbtVskJg+PlD+xgBHVLfYcQCEYcNi/R19kPb+RRwGbO/pK8+XyZRh6fZRRtnA7Z
         BIvbnpM1rNu2Bb4xAA6ptFdz62ooJ+ayuWoXKAvDIMbEmAPF5FTSmbFzG1QuJr0iWjEo
         K2PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=YuCr19yY32x7rWFAvs+3N7JOh1jAyp/iY7KfCFpXvOQ=;
        b=zfpGUnFqg1DiJxQXfL7Va0vUa5c382sBEyLF5P4tNYUtNxov93fnqfckCK4xbl7LMO
         bGp/6VKriOwbmWZmKybdrAADZKphV0S7JYPWnbUMMoTZuKb474e/3tYwnG+jF2owaVV5
         3szv8X44glyPF7GNlzEXIJLT4Omwe43gtG8DqfkgL7/ggvrl9Wcucl9tHcXuXSfG0VK6
         LUWL+14dcM9O9HSWj/7lz608xZ6gQY8ygw8BXzvHzKoF7A7X3B4ONtSAjLsank3p1aYA
         EIiT4N26uRfrJ7PryVt/IwRuIa32MUxBdwJm7iO1uTJCRsz+mYOpf7/8bF4uT244GIgT
         g3Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ChsOlRrZ;
       spf=pass (google.com: domain of 3cyerxwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CYeRXwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id e5si63632wrj.3.2020.10.22.06.20.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cyerxwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so582802wme.8
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:10 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c04a:: with SMTP id
 u10mr2667777wmc.83.1603372809904; Thu, 22 Oct 2020 06:20:09 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:11 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <f48f800933dacfc554d9094d864a01688abcbffd.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 19/21] kasan: don't round_up too much
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ChsOlRrZ;       spf=pass
 (google.com: domain of 3cyerxwokcwa8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3CYeRXwoKCWA8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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

For tag-based mode kasan_poison_memory() already rounds up the size. Do
the same for software modes and remove round_up() from common code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
---
 mm/kasan/common.c | 8 ++------
 mm/kasan/shadow.c | 1 +
 2 files changed, 3 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 5622b0ec0907..983383ebe32a 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -215,9 +215,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_memory(object,
-			round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -290,7 +288,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 {
 	u8 tag;
 	void *tagged_object;
-	unsigned long rounded_up_size;
 
 	tag = get_tag(object);
 	tagged_object = object;
@@ -311,8 +308,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
-	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_FREE);
 
 	if (static_branch_unlikely(&kasan_stack)) {
 		if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 616ac64c4a21..ab1d39c566b9 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -82,6 +82,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = reset_tag(address);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f48f800933dacfc554d9094d864a01688abcbffd.1603372719.git.andreyknvl%40google.com.
