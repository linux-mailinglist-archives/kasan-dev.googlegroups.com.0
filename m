Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPGN6WAAMGQE4XNSWXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15FFB310D41
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:41 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id s15sf5568635wrt.14
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539580; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbOlJKRiHLgQwG9BdNtabi1o1m8tUg4s2EYXZSW/O+u5kPrssqCJj+izt82dKC2Z+q
         uFKnfl3tn3UOEECaQd7wb3QafT2RDZ5G8vapanviIvGwvHh8LLUxOTagfB9P5mqv75OG
         exbHezlpvnneZEe91q7wEdfJl/2KG+Mvbmacm0FGkTVI2DSNz4CVXzC7QEdSiySnfpek
         Q2prDydW6J/t8vB3KM45zByB5yr0fEvLF3wN8tMLlgpL6OjidVtIQUru2MVhXWnLB7so
         QQfmnsgiCPPynuVQMQM7yWy8E22XtkV4biFV46/Z5+flVKH91aWx3YOSwVZIsTbJhh/Q
         BwLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=cwBfsFQMy3lUsSElJw0k8Re9lzH1rtRqqsB/rWQfh30=;
        b=Rfoe/7/Gz9lMhIx/dQH6rulthv65nShlpNAHHBWxH5q5DiafHz6fUz/vRotPwlE4O+
         nPX1GUBLFMvgHdfzVxH9Xn6NltrexYq+/E0tAo9f2APGHyuWZXToJTBlRcXO15+8+yjx
         3jAFLzf+nVLnXGvnrjSOeGqWW/K9An/FaWbtSOntSJshWJpg0+laOd8lIKO/oY9HaNeQ
         9kD5IwPWfEHdthLnMC9ClahWxDOSZkCNYj5ISDJu+xPcG1NRWrActIeo7k9EDI1sYECn
         4uet9Dsvw6s1wtSX3tWCOSZLHHihr8n2NvMRRHmkAQcFidLF2zldEFutKW8SUwzA96dl
         kTvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UwU8BZgl;
       spf=pass (google.com: domain of 3u2ydyaokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3u2YdYAoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cwBfsFQMy3lUsSElJw0k8Re9lzH1rtRqqsB/rWQfh30=;
        b=J6/XfuJpUcxe9eg0QCaS2xZAYFnjlu01CkknLQaYkR8zeqIK8R18cTZfI1rAglY29r
         hKr85bytE6a/3ruyMZWZGsGCg9v/KmBchEVWcAZYg8uxE2X62OptgSLG0T97tvH9epc9
         Rv9N1J6CHVWSYr3M4QfhEPehb1NCAGIewKw7rkVefbAzZjy4hB1di0ubYKHHa9ERzMnD
         gf2n8hmMShDjGgNZPydhavTNCqFfdZrezaeKTjQlP9bDNYVXmDlIlklBsRhqt8fsNv+Q
         QbTmKsHLJorbi25LOzThiU9T5NDec4XDTdQRPvcY6/+PJjA/hX9nZ/j4BTA1B3IGjJF3
         A0aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cwBfsFQMy3lUsSElJw0k8Re9lzH1rtRqqsB/rWQfh30=;
        b=hW2f8Nv+3g5sAh3Ez4wajRe1FNo/8F80Kp9OePRcsYH2Z19NxjxSh7LUl2QI3UQm5Y
         5SD/VQRdJUIWAp8Q6kniYD6i5hHircNrJkSinEhTKjPnwdquIl6Jgq69RWBI/328VGj7
         iK7Bt79KvyhMjhSs1i3DZb2TMyPauR+iH8sIyRjto2dCS/ywXCuwmhk5Pw0Ruofu1wKb
         9KyvvE8xclkxESheMuV9C2h5ErVNA8wM5eelT8zLIgRzBDB2rfT/G0JZ9rfvKYD3a7Xs
         X9sKf+CqL2j/YafVfv4cZy1NNJx2kLiIDLRxYb3q/3y4uk75pZJb64YJxzKNdCBl1lAz
         SXkg==
X-Gm-Message-State: AOAM530Bt1HcP51S0YGQSe516f9Qz2h1bKRotNnEgjtPCIX26dqxoQ5W
	Ei73D2hMJWiHFrV4VlhecDw=
X-Google-Smtp-Source: ABdhPJw/W0FdTMVPkrIkcP8aMyQuus+s+J87I5K5BuwlVT3TfNhx0HR1gpt7N5V41aT610pNsIPwHg==
X-Received: by 2002:a7b:c055:: with SMTP id u21mr4195943wmc.68.1612539580815;
        Fri, 05 Feb 2021 07:39:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls837773wrq.1.gmail; Fri, 05 Feb
 2021 07:39:40 -0800 (PST)
X-Received: by 2002:adf:f9cb:: with SMTP id w11mr5698463wrr.199.1612539580197;
        Fri, 05 Feb 2021 07:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539580; cv=none;
        d=google.com; s=arc-20160816;
        b=l+w55A6yq5mC55JFFXGR8/X/QKTQTnQE9uB9Av9FhcaM+wmeO3d2csTm4ymOOxIXuy
         mNaDoXK3mukTlj0aPjS5GSg7yP2ME+YOm5Myo7NzMDCY1RRu6abQvrkM2aJLq0gHlCuZ
         xvLkFwcDxIOJjfgfPivDV6ea9zqV0ao+4g8Kq66g5h1lU9LTemqAJKfsUtJ6wBmRZ/mB
         ivCrGKgP6RwvU1ESDueHbYHViTDXSvJyenarD81/3qR4i5UkY3cqcaADXyh4T7OVTBcY
         X3ZG4Ri1Rfk36CL8GXEE/sdwNGxmWqCoMakrbBP+xPBBBbEwR9wPNHyFQXoMRneP8Mcy
         XrUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sdkgj896Qo+AFN+zvttnZapcO4bCa1e5ImK6MurFn1k=;
        b=p9/VG5bKC2BHlCP3GhHgoQuckm7jEU9WeMRVLw+aQhpERgEQMwPl95E2SoztcmqIx8
         Zk6e3lfmBYFtFC8vSnPEP6z2dnRy9dOrAPVhZXB6UrG+mQvUjr3lucKaOLgz+kZMGN6n
         0pVejt7uC5dea87R6lGjUzlu5yGDthd8va2CZI5hngJLIzAlDArlq3maoKn3ljjb1Lw4
         uhgTbMx09ch9BPvBkA/o30MCRX8DJLrGjPsvGtY0LGU7gcRjKq7H8oMAHYC1yC9BxPhj
         8OGV+jYxLfeDGQ/w4gsOxfwQqGuFzk7dnuzHEf5NeI1xBGLoIZ2EfZsjQyUJ42fyHbwX
         yn4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UwU8BZgl;
       spf=pass (google.com: domain of 3u2ydyaokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3u2YdYAoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id t16si1054806wmi.3.2021.02.05.07.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3u2ydyaokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id z9so5554571wro.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:21d2:: with SMTP id
 x18mr4105351wmj.186.1612539579825; Fri, 05 Feb 2021 07:39:39 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:10 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <3917dc59e3dbf99b2929a1e20d41df0c5930e026.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 09/12] kasan: ensure poisoning size alignment
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UwU8BZgl;       spf=pass
 (google.com: domain of 3u2ydyaokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3u2YdYAoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

A previous changes d99f6a10c161 ("kasan: don't round_up too much")
attempted to simplify the code by adding a round_up(size) call into
kasan_poison(). While this allows to have less round_up() calls around
the code, this results in round_up() being called multiple times.

This patch removes round_up() of size from kasan_poison() and ensures
that all callers round_up() the size explicitly. This patch also adds
WARN_ON() alignment checks for address and size to kasan_poison() and
kasan_unpoison().

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c |  9 ++++++---
 mm/kasan/kasan.h  | 33 ++++++++++++++++++++-------------
 mm/kasan/shadow.c | 37 ++++++++++++++++++++++---------------
 3 files changed, 48 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a8a67dca5e55..7ffb1e6de2ef 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -261,7 +261,8 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison(object, cache->object_size, KASAN_KMALLOC_REDZONE);
+	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
+			KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -348,7 +349,8 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
+	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
+			KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
@@ -490,7 +492,8 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = (unsigned long)object + cache->object_size;
+	redzone_end = round_up((unsigned long)(object + cache->object_size),
+				KASAN_GRANULE_SIZE);
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 			   KASAN_KMALLOC_REDZONE);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 6a2882997f23..98f70ffc9e1c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -321,30 +321,37 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-static inline void kasan_poison(const void *address, size_t size, u8 value)
+static inline void kasan_poison(const void *addr, size_t size, u8 value)
 {
-	address = kasan_reset_tag(address);
+	addr = kasan_reset_tag(addr);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
+	if (is_kfence_address(addr))
 		return;
 
-	hw_set_mem_tag_range((void *)address,
-			round_up(size, KASAN_GRANULE_SIZE), value);
+	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
+		return;
+	if (WARN_ON(size & KASAN_GRANULE_MASK))
+		return;
+
+	hw_set_mem_tag_range((void *)addr, size, value);
 }
 
-static inline void kasan_unpoison(const void *address, size_t size)
+static inline void kasan_unpoison(const void *addr, size_t size)
 {
-	u8 tag = get_tag(address);
+	u8 tag = get_tag(addr);
 
-	address = kasan_reset_tag(address);
+	addr = kasan_reset_tag(addr);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
+	if (is_kfence_address(addr))
 		return;
 
-	hw_set_mem_tag_range((void *)address,
-			round_up(size, KASAN_GRANULE_SIZE), tag);
+	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
+		return;
+	size = round_up(size, KASAN_GRANULE_SIZE);
+
+	hw_set_mem_tag_range((void *)addr, size, tag);
 }
 
 static inline bool kasan_byte_accessible(const void *addr)
@@ -361,7 +368,7 @@ static inline bool kasan_byte_accessible(const void *addr)
 /**
  * kasan_poison - mark the memory range as unaccessible
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size
+ * @size - range size, must be aligned to KASAN_GRANULE_SIZE
  * @value - value that's written to metadata for the range
  *
  * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
@@ -371,7 +378,7 @@ void kasan_poison(const void *addr, size_t size, u8 value);
 /**
  * kasan_unpoison - mark the memory range as accessible
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size
+ * @size - range size, can be unaligned
  *
  * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
  * marking the range.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 1ed7817e4ee6..63f43443f5d7 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -69,7 +69,7 @@ void *memcpy(void *dest, const void *src, size_t len)
 	return __memcpy(dest, src, len);
 }
 
-void kasan_poison(const void *address, size_t size, u8 value)
+void kasan_poison(const void *addr, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
@@ -78,55 +78,62 @@ void kasan_poison(const void *address, size_t size, u8 value)
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = kasan_reset_tag(address);
+	addr = kasan_reset_tag(addr);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
+	if (is_kfence_address(addr))
 		return;
 
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	shadow_start = kasan_mem_to_shadow(address);
-	shadow_end = kasan_mem_to_shadow(address + size);
+	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
+		return;
+	if (WARN_ON(size & KASAN_GRANULE_MASK))
+		return;
+
+	shadow_start = kasan_mem_to_shadow(addr);
+	shadow_end = kasan_mem_to_shadow(addr + size);
 
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
 EXPORT_SYMBOL(kasan_poison);
 
 #ifdef CONFIG_KASAN_GENERIC
-void kasan_poison_last_granule(const void *address, size_t size)
+void kasan_poison_last_granule(const void *addr, size_t size)
 {
 	if (size & KASAN_GRANULE_MASK) {
-		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
+		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
 	}
 }
 #endif
 
-void kasan_unpoison(const void *address, size_t size)
+void kasan_unpoison(const void *addr, size_t size)
 {
-	u8 tag = get_tag(address);
+	u8 tag = get_tag(addr);
 
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = kasan_reset_tag(address);
+	addr = kasan_reset_tag(addr);
 
 	/*
 	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
 	 * that calls to ksize(), where size is not a multiple of machine-word
 	 * size, would otherwise poison the invalid portion of the word.
 	 */
-	if (is_kfence_address(address))
+	if (is_kfence_address(addr))
+		return;
+
+	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 
-	/* Unpoison round_up(size, KASAN_GRANULE_SIZE) bytes. */
-	kasan_poison(address, size, tag);
+	/* Unpoison all granules that cover the object. */
+	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag);
 
 	/* Partially poison the last granule for the generic mode. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		kasan_poison_last_granule(address, size);
+		kasan_poison_last_granule(addr, size);
 }
 
 #ifdef CONFIG_MEMORY_HOTPLUG
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3917dc59e3dbf99b2929a1e20d41df0c5930e026.1612538932.git.andreyknvl%40google.com.
