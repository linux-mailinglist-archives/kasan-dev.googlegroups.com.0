Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUUD62AAMGQE26WRPHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A8602310EC8
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:17 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id j15sf4187426lfe.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546517; cv=pass;
        d=google.com; s=arc-20160816;
        b=SjpOOiZHYqHQnywZXfw+q+g6DSLYYq1jtvf2zLXykg2I2Q7aE45oVJLxUeh1AAPzKz
         9Y9G3A+aSDw6wJtqSLIAsF9H51O63eMXbZrmJQWLfXwG5t2igW6BM5REoqfBJ2tTylHG
         1RlirYqfKdJNwLmPWY+YOnrLpoO8mI+Sah+/bfJCZMU82E9YFFpgOKPPhvv9MDVb6tVF
         JSvH683ZfVOjZPqbwOizQmmBb3bsmHTt3m2YQ5fi//8ryEsHtgcp1S4oQvISL1pJJ7jC
         75Vkxa1IflBDAhXFr1e3BQ/7pq/0u1x6xSxvPrjujHTKncfouxHHzoeW/0TLX75AArpu
         evcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ttsbADQUcCdrTWYxzeeIyPjCX7FHDOVFxSbiDnwz2+A=;
        b=y3yiIgnfis83cBOI4qtv1vOwsnnxn4UXkJ2VEwSzUuDKsgfADJ3Z27Y1e8WEEeMEpJ
         1J2IDWXF1l0FT4pZuPSbmt/+u9w5keaxSea1CgZnA16mWb8AAUPSzsoQGI8FXrlyUWvy
         Rnxg15WZ6S7typl/bBKPpn/d73nF3Mq1oLfCZiWCzeAnWIMf83C9MGZwCmNhd7OnKhQY
         Cncc/hGAbOQyfEbI9NDsUcE1nUB4P1JVNQ43LvSAT4NAJrdElADyw93+8BpacIlTEs7D
         8JF1GRWKlkolDmDyPgy62kneU6ForFbf7inknf8kXBbkCR8VSmzngJIM2gyzrPytHp9s
         P8Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o3q+JKMB;
       spf=pass (google.com: domain of 30iedyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30IEdYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ttsbADQUcCdrTWYxzeeIyPjCX7FHDOVFxSbiDnwz2+A=;
        b=QsmPtERdEQqb7Re2mb54jfH/iLoq/H1VFtqauREO6MJEQdnQ8bSerPdfI200oKAiSG
         pc2zHx8KRRp7WVVSeG7TtQD3/Sphbpio+TFMejYnReZECLGzH57G/g0NrXoi0MfBLjm7
         lwclEj1Rx3M5OJ+Rfa/orYlC+XKXvTqBOiRbim+XW5NXSlWO6RTiiyiRCJlDXT+HMLqE
         h2Pv7o/8kiYiY5yYfyVCKM7BB3DFNsxoPxyyXao109+OOP98ZyeQp5Q6YrBNeMTN/VnK
         eyFohXDz4jxB80H6IzBjUj/YCGRVAiY/OzMvpBW1lFCw7iXGShg5XkPllGTl85JbteRJ
         n62g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ttsbADQUcCdrTWYxzeeIyPjCX7FHDOVFxSbiDnwz2+A=;
        b=e11YsahCfrr3Sp/HbkMAiruysc6kuvpw8NCz+bwofsJOI+z4tu4z5o1VcG8iicKNqW
         YYJ/1VOwqrSV7poSG2VImn18wwqgVTzjZ2RJtC6T17IsQ/mDBqT8ckhoqgmgg6iAf3OF
         W1YJEQN6KVJ6o0ZdQUSllTTM6fzuVTQjj0twue5TOGFhoK3GoI5zC/3XhtWxim/kxmQO
         fxvknY64inlns7Do0d2/9C0gvJ3chaCfH5GUt1JxFA4EsTZfNkkUu8IqS+6uS3AwaCeb
         0UsCd5Sxtxr58h/W6PyqUXz3GAcqhrFkoadJlXsMOW+GMg88eefWbq+k8URez0U4aQGh
         MHBQ==
X-Gm-Message-State: AOAM5303NiJt37LQmpsgWZMW6E6wwYLOCgDDs8o5UH2r6N5ZyYYowMoX
	wJxlGUrF51hIJJrypSL1+bQ=
X-Google-Smtp-Source: ABdhPJxFayNpvcHslrc8JsbLQxU5qmt3/3qsg3cbFW6xduWAXKaT561XYl1KvHqP2PR2mJOmHYTfuA==
X-Received: by 2002:a2e:9893:: with SMTP id b19mr3128602ljj.317.1612546514256;
        Fri, 05 Feb 2021 09:35:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls172654lfp.0.gmail; Fri, 05 Feb
 2021 09:35:13 -0800 (PST)
X-Received: by 2002:a19:7cd:: with SMTP id 196mr3093256lfh.498.1612546513392;
        Fri, 05 Feb 2021 09:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546513; cv=none;
        d=google.com; s=arc-20160816;
        b=sLdje6dvHY86FIglCMDm6TSQuCEa0syNCMoRhFDTFTOPAiUCGKF6pD7qQjr94z1eQ/
         jwk8MvJ5hmO9Ej28u7fVzUpgJUAq8Axij13PND4lIHCaQjrrFqQFF22CaHMIeXmKTqzf
         kQRMcmxX+8VzWZu597zme6tICucP8kXCZ3VMK5DXLnZgkzexYhG3kGkwZ2l3OWN9MWe3
         xAUpznQrTU42h8+v7OaZa2fAyZ2SMYXH7Dm7tOq/DmpKtbzZM8Hp2B3MWgply9XM0Mc/
         CFCdQvYqU/7H8dRidT/VXqB32Krl8sW4+ELjctJpS1fU8lcTbFNcZIByx1mPz/FPt8B9
         /D0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qufdT2LxTRMhYRcFfEhB7241MbQS+EEn9OJq6bu53kI=;
        b=FjPAZfY5MjQkDPDhYcdCIXch+Q9sZawetJXixtYnDLPBaGcMcsi609oFDoFISRNbgX
         d7pUYgf3Tn61GSDGjstwU44xWPzj5swe8p8OvnxaWj9EsvFAocBotJ7pxbcOOGog122j
         6QcMiejYShyewGG3D191bFKGJT6gcWpSQ5pxXTckizz333499+ugKr4E3r6+uMCgEusO
         qtiYZ/+8ShTyHoKsZFZAcMaikbgOl3BYyqJ16MwiZrXRlzjd4xP8ATrH/8jou622vm5I
         ORjqoe1/QYKWSf9XAyJWDgvaTzSOyMO9l/eEY7pKh9KOmLpZ3f6fC17xjcNNDEoeB204
         DauA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o3q+JKMB;
       spf=pass (google.com: domain of 30iedyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30IEdYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id d7si516348ljj.6.2021.02.05.09.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 30iedyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id h4so7078701eja.12
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:5193:: with SMTP id
 q19mr4617213edd.264.1612546512746; Fri, 05 Feb 2021 09:35:12 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:43 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <3ffe8d4a246ae67a8b5e91f65bf98cd7cba9d7b9.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 09/13] kasan: ensure poisoning size alignment
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
 header.i=@google.com header.s=20161025 header.b=o3q+JKMB;       spf=pass
 (google.com: domain of 30iedyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30IEdYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
index d0a3516e0909..cc787ba47e1b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -318,30 +318,37 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
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
@@ -358,7 +365,7 @@ static inline bool kasan_byte_accessible(const void *addr)
 /**
  * kasan_poison - mark the memory range as unaccessible
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size
+ * @size - range size, must be aligned to KASAN_GRANULE_SIZE
  * @value - value that's written to metadata for the range
  *
  * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
@@ -368,7 +375,7 @@ void kasan_poison(const void *addr, size_t size, u8 value);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ffe8d4a246ae67a8b5e91f65bf98cd7cba9d7b9.1612546384.git.andreyknvl%40google.com.
