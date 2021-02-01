Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAVU4GAAMGQED3YECXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 273B030B0A2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:44:03 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id k5sf14808089ilu.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208642; cv=pass;
        d=google.com; s=arc-20160816;
        b=bB+t8tVX5JBM5C6i1FkyprlLLjOONA3IjL5sMOSFPiWoMkrqBtydHn/3Aqe9J0ElpG
         cfY1Cex11lN5XvWn0nrAsScUO1pH/qE6EIa1jKEc7sYxiIYlIu/P6DLBH2dITzlaOUbW
         RtmTeGVLYotAjK5VKTtov98LF94b+fC5qwvxlx5l5t5HDgs1UN2nO9jjKqSo5Si7BPau
         WQPD2Gi+qmjlrJKfL7U5kPSSQZL6YaOJKZSm4MR0gwtG+gFcqHYUvMSlxJFlTcR6s9+n
         BfvFld4WWnk1ErGQV37Ni1k5S/FMvgzjcY8zlxu5KKmN20t2dGvWb5D+m8DCo4+OHtu/
         cFiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=B2xUUdC9/A9C94GgD+64V4YXr2DSK69gt/mk1QJOPgw=;
        b=pjv3MpN6oqcHkPW3q+Je7ORotnfCwqwvQj7Oa3XAMVWK2+LQhz6mCBbFKhWxyL9jTo
         ZI4D+0OgO8TjwZIbRoZ0V4fmsH9B49sizh5iitwZ84uOWWawQmc7FlSeMsFSGO4+uChk
         DL/zvXvmRt9rVmMnRiQNeK9f/uDsB83yAuSYV8PrJ8Si2U7WU8SnU/lvdX7V6CKDvuSK
         94DAKCFK+2LfbuQGUF2Q92sdEbjngWpOTeDHSJMYpt4pPRUd0u9QwdbMTwyG25AA0P17
         qio91JMJcHUjVADJ/hLOAlRd+GZhmv3NJCjVYD3x8yjk5sT731imfWHv8zNl30kE0KWl
         +uYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzK81n8j;
       spf=pass (google.com: domain of 3avoyyaokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3AVoYYAoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=B2xUUdC9/A9C94GgD+64V4YXr2DSK69gt/mk1QJOPgw=;
        b=M3ssdSmJrNi2uGdscZd7SZISlCJPZasK/hU/Hf8OelSMQLOSSOjScZXW6tZgYQCwrl
         hXQp+A7tyGxeaHcfcka3p5VzgsDMpwRF66OQVq9H1907Tedj47e0/Cr0DvJnqrz2E2U9
         Jzx+rtss/XYl2ySAy5rr+EFOJIdvLXI0AsNSwQUSgEj64J6pT+3YlJpBXgN8Q7gHHULo
         4ryTIgijvy34Ji0C7BKStQHwKwYMqR1F8jfatUekJNin1MsLcCLVwrmG7p7gt6my3qWk
         Kd5IRWMlYggPRNnl7wZv0mWkEAV9blgFfGH67NWF8QaELqNmYrszkiMtCBKFBzuoi1BP
         GjyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B2xUUdC9/A9C94GgD+64V4YXr2DSK69gt/mk1QJOPgw=;
        b=qBk821Ld3c3hyW+OH7k0RT/9BaCvLTaQ5KnpHJ5FijcK4uvg+gLjJNYPutShedHvYe
         4gyG4u8PZ+CTAr8KXOgTXt7JnwrnpKJDkxGttuWz7jlCRZBHdYV1Q/uxRD+Iid4PcLJI
         fQ/elCP2hXTQ2I0bVNtB1K8XPI+eOp5uFXWRKvrwCZ+ErPKzKtiKVqkL/s0D5idzEl2H
         EvDTtqhbHfL18NxI/42NuUbEtHvNTNSruAMcsYH/8CJLJLkpoeWHTjBLTV4VibK7uaqK
         n6yxt+IxKuxyvObgSgSWwHTdnC6g0kbOCBxtYRQlhtDG2m/i4nRZcqDkp+V4tMkOsYTd
         U68Q==
X-Gm-Message-State: AOAM531G1UYQiMH72PLFWBOsusBLcq4NSpMDn7ljTmuNtbeEULUl/0g1
	9LKZxi+pip3f7jdMfYP+pQk=
X-Google-Smtp-Source: ABdhPJxDH9mTNyCDQxS4Pbx0Cvb/17tEAF9bgxHaJlZ9yMRfmQ/18bRh1a/W3Y09OiEyaZ6dt+4Q+w==
X-Received: by 2002:a5d:8ac8:: with SMTP id e8mr14435222iot.163.1612208642162;
        Mon, 01 Feb 2021 11:44:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2195:: with SMTP id j21ls4128922ila.4.gmail; Mon,
 01 Feb 2021 11:44:01 -0800 (PST)
X-Received: by 2002:a05:6e02:52a:: with SMTP id h10mr14215146ils.1.1612208641725;
        Mon, 01 Feb 2021 11:44:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208641; cv=none;
        d=google.com; s=arc-20160816;
        b=lIzkDBao+mahd1YZ1CPJCSW4lHJfHw91mOA5qMlKQ4gQ4iWRNT2Z+V8mwoMAklIy2/
         jvquHtz6n6Ur8B99ZhU4goviVvBKcVzZ52T0k78ngAb2364xKuBTgJIaWREztG/2o80A
         geaksSNC2eP2SvKIWYPs+cslnYyGJaGkinur9qlPBaoAQ4TV6/WuAPg52ezAt3wIJyIV
         cLwHi7sk945uZenOgrGZP6rghcEQ8aegOqEN91BOTQYnOR6EtrhVagcvZphngM/h4Rl/
         NvuBvSwcQC6ssoJE8H2P4iHi/uqlwEgtOanHTy/6n8rymfB9V6k+4IV80YRh8P4yugZ3
         JK5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yIaCjepZTR5qWD3z/y90ARyLWJ/KolY2qLhEkXBJOWM=;
        b=fJ0KxA8J5bWLDg5uXDHTFRDAVHafeMWb9JzY/4uYUZYWnUSahKUJ9OnC9KmJ3nwhrP
         IWt8BjTaM4VwnwIKFMcQIfOsqNiRaGjrNYwMXVZiGQg61TblvGFSDc/SxM3hq5TbVnel
         9G0z/JmiScNnXLDpYvakShRA+Q7UUMMY4I9uhe4f+z5Cu20vbucHKFbm28xAXapMRxU6
         SN+TvrYtz1X2rjwCcxh8uKk/YsAHuheP3ZjRqhX+XBc9snYoIuA5fII1ov+F2TKHE79y
         bJxgk0mlYy2IUoly9ZFtWTphmOlAMCY+nKpOYSgu9LDIiyMHPo4qFgXZUnH+NogrL0ry
         fqfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzK81n8j;
       spf=pass (google.com: domain of 3avoyyaokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3AVoYYAoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id o7si880347ilu.0.2021.02.01.11.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:44:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3avoyyaokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id g80so10971319qke.17
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:44:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:efd2:: with SMTP id
 a18mr16703061qvt.7.1612208641117; Mon, 01 Feb 2021 11:44:01 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:33 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <fee7c8c751dbf871e957935c347fcf7f1ca49beb.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 09/12] kasan: ensure poisoning size alignment
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LzK81n8j;       spf=pass
 (google.com: domain of 3avoyyaokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3AVoYYAoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c |  9 ++++++---
 mm/kasan/kasan.h  | 33 ++++++++++++++++++++-------------
 mm/kasan/shadow.c | 37 ++++++++++++++++++++++---------------
 3 files changed, 48 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a51d6ea580b0..5691cca69397 100644
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
index 6a2882997f23..2f7400a3412f 100644
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
+	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
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
+	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
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
index 1ed7817e4ee6..c97f51c557ea 100644
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
+	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
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
+	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fee7c8c751dbf871e957935c347fcf7f1ca49beb.1612208222.git.andreyknvl%40google.com.
