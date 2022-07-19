Return-Path: <kasan-dev+bncBAABB47O26LAMGQE5ZXWYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 39CEB578F02
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:14:44 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id z5-20020a05640235c500b0043ae18edeeesf8848409edc.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189684; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDnuOxtKO/3XgtavNSJyFKm2fjP/lA1T6PVtYbWcSmQ3al5jYKVUJkJLe/D6wTZ7VU
         gQqK6JuSG7i/B/1FEQC9m0uHVSYL7v4OteKsq+y38dk6UO8Aq3UmxsvLASEV1Y+Q/RyA
         19s9jL6VDhNsDZud7os0KepPW14IIXpWzwakLQR0GKNnpdNOM3iSlAYpogWDgl/o5IiG
         sHs0Nqnfwh9nDM/BWqWO4eYBMZAiw0sSvriGee9q+5aVkjGztXAuwF/+TVZTsjQrFQ6Y
         QqP4xJEZBDVRduKmQO6FzioLDjc5XWaurEbUBMKindR+Abrp6P9k0tcW822mRkIPiY6H
         S9hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F1uWMuSPiudf33m5PwSIXJr5z2fQjzI5eB7aUuT4MNY=;
        b=m8KgpV2a//t5UZe2XvsrX40AwdIgJYYNKh1nzY868uwYxmQixp7GHh3DGueQoVrrMe
         Hg5ZDTRYajG2hBfsdM+kZYNoj8Nh7LEopQOW9+SCcbp4Q/AoNMRBIy96DnoujSCwAQAQ
         bdr00okNISvFvFgGmNdyq4kNIbgG/KNUuXyNJyR4PGu/uOjvqM4+r5H2oaNId+xKqcXP
         53al1+yesEHjpEDqMOWu+ue2j5Y5WWpl3CbRsrM786Y1MIjrVysg6/NGjUUoVe8hpffB
         JjokLbDugXOxMvpsh9rYdg8t66Qb7aipcBhKqsw18W1By10Lckk1l329DGDGdEUUdd2+
         KAKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EezPcQcj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F1uWMuSPiudf33m5PwSIXJr5z2fQjzI5eB7aUuT4MNY=;
        b=aFwpVKejw+NpF010Fwnop2IXAX/om1HEh6h0PSy2veXKgjWszh/aqZREta76ivDpbf
         ofooGw/EQWgj3TK6WpUWRDQM7dKwUmFlaRjjD3bHvTSrQwOHq+lLEXJL3YI1owLDS+qo
         cuG8zbmfZ8uKyvDXoO0Sb188A4B6uqtFtwpmnm58cgA1eXMLAt4WyrKtT6ftaPEKjc5b
         eWn07vZLYOF1VO4DQPgappDNcqYxqDjFq2gYSgS2OkU2PZuDywi0K5laRgZren7ZyR2w
         tuCgSQKT3frAgshE8ILk1NlIzbpYgkFRwBPbzlgBYYaHKWT9lpq3Zop/XfcQrv+1CWBx
         tKvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F1uWMuSPiudf33m5PwSIXJr5z2fQjzI5eB7aUuT4MNY=;
        b=X892KhVLPpYMA3gaRLhuJtEFKO3nFlKOavovUYE+H1S1iDx/L/DYRYtxXsWM4cjtSQ
         jGPkkebd+MhJ/AqkVb3MJY/zATVLkdSAB5k0t7q/4nSM2qVrWeBm4C0tOiHruik1lGIM
         llZhVMhtAioq3KNeRUG7TpDLs4WlPE8abulbn0gwy632jqqWAaB404LVjnNstv1ED5x2
         nHwcE8Wwi6tIqdxtX3ukYNaLwJuUGykk1rZR7EMHnmhQhOC2207ZoDYDXX74oOXdTuGJ
         rjhIdtmCzi9IQy7IPA434v4NAHQ3BBSyQs5Ou2kS7EhsbLyYAyOTP0XHFVkj42dKykJ2
         l8zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8P64T1LHENmnUm64gDZMx9uwLWaREEdHtxBsSxWp5Uohrjae1P
	8qMk5NrdB6VEh5biG/jeXgk=
X-Google-Smtp-Source: AGRyM1tdpy1jg5p+h32sF6dhGNUExBUwzxFCysy2syBCjwGFYZqYZq6BvOGUlplSgWiYizUxL9bJjA==
X-Received: by 2002:a17:906:e9b:b0:72d:ec31:b037 with SMTP id p27-20020a1709060e9b00b0072dec31b037mr25413879ejf.595.1658189683920;
        Mon, 18 Jul 2022 17:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f1d3:b0:726:2c39:8546 with SMTP id
 gx19-20020a170906f1d300b007262c398546ls202184ejb.8.-pod-prod-gmail; Mon, 18
 Jul 2022 17:14:43 -0700 (PDT)
X-Received: by 2002:a17:907:1b06:b0:6fe:b48d:801f with SMTP id mp6-20020a1709071b0600b006feb48d801fmr27915560ejc.322.1658189683206;
        Mon, 18 Jul 2022 17:14:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189683; cv=none;
        d=google.com; s=arc-20160816;
        b=HWFQwC+smw4uEdnA8YlEe8Q0moKDXe0A9Ash6U7/V3tm6agiCXCYydXmfZkTic8j+3
         MXLHMNviZVnaMJGXMvFvDfEFWV+WuL7Ig7Uyg8BNKBti2gxpVOqdXVVf9qCbZo7uRkM7
         +Z10ztcBfhPjICtGBJ5tYG0jZaPXNuCAbpB5qJ+BfUQVOlEwXQLqlWtkAjDsxlMF4GvX
         8bB+hhK8UooA+K3xeK2DoyUY+FFsaZ8ayGt0pLHmpAlhBEhlYV6aFfuHRg7tX6G+nSCz
         XqU1BX124Jgk/Gayb8uz9MdUk4Oc+Mmo0ee7nwdwv/SHm4oVU5y9RR0X6dlS2NQ+VTfK
         DdpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vzRea5hvMdoTmboaBEtojUXPva3xnD8ejz88W9zk+eA=;
        b=j98bB+cQaV6mdttL2ZnOBbGbpqRlspmwsN7Evjt0SVjLIn/P2XDwqgYx0xIwgjZjGH
         t6Wm3wZgJnjT/vyNduOTuF99Vsabu6VUK9rlNijITQld8iDCH7px+gJj0C+TOgVW1DKd
         rfE+uMREkLyFHx83+nR6SehPr+KmPnES+neai93oTxqe3BGJClkqaFCK20OvpzLp2sdv
         6rY7J0A2gB1fCmTCJEl7u40vCtbS4PgH12iMF+tjPSWfMXt8ZfBQhqnji0pRJs5D4C+e
         0dUzDt7xyNGHHdd6FzoC6BBLgp69Tds5Nruhj3dWZtDkzTg1qj7AV760L4wtxppgw5+S
         Z4PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EezPcQcj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id n26-20020aa7c45a000000b004359bd2b6c9si366656edr.3.2022.07.18.17.14.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:14:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 29/33] kasan: introduce kasan_complete_mode_report_info
Date: Tue, 19 Jul 2022 02:10:09 +0200
Message-Id: <5f6e8cdf1a25410d2da1ae74ec45d8a17a611c46.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EezPcQcj;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add bug_type and alloc/free_track fields to kasan_report_info and add a
kasan_complete_mode_report_info() function that fills in these fields.
This function is implemented differently for different KASAN mode.

Change the reporting code to use the filled in fields instead of
invoking kasan_get_bug_type() and kasan_get_alloc/free_track().

For the Generic mode, kasan_complete_mode_report_info() invokes these
functions instead. For the tag-based modes, only the bug_type field is
filled in; alloc/free_track are handled in the next patch.

Using a single function that fills in these fields is required for the
tag-based modes, as the values for all three fields are determined in a
single procedure implemented in the following patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h          | 33 +++++++++++++++++----------------
 mm/kasan/report.c         | 30 ++++++++++++++----------------
 mm/kasan/report_generic.c | 32 +++++++++++++++++---------------
 mm/kasan/report_tags.c    | 13 +++----------
 4 files changed, 51 insertions(+), 57 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b8fa1e50f3d4..7df107dc400a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -146,6 +146,13 @@ static inline bool kasan_requires_meta(void)
 #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
 #define META_ROWS_AROUND_ADDR 2
 
+#define KASAN_STACK_DEPTH 64
+
+struct kasan_track {
+	u32 pid;
+	depot_stack_handle_t stack;
+};
+
 enum kasan_report_type {
 	KASAN_REPORT_ACCESS,
 	KASAN_REPORT_INVALID_FREE,
@@ -164,6 +171,11 @@ struct kasan_report_info {
 	void *first_bad_addr;
 	struct kmem_cache *cache;
 	void *object;
+
+	/* Filled in by the mode-specific reporting code. */
+	const char *bug_type;
+	struct kasan_track alloc_track;
+	struct kasan_track free_track;
 };
 
 /* Do not change the struct layout: compiler ABI. */
@@ -189,14 +201,7 @@ struct kasan_global {
 #endif
 };
 
-/* Structures for keeping alloc and free tracks. */
-
-#define KASAN_STACK_DEPTH 64
-
-struct kasan_track {
-	u32 pid;
-	depot_stack_handle_t stack;
-};
+/* Structures for keeping alloc and free meta. */
 
 #ifdef CONFIG_KASAN_GENERIC
 
@@ -270,16 +275,16 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+void *kasan_find_first_bad_addr(void *addr, size_t size);
+void kasan_complete_mode_report_info(struct kasan_report_info *info);
+void kasan_metadata_fetch_row(char *buffer, void *row);
+
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 void kasan_print_tags(u8 addr_tag, const void *addr);
 #else
 static inline void kasan_print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-void *kasan_find_first_bad_addr(void *addr, size_t size);
-const char *kasan_get_bug_type(struct kasan_report_info *info);
-void kasan_metadata_fetch_row(char *buffer, void *row);
-
 #if defined(CONFIG_KASAN_STACK)
 void kasan_print_address_stack_frame(const void *addr);
 #else
@@ -314,10 +319,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object);
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object);
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ec018f849992..39e8e5a80b82 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -185,8 +185,7 @@ static void print_error_description(struct kasan_report_info *info)
 		return;
 	}
 
-	pr_err("BUG: KASAN: %s in %pS\n",
-		kasan_get_bug_type(info), (void *)info->ip);
+	pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
 	if (info->access_size)
 		pr_err("%s of size %zu at addr %px by task %s/%d\n",
 			info->is_write ? "Write" : "Read", info->access_size,
@@ -242,31 +241,25 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object_stacks(u8 tag, struct kasan_report_info *info)
+static void describe_object_stacks(struct kasan_report_info *info)
 {
-	struct kasan_track *alloc_track;
-	struct kasan_track *free_track;
-
-	alloc_track = kasan_get_alloc_track(info->cache, info->object);
-	if (alloc_track) {
-		print_track(alloc_track, "Allocated");
+	if (info->alloc_track.stack) {
+		print_track(&info->alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
-	free_track = kasan_get_free_track(info->cache, info->object, tag);
-	if (free_track) {
-		print_track(free_track, "Freed");
+	if (info->free_track.stack) {
+		print_track(&info->free_track, "Freed");
 		pr_err("\n");
 	}
 
 	kasan_print_aux_stacks(info->cache, info->object);
 }
 
-static void describe_object(const void *addr, u8 tag,
-			    struct kasan_report_info *info)
+static void describe_object(const void *addr, struct kasan_report_info *info)
 {
 	if (kasan_stack_collection_enabled())
-		describe_object_stacks(tag, info);
+		describe_object_stacks(info);
 	describe_object_addr(addr, info->cache, info->object);
 }
 
@@ -295,7 +288,7 @@ static void print_address_description(void *addr, u8 tag,
 	pr_err("\n");
 
 	if (info->cache && info->object) {
-		describe_object(addr, tag, info);
+		describe_object(addr, info);
 		pr_err("\n");
 	}
 
@@ -426,6 +419,9 @@ static void complete_report_info(struct kasan_report_info *info)
 		info->object = nearest_obj(info->cache, slab, addr);
 	} else
 		info->cache = info->object = NULL;
+
+	/* Fill in mode-specific report info fields. */
+	kasan_complete_mode_report_info(info);
 }
 
 void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
@@ -443,6 +439,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 
 	start_report(&flags, true);
 
+	memset(&info, 0, sizeof(info));
 	info.type = type;
 	info.access_addr = ptr;
 	info.access_size = 0;
@@ -477,6 +474,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	start_report(&irq_flags, true);
 
+	memset(&info, 0, sizeof(info));
 	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = ptr;
 	info.access_size = size;
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 74d21786ef09..087c1d8c8145 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -109,7 +109,7 @@ static const char *get_wild_bug_type(struct kasan_report_info *info)
 	return bug_type;
 }
 
-const char *kasan_get_bug_type(struct kasan_report_info *info)
+static const char *get_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -127,25 +127,27 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 	return get_wild_bug_type(info);
 }
 
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
+void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
 	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_free_meta *free_meta;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (!alloc_meta)
-		return NULL;
+	info->bug_type = get_bug_type(info);
 
-	return &alloc_meta->alloc_track;
-}
+	if (!info->cache || !info->object)
+		return;
 
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
-		return NULL;
-	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
-	return &kasan_get_free_meta(cache, object)->free_track;
+	alloc_meta = kasan_get_alloc_meta(info->cache, info->object);
+	if (alloc_meta)
+		memcpy(&info->alloc_track, &alloc_meta->alloc_track,
+		       sizeof(info->alloc_track));
+
+	if (*(u8 *)kasan_mem_to_shadow(info->object) == KASAN_SLAB_FREETRACK) {
+		/* Free meta must be present with KASAN_SLAB_FREETRACK. */
+		free_meta = kasan_get_free_meta(info->cache, info->object);
+		memcpy(&info->free_track, &free_meta->free_track,
+		       sizeof(info->free_track));
+	}
 }
 
 void kasan_metadata_fetch_row(char *buffer, void *row)
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 79b6497d8a81..5cbac2cdb177 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -6,7 +6,7 @@
 
 #include "kasan.h"
 
-const char *kasan_get_bug_type(struct kasan_report_info *info)
+static const char *get_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -22,14 +22,7 @@ const char *kasan_get_bug_type(struct kasan_report_info *info)
 	return "invalid-access";
 }
 
-struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
-						void *object)
+void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
-	return NULL;
-}
-
-struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-						void *object, u8 tag)
-{
-	return NULL;
+	info->bug_type = get_bug_type(info);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5f6e8cdf1a25410d2da1ae74ec45d8a17a611c46.1658189199.git.andreyknvl%40google.com.
