Return-Path: <kasan-dev+bncBAABBIFYT2KQMGQE7NCAIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D2EC7549EEC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:20:48 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id l17-20020a05600c4f1100b0039c860db521sf3419912wmq.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151648; cv=pass;
        d=google.com; s=arc-20160816;
        b=QLDGBC8V96UdX8BJ+GgqRetAwqGyQhWsj3aZrGm4kuIOIQpErS11EoxSWtOx8ZYFDI
         E68O0M47Hx08Bw5CNuGA93vBb3cuX3t/bv/wuvZJS9LceTNFGxTTWf7longA0ieasKSv
         esTjFriGOJ+rQXNM3JHVix3adf4eNIwEhdJG6MXFSSo/TxP2m5J7m2Xd/LoOrXFRKSQg
         KAtLYm5ocCPZh1JK+BMALeEYzrgDUQj+CFSbdzPf15EZijqCxKqEIxmK5ta6mXmi0CjF
         JUXMBN4M/e/IgDG8VsbTCf4VtW7V1paKuW23GtEP0r3rOM+l/zhxIXk/tejrHwcTfFst
         JqYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZznR2vUDZ8kz5jeSxzqBIrZHuD4HpSQsjEh366hDYd0=;
        b=HrNeqHtGCEiiM8koKWxZixT8SaQuIgPVRNt6tdoKUOTVhZqPTUoTqgCWu3T7/uYHJo
         bMANwIl1dxQGISGQYVhqtOMTy8l/mCBGhDvUgnnkXt7E/YZLkZ6Z+e9vs2IZ9S1SfMrA
         D91C5FRk4HGXt3WwZ8dcVlXxUfCWWZGV8eHMJETqDdcdjtwPUCOUMoO/J81eHjyEBV0m
         9BLTYCDxNJmUGawacZDtq7+SRiV6kbyjPGzHcR84oljdXLaU+cEEWPHTVOaJik5gz5jq
         i0g093JnoCh6QRxREdNZRCvCvYVzz65+bf4/yZmXZ750UUHzpnqnC4YfnS0jCafms3NL
         FJmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h7JWBIF6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZznR2vUDZ8kz5jeSxzqBIrZHuD4HpSQsjEh366hDYd0=;
        b=pXw7nRIlVLHQ/o7mlev9Dc/xerurlkZBw4p308oDOtpNBOIxG92NG3RIR5aHpnW2Lx
         DtqEqm0PTmPS1VO8qE5B7m8RJ1bOGrkGSmRBTZjiYfsYcPKCLuLIap2b98TEwsWktiV7
         EyEmMZotUj1QQRCyOZ2DrVxDa9Ef7b3LwhJtz4e5dMLWU/mONxXeBhx2Q5r7r+5PpxhG
         wEcQ0vX23a3ZQPFQ79xLRPkF9v2varRVPxj2JTFVwDiaQbEcpi5sxCk6OstINjFldyJt
         4hDY8witPJs8a+7T8iDNTPNSFu4j24vaCBcQ1mSTyHLG5rMDhA9vsHYhiTmwOVkQaC1x
         4/lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZznR2vUDZ8kz5jeSxzqBIrZHuD4HpSQsjEh366hDYd0=;
        b=dVQQNHjqAyh4sySPcUgAOMtdncG+2yLKtA+CLvES4GXMMzMKsqwPYVWS4BZsMIfq/f
         z27Vb38GAld0pz7oO5Hk4VoA2+fvHYkH77Y+Weu/3mqeqkIyumZ0qKd7aw9aDnN8dBv+
         ZLuf4LU9MhwMRKRxPHBe6e0mHK2DOy16CmtHikBjmcN5jn3u/nmgveL7FDsVUPYBMi3B
         DPDxAaTIv+18uh04hIm/4MpqynHmXRiZHwe/T2XHgalQ/Tfj/Jyt10Q6MZWRxY8p5gGl
         aM71Rnjz4y9obuN6ksDyawRPqYx2vJadNsJt61O8geLi1hqEF66iHRjZHCYHFcvJWiE0
         1PLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xHq3d962v6cK/rLEuASAJTjBQnM8Kqhp+RVis5WxLBvYnkTQU
	58j9v0pfhupE0H1WFTPB0WM=
X-Google-Smtp-Source: ABdhPJxyoHfsxW4Ia9KhrpHfrrpH9iQgRjS3xp5fKfaDB04/yppUCLELBaiT4GYCEmFhMRQAJdP95Q==
X-Received: by 2002:a7b:cc94:0:b0:39c:4507:e806 with SMTP id p20-20020a7bcc94000000b0039c4507e806mr444593wma.91.1655151648431;
        Mon, 13 Jun 2022 13:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ec7:b0:39c:871d:313f with SMTP id
 g7-20020a05600c4ec700b0039c871d313fls126599wmq.2.canary-gmail; Mon, 13 Jun
 2022 13:20:47 -0700 (PDT)
X-Received: by 2002:a05:600c:8a6:b0:39c:5682:32d with SMTP id l38-20020a05600c08a600b0039c5682032dmr453086wmp.126.1655151647689;
        Mon, 13 Jun 2022 13:20:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151647; cv=none;
        d=google.com; s=arc-20160816;
        b=mMdzG91DRya7VaGqAKH3DMhnWnxcr+NtUPUtcoWhenbPUN+61DGqwoqBnx0pTNqa+d
         ggnIZnVpxwlNido04bGUXLuEM9vReL8lIUU8TjRBdDYyU5DzQEG8fRpRdZtjq/mUDom4
         UZebV+K2Gy7dhMDOe1AiEF67D9tOtuy4A8iRoyHNtqPwjoYcNNGqEJhdZyjw3PH00IR1
         OysYj7wNcKjMNaJivIHMn+z0Tx2L7Bf8B0dsQb27ZvcatYxOqbCOxsG0MzUgk6vZIOyY
         /0OR/z5hNFXVmvbW66AD1giPsaadJOuYN2TkwP6odb6LeDSEPQjMvjTMqirWoiM2vdNO
         Ivlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=elbTPIbPzGd31s7aorwI9rYhjRmEHK3gjeAMkGGimu0=;
        b=HNfe+IH63ulB4RJK/gUYU1sFUn5yYKlax11T6WMFkD1kv7BtnSgJZz4VazgpDF+hze
         JwkEbZgcWtUzT9HsSobitOuPM5pWcP1syBH7HdD+3qWBiPrapwGDFix7KSJ3kAhYFnlA
         qB4RmVN4nb1tV9erC3zDhgdACC7zUyg5hXTkm81zSoTmggWJQJmF4P4BnCxx9EP6wHUZ
         CWtjr7gZ3aVkC5uzHP3fuuMPRT8VgWwoLaqwgD2szW8Ed0s9dum6lVRagXiE+nXT6l/f
         k/rBmLCIKWloq6VMM271dQwem8IXKdU/lGt+iIBhX1SMlJcqdPLIOnqwHkCAznEQjqjB
         I6AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h7JWBIF6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id p17-20020a5d4591000000b00219adf145aesi232113wrq.6.2022.06.13.13.20.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:20:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH 30/32] kasan: introduce kasan_complete_mode_report_info
Date: Mon, 13 Jun 2022 22:14:21 +0200
Message-Id: <d8a0a85924bad7714d620f92516d28d4154f5325.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h7JWBIF6;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 mm/kasan/report.c         | 29 ++++++++++++++---------------
 mm/kasan/report_generic.c | 32 +++++++++++++++++---------------
 mm/kasan/report_tags.c    | 13 +++----------
 4 files changed, 51 insertions(+), 56 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b9bd9f1656bf..c51cea31ced0 100644
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
 struct kasan_report_info {
 	/* Filled in by kasan_report_*(). */
 	void *access_addr;
@@ -158,6 +165,11 @@ struct kasan_report_info {
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
@@ -183,14 +195,7 @@ struct kasan_global {
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
 
@@ -264,16 +269,16 @@ static inline bool addr_has_metadata(const void *addr)
 
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
@@ -308,10 +313,6 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
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
index a2789d4a05dd..206b7fe64e6b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,7 +176,7 @@ static void end_report(unsigned long *flags, void *addr)
 static void print_error_description(struct kasan_report_info *info)
 {
 	const char *bug_type = info->is_free ?
-		"double-free or invalid-free" : kasan_get_bug_type(info);
+		"double-free or invalid-free" : info->bug_type;
 
 	pr_err("BUG: KASAN: %s in %pS\n", bug_type, (void *)info->ip);
 	if (info->is_free)
@@ -236,31 +236,25 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
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
 
@@ -289,7 +283,7 @@ static void print_address_description(void *addr, u8 tag,
 	pr_err("\n");
 
 	if (info->cache && info->object) {
-		describe_object(addr, tag, info);
+		describe_object(addr, info);
 		pr_err("\n");
 	}
 
@@ -420,6 +414,9 @@ static void complete_report_info(struct kasan_report_info *info)
 		info->object = nearest_obj(info->cache, slab, addr);
 	} else
 		info->cache = info->object = NULL;
+
+	/* Fill in mode-specific report info fields. */
+	kasan_complete_mode_report_info(info);
 }
 
 void kasan_report_invalid_free(void *ptr, unsigned long ip)
@@ -437,6 +434,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
 
 	start_report(&flags, true);
 
+	memset(&info, 0, sizeof(info));
 	info.access_addr = ptr;
 	info.access_size = 0;
 	info.is_write = false;
@@ -471,6 +469,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	start_report(&irq_flags, true);
 
+	memset(&info, 0, sizeof(info));
 	info.access_addr = ptr;
 	info.access_size = size;
 	info.is_write = is_write;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d8a0a85924bad7714d620f92516d28d4154f5325.1655150842.git.andreyknvl%40google.com.
