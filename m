Return-Path: <kasan-dev+bncBAABBO6L3GMAMGQE6JUOSYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id DD7AE5ADABE
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:19 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id c6-20020adfa706000000b00222c3caa23esf1493179wrd.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412219; cv=pass;
        d=google.com; s=arc-20160816;
        b=DX07qLMZD8vL2m5u++Hkd8r4YJS991JldffFTFe0czOEAebbu/erH4fcMkvOvLFor4
         0m7nNX6A++Vj6rIyA9aBwgtVFcHYuK6bjdujV6xDCl3a5zuYR1Ld/MbxnWMd6BXZOFZt
         HGjeS+iEboyzS60VNdT8v1Vs+gW2hMnaG8/GO4/B1Bv7Gfg58BnYxEzqX7L/ZaR78MvY
         nx6qxLmr1WwyrowPmAXmWP8erXr673674CPW/lCXuwysJ4i0NwrP452QKbd4gc1kfSsA
         SATYivksy2IaA45oEE06wnAWyrZfewYWuakSB79vdh9dZf5IcbqjnxbRqF9oaGb8gNtC
         m0CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H5wwDt0EXX/KXoYtea0pXtagO3XY6i8364NRdRnTBdM=;
        b=zuFIrUE713/pE2nZn8dammQePs88fghyBRC2ZmPb4dJtVUhX53iltE89YohByQpYR6
         AYAsS/Wk12gfNp2gSXWh6D3Wdmg5EoSd+8Hfx9kgBOaXB/uBjQLucZCN2imeiPrpte1A
         g0KDDzB7TlVIN8zKfAIpcGq7SVIdqoiCyN2hIpljH11Gn2pElSfSzs7lmRcg+zNUlQ8Y
         67czGxFk50DrMwn3g/DnWpZSKR4SX9J32No9NX8Fp1+sw5FRKBhk0DfbGya92b6h2eM5
         In7a9MyDYuMgRsE55nZSg5J8OQD31bYIJebVDPnjjnGGcfFbeFPCYyPUhKlrmuuRbofA
         2urg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mOUTyYb6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=H5wwDt0EXX/KXoYtea0pXtagO3XY6i8364NRdRnTBdM=;
        b=OVTxaG6h3PA+tMxxcyd9IM0UFiF4+UspJjnUGvewgZndUYGmVlctHpdZ/3hLs8iSyO
         mWmjav1HJYT+XSzQENM3L8uw68mnFY0Ikdly0Fl9WM2rdxW460uJrllOORITQ8dVwS59
         x0XLm+lD0Cvy6ZawJNU3vwx0IZdrkVAwdlLCtkFDZnU47O02I52DlWTLB0/Bu2Y6sKul
         8mTq2by5mnbmL/1vqzLOXyzYYil11lnTVdjiFCNq3FjRg970QvoLYSPz5zN9iIwjXm9d
         e4kKvMC/vSpiMezmgqhvg4VoSv7xO8tHKZ5UHrw1LZjkKgf4gXnPfJrOFsslJlXg7uVg
         mytw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=H5wwDt0EXX/KXoYtea0pXtagO3XY6i8364NRdRnTBdM=;
        b=gzaKK9LGtOFQYBXyGDH3Yt6NrAHkLeZY/B7fH/58Is2YBeBBKOWm8ypmX8nNEWPT+0
         HfCS1ZYnzUDRsjMwahVmhGukj5f761BrU4+aD5vbp1yUqlQMWY23WnvR6ab48A3XwG1W
         R77nIWctoQlS2P/5gG04JI45O2FLoCNvpT7lOpsE1xnpO+lwQ28lPOtELLzhHqsqvELC
         L0InduoVg3XiKYLL00jmuIR+Jjv9noHpwZ3bOQUfKFRcYjgAiHQMom3UVUWPeZze8ZV6
         AA9fMTgXua9sqb9mnMRuumIAw/62zzwpN/owiSbtb/pC4ViKQiRzgxkfze33aUxVIQS6
         KP7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2HyV/FosKbD/gNnI/I3UTecFxlHEXeCwKL1H0MCctUpgCvah8/
	nt7wcMTVvO38YAA27QkQx7k=
X-Google-Smtp-Source: AA6agR7/EsUhRsi5DE4I+TD4a81EVIPbn6JZmL8zyZE/vlLxZRuJwa/SFpSEfJnSrNA3dWhYwpY8gQ==
X-Received: by 2002:a5d:6190:0:b0:228:6972:fd14 with SMTP id j16-20020a5d6190000000b002286972fd14mr4828315wru.114.1662412219592;
        Mon, 05 Sep 2022 14:10:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6018:b0:3a8:3c9f:7e90 with SMTP id
 az24-20020a05600c601800b003a83c9f7e90ls5124418wmb.1.-pod-canary-gmail; Mon,
 05 Sep 2022 14:10:19 -0700 (PDT)
X-Received: by 2002:a05:600c:3781:b0:3a6:804a:afc with SMTP id o1-20020a05600c378100b003a6804a0afcmr11625373wmr.27.1662412218985;
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412218; cv=none;
        d=google.com; s=arc-20160816;
        b=RseyXIaIjqYbBtdqmxeIjiY3Dv1M3rw6OnPR1veag5ocf5/r6hfxfK/zfe6lb7zBsE
         OoQXG3Rs8Cuodfun+BXgkdV4s7hRjLSHsxQbveuZwI0g2GvcOoy9h5XHLBEL0MDrYNLt
         rzWX5WIR+eeMfRLbsCH2uEUPBblTc26ymLrxnI5HNbo12W8B8YXDlv9XGpw+VSPjNg/C
         hI0C9i7kX4KDDsTiix41g5OhCOygytRMfvPhg6H4Ze7LXZai8kLf5O8dFVmDRF/6DXhy
         FaHLKHeZ67jS07diKQjalCot0CwE1ZvfdL37Gu+PmEPNVZSar9v6s4CxJLKmFklmmJAj
         slmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fbsbfSe3kreJ8FQYEympw+02wCBaQbw817ssVfjzz8Q=;
        b=rYP9R/Hvx6++e/GM5In9aHclqg3dTGifwgAAJwuLISQsB9Wy8jUiL2eeItMuRQG3Q7
         qYXLxj5cch5zmqdMMzIRbL+qMbTMV45h0DH2wQ/XW1wAdZ6Vt6bpyVHA9Hh+49z8r0nh
         1ZFPzrs9LXBENX2F+0InJYzxZeVWI4++0h9TYLideDJUMOlcW/gTxwSC+cdP0O2njG/1
         XHJfGkgSuAAx7kqDlVrQhrjRFYqRI9AWoQehzd6XmJTBea0PjrQ2EmtyMriTZeuYk484
         L9+cV+f9qfuZt03Cq/ZSX4arVI/sFtTYoPObjUjALPirAbsOOTUCoGKxorXfwGyGZOqA
         l/OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mOUTyYb6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bn15-20020a056000060f00b0022560048d34si460219wrb.3.2022.09.05.14.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 29/34] kasan: introduce kasan_complete_mode_report_info
Date: Mon,  5 Sep 2022 23:05:44 +0200
Message-Id: <8432b861054fa8d0cee79a8877dedeaf3b677ca8.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mOUTyYb6;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8432b861054fa8d0cee79a8877dedeaf3b677ca8.1662411799.git.andreyknvl%40google.com.
