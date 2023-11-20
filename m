Return-Path: <kasan-dev+bncBAABB5VY52VAMGQEER2DWDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BAA17F1B8C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:50:47 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-53fa5cd4480sf3400975a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:50:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502647; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gb2tNOyA/RtmqZfh9bsjdc17e5mhzuMOTtfnjdE2lFPXOS3cxVcjTOweypTR21bNQj
         cbyni0N7BUpcdPXFyqzP3wlfuRfr4clhtG70fj7Zqofqd7B6xFr/35g+WIBihoNGILDb
         7kgYkthCOxxyHDjDhLjsYONa1LnKsTJHKnbg5FLFqf8io/uTD5/56+5Fo2KP0qlOf3ch
         2R0IyLzpkYXMx9RzV0/7tZc+E2MZKZPONZR4IRWw8caDN8crZ8kZBi64oaXHKRc55LjN
         JxPYAPMlER+av9/LzTModzMEgLsLEKJR0bsIPqIr8iLrA24wGK6VMjXBlTC5zZCBX2vp
         tucA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dZDwH0B/iOfE/mWV6N9AcHejnc1eJvBCnQZQfY6Hq+4=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=izMNuP0Y4C6fbgFkhdFxiJ35cs1L+TexUXU3QEUTc4XP55RpaEeXLGzVklfgwWipmV
         hkQJ5FPkG+DuAn8dWeVxNdzBn0Fy66Qt92qoLGXcuUwDdZZ+RwCWYE5A/UElLp20ooLP
         3mywmGMxzmwcGtl/D2BuWjFqgxThQl88ZF8aO1RkhWI02Y7F1E7wbhpT3nkOejILhfVs
         AjNqhSS9U4OCEpLt6rvqNsOeCUwUapmEMAes7vmd0Hlb/J19+00nqxZGgQuqNXlzmgLo
         stJB7slvF2+jpezsdiR7M8jA+oxZ2Ee+5dW10fDjMayG2QmrK0u4AoXw9eiztCQtgfdM
         6iDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DNgy9uYy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502647; x=1701107447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dZDwH0B/iOfE/mWV6N9AcHejnc1eJvBCnQZQfY6Hq+4=;
        b=OZW2Ys03hI7IbtWQu4Iaxxocr+v1kliHTEG0tkQrBgiZZOMqLSRF/9ltJliynKkaLP
         AruQqht+Mm4BG+WhXAhkxAVcj6/Rg1ELHYQb6sdYDTXL1kywP5q+Rd9ZyqTX5Inld7ZO
         E/LzU1ty2AY7EybDANZ7hmfTyAt78CMT5ef/TZ8jtw2r0AvCb0IA3SvGncJbJ5Ebm0k7
         SZfjyHhMmjz0lc6VWdMN+ucFqR9e+osvJpOoaNlZiitgRBTYIiMycvKCevHZOb0OIyLi
         ++X7aElKXTsTtUV7PtsjFJ4CB4YkrUwF9fzpvHWPvJjjpDTzagA/EeEVSFvGwihhp1Lm
         7y2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502647; x=1701107447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dZDwH0B/iOfE/mWV6N9AcHejnc1eJvBCnQZQfY6Hq+4=;
        b=LP5v6BwT6dBx3r9vf14eCVyg5AzVWr8OQd136FPkm3CMY+vunfXGSufiI0LkACKMEP
         oRlO+LB4XCjiYH0KzYv9qcndJ/TJxAEb8F4pTMiG6b4rZTThxKQtYEVSAKr3CKXhkXm/
         kOQC7MtRQkEiL3CK8vBFl30fO4nqOXBbtaspgLzwfmWZuqrd15RYN/J1iSryc7JOfdt0
         5uKORathy2239GSTS/skAV/nwJiQeB/nuhQrM2wsUeCKuxi0nlq+aoBiY31OewTrVV7g
         ABgHSlySSejjZakry53HX3QlcdihPNkFsWvWhYSg6tOxgLIyDWZGUgk4NxEAcg/HftRK
         Gp0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwoaC74RoDPPokfVnWEJZGkNJPKlwOqoG6aHfh2K1/6xtFSU5Lj
	6s/6kc6ZliBLkspcpFyyVqI=
X-Google-Smtp-Source: AGHT+IEpgxNnrRasSwPkWPzno/SUTrIm93lA+yEjio7b9vfqF+G5NAFLQfpx38czk7YdbK/m91ziBg==
X-Received: by 2002:aa7:d145:0:b0:548:4b10:7343 with SMTP id r5-20020aa7d145000000b005484b107343mr102269edo.15.1700502646738;
        Mon, 20 Nov 2023 09:50:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5020:b0:542:df39:bcf2 with SMTP id
 p32-20020a056402502000b00542df39bcf2ls604421eda.1.-pod-prod-01-eu; Mon, 20
 Nov 2023 09:50:45 -0800 (PST)
X-Received: by 2002:a05:6402:3d5:b0:543:5852:2f1d with SMTP id t21-20020a05640203d500b0054358522f1dmr87922edw.37.1700502645185;
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502645; cv=none;
        d=google.com; s=arc-20160816;
        b=Bbe3cd0qhfs8LaXxZ0Q1GtNtorkHkpgGhUTAtRnmofMbTiPAL2Zzn/Uc2V1i23aqTl
         WEMOW1T42SdPeyvw8aTfBbkVFnnuwCeIoQfomtjbyp2V4IKmsh9s7gmthYyaDLt1TDOy
         5pLBgePkKoezKdP9OE0Wa7cUKb3IUm9IVWWIe63oAtbE/b2RkUbsKCVFwLdENEKwmi+9
         RVCfE/QzhDf++CfwY+L6SNBo8AV9AkVNN4U3SkLIybm73TJQ/a4ntbEzyLMqTkztQ73/
         LdapkJShaVW42VYiMK0NIilKfZEjh/vhW5VFZt3rZaWpP7j/7cyMCKF99zZ0JiOw6Knl
         wH6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RvoTVlNH/9QJKGjG7ts3ES/7xJIaYyT0JIUdEPtk5OM=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=vYaaAAliFNWunrBEagO1Bwo5pznHF/nTttpLYq62fdv/YuotsPxZDE9eUz/PkmZqzd
         wJ0nigxoGVBsA5QR0rO3YFBin9kquRi5sZGhhkjbzhpQmcXqoYRsAhz8Iqsq2GxILfXO
         8tQ198nWjoP+G5gMgOCd+lSdr2nZ2aGwyqADDTelK79jjXLqmSZ5qQidGKLgMvDikQwX
         gDZri68YoK3eGs/q83U78n0iTqP6tFtjxKkIc/Iei6XXxJdv5TKBnakHm7sf4Hdjdkrh
         ksJDDMTiz2HFFDOXTsa3hCfOyNga5/4meU64OW7E7REjepQhnyMQeFtG847n61HuAeVv
         YdCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DNgy9uYy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [95.215.58.170])
        by gmr-mx.google.com with ESMTPS id p12-20020a056402500c00b005457f8a07e6si352596eda.4.2023.11.20.09.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:50:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as permitted sender) client-ip=95.215.58.170;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 21/22] kasan: use stack_depot_put for Generic mode
Date: Mon, 20 Nov 2023 18:47:19 +0100
Message-Id: <5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DNgy9uYy;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.170 as
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

Evict alloc/free stack traces from the stack depot for Generic KASAN
once they are evicted from the quaratine.

For auxiliary stack traces, evict the oldest stack trace once a new one
is saved (KASAN only keeps references to the last two).

Also evict all saved stack traces on krealloc.

To avoid double-evicting and mis-evicting stack traces (in case KASAN's
metadata was corrupted), reset KASAN's per-object metadata that stores
stack depot handles when the object is initialized and when it's evicted
from the quarantine.

Note that stack_depot_put is no-op if the handle is 0.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c     |  3 ++-
 mm/kasan/generic.c    | 22 ++++++++++++++++++----
 mm/kasan/quarantine.c | 26 ++++++++++++++++++++------
 3 files changed, 40 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 825a0240ec02..b5d8bd26fced 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -50,7 +50,8 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
-	track->stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
+	track->stack = kasan_save_stack(flags,
+			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
 }
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5d168c9afb32..50cc519e23f4 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -449,10 +449,14 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 {
 	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_free_meta *free_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
 	if (alloc_meta)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	free_meta = kasan_get_free_meta(cache, object);
+	if (free_meta)
+		__memset(free_meta, 0, sizeof(*free_meta));
 }
 
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
@@ -489,18 +493,20 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
 	if (!alloc_meta)
 		return;
 
+	stack_depot_put(alloc_meta->aux_stack[1]);
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
 	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
 }
 
 void kasan_record_aux_stack(void *addr)
 {
-	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
+	return __kasan_record_aux_stack(addr,
+			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
 }
 
 void kasan_record_aux_stack_noalloc(void *addr)
 {
-	return __kasan_record_aux_stack(addr, 0);
+	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_GET);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
@@ -508,8 +514,16 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	struct kasan_alloc_meta *alloc_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->alloc_track, flags);
+	if (!alloc_meta)
+		return;
+
+	/* Evict previous stack traces (might exist for krealloc). */
+	stack_depot_put(alloc_meta->alloc_track.stack);
+	stack_depot_put(alloc_meta->aux_stack[0]);
+	stack_depot_put(alloc_meta->aux_stack[1]);
+	__memset(alloc_meta, 0, sizeof(*alloc_meta));
+
+	kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index ca4529156735..265ca2bbe2dd 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -143,11 +143,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
 static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
 	void *object = qlink_to_object(qlink, cache);
-	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
+	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
+	struct kasan_free_meta *free_meta = kasan_get_free_meta(cache, object);
 	unsigned long flags;
 
-	if (IS_ENABLED(CONFIG_SLAB))
-		local_irq_save(flags);
+	if (alloc_meta) {
+		stack_depot_put(alloc_meta->alloc_track.stack);
+		stack_depot_put(alloc_meta->aux_stack[0]);
+		stack_depot_put(alloc_meta->aux_stack[1]);
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	}
+
+	if (free_meta &&
+	    *(u8 *)kasan_mem_to_shadow(object) == KASAN_SLAB_FREETRACK) {
+		stack_depot_put(free_meta->free_track.stack);
+		free_meta->free_track.stack = 0;
+	}
 
 	/*
 	 * If init_on_free is enabled and KASAN's free metadata is stored in
@@ -157,14 +168,17 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	 */
 	if (slab_want_init_on_free(cache) &&
 	    cache->kasan_info.free_meta_offset == 0)
-		memzero_explicit(meta, sizeof(*meta));
+		memzero_explicit(free_meta, sizeof(*free_meta));
 
 	/*
-	 * As the object now gets freed from the quarantine, assume that its
-	 * free track is no longer valid.
+	 * As the object now gets freed from the quarantine,
+	 * take note that its free track is no longer exists.
 	 */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 
+	if (IS_ENABLED(CONFIG_SLAB))
+		local_irq_save(flags);
+
 	___cache_free(cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5cef104d9b842899489b4054fe8d1339a71acee0.1700502145.git.andreyknvl%40google.com.
