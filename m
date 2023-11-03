Return-Path: <kasan-dev+bncBAABBRWLSWVAMGQEXJAIIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 556C57E0AB1
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Nov 2023 22:27:36 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5344aaf2703sf1936325a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Nov 2023 14:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1699046856; cv=pass;
        d=google.com; s=arc-20160816;
        b=fnhOPMBQAZvZvSxVkFCbIROtEV6Zk/d7IWxeQtI/XQhRjy4O3CZanRkjjbmfH8Tp3E
         SNdylvgFZo0WQteg6811XdQelGb7RnOwnVPEiWdT3SjnNPNWcuS0AlvKs6SO4q+agnvs
         SvJc7+5NpV1DJAhOcpikzMgtVQ8x9GvJcg50INib+Mt72uRGD/9Y7MKSP/j+R/uEnR8e
         z07NrsbFWHk6vhXDKOyHkvrgEj9koCL5J29azL0NSWRixJ0sV81FgI1O5ygMp3A9Mref
         sys3CVgRwhwd5F8TE9NOsKcVHEDMZ99zRTHArYM//jr8PIQCQFC6wyVJcs7DjrIOe4s7
         KDig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7PWM96FO7tziTM4qU/5FNR++/kszate7YsYex+EIdnw=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=BDRxykWrQSW4CQ3PzHyIbBY6tlnEL0dB2q4LE6Bpy3cNQ57xYrHic5GRZmwCrlxFkk
         YJuYMJjfxZzJf+MyqVHLJt7fysVyxPqIQgHk8hw8hi565/EoUCWo9gN+bIMLndTf63kK
         R8sh/tH8yeGmbvKQNiPKzcGeEVCrcfdf4Mqv07MSHYK2i3FZyQ99uMMblcCEZlchbo9o
         XlmT/n5adpsz5B13yGlRIjBcU4Jts4KFBtKS1uDTuDeVfyYS7EAO9T2TFWF7TYoLBBIt
         DVhvraq+bOi5rAojAuAIENDf5iWLVtHcWMDl0O45ynQDlLXl3FHhopRoyRudHuZ6tNmk
         /1wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BnwK0S60;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699046856; x=1699651656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7PWM96FO7tziTM4qU/5FNR++/kszate7YsYex+EIdnw=;
        b=Q/PU9LVqq9+OcgedK97zPs2mlFH82KZvecOk1KQ7Gy5FMls1IbZpjaBTeN/QUOF369
         x4ZhSAdkD3MlTnE+E8GW8ZkziNsK/Sx7aCjCpJAWDcXeeK1POm2A5dYDtKV+OTqCUBjT
         DOvfkv4G9z4elEzCKPfvrj1MukhuyQnv7uMN64bdXwHHgxCtY+OVe+mUeIhaN4z4PQaG
         dq/LZDEvDHg3zJD7cTLFlL4PUlEzd28B17POoEi3knO8uo6g9x7zl7q3I+NwuhMgYBg8
         b3w5afV/G9HmrwpKTHcA9S+vpXmgDUpULatXAY9ZkpzCGCcwcAOvmmMo69WwtGTro7Xq
         lNLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699046856; x=1699651656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7PWM96FO7tziTM4qU/5FNR++/kszate7YsYex+EIdnw=;
        b=U09dT1qviwMjeV/q7QHGzGt1f604OOA8vZnn6InOgrgVUvytvDZbCS64yrk0F2urNW
         OxNHuLy88YGwmugdF/L26QZa6vf5TD9YA9ITiNjWXFXhPJT7EeAgNilf4Y6FsRf2e+QY
         btGgjjc3MYx1mAKxFBsbzAuNvzQt+ofoboyOmWqv4qOfDMGbU+iU1RMPUdnXDHsserFY
         O4vTvKfzuix7lJz6A+uK+RwohNfxykwbomQefEmxfuAzq9F4b69asEnOnMuJs58pgVIp
         VpPCqZfLJ4+bqYTLKNtFbXoNBgC3T1WjaClfn8in3CSaLM0VdMVsAx+RrNYxbNAYfFxb
         nd6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw+10FDpWIs/VJksQ9/CqjgvWznRJ7rv3LV4fRFpzCofX5iIUIJ
	4PyTAHKXvpnhtAnzXEJGkJM=
X-Google-Smtp-Source: AGHT+IFgaSU14mILULoo8338n7CJo5EUZM7b3PlsggQYVNvWtbeIrCgo3G7tAJi9crOffRLKyuANNg==
X-Received: by 2002:a50:d49e:0:b0:543:5741:c9cd with SMTP id s30-20020a50d49e000000b005435741c9cdmr10982555edi.34.1699046855184;
        Fri, 03 Nov 2023 14:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:453:b0:53d:b3c3:2123 with SMTP id
 p19-20020a056402045300b0053db3c32123ls521567edw.1.-pod-prod-07-eu; Fri, 03
 Nov 2023 14:27:33 -0700 (PDT)
X-Received: by 2002:a05:6402:1bc4:b0:53e:3b8f:8a58 with SMTP id ch4-20020a0564021bc400b0053e3b8f8a58mr17816197edb.11.1699046853563;
        Fri, 03 Nov 2023 14:27:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1699046853; cv=none;
        d=google.com; s=arc-20160816;
        b=ENWhIDJhK09ae31gWNvD0ebOCzzFHZ3eWt8NBXR82uGmeJcUluxt4wK7vCKAIcvtcq
         c0g3InnYYHLMx6N3TmAJf9L7E4FDC7ldB+Q0BFyURcWNRuGSRh7wRlQBskaTfMHcN4QM
         K46Ux7V1vIK9FQzj6pYD5wEwt4vjvCw6txWTzDNJGjK9XhbZooPwMILwJ8Q9lf7Fv5Qp
         UsgXvWHw5wrgb1cuu1VqFW2PvUmby+Vuy4iv9VeJ/+6JpvPJDUKhbJlSSFdieSLT8Nkt
         RS5/WdOqdHEKfBs6p1JIZh3mBpplBUB0gPRI1QPkuxXP74ojSRnyFCmd2cTU+rfB1ccj
         L7rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=zpQnTcl7Ae4p19CvIz4jyFHYTSPPJ5pSlBVfY1JSDUg=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=jjm/V3XUN1KkBLReVE/Wd93LXAe/O5DLD8su6/3rFc/uWGsvYsRWD9hP8vmKQNcjQT
         KlqFyDGb3nqh2wDZFGYvQaqibw2ms/6kK/Sw7Wee3S4myQRELUpkft91QMfHR+SEZYlY
         qqNWOwCz4gLVubU6f6VM7Tfmop9YQ8y15/Ml5vgop1l2MmyLzv9AIY8TcazY/2OgombU
         784JXBr/LW4lTy4X7tcvevDswkQ/iwkJThUtrRD9HU0ppitjRBQULZlouPcpTkF5mDm8
         e42mSU3ppWknTTzIydeNl+LFsLOYNykeCH67SAZd0mULpTYlV/+oR+JUAR3IewgpoxA9
         ItEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BnwK0S60;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta0.migadu.com (out-170.mta0.migadu.com. [2001:41d0:1004:224b::aa])
        by gmr-mx.google.com with ESMTPS id bm7-20020a0564020b0700b0054359279646si160765edb.3.2023.11.03.14.27.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Nov 2023 14:27:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::aa as permitted sender) client-ip=2001:41d0:1004:224b::aa;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC] kasan: use stack_depot_put for Generic mode
Date: Fri,  3 Nov 2023 22:27:24 +0100
Message-Id: <20231103212724.134597-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BnwK0S60;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::aa as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Evict alloc/free stack traces from the stack depot for Generic KASAN
once they are evicted from the quaratine.

For auxiliary stack traces, evict the oldest stack trace once a new one
is saved (KASAN only keeps references to the last two).

Also evict all save stack traces on krealloc.

To avoid double-evicting and mis-evicting stack traces (in case KASAN's
metadata was corrupted), reset KASAN's per-object metadata that stores
stack depot handles when the object is initialized and when it's evicted
from the quarantine.

Note that stack_depot_put is no-op of the handle is 0.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This goes on top of the "stackdepot: allow evicting stack traces" series.
I'll mail the patches all together after the merge window.
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
index 152dca73f398..37fb0e3f5876 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -141,11 +141,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
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
@@ -155,14 +166,17 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231103212724.134597-1-andrey.konovalov%40linux.dev.
