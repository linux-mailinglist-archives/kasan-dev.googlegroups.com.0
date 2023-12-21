Return-Path: <kasan-dev+bncBAABBBULSKWAMGQE7EDWXNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A4E381BE4F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:35:51 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40c3cea4c19sf9486515e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:35:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703183751; cv=pass;
        d=google.com; s=arc-20160816;
        b=TxteCSYVo6hEyOAc+PxWx9VOav8Ohy1mwr877kDN2ynECT6PkSN/CnlA+I76b1UzvS
         W35+38qBM9KPCqxm6DkiQe2p827oJWFjVncp+wnZNdqLunIYQtqIlx6dbKTLYUINBtw8
         vQpQ4ypZ5Rsj/XMu/TQkNPbQBcZH773/9ar8oz6ZFunH1Vx54CtOaBb5L5xx7DCW0fRg
         jvNulLeCmTmYJEEMrlIKdEyjWOmF2gNqjxGCu0c5SxOKYHkCxhcQfyCyETzK8pziewuF
         1cZmGB0YdJtNS9XAOEh3WUu5KZnuVQ/fNcuAAoFX0gTVGZ4Tf401BdJ2N3l00qkKQkiN
         QQ2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=i8Rouhmgi97TfFpxVB2B85s7ZjHtP6NkHjpvQVXGB5Q=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=ZzhvJbjQ3zQL8GCMZ14z1BebaSHk4vSgxd8nwS/YNNo8/wLh0b8EM2IpBxV2Uct2Fu
         RfeYSz08W/N/zVPcsbGU/RDMqvqQILZ0mo+AgPahswClA60Mkk8SNZ8dPfBQER0dCkuI
         YGGkwGDjB6lG6+kgIIwSwLZEwSB8z7ibNTuco6/sfiBe7E9vlEm2XBldtJHrImapTOD4
         DZ9QMy5QJWnILh1Ht5euJMK0ePUKD8p/9CYdb/NSXFwygz8jH7DjXPdDuNN+FFscFiMf
         bhgXKwsRhklfM0litijelSrKeRgCR/Gr9MDDzIcDeK3sPIeMWbUvjA2mEcYmqxw2bsCk
         uQtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Wp4SgxAx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703183751; x=1703788551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i8Rouhmgi97TfFpxVB2B85s7ZjHtP6NkHjpvQVXGB5Q=;
        b=T1U9ta2EIeJBQjvqAoBJurs23ppSoxQLnEtvm07GARlq+bgW4axWz8K8Q0HUzqejbH
         dtYIaEwnCCwQzNE7CFLBzI1IsRjyh9NWZaWhTxhM5MOKSmX3PEMimMPmPI6CM/i6rwe3
         aqMPoVx59CzaujVK6ys0ymW3ecW/gYy4PP43LJtgS50WMRy6M6cES1l9ifGrbATK+Mtg
         LnbZ7Rw2AoeYJRsudghPUmlzHUNLPB8D2fzELibjZ61uxE4DFaJuco7jXCn7opbsSmyf
         tDss9NTe59Rd6Y7XNLPGS5K7yYX9Ypk9ogOlMB5jLxTlZn9SqAm9jzNS8TPng4IZsJun
         qt1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703183751; x=1703788551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i8Rouhmgi97TfFpxVB2B85s7ZjHtP6NkHjpvQVXGB5Q=;
        b=BH/f1wssHYbCrrdRSKb5s8uBpJYU+rIk2HiD25tKrz517rlGBn7y5dkAGCPrSFGZuU
         gYTv/nT6Kh53S1luDO4yzxzKCf+29cbUU031YvnDPwYNGqom9ktevH92BCjcSNq7/obb
         Omcks4cxgp4xfy0s8Y6v2+8Gxt99WQLN81c+oj60+vw6AWa4pcqvbW6LatxPccKbwtAe
         2btLk7hx/+QECT8cOxZo+j5qnfWGJ27I+t1Sz7TgkIzXDNh+oaIGMXG7aOfsy3VA45ho
         ROU/QPxVYbemtbCnpA8N0Cnh/C7+kBeIcHhzhAHfWziIK8LZIku22vIvobSDpD23civT
         0T2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyPNsfljFMTawvR6mAv/cL3bRtn4mVjNHTm+1MaSwScwXpzpo5u
	xuq7vlpsiyWvCZgruiyiKj0=
X-Google-Smtp-Source: AGHT+IH7TfwVH9wevF345PlvtLgBWaxPCTXNzp/+1SKZIGgwU8Z+QMRKexLyzSp8lmIkdxA8fszu5w==
X-Received: by 2002:a05:600c:4f94:b0:40c:3e0a:692e with SMTP id n20-20020a05600c4f9400b0040c3e0a692emr64744wmq.232.1703183750633;
        Thu, 21 Dec 2023 10:35:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:b0:40c:461f:bd7f with SMTP id
 i4-20020a05600c354400b0040c461fbd7fls726497wmq.2.-pod-prod-01-eu; Thu, 21 Dec
 2023 10:35:49 -0800 (PST)
X-Received: by 2002:a05:600c:234a:b0:40d:190d:f36e with SMTP id 10-20020a05600c234a00b0040d190df36emr87128wmq.161.1703183748944;
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703183748; cv=none;
        d=google.com; s=arc-20160816;
        b=bdgY1evpEgdgVX11FQ7vSwheariMSAetZe0Y8E1IybQdI+pVPohoP9EBa+Zbc/yfWl
         Ve+5Ncd74+8kBDfJq4RPVvGkMVwstc7qkNAFWevOct7+nJRQXhirLf3vPIbBPWuNFYSF
         HJrG/9Su3bRkJGFEk2Nz7VRXFynw2xHetXtf4BZAKmIu2/AapMHl/K7mpe2OBAFYLWXA
         rpXcU40D8Nc9sv0YNmy0GvY7rplv4Zz4kIyC5Wkll2UjBhJxrLspLJo8De0DbycjlfIi
         eSmWlAo3HiQVwfylD2WT84dazOEgbABBZbgQDszvlLIHxeWYsRCZI8rafR5IXTCxLHY7
         pf8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wLcCaNYp1HtmrZAPrigLSWnYXTa9aslZ8ruUHa0DHbo=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=N4zuVlQIIYSL1rjjLvr2kBl7naetcx0Sh3JmHu/3z1yhhwhUd/Hs3deS/8CSzcURr3
         62Gp0/rzlP0f99KxglMqubsZ/1jVrqpKY+nCR2dPoPjDXTydamr6VgKo6BrtX1faBAV6
         Ij/fwHNFN/bS3VDYMoq2SdqokRf8sPc9rT5GWu2CEB6NGj37LgbjIevbyavyFzKz0vZb
         zb9UF6Xsq/EvAB6DGaBxGYknA3zPK9dFD8iAo5OwgFG76OKJue5wDqfJSPU/x94SC+ST
         emvLwRsy9yiVViPXG4/MXCdYT1I1nG9/kOr/HiIKx1wSrmjwKmWDyFo53gs0WolzW/UC
         bArw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Wp4SgxAx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [2001:41d0:1004:224b::b8])
        by gmr-mx.google.com with ESMTPS id ba2-20020a0560001c0200b003365d6b3e14si135458wrb.1.2023.12.21.10.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) client-ip=2001:41d0:1004:224b::b8;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>,
	Juntong Deng <juntong.deng@outlook.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 3/4] kasan: simplify saving extra info into tracks
Date: Thu, 21 Dec 2023 19:35:39 +0100
Message-Id: <20231221183540.168428-3-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-1-andrey.konovalov@linux.dev>
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Wp4SgxAx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Avoid duplicating code for saving extra info into tracks: reuse the
common function for this.

Fixes: 5d4c6ac94694 ("kasan: record and report more information")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 12 ++++++++++--
 mm/kasan/generic.c |  4 ++--
 mm/kasan/kasan.h   |  3 ++-
 mm/kasan/tags.c    | 17 +----------------
 4 files changed, 15 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index fe6c4b43ad9f..d004a0f4406c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -48,7 +48,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
 	return stack_depot_save_flags(entries, nr_entries, flags, depot_flags);
 }
 
-void kasan_set_track(struct kasan_track *track, gfp_t flags)
+void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack)
 {
 #ifdef CONFIG_KASAN_EXTRA_INFO
 	u32 cpu = raw_smp_processor_id();
@@ -58,8 +58,16 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->timestamp = ts_nsec >> 3;
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 	track->pid = current->pid;
-	track->stack = kasan_save_stack(flags,
+	track->stack = stack;
+}
+
+void kasan_save_track(struct kasan_track *track, gfp_t flags)
+{
+	depot_stack_handle_t stack;
+
+	stack = kasan_save_stack(flags,
 			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
+	kasan_set_track(track, stack);
 }
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 769e43e05d0b..11b575707b05 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -553,7 +553,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	stack_depot_put(alloc_meta->aux_stack[1]);
 	__memset(alloc_meta, 0, sizeof(*alloc_meta));
 
-	kasan_set_track(&alloc_meta->alloc_track, flags);
+	kasan_save_track(&alloc_meta->alloc_track, flags);
 }
 
 void kasan_save_free_info(struct kmem_cache *cache, void *object)
@@ -564,7 +564,7 @@ void kasan_save_free_info(struct kmem_cache *cache, void *object)
 	if (!free_meta)
 		return;
 
-	kasan_set_track(&free_meta->free_track, 0);
+	kasan_save_track(&free_meta->free_track, 0);
 	/* The object was freed and has free track set. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 9072ce4c1263..31fb6bb26fed 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -372,7 +372,8 @@ static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
-void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack);
+void kasan_save_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object);
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index c4d14dbf27c0..d65d48b85f90 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -94,17 +94,6 @@ void __init kasan_init_tags(void)
 	}
 }
 
-#ifdef CONFIG_KASAN_EXTRA_INFO
-static void save_extra_info(struct kasan_stack_ring_entry *entry)
-{
-	u32 cpu = raw_smp_processor_id();
-	u64 ts_nsec = local_clock();
-
-	entry->track.cpu = cpu;
-	entry->track.timestamp = ts_nsec >> 3;
-}
-#endif /* CONFIG_KASAN_EXTRA_INFO */
-
 static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
@@ -137,11 +126,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	old_stack = entry->track.stack;
 
 	entry->size = cache->object_size;
-	entry->track.pid = current->pid;
-	entry->track.stack = stack;
-#ifdef CONFIG_KASAN_EXTRA_INFO
-	save_extra_info(entry);
-#endif /* CONFIG_KASAN_EXTRA_INFO */
+	kasan_set_track(&entry->track, stack);
 	entry->is_free = is_free;
 
 	entry->ptr = object;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221183540.168428-3-andrey.konovalov%40linux.dev.
