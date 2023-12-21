Return-Path: <kasan-dev+bncBAABBBMLSKWAMGQEAMVWPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BB7A81BE4D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:35:50 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40d42061a35sf2888735e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:35:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703183750; cv=pass;
        d=google.com; s=arc-20160816;
        b=um7I+J3C4AY9PFaYl2M5/QthGKjD3H888CZLRROiyebXv24mUXwghAll2ztfW5Fyl7
         UA0+65IFtFO18vpYH5TfjAXZO4FqG+awH47Bm0BNPG5Bd3JtAzbKXDeMWYxETDjBqNn/
         qFJ4QnvBRhO18KRb/Loywa6gJFP6hiJhJ+SfA79OKafuTSiBmY1TfltRCX+f8zygTPt4
         vLQL98qqtdZkq7C3Aa6QUvWTtmegA9ogcv1LGjvGvmcty6KiRkUQGdQvPREF6fHDFoeS
         PJkVYp5rHnyYdU9j6BmxSWvNyXxFq+0K1yWp7/c9lirw02CbnymvmoVQGmMJRyP+IJs0
         4LmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QxmScXvNDD+YOTdyFmKpvJPmOVmbVXn98L2VPOZcZFc=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=hZE8M0KTiRUIDK4pApOQPN3K+Bz/0ali66thsrNCUcC8Whdui4CXc+b2AH0tZGwBZV
         /p+OUHT/elXhaYVyiM0sCqY2Z4kDwoojbV6QDKk+TR8wHp54+JCRCUwKs08wq27IeY9f
         XztJn9aZzYPNZzhvQqa3c5KIBDk4z694i4QX+9MrPI9RaHoEVg+Q4+aMKWZm4ON1E5i2
         nj7NSeWUi6tmra94kkKZCeRxOrBR8DKYJ21L8nKyFoWOTi63Klr6toYfEQA9Os69hZhB
         BQtzq3xWZHSsN3y1gKAKiQKgnxgcgn7IIfNDuz2pS8/qHqJDvYW4L2ko1PakhVHUx3aC
         HO/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WarMWAg0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703183750; x=1703788550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QxmScXvNDD+YOTdyFmKpvJPmOVmbVXn98L2VPOZcZFc=;
        b=t2/IIOFcXKFKBH8xRXlC/l4oc3wm7Iy0VHpysC2iW2MF9GeNZOrYIQMHXORkpBM0PI
         Y2nFs8PX/+zK74PpJGba7RLNaVa4SXZvygVIkS/Qy4K+DVzxHKCHkXphheO3v+2yjRPJ
         CqXP7xwFF+10U+4NONe4FHIeqTSZF21E3h+Fiu2qrVCH23FSFv6cgj0aaenMnpXZt+57
         +TXpA1dCYHl4UL8XxKsvBnzQ5h2dLiWwwDVQ++MncY5cMJVcWnQBj2+kGUlqo/6sldRE
         cvIXi9vWiki736dkOuVuDnMAF7axzc47gKt33fKZu+2n0GHINYNMF5TVV2c4tcZIe+hP
         oUdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703183750; x=1703788550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QxmScXvNDD+YOTdyFmKpvJPmOVmbVXn98L2VPOZcZFc=;
        b=EPfgc8bKC0OWCAFz2H3G+UJX+YxzkyPjVrwrNHc2/TVmniGAg8bO+kGmHAthG8qLjW
         O9wy8wHJUUTPgi3siaoKqM/k6c8Oh06PLuYEryCImQO7g/kdoR1S9cWVXg78XGct21nd
         nIby2e5lCWVW3a//xo8KtSS1Wf40hk/f2O1doRva2y/dwHv0EUfUPlXvbFrjp6GPW7bu
         zerrbGmSWWB42rE16wH2lYAdpdfmUtIiop4XHcLqBWdbYV1Qc9CBF4wVDGKwTJaS/T63
         Hkn4tZe10CTkVQeHUMM12MeadKIVTxnptcp4UR8nEt5XKIjL5y2GuIO/qFP9jXlQTP/e
         tstg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy1FiPNHdYWze9HJbCjh/tZ6hgl3lbxHPr+UEl/cG2Qu9BrDoqw
	J5gV+a3cAQVTnw80XMfP8UQ=
X-Google-Smtp-Source: AGHT+IGwg7SWIU2aRiEK9ZCg+TEJN7scCtCXb/sQGBIDnQ705HJ/0bgnoYLlBXiDd1VGs4XDNDDQXA==
X-Received: by 2002:a05:600c:6a8d:b0:40d:3076:1f2f with SMTP id jl13-20020a05600c6a8d00b0040d30761f2fmr94329wmb.136.1703183749721;
        Thu, 21 Dec 2023 10:35:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c17:b0:40c:2324:253c with SMTP id
 j23-20020a05600c1c1700b0040c2324253cls679016wms.1.-pod-prod-04-eu; Thu, 21
 Dec 2023 10:35:48 -0800 (PST)
X-Received: by 2002:a5d:6703:0:b0:336:64ba:39e7 with SMTP id o3-20020a5d6703000000b0033664ba39e7mr123663wru.102.1703183748309;
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703183748; cv=none;
        d=google.com; s=arc-20160816;
        b=QSBkwfRQIknEKZ5D92P6Q51kcGE2dzgM+IlnfOtNJxQ2wM+0Jq++/9yll6MAH2oXZq
         pfsMmJIau/dhvyGAquszgtJ0MlXqZv1qUMUmBll3ZPuEUnnIJwcIWXgv6h8if0ZpANRs
         UTv0hZmv4iivxba1zw0ymhWKfRtE+Wu1bsq+UeQD4b81KYV/Q20QsnG2lBGvNZYfBrN8
         kTc3GCiggJfySE+u3/F5dwdRCNfVr0p/Go48uJzsfNNEgo5p4o/DSAfKBQ8e0I3qf/gZ
         8LCWKmjstT5IAammwRsiK/T+2AAs0Gl1QBYf/QDSYHfuuCeg8WFDdeB6SwHV/jfqzQLp
         Fegw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9xuoTXuQnTI+pN/bKZ3i8KybAohyAUoP+IGmtMicRak=;
        fh=E9W45FwZb6Id+g4Lg+hTR4TMK1PXvrXS/qWrVP2FBRY=;
        b=NRqOGDehkk3+GMieZOh5Uv2ULbCgL3oLP7QR2ErrWHrj1CCQ1zWMDF3lyeBbE+jLcD
         cqaU+NmsCdtNyhzw3d5Hq4zxYihKCrUMal6UE12QFfCR4XRCsi0hCV69oHtIyVW4KA90
         HOZtAskby9Ph7E+A5CHUDdTcLyFXpYkLh/U57tZ+daJaDvgWpLdVcTi1Zy1644T77uD1
         iZRhKJUbMEUqNBI7eMTGswzMrPcIZ9ZtklOSOmfNkVIiL8UkM/H6jnSUHa/Vpbtfe369
         m9CFAPigQN9zb6HGB3eEDtpcla0sSohO/kTJ+VvQqT/q4/jFIwHk0mL6fhGWAqNpFJQ8
         jJFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WarMWAg0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [91.218.175.179])
        by gmr-mx.google.com with ESMTPS id t15-20020adfe44f000000b003368d5d1fcbsi29812wrm.0.2023.12.21.10.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:35:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) client-ip=91.218.175.179;
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
Subject: [PATCH mm 2/4] kasan: reuse kasan_track in kasan_stack_ring_entry
Date: Thu, 21 Dec 2023 19:35:38 +0100
Message-Id: <20231221183540.168428-2-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-1-andrey.konovalov@linux.dev>
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WarMWAg0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179
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

Avoid duplicating fields of kasan_track in kasan_stack_ring_entry:
reuse the structure.

Fixes: 5d4c6ac94694 ("kasan: record and report more information")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h       |  7 +------
 mm/kasan/report_tags.c | 12 ++++++------
 mm/kasan/tags.c        | 12 ++++++------
 3 files changed, 13 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5e298e3ac909..9072ce4c1263 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -279,13 +279,8 @@ struct kasan_free_meta {
 struct kasan_stack_ring_entry {
 	void *ptr;
 	size_t size;
-	u32 pid;
-	depot_stack_handle_t stack;
+	struct kasan_track track;
 	bool is_free;
-#ifdef CONFIG_KASAN_EXTRA_INFO
-	u64 cpu:20;
-	u64 timestamp:44;
-#endif /* CONFIG_KASAN_EXTRA_INFO */
 };
 
 struct kasan_stack_ring {
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 979f284c2497..688b9d70b04a 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -31,8 +31,8 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
 static void kasan_complete_extra_report_info(struct kasan_track *track,
 					 struct kasan_stack_ring_entry *entry)
 {
-	track->cpu = entry->cpu;
-	track->timestamp = entry->timestamp;
+	track->cpu = entry->track.cpu;
+	track->timestamp = entry->track.timestamp;
 }
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 
@@ -80,8 +80,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (free_found)
 				break;
 
-			info->free_track.pid = entry->pid;
-			info->free_track.stack = entry->stack;
+			info->free_track.pid = entry->track.pid;
+			info->free_track.stack = entry->track.stack;
 #ifdef CONFIG_KASAN_EXTRA_INFO
 			kasan_complete_extra_report_info(&info->free_track, entry);
 #endif /* CONFIG_KASAN_EXTRA_INFO */
@@ -98,8 +98,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			if (alloc_found)
 				break;
 
-			info->alloc_track.pid = entry->pid;
-			info->alloc_track.stack = entry->stack;
+			info->alloc_track.pid = entry->track.pid;
+			info->alloc_track.stack = entry->track.stack;
 #ifdef CONFIG_KASAN_EXTRA_INFO
 			kasan_complete_extra_report_info(&info->alloc_track, entry);
 #endif /* CONFIG_KASAN_EXTRA_INFO */
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index c13b198b8302..c4d14dbf27c0 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -100,8 +100,8 @@ static void save_extra_info(struct kasan_stack_ring_entry *entry)
 	u32 cpu = raw_smp_processor_id();
 	u64 ts_nsec = local_clock();
 
-	entry->cpu = cpu;
-	entry->timestamp = ts_nsec >> 3;
+	entry->track.cpu = cpu;
+	entry->track.timestamp = ts_nsec >> 3;
 }
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 
@@ -134,15 +134,15 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
 		goto next; /* Busy slot. */
 
-	old_stack = entry->stack;
+	old_stack = entry->track.stack;
 
 	entry->size = cache->object_size;
-	entry->pid = current->pid;
-	entry->stack = stack;
-	entry->is_free = is_free;
+	entry->track.pid = current->pid;
+	entry->track.stack = stack;
 #ifdef CONFIG_KASAN_EXTRA_INFO
 	save_extra_info(entry);
 #endif /* CONFIG_KASAN_EXTRA_INFO */
+	entry->is_free = is_free;
 
 	entry->ptr = object;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221183540.168428-2-andrey.konovalov%40linux.dev.
