Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMFZQKAAMGQE5ZZQ53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 906822F6B07
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:34:08 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id a9sf2824603edy.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:34:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610652848; cv=pass;
        d=google.com; s=arc-20160816;
        b=RcZacl4q4Og9usOmV6GUndq3OQ6PgnJ65JyQkvsey3MOhGs/8pakaoMQFl5jzDT2Nn
         tfoDyacn7sViTS7cR8OVexdJDpr5mtS8PsNGvfIg2M9GKDErsNdFdv0HOr5euuor8u5y
         ZsKFerwNWZziX904Qv9QOyaHQokZvUP2TunfXwg3jnklI6JnwLF2ILWMAb+25//wBTJ5
         xKVroOtjTrg19TN3I/oUyEjiWYybeqXkB8YoPHtW/b0pP842rguyrGIe7JgFgcguXdxN
         JLPQDvPMu2uXv1Z/yGYjqeF6KOd5qTcvTbJ8op1YUqbV/HrqaJ/8sNUdHlVlK+8F6Bks
         IxZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=arOQEnJ9kKNDrGwZxpaw3RqkRXbRfTG/MounJO9Il1k=;
        b=g3r+8OJ/cvWpBbvWrOoB6uCjWDcP5g7JHXtNPJUPx2Q5pKMWXKvxBBJHFTBrsayZ6O
         M2F4V9W/9pW9S8O4MNVVgFmyQYmUNMwkCUFLX2xeiJWN+5f6cCNgmMCvF3ZQ5/Bh68Cs
         Cjw5bLIPr6lDhb31mCZFJQSv1cpM93dl+D5qFbMxMG2mOHy08ZD+UIlWgIkDYnyHx7vb
         CB9jFKnOEdUAoYWPIIRXejjrKUaTz21taES0qZgOnY/bk3P7hzWcBzMWqZK8Q2LLmKWE
         BvQpUcd8LU9whtxHPTe7X79Q3NwilpX4uACKG5lTVsN+idpQhGdV0mIHNs6zlVaO6JvR
         rBSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vGVmZqHj;
       spf=pass (google.com: domain of 3rpwayaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rpwAYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=arOQEnJ9kKNDrGwZxpaw3RqkRXbRfTG/MounJO9Il1k=;
        b=Nj3s5hR3p4UO5Ke53wXwff7mn6vo/OD278LHlsA6aWJaaVTTbzWC9GFJjnaWUIPgCa
         3UAT35LipXKhAEpsyZ8kNKcBYyPxA+osHCWNQz1PvTLlnZM3/W6AM3NVklibrNNvJUAe
         0FNAehOTEI6dyBinBDRjfJjlf8S+ebruY37TK4eKEp/hI8Col3cRxfJk1jwiEx9rJWB/
         KojOecLlbbU1mG1a0o7v7QECXlgKfTDU6u+2IoZJ5NHuUEVMCARtVwWdqXl4ESXLKq1o
         4ABEeOS0hIkogg41/CI4WEBWlShmcxd4paliGcavv+wS/gPky43aeLo5UPlZBjE29L7v
         XzsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=arOQEnJ9kKNDrGwZxpaw3RqkRXbRfTG/MounJO9Il1k=;
        b=Yht+qCY97tQ02pXact9XETU9Xa2TORAHVil7C8E1hik15YqAnTohjbqhab8b4cZKFz
         27uuIt7LyifbXTtx2nOiFeq7e/pUOpvWeSRbOgRKoMs3tF2UFK6VxV9p2Jw9d0QoxCya
         zKAmhtH0M85EL6GS58cCgaKrDv+xfrNy/72BmLO/OoihOEJuqYDmovpxzJxIS34i8Ch3
         an9zyYDqoKg+1DzJr2pHTa/7O/IwAlwOahkg4KCjS6e6fQDi46lrF92FRKOFsUiD4sOh
         xErFd6yy23qRg12FnsgiDaXRT45qmPUNdU2M6gjOTknvO53KRecxoAUMl90bPmAN2qZu
         bnrw==
X-Gm-Message-State: AOAM531i92im3RQQeNzgar3JOkDtFWmd5RElOgBFcOYzZF0ZahqEBPiT
	5CXHTJcCvPU3mwNgMZoexLs=
X-Google-Smtp-Source: ABdhPJxIjPmG1evXfXw5N9snCzXWIxCxJIvedl7Z0qBsmRRKTgx5xZy6i6x6L4BmhIvv6IFz+rdz0g==
X-Received: by 2002:a17:906:3999:: with SMTP id h25mr6498225eje.146.1610652848339;
        Thu, 14 Jan 2021 11:34:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cec7:: with SMTP id si7ls613160ejb.2.gmail; Thu, 14
 Jan 2021 11:34:07 -0800 (PST)
X-Received: by 2002:a17:906:b56:: with SMTP id v22mr6389825ejg.145.1610652847469;
        Thu, 14 Jan 2021 11:34:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610652847; cv=none;
        d=google.com; s=arc-20160816;
        b=iJmEoyQE9rws5iL5kVwTgCDG0KCvEDPnbM2Pm/v5MJnoF1aggZUtUtq7wijQzAKGvy
         Dq4h3e6qIx7NJrVawdU6nt4r0EG5ckFxbT6dY0bx3J+JcBw4Odh1Epxz7e/Dvp+rc2Dn
         CQHZGFo94WAu22TDNXQLUAji1+Sa/7Nb5q1pUhGNHBBbWXk/w1U90U/xty+jmlB+LjAh
         GHgnNL56/rAFocHPJ4ck13ODJXzmHuRZIyscOLi+SiLZleigvYLQ3InI32jxgtVnUEF2
         ssnsgWp/z9+mwVc2D2agtYMUAHDjTbFOb62sP0u/6AP3kRXw8vDyqaUb8r1ljfQ58bv/
         20SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=K3THHtce7/ygl6Gpfs3Di2sEUO2VBikWbOhVCkSY9ac=;
        b=01ANtau0WPGavYQ/WYERt7izqjEBvb9LB5Gj2vRjAfZn/U55Mp9CLjL+frY+lB9U+R
         YEQi/koD9xOgit+N7UuBFn9cQL/pVwGT1dP1bo3UJ3barVo/y4cJFY0L6fUxzibBvdjK
         wAkZlhjqaFGWXegeTvNTBQ9XyQvmuwUJ5/5/j5/ndRFSWzTa9Gb2PVqPD6gx7UPpMU7p
         T30IcqUXWkBweNPlE1fbOIKgVi9EEvptn6IheBv6Ewb+DV06Fd/EaZlgRSGLACxnSacz
         Zuf+Ls08Hz+YYfE+155pvxtMD0jUaM5hbhuuRGfh4hSKQgy5QvxJLpABx7/7PpgAVNQ5
         k2VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vGVmZqHj;
       spf=pass (google.com: domain of 3rpwayaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rpwAYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id z13si209079ejb.1.2021.01.14.11.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:34:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rpwayaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id s22so2616428eju.21
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:34:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:578e:: with SMTP id
 k14mr6448146ejq.90.1610652846821; Thu, 14 Jan 2021 11:34:06 -0800 (PST)
Date: Thu, 14 Jan 2021 20:33:56 +0100
In-Reply-To: <cover.1610652791.git.andreyknvl@google.com>
Message-Id: <89cd4db80c3ee8c1975eb9171e99fcbc894eb1dd.1610652791.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652791.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 1/2] kasan, mm: fix conflicts with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vlastimil Babka <vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vGVmZqHj;       spf=pass
 (google.com: domain of 3rpwayaokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rpwAYAoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

A few places where SLUB accesses object's data or metadata were missed in
a previous patch. This leads to false positives with hardware tag-based
KASAN when bulk allocations are used with init_on_alloc/free.

Fix the false-positives by resetting pointer tags during these accesses.

(The kasan_reset_tag call is removed from slab_alloc_node, as it's added
 into maybe_wipe_obj_freeptr.)

Link: https://linux-review.googlesource.com/id/I50dd32838a666e173fe06c3c5c766f2c36aae901
Fixes: aa1ef4d7b3f67 ("kasan, mm: reset tags when accessing metadata")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/slub.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index dc5b42e700b8..75fb097d990d 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2791,7 +2791,8 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
 						   void *obj)
 {
 	if (unlikely(slab_want_init_on_free(s)) && obj)
-		memset((void *)((char *)obj + s->offset), 0, sizeof(void *));
+		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
+			0, sizeof(void *));
 }
 
 /*
@@ -2883,7 +2884,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
+	maybe_wipe_obj_freeptr(s, object);
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
 		memset(kasan_reset_tag(object), 0, s->object_size);
@@ -3329,7 +3330,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 		int j;
 
 		for (j = 0; j < i; j++)
-			memset(p[j], 0, s->object_size);
+			memset(kasan_reset_tag(p[j]), 0, s->object_size);
 	}
 
 	/* memcg and kmem_cache debug support */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89cd4db80c3ee8c1975eb9171e99fcbc894eb1dd.1610652791.git.andreyknvl%40google.com.
