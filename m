Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PK7SEQMGQEJDICJDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B3015408A16
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:38 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id z6-20020a257e06000000b0059bad6decfbsf12394887ybc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532397; cv=pass;
        d=google.com; s=arc-20160816;
        b=O37IoPdMLhNbKl+Y2s9/qWiSet4/y1UF31dX/Wt3ngFTbGo3txW6UYOK80cPg58Gsr
         dbe0kABh2aoTEw1CldX4MVcAPc8J7gNeMZtaSCOwNUS583mcUk/2XLy5s9ylVkIPlAj9
         /BR61Zs5Kv9d067+giCAthou/NeYOuDr31kBMo4/jb36BtbSap7xZDjY5NA6fChbg3lm
         DIzE0Md1wNVSB17quEhcvDqMspL+KTo3HShjzZp4GY+ayl2qPX95ui0MalHNmlT9HeR5
         pMwvgdfJEDJ3GfrIEl3kTECWqzT4KYadX6Epo9c0mF3W2JLPEHv/EoaN9qbYFCnwVccC
         WK7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lNo8OtRoSwBMTsswrwQG6jvbg0NmrIQWFPkSw6PQZlM=;
        b=y5u+FT4R7hoFt3jZg+o08fgWh7s1OZ+s0GTJ8FWHxXY8c+lBKoPWVSKsOHC13bToiC
         Dpz9t7a0rndcPjNKbv/mNIfjOmXv8RaXoFQKwPukBD5PRkJwSsavdzU7kpymMTRkNsSG
         1gFd5scB0Pp3SEtTKsG4/7BzmbFmfEkhxAXKHQZfeOXW6btXHbiTscAkKQKn961DN1WT
         nBvwhMZl9exCtLDuJpf8yvCOInDejZfo3UJGwwURa7gJlbns4uLH2Oa2sy9u2MQl/FLU
         RePpIDoxmDmVnCYeKhaaNaouu5LrGrjWxy4Sum3mxXav7qFijk0bxgbvl18lnY+7Jue4
         JRHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lQJHcNeX;
       spf=pass (google.com: domain of 3bdu_yqukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bDU_YQUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lNo8OtRoSwBMTsswrwQG6jvbg0NmrIQWFPkSw6PQZlM=;
        b=KzZH/sx5PVHOOmdAW3qWcVVdO0xjQqT5RjXNW4VHEOxIarCkdtpqK/gk8uvHwQfyGG
         pSkZk331L2EyNDsQ3RuyRmGBjOUa0bStlRIf4wxyZYlRcT5jXb90EVC1yfdvEeeseosG
         jRChX3xM4dx7XA8SculPlWUCmy9wNjnX1NwGnBMqFo9sW/cfcTf6ZC0+Fy0LyOcTKNf6
         s+kJ0vy9AE6AAEStUxDV8Qph/XAeJwU19dvaxa9i2IvRRKzT1nlbg3LsM/cF+Y66d/Ox
         AYdpy76MeskmrJjB94wTdMZ/3GHGwbD1088z20XYKY2LxxoYhL5+ZkgEGxKGwdEhRCDh
         0qLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lNo8OtRoSwBMTsswrwQG6jvbg0NmrIQWFPkSw6PQZlM=;
        b=xE3zyeg4sxnS9Hlfx9rp4I8Tda4k991sdGpvhqXSYCv4m7VJ8XJDFdcAfv5YnI898i
         BdE/EAP4IPWRIwoAIyqfDhmxZisqtegaX7TKyQGLY6Z1yeQ7W37caqNZqyNB1d3jUFxM
         EVfZDf2z2ftgqP4Gan1/8nMpdZ7DVGeYBAdY27CTGkJHNWM/YF/z0nmQIM+84wbGxUM5
         4GKi08hOgP//eoylrwvlFHnseoRmx7ZvaPTJcIUsbl3Gvf54c3K0d9LUhxIDQVAIDy49
         DYPHrWGXYgCVsSA/ry/7z6O0qFr2wauia/3loI6ey5yfhAAkX8SB9i6dLYudzbY4tthf
         5OXQ==
X-Gm-Message-State: AOAM531bhydQw1ms95PIVhBhHlJwE/62iKS9Dw1wYwC0H18TNOLtBMAN
	DMUeccK8jkb4V98iicOxMJ4=
X-Google-Smtp-Source: ABdhPJyXHyR7qyPVWgVW6MPuvXruMhvlUnO7GyxLHl+xbrtcclxFZ1AXBKV48VhD4ji+Zg+uyngXIw==
X-Received: by 2002:a25:b7d0:: with SMTP id u16mr14419896ybj.342.1631532397686;
        Mon, 13 Sep 2021 04:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9904:: with SMTP id z4ls2960017ybn.5.gmail; Mon, 13 Sep
 2021 04:26:37 -0700 (PDT)
X-Received: by 2002:a25:7ec4:: with SMTP id z187mr14684428ybc.136.1631532397302;
        Mon, 13 Sep 2021 04:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532397; cv=none;
        d=google.com; s=arc-20160816;
        b=SCUKIic3FNEnPZFHKNkV3p0KnyPa0DBj+qQIkbUGRMasVqkWIQgAuhoEmd7Jm5V1sc
         lqIfmnb9Tg27ozcfk1foCLB+aU8TTo4ju9ibBOaGRsnDwOmMHu7tidT4VuN9ZuFDb9LO
         q3bgT7722vZU1u579Doj0dnEk9WlQWsgURGOmpm5roEbqfN5VPHEYxFd0ECwNSLPPhwM
         m1F/dUxvC4xwWe57TP6Vcw/PkjB7jIOKzdZyITSBKZikhi3o7xGd1XvLZJdP/LQVLZ7v
         zZVHogFVdV0oFy0xw2ZBrtVpC+w8VVsfTXi8Ayx/Qih6gYNmUmeTcPK/yhNnpBAAv3Lh
         bXhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ptSP4yyc5ltqSERpcwLdEP2vwQAqnRLUENIn1iThCXw=;
        b=c7FYJ+s6aqVZ3pXzx6GXQmfwRpmMHa0GAb0cr1xkYIjczXyyBJXyeOnRvrt0oreypN
         ZjEZdvx07YUXgM7ScFzNsvf+sZSK6/7o9WtrMkZomHisNJd1g6L4uwqnAny9kclxdl3X
         fzl6ZK7HnDBIArQAVEacQgqDMtVOqRNLrmd9aUrLjaOzjf6al5sSVTgdvPxMQmNAG2fO
         XA4LO95mU9tM217TVwrWby5R01Vr2mVkFKvjZnrIGZ1EdBQztuSiRKpLxIPrQSqtXLAU
         rk8mOfcMLZEy/HaDwKdZFse+o0qdUVxDHGDpBE8+WfgVWGmRHuR1Eh0g57kHx1dElc5Y
         whHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lQJHcNeX;
       spf=pass (google.com: domain of 3bdu_yqukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bDU_YQUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id w6si455217ybt.0.2021.09.13.04.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bdu_yqukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id h135-20020a379e8d000000b003f64b0f4865so40664188qke.12
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:37 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a05:6214:1142:: with SMTP id
 b2mr10077845qvt.0.1631532396945; Mon, 13 Sep 2021 04:26:36 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:07 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-5-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 4/6] kasan: common: provide can_alloc in kasan_save_stack()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lQJHcNeX;       spf=pass
 (google.com: domain of 3bdu_yqukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bDU_YQUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add another argument, can_alloc, to kasan_save_stack() which is passed
as-is to __stack_depot_save().

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 mm/kasan/common.c  | 6 +++---
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2baf121fb8c5..3e0999892c36 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,20 +30,20 @@
 #include "kasan.h"
 #include "../slab.h"
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags)
+depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
 
 	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
 	nr_entries = filter_irq_stacks(entries, nr_entries);
-	return stack_depot_save(entries, nr_entries, flags);
+	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
-	track->stack = kasan_save_stack(flags);
+	track->stack = kasan_save_stack(flags, true);
 }
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index c3f5ba7a294a..2a8e59e6326d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -345,7 +345,7 @@ void kasan_record_aux_stack(void *addr)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, true);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8bf568a80eb8..fa6b48d08513 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -251,7 +251,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 
 struct page *kasan_addr_to_page(const void *addr);
 
-depot_stack_handle_t kasan_save_stack(gfp_t flags);
+depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-5-elver%40google.com.
