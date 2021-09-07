Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXH3WEQMGQEBGTEIXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E04E5402A82
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:07 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id n202-20020a25d6d3000000b005991fd2f912sf11789077ybg.20
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024046; cv=pass;
        d=google.com; s=arc-20160816;
        b=DglKJBiNqjOdQAKQV2uu0x/eDTe81htpwDvrhESuCQ1VuRke83UXgFcA3bove11IFy
         LQwlfD7WJWDcDS59ypEUxflLzjr1Nkr6N7a4+o8tGu5JjnXEtPOBA3r9zTnDqh8FUyEX
         vqg6JjeB5R648CdC+ueXEQKDkMMjR6F4dc4r/eNeUerD34gKXngrF7cpz0iVlIkVPSiP
         sdMYKxaJWEXyfdcv6DQ+8e8dlBv1nuPLQI5+d7X52YFDNhZ7Z7hSO48ibGzOJmGD4uTv
         q3VWaZJO2pJz9TEml7wRvM+JIsAt0kWWqQIC5qysBPc16y0BGlFtwloXmagAXcerXgPi
         GnQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=avjtbvevxep1JgZfpggPIDvLUMjj2ZnKEHuER4Xotno=;
        b=lQW6fMY6o8FsUt1A9NcbW8QwNyG1sjsj5NcAfGOIITFFH3ERBcQqyiqB843QwqMZom
         lExmcZ7onWcHaD6HvwmXcf21tnLf23TC1yrxrLXKbO3HOrG3tuP22Y/lfc1zAImJ1VNN
         RmQzZXhWaawyM4nfg04GaWoHxqXz7AB9yixA20FadJvr6Thbmn4Ly31l2hvc4gfuqDx1
         Yu5nO/6kIVZxJg6OsMrAP+4TO6AxkkI8Ql4LFlkHBMIpDUa67I4SxCOoWqT25BX6JLbO
         DU4U5+1cA//9sa2ei733feyQH3Mo1kkS4xEIbI6rbZgfPTs3i1vY7fihqM237pccKoiB
         EsQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRISar8+;
       spf=pass (google.com: domain of 3rxm3yqukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rXM3YQUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=avjtbvevxep1JgZfpggPIDvLUMjj2ZnKEHuER4Xotno=;
        b=KdN/GI+nomOcct+JGeQsKDtz1IGdqA7W5ltBH/9J2zpjodjzVwlyL8JfWKI9Bimxl/
         acqiEdtRLh5j1RghQpZHxlxqCMUvpM1jzL4Q5EwfEFBkwBgL6iC0Xy8n2AG1JHGwMR4u
         XsQr2vbaVIXQtZxm02zAJZljeSkL1xu7Q/AivlMJEJgJJFGm9U/QK860veM0cJbamUnd
         48uivVAEvG4Cz1T/kR3LeBzpE95f0OrdPWVe8jaX3Z+0oThlTV71ujrCZ/q7qE1VWi//
         RPUAyCf4Ku/J9d64IDJyk+8c906DvesJEtCW++wMpSYjeFH0B3M/c0ztIMbd7VoP131m
         MA3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=avjtbvevxep1JgZfpggPIDvLUMjj2ZnKEHuER4Xotno=;
        b=kbwRXYMpGFohTsxeMOxSqB5jIuquMmGWAKw0mVYJ6NaD4bl7RkGXNkJ7dqUq41eIEL
         lXHNdmsIlYFx60X6dWRwG1Lm5K8onT+EvJsUoK/o4G/0yd3W5+5Oa0GgB13lZ67KjeFg
         XMVviIH56MT0irHi/mK9MUuDIMIdAcCcilUC4plLEEM4AlO3RiuMSBBJiBTPmvpiq8xd
         ejGTG6OUSmTQdntnfUZQvZSabidkzuQD6LV8zAHNp0r8rIP3h6m7GrhjdIUIrxwWFcYe
         Q4sW+W6JVV7H2EsD8miorY3wOhVU5ThPh7zsulk7ecNdZPdQqIajQ3gbFF/R++vIX/Mi
         tYSg==
X-Gm-Message-State: AOAM532JoMDhkwamJraRCZLV6MZ3U15rMly8KbPxeaXbi8YmowNwkCyf
	ySzQR259wbBNxCz/Rp0IMAU=
X-Google-Smtp-Source: ABdhPJzgAstsmiiMhiBs/lTxwdeZ7KQozyOl+un7oOGCsXlJLpckEebIM0yj56dGWA8plMAJ3K5+rA==
X-Received: by 2002:a25:f407:: with SMTP id q7mr23911404ybd.195.1631024046671;
        Tue, 07 Sep 2021 07:14:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b981:: with SMTP id r1ls124534ybg.8.gmail; Tue, 07 Sep
 2021 07:14:06 -0700 (PDT)
X-Received: by 2002:a25:6cc1:: with SMTP id h184mr22938081ybc.240.1631024046213;
        Tue, 07 Sep 2021 07:14:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024046; cv=none;
        d=google.com; s=arc-20160816;
        b=z0juLQpxnoLU9eufjcLZWVf6T9zq6+dWNWsYBg6ex+aCCVdJuj4tah23PVqbGpS518
         cRFtzVAGBYyuKCReyWqLaIJg+T2uI4H9h8eIobwGi9uOgJNdLmC+vAfue4PEYAsn2Knr
         Vu3GjMroJ4aDBVsZIzhkaANM3Dm8fqL8n77C2M86Psb9/CqDxR+s/IuoEoXq/aLfq+I/
         l0xc/31V1iSba20kiOslZSMdo3yK0L07VDhxUf70AvtNprgaUfF8us5LwRINzr9RHx/P
         H8Ccr4UW3O/UUpEovqqRmblcZjNvz9HyDLJqjZ0iSCCf/ml/l4cbGRxIiwQI9yALTVf3
         0tvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=N/5YJhYADcqy8sBs5vH/zCaS3u8GV2W+ZzJdQ0X+ILI=;
        b=1HJf7aOnEGlU/hjmmdI7Qoq6uLHiPqHoinQYIcXmAaksGN/Ne4TNFrYNzG6gBpf+EG
         v50pSz1crAeUEvOnwp+orS8WvKAd6E7mlD87KQI3VyaUDj5fNz6hrAu88EEOsKUKfDwg
         bbR97Tq96lkmCvbq+AEcNrsNFkuwssD300pdyHmxoeQ3sAblKiPQFU2ZogPQuFFiQ1xy
         ViGKwTsUCFDBRtayaf80Y8JGiE+ExhghqxVNvLbmHeTQ8LRoXODqoUc4V4485l4wgxiQ
         Y7Ir02b3NH3n68fHPjNAFY9KBlTACuLEvTNEiJaVu14ViqE1DUK39PVYgIIGVaOp1P+C
         wDHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRISar8+;
       spf=pass (google.com: domain of 3rxm3yqukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rXM3YQUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id x7si504477ybf.3.2021.09.07.07.14.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rxm3yqukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id c22-20020ac80096000000b0029f6809300eso12820785qtg.6
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a0c:be85:: with SMTP id n5mr17013941qvi.59.1631024045883;
 Tue, 07 Sep 2021 07:14:05 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:03 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-3-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 2/6] lib/stackdepot: remove unused function argument
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LRISar8+;       spf=pass
 (google.com: domain of 3rxm3yqukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rXM3YQUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

alloc_flags in depot_alloc_stack() is no longer used; remove it.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/stackdepot.c | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0a2e417f83cb..c80a9f734253 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -102,8 +102,8 @@ static bool init_stack_slab(void **prealloc)
 }
 
 /* Allocation of a new stack in raw storage */
-static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
-		u32 hash, void **prealloc, gfp_t alloc_flags)
+static struct stack_record *
+depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 {
 	struct stack_record *stack;
 	size_t required_size = struct_size(stack, entries, size);
@@ -309,9 +309,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (!found) {
-		struct stack_record *new =
-			depot_alloc_stack(entries, nr_entries,
-					  hash, &prealloc, alloc_flags);
+		struct stack_record *new = depot_alloc_stack(entries, nr_entries, hash, &prealloc);
+
 		if (new) {
 			new->next = *bucket;
 			/*
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-3-elver%40google.com.
