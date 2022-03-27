Return-Path: <kasan-dev+bncBDKPDS4R5ECRBDHT76IQMGQENLFRD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CDA54E8618
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:43:42 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id o6-20020a17090a9f8600b001c640fa1499sf6066250pjp.3
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Mar 2022 22:43:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648359820; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ss5gCQScpAwJUX0ko9dnXkcoOi4rkgrK71K0jj6Gr3D3AERS/9eAbLTkJF8b7x3Bd/
         8Z4iZIpk2LbvpOcSOffR4ds/VbXuOtbf+fxfxJ2Fx3l/ZTGZwOoWu1Z77cPIgirMLkX2
         qjdl/WYxVGJ/ZRcopE5wv093KlxXi+kfe4YfYBjrTOIOY9E8EqrDYFtnK62YnjY+7VHr
         NcVBLSeFA/qPISMpK6DqHD4+3LYtMVbvMkWCQ1QDS1qN8hpNIlrA00DkTr9NvWjYt5dG
         wQktx3rFjyp85tUI6XftR4r9CDHgt0ChdhIJzeDf8+NqnCnTgDPVZlLO3CWlTVKFx/pK
         yUCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fFW/fKb2Q4zhzWNygEboypqkNG7nysJj0stWq4vkvxs=;
        b=tWhyHkaB/ZW8BFU12OJf2hSh/ap4SHKFW/QjwB0hptUfTjERtP9afadh82V+DzkfXl
         6IB89fJlgvmbR/+gPR9rk/jH5XY8gPfAQrA8JEUsNvx4U4BJtwGevYe0ccjPfRc3Xb49
         3xU7ODY3OLLmH/P4pW3mr8j4j83194n+q0uodJ1mTKkkd+X7XhkJe8i+y6/Qw0KeZzkL
         +MxCRbSVVreVN7nBiiYpbsOU4S9EbQ75HVL9KV7A3sk2Dz0rRF2Jde0hfvDj1tD1So/u
         STX2u7weOpgJtzhDEzoKCNUKl3ji29FOdRxdqnkUOoRMsqyjUoBgGTx76LyP4Kxd+Vsr
         iLEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=icDZzCAP;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFW/fKb2Q4zhzWNygEboypqkNG7nysJj0stWq4vkvxs=;
        b=nO7keGAxUXx6HmCz4eDTFGQlQwFF+afmwRUSCexX4RdxwDPF08T1qBSdYE66C44UI3
         neLkABGOEW1bcibfIbdFcovnyJn/EEwEUFYM2bt3wTX/L3hMkw86MriyVaeHD5yjiNLz
         dbw1SvKsiFAKlw7b7PUobuIcKGiDNTyeG3uZah+7Bk7YTzEztX2ouZW9P9VZ0uuzFFr6
         hDmdHC9zpSwU8vxR9VhFfnuEP6OF6sVOtdmI1U1r12eH4J2ZD5z2uRIJcOM4/tvhpkGv
         WzXAuHIp9AuyRwR5LYCgFt5Il/6DWTaVHrgNLiO3aL77n2eJa7TS89sfmqgndHn+Ewqg
         H8kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFW/fKb2Q4zhzWNygEboypqkNG7nysJj0stWq4vkvxs=;
        b=b7KsNfMCicN8a3JyfZ8wN/xvE5zoYbLh8acOSJPFkPhaOUoq8MVmZSziYGf3fn3yZs
         kWn9m6PX6Pm5A9BTUihm58Qz2gHoP6Xa362zR1DfKK716wlJKZS6LBQSqblPTAkACyhO
         mv6TEfnf41vlsWnCaVzU/HOiV6p/7DOjtG9drWms19aauFZggUMfUGPHjyx6ubNGIfFe
         sQp+J83BVRAeVY/3NmUMp0scRPYqnaK87MFjh8i0xCl8aNC6DgBZYT0RDKZzDAfsunrA
         u+pZk4uWCZOpisJYsqR3Wqq3GuNcxnhhx0mRloHvE19Ia2UQArL419TMv9L5klHa3Fcx
         8oew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iozOfZcdrly18WSi9V7SDvwq4ej8Cb/i7zbJNmVpPkwa+vGNq
	pSJQEgyOiEpWURuCjkvl35o=
X-Google-Smtp-Source: ABdhPJzeURqYm9A5iiOJmuhuOU4fz8C+TNixpGE/DUW5+In78nOlZoHb3NpKv/D2ZRDToPef2+l+UA==
X-Received: by 2002:a17:903:11d1:b0:151:9fb2:9858 with SMTP id q17-20020a17090311d100b001519fb29858mr19918010plh.136.1648359820830;
        Sat, 26 Mar 2022 22:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ced1:b0:154:624c:2ff4 with SMTP id
 d17-20020a170902ced100b00154624c2ff4ls7553801plg.8.gmail; Sat, 26 Mar 2022
 22:43:40 -0700 (PDT)
X-Received: by 2002:a17:90b:4d0e:b0:1c6:3ea9:7b5f with SMTP id mw14-20020a17090b4d0e00b001c63ea97b5fmr34397051pjb.166.1648359820285;
        Sat, 26 Mar 2022 22:43:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648359820; cv=none;
        d=google.com; s=arc-20160816;
        b=upFfCkl6lCbdG1KwwmK7wSFuUqrc257p6d+DNe0N5HKmDILGBgJ1cbPCoo3kES4QCZ
         6GEObPQbo3QjOfswjt0r4AEMut6t+QKLXyDmzMGOvzTHECF84RRvS5EbMIC4x9vJlwn4
         b1wDTAjzReZPUekpiRw8l6tO9ZxooZUyAtGidb+x7/JwXKtGjs1VEmDKxkLwDceMwySJ
         WVxXZW1PmvGeMLdhNqSUVl3kh2GdO5lpIYck/W75tn7/wzvMAd+po0RNJqy+tN9gIG3S
         ca18N/dmKxPtX52js1jPgWKbQcdMbhPLbqBjW6V10buWh/g++yV998swTttychPk9zP3
         6rIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kp+n7MjmnLTJ4vOAA537LLcCjh6KRC0etIIuCa/wcqQ=;
        b=V8ATrfD9PZtZPaJF0HQdEh+/B62laOmpGqFJAP2MsNAbk8aRRy2TQ3rQWhN/R3oNIi
         aWgjgDJVoWRdVjW6luXuULwXyB/ZAQupgzTULBUd2Ubv8gCvarD6hM6feET9sbSGswgc
         E6u3SL+irRTb/qTn97K6OafMeQEFl3FoePRp9UPdfmXVqbUzv+eKOWHfclu4iQlQmu/C
         GJada5t/zaU5U1HJXTuSVZOz6t4NwKl3YIEN6azigNCwi5vLL0HGK4H1pqzllk63is8N
         K3ynE6h0BYqh53jQQGGYT05CCmadGeiMWn06Lb4GKgaCjBUfSLPCoeGb0X7spDzvRAV9
         U/tQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=icDZzCAP;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id p23-20020a17090a931700b001c75ad33c27si783369pjo.3.2022.03.26.22.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Mar 2022 22:43:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-2e5757b57caso119214447b3.4
        for <kasan-dev@googlegroups.com>; Sat, 26 Mar 2022 22:43:40 -0700 (PDT)
X-Received: by 2002:a81:5dd6:0:b0:2d6:3041:12e0 with SMTP id
 r205-20020a815dd6000000b002d6304112e0mr19479093ywb.331.1648359819570; Sat, 26
 Mar 2022 22:43:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com> <20220327051853.57647-2-songmuchun@bytedance.com>
In-Reply-To: <20220327051853.57647-2-songmuchun@bytedance.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Sun, 27 Mar 2022 13:43:03 +0800
Message-ID: <CAMZfGtVWa0uOKqSeuau9pCNXSQHPz5=S+yYupCUYRqhqyhod+A@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
To: Linus Torvalds <torvalds@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>
Cc: kasan-dev@googlegroups.com, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=icDZzCAP;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Sun, Mar 27, 2022 at 1:19 PM Muchun Song <songmuchun@bytedance.com> wrote:
>
> If the kfence object is allocated to be used for objects vector, then
> this slot of the pool eventually being occupied permanently since
> the vector is never freed.  The solutions could be 1) freeing vector
> when the kfence object is freed or 2) allocating all vectors statically.
> Since the memory consumption of object vectors is low, it is better to
> chose 2) to fix the issue and it is also can reduce overhead of vectors
> allocating in the future.
>
> Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Since it cannot be compiled successfully when !CONFIG_MEMCG
(The following patch should be applied), I'll update this in the next
version if anyone agrees with this change.

Thanks.

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 9976b3f0d097..b5c4b62b5d2c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -583,7 +583,9 @@ static bool __init kfence_init_pool(void)
                struct kfence_metadata *meta = &kfence_metadata[i];

                /* Initialize metadata. */
+#ifdef CONFIG_MEMCG
                slab->memcg_data = (unsigned long)&meta->objcg |
MEMCG_DATA_OBJCGS;
+#endif
                INIT_LIST_HEAD(&meta->list);
                raw_spin_lock_init(&meta->lock);
                meta->state = KFENCE_OBJECT_UNUSED;
@@ -940,7 +942,9 @@ void __kfence_free(void *addr)
 {
        struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

+#ifdef CONFIG_MEMCG
        KFENCE_WARN_ON(meta->objcg);
+#endif
        /*
         * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
         * the object, as the object page may be recycled for other-typed
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 6f0e1aece3f8..9a6c4b1b12a8 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -89,7 +89,9 @@ struct kfence_metadata {
        struct kfence_track free_track;
        /* For updating alloc_covered on frees. */
        u32 alloc_stack_hash;
+#ifdef CONFIG_MEMCG
        struct obj_cgroup *objcg;
+#endif
 };

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtVWa0uOKqSeuau9pCNXSQHPz5%3DS%2ByYupCUYRqhqyhod%2BA%40mail.gmail.com.
