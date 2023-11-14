Return-Path: <kasan-dev+bncBC7OBJGL2MHBB57PZWVAMGQEO3ZMPKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 072B77EB0F9
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 14:36:57 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1e9adea7952sf5079277fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:36:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699969015; cv=pass;
        d=google.com; s=arc-20160816;
        b=PB2YLYXgTmQbL2nj7tx0M37RwyhQAPMBp7IEZjLPW/7E1jz/1i+Wszwq2veUboTWeG
         KjuGqWgqCr8ph+YB2YsTlAhUlw2ShkZEINrBbC5z6g2dXYM03EdupCJDemuAmkBdODSg
         59ZeW9Iy2xXHCddNk3ift5sY85D1W9EYGXZHa3EgaqGF2yrr/YvTbjrOf0VL68a6skX5
         ED5jiSuu6fZVMLeuU1D0s9XHrUpS3t5DfFaq/3gEhd4CUA+DsjONkun7NG3lc1CkaNmf
         iKOtEMwubh6nNg/KDQmE4OCZr1ScsWw6vUiFtIINzycYwVOM5/fWpYlivTi++LB9kMBU
         DSLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1XUUKUGJRgIM3XsQaXc25p7HTLAoJUV9Suikpa2v1j8=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=yYSY/iFDlhCN9aUnfwext0gwdkgHDxCkDjidBAL8+SXPWOItir1gNbyO00fKivoQQu
         cIaOyRkmnA0Q+Tzjv7Y28hEKOfUw1CsxcF2mnYmzghnMrs5gphe9+CKUo2jllm1VrP1H
         kg5r2y5kgIZMnsfDD1h4VQ8KDkfKNfC6AzNaR74P1+4EYsxy75LX2rVj52zdhFGPzjGf
         rLK2c/YWmgfVvTnDlEib4Z3SPtIg5Sa71NAZXLEZ9sTNE217IEebH+Mz3Eo7Kxdxx8ti
         oR5RW5bSjIvFqG7cai51GO3ottfR5HRWqqPrEp2zNhSS+nbe2YeiQhW2eO9Ohd8b7eWC
         CF/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yf3XlcpO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699969015; x=1700573815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1XUUKUGJRgIM3XsQaXc25p7HTLAoJUV9Suikpa2v1j8=;
        b=qiJxzNgCxmYvEINud+nK3dTl+KLcufUhDFNA0b9jcwK6k67girsrtgkPcfd4pbIlaZ
         2JSUBAC4QjClyJZ56L5YjzAjLWBDKilLqk4+bZByiJNpMnwdQpDfZFry2tkmO97Rms40
         BPKfHqsbu9sN/Guvhwt7homtmIueJ6dgXN2BhI40sslMdgN5V/tlXzdKi9X1qoj732nE
         uP/20i3n3a1ey/6BjgmxJj4zpUWDRzncCOIydEvfZ0FHbOkjL3RsGAkTDQWFZqmIptWq
         NPA6Ay0Bqm62/HlBLcNDbB7Ur+9b38PVxA8iWriaas9Khlx6GReB4X7PEvnwye1KpipK
         Iuzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699969015; x=1700573815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1XUUKUGJRgIM3XsQaXc25p7HTLAoJUV9Suikpa2v1j8=;
        b=JBlAvaPZoKuy2xGYHVOkLtzJDgCM2E+cMwNEpFnALAixxNBP3flkG6MZmZ7awBwqe+
         XJNb9dU1d7hMR0sjwCBbo3HKs22AzepyuM5Tg4G4hxKVK3hQ9d96kVwnV7Y7665z9TX3
         6xU5HBgIIrDsDkE5sd/URl8Yp1ns0xaepLQO/gMcW0O557KQATOeLucp1aBwfoSFFwxz
         JH6Uetofs45tquIPFRiupRuSEpKub8NQwwF1YHiOLg1KpxFCQTW3CwX12pi5twNmYpTp
         vteyRKpdai/Bona1bvX36UhCRjapUOptE1DO8eOeULQiPUb/56u71QUaguEiwpxqGfhZ
         ejmw==
X-Gm-Message-State: AOJu0YxxDHOry44F93WVa+sN2XtzEwPt7I0ApSrx8jvJMSjIr//7ZicJ
	kKqKDTk/VHqnsShhHpFJVok=
X-Google-Smtp-Source: AGHT+IEr4Lm8pudbIwYWbZhA7E5szot1MEnmCy9SNMEWdNSc/TUQ3d1mGyEGuIHOJX3O3j60lbqS9A==
X-Received: by 2002:a05:6870:6707:b0:1e9:f4e4:2882 with SMTP id gb7-20020a056870670700b001e9f4e42882mr13537898oab.38.1699969015681;
        Tue, 14 Nov 2023 05:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4414:b0:1ea:d76a:4f02 with SMTP id
 u20-20020a056870441400b001ead76a4f02ls602103oah.1.-pod-prod-03-us; Tue, 14
 Nov 2023 05:36:54 -0800 (PST)
X-Received: by 2002:a05:6870:9120:b0:1ea:131f:5fb7 with SMTP id o32-20020a056870912000b001ea131f5fb7mr12879020oae.26.1699969014694;
        Tue, 14 Nov 2023 05:36:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699969014; cv=none;
        d=google.com; s=arc-20160816;
        b=W9rVn8AQlvbnIihkpy7MircJzDfaQY2pPbe6+5qPbqVItZpBkZEwrZxwR36nAB5pjV
         oPNFBPpzFKTwkTNu3up99Qh180ddhPHvAl2XLG8qZTPNB+NA9A9DZdYqOBJNjunbZQYD
         BYE7vDK7Zl0wBB4UfLWc2CibppBgxeMzrNxz31OVIMkUmCWYshYTDCOo4SlTEulc14GO
         lNuNsCao8hq6Xg3C/ZZMgOWRIBkQWnNKWi7H3X1D/zytOivrCEXbExJa0xzXehbSzrUk
         CatVAqifoLOEtGAmhczh5OmdHWHp1HsNBibqiTT0ual0bEiFFI8x5WfD4neoVFYNQmAZ
         kKQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ylLF0ezxv0p5B3lhnDvW84ZadVID6r9w9mm9HftD9ww=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=0biHWpdpkpqM5l7yZYOwd7be96XjCfTTZ6OOiM61rth59LhDwcv96rmn9Vbif1shv4
         UTLoR9AoiiRvfNqOxsKWJZ2ItN0/gyisxXg+DDGHKjMTaH96WCDOY2f6QWOgFqR28TNr
         XYgA9e3HWB7CYqCx0Ha3KErT/ItSWU7+2Mdv27DTzwmenLj3mXu1TTTwX0PooWac9tbB
         n3g1XKJ9CSD8YJPwkIE/OvIELJzhPPvoIe4RoiC8XUQycDl3eQUnYv1i5eQQLjgiJ9RR
         51oG9WtKjZXzvmjeNhlpIqEpeoXHdvxbVCDxm9caZ44mDIoX7OrdKddik4GWCAURFh2Q
         bobQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yf3XlcpO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2f.google.com (mail-vk1-xa2f.google.com. [2607:f8b0:4864:20::a2f])
        by gmr-mx.google.com with ESMTPS id x18-20020a056870a79200b001dcf3f50667si577119oao.0.2023.11.14.05.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Nov 2023 05:36:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2f as permitted sender) client-ip=2607:f8b0:4864:20::a2f;
Received: by mail-vk1-xa2f.google.com with SMTP id 71dfb90a1353d-49dc95be8c3so2121046e0c.0
        for <kasan-dev@googlegroups.com>; Tue, 14 Nov 2023 05:36:54 -0800 (PST)
X-Received: by 2002:a1f:9cd6:0:b0:4ab:cdf0:b2c7 with SMTP id
 f205-20020a1f9cd6000000b004abcdf0b2c7mr5133093vke.5.1699969013928; Tue, 14
 Nov 2023 05:36:53 -0800 (PST)
MIME-Version: 1.0
References: <20231103212724.134597-1-andrey.konovalov@linux.dev>
In-Reply-To: <20231103212724.134597-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 14:36:15 +0100
Message-ID: <CANpmjNMJJyiaEWKouY4jho-Qg1+i7eYSxdjn_vEPCbQ0AR9Sew@mail.gmail.com>
Subject: Re: [PATCH RFC] kasan: use stack_depot_put for Generic mode
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yf3XlcpO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 3 Nov 2023 at 22:27, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Evict alloc/free stack traces from the stack depot for Generic KASAN
> once they are evicted from the quaratine.
>
> For auxiliary stack traces, evict the oldest stack trace once a new one
> is saved (KASAN only keeps references to the last two).
>
> Also evict all save stack traces on krealloc.
>
> To avoid double-evicting and mis-evicting stack traces (in case KASAN's
> metadata was corrupted), reset KASAN's per-object metadata that stores
> stack depot handles when the object is initialized and when it's evicted
> from the quarantine.
>
> Note that stack_depot_put is no-op of the handle is 0.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Maybe mention the space and performance difference from your
experiments. As-is, it's a bit cryptic what the benefit is. I assume
this patch goes along with the other series.

> ---
>
> This goes on top of the "stackdepot: allow evicting stack traces" series.
> I'll mail the patches all together after the merge window.
> ---
>  mm/kasan/common.c     |  3 ++-
>  mm/kasan/generic.c    | 22 ++++++++++++++++++----
>  mm/kasan/quarantine.c | 26 ++++++++++++++++++++------
>  3 files changed, 40 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 825a0240ec02..b5d8bd26fced 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -50,7 +50,8 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
> -       track->stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
> +       track->stack = kasan_save_stack(flags,
> +                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
>  }
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 5d168c9afb32..50cc519e23f4 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -449,10 +449,14 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>  {
>         struct kasan_alloc_meta *alloc_meta;
> +       struct kasan_free_meta *free_meta;
>
>         alloc_meta = kasan_get_alloc_meta(cache, object);
>         if (alloc_meta)
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       free_meta = kasan_get_free_meta(cache, object);
> +       if (free_meta)
> +               __memset(free_meta, 0, sizeof(*free_meta));
>  }
>
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
> @@ -489,18 +493,20 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         if (!alloc_meta)
>                 return;
>
> +       stack_depot_put(alloc_meta->aux_stack[1]);
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
>         alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
>  }
>
>  void kasan_record_aux_stack(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
> +       return __kasan_record_aux_stack(addr,
> +                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
>  }
>
>  void kasan_record_aux_stack_noalloc(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, 0);
> +       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_GET);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> @@ -508,8 +514,16 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>         struct kasan_alloc_meta *alloc_meta;
>
>         alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> -               kasan_set_track(&alloc_meta->alloc_track, flags);
> +       if (!alloc_meta)
> +               return;
> +
> +       /* Evict previous stack traces (might exist for krealloc). */
> +       stack_depot_put(alloc_meta->alloc_track.stack);
> +       stack_depot_put(alloc_meta->aux_stack[0]);
> +       stack_depot_put(alloc_meta->aux_stack[1]);
> +       __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +
> +       kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>
>  void kasan_save_free_info(struct kmem_cache *cache, void *object)
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 152dca73f398..37fb0e3f5876 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -141,11 +141,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
>  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  {
>         void *object = qlink_to_object(qlink, cache);
> -       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> +       struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
> +       struct kasan_free_meta *free_meta = kasan_get_free_meta(cache, object);
>         unsigned long flags;
>
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_save(flags);
> +       if (alloc_meta) {
> +               stack_depot_put(alloc_meta->alloc_track.stack);
> +               stack_depot_put(alloc_meta->aux_stack[0]);
> +               stack_depot_put(alloc_meta->aux_stack[1]);
> +               __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +       }
> +
> +       if (free_meta &&
> +           *(u8 *)kasan_mem_to_shadow(object) == KASAN_SLAB_FREETRACK) {
> +               stack_depot_put(free_meta->free_track.stack);
> +               free_meta->free_track.stack = 0;
> +       }
>
>         /*
>          * If init_on_free is enabled and KASAN's free metadata is stored in
> @@ -155,14 +166,17 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>          */
>         if (slab_want_init_on_free(cache) &&
>             cache->kasan_info.free_meta_offset == 0)
> -               memzero_explicit(meta, sizeof(*meta));
> +               memzero_explicit(free_meta, sizeof(*free_meta));
>
>         /*
> -        * As the object now gets freed from the quarantine, assume that its
> -        * free track is no longer valid.
> +        * As the object now gets freed from the quarantine,
> +        * take note that its free track is no longer exists.
>          */
>         *(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
>
> +       if (IS_ENABLED(CONFIG_SLAB))
> +               local_irq_save(flags);
> +
>         ___cache_free(cache, object, _THIS_IP_);
>
>         if (IS_ENABLED(CONFIG_SLAB))
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMJJyiaEWKouY4jho-Qg1%2Bi7eYSxdjn_vEPCbQ0AR9Sew%40mail.gmail.com.
