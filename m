Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7XQWHAMGQEPODJ5UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 508F747BA61
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 08:00:56 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id a15-20020a92d58f000000b002b452d7b5ffsf533698iln.23
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640070055; cv=pass;
        d=google.com; s=arc-20160816;
        b=pCcLGyhaBqlHNGb98bpVvgLoTAqRryoW+BSDFtew9ZU3crpNLfX3z+hllR//+usgDl
         nuggXgGLr8TLmb/8tXo2r1wJ8bFD+wq3cJpXA/plEzEBA7E+8PxFZGS6QfP9+rTpg87m
         2/AjGbDMrfVry2nioaQ06GOgbcyyRpzcI0JPfa+iTOhbraBS8MaV42dgxahmKz8vGi52
         cUI/fxAT+Sg7iMTC3VsqB29Xzwz8J/DaLfa60iqEfmi1gypCX50ffMTp6WTPfV+6aOgn
         BZLIci9iDrvU3Ub8UUBIkIIrukJ/gVYQ3UKpQtF9sEmK3Cru0RLivNzDAeXFCx2VnZyU
         XFOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c7vX+VZp1Q5xKe5uTUgdHzrsGopK/48r2KbLUBsdD4g=;
        b=zmkikd3Q4nQgIEOPCa63KdctblGghlSZEh3rBdO3VydtiWv0ghuzg+6zspZLkcc2J/
         8E+60DVMLp5NeALdHa6SJJwAq0MrMh1OHgbswc9Da2ThEnjkQnTSYLj97IwE9TpM2X8y
         Nrl/mW3UH+nOnM+cuP9/m2bCeQch4cAhXvjU3rjKgGxKOof3wLevrMf333GpypNAMR+I
         UNhapJQ5nwCPnc92xw82bvvxXCXMR9fmtPJDZvddtglDn0dfqvxgkpAIf70duIzreilq
         I6KK9iMTTIpmjkB7Ck1gHGmm4dLnBgwQCoQoPRihAQhg/dTnX26ELFrg2jgssf1AARC+
         E7iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K1y9AZVS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c7vX+VZp1Q5xKe5uTUgdHzrsGopK/48r2KbLUBsdD4g=;
        b=oLp2JLqc4MQ8IScqEGhF4yaEASDakF47weexqhQf9EykAocN22Il8EXAXHxvHyBu0x
         9SI0tFNJEz+PSzludIXUni22EaSKl0jEvrCzmGgppK/X1WfwIk4yxejBGlFApeni2Rrb
         LhGxofi6TPGCUlC9xUqosxntO91qZMtsYeY6Pcd13g4MtFHx9NKdB5qvkXyyb0WH9ZrO
         GfsQfAz566iP8gqEyuuWaxDfQEUDSbILPQOM0/da764FCXgbgriH3+wl8re4O6d7Vrtk
         mISynCCnOItZDRFe3qVGFGOHtFXYOAVfWjeSKfehRZv41TeNbKWZXN4fm3hv3u1NNZHv
         YySA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c7vX+VZp1Q5xKe5uTUgdHzrsGopK/48r2KbLUBsdD4g=;
        b=VMYzpgdlWWsuKQkIS8LC3GBoLNDEDYxOeoA3UhYafin4aETcA22N8aAJpF6r8eukdu
         By31iFK4LrTjXgCw82tIKNcEULcsbfi0lROTDjlsUyR7M3aUjNSb7ZZuenDg+JJdonUY
         SZxouhk8wiEeZthdz3ZXn5ZOu1QBdgw+3rsyxCr3//5vg5m6SjPGYSidrSxtgOBmMgM2
         EndTTyqOANOaWBEF3HX5xIGwXTNvXZ+7LAZd+N+/3p2/9tD0Lc4iQrlImwS/iTgORB6w
         v+N2WMXO8Y5Rh6h787YzEBHVd1fgo7ohU3U7JylUGcdKpux55gPu0cYnMuPTkfq5KXRq
         LmmQ==
X-Gm-Message-State: AOAM533mtXDOEo1q9BdwzSKrVH/6eucAvVcashau/t9TJcmoDRa+df+/
	EqujMOvjB7t07qg73VvHgbw=
X-Google-Smtp-Source: ABdhPJweh158jJOM9X73xCO1rHDb2P3jwoZ1bl1F3eEBijx9LOFPcGQefv4GFHim6Wn8tWAWk3wS9g==
X-Received: by 2002:a92:c6d2:: with SMTP id v18mr813646ilm.240.1640070055094;
        Mon, 20 Dec 2021 23:00:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8588:: with SMTP id f8ls1910155ioj.0.gmail; Mon, 20 Dec
 2021 23:00:54 -0800 (PST)
X-Received: by 2002:a05:6602:2244:: with SMTP id o4mr925794ioo.13.1640070054744;
        Mon, 20 Dec 2021 23:00:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640070054; cv=none;
        d=google.com; s=arc-20160816;
        b=S7sf3qR2mCX0D94mMv1kj8LrXGW78KgfxuQbWmjNDAw/Lc+322AiTQJCmQCJudIc3Z
         cuGyXbveze+i15lzh4spiffyf9K0Ydyr/xV8AETKq8yTSLUXb7crQdSuzgNWKSc9++3L
         03GHd7wr+e75IbFHxIXbJ9mam6NO2i9qfIXc+MHUUZq32n/KvJu2ct53FdyI1frflORr
         lehl01mKME+050fiEWywrIXNW0L5e8k4blE58T1D/wE+ep+S+CdCRiCT1bqWbcYnSXAN
         XFdhY5JpqKfzBTtsVotARaSsqaHn9gbIMPtyBF+EFGY7yN+95z9jjyODggN2fv3Brpot
         MWtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+5ef5JzSGQ5fXSk8VRtgDlO2+PhbXiBhrkEtspsXmP8=;
        b=yRPurdJXl1gXSiNhHMKNEXEeWbBjqgvug2JjxtqYgfAJE9y0ad87bAawlaWz2cbh/a
         HkAxV8wy1/XSs12Ubdngl/V5MRr4AoyHzQ9Y2LkJJwQkjuVDTU7/GnaqsiZsde7ZKHv8
         TFcGzEGtxQKcA3kB7hrO4kPc6Y605mFIuf53m2vef4ODxWjr0ViLNWr2W61Qucghgr5l
         zzeHLeUPItzmDcLxr0azBQweDefxKLrIixwwCf7yzqu+eAXyZ6yIh5vtA6cxPnIUiP72
         XB+XV5mSU03XY76iQg0uH+AmEZjSa0oWurKLwxtFQEJuGEzlyTJF/BO8xQGUV668PSgJ
         ZcYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K1y9AZVS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id c11si1251616ilm.5.2021.12.20.23.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 23:00:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id a23-20020a9d4717000000b0056c15d6d0caso15503449otf.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 23:00:54 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr1233943otl.329.1640070054151;
 Mon, 20 Dec 2021 23:00:54 -0800 (PST)
MIME-Version: 1.0
References: <2805da5df4b57138fdacd671f5d227d58950ba54.1640037083.git.andreyknvl@google.com>
In-Reply-To: <2805da5df4b57138fdacd671f5d227d58950ba54.1640037083.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 08:00:00 +0100
Message-ID: <CANpmjNPKoKxafo22y9KVBvc52bhsX5nPr3s27y0TvdncXVyn1A@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix quarantine conflicting with init_on_free
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K1y9AZVS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Mon, 20 Dec 2021 at 22:56, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> KASAN's quarantine might save its metadata inside freed objects. As
> this happens after the memory is zeroed by the slab allocator when
> init_on_free is enabled, the memory coming out of quarantine is not
> properly zeroed.
>
> This causes lib/test_meminit.c tests to fail with Generic KASAN.
>
> Zero the metadata when the object is removed from quarantine.
>
> Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

> ---
>
> Changes v1->v2:
> - Use memzero_explicit() instead of memset().
> ---
>  mm/kasan/quarantine.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 587da8995f2d..08291ed33e93 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -132,11 +132,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
>  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  {
>         void *object = qlink_to_object(qlink, cache);
> +       struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
>         unsigned long flags;
>
>         if (IS_ENABLED(CONFIG_SLAB))
>                 local_irq_save(flags);
>
> +       /*
> +        * If init_on_free is enabled and KASAN's free metadata is stored in
> +        * the object, zero the metadata. Otherwise, the object's memory will
> +        * not be properly zeroed, as KASAN saves the metadata after the slab
> +        * allocator zeroes the object.
> +        */
> +       if (slab_want_init_on_free(cache) &&
> +           cache->kasan_info.free_meta_offset == 0)
> +               memzero_explicit(meta, sizeof(*meta));
> +
>         /*
>          * As the object now gets freed from the quarantine, assume that its
>          * free track is no longer valid.
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPKoKxafo22y9KVBvc52bhsX5nPr3s27y0TvdncXVyn1A%40mail.gmail.com.
