Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6UP5HDQMGQEWC3S6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id D112BC0213D
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 17:21:32 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4e89265668fsf27767341cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 08:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761232891; cv=pass;
        d=google.com; s=arc-20240605;
        b=ccqXEcZYidO5lgPYAy2+pNb5iUGdcuov0C88Vd4J1i968ys0ClzgJA5tpiVRMY/nBx
         Vmu6BMqjpZ/3eSWROrLP5ypjFlvZpmjNrjmCogGo9VOpglISbuB3DMR3rLBB80MC6m1i
         vVnrXY5+N1+2K+3zwX+Zl+5nvElcesKyvcKbsOX4HPi1eltEOk1ZUQ1jAwUXa7fuzFHf
         DxnJ3Y0+0GVE4XJV1xhFSGjirKN/SrLr3p+M54rvc0nVMQVLllGcSaBacZHtgmucSW+G
         hijLFb8cpIRoHyuE1Kh4H+OSE06h+G8R1xz0JtMLmMfn8uyOExEhZJt2qGTz4qa1ggJf
         qh3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/e5uGPPesPdbGPza5XLP0JJrvuTwMkVfA3iHqBaNoMs=;
        fh=mbWi4b3ctIRtRwiUYJJcpPtjYcLZNYWHzPgvxKidkBI=;
        b=Z0eHHnhH++rTk4DxQV20gS9SWPlrW5qD7nrqNyrBBI/cJEgR+XKBVRu0k90JSaNKEN
         wdYsMnWJuxKxgZNW+8nsqkLnqvjRKOO5ET00i8vBn5Hl0BBna73dgsoHAxAHi1oLzloX
         lKTKXWjhwtrVyTIpovjIQvfB0FCrimVTg7RqNrKJv60ZhuR8XDJwx8kDKEJb56hyPo2n
         IR2W6ExMR0kHadYsuudELOyqX7xxBGlwV63PAKH5P4nYDPmgPnbFr8VROYDg+13ZLeoh
         wOQg2YDlP5sxB2pRVxFhu5pWUSI3beucJBtRydlim+D+6gc4ZjO7r7ht/v6b+2y48+xo
         OPUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tnl2JOra;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761232891; x=1761837691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/e5uGPPesPdbGPza5XLP0JJrvuTwMkVfA3iHqBaNoMs=;
        b=KNEyN5+LoEmJAl6XY0NUUVtX5BKscyOfFp0pFa6B+VbGM3eqGJlrSgHnWTYxVhLl9u
         sGOSXlw61c3nbbSbNrpksAlz8H4f3aUMtXJOZYfwWDlYTKt11Z44++GVBdVF/j7phfvK
         CmqjFc7lhIcoq1SUwqujy6Lf6y+h6vN/wy211OulG/7LItDso4mE2/DJm9clWEHrj/Qj
         W+MkH8mu0NiXt/jnosJOvye1BUYTWIOW7p4oVxhqsO6VjziBDkWMoQ7ylT3dALOK/oBh
         2ReYvTp1SlsnNuc253aO6J+j5Ot8pL8LjO654e4/0p9WiIXFn05GXWrZX+ldT2++NTja
         hgzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761232891; x=1761837691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/e5uGPPesPdbGPza5XLP0JJrvuTwMkVfA3iHqBaNoMs=;
        b=s8VDEXd0cDWuq2oJBo/XcMR/N7HfwmDxAAh0bwdSJWDEP4FvXBNZuHXcfr3fvWw1Qj
         tOb4lW2kG6DrYTrfc0lh4KVFooJIuVOkiWkt36y6fXFLe8IxKUu2EKDyL82crZZG7S72
         WTI2jNmeTmsIjhZu27UfSlAIBg60CuYEB5bHFQIKuWHU2y88cNQXouXq1aM6i0aeRQHR
         EJtDobf5M3D7qdBesl9EBMckNkMsDVyzdfJC5y1MnDyQnY7FdkhthNGyRVRdMeCys6kW
         B8lx18wLzmvam13wlRR+yJC5G6JCS3AYx85InKt+/LvXfCCCbii0tKpnZkA8gQzyN3Og
         n+IA==
X-Forwarded-Encrypted: i=2; AJvYcCV1xglFs0h99rfczjF1AOlHX7yJqCYWF9at4F3olg2S/H9PgfjmtS0Nyz2u7pv2S/acNfMDfg==@lfdr.de
X-Gm-Message-State: AOJu0Yzec7kGWK9AkzrvPuoBoRzhkjzPoZ9t4OgijRE8WypCFwbXlYdO
	WDgkR75pd/J/F+aWjPKXqnXyXTammySelUyaoghqT6x0+1nxlS7NIAJt
X-Google-Smtp-Source: AGHT+IFRCJ3/kmgC2b+a35m2BpJ1HUIG1FBjsaUDhqMuAeYJD8hrJLaIinsnHD8onHHpZz8SJJcb2w==
X-Received: by 2002:a05:622a:130d:b0:4e8:97e5:8e40 with SMTP id d75a77b69052e-4e89d3e5872mr294747371cf.74.1761232890963;
        Thu, 23 Oct 2025 08:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6+a5CnGGOCAndgz06+bhtqK2VV9/B6OEusAjw8Cg+6vg=="
Received: by 2002:a05:622a:282:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4eb80edfaffls14565631cf.0.-pod-prod-02-us; Thu, 23 Oct 2025
 08:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY4sdx64l8m4/CokIKUn7ceSqSH1NeNLnsqd5DnOxl6i7BKHkzClDYoInhxmuFWWA8whnUFPLAJpc=@googlegroups.com
X-Received: by 2002:a05:6102:291e:b0:525:9f17:9e55 with SMTP id ada2fe7eead31-5d7dd5ec4eemr9237207137.32.1761232889558;
        Thu, 23 Oct 2025 08:21:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761232889; cv=none;
        d=google.com; s=arc-20240605;
        b=OEp1mbBd4orBmJJBc9npr+07DFHKbCLGrbQ26YN9CfzCur6/CxiUcaK2HA5zlvOQaD
         YENeiWzwvgzecx0btpGnxuI/przJAU5gOXCUxBdLB3akomKTt445jYPnwGO7ginoYBbx
         hldfW3Ho4sJCk+MjCOfNtpDIfKIZChQfE1XqRGym1l0O430JqDwlCnYB7KE/e5tp6HxI
         6oDLN9gua4abIADW/NGOhDaeZ+D9yGchA/eJoYGi1/ngupe5ohXEh1RuSs4t502PnhpG
         7VnISHh82GJarmcoVKrz1rQY8j7weTM4eiPPMGEPfQxp+opk9FRSS6qWWSICzWyy59Ak
         q8zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G2jwrgWQY1h1RtIcpPrpzP6Qz2BnEli8aRyjgsdjGiM=;
        fh=0jU5qnl03LthEoeXBWE0qP2wTwtstFEebE3c2jz/06Y=;
        b=RVENmGG2pCyaY86oySLeDKrmBcTVl377tTS+HIDRW5eTcNbZx630o7rgzBUZp4KziE
         LLEno+xp34TxOJJ7/psJOKZAqB74izVOw4XUk6cNJtIdVdBjg90tz4uXZ85V19ap8Qj3
         wPR0+PbtEURxJq6hnlJLt9FUP+gaUx2jJDPAjB1q0yl9A32htUVV35mDOIYcQfwzE24w
         3tXjQEgp3ARtSTybm7iBUHAFJRP9f+akG4QtHPz04mzpP2IjF3EawbtrpiyEcOePQ1KH
         K3Qyp7ZV4/41fw/lNy/WetOU/Ymq1oh6y4SSOzZXgk/DcSpmG3VgVRMDSSM+/KIFNFe5
         0ZSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tnl2JOra;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-557bee0afe6si79354e0c.4.2025.10.23.08.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Oct 2025 08:21:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-290ac2ef203so9112555ad.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Oct 2025 08:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUM63ipHLfikVLPCCXa9dVeGrXtKh6duhvjlIwg3WbTgEsmsj2/yMC1jKWIlOCIvKaisVczh2Z6sgg=@googlegroups.com
X-Gm-Gg: ASbGnctQWtf0ezDyUUO7CNcDP7OGP8KMlxg1n6KPGvMiw5SgEk28bDNFVPpU/Vm/YNW
	eMHYQfBosuNySlf6WzcnwvBZQp+NZuwwjm2t8ar/JEjRiWObau4Y28QJU9JHxYEjuDA2Juh1+X0
	y6LBCjmDTgUwnZH6sSsUoipKzenBUCkknrLF7ZsaFhOqhrHsTWrLTIskqEC7Wh91zv356bFrjnQ
	/CxZkiJ29pUheXt5Cbfgx4m1Nm9i2Y+Po5j56v6ZXos5JKu1UC+LSHkt8flz5XGnu9UrKRkWcwi
	01nKs3UHKOiLvKI6bfTFjXmlH3JE37CZjC6s
X-Received: by 2002:a17:902:e746:b0:28d:195a:7d79 with SMTP id
 d9443c01a7336-290c9c897cemr312219295ad.5.1761232888223; Thu, 23 Oct 2025
 08:21:28 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz> <20251023-sheaves-for-all-v1-1-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-1-6ffa2c9941c0@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Oct 2025 17:20:51 +0200
X-Gm-Features: AS18NWBMguvD9NqZ0MBG1ww1DA9Wez_eaadFg_kTQ6tj-ZGocLoyPMGw450Hbw4
Message-ID: <CANpmjNM06dVYKrraAb-XfF02u8+Jnh-rA5rhCEws4XLqVxdfWg@mail.gmail.com>
Subject: Re: [PATCH RFC 01/19] slab: move kfence_alloc() out of internal bulk alloc
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tnl2JOra;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 23 Oct 2025 at 15:53, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
> allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
> but it's conceptually the wrong layer, as KFENCE allocations should only
> happen when objects are actually handed out from slab to its users.
>
> Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
> object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
> was refilled with KFENCE objects. Continuing like this would also
> complicate the upcoming sheaf refill changes.
>
> Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
> to the places that return slab objects to users. slab_alloc_node() is
> already covered (see above). Add kfence_alloc() to
> kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
> prefilled sheafs, with a comment that the caller should not expect the
> sheaf size to decrease after every allocation because of this
> possibility.
>
> For kmem_cache_alloc_bulk() implement a different strategy to handle
> KFENCE upfront and rely on internal batched operations afterwards.
> Assume there will be at most once KFENCE allocation per bulk allocation
> and then assign its index in the array of objects randomly.
>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 44 ++++++++++++++++++++++++++++++++++++--------
>  1 file changed, 36 insertions(+), 8 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 87a1d2f9de0d..4731b9e461c2 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5530,6 +5530,9 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, gfp_t gfp,
>   *
>   * The gfp parameter is meant only to specify __GFP_ZERO or __GFP_ACCOUNT
>   * memcg charging is forced over limit if necessary, to avoid failure.
> + *
> + * It is possible that the allocation comes from kfence and then the sheaf
> + * size is not decreased.
>   */
>  void *
>  kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
> @@ -5541,7 +5544,10 @@ kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
>         if (sheaf->size == 0)
>                 goto out;
>
> -       ret = sheaf->objects[--sheaf->size];
> +       ret = kfence_alloc(s, s->object_size, gfp);
> +
> +       if (likely(!ret))
> +               ret = sheaf->objects[--sheaf->size];
>
>         init = slab_want_init_on_alloc(gfp, s);
>
> @@ -7361,14 +7367,8 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>         local_lock_irqsave(&s->cpu_slab->lock, irqflags);
>
>         for (i = 0; i < size; i++) {
> -               void *object = kfence_alloc(s, s->object_size, flags);
> -
> -               if (unlikely(object)) {
> -                       p[i] = object;
> -                       continue;
> -               }
> +               void *object = c->freelist;
>
> -               object = c->freelist;
>                 if (unlikely(!object)) {
>                         /*
>                          * We may have removed an object from c->freelist using
> @@ -7449,6 +7449,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>                                  void **p)
>  {
>         unsigned int i = 0;
> +       void *kfence_obj;
>
>         if (!size)
>                 return 0;
> @@ -7457,6 +7458,20 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>         if (unlikely(!s))
>                 return 0;
>
> +       /*
> +        * to make things simpler, only assume at most once kfence allocated
> +        * object per bulk allocation and choose its index randomly
> +        */
> +       kfence_obj = kfence_alloc(s, s->object_size, flags);
> +
> +       if (unlikely(kfence_obj)) {
> +               if (unlikely(size == 1)) {
> +                       p[0] = kfence_obj;
> +                       goto out;
> +               }
> +               size--;
> +       }
> +
>         if (s->cpu_sheaves)
>                 i = alloc_from_pcs_bulk(s, size, p);
>
> @@ -7468,10 +7483,23 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>                 if (unlikely(__kmem_cache_alloc_bulk(s, flags, size - i, p + i) == 0)) {
>                         if (i > 0)
>                                 __kmem_cache_free_bulk(s, i, p);
> +                       if (kfence_obj)
> +                               __kfence_free(kfence_obj);
>                         return 0;
>                 }
>         }
>
> +       if (unlikely(kfence_obj)) {

Might be nice to briefly write a comment here in code as well instead
of having to dig through the commit logs.

The tests still pass? (CONFIG_KFENCE_KUNIT_TEST=y)

> +               int idx = get_random_u32_below(size + 1);
> +
> +               if (idx != size)
> +                       p[size] = p[idx];
> +               p[idx] = kfence_obj;
> +
> +               size++;
> +       }
> +
> +out:
>         /*
>          * memcg and kmem_cache debug support and memory initialization.
>          * Done outside of the IRQ disabled fastpath loop.
>
> --
> 2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM06dVYKrraAb-XfF02u8%2BJnh-rA5rhCEws4XLqVxdfWg%40mail.gmail.com.
