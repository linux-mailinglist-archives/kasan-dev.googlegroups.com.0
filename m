Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG4B2OLQMGQETJNECPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id D80C358F93E
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 10:41:00 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-31f3959ba41sf145349907b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 01:41:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660207259; cv=pass;
        d=google.com; s=arc-20160816;
        b=MGAx8lJSBWFL2aFjPKu5szUjTFBxR9xN/Y/6cSeptlfriJ71H3FzTrald8DO8LIl2D
         C5EJZC3ZGcqFxhhDJib/09tZh87VMGkm6EBNbuLJDRlLIizJkukU82w24HxKfismfwTL
         lg4EA8L3tcdaWN3TCk/xVlWN+B5N0zXpHUfVBTvFNl3Wji0uuq5sdslj2xViQSYFqeKT
         w5eoVoFar5BHxRd7gB1Oz2WmgIhkEMzObM8wfoy/T9VIqKh2gxBYTwG8Sb6h6f4Cl1pg
         3xXTd2kvldEwyngEGN9A0FkTcHLPFStPn6mUusggyhjKauOsJ7wSeksa1ZBOkPQG8vjw
         lXsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yWn2nQ0QIKCeqKYMlb2Iyo//llo5ceSQWu9oM9Eotsw=;
        b=bIoVfSmbikTqrUwFP7OINe38ftg4Wh6d74tyz+3qGpfxuhK2mrCwd6Go7nViDuby9W
         GH2kEftdk5UnfKDPZ62nut6DF/XdlfH/cw88HhLfxkWkYfvlclzHC10CkCNiuaLwPzfY
         zP0lIOqfpKPLunqx+3OV6kyigxO/EA9OquaU8MUvS4TOt7cR5N7CYkHZ/PVrlldvMKID
         m/7ioDh2yNyZVA4a2Rs6+GyTRRmI0d/BBwY4Q9gigoo6UDhdcCT+iPlMBZvUt4JACrIx
         hn4/TbwmfF4b3pOtRf9abdMHLavavl3wq1UOIU2iQL9eeIquDkw/p64QbTlyCtTwHHwH
         Wkpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=maHTlgEH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=yWn2nQ0QIKCeqKYMlb2Iyo//llo5ceSQWu9oM9Eotsw=;
        b=Za8wtN/K8BaB6VNjEAWGMAR6PgLWJAiTHbtmJ9gccOCOyGagn94R1X2Wj1vv1i4AM0
         1RlZ/v70Me4CbxWN7zIVV2ilb5lGibT9BHSMOL0VUs3YZbFgtYA1qeh72Qgfmo7sD6jr
         HNiXQ7Raw4N9rNiaKlvblcXFTxNjLEJutLC5YJeCxwOOhuGqFYMWxjERlskzPN744B40
         aKGmd777P0SJx4n/rZNRH9EvWNEOmrB1WKtt0oNKVcOvktSLWSdyLP4m8QHllzvTT9xh
         zBNlq+xu9LlCqpmy80S2jR7z8qH5mMhhw3FUtYcQdteQoQq8UsOR3tA0+hK+9HpiRHiz
         mXrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=yWn2nQ0QIKCeqKYMlb2Iyo//llo5ceSQWu9oM9Eotsw=;
        b=YRSYlBlak2HUe8EiP+zcri2f0d0kgrybb/6UtDD2RwAg5w38NRr/JjF8dX5xjBpTRo
         GX5IF2/TjSUj3gqKGcxGAHd3bbZmh4Iy7j/pyz7bzlu7vdV9aNniawpjekGpoJ76ZSFd
         RlWedaZzjlrPvq5HFYNLkkoQTG2Q2stMqndNNLFY95YIqGFGycSqau0mhcFNW52WCHre
         4x6tjKSGaR5n8hr5rtm6tlZXMVohV1L1QmkNDbHAwYpnfnKrSfB7UXfg7vrg3rf1L2lZ
         YJ4cT2wYX5udCoY+HApLlr4TYziy7NsatAIllnzyLe/5XjW8KJFlSGoo42WYAnL+j4HD
         WToQ==
X-Gm-Message-State: ACgBeo3RAGK9ddHP2q89ppmErwIbv44OvAWNk/g7X35WLs4GSQyWuf0k
	zL9FuLG9HbiovAtmfZe0laI=
X-Google-Smtp-Source: AA6agR5R9JESuT12QsCMJ2KMMdUnq78RuJs4LDg2EeTdtWwLm/+tJ53CJ1oeUNa+j2oOS1RLfpubrg==
X-Received: by 2002:a05:6902:10c5:b0:671:7158:cf2c with SMTP id w5-20020a05690210c500b006717158cf2cmr29383358ybu.314.1660207259698;
        Thu, 11 Aug 2022 01:40:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3608:0:b0:66e:7859:9c23 with SMTP id d8-20020a253608000000b0066e78599c23ls697870yba.1.-pod-prod-gmail;
 Thu, 11 Aug 2022 01:40:59 -0700 (PDT)
X-Received: by 2002:a25:2d5b:0:b0:67d:e14:7daa with SMTP id s27-20020a252d5b000000b0067d0e147daamr4573985ybe.561.1660207258984;
        Thu, 11 Aug 2022 01:40:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660207258; cv=none;
        d=google.com; s=arc-20160816;
        b=hUhfMjGS8BaJgryZ8/9TYr36aBvuf620b8WzenharIqplnAjEetRNLH6PAFJTNJfVy
         dFg0pS9iLJd9vSvue+TguBD6cP+QdTY27oq1joQSGEDx9Rbq7IBsxsuRVtYn2n4+9Lzf
         eYtOSrbWb/wtElL1rcEQ0/hMkSsBjGVYmBY9zTzCjMOjrUHszxuILXyyOUtyvNMh5TrY
         X7kt4iclnc+JznxF7PRhHBgJ4jjdmxxNwR+Dzc5aJ76zGy4zqKWX93RWVnKNdKuoN9iP
         yCmfMerOPtIN1qdP6qXpjVMFXTRKuleM31dDKBKbJWYN9DiKrHwn12BoP6O3YuZAe6sO
         +Oxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/4ZTaTdAfStvS4s3TOdOS9NhP4siit/2BMoKXlrckaA=;
        b=FJhVeesj7W7tb/d5Dn6ABIQoDm2yGAkyXrOtAEfczEz1YvlCSH7XIOYLQZyLB7xaXF
         1VmVMcsrmxmZ22Rx100i0UtgyPzA2JWFcFS4DL6q/Et+A8ThgJXYh5gHwZxx3Q2dSsPo
         KQcIaeGpzuQr85A4Tc4HhX90uN7ZC4VRR1MjwThEuEfOR84dzhvJDXQcvu/NH+XHHEt/
         xecrQHUURGSi+J7/msQkB6bJSftu8ZoUmTTehlrkxMK3WiwqduWuRDYdJcbkn1RkbxRX
         JV1w3ICtw+2+cjmJPUQc8reN1SSkvT5NT//8jGY0/QBKxKqZN4DUwAbLjO0WU/aVLwKU
         LbAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=maHTlgEH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id i85-20020a25d158000000b0067a69dcb59bsi1022687ybg.2.2022.08.11.01.40.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Aug 2022 01:40:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id k12so27201750ybk.6
        for <kasan-dev@googlegroups.com>; Thu, 11 Aug 2022 01:40:58 -0700 (PDT)
X-Received: by 2002:a25:5c7:0:b0:67c:37a4:36d with SMTP id 190-20020a2505c7000000b0067c37a4036dmr8315769ybf.584.1660207258506;
 Thu, 11 Aug 2022 01:40:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220811072551.2506005-1-imran.f.khan@oracle.com>
In-Reply-To: <20220811072551.2506005-1-imran.f.khan@oracle.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Aug 2022 10:40:22 +0200
Message-ID: <CANpmjNNDy5-OssTWP6sm7r0BOFkBVdOa1_ZsPWGQOKjLwGZoCQ@mail.gmail.com>
Subject: Re: [RFC PATCH] Introduce sysfs interface to disable kfence for
 selected slabs.
To: Imran Khan <imran.f.khan@oracle.com>
Cc: glider@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org, 
	rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org, 
	vbabka@suse.cz, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=maHTlgEH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as
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

On Thu, 11 Aug 2022 at 09:26, Imran Khan <imran.f.khan@oracle.com> wrote:
>
> By default kfence allocation can happen for any slab object, whose size
> is up to PAGE_SIZE, as long as that allocation is the first allocation
> after expiration of kfence sample interval. But in certain debugging
> scenarios we may be interested in debugging corruptions involving
> some specific slub objects like dentry or ext4_* etc. In such cases
> limiting kfence for allocations involving only specific slub objects
> will increase the probablity of catching the issue since kfence pool
> will not be consumed by other slab objects.
>
> This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
> to disable kfence for specific slabs. Having the interface work in this
> way does not impact current/default behavior of kfence and allows us to
> use kfence for specific slabs (when needed) as well. The decision to
> skip/use kfence is taken depending on whether kmem_cache.flags has
> (newly introduced) SLAB_SKIP_KFENCE flag set or not.
>
> Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
> ---
>
> This RFC patch is implementing the sysfs work mentioned in [1]. Since the
> approach taken in [1] was not proper, I am sending this RFC patch as a
> separate change.

This design is much simpler and looks good to me. Feel free to send as
a non-RFC.

> [1]: https://lore.kernel.org/lkml/20220727234241.1423357-1-imran.f.khan@oracle.com/
>
>  include/linux/slab.h |  6 ++++++
>  mm/kfence/core.c     |  7 +++++++
>  mm/slub.c            | 27 +++++++++++++++++++++++++++
>  3 files changed, 40 insertions(+)
>
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 0fefdf528e0d..947d912fd08c 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -119,6 +119,12 @@
>   */
>  #define SLAB_NO_USER_FLAGS     ((slab_flags_t __force)0x10000000U)
>
> +#ifdef CONFIG_KFENCE
> +#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
> +#else
> +#define SLAB_SKIP_KFENCE            0
> +#endif
> +
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #define SLAB_RECLAIM_ACCOUNT   ((slab_flags_t __force)0x00020000U)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..8c08ae2101d7 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -1003,6 +1003,13 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>                 return NULL;
>         }
>
> +       /*
> +        * Skip allocations for this slab, if KFENCE has been disabled for
> +        * this slab.
> +        */
> +       if (s->flags & SLAB_SKIP_KFENCE)
> +               return NULL;
> +
>         if (atomic_inc_return(&kfence_allocation_gate) > 1)
>                 return NULL;
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> diff --git a/mm/slub.c b/mm/slub.c
> index 862dbd9af4f5..ee8b48327536 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5745,6 +5745,30 @@ STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
>  STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
>  #endif /* CONFIG_SLUB_STATS */
>
> +#ifdef CONFIG_KFENCE
> +static ssize_t skip_kfence_show(struct kmem_cache *s, char *buf)
> +{
> +       return sysfs_emit(buf, "%d\n", !!(s->flags & SLAB_SKIP_KFENCE));
> +}
> +
> +static ssize_t skip_kfence_store(struct kmem_cache *s,
> +                       const char *buf, size_t length)
> +{
> +       int ret = length;
> +
> +       if (buf[0] == '0')
> +               s->flags &= ~SLAB_SKIP_KFENCE;
> +       else if (buf[0] == '1')
> +               s->flags |= SLAB_SKIP_KFENCE;
> +       else
> +               ret = -EINVAL;
> +
> +       return ret;
> +}
> +SLAB_ATTR(skip_kfence);
> +

^ unnecessary space?


> +#endif
> +
>  static struct attribute *slab_attrs[] = {
>         &slab_size_attr.attr,
>         &object_size_attr.attr,
> @@ -5812,6 +5836,9 @@ static struct attribute *slab_attrs[] = {
>         &failslab_attr.attr,
>  #endif
>         &usersize_attr.attr,
> +#ifdef CONFIG_KFENCE
> +       &skip_kfence_attr.attr,
> +#endif
>
>         NULL
>  };
>
> base-commit: 40d43a7507e1547dd45cb02af2e40d897c591870
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNDy5-OssTWP6sm7r0BOFkBVdOa1_ZsPWGQOKjLwGZoCQ%40mail.gmail.com.
