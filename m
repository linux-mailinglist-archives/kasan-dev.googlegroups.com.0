Return-Path: <kasan-dev+bncBDW2JDUY5AORBMF26KNQMGQEY3LP2DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B8FDD633930
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 10:58:10 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id x203-20020acae0d4000000b0035a623fce1asf5217470oig.10
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:58:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669111089; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zlh8evDhVCzyJ3N3LCVAgnM2jvs/HCvWTPJ/p50J57mNXAe1dVoJT1lp/LmvX4XIzE
         LWCIw6jOFTdfOkwaSjJ0dJQHzicijpcm+csp6ZJ0ISj098mSYc1TWpeZBQd452DuV0pj
         fggmW/nf7C0j0rLkbWtq2paeh6CEVYvu9GybvukcIs8OMoaDnq55g/Z01Ft546GCOXTE
         woJOAajo5A20j37j/SwohZWJp0V+hCzq/0TEZHNajb1DT0t3qM/JK0QezGrWv8mAe8mQ
         vq+EmlhCXYEImu8vP5E2ynKAofxis+RhYNNoUVEfS3nLxNHXnxfN/r2vA+9btxwUoTzp
         1bMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=U/Q4XepgyKaxnb3egna8GuyUs3wPc++5Rk3iTO9bo80=;
        b=EsSX51p9e0CKQvojc09KZ8ukOzF8DCLyUT/gHbYgtqQCy5Ju3tGnpKGiyEnDQ5kTMw
         cEyR4ZqnPy3asxe+KS9/1CWdjHTo6hioWoUkcDRRbPRR9eVVQaD8Qh4xAfk4D3c4+5vP
         h+fn2oxmNfjKgTNvDGf09oCfRsfiWofluLsHrk3gC6wQtIz9MUYAZ+v/IpgGNnLUG/ix
         ODP18cLR4WB7PSDXpBIdqdOvFZgMU9PeRMpV48fdwQeQJ+ci5zeu0uKQq80CDQjkHy7D
         jbwD0ysk0TvsB44MEw38mljTGG1Z8ZZpZYrKINHZ4biA6vc3cRSuW1SOkxfKoWZkufFT
         HCTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fFy0T2aF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U/Q4XepgyKaxnb3egna8GuyUs3wPc++5Rk3iTO9bo80=;
        b=BSW4qgoaiPAxXO+2uJVprc0ym/GO00X1hhXUe5kt3/RJ2WULYSqhFokCUvJ+7Tp+Oh
         6i7I5xXu4gFLuLDqG888QG24qcWYspo5x4bDnDZZzj3xwyti3cB9k20C5fd2yOj0d0mB
         /zcLFRHCr0dtHQ83BHQCXEn9XngcNgI5P+be32TxQ+pTsllb20BVY5Pz3+H0fOrqOQ4S
         dHXyUWg3aDIbbqCZ91T6ZxbwrSwkUwOd0QpT73k2Q9lBz+xdOSmsM+5CFovzDbqLwRmD
         vRnzPrwPMmeKNd92EcFy0TTAXpCCcRceANrhJq+x+tfqxUy6+aIaTRReQ5biRWDEhTCo
         N3sQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=U/Q4XepgyKaxnb3egna8GuyUs3wPc++5Rk3iTO9bo80=;
        b=Uml2hcgwmOSolj+3NqkFiZweBX2tLIxu7x36gKnx0ssSDMBFidkFg3IRt3EHlYrbOv
         h4izM2oMJulYfbDEdIqNTQt4MUwsQfVvxhGSzj/aM1n/gXnOJNqLHDZFwUG8K2rB3J+Z
         UKYCRkeYhUsfNpO2L0UyhSKoKkImQXYLgk+NEtOt2vCLjRN5sYowbmT7nqb3WiRQ9kjT
         D/ppMQT1cyAFxcPUI+dWNdkYC7/t3XgGI9mQBqsT6RWvqjgkFmp+NUeqSlWPPvP4EH3B
         l7sA1+jvydRfDoKhIKWsS9AZlsUryzP0nlqVHrSVB329jMg3X5wpAUphLO4X+ERH5zCa
         62eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U/Q4XepgyKaxnb3egna8GuyUs3wPc++5Rk3iTO9bo80=;
        b=eesmsHboLmTtCQmsY6HWUTmjCDlZ/AqlexQFjBs83+fGg9pEGR5sxYxN6XyfHirEX7
         zDJyFbYakZDSOg/4e0THvwvMx/dquVjjj3w65u525ixEN16f4vCvGD0OybXcbIu4Lk0t
         zebC5dzUg+FQ7JscFzmr4v5+sOvaKQUwdLyfNZCQK39CBRU+kTQfOcxyHC5npin88Ff4
         EzdoYO+agFyQ7SWiqqIPQ0MMzcNuswfrXjt7jzF+y5WNFR6QIEeFy2M5bUYMtdjld5Qf
         nIh4ErtcjHQin0Aj8R1hjffhNq/wAKISak35ENmG4XqiqOiNHZvjd5dt5EAghR1pP7QM
         /+nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plRgA3mFdC3Of23qNXU/6CKTV93wVW7NLZ0seCaQ+NWG5lmvEoG
	HoaTPjASnA7zEoyZFlHZPo4=
X-Google-Smtp-Source: AA0mqf73Knj0GQh1Yneupv9XaLoeXp/stbX9eky27bQEqAgPjcF0C35Fnv2wbwWOQkfdxm83OOPrGA==
X-Received: by 2002:a05:6870:9d95:b0:13b:a163:ca6 with SMTP id pv21-20020a0568709d9500b0013ba1630ca6mr16348681oab.125.1669111088891;
        Tue, 22 Nov 2022 01:58:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:181c:b0:35a:6687:ef26 with SMTP id
 bh28-20020a056808181c00b0035a6687ef26ls4049417oib.4.-pod-prod-gmail; Tue, 22
 Nov 2022 01:58:08 -0800 (PST)
X-Received: by 2002:a05:6808:1919:b0:359:ea79:9114 with SMTP id bf25-20020a056808191900b00359ea799114mr4902388oib.121.1669111088466;
        Tue, 22 Nov 2022 01:58:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669111088; cv=none;
        d=google.com; s=arc-20160816;
        b=iDX9UXpibv09qdTOO+AHGqsa3T2OHjM32f71F74IbUA09wbyeFY12CP+Rgd1+gHzmr
         37GISCCCiz2ONrMvpVF3oJ1gDkpDtu+mUa6clIYa3TSkXRvr0YL1Px3NN1ECJhXuynMB
         ZvnxANjj/8NmpiMaGyeOQnTLiP7EmWv+67xmmY7p6gcBhcypJ6SFJ95bySIjCNNXWNij
         X3XKfr6RAJLkHaOa/dSoEyNdg7+Cc3dr6WWO12kYgnE/48z0njGsZdMCNGMwhU0gtY9/
         Dj7VX4JqpZr/o86HKuKEIWmuYFcF81uL0cwY7RKY5+pQtJLpychlkfAdKP9MrYYCkEc6
         RhxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Iswb2ultRT2N7P9BN9RKy+2BlKMbcXeEkzv8Y2QxO6g=;
        b=De15vy5obKdhZls337rascDKCWthFPPkMzmd+LB704ZY0DIQM8MXQAEj4Qzu51hqwv
         YVZ13tna4j68KpQx1dvrX9JrF8uC7fiR5MUFq4Fy7mWuX8liJQuKszpDgcnC2TjPnK4f
         z7sFQo0Sl7wXTcGke8CaQpiIQOSjgqxc62defdTpGN1Z9Gh7eYkMUaNcr3ok+WUe1S68
         YzCT34IxFRfCgI+1vAgp9Pn/hgrl7H+y2Lv8fh21cRiB7xKVJIgrvddeUr6vbfq4nqNW
         Ec/s7UY26M33bFg8SKk6lKuLJIJ3c1sZ/hgLjF5hHrngP5eAes8nosmuivnKrXXkqAHX
         WVkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fFy0T2aF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id g8-20020acab608000000b0035522fd7d98si769086oif.1.2022.11.22.01.58.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Nov 2022 01:58:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id jn7so11278426plb.13
        for <kasan-dev@googlegroups.com>; Tue, 22 Nov 2022 01:58:08 -0800 (PST)
X-Received: by 2002:a17:902:8214:b0:188:e878:b5f6 with SMTP id
 x20-20020a170902821400b00188e878b5f6mr3038130pln.150.1669111087764; Tue, 22
 Nov 2022 01:58:07 -0800 (PST)
MIME-Version: 1.0
References: <20221121135024.1655240-1-feng.tang@intel.com> <20221121135024.1655240-2-feng.tang@intel.com>
 <CA+fCnZenKqb9_a2e5b25-DQ3uAKPgm=+tTDOP+D9c6wbDSjMNA@mail.gmail.com> <Y3xx7JUaRfRXRriw@feng-clx>
In-Reply-To: <Y3xx7JUaRfRXRriw@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Nov 2022 10:57:56 +0100
Message-ID: <CA+fCnZe0av3Ko8iRGAFjF1jpG77cE3mtQVK-HqZE9sP=eGwGtQ@mail.gmail.com>
Subject: Re: [PATCH -next 2/2] mm/kasan: simplify is_kmalloc check
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=fFy0T2aF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::632
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Nov 22, 2022 at 7:56 AM Feng Tang <feng.tang@intel.com> wrote:
>
> On Mon, Nov 21, 2022 at 04:15:32PM +0100, Andrey Konovalov wrote:
> > On Mon, Nov 21, 2022 at 2:53 PM Feng Tang <feng.tang@intel.com> wrote:
> > >
> > > Use new is_kmalloc_cache() to simplify the code of checking whether
> > > a kmem_cache is a kmalloc cache.
> > >
> > > Signed-off-by: Feng Tang <feng.tang@intel.com>
> >
> > Hi Feng,
> >
> > Nice simplification!
> >
> > > ---
> > >  include/linux/kasan.h | 9 ---------
> > >  mm/kasan/common.c     | 9 ++-------
> > >  mm/slab_common.c      | 1 -
> > >  3 files changed, 2 insertions(+), 17 deletions(-)
> > >
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index dff604912687..fc46f5d6f404 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -102,7 +102,6 @@ struct kasan_cache {
> > >         int alloc_meta_offset;
> > >         int free_meta_offset;
> > >  #endif
> > > -       bool is_kmalloc;
> > >  };
> >
> > We can go even further here, and only define the kasan_cache struct
> > and add the kasan_info field to kmem_cache when CONFIG_KASAN_GENERIC
> > is enabled.
>
> Good idea. thanks!
>
> I mainly checked the kasan_cache related code, and make an add-on
> patch below, please let me know if my understanding is wrong or I
> missed anything.
>
> Thanks,
> Feng
>
> ---
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 0ac6505367ee..f2e41290094e 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -96,14 +96,6 @@ static inline bool kasan_has_integrated_init(void)
>  }
>
>  #ifdef CONFIG_KASAN
> -
> -struct kasan_cache {
> -#ifdef CONFIG_KASAN_GENERIC
> -       int alloc_meta_offset;
> -       int free_meta_offset;
> -#endif
> -};
> -
>  void __kasan_unpoison_range(const void *addr, size_t size);
>  static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
>  {
> @@ -293,6 +285,11 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>
>  #ifdef CONFIG_KASAN_GENERIC
>
> +struct kasan_cache {
> +       int alloc_meta_offset;
> +       int free_meta_offset;
> +};
> +
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
>  slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
> index f0ffad6a3365..39f7f1f95de2 100644
> --- a/include/linux/slab_def.h
> +++ b/include/linux/slab_def.h
> @@ -72,7 +72,7 @@ struct kmem_cache {
>         int obj_offset;
>  #endif /* CONFIG_DEBUG_SLAB */
>
> -#ifdef CONFIG_KASAN
> +#ifdef CONFIG_KASAN_GENERIC
>         struct kasan_cache kasan_info;
>  #endif
>
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index f9c68a9dac04..4e7cdada4bbb 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -132,7 +132,7 @@ struct kmem_cache {
>         unsigned int *random_seq;
>  #endif
>
> -#ifdef CONFIG_KASAN
> +#ifdef CONFIG_KASAN_GENERIC
>         struct kasan_cache kasan_info;
>  #endif

Yes, this looks good.

Please resend as a v2 and I'll give a Reviewed-by.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe0av3Ko8iRGAFjF1jpG77cE3mtQVK-HqZE9sP%3DeGwGtQ%40mail.gmail.com.
