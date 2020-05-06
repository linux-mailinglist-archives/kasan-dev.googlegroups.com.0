Return-Path: <kasan-dev+bncBCMIZB7QWENRB3UQZL2QKGQEBS4XUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id ED39A1C6D8E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 11:50:39 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id e9sf1333360pls.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 02:50:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588758638; cv=pass;
        d=google.com; s=arc-20160816;
        b=uytZ2AbyRt1+V20+b9qvL6ycyog99iLvmRNFnpVccwmpoax+uwxvxILOUF5sSHAuJu
         ouef3nJtdnJkvvt+yQLDKIFavAUjemUUe1RrBo5CiRHegrHbLkpXsQ10R4hk1Wo3nCoU
         QCSxfzHgj/oTnY6iB3cSw8uoc6YVFc+AraVmupP/HOSwi1hfIJrgKN7YSlU75JK2+iq9
         uUqFPMV9GVzTT0ByoN+HnGJfFALPR4zywidEfTIEEzZ+Ipe/7TRIewMoLoRjngHKXlEJ
         VipJTGUSwPgJlPq2MQt/gx23/E4PjFr4hYJIVo3+pcbRwGorG+UcYrh3JMS2MCLPlW6q
         BnDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fwTK1VCmFgVufIzyezWZQok7bdD9mmAvidVn0jC1Bh4=;
        b=PZnfhFLNibVLH+CcOv2iZVy5mKH5raNVJZd1spQLFtFrnvWngaC+jzaDMdOm8Wblzx
         gucIWSSjUy8w4SAROwqvUBDzgLtFfdEsEeoNHN20inNb/xAfUzJ+R/EdtflXmxAQGpHs
         Pvzba+92iuGdHEtECLwCjfjO8SZ6UAiEZzfDXAyc+lgJWu7q6q8rxH4sOyNNKePnLP71
         N/dSn9mgHeoshFR3A/AYpwxCwmKzWVdyUSEPQssm9/1JXzWIXKq4wh37AFJB89CUKMqp
         712IpKUPDpuSx3gVZspg2lZFn8tefDBqEBq6Be5rALyvYDQgumB1xDADWNsgfxhlHXKW
         BlbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WpjHBPWX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwTK1VCmFgVufIzyezWZQok7bdD9mmAvidVn0jC1Bh4=;
        b=StV08vpq6tBfPz8TuOR8TJ5S4xzrw+ZQ394qKLgZ256TT0+p4S3RyHfufJiiUgkFiV
         MpQ7Hm2VS2n/HUrZSyJcNpsuJsZdsKPUnB3jDkUQrY47T7bXJMGfpLilTVeqU4cBfV6a
         itYOzOkgPuFTf97Ict3KnO8m2vryKRJSWIu9csOhCz9nuKzzVB8vJ6mp2VMQ4Roh4saZ
         b5UBaRR0PYHy7nTElx/lr7HVr6xGn26FBcGN/tYqmbWHl4AdiTAz1Xn3odVXgRr8LxKH
         FY+2eZmuUls3MVOWVqtToCdsbAUb3uWlKMaIQm3OI8C8F3w7+fWdsyM/NeAg2GoyUeJy
         C29w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwTK1VCmFgVufIzyezWZQok7bdD9mmAvidVn0jC1Bh4=;
        b=IEFORJ/ixs8O2kcALPgixtyIEVjMOqHxhwywB3KAXvO8KpFpC+kmJtBgwRRWhxTJOh
         5mGWgbFFiKz6/fuOIRi3JlatqylRtNNF54fJWo1emboak0g2k/1aa26e8EEcAB5nYmCC
         a96Vmq7i/Ohnxs3HafFEoOW8TTrY8E+XlzAeWbdglTi6iP3TQ8D4C7vTHSS+nvX+D8ak
         nGUELVi8gP5HvJqPK4qw2N2DDSRE97c9yDOMZEvn6i8y5ZoqJxRii83Rj8uZ2ZYoC6Ex
         Xp4Qmd6hWWqjTTwvuk8bEl8jc6zi+XMuCovQ5HXcA08VRyeafIq2ej96XpPrSxm+Bxy/
         FBaw==
X-Gm-Message-State: AGi0PuYQF6Tbd6xYKYT6eB0OT1ZwfXzRXLR6G6U+Ve7ufNU+I9DsW2SD
	0w1TqwoscLS8wIMyi8ppF4s=
X-Google-Smtp-Source: APiQypI8FGYaYngd8iazXl2kPM29cE8gUPS0zEzIgTdcyTJ8U72+x4sfLE+hV7UkikDGA89QEjfIOg==
X-Received: by 2002:a63:756:: with SMTP id 83mr6315784pgh.293.1588758638436;
        Wed, 06 May 2020 02:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:224f:: with SMTP id c73ls3008398pje.3.canary-gmail;
 Wed, 06 May 2020 02:50:38 -0700 (PDT)
X-Received: by 2002:a17:90a:22e9:: with SMTP id s96mr8547257pjc.46.1588758637978;
        Wed, 06 May 2020 02:50:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588758637; cv=none;
        d=google.com; s=arc-20160816;
        b=E6yZr/BggnuQ09lx4ycLN/2O0Nj4Z1oGh3fovOeUfb+cg+VjF4tF6/2Ew8d1AV6pSM
         FM4en6KDdfIRfcNk2MqcVLiYvHRccQWg10CbzrlY4FEj4hucMQNUPimPaMH+m5dS2dUT
         VPUE8dIKKclQ1qKlHLj1Yfhsc/2o3YwjewTFMSK/s0z6i2/beahdfiuAYCQ8r7oYkFg/
         18J/zGolASfKfQy93lTim19de7n52P8nyoKh3uaHx5rMdkeR0AyF8nSAAEKRGBfZZAUP
         B9s+ivBHqEKVJD+SOLvPCOBGa+ErLiFD20+xt0+/AFAzxOc/OOYbq6tDQRx52OUeITTj
         wTWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j5iMU2d4N/4y18awBTt8gjljQLvXQSdia/Cv9QIxeQc=;
        b=x3RyuQFb6nVfr9Fg0xFeoeTAmceVvMi//L3Dkm8dY6vHx78T6Hb+ceB+UsjaeD2Jit
         wbN6shdHmoGOENegfiVdE4LuI3V9wFKBvuo9XQ/MpcdmP/OABGrODdkaM88FUFvMDPvg
         Ad43/2I4SAenfB0N+d+cZwDf10HnECQnco6dbzM9eRWh/saiLES2s+dMbpd/uATTJQJX
         8kRnVouwuI/tlYOgkk03ELgghlZkFb7n4aVHm4R++4N46QF+FX/M821NZE9zTBYHS6pO
         WOsJGCOLy20CKQg+7Vsr2Ro4O2RQDDCwgsh71zDTomQwgEJGAk96FZd+qaBLSO+EZy/q
         SEfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WpjHBPWX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id t6si573240pjl.0.2020.05.06.02.50.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 02:50:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id t8so383460qvw.5
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 02:50:37 -0700 (PDT)
X-Received: by 2002:ad4:5a48:: with SMTP id ej8mr7241682qvb.122.1588758636814;
 Wed, 06 May 2020 02:50:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200506052155.14515-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 11:50:25 +0200
Message-ID: <CACT4Y+ajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA@mail.gmail.com>
Subject: Re: [PATCH 2/3] kasan: record and print the free track
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WpjHBPWX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, May 6, 2020 at 7:22 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> We add new KASAN_RCU_STACK_RECORD configuration option. It will move
> free track from slub meta-data (struct kasan_alloc_meta) into freed object.
> Because we hope this options doesn't enlarge slub meta-data size.
>
> This option doesn't enlarge struct kasan_alloc_meta size.
> - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> - remove free track from kasan_alloc_meta, size is 8 bytes.
>
> This option is only suitable for generic KASAN, because we move free track
> into the freed object, so free track is valid information only when it
> exists in quarantine. If the object is in-use state, then the KASAN report
> doesn't print call_rcu() free track information.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> ---
>  mm/kasan/common.c | 10 +++++++++-
>  mm/kasan/report.c | 24 +++++++++++++++++++++---
>  2 files changed, 30 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 32d422bdf127..13ec03e225a7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -321,8 +321,15 @@ void kasan_record_callrcu(void *addr)
>                 /* record last call_rcu() call stack */
>                 alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
>  }
> -#endif
>
> +static void kasan_set_free_info(struct kmem_cache *cache,
> +               void *object, u8 tag)
> +{
> +       /* store free track into freed object */
> +       set_track((struct kasan_track *)(object + BYTES_PER_WORD), GFP_NOWAIT);
> +}
> +
> +#else
>  static void kasan_set_free_info(struct kmem_cache *cache,
>                 void *object, u8 tag)
>  {
> @@ -339,6 +346,7 @@ static void kasan_set_free_info(struct kmem_cache *cache,
>
>         set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
>  }
> +#endif
>
>  void kasan_poison_slab(struct page *page)
>  {
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 7aaccc70b65b..f2b0c6b9dffa 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -175,8 +175,23 @@ static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
>         print_track(&free_track, "Last call_rcu() call stack", true);
>         pr_err("\n");
>  }
> -#endif
>
> +static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +               void *object, u8 tag, const void *addr)
> +{
> +       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
> +
> +       /*
> +        * Only the freed object can get free track,
> +        * because free track information is stored to freed object.
> +        */
> +       if (*shadow_addr == KASAN_KMALLOC_FREE)
> +               return (struct kasan_track *)(object + BYTES_PER_WORD);

Humm... the other patch defines BYTES_PER_WORD as 4... I would assume
seeing 8 (or sizeof(long)) here. Why 4?
Have you tested all 4 modes (RCU/no-RCU x SLAB/SLUB)? As far as I
remember one of the allocators stored something in the object.

Also, does this work with objects with ctors and slabs destroyed by
rcu? kasan_track may smash other things in these cases.
Have you looked at the KASAN implementation when free_track was
removed? That may have useful details :)


> +       else
> +               return NULL;
> +}
> +
> +#else
>  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>                 void *object, u8 tag, const void *addr)
>  {
> @@ -196,6 +211,7 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>
>         return &alloc_meta->free_track[i];
>  }
> +#endif
>
>  static void describe_object(struct kmem_cache *cache, void *object,
>                                 const void *addr, u8 tag)
> @@ -208,8 +224,10 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 print_track(&alloc_info->alloc_track, "Allocated", false);
>                 pr_err("\n");
>                 free_track = kasan_get_free_track(cache, object, tag, addr);
> -               print_track(free_track, "Freed", false);
> -               pr_err("\n");
> +               if (free_track) {
> +                       print_track(free_track, "Freed", false);
> +                       pr_err("\n");
> +               }
>  #ifdef CONFIG_KASAN_RCU_STACK_RECORD
>                 kasan_print_rcu_free_stack(alloc_info);
>  #endif
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052155.14515-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BajKJpwNXd1V17bOT_ZShXm8h2eepxx_g4hAqk78SxCDA%40mail.gmail.com.
