Return-Path: <kasan-dev+bncBDW2JDUY5AORBJGJUWKAMGQEG45QH2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id A37B652FFBE
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 00:16:05 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id z19-20020ab04913000000b0036868226b2fsf5483462uac.16
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 15:16:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653171364; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCh8Ecz7ogHRGgIK5Cbrgl36hes27YD6lw3JHFUDrVQ6BLtet2dMyjd+v7f0FVdHiW
         7LzZya96TWZLPzWJn+ETA+oSqJSGF9ZKQ5ebDeo+GOL4MxRjEUXX+BQ9Pp5BKUKt+OCh
         vHRPBiDZ2iAI9LaBaGDm7mQ80R11FAxcATTNSeoi8+GB6c3Hqh+gLrBR9IzD8JO5kbAt
         eZT7RcdWVF1JHjc9CbbZbqjalz6dnj8LqLMlR6xLHKXt1doxrfC+5NhyS0p1OGP4sWND
         1AECXBmtUFUt2j5oymLaTCcwKqCkev4mARje4kOoTnBO7zjGa9yaL5BIqusfuB9IxkjI
         PwiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MMnPkC6EdVROoPVM2SdQQSHWQIbnFuKCKIMiFkus9Mc=;
        b=Ycqv955fm1y4/c2C3eYBoimsJwBfZO4WoSnJ5HonvHM2nGAmUFcyyWbJoLCwxeLDcs
         8jPv8iqd/2C0vu5Zs0JqT4sMCYBINmQUUpPLOUEgRTJgt6J/EDMdBEvgi34wS8IsEwVg
         DuwB1BVeXVIclKq86dOD5RgBAXOApTL6lUWm8MekNomV+YeP6fl99bS4Oi/9Ytyr4QKf
         4ak5ZRdCikAnpNKP1rzuXHfd5/r3ifCNN37PuPgT7Tb7v7Zo+Wyl1NdNN/MKl8nK3Mpg
         doJoII+GYcvLFlpZTfQqMviFqQrAkmR4LFuxFveUjdmUq3MekOeBTk4fxLZYeeKSO3s0
         vBlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Au8Iw4Fq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMnPkC6EdVROoPVM2SdQQSHWQIbnFuKCKIMiFkus9Mc=;
        b=YjGOzK+GBB3GI0O3+pBQ/wlG9mdFVxPdX1+HXOFu/ETxa9GTL2HgxdiLGZlr5hQ14Y
         KUe0lfm8Kdspl6TFi9P5aifOK5DEB1P+q7sDQuJ2Ns2HczpAz6z5PrD6NY1Hh8TCf0N7
         x0r77yX/BfEU5QlpQqZIpgGBSj8Jp5Is8IOI7FEQs+ZwgTTRSI5zMKgjLe8Okvr2hSb9
         9+i0vLi1R55O4HWK41a9ABfUm431P003n5sYLNjwOktqud1eX1H/q4lVHh1V7tRsqTkD
         rpoLZsMKUwEwqxQo+JYY5yBiS6xPcys7riYyho7XMqqveoIaKwYDZv7RTHNdNk1DAs6Y
         eAyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMnPkC6EdVROoPVM2SdQQSHWQIbnFuKCKIMiFkus9Mc=;
        b=ahsxsJ0b+EJzR1tAW50xf/lgz5B2TKOOwNbyWfyLUnA/b+dBDbzYXe89CIn/0LL8k5
         8jk1jfSuLCxtjijDc4FgA1GgcsIRyqN1kZk5MNZ5SEn5lWbcM74E1ct4DYQTfj6s9m1K
         9fEFkWW4ne2Oo2aniI+dmqqvAYQ1wt5ZXL2efn4PP7+U8l9cewqhlTchDthYcEkJUIRG
         qGm6v053n/yqi4S5RDpi9czHCddMHt+FTCUm/o4tH6F7Ht3vPZTn0Da6Hm9aR2pxJ+g+
         iH4rwv4J9Byu1S1ytSVd1fknKSpMbdoQM0jccC+UaKzdhQk/fWYdVgpSog27K6roi+zr
         RLLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMnPkC6EdVROoPVM2SdQQSHWQIbnFuKCKIMiFkus9Mc=;
        b=Qr6bMMrWj888EiuPyaD6EM25xH7A6xIl/iZQNGgjws0kMyiDIGp+XNypvhl0Ec0bv8
         22hL1h2C3aeB3Vkime5wr8Y5EutLPAKRZkeE8dRRZLygakRUftxuu6+xVtsoGiyl3fqR
         XW0W2rL99ch120lF2RviNLbpKJNbX38toJl1L7HIskpvMLZqhJ97zcoD11vOxjcvTwu9
         EBiQNzBHUqqgAsM2IPkO9U4a23aookX54/ZvMEawIpBn3782jXb3jVKtV99bh9kS1DOl
         rinDOFPo2vzJVi+XolEJC+Jbds24sTCfmxVP5RjMbrusptAEBNw5uoMnd1Vgbp8Szt1U
         tfdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323DkWeyALeEKWxQXJCmeyQkCWxXusFbIiQodsKk06xrAXkHR3B
	8QKqEmYM1YFYH5Dx4sW7FgA=
X-Google-Smtp-Source: ABdhPJzwUL2jHPmzrVKh7jKo9PFLJ8kWqAz50/UNb9MA38HRJMZy5aEWisieJ4AyFLUYQHaVexJodw==
X-Received: by 2002:a05:6102:3753:b0:337:8f39:f642 with SMTP id u19-20020a056102375300b003378f39f642mr2866749vst.52.1653171364412;
        Sat, 21 May 2022 15:16:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7243:0:b0:333:c559:c31e with SMTP id n64-20020a677243000000b00333c559c31els1782143vsc.7.gmail;
 Sat, 21 May 2022 15:16:03 -0700 (PDT)
X-Received: by 2002:a67:f6d9:0:b0:324:ba1f:1a94 with SMTP id v25-20020a67f6d9000000b00324ba1f1a94mr6372330vso.42.1653171363779;
        Sat, 21 May 2022 15:16:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653171363; cv=none;
        d=google.com; s=arc-20160816;
        b=a1uhrMRp1b0UE6aWuFa7OkZyXT/DWmPh4xnVXz4SdP+usFW+iCY50AjCP6cShN/IS9
         GIBVV1v2APMzPR+xKMOfpsZYoREYnoX4/BxksdF+jYfqnl89cn7a8hxG6+Ft0y5HWOEf
         ehDg5QFsIRBgTMjfJXsDMlxvgmYAd5dYRwJCfYCSo8rDDEwkN5kbdnATzgfP7a1VPADu
         399RzO1Tk+6Y7kWYEc8tQ2uttWwZTlIXsDryiekPsextLVL5r9SgymgnmEma2Wzh6kB8
         +o8CDRXibrlTJYtT37C4mkgp+AvfGqNtQgS6wDebUbwSWqKSjrIfx76TztS6gqxNQBRA
         CW4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aWQQOMvZvNb9EO+tYEYsUZRSb2Mw7z8jDGanyH/woCE=;
        b=QETJoL0OtoJFzkZLcPiV0swEOyIg3kYRS8CM+KGwjiGEPOiZwYvXnt7D2HHYS8c/od
         AQN888FU825vYj1GjOR5UidAoVHsamn2PdKSSpQ7pOCVSciC+mSsM2G6ibqb23dCJr6/
         8Flnt7gsAfO+JmYlrBqQo3eYAc3wOWcN/ObbDyY06Zll6cMQ3NZQJqc/S2QLCkThV+6h
         RXz/Hz28GQ7eVuz53WzUKQmE8/BQMxQRlelC1YIEQa75ppV7aHzqkGWEnoyFU03v/wCG
         YKkaEdbZdj/GiQMXT944VnMo8EXgn7KYEeiG5Rp2AvDAS9fDO5k3cNhAyQ4+x/PsITF1
         5lEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Au8Iw4Fq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id l24-20020a056122201800b00345486abd1esi376040vkd.0.2022.05.21.15.16.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 15:16:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id s23so11938014iog.13
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 15:16:03 -0700 (PDT)
X-Received: by 2002:a05:6638:d13:b0:32b:cf94:275b with SMTP id
 q19-20020a0566380d1300b0032bcf94275bmr8771607jaj.22.1653171363343; Sat, 21
 May 2022 15:16:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com> <20220517180945.756303-3-catalin.marinas@arm.com>
In-Reply-To: <20220517180945.756303-3-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 May 2022 00:15:52 +0200
Message-ID: <CA+fCnZf+1qM9sPNp1EMRW19P++J3o8cQ1wce2sbHuEoi-hczpw@mail.gmail.com>
Subject: Re: [PATCH 2/3] mm: kasan: Reset the tag on pages intended for user
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Au8Iw4Fq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
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

On Tue, May 17, 2022 at 8:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On allocation kasan colours a page with a random tag and stores such tag
> in page->flags so that a subsequent page_to_virt() reconstructs the
> correct tagged pointer. However, when such page is mapped in user-space
> with PROT_MTE, the kernel's initial tag is overridden. Ensure that such
> pages have the tag reset (match-all) at allocation time since any late
> clearing of the tag is racy with other page_to_virt() dereferencing.
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/gfp.h | 10 +++++++---
>  mm/page_alloc.c     |  9 ++++++---
>  2 files changed, 13 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 3e3d36fc2109..88b1d4fe4dcb 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -58,13 +58,15 @@ struct vm_area_struct;
>  #define ___GFP_SKIP_ZERO               0x1000000u
>  #define ___GFP_SKIP_KASAN_UNPOISON     0x2000000u
>  #define ___GFP_SKIP_KASAN_POISON       0x4000000u
> +#define ___GFP_PAGE_KASAN_TAG_RESET    0x8000000u

Let's name it ___GFP_RESET_KASAN_PAGE_TAG to be consistent with the rest.

Also, please add a comment above that explains the new flag's purpose.

>  #else
>  #define ___GFP_SKIP_ZERO               0
>  #define ___GFP_SKIP_KASAN_UNPOISON     0
>  #define ___GFP_SKIP_KASAN_POISON       0
> +#define ___GFP_PAGE_KASAN_TAG_RESET    0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP       0x8000000u
> +#define ___GFP_NOLOCKDEP       0x10000000u
>  #else
>  #define ___GFP_NOLOCKDEP       0
>  #endif
> @@ -259,12 +261,13 @@ struct vm_area_struct;
>  #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
>  #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
>  #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
> +#define __GFP_PAGE_KASAN_TAG_RESET ((__force gfp_t)___GFP_PAGE_KASAN_TAG_RESET)
>
>  /* Disable lockdep for GFP context tracking */
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (28 + IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
>
>  /**
> @@ -343,7 +346,8 @@ struct vm_area_struct;
>  #define GFP_NOWAIT     (__GFP_KSWAPD_RECLAIM)
>  #define GFP_NOIO       (__GFP_RECLAIM)
>  #define GFP_NOFS       (__GFP_RECLAIM | __GFP_IO)
> -#define GFP_USER       (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
> +#define GFP_USER       (__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL | \
> +                        __GFP_PAGE_KASAN_TAG_RESET)

I guess we can also add both ___GFP_SKIP_KASAN_UNPOISON and
___GFP_SKIP_KASAN_POISON here then? Since we don't care about tags.

Or maybe we can add all three flags to GFP_HIGHUSER_MOVABLE instead?

>  #define GFP_DMA                __GFP_DMA
>  #define GFP_DMA32      __GFP_DMA32
>  #define GFP_HIGHUSER   (GFP_USER | __GFP_HIGHMEM)

In case we add __GFP_SKIP_KASAN_POISON to GFP_USER, we should drop it
from GFP_HIGHUSER_MOVABLE.

> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 0e42038382c1..f9018a84f4e3 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2382,6 +2382,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>         bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
>                         !should_skip_init(gfp_flags);
>         bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> +       int i;
>
>         set_page_private(page, 0);
>         set_page_refcounted(page);
> @@ -2407,8 +2408,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>          * should be initialized as well).
>          */
>         if (init_tags) {
> -               int i;
> -
>                 /* Initialize both memory and tags. */
>                 for (i = 0; i != 1 << order; ++i)
>                         tag_clear_highpage(page + i);
> @@ -2430,7 +2429,11 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>         /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
>         if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
>                 SetPageSkipKASanPoison(page);
> -
> +       /* if match-all page address required, reset the tag */

Please match the style of other comments: capitalize the first letter
and add a dot at the end.

I would also simply say: "Reset page tags if required."

> +       if (gfp_flags & __GFP_PAGE_KASAN_TAG_RESET) {
> +               for (i = 0; i != 1 << order; ++i)
> +                       page_kasan_tag_reset(page + i);
> +       };

I would add an empty line here.



>         set_page_owner(page, order, gfp_flags);
>         page_table_check_alloc(page, order);
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf%2B1qM9sPNp1EMRW19P%2B%2BJ3o8cQ1wce2sbHuEoi-hczpw%40mail.gmail.com.
