Return-Path: <kasan-dev+bncBDW2JDUY5AORBUNT6SMAMGQEB3ZR55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B70C35B4AC8
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 01:12:18 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id u19-20020a056830119300b0063913260813sf2779099otq.21
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 16:12:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662851537; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+cHwLvqYUULW7p1k6rf8o+Ahsorx8fw/Wnw5r8Mf/TNL41Pn2Koab+eSSLk2Ytk65
         YupEEmhxMMeyL7ziyP5EVRy3HnTg1J+Z0yUeoAIxEdR+aB9CfcwV/e4KL/qyHoOEeB9+
         TKXcM6CqgUEnIO6lbRsDKezZFdhHh+n44ZwXa0mSXW01iFQXA4e48wNF3q5rFGGxzJKN
         EVs2e+olDoaJqrYzwlq71ZLprOV01Zeb3omeurcJvrgPU3OS5IR2z8GmoH/KIw4ImJW7
         pJsJYKUN+nipUKry20KYYhVNmm4JfY1A31TqrQXJ1fbdG+xyaQo2m+FkWTaNdzwfviFZ
         IF5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=PPVD3aBmLo7DAf4K6HtNI0CjT+xfR2Vx1xPLqaZQ0Pc=;
        b=eWMmJXa+ivAxJrWXQdv2taFQRNlqjdpklxrPjp8q73QUG7WExubSOflSj4BEI0Mxcc
         J1rhaTX77SSBeEzGeIBM4xQxwNkIPUSkpw0z323QRuDpkflVNWqTDGW3f9pC+D0DQhVo
         9Ei12z+rEfWREhOJV4e6Ap7TCx9Pd6qtKsrOZ+IrtroMPM7MXHzwJpZR0MtSPppXt2no
         VVyAXK4zBAXOBDvJAZxFHEnALUstjq3R0iNGwc8dAQ4AfI6VEms3LMNw/GEUYP3l7+OG
         pN83jffPxOTUnFSUy00/xoq3BjKcjP+zSvRLXM/sABTywqBR/WBFaplw/8wqCk5Ry7RG
         vcLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mwZQUBhT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=PPVD3aBmLo7DAf4K6HtNI0CjT+xfR2Vx1xPLqaZQ0Pc=;
        b=hruoPYk6SaUhOd7/1DIpvpEqArbpjSbHFOl7TF+ydCaAFOSUk8iRAB/l0f3Qz6HE9p
         m306JpiaFWp6Xmp2/FMLXuY/B89hDQzaNhtcfe0rqsdOR3Z4AJ4Lwt5+L3UAogsrR6/h
         6JlKjdDgeZo7GDua+A63v1if8RiE2r7H+sd13FA9xAwjW4t83Wy+k4BduIH5Ar399IYK
         ofFRiZwHy4+VCUYmLdoroovZSR2Vy3Mjk3oRIoc5IXpVhZtkDGcIxxgBrX/UcrEarNQg
         eQJBwLGnfdSa05kQqLBoGXvVh3dbuFUzL5hAsRTs2xv8muT9tIfeDTQbv/XhqE5LV74w
         2/1g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=PPVD3aBmLo7DAf4K6HtNI0CjT+xfR2Vx1xPLqaZQ0Pc=;
        b=hN+RVKxz1gfYDg5e3/GoF/0LDhcKaUWRwPgAINW2oxvRkGwgjVDFfBJweb0qVGcIFq
         xkdjp1vsQDRKfPcvIk5a0BcJxMm6bk5zEwMQdxMJwsBXujpTwFg94SDuDtI0bORMWpcZ
         if+AVF69f88IC0EahUDn17VqpgYgilEd7qiLqp8y75cOXlaejqIvDCWpIqGyfJgRes/2
         DZ0lh0OfrQvRFopl1c1SBNPCGULr5tkiqxUA+JFh0ilD30U/TReBWl86evivc8AutOJB
         odi8+gbRDMeu2mTD4GRlwERNjkXQfjXjkFGSJAftJ3I3lbdXZETNOS77KJh8nOkANwov
         jkcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=PPVD3aBmLo7DAf4K6HtNI0CjT+xfR2Vx1xPLqaZQ0Pc=;
        b=VSha5jRBM7gFDtaejlXLecg2O2VtWVaaCOm3klBgXWafmp9STleC3AuoE8qNhLc77q
         ao2Ha1D/SJEw2nwD8HsFEOAnrUeLSnHIWrrYOTY7DuneSrZU8XCCbRAOOayg2qb+VwMj
         7wRk9UEl1sfXopFEk2gq8aLbtqG3a1IPk/zEB20RaTMR6Yau32SuXw1KXyocEAZ0/vAf
         X7PCu30xbEAjN4/98QVh4LnOrF5Tsh0IeUr7OfpyYBxI53rEggyxJINP73o9cCyalKIY
         +vQOeuRS/v59it34gV1tPWod3XS8VLYGwGgwLIyt0MuVL24d3JXbfTbP+tj/YhsPQJO9
         /Rog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3AQfqoc2pi7qIOkIztdsJJmam4AV/IWdTR64N4HusnCIPom0sh
	1aygyY+095Hn5h2PwQmrl7o=
X-Google-Smtp-Source: AA6agR6GFzrTSHu8hvWpccBHkTQZ3il3md7NSDwVZwc33ZuKGJ1xug75gz44m1sQhv+6WQaLG+eZyQ==
X-Received: by 2002:a05:6808:1446:b0:34d:dbd4:4c16 with SMTP id x6-20020a056808144600b0034ddbd44c16mr4026889oiv.194.1662851537547;
        Sat, 10 Sep 2022 16:12:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b1d1:b0:127:7af0:8da5 with SMTP id
 x17-20020a056870b1d100b001277af08da5ls2999033oak.2.-pod-prod-gmail; Sat, 10
 Sep 2022 16:12:17 -0700 (PDT)
X-Received: by 2002:a05:6870:d24e:b0:127:ba61:5343 with SMTP id h14-20020a056870d24e00b00127ba615343mr8231899oac.81.1662851537201;
        Sat, 10 Sep 2022 16:12:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662851537; cv=none;
        d=google.com; s=arc-20160816;
        b=CZQlLe2BjfzJXD2zBSGi3NJweBHHjuSik3c+9eAxY+HoObKG0FUrvdn6UmtyMiDyYV
         JPaab9l8wCsblkWipkzHD8CfKx82hTsKjT3nNUFFYcFGt9S7mXQClI3jharujdA2zn9x
         Jrjqo2IwYKXAbEU32b6qrBPBvcbs1G/GxuDL2BOdqIMz70ITh3ogw3cydWueIaAfZTUc
         OnBKevZ/eSMokIgccYuMsadGU4qlSc+Vqu2NQ6wE1htyKzGuTaEwuX9dgPrZE65KAcTk
         8d8Rxn19m17CbGFloYTmFOPdEf+P4ZYCHylfenM6TdSDJQAJdzw12z4bI7Bjk5TXTlBo
         NXnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1qAOHyl0ZytUGK0LKmP2phdfOjsGHVNHqllONgN6fKY=;
        b=if7DpaGANH21InHxMho65Z9J+rYvYKD6eCuxhpuZsFYNfG2L3iuXFa6i/++qcZjoFQ
         hGYf4n4Cbjn2FSo+YJAhbU+MICU2t4mJtIXeDAX9JIAVzuNQWhz2ycA3tRejJ488qWkk
         gmVolkL4ZXNVWGkEz8iZTwHGrztN6Q+BL0JeMT2R1S1gcHjuRAs1gVQXMr3jDBvjCupd
         QivXoTIrVsqCw/zeAQWmccAvqYRtIRJ+5qPqCLxXECJTAvOKIhVo3IvY7ushxNR2H1sC
         JYwQ1tT1ZIcu5XCQ4Eoy6rNLETuNNodcCpivoPWNlMhilSG3/XIlFq2ZtNrAqn6fDmLL
         hpTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mwZQUBhT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id a38-20020a05687046a600b001280826e23csi273344oap.5.2022.09.10.16.12.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Sep 2022 16:12:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id g2so910221qkk.1
        for <kasan-dev@googlegroups.com>; Sat, 10 Sep 2022 16:12:17 -0700 (PDT)
X-Received: by 2002:a05:620a:25ca:b0:6b8:7633:baf with SMTP id
 y10-20020a05620a25ca00b006b876330bafmr15148666qko.515.1662851536678; Sat, 10
 Sep 2022 16:12:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220907071023.3838692-1-feng.tang@intel.com> <20220907071023.3838692-5-feng.tang@intel.com>
In-Reply-To: <20220907071023.3838692-5-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 01:12:05 +0200
Message-ID: <CA+fCnZfLCe8fhQ5UAyF1LwZuMCfbsoEXDmX3deaW6i_E5UE60g@mail.gmail.com>
Subject: Re: [PATCH v5 4/4] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Dave Hansen <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mwZQUBhT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72e
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

On Wed, Sep 7, 2022 at 9:11 AM Feng Tang <feng.tang@intel.com> wrote:
>
> kmalloc will round up the request size to a fixed size (mostly power
> of 2), so there could be a extra space than what is requested, whose
> size is the actual buffer size minus original request size.
>
> To better detect out of bound access or abuse of this space, add
> redzone sanity check for it.
>
> And in current kernel, some kmalloc user already knows the existence
> of the space and utilizes it after calling 'ksize()' to know the real
> size of the allocated buffer. So we skip the sanity check for objects
> which have been called with ksize(), as treating them as legitimate
> users.
>
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.h        |  4 ++++
>  mm/slab_common.c |  4 ++++
>  mm/slub.c        | 57 +++++++++++++++++++++++++++++++++++++++++++++---
>  3 files changed, 62 insertions(+), 3 deletions(-)
>
> diff --git a/mm/slab.h b/mm/slab.h
> index 20f9e2a9814f..0bc91b30b031 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -885,4 +885,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
>  }
>  #endif
>
> +#ifdef CONFIG_SLUB_DEBUG
> +void skip_orig_size_check(struct kmem_cache *s, const void *object);
> +#endif
> +
>  #endif /* MM_SLAB_H */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8e13e3aac53f..5106667d6adb 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1001,6 +1001,10 @@ size_t __ksize(const void *object)
>                 return folio_size(folio);
>         }
>
> +#ifdef CONFIG_SLUB_DEBUG
> +       skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> +#endif
> +
>         return slab_ksize(folio_slab(folio)->slab_cache);
>  }
>
> diff --git a/mm/slub.c b/mm/slub.c
> index f523601d3fcf..2f0302136604 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -812,12 +812,27 @@ static inline void set_orig_size(struct kmem_cache *s,
>         if (!slub_debug_orig_size(s))
>                 return;
>
> +#ifdef CONFIG_KASAN_GENERIC
> +       /*
> +        * KASAN could save its free meta data in the start part of object
> +        * area, so skip the redzone check if kasan's meta data size is
> +        * bigger enough to possibly overlap with kmalloc redzone
> +        */
> +       if (s->kasan_info.free_meta_size_in_object * 2 >= s->object_size)

Why is free_meta_size_in_object multiplied by 2? Looks cryptic,
probably needs a comment.

Thanks!

> +               orig_size = s->object_size;
> +#endif
> +
>         p += get_info_end(s);
>         p += sizeof(struct track) * 2;
>
>         *(unsigned int *)p = orig_size;
>  }
>
> +void skip_orig_size_check(struct kmem_cache *s, const void *object)
> +{
> +       set_orig_size(s, (void *)object, s->object_size);
> +}
> +
>  static unsigned int get_orig_size(struct kmem_cache *s, void *object)
>  {
>         void *p = kasan_reset_tag(object);
> @@ -949,13 +964,34 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
>  static void init_object(struct kmem_cache *s, void *object, u8 val)
>  {
>         u8 *p = kasan_reset_tag(object);
> +       unsigned int orig_size = s->object_size;
>
> -       if (s->flags & SLAB_RED_ZONE)
> +       if (s->flags & SLAB_RED_ZONE) {
>                 memset(p - s->red_left_pad, val, s->red_left_pad);
>
> +               if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +                       unsigned int zone_start;
> +
> +                       orig_size = get_orig_size(s, object);
> +                       zone_start = orig_size;
> +
> +                       if (!freeptr_outside_object(s))
> +                               zone_start = max_t(unsigned int, orig_size,
> +                                               s->offset + sizeof(void *));
> +
> +                       /*
> +                        * Redzone the extra allocated space by kmalloc
> +                        * than requested.
> +                        */
> +                       if (zone_start < s->object_size)
> +                               memset(p + zone_start, val,
> +                                       s->object_size - zone_start);
> +               }
> +       }
> +
>         if (s->flags & __OBJECT_POISON) {
> -               memset(p, POISON_FREE, s->object_size - 1);
> -               p[s->object_size - 1] = POISON_END;
> +               memset(p, POISON_FREE, orig_size - 1);
> +               p[orig_size - 1] = POISON_END;
>         }
>
>         if (s->flags & SLAB_RED_ZONE)
> @@ -1103,6 +1139,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  {
>         u8 *p = object;
>         u8 *endobject = object + s->object_size;
> +       unsigned int orig_size;
>
>         if (s->flags & SLAB_RED_ZONE) {
>                 if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> @@ -1112,6 +1149,20 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>                 if (!check_bytes_and_report(s, slab, object, "Right Redzone",
>                         endobject, val, s->inuse - s->object_size))
>                         return 0;
> +
> +               if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +                       orig_size = get_orig_size(s, object);
> +
> +                       if (!freeptr_outside_object(s))
> +                               orig_size = max_t(unsigned int, orig_size,
> +                                               s->offset + sizeof(void *));
> +                       if (s->object_size > orig_size  &&
> +                               !check_bytes_and_report(s, slab, object,
> +                                       "kmalloc Redzone", p + orig_size,
> +                                       val, s->object_size - orig_size)) {
> +                               return 0;
> +                       }
> +               }
>         } else {
>                 if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
>                         check_bytes_and_report(s, slab, p, "Alignment padding",
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-5-feng.tang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfLCe8fhQ5UAyF1LwZuMCfbsoEXDmX3deaW6i_E5UE60g%40mail.gmail.com.
