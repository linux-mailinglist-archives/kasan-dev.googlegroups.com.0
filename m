Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7N6QKJAMGQEPSFOAKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA8944E8919
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 19:31:42 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id h10-20020a05660224ca00b0064c77aa4477sf589597ioe.17
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 10:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648402301; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQiU1tGLXd4rDhwqnhUMupbzXEFX+lYZStfWLMa77XjyEJDBRpfMKMMnO1EfIbkyRZ
         ISKY7q+NhMOQLTGMv034Cx6wfSYsB5Vm8asNK/0t8oCmBvFu/ktFTlZJsyIvPyKlst/i
         Tm3+nJ3+S3sRMKqgDLFR7/BrwgT2XG40I45hJzgY5uBm4mzTONuAxTtYzdhhyeQkin1s
         CFmsTkKvEi4L6La6ntoe9xKTGGyN3SIrS4mvv1U5ateE1aHlkp+ThZy5lSopRlPYpWre
         o7cE2I2JjetLzWaxIttMfQUzmFGYl9uOqsv5PtOvf2ZCLBdjQehtUtnybsak8t89QmHR
         lmYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bLr8uQK2uhSEHunj8MwYl05irZV+j+pDgQJxffYfLcI=;
        b=nyXGcWWBiasneVlYqEnN+vPNmi4yNy69T5fN143HYK0CR4vja6Gfd9Z2DVuqGeER3v
         kt7H4e0ihPUNXT9iozy/f0MAMU9g2OLzNFh1g2O2+hnmmjKH/98ayU08GekpS+YM2+de
         Dt2aWZJa96RhGKur+7fvJZBMRQlZF+cRHVr3HxDz7jXSUaWwDf3n9n6mKnHlHLKuIOH6
         s5sPQUHSxFI5Eh0Yn3xIRNAPTKr1O90PVvdbmg35yPaZbZDzEv45FNDLI6d2hpz4oy11
         AesPKcN9SSsfLDpn/nIm7iJneJXecCyfxrDWCjrnacKMQpVxRBrqq5mBdfirYBTbVcDO
         YQHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h+37ODtn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bLr8uQK2uhSEHunj8MwYl05irZV+j+pDgQJxffYfLcI=;
        b=oaINmjK0S40dVcu6Nj9xkZen3hCKo+Dew41VHXGEmfOITYjHt4hEaSDVWmzxMCeeDh
         NtxXUWO/fSLRz3XqT+BxM3q2vM7TEbbPtltfY0nLUEHDpr0vuRZ/n8a5ORU4bbi1bzLs
         lHo4v2cEQJLENDvY3u3j234zRH0NcbhDhdcLhxTRi70xb1iSPFuz6bWJTrwhwXcIMsEf
         VDHoSNovy2z3mZiXlKel/9t1trvK5w1gU6FxfCttw3DjFjWsmesI6U78kxbKVNWAOgjm
         hby8KN7sqIBIEED/DCc8kAl291qzF2tWKSGrS7G1Dpq0UunnPzjFb6z5bTtYnBupy2pO
         bwVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bLr8uQK2uhSEHunj8MwYl05irZV+j+pDgQJxffYfLcI=;
        b=6eccMMNXBgjDXceVRjhOGgH9gxvxZtuTFag1utWbdv1ojIZRLDlcr1JA6w7Rp9+kWa
         EsDjvSgl2PKpAeIu5hgfexxmnugfhjHSlHj5889vSj0XWVV87AaFV/5V4HxRxfECJouF
         DK6p7AjLy6rCQvQByAhv5UQoaKJLRc5d3SPP6M6JrnMvt9iq82xfovoHrheJGlsUX3Wv
         7VvdVvDfudLMtZY131jMVACFoLgb1F4zwbTyMLUo7iuFLvFulKXvnjhqXWr4GdoYb95f
         ISE1SzO1/errcG7sQoL5yrcUDKPAMWWbStjDbnBDpm9aFLsXY//oDS9agmKLQq+fY4iL
         x7zg==
X-Gm-Message-State: AOAM530qtxH+RAqhOwbrxo5Kq73ltAlFwFAkIXyahNLHk6hNwIUAORch
	F7djOg1zp13Adfilt9RXfsY=
X-Google-Smtp-Source: ABdhPJxFyEj5QV+nLp0ZB0br+zfaLEq/EryOVCjjBELEHiaDuZtv/u2ieMr91bSE0mymuHCFW7hytA==
X-Received: by 2002:a05:6602:3281:b0:648:d45d:22e with SMTP id d1-20020a056602328100b00648d45d022emr4380275ioz.7.1648402301768;
        Sun, 27 Mar 2022 10:31:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1aae:b0:2c9:ae65:8102 with SMTP id
 l14-20020a056e021aae00b002c9ae658102ls299343ilv.7.gmail; Sun, 27 Mar 2022
 10:31:41 -0700 (PDT)
X-Received: by 2002:a92:c249:0:b0:2c9:b344:f57b with SMTP id k9-20020a92c249000000b002c9b344f57bmr1160427ilo.276.1648402301381;
        Sun, 27 Mar 2022 10:31:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648402301; cv=none;
        d=google.com; s=arc-20160816;
        b=XG0bSGbG3st5+pGAJoR32r/RAAmGbTdz3WuZCOQrGDyseBjeJ+2SL6A2O0e+DUyorB
         3Lc6aC8o3/qhxOQIjpLa4ZlEPUozA8j0CcJLLuO0aHw++TCwDEi6E0pVB8YNhZPsjccV
         9pQcS3E65+HCEA6Tvtm7NNHzsj+G3rgrOOwcsG15DFT5cy7MMrUqHzVMLKZkanB/92ox
         8NsLdNJNRf1qIOYCMEUZZjm9KiiCOSJLkyLNcYIJTYhKSmValjIWWgC+ao36q6KrUt6E
         K9kJ5EKRPVG1HNysQ4XYfdB1RLTL48xI/+hEi2jdPjd49JVB5FsI4EExRZBUBETPJFZl
         yDaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zr0NjEDn5ahm6BQl9cvFf4dmTZugbKlSBosKFEdMvGE=;
        b=RYN4oOYk122KatyJG5uU8Xe6jufiuCN7Iwi/lOqSi5IGavjykLtfFenr9OqBTPv59a
         qnXdqSn2azV0dKG50iBLP6j4ncjFh+EO4NPekv6TTQyQif1HyzDGSTe2uEaymummZ3SV
         VnWyONdBdyexMJCZSTDZGVq5WvBvmd05mj71d11zIZ7hw8JMcnxK1r2xRxiX7NgiTEEI
         EeaJV56/+RPrKWAQkV9dHoOngZ7MC6BjYZgcQVj62Bpl9yrI1IEv33iHlUnmaZW8GQOf
         sONmwzYOfsMAa8z0L6w9AA+mbn0kOHJcVdJyjKjYxgRPYgkkJuqHQY4jVBWgNq8hksf0
         Z30w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h+37ODtn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id b11-20020a02914b000000b00317c6dd732esi800862jag.4.2022.03.27.10.31.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Mar 2022 10:31:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id z8so22353336ybh.7
        for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 10:31:41 -0700 (PDT)
X-Received: by 2002:a05:6902:1149:b0:634:63a3:f6a1 with SMTP id
 p9-20020a056902114900b0063463a3f6a1mr19743428ybu.425.1648402300751; Sun, 27
 Mar 2022 10:31:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com> <20220327051853.57647-2-songmuchun@bytedance.com>
In-Reply-To: <20220327051853.57647-2-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 27 Mar 2022 19:31:04 +0200
Message-ID: <CANpmjNPA71CyZefox1rb_f8HqEM_R70EgZCX8fHeeAnDyujO8w@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
To: Muchun Song <songmuchun@bytedance.com>
Cc: torvalds@linux-foundation.org, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, cl@linux.com, penberg@kernel.org, 
	rientjes@google.com, iamjoonsoo.kim@lge.com, vbabka@suse.cz, 
	roman.gushchin@linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=h+37ODtn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Sun, 27 Mar 2022 at 07:19, Muchun Song <songmuchun@bytedance.com> wrote:
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
> ---
>  mm/kfence/core.c   | 3 +++
>  mm/kfence/kfence.h | 1 +
>  2 files changed, 4 insertions(+)

Thanks for this -- mostly looks good. Minor comments below + also
please fix what the test robot reported.

> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 13128fa13062..9976b3f0d097 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -579,9 +579,11 @@ static bool __init kfence_init_pool(void)
>         }
>
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> +               struct slab *slab = virt_to_slab(addr);
>                 struct kfence_metadata *meta = &kfence_metadata[i];
>
>                 /* Initialize metadata. */
> +               slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;

Maybe just move it to kfence_guarded_alloc(), see "/* Set required
slab fields */", where similar initialization on slab is done.

>                 INIT_LIST_HEAD(&meta->list);
>                 raw_spin_lock_init(&meta->lock);
>                 meta->state = KFENCE_OBJECT_UNUSED;
> @@ -938,6 +940,7 @@ void __kfence_free(void *addr)
>  {
>         struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
>
> +       KFENCE_WARN_ON(meta->objcg);

This holds true for both SLAB and SLUB, right? (I think it does, but
just double-checking.)

>         /*
>          * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
>          * the object, as the object page may be recycled for other-typed
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 2a2d5de9d379..6f0e1aece3f8 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -89,6 +89,7 @@ struct kfence_metadata {
>         struct kfence_track free_track;
>         /* For updating alloc_covered on frees. */
>         u32 alloc_stack_hash;
> +       struct obj_cgroup *objcg;
>  };
>
>  extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
> --
> 2.11.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPA71CyZefox1rb_f8HqEM_R70EgZCX8fHeeAnDyujO8w%40mail.gmail.com.
