Return-Path: <kasan-dev+bncBDW2JDUY5AORBZUX66MAMGQE72O5IVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B0FF05B4E97
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 13:52:08 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id k19-20020a056a00135300b0054096343fc6sf3812698pfu.10
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 04:52:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662897127; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8c22ZiZAO8H+gYffHpwp4KyxNLTFaPmL4Jllu9cFZ3pwb5X43xqWpmoQRdYSGIrox
         0VaVG/BHGvENvFviHq3+NTH2EbwC5UK3Ea/TD+hlH2C6GdUuqqSdNlxOAF/OXimbJqcD
         1WmMTCzfdnBeWkcmlAvlaq2UN3gklC08UicrQyYMQCNr0gK6QPLdney/iExR5AQXUvUG
         qe+VpYUvj8jYxRicHMFQCE9JPJJrvZ6mxo5keBEcm8SWhVPnrNqEMBqM5OEoqV0lafUR
         i9hWMcdL94CHERmmjyUaKJn2j3L1aPUgq6a/tZ70XeYSKV58uOowxNlFnFP45ycaMlag
         ISsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mk3ZUQjFegbTnEmbYY/50FAf7lOVqBZ5a6Ig/nSvLUY=;
        b=C88w0TqXocAN/yJ5htxQ0TTIdVpDsDIBInxHO7rfsK+yP4BvWMkJOTjhqrZ0XM9zBC
         Rq6R/B8JqKF2fS0rVVoQtZL2AgAMd9wPptxz+IJeB35+DsQ9KFyonw6FDi+BUH4bAk5z
         oW/G/YwtqYbB7s9eOwgIS7gTui4sBIoEkVbvLzmOG3vZp4tmWpOGPkM41hCSICqmEIc2
         ikNMwnO7xwyNahZN8atEZDdIy0lSUhRHJF+G0QTCMHN1/pJGr1KrE8AfPy3j2eNBDf6V
         Rjz5vBjSV/5tBFuCkvAWhL7jGx0BT+GiSTCQu8ADirO5IhNS5xthkGej8/asV8rOUPDJ
         kPlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SigBH0gv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=mk3ZUQjFegbTnEmbYY/50FAf7lOVqBZ5a6Ig/nSvLUY=;
        b=KtQr9dSDnheFpbxY8nsjG2b86lS189ySkzteoyDnjmdRwJ37YC0creyoTa/KgYR8J2
         jvVRs37uULGZZrONCwl2A7axjUWp7MrlMqn8tVPeoSYFB6d1Y07d0dhfpZ0ciKZ10mwo
         OQm0Zzi0umr9irZriI8vGln4RB491O0CX8rCLhj+ws3r2P3j2UrdqPr0EVHfcM0qcHCr
         vg0sxgBAyE9x4jaNdVJTpkc43FuMJnkTvyNb5wHLfM/E/0GX/MoK8E5oYFxncMxJQK+b
         rGGjxiCb6Gsq8VET8Jl9zpKCSVQhRSLy5MCJUpBKgDdIghwE9SDt/QOpk3deux6LXs7w
         POBA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=mk3ZUQjFegbTnEmbYY/50FAf7lOVqBZ5a6Ig/nSvLUY=;
        b=BMcXvanLm1zedcGhhy9EM+BWOdSW09asYfjqKs5xXl9+K0MInk1dLCb+MQBd588kEK
         urwSkK85eMbpNYCBS6VY+Ky/YEloMOV/oFsE+ZcDo0S2Csb4r261SHiREb/IMEvgSbMt
         MIZXLTJ/1TpQpPM6wfB1j7mJKWVlvCXibB2mXxFxoLGAXzhGdGJGoYI5xirss7DsaXCZ
         dvdRiLQXdCrnX3DkNYSl+6d7UYYjdKbn01bYo8DZtfEhYkXNiluYTGsFyaXp1GalMGVH
         4A7He8VWlgCloMiWF0NJ6yraOz/tuuqevekMuoC/pWHXfpQGkcUluluUfoesLzrAzTU4
         xKeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=mk3ZUQjFegbTnEmbYY/50FAf7lOVqBZ5a6Ig/nSvLUY=;
        b=MVRUzqWd+NbPbpfoNdqbyoWThxLcIrMIJGKGl+n7zJxJIJ6eaX5z19oP7QuRu9J1lg
         9oO9cQhl73rldjTArLUvYMeZDpG7MzfuCyNrJtyQWaB9kz3NoOAD/PR5FBKQVU39JEa5
         7UkqVVnen3ye3jU6Q6rtgfKA9NG2c/ywj9b91gFzwCWh8gmVO7Xgf7ievODh52JOxTFw
         twymCNP2kJD1EEhqQGXYDMjj7NuUr/VJQmEN+7UJuBZwGXOnmzRfGono9+qeTwMMhpav
         u10N+tp/xRRqbQ0s7opbX9nmck8TqrYCo+r0axREuEzpmX1+EkxRyeRdo+QgO0KSgXEQ
         c3JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0N9SgbIgeEbrIos2GuFwQB9czATHX+XrDC/gEAP4Ep4/ukW8mA
	uHvuTH+pzejO/o0xG88v6JI=
X-Google-Smtp-Source: AA6agR55m+Q0cFBUPPqJI2YUPVNSsH8YO3nDt3NuuMz+l8UU/POsvbGvbbsiL3jYtBqDSbg72YSVJQ==
X-Received: by 2002:a17:902:ebcb:b0:168:e3ba:4b5a with SMTP id p11-20020a170902ebcb00b00168e3ba4b5amr22187441plg.11.1662897127106;
        Sun, 11 Sep 2022 04:52:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1204:b0:171:29d0:e7e0 with SMTP id
 l4-20020a170903120400b0017129d0e7e0ls5868824plh.3.-pod-prod-gmail; Sun, 11
 Sep 2022 04:52:06 -0700 (PDT)
X-Received: by 2002:a17:902:c941:b0:177:e69a:a517 with SMTP id i1-20020a170902c94100b00177e69aa517mr19208604pla.144.1662897126217;
        Sun, 11 Sep 2022 04:52:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662897126; cv=none;
        d=google.com; s=arc-20160816;
        b=gbdV6T7O3QTPVvco7f/2Pzyckvu+KTKV/oCqQxTUr1d4ZOnC4o7tZylQfK/Ebdq66B
         r8nGKNevwTi1x7XpNJKXQPOAFfxuqjnXbzRAFJfvbiRcVKpWxi+xqdYw6Ps+YPCtzUps
         bOow2qzavDnAiRq55r1HyvJSyhiMJsiAUvMLB0PjWAqbSGtojUj2lpxPpZJ17YrF13kJ
         ov3IjT2dB99u3l+7jgJPp6P9qIvX2wvHSaGszCGAa/djB50K0r2ABxCJbRHMgnhWrObI
         nOgioe5vwafdz4mO16pjOPjzhagJyPvH2PkqsLab3zTrBTKzYu3n0qg/HHKVkGq5hnTc
         xFpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MQaM98zF6Au3ifgBX1LN9vhnn6oLk/4qb19oOxSo2ys=;
        b=VyCv8Fd7ngmWEc535waMoob6Ec49BI2Tu1yZWFe8OhhA64xRJulhGGtxXMvkuM/aoe
         uvsIH/X3e4Ulb0X45ufUXa8JPC2Kzfrgi6AZiFCBqymma1tbaNIfALIBr/0HvDcPnS/Y
         s52CMbLrNoTdm2Qq5aow9MXt4w5FTVdMFtSVKcvjPCMeODqwR9b6uByiC0AoDNOtTrP6
         /mFrv6NwhUoX1SVSkp6jOVaFg8ISFij8OH1NzwJ/CRC8lmWrlVLYbN8MSOK4LxeLP/VV
         XVYWt+OVVIi/yUrXtLDbcun/hAwWecz2gMll94FKBJI1pEHF0X+K5joFwU0Yiy67z/UU
         91VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SigBH0gv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id w3-20020a627b03000000b0051c55b05eaesi121437pfc.5.2022.09.11.04.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 11 Sep 2022 04:52:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id z18so4411947qts.7
        for <kasan-dev@googlegroups.com>; Sun, 11 Sep 2022 04:52:06 -0700 (PDT)
X-Received: by 2002:a05:622a:14d1:b0:344:b14a:b22a with SMTP id
 u17-20020a05622a14d100b00344b14ab22amr18977092qtx.203.1662897125285; Sun, 11
 Sep 2022 04:52:05 -0700 (PDT)
MIME-Version: 1.0
References: <20220907071023.3838692-1-feng.tang@intel.com> <20220907071023.3838692-4-feng.tang@intel.com>
 <CA+fCnZeT_mYndXDYoi0LHCcDkOK4V1TR_omE6CKdbMf6iDwP+w@mail.gmail.com> <Yx1caGQ8R2alhOKh@feng-clx>
In-Reply-To: <Yx1caGQ8R2alhOKh@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 13:51:54 +0200
Message-ID: <CA+fCnZd1bDe9oQcCZjN+NTxs8qF3fzRoXcSZvyeCNxoX6U-wsg@mail.gmail.com>
Subject: Re: [PATCH v5 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Sang, Oliver" <oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=SigBH0gv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::831
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

On Sun, Sep 11, 2022 at 5:57 AM Feng Tang <feng.tang@intel.com> wrote:
>
> Hi Andrey,
>
> Thanks for reviewing this series!
>
> On Sun, Sep 11, 2022 at 07:14:55AM +0800, Andrey Konovalov wrote:
> > On Wed, Sep 7, 2022 at 9:11 AM Feng Tang <feng.tang@intel.com> wrote:
> > >
> > > When kasan is enabled for slab/slub, it may save kasan' free_meta
> > > data in the former part of slab object data area in slab object
> > > free path, which works fine.
> > >
> > > There is ongoing effort to extend slub's debug function which will
> > > redzone the latter part of kmalloc object area, and when both of
> > > the debug are enabled, there is possible conflict, especially when
> > > the kmalloc object has small size, as caught by 0Day bot [1]
> > >
> > > For better information for slab/slub, add free_meta's data size
> > > into 'struct kasan_cache', so that its users can take right action
> > > to avoid data conflict.
> > >
> > > [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> > > Reported-by: kernel test robot <oliver.sang@intel.com>
> > > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > > ---
> > >  include/linux/kasan.h | 2 ++
> > >  mm/kasan/common.c     | 2 ++
> > >  2 files changed, 4 insertions(+)
> > >
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index b092277bf48d..293bdaa0ba09 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
> > >  struct kasan_cache {
> > >         int alloc_meta_offset;
> > >         int free_meta_offset;
> > > +       /* size of free_meta data saved in object's data area */
> > > +       int free_meta_size_in_object;
> >
> > I thinks calling this field free_meta_size is clear enough. Thanks!
>
> Yes, the name does look long. The "in_object" was added to make it
> also a flag for whether the free meta is saved inside object's data
> area.
>
> For 'free_meta_size', the code logic in slub should be:
>
>   if (info->free_meta_offset == 0 &&
>         info->free_meta_size >= ...)

I'd say you can keep the current logic and just rename the field to
make it shorter. But up to you, I'm fine with either approach. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd1bDe9oQcCZjN%2BNTxs8qF3fzRoXcSZvyeCNxoX6U-wsg%40mail.gmail.com.
