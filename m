Return-Path: <kasan-dev+bncBDW2JDUY5AORBBO72CHAMGQEHNEOVRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C2FFB4840D6
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 12:29:11 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id d3-20020a17090a2a4300b001b22191073dsf25602406pjg.4
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jan 2022 03:29:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641295750; cv=pass;
        d=google.com; s=arc-20160816;
        b=ot7PsoXc7QcqnXB8wP9/IyDj0J9jB2Vyu6b7DIi1E+43TEAaSvSVAitDGsBavQJVCn
         VrQHFWLfediHby4h01WtVgUAH3P1fOau9gSyDRFv463Jt0aeXIQpFLNqnvCCMgLudSRq
         rGsSqu6eNDkbHeClQz/w10aMsq1HJ+IdgNXnehrjyFieGSdQtnoCRZ1mEfra2ZRq26js
         g5Iio6qEuO3RPCfNFFNF+NfVjM5lLuEJwJrQUJG/jZuZKcp0lP88N7DsYkAFJhmAqASy
         wbBSHxnX90T0XWleAoxql98GAQPKNnXz579QbUlqKqtCJoGS4gy6ib3ox2El7tVmzGPj
         rBjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=1TzGtT9XaFhdNBwjMp+WdMgwbYJauQHjjbtuiwheOOU=;
        b=sozNikSvqX/VRQ+Ap3wymYjRG0Mt/9pXk9mmY2IhhSf9D5JJaioR573msqCDDR8hBs
         80Ca6H4YOHWOMFu7yqXavy5yPh0ISB5+xnXnpirgjcefL6Rgk8/Uy1GFFPY8XaZ9Tb5T
         Ju8jsGAYulJ3Uqh68/Du9/Jrb9xruMY6+HHrEDjTIIXDsbYoGFngLSw4t4wXtjG+sfLj
         jddJ/J8QykMkZ/aAPAGiXljNFzLLOEUEeKLoYvnKOviAjAd2jKGaNXqz89Sy3KY27JFD
         LmtDFCLZ8C6xx15lxb1aM5Vc8oYom9AZlYSS0rnxfSEqGN8G1O0FK2pspA/ICYZPCSw3
         7AGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qL2vWPom;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TzGtT9XaFhdNBwjMp+WdMgwbYJauQHjjbtuiwheOOU=;
        b=kDE4t45ZGPMCQvDOfqnngKqjlUEBkV1SkU9dGI8MLMhhSERTdONR2j44zN3NZYvbIj
         XwI1xLBxG50KyxL14MHZnfeRbZVPQvGOQ4NkbcnZxv+q0gN+XERu7KFXXLqJCHFmz1hu
         dX+kATwPjQnAzMZga2TLha0+ROpY9CrKFBBImpt+RHiA0kezDRdSRU9w0ImTy3EXyID6
         GHpoh5zuuDCArGCCAY2TUO3E9aMHgBc26JvXDlSCL8YmJmVv6EkQ6bHOJUIDTQm986F+
         fa9L0HM8avx/asFO/zKeuXD2yW2bbTHKEobB32G2LDXvi4zf1wCdm8h1QFva0srPe7Yr
         phuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TzGtT9XaFhdNBwjMp+WdMgwbYJauQHjjbtuiwheOOU=;
        b=d2Uo8SBVINf4VLR7rsmpe+iiYPVhyUT+F0EyzUcplQq98HWJVS/tjdL2f/eLml+RAc
         sL+SFQdX9Hn+OJkOBtiupSGTzVSEkg4SX/SdG6ZDoaEZ7OQcLjsKcwLfhlHcyHhumZIA
         scjDeSv0Rj/MbvNYF3W47C2fruKtKV1DHpWGJ0GQQwPrXFDjOSZIqcwlllthKeMFtO4P
         KOM5ZOeJDJ0/6qrLYhXEMb73emIjpA7HkuGQagbmwEEMJjJ8R4wC5spoCN0yoW2J3+f3
         Gpzvjq72NdPOYT8pguVDiLd9Z/Fm9gQd/Rn3UTQ+5ZCFn43h6eO6MrULEGWbGD2t3num
         uYkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TzGtT9XaFhdNBwjMp+WdMgwbYJauQHjjbtuiwheOOU=;
        b=tcExrnOpF4wzVpnSGVY+tN3gzz0Y8+q/d9rG7wUAdhv/IeIciJ0tBN17s1725LR/Ue
         fWkimQiiKhWDc9oWhW0dTV4N6UeTAFyL0/DF8j2Ep61Ow05DmlLrIEN0X17s0syykqwo
         mDOsAyPBVT6CHpXIQCZi4N+31OnKdC5rTsZ5Pd0e18RcN2aimDgnYO4ov4ikZDldkNBK
         fmy8HbIqwg6I0Djrie/0L9Y3ZIeHSxteiu5cPGhOg6oSX3gGyrk7ynFvq5oyLW2Ijhmi
         QeW+KwIFPiJZK5DDfTFfhs/CLWjkTJ/EpNzS/4GDcUhizzAU7L2v7xgcU4mDtHfXdmDP
         ToTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lV/5qm8LOiDCnzMZCRZhVHlHaCZfdaCiqezepufS3xfePZIA2
	ohzOAmYSkQ++TcFEth46CMw=
X-Google-Smtp-Source: ABdhPJxagNm24DD0RfIN5W0odeOITEoYzsHz+TTZu88b82Z+8W7pIQE6wbA4F38iygEEIBuEgfhbXg==
X-Received: by 2002:a17:902:bd4b:b0:149:460a:9901 with SMTP id b11-20020a170902bd4b00b00149460a9901mr48960761plx.44.1641295750107;
        Tue, 04 Jan 2022 03:29:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:174d:: with SMTP id j13ls10269328pfc.0.gmail; Tue,
 04 Jan 2022 03:29:09 -0800 (PST)
X-Received: by 2002:a05:6a00:1946:b0:44d:8136:a4a4 with SMTP id s6-20020a056a00194600b0044d8136a4a4mr50488989pfk.46.1641295749564;
        Tue, 04 Jan 2022 03:29:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641295749; cv=none;
        d=google.com; s=arc-20160816;
        b=NXeb8EJJZJe6mnQ5lYgt4nO5vWMhRTAOeO/BuvIaxl7tEH8l4Y9YuqLditt7xYE5/t
         1JFVHduAlQj7oBFBYoGMGSFBuQQXGewK51XG1QK0LMnZjaF8ETdzn1H1hN/wv5H3oiOi
         wLmVNik8niPAX56ufwLKnZtrLVL5WkmMc6IeSmFNsktUNrUAjKYeodOgZ4UqQ/DLhY5U
         WG1te/KCzVrJRHhwiK4HKhjT+mBpvDRH17sqM62WUuvpn/aCNJ9CLyPojSqypVH1mZpz
         q65G5FWYfwf8qsCl2ven/VioB9yHp1HggKso7b+2rlPuO40zx+i1Y/OP1XAo4N4uJ60E
         l9nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PKqdYNUCxKzWzj64ePA/dIaYRd4jF6O5Lkt/GXeobao=;
        b=sszKHr4OHaWUvztOUOGNjCyWVlOCjQgeN2qIDRO9ulNgVXtu5lTXWtt4SR7KRGw8if
         mi9CPM/FIGr9O4NJSJ45EGIvZFX6dkCjz+xNiAadhU/ObldU0eIgaE3PbY4qcdJpBbKJ
         HBgyjXZPXeY82Pw9MABkQxuTjxjlqGkr/TO+NHnPqM5uDkMQMPUEyeuURLsz8JMFoGAh
         M/0gl2Qt3zhbJNR9LxKwQivTL2vg343jVCfgSDJgws3iLCOeSkS4U60VDzM15wxfWAAQ
         61+DT0PeaTtLVdNMRQdwRlFOAmLo7ukdIk8EuQjMT5Nalompz+EAK0dDBbcAxGoQgvw2
         xoKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qL2vWPom;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id k15si702974plk.3.2022.01.04.03.29.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Jan 2022 03:29:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id e8so28054455ilm.13
        for <kasan-dev@googlegroups.com>; Tue, 04 Jan 2022 03:29:09 -0800 (PST)
X-Received: by 2002:a05:6e02:1bec:: with SMTP id y12mr24360769ilv.233.1641295749226;
 Tue, 04 Jan 2022 03:29:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640891329.git.andreyknvl@google.com> <88f2964f4063aa6fd935ef8c8302d02d8d67005b.1640891329.git.andreyknvl@google.com>
 <b968e485f4d7f201fdb4e39f64ca757180e7374a.camel@mediatek.com>
In-Reply-To: <b968e485f4d7f201fdb4e39f64ca757180e7374a.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 4 Jan 2022 12:28:58 +0100
Message-ID: <CA+fCnZd4p+80MqOLJTa0-SwcXPbXe+n3FsCCN2dFHJ+bAsdZ-A@mail.gmail.com>
Subject: Re: [PATCH mm v5 29/39] kasan, page_alloc: allow skipping memory init
 for HW_TAGS
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qL2vWPom;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d
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

On Mon, Jan 3, 2022 at 3:32 AM Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Fri, 2021-12-31 at 03:14 +0800, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
> > initialization. The flag is only effective with HW_TAGS KASAN.
> >
> > This flag will be used by vmalloc code for page_alloc allocations
> > backing vmalloc() mappings in a following patch. The reason to skip
> > memory initialization for these pages in page_alloc is because
> > vmalloc
> > code will be initializing them instead.
> >
> > With the current implementation, when __GFP_SKIP_ZERO is provided,
> > __GFP_ZEROTAGS is ignored. This doesn't matter, as these two flags
> > are
> > never provided at the same time. However, if this is changed in the
> > future, this particular implementation detail can be changed as well.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > ---
> >
> > Changes v4->v5:
> > - Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.
> >
> > Changes v3->v4:
> > - Only define __GFP_SKIP_ZERO when CONFIG_KASAN_HW_TAGS is enabled.
> > - Add __GFP_SKIP_ZERO to include/trace/events/mmflags.h.
> > - Use proper kasan_hw_tags_enabled() check instead of
> >   IS_ENABLED(CONFIG_KASAN_HW_TAGS). Also add explicit checks for
> >   software modes.
> >
> > Changes v2->v3:
> > - Update patch description.
> >
> > Changes v1->v2:
> > - Add this patch.
> > ---
> >  include/linux/gfp.h            | 18 +++++++++++-------
> >  include/trace/events/mmflags.h |  1 +
> >  mm/page_alloc.c                | 18 +++++++++++++++++-
> >  3 files changed, 29 insertions(+), 8 deletions(-)
> >
> > diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> > index 487126f089e1..6eef3e447540 100644
> > --- a/include/linux/gfp.h
> > +++ b/include/linux/gfp.h
> > @@ -55,14 +55,16 @@ struct vm_area_struct;
> >  #define ___GFP_ACCOUNT               0x400000u
> >  #define ___GFP_ZEROTAGS              0x800000u
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > -#define ___GFP_SKIP_KASAN_UNPOISON   0x1000000u
> > -#define ___GFP_SKIP_KASAN_POISON     0x2000000u
> > +#define ___GFP_SKIP_ZERO             0x1000000u
> > +#define ___GFP_SKIP_KASAN_UNPOISON   0x2000000u
> > +#define ___GFP_SKIP_KASAN_POISON     0x4000000u
> >  #else
> > +#define ___GFP_SKIP_ZERO             0
> >  #define ___GFP_SKIP_KASAN_UNPOISON   0
> >  #define ___GFP_SKIP_KASAN_POISON     0
> >  #endif
> >  #ifdef CONFIG_LOCKDEP
> > -#define ___GFP_NOLOCKDEP     0x4000000u
> > +#define ___GFP_NOLOCKDEP     0x8000000u
> >  #else
> >  #define ___GFP_NOLOCKDEP     0
> >  #endif
> > @@ -235,9 +237,10 @@ struct vm_area_struct;
> >   * %__GFP_ZERO returns a zeroed page on success.
> >   *
> >   * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the
> > memory itself
> > - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> > This flag is
> > - * intended for optimization: setting memory tags at the same time
> > as zeroing
> > - * memory has minimal additional performace impact.
> > + * is being zeroed (either via __GFP_ZERO or via init_on_alloc,
> > provided that
> > + * __GFP_SKIP_ZERO is not set). This flag is intended for
> > optimization: setting
> > + * memory tags at the same time as zeroing memory has minimal
> > additional
> > + * performace impact.
> >   *
> >   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page
> > allocation.
> >   * Only effective in HW_TAGS mode.
> > @@ -249,6 +252,7 @@ struct vm_area_struct;
> >  #define __GFP_COMP   ((__force gfp_t)___GFP_COMP)
> >  #define __GFP_ZERO   ((__force gfp_t)___GFP_ZERO)
> >  #define __GFP_ZEROTAGS       ((__force gfp_t)___GFP_ZEROTAGS)
> > +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> >  #define __GFP_SKIP_KASAN_UNPOISON ((__force
> > gfp_t)___GFP_SKIP_KASAN_UNPOISON)
> >  #define __GFP_SKIP_KASAN_POISON   ((__force
> > gfp_t)___GFP_SKIP_KASAN_POISON)
> >
> > @@ -257,7 +261,7 @@ struct vm_area_struct;
> >
> >  /* Room for N __GFP_FOO bits */
> >  #define __GFP_BITS_SHIFT (24 +
> >       \
> > -                       2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +        \
> > +                       3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +        \
> >                         IS_ENABLED(CONFIG_LOCKDEP))
> >  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) -
> > 1))
> >
> > diff --git a/include/trace/events/mmflags.h
> > b/include/trace/events/mmflags.h
> > index 5ffc7bdce91f..0698c5d0f194 100644
> > --- a/include/trace/events/mmflags.h
> > +++ b/include/trace/events/mmflags.h
> > @@ -52,6 +52,7 @@
> >
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  #define __def_gfpflag_names_kasan ,
> >        \
> > +     {(unsigned long)__GFP_SKIP_ZERO,           "__GFP_SKIP_ZERO"},
> >   \
> >       {(unsigned
> > long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
> >       {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,
> > "__GFP_SKIP_KASAN_UNPOISON"}
> >  #else
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 102f0cd8815e..30da0e1f94f8 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2415,10 +2415,26 @@ static inline bool
> > should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> >       return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
> >  }
> >
> > +static inline bool should_skip_init(gfp_t flags)
> > +{
> > +     /* Don't skip if a software KASAN mode is enabled. */
> > +     if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > +         IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +             return false;
>
> Forget to drop the above check?
>
> I saw v4 mentioned that this check can be dropped. [1]
>
> Do I miss something?
>
> [1] https://lkml.org/lkml/2021/12/30/450

Right, forgot to include this change. Will include into v5 or post as
a standalone fix closer to rc1. Thanks for noticing!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd4p%2B80MqOLJTa0-SwcXPbXe%2Bn3FsCCN2dFHJ%2BbAsdZ-A%40mail.gmail.com.
