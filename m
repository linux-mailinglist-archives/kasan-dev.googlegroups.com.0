Return-Path: <kasan-dev+bncBDW2JDUY5AORBLXOQOHAMGQEST5IHEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5767C47B545
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:35:44 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id s8-20020a63af48000000b002e6c10ac245sf7576435pgo.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:35:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640036142; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQjng6tKTMuTmiaBLB2iZgEZbhGfm3BJW2qhhYPLeBFj0snLje4syABLeHWOb8TouE
         3HIjOPENypqIE4/tTiGCB3nMAxItSrjfVsKxaGFT9Vg/Rm9x3EJ73Ky7hxqgOw2OYubP
         ik/+GMv6j0y1VyLdmyvaoviPWYOJxgbCWIq8bPLM7GyoVpwGUNXl9DvNbRIo9p+RRQx4
         Wx8qw3G5We2CHZ9RUT49m2nvygXeg5oNAcSqBpS+1T4MqRTd/8y9bl0KNeIKwBxPPW4b
         qrwurxhbVU3cE43QM3gN5dA1wZ5yI7Xh3IvfIhVmj+7Q+tyHib5vB/NDRYp+LN/gujzh
         MMIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iyrhHrF+VM5CI4bJJDw0tR5XW6Ni/j8ZDI/x80RpMbI=;
        b=yhOn9atU0ezE7gaxzVNWi525RqD3WdGHLiKOEAvy+LpyyJzeiDUj36L0EMTEpUP0LI
         vh8KzRUUqnh5AEVBznf6ALmjetNbtMfiLZ7F+POfpa6r9l6vPsNh6C8iLRrw7NopOLLt
         pfuHO/SLhw/J9v8E0FPk05xP8dzCdrSQTKN78bp1TKzla0A+kogT7Zt4No7/d1mbz72E
         XLz0IWoYdNwM5DG6arrF8JozZEcPbJzX6djx03OOQRyYe1v867NPdnNEfVn5Esjb++Xl
         XM3apAZKOzUXjxbIFpepxhB++tIngI5QGm8cv2WTQiIDTcAUDhakd2SfoEnypS8bB9TD
         Bi9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qmMCnZ2C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iyrhHrF+VM5CI4bJJDw0tR5XW6Ni/j8ZDI/x80RpMbI=;
        b=ctkEulZRW8nZuV+2aVRPOvSPjJz4DaqpJBrPU/M3q3dgsz6yoCQ95JbMKSIPyY2niP
         Dblspsed0Y2B9bm7U/uMUO3yFxY9cTMPxWkN1aGqjJ0+ctdskiyFHcawcvFqmgmP5iMJ
         LffeEXs5RM0aMaQUnZlH3mUPCUFOV4cYf+f/mVgrjb+BJCc6QvpWrnCvEFptme+8ukY0
         uSB3XeaYYXvelhuCKd8PpITDg219s9gpgOTG7WMb00YOaKo77fQ37frPKsqAmIqqhVqH
         9YsphpCp227pvXPs3tJ52hZwzOYF2KH37sbeyxapGODmi+bXknTyhRIxnqWa5R+TWkUK
         jxIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iyrhHrF+VM5CI4bJJDw0tR5XW6Ni/j8ZDI/x80RpMbI=;
        b=iMEN8A2Y7IMpocN6I4zEAwBFau/tJU76H0VIUW7Cz8TR/QSjrIuT1VObmCK+QRjGgc
         bYEvSnvX890/NNwj5dKeqYB9Rl5dBhY1jousWbm4sZMyyHXqnI6T1Xr3yGn0NbQ7QXBE
         H4/dE//VNarqqLi69Bz1bhLj5ns+cwO/2Iacv4+tNIICHLc85P8D97YubAaSDI+0wowe
         ouluXzJOeIQXaQuwUdimh6u5hOsg8K6PsK5cZywk/PvYstBev21dgXg7o4iLqNK+R61k
         Qv19weml3A0Hr87MRVpCP24jePTMNG/3g/sAP/KWsXTfX9tpLyTRDtdQ1WB0PbJy0sHd
         OKJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iyrhHrF+VM5CI4bJJDw0tR5XW6Ni/j8ZDI/x80RpMbI=;
        b=jBxWwLi01sDqx6r6Rri2TJ7lyvpKugfRIRCtEbvxJm/9pa5cmy8u+DGPLrdkGt2+ig
         nbppTeT7OeZizc/6mxt6wC/T8b4Bf5JHT/LpSfKJzXW+uxVMa5DjXmvWEhB9BOqgaMpF
         T13J9Uj9PpnDuIdoFirvqXqC/31M9BGN7F2ZmwFYm2fUwAwMA7dBNFKUb1BuHDSBkgh/
         YvpJvZDquKVkxqwYPB8DGPu35D7ewW6M9n4wluE+HEAje67/Yg/61zGUml7dZmn/SDkg
         NZ5cjcM4IkaqP6/mGgsMXyytX1V54kWNtsL4I7HiClvGnJ+2zNTka5IbeLANTqBI6sXR
         O9iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e7O/C/v3lOROb3z7iEdzoIQ4suiq968XJYpEOYPy8k3QnpAZQ
	ksDNJxKMMjhvHSNJeqEt0uY=
X-Google-Smtp-Source: ABdhPJwTCpvzoc9+BocKS1sr3jdGLUq3S+lwzRbZ+A7DNKBZdDX0BQoHLwaQq5e1WWqqnKbXkJFknA==
X-Received: by 2002:a17:903:2283:b0:148:a2f7:9d60 with SMTP id b3-20020a170903228300b00148a2f79d60mr12066282plh.127.1640036142717;
        Mon, 20 Dec 2021 13:35:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:11c6:: with SMTP id q6ls2839531plh.2.gmail; Mon, 20
 Dec 2021 13:35:42 -0800 (PST)
X-Received: by 2002:a17:90b:3ec4:: with SMTP id rm4mr172300pjb.88.1640036142154;
        Mon, 20 Dec 2021 13:35:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640036142; cv=none;
        d=google.com; s=arc-20160816;
        b=XZ2JiLQe4eZMlM/E53QsaTWLti7d1xK7XrElB1MhctMqJQmg4IHKvDSRN8uqItdgxL
         y5QgjeEZAr1T37r7oTktZRR2jHwrnkL8rWsNM9B8AJQbMltpDz+mr1GGAroQkMRoVLxP
         Gq+Dhp9qLeqYyAPTo6wU6sc34y8j5HukIlymFgWQ5F3BDmx5Lj6pxgXQXPCWo12zR0w5
         gWdIYcin7et9F/kZFlL1WcJwsMqSlOkO1k0RPR7rdDM1ffm/HjqNrZsbu/nQMIPnFF1p
         UVxBi7/4r5UvZveHyJ7JLwkbOzf0L8Nqr+1mnDWL1uPhCJp8wjVlS6ZIi+bIaS/JBQHD
         TsRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mHpnB8CgjO+Yms6LesT1nUtQhl96Ut7K5WNqbdqk9YA=;
        b=bMSHf2Yxl/9iyOjYsNpL63MtxkEJqyI6Mk3AN+paKUqnxzP3okGY18vyQjZe9KWGz8
         M4DCICxY365NhvIyVlcB+BqV3BPhDzJuj2KPTPOawzZ36vVATeUpXSxVbo6RXdeoHlri
         DJqtqFt58QXrB26+FxP7PQmga4OkKII+VUK4nDS7wqbjtV6oFhulFwZWgiKCzwVfw6if
         ol0ok6PQT/jlBGzixCy9NzxAU/OZd2FGsKeJj2Bkb/EY7GSVlWXcA63N99hEwVeBl8Jc
         xQfybhL2q9aT4pgskakOYHJBX9CrJoXnPetdf+AQBgw4Tu/QsRV2gx6rmDzuvlR72DdA
         FIVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qmMCnZ2C;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id fa11si32277pjb.0.2021.12.20.13.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 13:35:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id x6so14960888iol.13
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 13:35:42 -0800 (PST)
X-Received: by 2002:a05:6638:3449:: with SMTP id q9mr84508jav.218.1640036141911;
 Mon, 20 Dec 2021 13:35:41 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
 <bf06044e10b5eae36c9ac6ad0d56c77b35ca8585.camel@mediatek.com>
In-Reply-To: <bf06044e10b5eae36c9ac6ad0d56c77b35ca8585.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 22:35:31 +0100
Message-ID: <CA+fCnZe1Szu7V6PbWpBBiOJfUV0-YO03wpR_L6zn_nJ06-UfAQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 28/38] kasan, page_alloc: allow skipping memory init
 for HW_TAGS
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qmMCnZ2C;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33
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

On Fri, Dec 17, 2021 at 2:50 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Tue, 2021-12-14 at 05:54 +0800, andrey.konovalov@linux.dev wrote:
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
> > Changes v2->v3:
> > - Update patch description.
> >
> > Changes v1->v2:
> > - Add this patch.
> > ---
> >  include/linux/gfp.h | 16 +++++++++++-----
> >  mm/page_alloc.c     | 13 ++++++++++++-
> >  2 files changed, 23 insertions(+), 6 deletions(-)
> >
> > diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> > index 6781f84345d1..b8b1a7198186 100644
> > --- a/include/linux/gfp.h
> > +++ b/include/linux/gfp.h
> > @@ -54,10 +54,11 @@ struct vm_area_struct;
> >  #define ___GFP_THISNODE              0x200000u
> >  #define ___GFP_ACCOUNT               0x400000u
> >  #define ___GFP_ZEROTAGS              0x800000u
> > -#define ___GFP_SKIP_KASAN_UNPOISON   0x1000000u
> > -#define ___GFP_SKIP_KASAN_POISON     0x2000000u
> > +#define ___GFP_SKIP_ZERO     0x1000000u
> > +#define ___GFP_SKIP_KASAN_UNPOISON   0x2000000u
> > +#define ___GFP_SKIP_KASAN_POISON     0x4000000u
> >  #ifdef CONFIG_LOCKDEP
> > -#define ___GFP_NOLOCKDEP     0x4000000u
> > +#define ___GFP_NOLOCKDEP     0x8000000u
> >  #else
> >  #define ___GFP_NOLOCKDEP     0
> >  #endif
> > @@ -230,7 +231,11 @@ struct vm_area_struct;
> >   * %__GFP_ZERO returns a zeroed page on success.
> >   *
> >   * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the
> > memory itself
> > - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> > + * is being zeroed (either via __GFP_ZERO or via init_on_alloc,
> > provided that
> > + * __GFP_SKIP_ZERO is not set).
> > + *
> > + * %__GFP_SKIP_ZERO makes page_alloc skip zeroing memory.
> > + * Only effective when HW_TAGS KASAN is enabled.
> >   *
> >   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page
> > allocation.
> >   * Only effective in HW_TAGS mode.
> > @@ -242,6 +247,7 @@ struct vm_area_struct;
> >  #define __GFP_COMP   ((__force gfp_t)___GFP_COMP)
> >  #define __GFP_ZERO   ((__force gfp_t)___GFP_ZERO)
> >  #define __GFP_ZEROTAGS       ((__force gfp_t)___GFP_ZEROTAGS)
> > +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> >  #define __GFP_SKIP_KASAN_UNPOISON ((__force
> > gfp_t)___GFP_SKIP_KASAN_UNPOISON)
> >  #define __GFP_SKIP_KASAN_POISON   ((__force
> > gfp_t)___GFP_SKIP_KASAN_POISON)
> >
> > @@ -249,7 +255,7 @@ struct vm_area_struct;
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> >  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) -
> > 1))
> >
> >  /**
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index f1d5b80591c4..af7516a2d5ea 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2409,10 +2409,21 @@ static inline bool
> > should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> >       return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
> >  }
> >
> > +static inline bool should_skip_init(gfp_t flags)
> > +{
> > +     /* Don't skip if a software KASAN mode is enabled. */
> > +     if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> > +             return false;
> > +
>
> Hi Andrey,
>
> Should we use kasan_hw_tags_enabled() in should_skip_init() function
> instead of checking the config?
>
> I think we should handle the condition which is CONFIG_KASAN_HW_TAGS=y
> and command line="kasan=off".

Hi Kuan-Ying,

You are right! Will fix in v4.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe1Szu7V6PbWpBBiOJfUV0-YO03wpR_L6zn_nJ06-UfAQ%40mail.gmail.com.
