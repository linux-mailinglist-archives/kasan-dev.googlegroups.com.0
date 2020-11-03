Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3XQQX6QKGQE4OHIHYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 824652A49F3
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 16:34:07 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id l17sf10711135iol.17
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 07:34:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604417646; cv=pass;
        d=google.com; s=arc-20160816;
        b=TUNPnThFCaTz0bwlcitKfc70cRtE46gaEF27CJ9RL0a4bz2gEigfAm1dE+8uozjGrh
         LoAHjCtY49WXMezedbhNM/8rvm4EzlACHY5FDh9yPQEnw7fwSGiIvUpHqWNbzRxZD7/F
         IKVhxaytiClO0SgdQB/av0tGD7BDkVmMcigJ448HgZHDaSmf5FDEsoU0N+o/r43LIzOl
         MpiFC6juG4xD5Rp2+AUQadJNTRTXD8LZqM/vJe4jG9/tmRqFZHRFWZ1uhxYfglA5l6g1
         IUOFULsmvsc9RxYiaUZKDLELLK+0ifEJLPxsrRUJfKPtg0qySr4w4I8+1RWcFQSD+t93
         dS0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wWRHTVuCgQDolk9NSr4uT3L7b+fMuMf8b7l13k2mxGM=;
        b=Or74XcCRwlIhKVLjPhiclpKb6/wxiX6ZXGCbPkfluQBucjLK7sgvBmvmxYVoN1ETuI
         F92lo/qZnDW+iqBdVLaLojWc2KyBPHmZ2Tn6omDKYVObOWARUEMcik0BNynvNBWfMgJF
         SZpm2c//Tak+OD/ategaov7pftGoMtV8FAzz1y7d4JMKBLA8TYsffyrr4omflRuh5Cev
         DvzGcpXYkpnAYfC3RQsyYa8/5vk7mxbclKG2Q2SDbREmpeLRmpoUyyn+Kq9xCH4Gle9G
         x+SLpCwwZuJ/lwz2Ycr66ZUIU4t000M3Rbn9SCuqJ7eGaTvj5XcUh2G1+NPNaQlupUjT
         8IXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iP5XPK46;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wWRHTVuCgQDolk9NSr4uT3L7b+fMuMf8b7l13k2mxGM=;
        b=ExSg7SITtvrQ84wT63zRr7wbY4Jr6V+98H3R7+ig9GH/+KU9ITtIAbe/TjJfAXmVSA
         3zIsmmuHqmtiGS9Ee0KNQTTy6+z+lD6FROut2xYPm/GVW+KjvuxDYM1Wa5duNa9ggLMV
         lHKLRP1CxlTVCaBLIj6YzVldfejYmHF1aamQxAMkojnv3avrqg36p1IQR6njScHkbnca
         aNPKO45xETdWo6ZJPS5Lv6l79cTKIfbp5//F64fupfJ57gGlrzMfSyn77DA9bXs41dNB
         rt0ipB9qC/H/NyshfXDCZ8xDTpnhagNIuK/KYQgJwxsI/8R0lpij6IHqjDDWSMyaAPf3
         emFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wWRHTVuCgQDolk9NSr4uT3L7b+fMuMf8b7l13k2mxGM=;
        b=bYtMj/SqqjnNVDnw91oepnWYNfD9AdAN89WG98Q1zTzV1y2/xmN7zVpb4s32fbdmMH
         s2blkreuQEFDI2IqfSWJ9bsOnwFNtONWU8Q5TGR3zqOmWUWrV/i3pHbQvfqUSpD+G0R3
         k6VeiYCFvP8mOKOXsAVkLY9PQ9xpZqFgiiKP0xKLpx7yJG5J5Sz/scStptANhw1GsR43
         DHBBMqm2T/BxFWkSnFU2a6iHrKkS8dQQITB9vngEi0kJRnyn9VQ6ML7VWWXlPcw8j5MS
         jEsMMcS88cdYAXRMe+DT6N12Vq25PVTQTzIoymkzXGlbeZozg6tNh5PXCiF/OLPGqief
         XOBg==
X-Gm-Message-State: AOAM533910LQdGwCd37le4Ke0enFj7Ed7Hxiujx7HLK7eoiCzl6uoD+Y
	hU21YA2hhWjbCzQd1YiiPqo=
X-Google-Smtp-Source: ABdhPJyRWTsKpcugi2oRWnyfC4V7ywXMhWIB+NvOWrNndLtmrAbAyl+y3PfvqAfHb8R1KOLxUD8EYg==
X-Received: by 2002:a92:d449:: with SMTP id r9mr4739001ilm.276.1604417646250;
        Tue, 03 Nov 2020 07:34:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:84ce:: with SMTP id y75ls503221ilk.1.gmail; Tue, 03 Nov
 2020 07:34:05 -0800 (PST)
X-Received: by 2002:a92:dc0f:: with SMTP id t15mr15434428iln.1.1604417645919;
        Tue, 03 Nov 2020 07:34:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604417645; cv=none;
        d=google.com; s=arc-20160816;
        b=dND5Lv63yrHGZkXs1+R2XaO6XQVY29BXgdQrnOCxR6X7TcVrKyhCjEs14fNCWre9XS
         18l8Xr8Op/I1152G90aKEqxJoXlcxkXHCfSCYQZ+wZnnfEHQdNXcGIAFTLUP1K/i3QOH
         8GwXKZJK9hLpsG4yh1h8SKX+PYKDDThOaBc3CkhGDLgaQTnDnjnvNLaYsFI1OSvMM0mG
         isGO627Lvyna9eyzScIADgAfTTT0lOex+QgiDnKHQo+HdZLxOwLJ91neJcbEEOI4c1TZ
         i7fL2Uj5YigNZf9FBi/s2JESNpYa4XmTXItX4VvKBZ3lTDUnCJ2mXY22PpxkftOAogiV
         j4fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HjUJI0OrjkWbAH3DienhZxTmqOna3ueAap2yYKG4ygM=;
        b=kgTwflFa40ELF3Fc/MmT2B/6dbhtFst9+JYIdiMaiZ3pWUrvIQKvI2epdMjo073B3S
         4f7mC7Wq2cg9gTfousACLO+D3mJi5iF5FElzCGa5JMNnofnWfm7zDBfTAOg1iLn9obOK
         YBpSTKWpmOvrvMTOb8leqaeFtwlQghP8w4sSeEfkqjBJiPo40EXkngfChTADOULz0H1F
         +PPvLTIlT3OMygZylZIYeB94q7y9lM8v9o1mClexY5DhpMBVy/LQkokiUfMQqK8fNsGP
         nh6F5z7nfKZ/GryKuSROB0QhxLA9v7hu6hwPETfOAQQ//RuTe4EDlYFR36om5rHOMMpL
         8scA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iP5XPK46;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id u15si1033852ilk.1.2020.11.03.07.34.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 07:34:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id w4so3726905pgg.13
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 07:34:05 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr356174pjz.136.1604417645395;
 Tue, 03 Nov 2020 07:34:05 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Y6jbXh28U=9oK_1ihMhePRhZ6WP9vBwr8nVm_aU3BmNQ@mail.gmail.com> <CAAeHK+wqdtPkrhbxPanu79iCJxdYczKQ6k7+8u-hnC5JONEgNQ@mail.gmail.com>
In-Reply-To: <CAAeHK+wqdtPkrhbxPanu79iCJxdYczKQ6k7+8u-hnC5JONEgNQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 16:33:54 +0100
Message-ID: <CAAeHK+xBZ_Rkew==1pj1YzU9XGdMJx5_uMP6n=BnnqdAH7LARw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 07/21] kasan, arm64: move initialization message
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iP5XPK46;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Oct 29, 2020 at 9:14 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Oct 28, 2020 at 11:56 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > Tag-based KASAN modes are fully initialized with kasan_init_tags(),
> > > while the generic mode only requireds kasan_init(). Move the
> > > initialization message for tag-based modes into kasan_init_tags().
> > >
> > > Also fix pr_fmt() usage for KASAN code: generic mode doesn't need it,
> >
> > Why doesn't it need it? What's the difference with tag modes?
>
> I need to reword the patch descriptions: it's not the mode that
> doesn't need it, it's the generic.c file, as it doesn't use any pr_*()
> functions.
>
> >
> > > tag-based modes should use "kasan:" instead of KBUILD_MODNAME.
> >
> > With generic KASAN I currently see:
> >
> > [    0.571473][    T0] kasan: KernelAddressSanitizer initialized
> >
> > So KBUILD_MODNAME somehow works. Is there some difference between files?
>
> That code is printed from arch/xxx/mm/kasan_init*.c, which has its own
> pr_fmt defined.
>
> >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Link: https://linux-review.googlesource.com/id/Idfd1e50625ffdf42dfc3dbf7455b11bd200a0a49
> > > ---
> > >  arch/arm64/mm/kasan_init.c | 3 +++
> > >  mm/kasan/generic.c         | 2 --
> > >  mm/kasan/hw_tags.c         | 4 ++++
> > >  mm/kasan/sw_tags.c         | 4 +++-
> > >  4 files changed, 10 insertions(+), 3 deletions(-)
> > >
> > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> > > index b6b9d55bb72e..8f17fa834b62 100644
> > > --- a/arch/arm64/mm/kasan_init.c
> > > +++ b/arch/arm64/mm/kasan_init.c
> > > @@ -290,5 +290,8 @@ void __init kasan_init(void)
> > >  {
> > >         kasan_init_shadow();
> > >         kasan_init_depth();
> > > +#if defined(CONFIG_KASAN_GENERIC)
> > > +       /* CONFIG_KASAN_SW/HW_TAGS also requires kasan_init_tags(). */
> >
> > A bit cleaner way may be to introduce kasan_init_early() and
> > kasan_init_late(). Late() will do tag init and always print the
> > message.
>
> It appears we'll also need kasan_init_even_later() for some
> MTE-related stuff. I'll try to figure out some sane naming scheme here
> and include it into the next version.

Actually, it looks like some arches already have
kasan_init_early/late() along with kasan_init(). I'd say we better
keep those for generic KASAN mode, and kasan_init_tags() for tag-based
modes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxBZ_Rkew%3D%3D1pj1YzU9XGdMJx5_uMP6n%3DBnnqdAH7LARw%40mail.gmail.com.
