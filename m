Return-Path: <kasan-dev+bncBCMIZB7QWENRBTNC73TQKGQEQCOZFKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BFE5B3CA10
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 13:32:30 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id d6sf12433834ybj.16
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 04:32:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560252749; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZEaFFlDLdWpsZo+kIlusMjvs/K2YyfwMeda+dI8CSK5V9vJJ6MUPThztvrdsb69pL
         8acaVhXhh6mJcDrP/8bEkXpl1ne/Wr33ZtOZfoAme6ryRpPNFiDtZvXusWbaOQBSpH3i
         Raf4CcMTEyFbByFm957grKNtQ4q/9UYv2bBmluzIhWY+OcXKFOaE69gqtabQJsPVHFDe
         nJ3EWiU13DdvsNm4qYY2naBjoPtE3t5tCYdjDmaxpYh6bhOCTT/sNve+LJ2pFb5kcGSJ
         Eh9P4Q+YOswOiWBFf1DK6+mpGsPfBeOG9sk8ekzdFTBmyqV9rDeW7EaOvuikAPTLLfZx
         4DtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ysXIMYmW+hxQQYMtI2yGOYoPZc+WfHEeJjvbvb1HgDY=;
        b=X7HRox5p6DcMH5gW17Y335POhXRffg69Auk5e+3azz2rsxwaaW1Hhk7z4Q4jP0WBoY
         Yf2jzw9ZWkhV7kFsr+A0rftuqZSBWXelrmLbgKT9vpTxiykwsmgl8uYdzoeolgBgBlTz
         ko0heWqRHvIsNNeMqFUM900VNgTyGwiA+iWBR1WZfcdIkoLHBGGuQbnRXBS2ydQatSNg
         IaRHYGCDKqD4kIKuR/sdqMfz5HgOU9kQTne/wVfncSrLFIUgpy5rU/4tHNRvGiti8UZV
         dDYMlgiJubx8qDAL7QggSoTDwmuWhLcEsuCqYbxn0UMHZ3s2IOvGOTqehvgfcZ6S341W
         OSrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TlTFwFIx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ysXIMYmW+hxQQYMtI2yGOYoPZc+WfHEeJjvbvb1HgDY=;
        b=NcMaJsV61ZjrS2Xp3u489aRoCj/AsxU8tr5U9lTOtZzc+iLIQ0nrG2HDCeT0sIBIUr
         V5EPgDyygLeWZ+ET5CuhQofpMFL8g8Kdp7eIKF/M5OglWi+qJ2o16hD7g6cyxPQ5bNIx
         2+ImGJesxGB/6dmDBs+5jFj2otcaqtpnyvXIkXUjA7ztEFJMnGkwrWO6oAub/jkYHfKQ
         EQSi0atly23PHMbl9QkTvD3Kl/AL1eVfvouGCD5y+8eiprfNtRjFqqzmuFZa+aO90OQB
         3khTjS/NtvhQU8s/Fr/O36o2yqSSQ70UBkM1gPvFUWC2d4NNNN/X30CBlVXOaPnFbiSV
         5cQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ysXIMYmW+hxQQYMtI2yGOYoPZc+WfHEeJjvbvb1HgDY=;
        b=FizUiFT22t75hd3A5gC7G4DCmiCesLw5FRvo7ZBiF7vMKqB+bztUI5SwUTHzYIhFcc
         5sCZBeRqm/uH5xIU0EToZblEUcNFeAwsR/CgzUps9BOZT5eePRNn+1uI/mhWdF4M58/f
         G9Aco/GHXz84obAel7B6wSABbvtOV4gRtwzIcxQnD3CUeiWS+jX4QaUoPJILTjniKvy5
         ++5C+DsmQgUdNR8OHt3GJP7BDI0FN7w7WGN5JM3BZu2+jNwOP/WgnwgjUXlk5dVOW2Pc
         4IghdjeQsGUa036r5CQacygIfL+EYO0mfStBaN/bbqkDYnBymIVVFEWt2dkzoYkguWDn
         bxvg==
X-Gm-Message-State: APjAAAUSN87XHYgSAz00suvieSxFsvJL3KBRi8Ps0Mg/K743eff4f7Ot
	JQurV2mAavQ94BJSYr8807Y=
X-Google-Smtp-Source: APXvYqwXiB+u0CNbrgmLhrYwdTjQI3DgadfoFHUcpSP1mO1HBqtfG1UXGmjGtjCWaT9JgY5p1A+7ZQ==
X-Received: by 2002:a81:4b92:: with SMTP id y140mr30232690ywa.264.1560252749615;
        Tue, 11 Jun 2019 04:32:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e301:: with SMTP id m1ls1073076ywe.3.gmail; Tue, 11 Jun
 2019 04:32:29 -0700 (PDT)
X-Received: by 2002:a81:6155:: with SMTP id v82mr40757118ywb.317.1560252749295;
        Tue, 11 Jun 2019 04:32:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560252749; cv=none;
        d=google.com; s=arc-20160816;
        b=qy7q6X+4mCO18d9VSjjb0I2xeWfVjyEq0D5fDLG+vgkwj3qiWfw9lMacJOfa+gEu2O
         7KAlrYuDnyFSDPDd+XaoV2bgzgoc2v9FQoPPxkQpFEPGPBLJf4AgWT0at1uulxRIfbwD
         PcBWN5JQ/pQXmmfk8SH0+7svgmMLdjRS9cZLZgZzpdtQUfUtU761aGh5wMLcf93txpzz
         okHakndtx132y1j6WsnYoQticW6CtFluiz9QG6YW91BQ8tXdStkIgCuW971urOQP/vOp
         CdIRbRYGl/qswXW+aLfcfm/rDCSL3MkkOJ+KyR0I78f2h3RwWRbtsVoDXEs+Wa+eaDJC
         X5FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GJ5KMjkPulVIlquMhDg/I0WD4XAnjse8O6WtWcGUz4E=;
        b=JyGT13u7rU1t57I9NwD6NZolMg0ljsRq8+wfDJxH+JY4CtwsN++W1ZaM79mn/0rvb1
         kWnT9TNxQn5e/ncP1KDkcbWBuFNucssR5thnu9Gbjk8kbmrZ0YZ1JonqAkvk0qov9f/y
         HMiAhfanrHhFwnlGjMWaHZeSbFKprHNbT3Trj98cgh1b4xHzQJOGnqjkvKwqImgEk/sq
         GgA79A3H/kFf+euioex9XPlDrx1w6bBmdsrIvk+pgv9c6Z89Ns0HoAxsB3cNYiuxlidx
         kfGidwAmYKjTuGI9RRwSGcjXO6IVW2U1kCmCrEGVcrlCQRwU52/Fw8db9z5T47fjh3PR
         L2cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TlTFwFIx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id e21si586752ybh.4.2019.06.11.04.32.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 04:32:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id k8so9586194iot.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2019 04:32:29 -0700 (PDT)
X-Received: by 2002:a6b:641a:: with SMTP id t26mr3295112iog.3.1560252747608;
 Tue, 11 Jun 2019 04:32:27 -0700 (PDT)
MIME-Version: 1.0
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
 <1560151690.20384.3.camel@mtksdccf07> <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
 <1560236742.4832.34.camel@mtksdccf07> <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
 <1560249891.29153.4.camel@mtksdccf07>
In-Reply-To: <1560249891.29153.4.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2019 13:32:16 +0200
Message-ID: <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, =?UTF-8?B?TWlsZXMgQ2hlbiAo6Zmz5rCR5qi6KQ==?= <Miles.Chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TlTFwFIx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44
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

On Tue, Jun 11, 2019 at 12:44 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Tue, 2019-06-11 at 10:47 +0200, Dmitry Vyukov wrote:
> > On Tue, Jun 11, 2019 at 9:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> > > > On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > >
> > > > > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > > > index b40ea104dd36..be0667225b58 100644
> > > > > > > --- a/include/linux/kasan.h
> > > > > > > +++ b/include/linux/kasan.h
> > > > > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > > > >
> > > > > > >  #else /* CONFIG_KASAN_GENERIC */
> > > > > > >
> > > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > > > > +#else
> > > > > >
> > > > > > Please restructure the code so that we don't duplicate this function
> > > > > > name 3 times in this header.
> > > > > >
> > > > > We have fixed it, Thank you for your reminder.
> > > > >
> > > > >
> > > > > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > > > > +#endif
> > > > > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > > > >
> > > > > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > > > > index 9950b660e62d..17a4952c5eee 100644
> > > > > > > --- a/lib/Kconfig.kasan
> > > > > > > +++ b/lib/Kconfig.kasan
> > > > > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > > > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > > > > >           4-level paging instead.
> > > > > > >
> > > > > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > > > > +       bool "Enable memory corruption idenitfication"
> > > > > >
> > > > > > s/idenitfication/identification/
> > > > > >
> > > > > I should replace my glasses.
> > > > >
> > > > >
> > > > > > > +       depends on KASAN_SW_TAGS
> > > > > > > +       help
> > > > > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > > > > +         This will make it easier for programmers to see the memory corruption
> > > > > > > +         problem.
> > > > > >
> > > > > > This description looks like a change description, i.e. it describes
> > > > > > the current behavior and how it changes. I think code comments should
> > > > > > not have such, they should describe the current state of the things.
> > > > > > It should also mention the trade-off, otherwise it raises reasonable
> > > > > > questions like "why it's not enabled by default?" and "why do I ever
> > > > > > want to not enable it?".
> > > > > > I would do something like:
> > > > > >
> > > > > > This option enables best-effort identification of bug type
> > > > > > (use-after-free or out-of-bounds)
> > > > > > at the cost of increased memory consumption for object quarantine.
> > > > > >
> > > > > I totally agree with your comments. Would you think we should try to add the cost?
> > > > > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> > > >
> > > > Hi,
> > > >
> > > > I don't understand the question. We should not add costs if not
> > > > necessary. Or you mean why we should add _docs_ regarding the cost? Or
> > > > what?
> > > >
> > > I mean the description of option. Should it add the description for
> > > memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
> > > memory costs. So We originally think it is possible to add the
> > > description, if users want to enable it, maybe they want to know its
> > > memory costs.
> > >
> > > If you think it is not necessary, we will not add it.
> >
> > Full description of memory costs for normal KASAN mode and
> > KASAN_SW_TAGS should probably go into
> > Documentation/dev-tools/kasan.rst rather then into config description
> > because it may be too lengthy.
> >
> Thanks your reminder.
>
> > I mentioned memory costs for this config because otherwise it's
> > unclear why would one ever want to _not_ enable this option. If it
> > would only have positive effects, then it should be enabled all the
> > time and should not be a config option at all.
>
> Sorry, I don't get your full meaning.
> You think not to add the memory costs into the description of config ?
> or need to add it? or make it not be a config option(default enabled)?

Yes, I think we need to include mention of additional cost into _this_
new config.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaXqjCMaJego3yeSG1eR1%2BvkJkx5GB%2Bxsy5cpGvAtTnDA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
