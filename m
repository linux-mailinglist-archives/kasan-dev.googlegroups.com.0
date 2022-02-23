Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUMJ3OIAMGQEEXZIALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id B75284C1FC2
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 00:35:46 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id w3-20020a17090ac98300b001b8b914e91asf304606pjt.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 15:35:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645659345; cv=pass;
        d=google.com; s=arc-20160816;
        b=wUb8Q5vtq8mbArSGTf8pNayLjstt16OmMgI+m3X4hyxPhzwLypQbJVJX5rbfoR6Nx9
         b/fW2myAoFy8SFcb13dkQs8aQqgYQWctDdTwBPigu1pd9SMM6d7G8acsjbPQxI4u1f0/
         VEJ3DyjTFtiNfz/swCGInZcVMMI7uwfrdtHiuLhOE3c3CIwnDTjAOAgq5fr3bAnPfOhN
         2pRH6Nlb4VCKeTXrAFBgJdi1pNVDxXwBZN5QJl3QvV+u27b/n4R+rQ87QK1UewAhgtM6
         5dUD1/60XHr8SWXliXQpiFHzC4mKkHfXm1lrhEpKPPIZkbhZgaN2OMEXaXpIH1not7ii
         E0pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Aqj/uneunH4bF0QtOZRKHTif3OZCVHcw2FcuLjqO6Ns=;
        b=w8i3RXklC0kidgHlDYUNYKV/sAmws2bNh7GSyucWa74tFrfKgl315Yb8QAU/Mi/tLV
         sZhQe3uDOqKYxTNjXe1cvDJ4Hp42TfMd6iovrft78CmvmW1hlKn05weYxDvXMlyN/Au0
         rSGLEhAONAMfh01Oce3XVKGpK1BWOssYGm6V9EKy2ngai2o776fTY2qr7nfdGZuyNYul
         mby9MbU2yeKqzjXroStGunMGXErs0a5XlwMP9OUL/9oM7f/BbIzAZsRGgV/n3WWYo/aC
         krl/Qi+DeOIbSN0f4LcZYMGAngDyj1CuHOCUYNKbW4lvAKPi0z/M9qCLDsMO0At3VdVO
         lznQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kXBeL+3U;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aqj/uneunH4bF0QtOZRKHTif3OZCVHcw2FcuLjqO6Ns=;
        b=Oln9571/oJgkhIxx7nivEHmPp99IgkGW6wyin7ICt3XiqtjNM+DntShKk/ielXnI0Z
         sLqHUVvZJHKSOn170R3MTi9IFfxZap2/Wi71MrsdSKMXjnT0lVSbsSoBt5LYg+RZy6NN
         G9utD/hcdEkLeFq4NnIyheF4xQkzQW1swlRyqahu6U5yQkDHRHAyJ/n7HWaoHmeE/BrQ
         s8GlrNd7C/zmTNHnSmk5VMMHpVIkPSIkmRkB1jZ/udMnnwf/ytRynk/+8C3Juo2LkD84
         TXeDR44QuBqPrHgmi3B+OCivcQmtO0Hfx3+O/3G2xNJH3SHpWMe9bGtStc0LAuE27wCp
         pxpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aqj/uneunH4bF0QtOZRKHTif3OZCVHcw2FcuLjqO6Ns=;
        b=db8+5H0qZdtZcTwJTNjrcUCuGUAYE0n5/95QT8YqHVDE01ZD5PudzmAZRpq1BEcQSo
         mF5A7gvwh1ove+fjFlbwhv78KWj2IyyyGpCqEbOtJX2ufoBn4BvjTzzK/MkxbtJ4Creh
         pmRMXGb7Jy4sraBi7FMwa4fNmA7bDEBGrlNE7n2OmdQ7lL0QfKIZa3YqiHYNUkE5sw5R
         hGKK+a00RdDp2mIVwv6N6Nnu1NDl69ZhbB3rTgVmkeJBwT/pLECoda36aW90g199+5cg
         32fcnfO0LJMPX01MxPZgXMl347H4JWHqEUCxTAdnbj4xl2AyE8tWGKtg92f8y2uw6pd1
         8Srg==
X-Gm-Message-State: AOAM5320nPYurzhEtlCE+60wPRXSC/D0EzGFS+tA5wZX47eRkeszLkt+
	g/MXPjlWVUZ5x3fur1FyWtk=
X-Google-Smtp-Source: ABdhPJz4bB1wrdr9T6OsiSBn5IUTPG9Qg7C2Wqrx/3h0t2kznroDFEsVF9d8jQEpsft/KArh4V/uMA==
X-Received: by 2002:a17:902:7283:b0:150:b5b:5375 with SMTP id d3-20020a170902728300b001500b5b5375mr1928092pll.90.1645659345312;
        Wed, 23 Feb 2022 15:35:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:cec1:b0:14f:f089:12b5 with SMTP id
 d1-20020a170902cec100b0014ff08912b5ls752382plg.8.gmail; Wed, 23 Feb 2022
 15:35:44 -0800 (PST)
X-Received: by 2002:a17:90b:510:b0:1bc:3ac8:2fe8 with SMTP id r16-20020a17090b051000b001bc3ac82fe8mr11573646pjz.171.1645659344356;
        Wed, 23 Feb 2022 15:35:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645659344; cv=none;
        d=google.com; s=arc-20160816;
        b=bWs6nqnQ+Qm7JGW1RNUGuustfQ0Gr9ouhRJmd731Fc2HgrOSocL6L8S6pzcLWfTp2D
         QLR6hDVQdDwf5/2RpjAtiLbkt2Qk3L4zDWZwQS4yOdVRwCj+aI1T4+lclKWtM/Mp03XE
         gU7PE8E/dGgFc9H41L0IUB+Ux2Ki/yqepMBaPFR5u65vwNhkn5jtjUa7jSO1tqr8M/hM
         kEyPF5p1oe11P8M7qsdJdflxe7aDz/gzS5A4B3IP8ekLS0ymmG1E/zyI2sHVI1pPT13q
         lzOCPTzCF6luQw9i/frd5SfOMChF+q9D9IYwqTawEPsl66+jKWdt2vMT1FUFNmpYb5xS
         D1AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=thOSbRDXMSWEe7zpjS3HEOJEuojyPix5lNBQyOalrFA=;
        b=yJZ06saCMY4EYNwvSTYY2aW/541eYbyGoiuKaWFC1TRiJfaz1zwvx8JwrcXOUdslVu
         pa6QzJKb29EBsTpY7KR4OqzWf/m0q8oCpds1JyNZvmzhKyn1iHzvMX9/IA3p5zc6ExdQ
         huvDdbD9Ok+ynhEKnRLDJlUp8BGZt3gVuYW0S3tXCKm5nZMCFxdryvr3gCj5llYaWDsk
         778O95Dbo7spt1iL8NqP8vY5WXxACr3/YWXBLTKQitIDR1rvrmv5nXqmSEQW3RMyuo1m
         xoldDCYJ1qi7XU4ed+CcBR8vXtKGIMCu/Fk5/a2crpL8kWAnyQgbqifzfhPMeeEwaYNh
         4LdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kXBeL+3U;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id bj5si56624plb.4.2022.02.23.15.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Feb 2022 15:35:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-2d310db3812so7287227b3.3
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 15:35:44 -0800 (PST)
X-Received: by 2002:a81:1a49:0:b0:2d7:fc73:dab2 with SMTP id
 a70-20020a811a49000000b002d7fc73dab2mr9323ywa.316.1645659343393; Wed, 23 Feb
 2022 15:35:43 -0800 (PST)
MIME-Version: 1.0
References: <20220219012433.890941-1-pcc@google.com> <7a6afd53-a5c8-1be3-83cc-832596702401@huawei.com>
 <CANpmjNO=1utdh_52sVWb1rNCDme+hbMJzP9GMfF1xWigmy2WsA@mail.gmail.com> <CAMn1gO7S++yR4=DjrPZU_POAHP8Pfxaa3P2Cy__Ggu+kN9pqBA@mail.gmail.com>
In-Reply-To: <CAMn1gO7S++yR4=DjrPZU_POAHP8Pfxaa3P2Cy__Ggu+kN9pqBA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Feb 2022 00:35:32 +0100
Message-ID: <CANpmjNMyuQh-G0kLOdoFWXyhw31PJsjXgbv7Qy+774v8iq9NWw@mail.gmail.com>
Subject: Re: [PATCH] kasan: update function name in comments
To: Peter Collingbourne <pcc@google.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Sasha Levin <sashal@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kXBeL+3U;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
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

On Wed, 23 Feb 2022 at 23:31, Peter Collingbourne <pcc@google.com> wrote:
[...]
> > > > Link: https://linux-review.googlesource.com/id/I20faa90126937bbee77d9d44709556c3dd4b40be
> > > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > > Fixes: e5f4728767d2 ("kasan: test: add globals left-out-of-bounds test")
> > >
> > > This Fixes tag is unneeded.
> > >
> > > Except the above nit, this patch looks good to me. Thanks.
> > >
> > > Reviewed-by: Miaohe Lin <linmiaohe@huawei.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > And yes, the Fixes tag should be removed to not have stable teams do
> > unnecessary work.
>
> I thought that Cc: stable@vger.kernel.org controlled whether the patch
> is to be taken to the stable kernel and Fixes: was more of an
> informational tag. At least that's what this seems to say:
> https://www.kernel.org/doc/html/latest/process/submitting-patches.html#reviewer-s-statement-of-oversight

These days patches that just have a Fixes tag (and no Cc: stable) will
be auto-picked in many (most?) cases (by empirical observation).

I think there were also tree-specific variances of this policy, but am
not sure anymore. What is the latest policy?

> > +Cc'ing missing mailing lists (use get_maintainers.pl - in particular,
> > LKML is missing, which should always be Cc'd for archival purposes so
> > that things like b4 can work properly).
>
> get_maintainers.pl tends to list a lot of reviewers so I try to filter
> it to only the most important recipients or only use it for
> "important" patches (like the uaccess logging patch). It's also a bit
> broken in my workflow --
> https://lore.kernel.org/all/20210913233435.24585-1-pcc@google.com/
> fixes one of the problems but there are others.

That's fair. It just seemed that something went wrong given
kasan-dev@googlegroups.com wasn't Cc'd. FWIW, syzbot uses
'get_maintainer.pl --git-min-percent=20' which is a bit less
aggressive with Cc'ing folks not mentioned explicitly in MAINTAINERS.

> Doesn't b4 scan all the mailing lists? So I'd have imagined it
> wouldn't matter which one you send it to.

Those under lore.kernel.org or lists.linux.dev. Seems linux-mm does
get redirected to lore: https://lore.kernel.org/linux-mm/ -- It's not
entirely obvious which are lore managed and which aren't (obviously
things like kasan-dev@googlegroups.com aren't).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMyuQh-G0kLOdoFWXyhw31PJsjXgbv7Qy%2B774v8iq9NWw%40mail.gmail.com.
