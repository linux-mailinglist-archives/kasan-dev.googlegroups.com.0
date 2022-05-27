Return-Path: <kasan-dev+bncBCMIZB7QWENRBGNPYOKAMGQEHC2XBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 20ACF536394
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:52:26 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf2052679lfr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:52:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653659545; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dxu0qHxdN0vaWWxT5NcnTD5D5pwxp9yIkOdk1//H/tKLJtRHwvn2imTSxkP8VoMrF8
         2YxU99wjLxQo5rirK3JkmyVUWFNTkGyI8uFlnqzP2+rTtJ56EWd6BqAvcm2JFIpuCg4l
         qdw0o7EGtIguYLCv+D9WR6Suk9wef3yr/H7iCMVCc8lJAkYhVOyqKvWC3pe2/UnPE1rA
         AWylGeiFhXCRTKhQt6EuPryYig21mw4fURqGjFUDpkg32aQ/lrXLljbFfwLeO5vv4i18
         Q6PgCP3KIEcm7FhFVznJv/UXTrxug95N8Mh136KNDBQNFf/1SxwlAMLJGOY/Go+1oOAm
         ggNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2qA0PpdcCe31LMZoJmTtfj1AoBUfvtz8V9XYp3BzHUw=;
        b=D+TcQGgZG/sPx2ECzi+6AOrH1+2lFOz2NI3zRihHyBEwna2dx2H2NEmQl3d8QLaK4D
         EFRyh9NrWiaGTzRShYYuZ6Na8q/CWF7W+QnuwETitvvy8hbYu9DQeLShINYTuzU+ta8t
         C/c5RfSHMmPxkgcy71rMs6k/TT+AxkbOpxNvmCrzBwIJg3VQjMdJ8kp7Qcd+Hztq6ZRT
         ZsY7YqmSWHZoGBA1wJkxaRcgmEofOshB4jfwLOYtgNG3lGApPFOsUuHkNcG6RK02Cuwl
         vwiTSg6oMfzCWZ8YuGkGxpkIZcLrQ3ySGdjWJTTCNQZpl0/2fGQWn71AKMt11fvEBeMh
         y+eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lBJHP5Ok;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qA0PpdcCe31LMZoJmTtfj1AoBUfvtz8V9XYp3BzHUw=;
        b=EIfqwblZpjwUm8mxgXbQTcOQqFF+hgquADjbRZG+JOYiCR+ozlyfwi/4H+gbyg4Glp
         eKJW18bSRAxh34eV3ahufcOcHLTYSZuac5x25i4an0cCX+gCggQ6s1nPyQHDh1CGa/PQ
         3b00iCziKWIFQLA7B2pTH8JDkvFMnl/dnjoXE3dgF+G+FLDPvmdUSNGKfMbHld606NAP
         JPWUsFVEMCDp4sFDkPrvq4He1RFwjlA6YKyxLM5NtyljliPs8ndawMBSdEQJsYTuYt9I
         C/oNZi6iHGTQ/PmroZthHnTC6qk1m/1fHMYM0VWFRoW1UJs8R7w+w4quCkJJ0+sNAAhu
         GqVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qA0PpdcCe31LMZoJmTtfj1AoBUfvtz8V9XYp3BzHUw=;
        b=uQYWA36lWevaB5/mV6Jov3abeLNbGe2qGuv50xQ/ujqtQT34blnjq5CWYpRNAAWvn3
         1ktC2/EtcxxtZ287ICix2p4KW1JGigukwZuPm4OHFeY29BVgIJHdfSBJbhRs/xN/qySa
         i+G2QV19lK8WkuW5q8Ey8o0HD9Yb2HKbEA65I4BTzabfvmUgNgurgEWvxg33ynPMaFU2
         deuLgJW8KW+TR2W3Hh+ChFEsXj0h2zy47iK1swQnJ/WuWXvyXE/k5UPzS86mey+p17xQ
         WdcDlUbHN3OtmYm1dyESPIM/LQqKzqYMj4HVorPsGY+QszZN//CKNvpDTjKXkanIFQxU
         l9TQ==
X-Gm-Message-State: AOAM533Hj7IDks8MVelkraWwOOe1P0Mq2J8OugzwCkAeD33YHP8FAsFy
	gYvEV8XfUX+H91ZpAXSwpA8=
X-Google-Smtp-Source: ABdhPJyko2ym8TRl3mscDDGn1+KMOFRa/IcX5H2T8Ya5JC4HHwFFbU0mBqM+R5HhHqg4z0mmgLZ/qw==
X-Received: by 2002:a05:6512:13a3:b0:474:2642:d00e with SMTP id p35-20020a05651213a300b004742642d00emr29831142lfa.328.1653659545393;
        Fri, 27 May 2022 06:52:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b896:0:b0:254:c65:c6d8 with SMTP id r22-20020a2eb896000000b002540c65c6d8ls1557113ljp.6.gmail;
 Fri, 27 May 2022 06:52:24 -0700 (PDT)
X-Received: by 2002:a2e:93c8:0:b0:24d:b348:b070 with SMTP id p8-20020a2e93c8000000b0024db348b070mr25293306ljh.434.1653659544227;
        Fri, 27 May 2022 06:52:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653659544; cv=none;
        d=google.com; s=arc-20160816;
        b=middsx0WbVeJCeZiVW/kcJ4gCXdWiMRqbafVG9lXdMvj54alfrNC7p0bd3HP0x3B+r
         zrZhTRHGO7Pb0Hw7j5kwiAj4yD6N4A6nQ0b2hLfOmSvy3wUqtZo64dflcXOnuBeuJyBH
         WOu0o+6b5Al16SW2wmzElJiXrWx/RdNhzjFSe/FsijBmEQy21jwydnCGSvYF1xLPsmpx
         iD3joKPIWrlk4W2D98sNSrhLOTJFJfcAjlhSpeKriJsxuKoMWHTT2+qZSYixN7KarQ70
         UqPARv3Zhrpt02U8MzD9BZX3VKZ6Tg2MCjQ+yvaOgpCW5rlZjz78nsPyMFIZ0IvmKTbV
         wIsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZYxRb+Vdjb6h7QtKyMpW1wUVocarnGCZDA40o8CZT2Y=;
        b=P1SsTSM3zgb+bYWnMTdxTFLkY60wKFOcWscjScLwkP7thvt1UA7g/+mr0uP9jdAWfj
         OWFSiCCwKbhSe6DMe5Z12E3lF6bTADaa13iaClgOgHg7ZO8hTiTF+ulbi7cVS31JHwJd
         R3y2S1UK7nw5TOchTljgukzyRtzYY9rOODnSBQtHddzUYqk42pV0sHJQBbvxndLxW1mV
         GK8VqWiKa6pU9e/P9Q//tZFwAamwTsP5zDQtDPYMDELcB0BvKw0mcq3VCDqNGWzBiRD8
         CPC6nURiFrNbAlVUVEmArKfiVZudaZ/G496GgFwYF7X8oBNjGXwLM39fstTw8ML7cvxH
         gfUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lBJHP5Ok;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id f20-20020a056512361400b004786caccd4esi206007lfs.4.2022.05.27.06.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 06:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id a28so2436085lfm.0
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 06:52:24 -0700 (PDT)
X-Received: by 2002:a05:6512:1588:b0:477:a556:4ab2 with SMTP id
 bp8-20020a056512158800b00477a5564ab2mr29939142lfb.376.1653659543723; Fri, 27
 May 2022 06:52:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220525111756.GA15955@axis.com> <20220526010111.755166-1-davidgow@google.com>
 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
 <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
 <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com> <134957369d2e0abf51f03817f1e4de7cbf21f76e.camel@sipsolutions.net>
In-Reply-To: <134957369d2e0abf51f03817f1e4de7cbf21f76e.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 15:52:12 +0200
Message-ID: <CACT4Y+aH7LqDUqAyQ7+hkyeZTtkYnMHia73M7=EeAzMYzJ8pQg@mail.gmail.com>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch <vincent.whitchurch@axis.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lBJHP5Ok;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135
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

On Fri, 27 May 2022 at 15:27, Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Fri, 2022-05-27 at 15:18 +0200, Dmitry Vyukov wrote:
> > On Fri, 27 May 2022 at 15:15, Johannes Berg <johannes@sipsolutions.net> wrote:
> > >
> > > On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > > > > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > > > > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > > > > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > > > > rather than just showing the RCU callback used for that.
> > > >
> > > > KASAN is doing it for several years now, see e.g.:
> > > > https://groups.google.com/g/syzkaller-bugs/c/eTW9zom4O2o/m/_v7cOo2RFwAJ
> > > >
> > >
> > > Hm. It didn't for me:
> >
> > Please post a full report with line numbers and kernel version.
>
> That was basically it, apart from a few lines snipped from the stack
> traces. Kernel version was admittedly a little older - 5.18.0-rc1 + a
> few UML fixes + this KASAN patch (+ the fixes I pointed out earlier)
>
> I guess it doesn't really matter that much, just had to dig a bit to
> understand why it was freed.

Humm... I don't have any explanation based only on this info.
Generally call_rcu stacks are memorized and I see the call is still there:
https://elixir.bootlin.com/linux/v5.18/source/kernel/rcu/tree.c#L3595
It may be caused by some narrow races, depleted reserve memory in
stackdepot, or race with quarantine eviction.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaH7LqDUqAyQ7%2BhkyeZTtkYnMHia73M7%3DEeAzMYzJ8pQg%40mail.gmail.com.
