Return-Path: <kasan-dev+bncBC6OLHHDVUOBBF7T7KKQMGQEILYFOSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 94BA2562F84
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 11:08:40 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id j35-20020a05600c1c2300b003a167dfa0ecsf1107909wms.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 02:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656666520; cv=pass;
        d=google.com; s=arc-20160816;
        b=znPnVHd/MJGbddO8jnbctpzp2NrH9YEQxXsxcn/69S2r0sp3BS1EGA174xZgSfR9Ys
         f3fHcTAKxjrUh6Fa7mFTzzFxtt5DHB349T+zENqkSAUj4p9gw25NEM4gVexgKCHzS3Ll
         EZF2Y0ssbw57Rg8/0Yk6WuQB3AFnrBZ6eS8phuJk/hXLwaErNbbh2cujt1txdzwBmEr7
         BTS7WCuktuUWmJmfgM41gqmDmoBryd2WV6qf++TVzmk/Hg6mwNoXwk24LRUtWlH6NCT5
         hiW3oTlbThmNV2M/3/xBKV5yaQSacUHUMXXMeZxwJ2DaAFujWPy6FtSInwgdXj19Qbgd
         2yGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L6+kXPjMGnyuXtBPFOp33wzndLia1eCkB6bVK6zAssI=;
        b=PsrMVEmvbaqCV0knGBdVECnwILKE+QVVSBwWvZ+H3asenJlw4vvsF3JoRa4bgkfyuc
         oDC7tCnePTZJis7UBjMy77e9FfLOxe3v1MrlkKdL165weozy0do4hTEyB7qekZi1/vkv
         vtKpv+vsmghZiA/qqvOTzQjDvs07Kqf1irqpf0dgjQaoqSgfJ/Aj+leEl+vxCo6Y7omx
         fTmIVgZGBbhVad2o5j31xgWDGGQps8VEZk/vALNJivo69wtJMsMT3K2idQhbDqfGeiZ3
         WjdAmn2Qu77MiMvIbO/NFxNN59iuB+dJzkLacUGPkJ7h9H/dQ+SqIk48WeE00ICJqwk3
         87TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S7EU9K2E;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L6+kXPjMGnyuXtBPFOp33wzndLia1eCkB6bVK6zAssI=;
        b=hbDOiU86VS1cEC9TJncIxbGYkplF+p80IveYFUySCIyt+zA0X5i8Pyk/q5SUFLvyUO
         kFDWOoZfZ5ZKVc5OlXEI1tXsCxbVBu626fAU5nWMoccLBjdJKQ2IiHiZb4vU1xsnPnNt
         ceBNEu7UoEfTm7EAYf76JEXvSJPU0f2ojwH2bHxfamms1QtKdK5DV3bGZaZcv/yzKDxK
         h0fM1FFe9t3+b/1FpMti/pg7y5iEkzOHLuSGLCz1LJMUe0CdldQFjxth8a5gFiJ/Ja1O
         ae9IdIQZwaYIUZdC1kBqIalCQYkuU0JYghQy0QDLa/sC+2OTNxc5u7mYSe5MhFk5tDXJ
         txiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L6+kXPjMGnyuXtBPFOp33wzndLia1eCkB6bVK6zAssI=;
        b=kEbY7JRc4ooqa85p/jpMZ/YhYxwUOx7b+24KBSjz/OldfkYmu+okIY7pRn9d/Zt6VN
         3lkcBvpX1SgubfweFHu4y/UrDGgjhaD3hSzrvVL+OLotHQvDmxn6YQXcR2/7vR9WuQO0
         kUiS2Zndd7tuXSsgACugIIYuZEVvvd3a/Y0L+8qKd0GSA2YIxeYkdjwrDjHzqfzOhZ6C
         NKx+ji8DonfcVFSFjbtvLO8uY8SK7H2ESW8+8bENbMWXyVfzIYxIGC4Bkh71JXj4TK4V
         ATyYpR9itCRRRE9oM6GEiaSY2aieGWhxPOjx2LsztkzJRFGG2WOumZQmiJFw9ezCq9aw
         rTmA==
X-Gm-Message-State: AJIora/xjQPLHZ4VGaUH6/dhv1M+mpcGHfHyuzhUmeTG+tz2rmbkqhyl
	KE/cZjV0igEdwA4v2gCRLXA=
X-Google-Smtp-Source: AGRyM1t0SG1/UpUSYSxjElqJBXTx19KgOsUB4eNiCLwjIjmXsTYLfNVmy74CRfdnx5NnrCusyjiHmg==
X-Received: by 2002:a05:600c:4e90:b0:3a0:57d6:4458 with SMTP id f16-20020a05600c4e9000b003a057d64458mr15534902wmq.198.1656666520059;
        Fri, 01 Jul 2022 02:08:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls3046018wms.1.gmail; Fri, 01 Jul 2022
 02:08:38 -0700 (PDT)
X-Received: by 2002:a05:600c:a14c:b0:3a0:4ddc:f710 with SMTP id ib12-20020a05600ca14c00b003a04ddcf710mr16687750wmb.38.1656666518879;
        Fri, 01 Jul 2022 02:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656666518; cv=none;
        d=google.com; s=arc-20160816;
        b=zohv9YE7CSHipHJSR5eeYhOs5CjVInn3guvb0GTWGJbr2swcoeZnwkfGWBxMIpJWEK
         rxs6PxT4rT+NZBlaz9fcI8N9NHMdaJHon2WFrY7YLz1yZgCclqg3KCsbXG/lxpWMBALI
         kmWwvW4dmk7xTYrhFFWi6m1VcHe6oXY4HC7qnOQazQYLgCrwl8O31oZBCMAqCRnSmgx3
         chT72oXm6Eb/r5IrnDvUGUHVpdq6Dmc5im6dQ8+HlsjEJOHrske5VbMjwfwDJm+0M13T
         7NUmOjcU4gv6OukWIjip3o53KH3NCQK46daTPCgVRECbyZnvxbuGCj6E3VdBqhYiTR81
         qP1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cWHIzp+3WUp4C4qcj3J1sqQ4NecfP0gvWEDQIXDxCZA=;
        b=bXrSpDPveQqx+3BIeumFQsDD6E9JvGrCbYshc8wGitevhPz3Urgr7V4YXtmCuxMcyd
         Y8Xsul6gvKGlBYyh/wwyb3g0b2CAxdd2ETV4NjEkbm1U+ac7Iuui1fKhwCr6AOBODAc5
         9aPRA0vIr2YA5Q/DG0IUQPWMe4VwiOIUHTVmQyg4yhRFHwXtPubS4FLcH6X/KnqFYqC5
         kClF9CB16777LMEZqU/TRUHJooKm+1wKDG54p16UW4ZuNUMa0u4IFaA7MDyYhmQ7ViiN
         EvOm1eZJBJMwhuqlQ/tgngNs4Xyev0Zpkcv+soyG3WAR8HA46qG1DB0Gv66BYQ5QRkPj
         wNBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S7EU9K2E;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id r68-20020a1c2b47000000b003a19123bf95si2332wmr.2.2022.07.01.02.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 02:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id o4so2261893wrh.3
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 02:08:38 -0700 (PDT)
X-Received: by 2002:a05:6000:144d:b0:21b:b3cc:162e with SMTP id
 v13-20020a056000144d00b0021bb3cc162emr12777663wrx.433.1656666518482; Fri, 01
 Jul 2022 02:08:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220630080834.2742777-1-davidgow@google.com> <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
 <20220630125434.GA20153@axis.com> <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
In-Reply-To: <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Jul 2022 17:08:27 +0800
Message-ID: <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Johannes Berg <johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=S7EU9K2E;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Jun 30, 2022 at 9:29 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Thu, Jun 30, 2022 at 2:54 PM Vincent Whitchurch
> <vincent.whitchurch@axis.com> wrote:
> >
> > On Thu, Jun 30, 2022 at 11:41:04AM +0200, Dmitry Vyukov wrote:
> > > On Thu, 30 Jun 2022 at 10:08, David Gow <davidgow@google.com> wrote:
> > > > diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> > > > index 1c2d4b29a3d4..a089217e2f0e 100644
> > > > --- a/arch/um/kernel/Makefile
> > > > +++ b/arch/um/kernel/Makefile
> > > > @@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
> > > >  obj-$(CONFIG_STACKTRACE) += stacktrace.o
> > > >  obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
> > > >
> > > > +KASAN_SANITIZE_stacktrace.o := n
> > > > +KASAN_SANITIZE_sysrq.o := n
> > >
> > > Why are these needed?
> > > It's helpful to leave some comments for any of *_SANITIZE:=n.
> > > Otherwise later it's unclear if it's due to some latent bugs, some
> > > inherent incompatibility, something that can be fixed, etc.
> >
> > I believe I saw the stacktrace code itself triggering KASAN splats and
> > causing recursion when sanitization was not disabled on it.  I noticed
> > that other architectures disabled sanitization of their stacktrace code,
> > eg. ARM in commit 4d576cab16f57e1f87978f ("ARM: 9028/1: disable KASAN in
> > call stack capturing routines"), so I did not investigate it further.
> >
> > (Note that despite the name, sysrq.c is also just stacktrace code.)
>
> Stack trace collection code might trigger KASAN splats when walking
> stack frames, but this can be resolved by using unchecked accesses.
> The main reason to disable instrumentation here is for performance
> reasons, see the upcoming patch for arm64 [1] for some details.
>
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11

Ah -- that does it! Using READ_ONCE_NOCHECK() in dump_trace() gets rid
of the nasty recursive KASAN failures we were getting in the tests.

I'll send out v5 with those files instrumented again.

Thanks!
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmxnTc31C-gbmbns%2B8YOkpppK77sdXLzASZ-hspFYDwfA%40mail.gmail.com.
