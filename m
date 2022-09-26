Return-Path: <kasan-dev+bncBCLI747UVAFRB7FRZCMQMGQEHSJXNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B47DE5EB310
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:26:21 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id b34-20020a2ebc22000000b0026c273ba56dsf1994139ljf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 14:26:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664227581; cv=pass;
        d=google.com; s=arc-20160816;
        b=YdcGv1BWibf0fz6/1n6cHkhYy8I85iR8hylWptVoEjsvfFXv6LTPfLxPL4jPcR+NhA
         RimJB4xwGB610XeWsPXzw848POh4Rp63GBH6fgthpCicx/Mmhr/MtQn/Cze49fwf0LBr
         lZDey8dok6keVfY9XIAYUm+phtKWDkQFkFYTBSjN7PEiEZ2z8rY+6l5hiobBuWLBvYlE
         g4dtNUL+S8cyV+KibbMsith+yJvboOS8Y8FrkpaWwqEUqy+YTzLz4Oh01C+5Txw6jRpv
         Re45iYdrdltbzc0BtzATE321hyhWy+0yiG2fp8Jt8Ps+PkVnMvzbFJ4TYAGLlGnF1Rtk
         gERQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pjdkR3H/LsGSCbZD3Jey0NzZgeO1mvez0Hbh0D6K0QU=;
        b=bXUU7uzFkyAevbQ6yWHyR+1a7vgJZPE39k1jZk+DIyCgtc7WDH8i3A5ja9hhUMZe65
         HqggXcpPRPUC7Fnsfty6Q75Q52yXxRfs8jVQZRytV1M0gWnrWN52xk/UcrQVQnTyLeiU
         9XNDvUDu8PP7drAIFNtW9gV9aWm/9/EvwMz4JHN49T1EybSapB5ykj9XE4SbzzIUHsDM
         mjN7VenPUwAU5ronx3k2f0zaBN6itlo/p4VTI/Z5f+J1ERckmmrnRXUmTYV/c1/A9z2+
         jpbZuov6GeE9emJGFm8eyv+JFSVbY17DqU2WoBf6KNZUlRb8Xw6s9H/wpgMIDvgwNqZK
         M1vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=cGDgWN4Q;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=pjdkR3H/LsGSCbZD3Jey0NzZgeO1mvez0Hbh0D6K0QU=;
        b=NBrngxpWN9M8SIEbEGwZQHYHnD7RwrblXM7608oKYqSimrj5J00MGGrlbCGZfkiq6V
         OWyPqdXpmh7UMx3qHoRNrXPrlzYz74Gd3UQc0CSqeHH0CnBVIM0jRv4nt4D0H6ibHCbs
         +8XwN61NKrynPk2p8fPZ+Bq7LWsCmH01xL6AswaU6GKU5c8TMoq5/aSRhJrNIy26XlfB
         bHFiU9kJkbLpOCEBdFEhoP+lKMQGT+Q5PtgZJrrsFSLJwBW7sH3FFUDjSufKJYqkOdTP
         vpEjTShqH7gpjP2xWu5hDEgzOrYkYaA9r2RfBPuMCT9VnZVSN8fXsCrIX9Erb3grzt9J
         CTcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=pjdkR3H/LsGSCbZD3Jey0NzZgeO1mvez0Hbh0D6K0QU=;
        b=AHaTF4113bO5/dl3Ys1Wywh7ELehV0OBGLj4V3E3MGGln6RKQR7RbjnwIqhYWMyZF5
         s0nUU4+rHCC/uEoc0P0gjl8jEEV0VAzBhW+Izwiwfwlhtwf3PxIeGTEFc8hQWq9KeBdM
         tUsfxNRosJf4q3QfM0UNa5uco18jxrHdCiu+LswejQLBLC4qtIxt1A8YB0j0SIInnSVf
         X5WGFKuqhFHxHG9Ttr3iU2g+wVzt+h1OfSS+PWct+FRUiJ9fsH2tjFkEBJUnDMMAOj3Y
         52zU+45xrX1vRpQkSOpDOCACzornIlkNBfAy5/yEHDuXbz+t9HDu3HPT+pGuz/bZMj4N
         Ro5w==
X-Gm-Message-State: ACrzQf0FFXWwjWWqeK5g+LtLJmv/hlYhiUMAx96+mhyGDgZA1nWI8713
	YUN9507+jIaGyCaD2etrSKU=
X-Google-Smtp-Source: AMsMyM7LwsITqiNHL+TtPtEfMZSNyxt9/cM4Xi7cJjmV1Q6xlusKEQV7LeTvEclpiB2aRShHmZg7rw==
X-Received: by 2002:a2e:be14:0:b0:26d:9825:abf8 with SMTP id z20-20020a2ebe14000000b0026d9825abf8mr2908338ljq.126.1664227580968;
        Mon, 26 Sep 2022 14:26:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:46da:0:b0:48b:2227:7787 with SMTP id p26-20020ac246da000000b0048b22277787ls601626lfo.3.-pod-prod-gmail;
 Mon, 26 Sep 2022 14:26:19 -0700 (PDT)
X-Received: by 2002:a05:6512:6c4:b0:498:f6fd:e82f with SMTP id u4-20020a05651206c400b00498f6fde82fmr9177314lff.105.1664227579719;
        Mon, 26 Sep 2022 14:26:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664227579; cv=none;
        d=google.com; s=arc-20160816;
        b=LpmbSS8Hekg3n+hP3LVyZ5C/eg0d181NWNDhyQnRfknjE+685GPbPoXYcDW45iMHnZ
         kHpY21V5pAn7XZzzTgS/2HV8NzCKt8D7Wa/YYKTUmrIDc6/pdcvsffrWzMKUcq69obgR
         WFX/Hg8aB53RVmkBJ/lSzKVgoTIguEGl9a/Sld2uFvFoUKLSHRnG7436/cuA33Aa/GbF
         5/H8SffTQzOUp5Ta8tt1e22VzVILJNv+tFMcI7w6FNzeysWfGarMw8Fxmd24etLFL9CO
         cwzFPBZyc4/lfvPAN3Xd7LJFzZC2OZUDfxgV9qRg2mR3oWZm1DlldMJQe5T7eMIsppAw
         M3Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KHREqfscGihuITklnK5EPpLhwNrIyruLZngp4Y+54eA=;
        b=BbDJyLOXjFfaeVcAwYf5I4ccNqvC6jm0V5cGVHJV3ix5IfjFcGlW7kfEm3t0I56g0Z
         47iFRbahemr7X4AVFaM0i2npX0CAaj/EZ5kCDgDXCZGofIuScyJzPAD88qotkMlVCKj2
         b2ixsn5bZyoCglqxYEI/Yk4JOLbe2aOp1mML7BWWvu3Yn+8X9CWWIFgXO5iG9+rKsdWU
         exTEvdvSova7phFC1Ll1f8Pn6LT77iuR06y3FmZ1nfH52Oz3jeP7DwU+hT7ABU5xR+fW
         lJI2xXCeBCYLN/OstAvXoLCZcB2jmFn5FdQrgN4qaF87VkD/m05A+G0VYFx6aBMx8Np/
         f8dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=cGDgWN4Q;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id g5-20020a056512118500b0048b224551b6si650373lfr.12.2022.09.26.14.26.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 14:26:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0BBBCB81148
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 21:26:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 592F1C433C1
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 21:26:17 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 6b87e8d8 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 26 Sep 2022 21:26:13 +0000 (UTC)
Received: by mail-vs1-f50.google.com with SMTP id k2so7870864vsk.8
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 14:26:13 -0700 (PDT)
X-Received: by 2002:a67:c289:0:b0:398:cdc:c3ef with SMTP id
 k9-20020a67c289000000b003980cdcc3efmr10100019vsj.76.1664227572907; Mon, 26
 Sep 2022 14:26:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220926171223.1483213-1-Jason@zx2c4.com> <CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
 <CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com> <CANpmjNP2FskJ4-pArVd=pT0MFokafPOYZiEg3tspGtjQ5OtuCg@mail.gmail.com>
In-Reply-To: <CANpmjNP2FskJ4-pArVd=pT0MFokafPOYZiEg3tspGtjQ5OtuCg@mail.gmail.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 23:26:01 +0200
X-Gmail-Original-Message-ID: <CAHmME9pN7FuzgHki5waXyetEE4r2=ORfuinAjaU=hdUO7E8G_g@mail.gmail.com>
Message-ID: <CAHmME9pN7FuzgHki5waXyetEE4r2=ORfuinAjaU=hdUO7E8G_g@mail.gmail.com>
Subject: Re: [PATCH] kfence: use better stack hash seed
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=cGDgWN4Q;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Mon, Sep 26, 2022 at 9:31 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 26 Sept 2022 at 20:01, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> >
> > On Mon, Sep 26, 2022 at 7:35 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Mon, 26 Sept 2022 at 19:12, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > > >
> > > > As of [1], the RNG will have incorporated both a cycle counter value and
> > > > RDRAND, in addition to various other environmental noise. Therefore,
> > > > using get_random_u32() will supply a stronger seed than simply using
> > > > random_get_entropy(). N.B.: random_get_entropy() should be considered an
> > > > internal API of random.c and not generally consumed.
> > > >
> > > > [1] https://git.kernel.org/crng/random/c/c6c739b0
> > > >
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Marco Elver <elver@google.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > >
> > > Reviewed-by: Marco Elver <elver@google.com>
> > >
> > > Assuming this patch goes after [1].
> >
> > Do you want me to queue it up in my tree to ensure that? Or would you
> > like to take it and just rely on me sending my PULL at the start of
> > the window?
>
> kfence patches go through -mm, so that's also a question for Andrew.
>
> I'm guessing that your change at [1] and this patch ought to be in a
> patch series together, due to that dependency. In which case it'd be
> very reasonable for you to take it through your tree.

Alright, will do. I'll resend both anyway (to address some feedback on
[1]) and make a series out of them.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9pN7FuzgHki5waXyetEE4r2%3DORfuinAjaU%3DhdUO7E8G_g%40mail.gmail.com.
