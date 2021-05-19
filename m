Return-Path: <kasan-dev+bncBCJZRXGY5YJBBEV5SWCQMGQE5WB7NHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 328FB3895D8
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 20:53:08 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id v22-20020aa785160000b02902ddbe7f56bdsf4803474pfn.12
        for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 11:53:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621450387; cv=pass;
        d=google.com; s=arc-20160816;
        b=sbTV8YNF10XxzYT38bKB+GPGBdJqJ+aOe0fs68O4XtVigQZXA+rGHhV5217wfdDhzX
         0e3ZXizUJmsHsiADDquG53MQ/Wv/c3dl9Zz5bMC7ej2wxrZvaFAnKA3372QGygGjxlsm
         MsQrUp8dJF+9TDEOhgGfNy99uIA4rykSo78jADK5aficmTHqssQZZTkkXXx5cW2Ijc+N
         hlUzFBaClJVX6akqAI9TJLfnq2n5JTDeyEtPqES8TrPG1oFZffjESPFhvkVapSUAcqoy
         uvqSelnqwaRXm2zXwaqNTPeuJP/FKsdhLWV45qG3Tb8B8fDwYgSvvUyle4kgCawCba6W
         978g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=83f+WMy4v+ODB2UOXBth2dxkr0XOuhiC33LNyEepJrQ=;
        b=wNfJHsDkbrxnk4cUfw6C7LjVa+9HpeHxskWtdMfhWXKXNOqe+HBzSP/t0a27yTHsR+
         dQiYQsIz4Br5SwZS2V8lYaYWEYbNxHYagFaVS5k9cSaCdqCKGub/ziz+qb3ttQA6K5v2
         lXviq3IX9A3siSAtbGtEL3m3yRMuuSUks4HlXlzUm1dsMqZUthwcjFGVNWIpB8DUe4aN
         yehRu+mpRGzP7vcYLAULajvweef61MWVwOujSb/RaiGBahzeY2nSamZkvSGXnN7i5abF
         2C6f8o2ATj4JZ/ILjwZV+gGMWyJEVM9z206j/gcqoq7eZ2TuI1g8in9FpU00f1PYTl7s
         DLbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Et/og//l";
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=83f+WMy4v+ODB2UOXBth2dxkr0XOuhiC33LNyEepJrQ=;
        b=N6sSlbgtDBwIdgce5ewGbRfaLOEXL/x9C/Zixr93awaJ4SmPj6UdfOAllFBzmqmdmP
         n15wJdqi/z4TSA4m04/Awiw7Ys0893O5ecOcECKE+/qV3zeW62IKg9kOPPaTr1zALh/f
         29bq19qh4yDLH42TcFxp6i3JUfNOvZ0RgkrudAKQ+rnNK6YcgSt7jUwgLTLQ+C/hjLRH
         npGpGOyhCMDuoEeysfDUYgwWqrazG+gz2nZq/KZp530M/8a56mmctuZvJy1FoIFcP1nD
         wcz1cpWtsLzjSwr10i78w+pPXEc5MHEWCCJ4zgEhgK7JiJJ1OQY9K+LQiPYNMiCVLZDi
         J8DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=83f+WMy4v+ODB2UOXBth2dxkr0XOuhiC33LNyEepJrQ=;
        b=B33WtEeNxYAMqnJWRmd7Qx4/PxCNN2OslnWjmN/qGlnQIaH1NhGJyuhE21E24MBi1l
         LnUZ2g179c7YqsWTeWSuyks+GVFWb//q3Lv+Lo9Dre+4HeFNIRBb0jXIqOLvrrmxomJE
         v+Nv5uYHdHX6UukxtVNN5t0k3qJLM4V9IgQo1kFP6bRMhciypa4/M+taZ0rCHBmspfUt
         tdqGarRFnyDSvMq3K6eOi5tigczlk2RMdnPwj1qc9GdxA+ZtNtbirpJepppFo0vUMY0z
         IexB2rXpTTIk2oSZikxXKqAvwSRDyqRfRXiRmQ+P2p7SsMtyVwvvsTv880tucj+8if2h
         eiqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533yq8pK/th+iQEdzhFI8RsbYQb5p4ZZkFk1klELWrVvvuvrL2jC
	pl/73pskK+sS46uoNKTJvy8=
X-Google-Smtp-Source: ABdhPJxPUPL+LxmTwDz1ATgTF595YTQH3Namkh7v9LwvaLKDLXEOBqe2Hfqggj8Y65BhaTOmGjw/FQ==
X-Received: by 2002:a62:d409:0:b029:27d:338:1cca with SMTP id a9-20020a62d4090000b029027d03381ccamr489102pfh.25.1621450386872;
        Wed, 19 May 2021 11:53:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:92cc:: with SMTP id k12ls41100pfa.11.gmail; Wed, 19 May
 2021 11:53:06 -0700 (PDT)
X-Received: by 2002:a62:d447:0:b029:291:19f7:ddcd with SMTP id u7-20020a62d4470000b029029119f7ddcdmr574145pfl.54.1621450386350;
        Wed, 19 May 2021 11:53:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621450386; cv=none;
        d=google.com; s=arc-20160816;
        b=zcNtc/YXQ9/ccxja6/QY1dirUjsNV3arUSb1sU8wsG2fCZbk3Y90z1Awj6S2BY5ZkA
         DobBJeucfSeHHfUsADo+JGDORpjazr3EvtwWgorM1e50aIiB1/upkei6d6jNNv9O3ceW
         G5SfHNOrighgoT491zHSbKLRtFmxX81iXm5M+k43P0m3CF/f+YoiKXuqXTVrZEqjNVsH
         Vt7ID4DTYSToaQfEuc+Y+AEbKvLyBHbypSMIUnhf+gvN6Ck3oIuMC7kgzEsSt/AAk7/X
         JhNNbJ4F2ViSTgfjkefPo0++VgDR66L8M1VNrhX1jxeQ73UaX/m3Qw69oEKuAbBdmL9A
         Dtzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1/1m/Ytpcrt+oGeRd9OvQkO4EyWjPtompTkRQaxL78c=;
        b=EwXCUQnZHgOz5fqY6GX/oHwrfYPUlsRXBMNS+PsS1nZICArdYSb+cbB+mImS9T0Dbk
         4EBugg9sjotX3h6L+Q7UzKBREBjlSRtQxjw2hgPHcQ2eLxvOcFrhONg+QwWmJvupcSCe
         nGMgYFb5nVgt9AyLxu1iwn0zE9t1qfydW1HNggMuTlHlE+weFXWiPb6HwiTTJmQ6VcOO
         Nze3bVhg0u+Mf5psApMezgktkB3q4hdfw+DXkm9RF04br8fb6wAjTv0u/TRpIwmcn/JI
         vv1yNBbL0+9lI28WAlZQPxWTRDso9XSUQbghhL/HotZeAsqtNmSA1vizJ55x1rwzY405
         66Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Et/og//l";
       spf=pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e13si65528plh.0.2021.05.19.11.53.06
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 May 2021 11:53:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0C17B61355;
	Wed, 19 May 2021 18:53:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id CA2515C00E8; Wed, 19 May 2021 11:53:05 -0700 (PDT)
Date: Wed, 19 May 2021 11:53:05 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Et/og//l";       spf=pass
 (google.com: domain of srs0=r9yk=ko=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=r9yK=KO=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> [...]
> > > All the above sound like "functional coverage" to me, and could be
> > > implemented on top of a well-thought-out functional coverage API.
> > > Functional coverage is common in the hardware verification space to
> > > drive simulation and model checking; for example, functional coverage
> > > could be "buffer is full" vs just structural (code) coverage which
> > > cannot capture complex state properties like that easily.
> > >
> > > Similarly, you could then say things like "number of held locks" or
> > > even alluding to your example (5) above, "observed race on address
> > > range". In the end, with decent functional coverage abstractions,
> > > anything should hopefully be possible.
> >
> > Those were in fact the lines along which I was thinking.
> >
> > > I've been wondering if this could be something useful for the Linux
> > > kernel, but my guess has always been that it'd not be too-well
> > > received because people don't like to see strange annotations in their
> > > code. But maybe I'm wrong.
> >
> > I agree that it is much easier to get people to use a tool that does not
> > require annotations.  In fact, it is best if it requires nothing at all
> > from them...
> 
> While I'd like to see something like that, because it'd be beneficial
> to see properties of the code written down to document its behaviour
> better and at the same time machine checkable, like you say, if it
> requires additional effort, it's a difficult sell. (Although the same
> is true for all other efforts to improve reliability that require a
> departure from the "way it used to be done", be it data_race(), or
> even efforts introducing whole new programming languages to the
> kernel.)

Fair point!  But what exactly did you have in mind?

> > > My ideal abstractions I've been thinking of isn't just for coverage,
> > > but to also capture temporal properties (which should be inspired by
> > > something like LTL or such), on top of which you can also build
> > > coverage. Then we can specify things like "if I observe some state X,
> > > then eventually we observe state Y", and such logic can also just be
> > > used to define functional coverage of interest (again all this
> > > inspired by what's already done in hardware verification).
> >
> > Promela/spin provides an LTL interface, but of course cannot handle
> > much of RCU, let alone of the entire kernel.  And LTL can be quite
> > useful.  But in a runtime system, how do you decide when "eventually"
> > has arrived?  The lockdep system does so by tracking entry to idle
> > and to userspace execution, along with exit from interrupt handlers.
> > Or did you have something else in mind?
> 
> For coverage, one could simply await the transition to the "eventually
> state" indefinitely; once reached we have coverage.
> 
> But for verification, because unlike explicit state model checkers
> like Spin, we don't have the complete state and can't build an
> exhaustive state-graph, we'd have to approximate. And without knowing
> exactly what it is we're waiting for, the simplest option would be to
> just rely on a timeout, either part of the property or implicit. What
> the units of that timeout are I'm not sure, because a system might
> e.g. be put to sleep.
> 
> Also see Dmitry's answer, where he has concerns adding more dimensions
> to coverage.

And I must of course defer to Dmitry's much greater experience with this
sort of thing.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210519185305.GC4441%40paulmck-ThinkPad-P17-Gen-1.
