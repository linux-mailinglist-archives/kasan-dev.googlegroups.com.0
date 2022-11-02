Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBCOWRKNQMGQESC5IVBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A9FB616AE9
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 18:38:18 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id b34-20020a0565120ba200b004a2542bd072sf5335888lfv.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 10:38:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667410698; cv=pass;
        d=google.com; s=arc-20160816;
        b=xV5GvoZXLv+/BBwJZ68J00BpjaNBaawTjGgEhhIMWx/wxEEZe+9+Zh02eWQp4uIHIa
         3JagZNd/QsIYSnRp5BR55wfNgxx9LkZWGXa5VGWqkTDn4qYpFuq653r+a0IzVkXrEcy+
         oEQw4OEcLzuaR1IhavqBdza7ofhCMc3ohDtSpIS9ps9iSK+HGuzV3wylHO7F9qbVFOGh
         W0mq5oKlYeowFpR1gEUEtPf8nTJLOkMFr+Ssf/qEjWi5qSOoSULJKnv23xKtoE6MDLhF
         u6+PZ7590IKcBYg1QsO9dKtAcbMmUzrTA1OJd4Gbkg9UQ2F/UMWmw24DrkBNOxaV214S
         cbJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wk9p7G/UhYlFrMIjPUba3LGeEkfH0DjyrPayGB8+roQ=;
        b=tvPNh+8xCMHF8kaj23aufN+N0OPfm/Cs1wgIWOOux2VB//FAoDvKXfhABZBcLkiZYE
         zjfjJgI17GUOyste2WAZNErrQEwGbjgSXkTarm3Up4t2aINLpvGkNrPqaViqfZnpqMzu
         8PFSvHCosbHc/TsoUc3OL9ycUKbI3vAo72H01d+5yuMMB/ZO4vQx1xamQWiDAmsDqvQy
         sVQtZmnexgZinbUeq6FEuAjSmYnXxCmwGQcm2Gv2XBsTeTZu6puUiOOy6g5pI0R434Qq
         nrpZCu5jLTkZvB5Q+8P0g0yLnCzqG+R/6/osPs9QMiZ/EjitN/NJgq9XsBHJz6qaNoW/
         1pTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QpvQxcSU;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wk9p7G/UhYlFrMIjPUba3LGeEkfH0DjyrPayGB8+roQ=;
        b=lhxQi6QlrPtuI3elvs53j2TBqtwxDTFO58TMN1Ea5dZPM6IXMOG1Dg48J/Z4Tn0igs
         bKxP9Vy2icqnNpcc8pGMwAeXbEY9301sB3gMpoF7tmX9RBxeDEv4zA/9nG8VyU03to/W
         j8uBLSSb3Z0ChKKj6XRbclnzU6i9NgEKJFyEfpRP+NpZNmnJJ3HGYGUMUdvLn9tCB3m8
         jSxdC1iEzSIjsgn8MBNjnbbEy0Tc+d5RUmn/6uGJBQFAQ6J0s8kp97386e59xk3xj7nA
         pZsGcLru43iqbpZijTRxpNPihcqafXVeDycowtGNt+hnH4/padtR6FoWvysGsedQlYc7
         /nOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wk9p7G/UhYlFrMIjPUba3LGeEkfH0DjyrPayGB8+roQ=;
        b=CGtVyiWj/70KFn+D1mdFxSUqQ7mIwEgmDZzVGjxmSTqw4eQFaK4rR5VUtTPti9mT0E
         xMDe3FfJxLUv7kNd1WEfr5oB/XEK4Mm+QuNPqO5K5/1oJiKO4H9lXON1J6Lle9BFVCpk
         h1d3vhlEB0m3cMv/fpxfLv0yRNQf852mbA7eDuBunPNly/uWvxo6RpVy+DvaMjpUsf/z
         fOE3PaSi/UiI1Gz/e2dg0ZCQ0P0cFUKwRfmBLspTcZrJxpzaY5d93w3ubNHr7Bn0wE4/
         TzX8DE+QENbY0wYn82NZ5xG3FWreEQ7+JAjp/gxrmuedYtgaVJrMTncObMLfCScdahTI
         rlyA==
X-Gm-Message-State: ACrzQf1Ui0bJoosE8xNneK0CMn+pzQLmLYFVG8atzjCooD+VhH3qkB8v
	3v5Yj+83mWsmI15YnueV2e4=
X-Google-Smtp-Source: AMsMyM6Qo3Mk5APoQIeNrgY+7H1QXYV58xgf2tzYwrNGDb5P0SrXfvpVm4EfCdTLM2xLTzVmCyGgxg==
X-Received: by 2002:a05:651c:a09:b0:277:2ded:cfc0 with SMTP id k9-20020a05651c0a0900b002772dedcfc0mr9910506ljq.398.1667410697598;
        Wed, 02 Nov 2022 10:38:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2116:b0:48b:2227:7787 with SMTP id
 q22-20020a056512211600b0048b22277787ls2361036lfr.3.-pod-prod-gmail; Wed, 02
 Nov 2022 10:38:16 -0700 (PDT)
X-Received: by 2002:a19:e055:0:b0:4b1:1fd6:1c90 with SMTP id g21-20020a19e055000000b004b11fd61c90mr3050453lfj.70.1667410696265;
        Wed, 02 Nov 2022 10:38:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667410696; cv=none;
        d=google.com; s=arc-20160816;
        b=hSc/k7oXYf8hKYT3Vs1zya9o20G8c0HLhI+8TN4UXbtXMfMa+Zdmd2VtuLtj0/gAWl
         TEu49LGPAqkI/gau4L2kSTunZi8Fjeq8c/WguRW8wVhjQCTSWA3ryLE7jQPAi87dZKRK
         9tBJkq3v1WqHzRpZKgiVX94mQmXkkXDZYbh1N0sxR7xdizhDnYbbxTvFIR241EEnRW2J
         COaxOJzVpKhupgnw3gbcGHZEjnWhV2IpfIAllvUXlb9uLmHbbkYYtV102TVdHWWRZ/K5
         v3y4BCiOfLFg6F9YrJ94EKqRkdDhZ87qnlHry13iEdY6/WaLi3phJTiLvlrsvhQ3ZTPo
         /Qtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B7ABouFgHj5ByNLmtwAswNa0h/Rt+M2oBytR/Rw8uLA=;
        b=BRJz4Ts12LuGfhuoAg6pQghb5jfu7T0szYExhsN0MdlqCxAOrEJdiYSLu+QJ4/Xilt
         xL0we0TRXFHTVGXCryO7mbcP+ijm9QDyWtqTaAd0stonAF3VQNhNtiGAP6QLsvOpKUjb
         sUPGLOjGvMyQYz3B+5RY40TNsSboVA9vP451JP2qQIIopSsvX2HaB3qMzFRTj1yogQQ0
         2nszwOJ5R9Z3cGoEWiPqNCceeD4LH0273gUf/zu6yEIkvwCNdN34AXQLp+b60peR6YRK
         ip7fkNViGPtl9Jm82VZRrtMPYAPU/qsy61etPdW4MdsKGeWrHxTqqE0118SYF3QaKHHY
         gNuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QpvQxcSU;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id s22-20020a056512203600b00499b6fc70ecsi423240lfs.1.2022.11.02.10.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Nov 2022 10:38:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id a13so27640636edj.0
        for <kasan-dev@googlegroups.com>; Wed, 02 Nov 2022 10:38:16 -0700 (PDT)
X-Received: by 2002:a05:6402:d0b:b0:458:a244:4e99 with SMTP id
 eb11-20020a0564020d0b00b00458a2444e99mr26154062edb.46.1667410695620; Wed, 02
 Nov 2022 10:38:15 -0700 (PDT)
MIME-Version: 1.0
References: <20221026141040.1609203-1-davidgow@google.com> <CAGS_qxrd7kPzXexF_WvFX6YyVqdE_gf_7E7-XJhY2F0QAHPQ=w@mail.gmail.com>
 <CANpmjNOgADdGqze9ZA-o8cb6=isYfE3tEBf1HhwtwJkFJqNe=w@mail.gmail.com>
In-Reply-To: <CANpmjNOgADdGqze9ZA-o8cb6=isYfE3tEBf1HhwtwJkFJqNe=w@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Nov 2022 10:38:04 -0700
Message-ID: <CAGS_qxr3dRQ8hUwA9LaFrbH9u4mdxjgfqtCByQ7kWCk-U2L-sg@mail.gmail.com>
Subject: Re: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies unmet
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QpvQxcSU;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52e
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, Nov 2, 2022 at 3:23 AM Marco Elver <elver@google.com> wrote:
>
> Hi David, Daniel,
>
> On Wed, 26 Oct 2022 at 20:31, Daniel Latypov <dlatypov@google.com> wrote:
> [...]
> > > -               return -EINVAL;
> > > +               kunit_skip(test, "not enough cpus");
> >
> > The only minor nit I have is that I'd personally prefer something like
> >   kunit_skip(test, "need >=2 cpus");
> > since that makes it clearer
> > a) that we must only have 1 CPU by default
> > b) roughly how one might address this.
> >
> > Note: b) is a bit more complicated than I would like. The final
> > command is something like
> > $ ./tools/testing/kunit/kunit.py run --arch x86_64 --qemu_args='-smp
> > 2' --kconfig_add='CONFIG_SMP=y'
> >
> > But that's orthogonal to this patch.
>
> Was there going to be a v2 to address (a), or is this patch ready to
> be picked up?
>
> I assume (unless I hear otherwise), this patch shall also go through -tip?

Just noting for the record:
I'm totally fine with this version going in, esp. if Peter is already
planning on picking it up.

This patch makes it so `kunit.py run --arch=x86_64` doesn't have test
failures, so I don't want it delayed due to just my small nit.

Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxr3dRQ8hUwA9LaFrbH9u4mdxjgfqtCByQ7kWCk-U2L-sg%40mail.gmail.com.
