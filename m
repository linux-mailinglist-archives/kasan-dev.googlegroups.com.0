Return-Path: <kasan-dev+bncBCA2BG6MWAHBBWWLS6LAMGQE7PBGXXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DEAB35692C6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 21:43:22 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id i5-20020a1c3b05000000b003a02b027e53sf10763400wma.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 12:43:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657136602; cv=pass;
        d=google.com; s=arc-20160816;
        b=maU7Vnk8FflRq3dJhYKpVAn7DmA8G44OD5Gv5WC/rCkr0Nm97GcApuw7SNrCr6WaU9
         XQFnUThjXRI1WS5+R+OoJvG1x1e5sSzsUJODGBHzlTMlFg4o9hnqWi4WaK0J6XDloXVk
         sc+Awk4sxPasjJ+SLMrEK9CgVSCL1AfkWV/cjy8JImAvG5VM5lQmRw85+vPxRZ3oN8Mo
         CKSPigxu6mLjuGiMnwWyl3kwMVPFBlJkA+fh9GfbrfFyPQ/uxE5fJgDKQtKmmZwfYO/w
         1YGilvADrbd6bQY2+BZuGOQVvoMWJL45uQu0GMTs6iJzeonj06IfeBbuMcK5+iiTCYOe
         uz5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tD887ZuCbPcvJVgkYqfS8EZmfNk6GWtUdg0s2u21bu8=;
        b=If1Ew1mW8IVAfyzgZ/Cr2bWrDwoRnAZALdURDvbU0I6mZCB0XMHVJvu+y11/LoxdJo
         XWcQDWQ6F1yt+YuWQEECWSkzhHLV6ZUkl/PeqhrLIsOYGwdeuNUwGUMNolyBjptqhHr0
         m1/QMq2u1JjLbm5Qrkjs23lvqeN6jJxaExB9/ZnzKsUeloBAQoMeZCwXPL04Wvx7e8Wt
         KRDelPRfj9Gy6gn28F/q5tAw95j74o4Iig4oPoBFx5O/fcluq588oViYTHkXht9A8Xqw
         XsWbzJYzUCl5rgJrHC96hXUWCIYsj0wUN1uz5JEB5nHNQmFAEZWFIrzujj40O2aWVLlY
         FTbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mc2otIGu;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tD887ZuCbPcvJVgkYqfS8EZmfNk6GWtUdg0s2u21bu8=;
        b=KKwWharh+nVwTdsdBlZMOVGF1lAjdW5QAr/dEZHA1BYP7FF/mMKAk5Zcoyv4/Rq/Is
         eYw78TVmHRGTUn58z24UicPHWX2kMUXSVyTmPFEDx9Vxvm8zE93FuAc0ytns+3UNqoKs
         /PgI6BO5R7c3bMlA8oztU4HXDA2Uo3hlTTynuGizB+TV50+nk8ntuEW6Jtf1/AOVHF+6
         QC+R5EsApj6qrXU61kI3fDdcZmiNCLfq7dKjgb78R885eoRM1ZjKZTZCXTkCtAHIdve6
         tZKZBNWXItGDolKS2uU9cd1wtI7x547k1Y3XELk1BXSvbs/8daHhkcOs3qVpuhJ2swJR
         XR8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tD887ZuCbPcvJVgkYqfS8EZmfNk6GWtUdg0s2u21bu8=;
        b=5LWfL2uySyzJ2J4fyiazjmNmRtdRgzgimmXjFt0kQqdeKj/pw3OcIvBx9EKi6oA6Sz
         XN10I7XjVCLuipw+llR3VaAKaXROoMiwewiNvy7h79aeHnZfgJp5RfU4otqFirD/aCt/
         pByGnZaImb/M0R+2AhcHR980qXpJcUzQyjqdDUTx1X8aHAf1sH1MZXYQMX0LmteevCN4
         2HZniLAWpEFDcf83OrDzG+qZPhkX7CZvx/lQRlujR4ThhwIaPJN1MBm0aOGXsCljL3II
         BgvJ17DwXxygu9mrlthFqw0lhQbAnZ867qHTStL7Za5K8E03fTT4qM6LDDnDZ5tcGrIG
         B7Ow==
X-Gm-Message-State: AJIora/1tNdFuodB1yB1BNt72I43AnRSGrTcUTESUNzgwz+GjaT2beHB
	UbpjWfKkVlVm1bQAUSQ8z1Q=
X-Google-Smtp-Source: AGRyM1vQFQouxmGbCuv5TVLQ+x7UomqVkvNdFY50P4dcHtNRdheEQ8MI0kMBvwq/0vaYA00JlJATNw==
X-Received: by 2002:a05:6000:18ad:b0:21b:a24a:1786 with SMTP id b13-20020a05600018ad00b0021ba24a1786mr41814281wri.115.1657136602361;
        Wed, 06 Jul 2022 12:43:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:178b:b0:21d:350e:23a6 with SMTP id
 e11-20020a056000178b00b0021d350e23a6ls7289722wrg.2.gmail; Wed, 06 Jul 2022
 12:43:21 -0700 (PDT)
X-Received: by 2002:a05:6000:691:b0:21b:8d0a:6035 with SMTP id bo17-20020a056000069100b0021b8d0a6035mr39966079wrb.230.1657136601329;
        Wed, 06 Jul 2022 12:43:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657136601; cv=none;
        d=google.com; s=arc-20160816;
        b=b+C3R5P/a1PozNE8y9Tl4RiNvT9rUDw+zR4RiYOLXJz/4ZRqEkQp9puq0MCYCos/q1
         uS+Eoc9fcTxIpEqnW6HzzANM7wLXC3VOnmSQscNhy5yehbdAOKCwl1+QZwlgKtcAEeO7
         JsSMLo2XTvKmArMC0+Va0PAQDMbrReMHZEjX/46/5fQBp/zvjbvTnb3EFlaWUF/8CdSY
         KS5cnqKqgUoA2OToT9pTjpVPLFAUeFSC5Wg5kThNiq21uXclUJFG6HCD6NbHD1ziYGy5
         j92tZ4zTyz0G2fPiLpxVbwyNZYcRPGVAKSKzSeP0fAcuCvHR+gblK3+J945w4vAo5uhm
         hhCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uQRsnwv9u5IuL08Zu0b0BsRI6BGP8zbhAD30ZwGOKSY=;
        b=YcEqK7edowjrKnTuJguQAwMRVmQLjpIhKcToZcDtIHtSYP09LKn8pZSa5xkI13Hj6J
         KLLMpA+23XCi50L6iFkKOXqF1wUMcTa+veRTxNNQmrSeQZQJMEOsMovgyFKByCsdrNaL
         pKrTgW1AV7jpsQSMz/xFF60xpsoL4n7Dv48WkThNMMPRK7TfZNgtWkSDw25VDfUNG4I0
         EPEHQP3/2Y4afNwuI9fsX2F3D2Msrhr9piOMEBvyI+ZeWM3tKQnu2/H6ZRVTAFZVUFct
         69EoTfMXxlfo+URDsbU9W/nsFvfPoKXC/6lXo+kUkHRB+StPSvyCecGWxnGlDHzQLlQj
         61MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mc2otIGu;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id h3-20020a05600c350300b0039c948d7614si12297wmq.3.2022.07.06.12.43.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 12:43:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id j22so2577861ejs.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 12:43:21 -0700 (PDT)
X-Received: by 2002:a17:907:168c:b0:726:c521:25aa with SMTP id
 hc12-20020a170907168c00b00726c52125aamr40430672ejc.46.1657136600905; Wed, 06
 Jul 2022 12:43:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
 <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
 <CABVgOS=X51T_=hwTumnzL2yECgcshWBp1RT0F3GiT3+Fe_vang@mail.gmail.com> <CAGS_qxqsF-soqSM7-cO+tRD1Rg5fqrA07TGLRruxPE4i_rLdJw@mail.gmail.com>
In-Reply-To: <CAGS_qxqsF-soqSM7-cO+tRD1Rg5fqrA07TGLRruxPE4i_rLdJw@mail.gmail.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 15:43:09 -0400
Message-ID: <CAFd5g44dp05DaEot23_a2QdOGfmg=eehtoe24=6yo_UKiGNukA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: Daniel Latypov <dlatypov@google.com>
Cc: David Gow <davidgow@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mc2otIGu;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, May 19, 2022 at 1:11 PM Daniel Latypov <dlatypov@google.com> wrote:
>
> On Thu, May 19, 2022 at 6:15 AM David Gow <davidgow@google.com> wrote:
> >
> > I tend to agree that having both would be nice: I think there are
> > enough useful "machine configs" that trying to maintain, e.g, a 1:1
> > mapping with kernel architectures is going to leave a bunch of things
> > on the table, particularly as we add more tests for, e.g., drivers and
> > specific CPU models.
>
> I agree that we don't necessarily need to maintain a 1:1 mapping.
> But I feel like we should have a pretty convincing reason for doing
> so, e.g. support for a CPU that requires we add in a bunch of
> kconfigs.

Agreed. That being said, if we have a good convention for archs that
are not in arch/, then it should be OK. The biggest thing is that all
archs passed into ARCH=, if supported, should have a default with the
same value for kunittool; as long as that is the case, I don't think
anyone will get confused.

> This particular one feels simple enough to me.
> Given we already have to put specific instructions in the
> kcsan/.kunitconfig, I don't know if there's much of a difference in
> cost between these two commands
>
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> --arch=x86_64-smp
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> --arch=x86_64 --kconfig_add CONFIG_SMP=y --qemu_args "-smp 8"

Also agree.

> I've generally learned to prefer more explicit commands like the
> second, even if they're quite a bit longer.

I agree, but I think I learned this from you :-)

> But I have the following biases
> * I use FZF heavily, so I don't re-type long commands much

Same.

> * I'm the person who proposed --kconfig_add and --qemu_args, so of
> course I'd think the longer form is easy to understand.
> so I'm not in a position to object to this change.

Yeah, I think I am a bit biased on this too, but I don't terribly care
one way or the other.

> Changing topics:
> Users can overwrite the '-smp 8' here via --qemu_args [1], so I'm much
> less worried about hard-coding any specific value in this file
> anymore.
> And given that, I think a more "natural" value for this file would be "-smp 2".
> I think anything that needs more than that should explicitly should --qemu_args.
>
> Thoughts?

If we have time, we could bring this topic up at LPC?

> [1] tested with --qemu_args='-smp 4' --qemu_args='-smp 8'
> and I see the following in the test.log
>  smpboot: Allowing 8 CPUs, 0 hotplug CPUs
> so QEMU respects the last value passed in, as expected.
>
> >
> > The problem, of course, is that the --kconfig_add flags don't allow us
> > to override anything explicitly stated in either the kunitconfig or
> > qemu_config (and I imagine there could be problems with --qemu_config,
> > too).
>
> This patch would fix that.
> https://lore.kernel.org/linux-kselftest/20220519164512.3180360-1-dlatypov@google.com
>
> It introduces an overwriting priority of
> * --kconfig_add
> * kunitconfig / --kunitconfig
> * qemu_config

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44dp05DaEot23_a2QdOGfmg%3Deehtoe24%3D6yo_UKiGNukA%40mail.gmail.com.
