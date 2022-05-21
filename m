Return-Path: <kasan-dev+bncBDW2JDUY5AORBKGQUWKAMGQEF73JWAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 2557A52FFC6
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 00:31:06 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 92-20020a17090a09e500b001d917022847sf6135778pjo.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 15:31:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653172264; cv=pass;
        d=google.com; s=arc-20160816;
        b=ckcecBBHuBG0CTqC3ngc5wS93GvnF6NcM9qpTw0FZx4qr6AE6Zn7KGoS6rsJA/JixV
         EtnoFBWUWx+fXv4+X1as0y5JGGmi0QQJIWSdg8HDubnrsaYSvgVlgXV9ffyuD+CXQIqH
         t1xBIu2RO1Wbemti0yh+6Xpy4TukqGIIb+XYj0z0joabGaiQeogY4rQ03l1YCkMHgNFa
         Zq5vjR3JAZO7HE/qLKkHlXTXoF+niQLeftPgto+bj09BtLFDzzAYD1MIK9RHi7QV3Z7B
         F9FpVSkoyWV4AALlqxxglrkxOyoFfdb4Iw4rkfw0Z/jSvsTB9/pvMD9lEmEwTe39ZWEO
         Fjug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=I8bG3eBcGino9OoRPWx536yKTEjYKDvrtCk5mmV8yTU=;
        b=JwAyWN8Ffqh0BMAFljRuacavA91R2cIh+jqqFV2JEIlAPNZZ1t5+zAZ8LS5sdqJ13g
         9JemG/+voUGhZ7NR2+WJ2LPL3uq+mMjnP0SSspQRdu77SB6FbUPOUzzemIDTfNK7ycLJ
         WhPgttk5D6n8dzBcWELjwHtfSk+A8SCWE9akIl0a+uEg4PtWe7l4uvWESIA2uDn/utQN
         4VYlkucGDv8bmTEo1UgYFT1ctlYJfFtFtDUfT7lLrvQ+dh9R0usKo4bWvp/z37HINBuX
         Z5UNNTa2mru/mR2SDSrFKZO+ll/tBoC4Z9ZvI/83bK4D9w6HmLflbA5Zd6gIjQbr3KaJ
         SZ5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NaAO8pGG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8bG3eBcGino9OoRPWx536yKTEjYKDvrtCk5mmV8yTU=;
        b=UFrROndF7VzO72xSkYqSyWC3sOgM4pR/jeV7/Csg90OG/NbftFrzxeaBh5otQmnsF4
         3FCXjs8c48w09VIZ2rtH38+WFh5oPVioK2pTiThxvHhia2J6nF0swkSxSsuQOrieLS7m
         Kgmrdl/0PqdoCefs6rWQBtdMJsbbTvhtPn4WRONOE1xQjTaKKW4x86KCpswK9IQfElyJ
         6q1yneIPPuiPw5mPfxdnk20Rblbo4gudAbfxoQbPo0JnGcq9ps1W/+yecJSKofTr/F9e
         vX6rECur5ftvzbaqGloCAxB7WKJKA6pWNFPNZJ3w367cocfbLy0VYPkafm9Va1zoDeRC
         7MnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8bG3eBcGino9OoRPWx536yKTEjYKDvrtCk5mmV8yTU=;
        b=U9o1P1bhSQoIlNpAIvVKy/uNNRyE3+Ir2bFhbPvOllqZie1fmNsw7EHOqeUkVXUCdB
         vy1085smIz9u+VTXmD8VqzGkPODnNT/7THchvPlmdxRgdab3h6NoDoJ7Nziy320arsxk
         qzHLwRmGzFYf5A/ulDyj7AMd8R5WfOmUicL2lQ/E1Piu0d7w9Ked4yuOv2gMUhfNEqsX
         VTLGw2SLR9QPLwallQV9OQZsBxDdpaDLeSiv061OZ2zc6xhUe3YWD1VpjA7Fw+uaQQ3I
         dP0fmt6GAHCH7/vbez57IxFvEYHjxXIOw5r2EXelgZpJrxdOkXV5LHKt/D3vuokfKnLH
         3Rjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8bG3eBcGino9OoRPWx536yKTEjYKDvrtCk5mmV8yTU=;
        b=EvDAg6/I5NUZeKWlmkpugAFeXAo4wSLha4MWQ+4J0NVQIUKEoJ/jlo8nT9XiaILMIL
         Fiie9p27ZZCnsuGmUj5W4pVh8wEZ0kYQ5ptgrTS1xRpFkURxh698FXdKa6a/cUzefWes
         l8ny/CJMfsV8oyC3icNoXDHxAuXqRe0AlMxzsOzuhbDpAeiA5yUukD7nILvZyWgAHK0R
         Qw6r4WPzYa9Ky26HPURk3Qtk+G0NpizByjce9L2YvmQDwl7+WKpOmvCy7TUqoyAWmJ5Q
         AyYBM7MUo09Z48JCFHM3UYc7vxY3Eazw1IMgkU/GLMDFYbF0zHm+ckCAANbFqI9kbhAw
         k6+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Rulxun2w46G3Zr+ENWKgIKvlacQi2LuBKeDw00wnT7xKJTAo6
	uUwxTYHTjmkMCUtcN3twdrc=
X-Google-Smtp-Source: ABdhPJxvjNx2AuMOyqYWkMOF8bqL3chD2Nc4ec3h2I4+n0vw38k1txm+YsfELMBlo3vJ4HyvS4WHsA==
X-Received: by 2002:a63:dc42:0:b0:3c5:e187:572 with SMTP id f2-20020a63dc42000000b003c5e1870572mr14300438pgj.82.1653172264749;
        Sat, 21 May 2022 15:31:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8c:b0:14d:d65a:dbdb with SMTP id
 m12-20020a170902bb8c00b0014dd65adbdbls6104782pls.6.gmail; Sat, 21 May 2022
 15:31:03 -0700 (PDT)
X-Received: by 2002:a17:902:f084:b0:161:dc38:4577 with SMTP id p4-20020a170902f08400b00161dc384577mr14303326pla.31.1653172263819;
        Sat, 21 May 2022 15:31:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653172263; cv=none;
        d=google.com; s=arc-20160816;
        b=PMJd+Ptlh+Vn/M/G+6WCQ5i5TEk5A7Qikno4NyBF9X9w6o4+20yk75xFumeGfOnguQ
         /50v09NkGimKdGP5o0ChlZ32TyuhPrMkrIJCzz82wg949O9ODEJErx78sUNcmlMWe/68
         kYxvvsEn4QSSA2KIxl9yPMDHBV32ESJyNfD2YQ95s4iAGnKE/cep8F8X8dMKtqCYHAiC
         xdRk8g7IFfDTTk/uvKCQ/Py55VUk9a3baHy6S9g6d+5K7aiTtr7hFWB21Nqaasvi+5zd
         6Xcmh0d9CMFRY2nIBcbVmP2ij/0XAlhdt/3S+rMHUjJbK0yR6XfI9v8kaTqgIa2X1UP1
         KQqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FonIHMi/3lO9Jffb1ttV3+nPKi58eDv/a59C6q9nmzI=;
        b=ZTLcj3GAhwiDs3wfVjFszbERnW/e9jihVa/8EpVAUOCWmwV6Rv9uyICnoBauCL+mxe
         T4dp3ZCe5k/ZyeIb6KKsDJr4BT2C8DV48DQ2Kog82MUcDrI/sILN83WYeswOB2Ynyjeu
         HeeNXyKS+qcpBgiE4vWPIagQKZ7kJgkneVIQUH1V3wGa+2fBM4VOfArlEP/PHDD6S9bH
         gJpu45z6dmC7kukZ5F0NRwS539Nbh4KDiOISzDNbHPh2sFTn+iQOx98I1dAwfVP/TRm8
         PpwqgEv1aqjRNuRKfq690Xhj5pgPm1oitrVJCrPf3TSdqPfvVd70LKLmB0sxfL7g2h6J
         e/TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NaAO8pGG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id l4-20020a17090270c400b0016146ab913dsi122921plt.11.2022.05.21.15.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 15:31:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id y12so12002326ior.7
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 15:31:03 -0700 (PDT)
X-Received: by 2002:a05:6638:381c:b0:32e:49f9:5b6e with SMTP id
 i28-20020a056638381c00b0032e49f95b6emr8942455jav.71.1653172263265; Sat, 21
 May 2022 15:31:03 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1649877511.git.andreyknvl@google.com> <YlgVa+AP0g4IYvzN@lakrids>
In-Reply-To: <YlgVa+AP0g4IYvzN@lakrids>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 May 2022 00:30:52 +0200
Message-ID: <CA+fCnZcM-1oxVeZSPHnnwy-9CiksZhWfqEbms-yg22hRjr7EFw@mail.gmail.com>
Subject: Re: [PATCH v3 0/3] kasan, arm64, scs: collect stack traces from
 Shadow Call Stack
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Sami Tolvanen <samitolvanen@google.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=NaAO8pGG;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
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

On Thu, Apr 14, 2022 at 2:37 PM Mark Rutland <mark.rutland@arm.com> wrote:
>

Hi Mark,

Sorry for the delayed response, it took some time getting my hands on
hardware for testing these changes.

> Just to be clear: QEMU TCG mode is *in no way* representative of HW
> performance, and has drastically different performance characteristics
> compared to real HW. Please be very clear when you are quoting
> performance figures from QEMU TCG mode.
>
> Previously you said you were trying to optimize this so that some
> version of KASAN could be enabled in production builds, and the above is
> not a suitable benchmark system for that.

Understood.

My expectation was that performance numbers from QEMU would be close
to hardware. I knew that there are instructions that take longer to be
emulated, but I expected that they would be uniformly spread across
the code.

However, your explanation proved this wrong. This indeed doesn't apply
when measuring the performance of a piece of code with a different
density of function calls.

Thank you for the detailed explanation! Those QEMU arguments will
definitely be handy when I need a faster QEMU setup.

> Is that *actually* what you're trying to enable, or are you just trying
> to speed up running instances under QEMU (e.g. for arm64 Syzkaller runs
> on GCE)?

No, I'm not trying to speed up QEMU. QEMU was just the only setup that
I had access to at that moment.

The goal is to allow enabling stack trace collection in production on
HW_TAGS-enabled devices once those are created.

[...]

> While the SCS unwinder is still faster, the difference is nowhere near
> as pronounced. As I mentioned before, there are changes that we can make
> to the regular unwinder to close that gap somewhat, some of which I
> intend to make as part of ongoing cleanup/rework in that area.

I tried running the same experiments on Pixel 6.

Unfortunately, I was only able to test the OUTLINE SW_TAGS mode
(without STACK instrumentation, as HW_TAGS doesn't support STACK at
the moment.) All of the other modes either fail to flash or fail to
boot with AOSP on Pixel 6 :(

The results are (timestamps were measured when "ALSA device list" was
printed to the kernel log):

sw_tags outline nostacks: 2.218
sw_tags outline: 2.516 (+13.4%)
sw_tags outline nosanitize: 2.364 (+6.5%)
sw_tags outline nosanitize __set_bit: 2.364 (+6.5%)
sw_tags outline nosanitize scs: 2.236 (+0.8%)

Used markings:

nostacks: patch from master-no-stack-traces applied
nosanitize: KASAN_SANITIZE_stacktrace.o := n
__set_bit: set_bit -> __set_bit change applied
scs: patches from up-scs-stacks-v3 applied

First, disabling instrumentation of stacktrace.c is indeed a great
idea for software KASAN modes! I will send a patch for this later.

Changing set_bit to __set_bit seems to make no difference on Pixel 6.

The awesome part is that the overhead of collecting stack traces with
SCS and even saving them into the stack depot is less than 1%.

However once again note, that this is for OUTLINE SW_TAGS without STACK.

> I haven't bothered testing HW_TAGS, because the performance
> characteristics of emulated MTE are also nothing like that of a real HW
> implementation.
>
> So, given that and the problems I mentioned before, I don't think
> there's a justification for adding a separate SCS unwinder. As before,
> I'm still happy to try to make the regular unwinder faster (and I'm
> happy to make changes which benefit QEMU TCG mode if those don't harm
> the maintainability of the unwinder).
>
> NAK to adding an SCS-specific unwinder, regardless of where in the
> source tree that is placed.

I see.

Perhaps, it makes sense to wait until there's HW_TAGS-enabled hardware
available before continuing to look into this. At the end, the
performance overhead for that setup is what matters.

I'll look into improving the performance of the existing unwinder a
bit more. However, I don't think I'll be able to speed it up to < 1%.
Which means that we'll likely need a sample-based approach for HW_TAGS
stack collection to reduce the overhead.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcM-1oxVeZSPHnnwy-9CiksZhWfqEbms-yg22hRjr7EFw%40mail.gmail.com.
