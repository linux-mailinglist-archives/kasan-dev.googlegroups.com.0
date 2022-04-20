Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEEZ76JAMGQEYZ4HDMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DDAE050846C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 11:04:17 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id l8-20020a2ea808000000b0024da289e41dsf407094ljq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Apr 2022 02:04:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650445457; cv=pass;
        d=google.com; s=arc-20160816;
        b=UupFtsxjPJ1/w67rb1f84dXGJ2W1Ou7BlsOPtX2XzWFMFxYIXl6rA7VU/qKfj2cHt5
         3EAlI8Tm507VImQ+drAsaecFWHZAc1g8ao5zoQDUhu1MK0idEwXZM1fOtpOz/lFJqiSb
         ncOeYJqrOwGjGD1coSTGnkX4fKsmNkwlStgOnWIT7g5TkdH5sPTeXLGI56P0769Geuaa
         2k0yGGZTBjeoXDf+eaMlb1z59OsivRqz2k72yJmrln5rYL8qFGcABkZ2clMnBJpqgim2
         pTqLjyOxW4RZWhRzOjEGtY8h85DttwmoxiH1othDCLAwWcrVQE1Vddm/1V3jPghr/OeX
         /n9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yXFlRU8xCmE3bCS5+YLAZuN0+hehhBet3Ne5NMK+d3I=;
        b=T6MD625BKszG2bcwg+42FMCEq6yx1LdbKD1OCFqm2FrbJzAHqlQSSCD/ypKGiiB43C
         dLVE2V8UHbzWxSzuaiO0qN5HOESLqq/r4snAYWHeULgC5kvABAnwdS1Iv8xSOBQrvQaN
         jyTVR5v1dslzKKHuyyWH2x0F9uH26F8sn5sg4t/SSmk0kc8RJLQZsbwBmYDL2huTIFuE
         DVlNtGO0tTezY1Yif7CcWy6lbZdJp99YFcLnASz0CmTg6+xdxdY1D2JxSOLRpJI6LSny
         KBUpjNi4ahXTwlymHFxgcBWylqqsEBV7UdKC14dQWQ1+9GBwYeF4H0LXG/dweidvY3lg
         Od5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xeq7nxTW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yXFlRU8xCmE3bCS5+YLAZuN0+hehhBet3Ne5NMK+d3I=;
        b=gXV+TWaAiRoe+sTUdQBKdiMXeDfmGY/QrrkrIszdShb3fN5XybEht1yxqwlg3CQWKI
         +Iw7PJiSttq6K0GJSdKzwCXjyBZFHWQZaf1xHcHSMOpr3ZO7lg6g9wLk7rNrpjR4RamG
         gL2HiD6G3Uu2FtNo7VKWUJAoayG/TsJPs/LgeZBPRIlYX3Xwr6N0neIcHOrGYnh6nZbb
         teaZ5dXvK3PSMn5ll/e1u9EmJPHzi+AQr4yAmZOPo2qpDcmTx9wYritNTPc3MiZmeNv4
         UFPtVJiXD0p4OhyZkhL5xw4WvF6uvCYcmtlglX4l2tc0fBCJ1I9MHyPhDEy48cQymf5a
         uSbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yXFlRU8xCmE3bCS5+YLAZuN0+hehhBet3Ne5NMK+d3I=;
        b=AJQjebMBppXu+Yg9TsBMQPKa/vKm+NAyvy1laOQSASVYdcHRCN23BsvNLyNpvNRvhp
         f/sDRnS/3f9BwTMUEDn9uZCz/D0Shm2H+7ppTtP3nNMDOdPPMG3H7LyxRD41MF2v3vRi
         +GGOEm7cJf2TL6Zw05PSN79awnbewrkx7bOhxYUYw0UhhhvgoulJrNxO7zFfvVRYnp4y
         q44w/1j4CgQlIpCzOWjiK4mQ7orSGX0mPT43wPQ/hKiGC/JjR6Lzj6ubNEC4VIOoiu0X
         aLSMVLQaE3mIE0IdbS1Tdpb5TLrVfj95i2u/rftzQh4e9ce8s0Ihy3xdrHnLsmEtcEor
         oT8w==
X-Gm-Message-State: AOAM532YJ5feXP2g7FT18+WzyUlGyETPAff6o/BsW+v3ngw/2XtClbPq
	TSOzQigv3pWsPtVV+gOXQVQ=
X-Google-Smtp-Source: ABdhPJy5EzBwyCJ+z2i1HvpgH21biAC4JAlry/9++zNCgTW8McFteT+MK1Xc+r/cS8Gc+Fh+icnH9A==
X-Received: by 2002:a05:6512:132a:b0:471:af97:77b7 with SMTP id x42-20020a056512132a00b00471af9777b7mr4123504lfu.115.1650445457088;
        Wed, 20 Apr 2022 02:04:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1355789lfa.2.gmail; Wed, 20 Apr 2022
 02:04:15 -0700 (PDT)
X-Received: by 2002:a05:6512:3327:b0:46b:be67:83a with SMTP id l7-20020a056512332700b0046bbe67083amr13810689lfe.223.1650445455668;
        Wed, 20 Apr 2022 02:04:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650445455; cv=none;
        d=google.com; s=arc-20160816;
        b=rawv4AK3domaey0eqpL/LyvOrz1rViwtJbYubCJQdVIJ3ZhFByNtxyty0mrXnPaEsr
         o/+w9bceQ9JwCZ1vsYQFonDbOt1vXRMOIcApoHtsFyJsvwpn9ohLApRIej+2MigCSQ90
         QLxggHPqpUkChWYC3bT1Psd8UMp9rbXB/Agg+rIJfdEMhHJpZS3R4zgW2aoLE4zE0Zw4
         vIpAOsJiO74XC3zjQPDoMNjUGMW2A3noC6mmGdNhWp0wcB2bnlOHdFP78B3d9aE+J6OH
         WBi2jZbwF4NsEM1vgFvRpv3UQ5iA42QFmrln+yQViNpIuWrUXcvoTDOhC7LKnsQn1GFc
         aEOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=nzUTcyuR4EzojyRzvTXUG1XF06DkhMoidKVpipah/8Y=;
        b=UwcD4CQJ8b5WBgT3oeFT9iatl0qwi9OS/Yh3rqg7E1nmNazMGaFzBA5fFRtUkaNKVz
         w30AAmh2s+IMn+iioKGTbGuR5nUzWoDCypKl5x2OrFeYIfchN4he2enTjVc2DxmGyQu/
         Y1tq8XE/Yyjm53zZ7OxgGDKVgJfwqQuLfTwl4LADXIpznUG1/GqF9Yczar+++TCPgN1N
         motoCAFDrEUYTafFId1l1xY1KVg5O1Br1tfthPP5oxR0NoySuozs/zAumFbYWeqm6iM/
         h7u6c8jEGMy6iECjO+eNxJJr4Eo3q/7MZUKWeeRtm3NBwtVGk8E0IJ9PRwptA7freF0S
         h9Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xeq7nxTW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 9-20020ac24d49000000b0046bb7703c8dsi55457lfp.11.2022.04.20.02.04.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Apr 2022 02:04:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id l62-20020a1c2541000000b0038e4570af2fso772473wml.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Apr 2022 02:04:15 -0700 (PDT)
X-Received: by 2002:a1c:7710:0:b0:38e:b248:6000 with SMTP id t16-20020a1c7710000000b0038eb2486000mr2620861wmi.39.1650445454920;
        Wed, 20 Apr 2022 02:04:14 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:7d9b:e7a5:8aea:d5ae])
        by smtp.gmail.com with ESMTPSA id u5-20020a5d6da5000000b0020a880e5e9fsm9644074wrs.29.2022.04.20.02.04.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Apr 2022 02:04:14 -0700 (PDT)
Date: Wed, 20 Apr 2022 11:04:07 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: "open list:TENSILICA XTENSA PORT (xtensa)" <linux-xtensa@linux-xtensa.org>,
	Chris Zankel <chris@zankel.net>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] xtensa: enable KCSAN
Message-ID: <Yl/Mh4gjG1hYW2nA@elver.google.com>
References: <20220416081355.2155050-1-jcmvbkbc@gmail.com>
 <CANpmjNNW0kLf2Ou6i_dNeRLO=Qrru4bOEfJ=be=Dfig4wnQ67g@mail.gmail.com>
 <CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX+RYvO1yft_K4hyLQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMo8BfJM0JHqh8Nz3LuK7Ccu7WB1Cup0mX+RYvO1yft_K4hyLQ@mail.gmail.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xeq7nxTW;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Tue, Apr 19, 2022 at 07:59PM -0700, Max Filippov wrote:
[...]
> > The stubs are the only thing I don't understand. More elaboration on
> > why this is required would be useful (maybe there's another way to
> > solve?).
> 
> It doesn't build without it, because the compiler left function calls
> in the code:
> 
> xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
> `__tsan_atomic32_compare_exchange_val':
> kernel/kcsan/core.c:1262: undefined reference to `__atomic_load_8'
> xtensa-de233_fpu-elf-ld: kernel/kcsan/core.o: in function
> `__tsan_atomic64_load':
[...]
> 
> None of these functions are called because xtensa doesn't have
> 64-bit atomic ops.
> 
> I guess that another way to fix it would be making
> DEFINE_TSAN_ATOMIC_OPS(64);
> conditional and not enabling it when building for xtensa.

I see - however, it seems the kernel provides 64-bit atomics to xtensa
using lib/atomic64.c:

	arch/xtensa/Kconfig:    select GENERIC_ATOMIC64

So the right thing to do might be to implement the builtin atomics using
the kernel's atomic64_* primitives. However, granted, the builtin
atomics might not be needed on xtensa (depending on configuration).
Their existence is due to some compiler instrumentation emitting
builtin-atomics (Clang's GCOV), folks using them accidentally and
blaming KCSAN (also https://paulmck.livejournal.com/64970.html).

So I think it's fair to leave them to BUG() until somebody complains (at
which point they need to be implemented). I leave it to you.

> > > Disable KCSAN instrumentation in arch/xtensa/boot.
> >
> > Given you went for barrier instrumentation, I assume you tested with a
> > CONFIG_KCSAN_STRICT=y config?
> 
> Yes.
> 
> > Did the kcsan_test pass?
> 
> current results are the following on QEMU:
> 
>      # test_missing_barrier: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1313
>      Expected match_expect to be true, but is false
>      # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1356
>      Expected match_expect to be true, but is false
>  # kcsan: pass:27 fail:2 skip:0 total:29
>  # Totals: pass:193 fail:4 skip:0 total:197
> 
> and the following on the real hardware:
> 
>     # test_concurrent_races: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:762
>     Expected match_expect to be true, but is false
>     # test_write_write_struct_part: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:910
>     Expected match_expect to be true, but is false
>     # test_assert_exclusive_access_writer: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1077
>     Expected match_expect_access_writer to be true, but is false
>     # test_assert_exclusive_bits_change: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1098
>     Expected match_expect to be true, but is false
>     # test_assert_exclusive_writer_scoped: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1136
>     Expected match_expect_start to be true, but is false
>     # test_missing_barrier: EXPECTATION FAILED at kernel/kcsan/kcsan_test.c:1313
>     Expected match_expect to be true, but is false
>     # test_atomic_builtins_missing_barrier: EXPECTATION FAILED at
> kernel/kcsan/kcsan_test.c:1356
>     Expected match_expect to be true, but is false
> # kcsan: pass:22 fail:7 skip:0 total:29
> # Totals: pass:177 fail:20 skip:0 total:197

Each test case is run with varying number of threads - am I correctly
inferring that out of all test cases, usually only one such run failed,
and runs with different number of threads (of the same test case)
succeeded?

If that's the case, I think we can say that it works, and the failures
are due to flakiness with either higher or lower threads counts. I know
that some test cases might still be flaky under QEMU TCG because of how
it does concurrent execution of different CPU cores.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yl/Mh4gjG1hYW2nA%40elver.google.com.
