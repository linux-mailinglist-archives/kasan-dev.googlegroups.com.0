Return-Path: <kasan-dev+bncBCT6537ZTEKRBS5422JAMGQEZWA7K7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D34114FE507
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 17:44:12 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id p3-20020a05621421e300b0044427d0ab90sf10405019qvj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 08:44:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649778252; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVLmtyrdBmpzn1IMQm3IUM6A1dlUHrD2VAhtgVCBjty0z/eOnZZXK5tzWIV3So6oL8
         3Gxb9mU3ygtYWXNy/C72ukwfnkKFxSu9nmWD28t+ELhu5u4cTQleoKh3G3+f0761Z+0y
         b3lKgvluAk5lNpXFZ/UjWKz7kf7R93V38jEczqrOssHhXwvQK/lG55zsVNAYdOVylSHo
         UBhawGNOsDHjvgBNHMhmyBU8KsHq14bKWOy5QlOARYn38eD40Sp9uVuQDbT0m0opHUM8
         R9RtHyaa20ZKfCSAjTFKzccilkS2AEHWB6mvUe3Dlts3HZfjBh2q/Pe9botVRkfDe6zY
         xncw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fgGiwaRsRaydYE+XCr3Wc+bMOejy8BJxw8NhAwULhB8=;
        b=e4jQdqfAxVmv5eUVPkMxZn6ytw8i2Hz3RbbOPGl99t2bEBv9/yJtXMv2QGfFYyXQL9
         6DWn87hhVRASXgaz8kfl3HxmczDdQIngiEyyfpTLZF7vmjtnMhsOfvC0+mLofmuVFfr4
         v85AA7h6pYh0aMQV5vMqpSLknWKlMfe292nF23qqEPcDtHIlnjYdgTqyJb3MzBqU0ui/
         KMwiFfhgJ3HUVp+WM0c7DrZ1FGfHVarHuyPMH4Btn5n4Tdb7oFp6Lf/nxjnvuLDs6tUo
         6UDCYm2pMILM5GFTt3oRcU9CSj1MA1Isxz4XQX1JTlbURz/c4E8pgONDLnf2lSo2oes2
         bSlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=FBpU8iZr;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgGiwaRsRaydYE+XCr3Wc+bMOejy8BJxw8NhAwULhB8=;
        b=Kaw/iLTPc+AMoDzhGSdrgGB3d9w07WHBM6PJ/TMNVYJYTyg96JggiSvp7EfFcYv5aR
         Tr2IwZ5ZdTczSHRNuLlgjCXowMQXs1M5MrDHMXbv0tvHVPj/kUBGBoGY3i1aYPeN5Cr7
         KLBk7ghd2Z6Cp78ABmekQ/15zGjRgVPi0QCjAhomGT8MPqrk/Ba5Jk6ygWtzzXVTF4OC
         R3rT0QqWCMnksrksGYDUbERlXD3aEqE6+aNK10+DF070hcJtPrYNqY9g6s7Ds7L1+FK0
         siPDWY+3SBeW11Wc/RWI62AKmgxpKXIceDUNPs1vApaViGCN3lVe9gytTdFPtZyg333b
         ZVNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgGiwaRsRaydYE+XCr3Wc+bMOejy8BJxw8NhAwULhB8=;
        b=gBs8LQdolLyqlssm8eTj0H/Ttr9mRhVMamAPghb4qLEiz33qZrMNqA3fFiFCXgEFim
         bh0EUVoczP4LZ0rKRiL3pP5HSrmB1tURIbVJb17YqoPdRqTQHBXp8PjaMWMgT3+m9Mhb
         uttxJgFywpoovfBzJCZcG0KKET/rJ/1RxFrZ3lsmNUfA7+VSayUy8FK8BqnCHs9Q/zB3
         sytYe0uGf/iwtna+Iv3o2jP3v1ytD+aOoNDtyloY8G68Jy6/dj3U6tyrOj2GEfS8aniW
         p7RsXNmIOePlaBrO1bdJv7+6egiWDDlSupxNlhW82SyuHSO06JvPKFCHYJTo/TSGuBsI
         RnYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gM3iV9iUhC2b5AVWvYypRW3oLN2M+gu3vnSylqiJC9ZyBQxIa
	ldvQhgQvwpys6vLlomDYeXE=
X-Google-Smtp-Source: ABdhPJzpy1M8aZecWTtpHSPS+Erfma7G5uINZ2Gh2RLgUFo2kZClezyn2UHWKO//dD9QH6kZKzNw2A==
X-Received: by 2002:ac8:5d8c:0:b0:2e1:e196:326a with SMTP id d12-20020ac85d8c000000b002e1e196326amr3748719qtx.475.1649778251894;
        Tue, 12 Apr 2022 08:44:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:203:b0:2ee:ee93:959e with SMTP id
 b3-20020a05622a020300b002eeee93959els7130223qtx.4.gmail; Tue, 12 Apr 2022
 08:44:11 -0700 (PDT)
X-Received: by 2002:ac8:7090:0:b0:2ed:ca4:f08c with SMTP id y16-20020ac87090000000b002ed0ca4f08cmr3679177qto.57.1649778251375;
        Tue, 12 Apr 2022 08:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649778251; cv=none;
        d=google.com; s=arc-20160816;
        b=R9Q5huVxkurN4J8OHiQZjLChcue7oAV2k6SbpvPEr7wt9kLxFAnuevHb84LXXTmSwv
         PeQF5p/kNVXfLkTYIrzED4DN9Rpjrt9VaEbaKVwtpwXWM53QHN2NWkwDuvyCp8pJcZF5
         6e94T7UuLU8tEAzzbKuXXp059ljwMxoyXN+6X+xerHOW1fQTuGeVu9G8Kz3FbR8/ue2V
         2ZzYFqV7tjRLdUCUQ0BIT6e7Oh75u1gJurCQ/HZseYOc1aB2Un09rTR2YZpcLxO3gHQe
         JkAXftOALZngoUidXK2BQpuF7SchIPapo7n8NJodzcPuFqnUalMigbN1sGql0WzHP1My
         3epQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tr9PBKtwF8uwxpVk+FAIjyu0P4+AAl4OjgCwV9dPuUk=;
        b=S5Z58rf9OKnkUKsc3WgmwO491JRY1kNcz0Fv9Q7vSfPyurQL9asEeEDZTT80JXJUer
         NjoOECfyptfgCxR2EtdXK9x/6tQ5VcfZL2J9Spvn5zOT2giuHOlH2czLWM8+pcWjqQJC
         fqnnd4hohAxGXcJjEfphMI4gER8Z07UitHdcuX3qhT+YvjXsG+zMRlDJ2W3Gxek6ZoBQ
         T254/hCj2gfbWD7gi+v3hXDkQq2QQNacEPK6sSLYSro6sOSm0gbvbEMShPHgSKGcW3na
         cLVNlBwy38u8jTP27LX/fy2iSE7ZUL4Wr+0S1Ke6mNKELI2w2Wk9wyQM3Ta3o6jKWKWi
         rRwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=FBpU8iZr;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id d192-20020ae9efc9000000b0067ae8797d6esi1219447qkg.0.2022.04.12.08.44.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Apr 2022 08:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id m132so4535927ybm.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Apr 2022 08:44:11 -0700 (PDT)
X-Received: by 2002:a25:df53:0:b0:641:1f31:1d3d with SMTP id
 w80-20020a25df53000000b006411f311d3dmr12954621ybg.603.1649778250882; Tue, 12
 Apr 2022 08:44:10 -0700 (PDT)
MIME-Version: 1.0
References: <20220412062942.022903016@linuxfoundation.org> <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
 <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
In-Reply-To: <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Tue, 12 Apr 2022 21:13:59 +0530
Message-ID: <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
Subject: Re: [PATCH 5.15 000/277] 5.15.34-rc1 review
To: Marco Elver <elver@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: linux-kernel@vger.kernel.org, stable@vger.kernel.org, 
	torvalds@linux-foundation.org, akpm@linux-foundation.org, linux@roeck-us.net, 
	shuah@kernel.org, patches@kernelci.org, lkft-triage@lists.linaro.org, 
	pavel@denx.de, jonathanh@nvidia.com, f.fainelli@gmail.com, 
	sudipm.mukherjee@gmail.com, slade@sladewatkins.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=FBpU8iZr;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Marco

On Tue, 12 Apr 2022 at 20:32, Marco Elver <elver@google.com> wrote:
>
> On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> >
> > On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> > <gregkh@linuxfoundation.org> wrote:
> > >
> > > This is the start of the stable review cycle for the 5.15.34 release.
> > > There are 277 patches in this series, all will be posted as a response
> > > to this one.  If anyone has any issues with these being applied, please
> > > let me know.
> > >
> > > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > > Anything received after that time might be too late.
> > >
> > > The whole patch series can be found in one patch at:
> > >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > > or in the git tree and branch at:
> > >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > > and the diffstat can be found below.
> > >
> > > thanks,
> > >
> > > greg k-h
> >
> >
> > On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> > with config [2].
> >
> > The finding is when kunit config is enabled the builds pass.
> > CONFIG_KUNIT=y
> >
> > But with CONFIG_KUNIT not set the builds failed.
> >
> > x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> > core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> > make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
> >
> > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >
> > I see these three commits, I will bisect and get back to you
> >
> > 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> > e25487912879 kfence: move saving stack trace of allocations into
> > __kfence_alloc()
> > d99355395380 kfence: count unexpectedly skipped allocations
>
> My guess is that this commit is missing:

This patch is missing Fixes: tag.

> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672

For your information, I have reverted the below commit and build pass.

kfence: limit currently covered allocations when pool nearly full

[ Upstream commit 08f6b10630f284755087f58aa393402e15b92977 ]

- Naresh

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYuJKsYMR2vW%2B7d%3DxjDj9zoBtTF5%3DpSmcQRaiQitAjXCcw%40mail.gmail.com.
