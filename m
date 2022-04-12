Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBJ6Y22JAMGQE5DFHGJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EB904FE61B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 18:43:20 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id m12-20020a9d7acc000000b005b21f450ed2sf10396364otn.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 09:43:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649781799; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZyKaakmnbzkrdY/UPWYEUbV8PrWMHyKPlPZ4NN+tzjinOuVUUDZabkRnNs1PsxwL8
         xyFONhxdiVgAtu0XMr/EUu8q081bSReDTGi1gZIKeVsGNkC4X2uIY8kjn/K3yvO/Qazy
         V2FTPkiFDe+8AmliS39Ee2/aP7ZcmVnNjJkPgTmyzNuudDhjG9GpHfpw/Qjwk0mE0kVX
         /Mtz21vXWXnpdDbf9nl/OIkpsb7hoDj3O/4CSrMShRMgQT24zEQXMW8YPSmvvDGgRFR3
         eLSeuiQqqUJBBrDnud8AN78gbpW2KjM8uweBh69auy1cUWCmOtVJ07JYLDAzChhW2/jx
         KVLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1vIvNQQ4GkG/wyJRn4njMnc8xWNbesvLef5BRHQG8lI=;
        b=L8xZNuZMzjSslXu25eOx+58tnjIP8ASawcKvDj66KV7y+UBTabkbvixtykMDAvJ7eU
         u7Ni4qfII3cxQJvyprEGicFHtxsMAs8zXZs/VvFy5V7xAajVWPMS0nDgjd3sQT2TH7jY
         wL2N3QmQkP0IZ+ETRqJfg29mkdcn5LZ37qsorDbrArd6ab4ldi58wAtSM9+gMYpI7Xy1
         1xSaMW76u5WdsCZZFf6F7zhgE3ViI0Eb+Z4quZxPH8QFcuAS0T3Wemr2Y9DfJhV1e28N
         wvfPkenZbreu9Hp9RSTU911/y3OXxUy9n88yBI6zvCB8ixSBDJbeGKyfJcj+BPfweGJF
         Y6dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=kMczoEcv;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1vIvNQQ4GkG/wyJRn4njMnc8xWNbesvLef5BRHQG8lI=;
        b=kuApT0VfmuMnCqvuI13hfA400FLjrEkha6uArEW3v1JB16N2KVbv5UnE4Pd7qYO4rq
         PVXWSjncw+F8vpjcjbqcqFU+TPR1YyXiYdY1d0zJgbFdX/ORhLgzyKf3SsiYzcbidzvz
         W6n3dNYIfxAFimlTug/IywC/8rMwwquFfbkhFLFu6w8MK2lTGGJ5dO+Xoigu92eXEF53
         z8kXxW36tlgbfsq/ase/L28p9FfhnZoXkjHRxbaB/CV/EXUDgjGleV4VZtS7/HbPkXhT
         gCdghJrkMiESRqMk9HGN8PlrIrD9oW2hcXLnNFcSO+iNH6eakm1ZaHwZRRw7RQjtiLoP
         lV5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1vIvNQQ4GkG/wyJRn4njMnc8xWNbesvLef5BRHQG8lI=;
        b=zMf6eMg3d9hwBYeZwZmN5ey+d0DOB3Yb/Uwb4Kt/NiyK+/telH8CeWLRGehr3v/b7b
         oo+KB5gwFdjleLK7GyLAZ9yBtv3FUmxpDJJWUdLxlz+Pm9Jk0I5Mbd41aT332IpsX++7
         6pAoaTahwKn7r11Dgv1D0v1ykAO8DLGx3wjBP7Dmtzodv2YWUUPxbPp/JQhF+sHy1hPv
         05SXPkZMGitIJcNy1d+USFVacpjyE6WKqNIMSU9P33P8EvuB4rEW5LcPW3sVjd0E2zSk
         TiOJzCpLNRwVsLfJ02yHK1MtGkTNxRXuI0FMdBgHowVTEaCWk1Y1q5IfUw4DwTzICt2c
         xAaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530b2ZcsKeQZQBYYQP9bcJjexE73uz31zSUPlfAdj4gHOjglfOW6
	OinaLW5HgLnDkbsSGQvaytM=
X-Google-Smtp-Source: ABdhPJxxV8xFiU6Le0hhxr3ySVjIAdf5KTel6LbXzmFb1cI2o4sgrpqTraUPaUURU7rENz+3NoVZiw==
X-Received: by 2002:a05:6870:a789:b0:de:a48c:c953 with SMTP id x9-20020a056870a78900b000dea48cc953mr2603287oao.298.1649781799204;
        Tue, 12 Apr 2022 09:43:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b387:b0:da:ea30:ee8d with SMTP id
 w7-20020a056870b38700b000daea30ee8dls13216369oap.0.gmail; Tue, 12 Apr 2022
 09:43:18 -0700 (PDT)
X-Received: by 2002:a05:6870:a9a0:b0:e2:862:161e with SMTP id ep32-20020a056870a9a000b000e20862161emr2506218oab.61.1649781798849;
        Tue, 12 Apr 2022 09:43:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649781798; cv=none;
        d=google.com; s=arc-20160816;
        b=vyeBKv7M7WK/MbBlC6qWRJEkiJdduKKfHIy6tv6gQ6W0IWeLHjGUcCb7Lto5NsNDA8
         ukNybZ6yIAFXfbIIfefbhFKhvL8oiLB0C6cW69iDblQjXTKqurTUqkFRmITRNdrvUUJ3
         m0fjwY/5/K9DSMucZvneYLezBy6OE6S6spwBkYcKbfaMbf9RLDjkPqsDiCuJLYo9SYvo
         zhexKpKyHIFEUTGhA6rNcMCs6cmU18B5mxj0ldHn5sNSjhCDb4uuUCO/UzanXeKP4clM
         1pTCrjQsNMdgVuwkZ2XOulV0woRsg5MBf5ybf8b6oAMzO7knR991J06YNOGDMF96dWKM
         XEvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iAReynud4J0H+xKvVnBy7WuOLeeVubOHs7EGLR/5NBE=;
        b=eXl1ke4ajRjv2sGJbZlfOxqn/FDK+kaaTMNXudlI2lD3X5Gxc8QpYWHa46FLhVsaOv
         dmdT9nA0iy1bfYOwijo9iWtU6KwCu/gNd966eZp4sOnkUVn9EDFehiWCK6ZDqTWDkPNR
         sJNer1L3TTtcB8yXUwhvmnPGLNbX93T2c/42h+rpDDEQWFI1S8cOWelRwJYguvn4OVwA
         T72iam0tQl0ZkPn5OKk+38+nNkEkOgSqoYa7yJ4yePaVMiKXGAx8TEiOCHHkCeIS52mr
         91yFe42RzahWyHi6MVLpD8kF213zu0P/osYsujrYN4SlxN8C0ubOnrR1gGL682Qa4CwZ
         MfUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=kMczoEcv;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 4-20020a544184000000b002ef895edb85si1766217oiy.2.2022.04.12.09.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Apr 2022 09:43:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 888DA618B4;
	Tue, 12 Apr 2022 16:43:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68123C385A5;
	Tue, 12 Apr 2022 16:43:17 +0000 (UTC)
Date: Tue, 12 Apr 2022 18:43:15 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	stable@vger.kernel.org, torvalds@linux-foundation.org,
	akpm@linux-foundation.org, linux@roeck-us.net, shuah@kernel.org,
	patches@kernelci.org, lkft-triage@lists.linaro.org, pavel@denx.de,
	jonathanh@nvidia.com, f.fainelli@gmail.com,
	sudipm.mukherjee@gmail.com, slade@sladewatkins.com,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mm <linux-mm@kvack.org>
Subject: Re: [PATCH 5.15 000/277] 5.15.34-rc1 review
Message-ID: <YlWsI/v0SWjpyofc@kroah.com>
References: <20220412062942.022903016@linuxfoundation.org>
 <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
 <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
 <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=kMczoEcv;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Apr 12, 2022 at 09:13:59PM +0530, Naresh Kamboju wrote:
> Hi Marco
> 
> On Tue, 12 Apr 2022 at 20:32, Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> > >
> > > On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> > > <gregkh@linuxfoundation.org> wrote:
> > > >
> > > > This is the start of the stable review cycle for the 5.15.34 release.
> > > > There are 277 patches in this series, all will be posted as a response
> > > > to this one.  If anyone has any issues with these being applied, please
> > > > let me know.
> > > >
> > > > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > > > Anything received after that time might be too late.
> > > >
> > > > The whole patch series can be found in one patch at:
> > > >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > > > or in the git tree and branch at:
> > > >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > > > and the diffstat can be found below.
> > > >
> > > > thanks,
> > > >
> > > > greg k-h
> > >
> > >
> > > On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> > > with config [2].
> > >
> > > The finding is when kunit config is enabled the builds pass.
> > > CONFIG_KUNIT=y
> > >
> > > But with CONFIG_KUNIT not set the builds failed.
> > >
> > > x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> > > core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> > > make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
> > >
> > > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > >
> > > I see these three commits, I will bisect and get back to you
> > >
> > > 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> > > e25487912879 kfence: move saving stack trace of allocations into
> > > __kfence_alloc()
> > > d99355395380 kfence: count unexpectedly skipped allocations
> >
> > My guess is that this commit is missing:
> 
> This patch is missing Fixes: tag.
> 
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672
> 
> For your information, I have reverted the below commit and build pass.
> 
> kfence: limit currently covered allocations when pool nearly full
> 
> [ Upstream commit 08f6b10630f284755087f58aa393402e15b92977 ]

I've added the above commit, does that fix the issue?

Hm, I can test that here, let me try it...

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlWsI/v0SWjpyofc%40kroah.com.
