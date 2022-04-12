Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBAXL22JAMGQEWGN2EAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C9554FE6C4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 19:23:16 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id y11-20020ab0784b000000b0035d2c9cd745sf3287280uaq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 10:23:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649784195; cv=pass;
        d=google.com; s=arc-20160816;
        b=aR/z9Z+297zyowd3elPJD/tZE6v+mP3GvIE8bi1dAOu8V5/LYPqf08YzOKz988ee+t
         UPn/JTHcHR3W4t8oKY1KpuaojLSyDrjuZvMZaXvqigVhEFVbOlyPSW3jNUNy6g6mKv56
         neIeuhjffL3xR0jLb/8cJP6tjPW6BoLxKKgZ2PsbgQUTsAhdVrP765uMyQ06vITZw+/D
         f1epTV1oa634fSnOcPaHmuS4hV01i+Q6I5X0oJza7Rd8KoMyDESN37PniqBNFoXzht0S
         LMSzheWpm35UJgyZmdk7Qp0oRNZk6UB1QxnDNmd7t4ozdr/3JJixuY/9Q/ruB2X+BevC
         OtjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RziELOAkk4p6DBEJ0uNIxFi7DNPFZWY33UawrMhfyt0=;
        b=U2XuCmQERCi5A8Q1QjQLdf2xu+3CYtj0Wc8OTHcBq2zBUKd4bDC8O+UdQ9VD7BG8nG
         UoLRmv3houjwyrq9YL3igEhFc8Y+P+xxXNjt1h30ulUITHLxqiYnPwFF6HNj+wMQOKeY
         FinQp/JEE5aPfAF19ScfZoxtHznCojS3+ULYLUbiiwEAL7wMTAr3nWgipFWTKF8V9Wnq
         8CDqdAjLK1gIHyj4oa5zPMVKsI/O0brZ+6hBYqiwjXoZ+AqVciCluf7/vfDyr111mc/h
         PhOpwecIV88033t37L9k+upsRbCbAkzO9aUwOk5g4UNH1Qal8Qf/1lk3C3ZefLtDnhI5
         WU9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=PrJTV6Ln;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RziELOAkk4p6DBEJ0uNIxFi7DNPFZWY33UawrMhfyt0=;
        b=PAIug7WsJjfHgxXgl/VM6e7+6RLi6hDKUph2EMCVn8yFMeVQxL8XZlnNxmalmuqKrN
         JRusad5PzpC+zYjRHKWa3nzMkvhiFkKDnv+mGoh4uWoMXTqou5E/dEcEuywRFY75jnoD
         t5THmIDoHEER1DgAyqM41MhwnKXlCkp9CZJ3564iRi5VkPvSHMFAHQdOg/AkDG5TsjrD
         Hsy41bUM9KQhZeDpQS8QzlHiyeGvGAsW5jIkuS9p22P6yZUR3PaeLGDpu5M6gmxIqdzz
         R7C3N3FY+aVau1iz3zMSlCQsWT14t3+7+qLzjA5I9kDOTuhz+SuqmB6DYR4+l57KLSbW
         EVOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RziELOAkk4p6DBEJ0uNIxFi7DNPFZWY33UawrMhfyt0=;
        b=iJQ1XEjUEV9gNr8ee4NvDVzHIs9y18Rs7/5DKDtFi/S0urH4j2IYzHp3N6fDQwvN+8
         Qkha+am3aumcAuTpbAljtODG+uTFu5U9Jht4FR1zDyhamzR5spo24RceI8e4mJsuWlG0
         BgQHxLfqqMtBH7bP2ougUgEzDHEzMV5lWq/99RTilWCx+5x9EWx7EZ+wkly8iuk7UZ57
         Fb4oeXnIYwHnuk7mEBeFS2VdiuT4g7warbU/cffdj9m5a2J3FKpyMwEE3+ijZ/i127Ot
         710VpaEMVbVJQ4k+XwiyezlXllPRMy7MDr43fkp53/eBeyl1JetOHadbYhbz3YLJRy7N
         IFzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307XYptsc7vUIPddblpgBSIxAxAE11CSf9jNrcGPWRTjTKoep8J
	lG0wqq4ow1XnW5ZRnqmINl8=
X-Google-Smtp-Source: ABdhPJzuDYXVpfZCAXH5opham7ljYPo4z6hAzeweBqPUXMXd1PtD9aBdO8EWq+NOiJVagEqBfRwMtw==
X-Received: by 2002:a67:d81e:0:b0:31b:a09a:1c4d with SMTP id e30-20020a67d81e000000b0031ba09a1c4dmr12639537vsj.0.1649784194875;
        Tue, 12 Apr 2022 10:23:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e9d1:0:b0:328:6d87:e799 with SMTP id q17-20020a67e9d1000000b003286d87e799ls2835519vso.8.gmail;
 Tue, 12 Apr 2022 10:23:14 -0700 (PDT)
X-Received: by 2002:a67:e912:0:b0:325:da49:d585 with SMTP id c18-20020a67e912000000b00325da49d585mr6814447vso.10.1649784194140;
        Tue, 12 Apr 2022 10:23:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649784194; cv=none;
        d=google.com; s=arc-20160816;
        b=zvKuqFPSV9TYOk3ndwINMimQSNQq1LgJp2WN6g69OPk+wG6Cg4zxNe4X/DuuJVmH34
         4wuUvlHVkqZH7fFiXUbKeR4anb1lTJFUykmwH/FaXyDx2iI2kKxje8Sl2kxPA2D/TJmu
         eNzUl6jK53vO91LMB9GDmkqwxC0BezAqG/361O+WDT845qH/lFgM5pXQrJKsKPY2548O
         Xbx5r3UIzEXQjD5fWVhguD3E3RUjs1EO37V13yJdcMCX/rB8S/ZBMXWmouVT72rwqeLL
         AQff9ENyX+S0cYuha1d/ewZrwr2h/jHAarVY4UNsPzeE5I7s/yukljIYocp0i0YwjmMA
         UfCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8nbeTGH02M+u+0PfOov84Sai9d85mWghD3XJw3iq8a0=;
        b=ZSKKk4cv54uTbE5WLoshKSnBLGbNII1FSDYo6Vz2Wg6f4xkIoCCEEPzglA1qotrJBa
         3KEScZf1Wf8NNEFlBDedy8wCXomkaRqRvWZ+yasW7D9vLznuhuDwZMCzxuNLVbljSUiU
         LVnRCmWrMA7s44QKPj3BdxDHUwffPUV9Km8VlZinvA5wVw/BcfvEJ/0zBtCA+TwlnXT1
         fJZXwkxSMjjVfpH7HWd9JYZ8G/6iU+ubqRSLdOFlHGhPRhjnc5Fbo0UFeyGvYayVD5CV
         WiPGxOy4eaCuhrq+iW/x/6fG+Pw63NEL5PU2yXFx5YA7QdO0PHuyhwPvVQZ5D6dCfrkO
         uFTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=PrJTV6Ln;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d24-20020ab03798000000b0035d35a0f706si982270uav.0.2022.04.12.10.23.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Apr 2022 10:23:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A0D4E617E9;
	Tue, 12 Apr 2022 17:23:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8D147C385A5;
	Tue, 12 Apr 2022 17:23:12 +0000 (UTC)
Date: Tue, 12 Apr 2022 19:23:10 +0200
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
Message-ID: <YlW1fk8TvqIxiCvr@kroah.com>
References: <20220412062942.022903016@linuxfoundation.org>
 <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
 <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
 <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
 <YlWsI/v0SWjpyofc@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YlWsI/v0SWjpyofc@kroah.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=PrJTV6Ln;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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

On Tue, Apr 12, 2022 at 06:43:15PM +0200, Greg Kroah-Hartman wrote:
> On Tue, Apr 12, 2022 at 09:13:59PM +0530, Naresh Kamboju wrote:
> > Hi Marco
> > 
> > On Tue, 12 Apr 2022 at 20:32, Marco Elver <elver@google.com> wrote:
> > >
> > > On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> > > >
> > > > On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> > > > <gregkh@linuxfoundation.org> wrote:
> > > > >
> > > > > This is the start of the stable review cycle for the 5.15.34 release.
> > > > > There are 277 patches in this series, all will be posted as a response
> > > > > to this one.  If anyone has any issues with these being applied, please
> > > > > let me know.
> > > > >
> > > > > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > > > > Anything received after that time might be too late.
> > > > >
> > > > > The whole patch series can be found in one patch at:
> > > > >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > > > > or in the git tree and branch at:
> > > > >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > > > > and the diffstat can be found below.
> > > > >
> > > > > thanks,
> > > > >
> > > > > greg k-h
> > > >
> > > >
> > > > On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> > > > with config [2].
> > > >
> > > > The finding is when kunit config is enabled the builds pass.
> > > > CONFIG_KUNIT=y
> > > >
> > > > But with CONFIG_KUNIT not set the builds failed.
> > > >
> > > > x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> > > > core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> > > > make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
> > > >
> > > > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > > >
> > > > I see these three commits, I will bisect and get back to you
> > > >
> > > > 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> > > > e25487912879 kfence: move saving stack trace of allocations into
> > > > __kfence_alloc()
> > > > d99355395380 kfence: count unexpectedly skipped allocations
> > >
> > > My guess is that this commit is missing:
> > 
> > This patch is missing Fixes: tag.
> > 
> > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672
> > 
> > For your information, I have reverted the below commit and build pass.
> > 
> > kfence: limit currently covered allocations when pool nearly full
> > 
> > [ Upstream commit 08f6b10630f284755087f58aa393402e15b92977 ]
> 
> I've added the above commit, does that fix the issue?
> 
> Hm, I can test that here, let me try it...

I can't duplicate the failure here with my config, let me try yours...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlW1fk8TvqIxiCvr%40kroah.com.
