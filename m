Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBVXO22JAMGQEEMTN6XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4A04FE6FD
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 19:31:03 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id q1-20020a17090a2dc100b001cba43e127dsf2031604pjm.9
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 10:31:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649784662; cv=pass;
        d=google.com; s=arc-20160816;
        b=LG/FByl1bjCkMbybDTYkSWji4FQUYSOfJQvarSnMAwGyMDNUUJgtZNPfbTy5oDJvSL
         paGOQcQ3WmTXzD0kPWDLH7emT8TzlfWOyv23Rk9UdoPa494RT9fVZa7WB7zeYkuSS1DI
         cAWRw5IMX7P5x7AQU3F7v1el+L/23xCi9z/ZtYeWaOinmAQnIxs4uyFG2QXgdqQNBMXt
         d9VAVNU7ZTyT/nxKOCW5jLwKsKSroYV6ZSX+wuHmaBgsven62rA63tY/lJno90lClZbI
         vedoflRcp6PMw78XBJ1m+er+VV59MbVrFr+fp7O9L0NgMz/UWLzM0htqCew4E27nMqmF
         M9nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UOLItNGtGO0udpNXrKGZgDHqmCQeeGbDYtN/IDFCD3E=;
        b=Cq61L1PS8AtYb6Q6aBy6ejbscZRDCQbgNHtVUADV0OD1SAUGMCT2JkS21p/5tgD5CF
         JYyrHO9jA3XHrzpRztDviSKhbaueAtxCpeH8aOqYuhkpRMHpFeLkdOdhOspICTUZrmW6
         YfLFq2iQmdEygzlMHzqGOMG0+8vhCK3KcE+0rXq3r0mk+qfCwo3hM12u2LupywHpVJSp
         yrRmEqatwoVWtP2V9EGOqmkk6LK+X2BPsBDRHCY4Z/W3U90dgy4P4GS23YGjTgIAs8Q6
         FhgwPIKtmeDDXZDWg7llRKfh2nBpxdFXOsj9zBEthPBmJHi0fO7eXRuSQoiZob9Fl4n/
         90pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="wjIp8//v";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UOLItNGtGO0udpNXrKGZgDHqmCQeeGbDYtN/IDFCD3E=;
        b=LzUnA97PTPNZkNMbn/bmlM0pMOe+ZZ36TUmjfFEakNvrsl7oxBxmEGabH4jwa0CiXr
         TEyWnBHOaUgj6jsbZv0JH4s1iA5ib0azIcQJMwqm6qMbg/ViTPGby7M2nByFaVO2SIoR
         oVUfaM34Wr1eVVDnAwSlqViS7nAl0BxQWYRXvxhkllVrMpRn1CAVtD7v03XaA8m8A5TI
         JZvJhTmCTIWII1+l/Dcpir0PX7qQPT/w3vhXgkUlgYl3xgTN/NDWJ/KQZR3ndHwwUaot
         n3ei57joB6MzR9uQwmZ4geFIoJVjaA5D5IngvUWrAaRr1ebWPjS8n/f+L3HIgwhVaB3v
         ZCpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UOLItNGtGO0udpNXrKGZgDHqmCQeeGbDYtN/IDFCD3E=;
        b=0WOUEhcuj/QIu+DYjflOmu9ezZDDlinfQNV+zOQV5aLCJI42LrTul614g94MPo0FxR
         1rjutGID1r/Ox27MlB0GGBj0J+W5VJfW4sq5kEhp9ROtY3BFJpZ9eJf8ktwwzoPcYcBZ
         /I7KtcpwQFrre7Bwj6Fx7SsNQZCY7oDzYnfoGGOpQAj6EyQHhkzL52TzDFivfK9Bajd/
         VA/IoBdImDE621sarOSIf8osmTcRTqkODutt639AxXqnVfUYWf9r2XMSYXVvmH0ui9G/
         HckXwmBcQv2HNeR8oUchMhZQmY5KzkmIntW06NKPvPYPpTKWwkO03eq5U76qjiyNkvfD
         j/wA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ngFWgRv1o2qibgSlox/6/dkya+oc7BcoYLz2cpcJAqjpatcCP
	0EWU9mHdt2qOgk9UXHcT8J0=
X-Google-Smtp-Source: ABdhPJzAREVRoluP0QMQNc7XweOdkG37/C5Xh3P9HPBkuoEVoC90KdidNfCKL7ArYuJFSHeb+drhcw==
X-Received: by 2002:a17:903:1cc:b0:158:5ada:886b with SMTP id e12-20020a17090301cc00b001585ada886bmr12546913plh.69.1649784662179;
        Tue, 12 Apr 2022 10:31:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1492:b0:505:acac:6e35 with SMTP id
 v18-20020a056a00149200b00505acac6e35ls9829282pfu.11.gmail; Tue, 12 Apr 2022
 10:31:01 -0700 (PDT)
X-Received: by 2002:a63:a0b:0:b0:39d:9a36:a73a with SMTP id 11-20020a630a0b000000b0039d9a36a73amr2875964pgk.502.1649784661410;
        Tue, 12 Apr 2022 10:31:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649784661; cv=none;
        d=google.com; s=arc-20160816;
        b=plCVq/yKs1nv2tMkbVrcKKZJDwaZCtWDh+AIrdLXAP7WaXeF7LvlUHGt3KUJT4iB1Q
         I70dDxpoCu2oYCecoiGQ7Iv/frKSWVwRtOriAmIeplnoq0KBPS/+SaPfgVTkeC4KGGIl
         WTTrR4GL9znjAcYphnZpRcZVyUv2xuXzrsc5G8X2Og6rTp91guugOsXRb4U3r9brytht
         wPjTcGhtUSMi/+oOa0m6FwoeKo1XHOlgLmbTurmq4/7yxpBiMsuny+zxBYxYC4wphYeH
         XR54ZmvGjbdfJDPt7VKd0OOjrnXKgedoiJClpY511TrzwsST8Izo16WcRciJdwoe3YfJ
         rXqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hdpyGWPTBwE7uJ36JXRsmnh2I/9TnktPPTPwHPdwVO0=;
        b=ZO7050VT0PuGi9dXj/j3BYvD/g6N2CoJSSyRs6dv65hMTMMwnCjbE9y5lj5TRBxgRU
         wjR4lkOtlEUmoXVqXu0ZUWVcwYEf8XN5Z5bWHlXGW2KKCjobZfgAwzA0e6uMd8ydJb+L
         zX/5hPyIKE3ojCwNPCm21c50Rn6LXqq6/t2ZREoQV9b1mv6J7bXUqkvosn1fqVZlYexE
         O0EMKE70bUg+RI5tS6PHFR1AuKhLD2YjYkyuataXmeLw204zqaz1rxa+K2m7tJohUWjw
         exxtCzJ67C8miVnOXe2E54lFNu43UJmPpu5xp+5wVGNb9atD96yPu9kCRE/DhDigMNvY
         uM3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="wjIp8//v";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d19-20020aa78e53000000b004fdca03b476si1498895pfr.6.2022.04.12.10.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Apr 2022 10:31:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D24ED619F1;
	Tue, 12 Apr 2022 17:31:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BB52EC385A5;
	Tue, 12 Apr 2022 17:30:59 +0000 (UTC)
Date: Tue, 12 Apr 2022 19:30:57 +0200
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
Message-ID: <YlW3UViZ2DMk8Msz@kroah.com>
References: <20220412062942.022903016@linuxfoundation.org>
 <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
 <CANpmjNP4-jG=kW8FoQpmt4X64en5G=Gd-3zaBebPL7xDFFOHmA@mail.gmail.com>
 <CA+G9fYuJKsYMR2vW+7d=xjDj9zoBtTF5=pSmcQRaiQitAjXCcw@mail.gmail.com>
 <YlWsI/v0SWjpyofc@kroah.com>
 <YlW1fk8TvqIxiCvr@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YlW1fk8TvqIxiCvr@kroah.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b="wjIp8//v";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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

On Tue, Apr 12, 2022 at 07:23:10PM +0200, Greg Kroah-Hartman wrote:
> On Tue, Apr 12, 2022 at 06:43:15PM +0200, Greg Kroah-Hartman wrote:
> > On Tue, Apr 12, 2022 at 09:13:59PM +0530, Naresh Kamboju wrote:
> > > Hi Marco
> > > 
> > > On Tue, 12 Apr 2022 at 20:32, Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Tue, 12 Apr 2022 at 16:16, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> > > > >
> > > > > On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
> > > > > <gregkh@linuxfoundation.org> wrote:
> > > > > >
> > > > > > This is the start of the stable review cycle for the 5.15.34 release.
> > > > > > There are 277 patches in this series, all will be posted as a response
> > > > > > to this one.  If anyone has any issues with these being applied, please
> > > > > > let me know.
> > > > > >
> > > > > > Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> > > > > > Anything received after that time might be too late.
> > > > > >
> > > > > > The whole patch series can be found in one patch at:
> > > > > >         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> > > > > > or in the git tree and branch at:
> > > > > >         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> > > > > > and the diffstat can be found below.
> > > > > >
> > > > > > thanks,
> > > > > >
> > > > > > greg k-h
> > > > >
> > > > >
> > > > > On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
> > > > > with config [2].
> > > > >
> > > > > The finding is when kunit config is enabled the builds pass.
> > > > > CONFIG_KUNIT=y
> > > > >
> > > > > But with CONFIG_KUNIT not set the builds failed.
> > > > >
> > > > > x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
> > > > > core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
> > > > > make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1
> > > > >
> > > > > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > > > >
> > > > > I see these three commits, I will bisect and get back to you
> > > > >
> > > > > 2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
> > > > > e25487912879 kfence: move saving stack trace of allocations into
> > > > > __kfence_alloc()
> > > > > d99355395380 kfence: count unexpectedly skipped allocations
> > > >
> > > > My guess is that this commit is missing:
> > > 
> > > This patch is missing Fixes: tag.
> > > 
> > > > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f39f21b3ddc7fc0f87eb6dc75ddc81b5bbfb7672
> > > 
> > > For your information, I have reverted the below commit and build pass.
> > > 
> > > kfence: limit currently covered allocations when pool nearly full
> > > 
> > > [ Upstream commit 08f6b10630f284755087f58aa393402e15b92977 ]
> > 
> > I've added the above commit, does that fix the issue?
> > 
> > Hm, I can test that here, let me try it...
> 
> I can't duplicate the failure here with my config, let me try yours...

Yes, with your config before it fails, after I added the commit it
works.  I'll push out a -rc2 soon with that added.

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlW3UViZ2DMk8Msz%40kroah.com.
