Return-Path: <kasan-dev+bncBCSPV64IYUKBB6W6X2BAMGQEO3DBM3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f186.google.com (mail-lj1-f186.google.com [209.85.208.186])
	by mail.lfdr.de (Postfix) with ESMTPS id C7A4D33C64D
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 20:03:22 +0100 (CET)
Received: by mail-lj1-f186.google.com with SMTP id d16sf12797496lja.12
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 12:03:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615835002; cv=pass;
        d=google.com; s=arc-20160816;
        b=mJsiudpx9Q7Y51KDsM9csPtU69ZjwnnJyDuTwLQmvnUTxWTExMpAWKeH8ZNnVuLBSs
         1oighTLG3zJwdvc/3IP8WBB88e289UmP0V7D+ace+eSQLZDTrzuiZ1j4lRkbjDpghd/T
         7uHQ9CmkEjjNT/XJ9CCycauhnQSFpAaI1xA/npSTBo/Yc0Nzm4wz+o020+Vz1r6+zc/D
         1eYK/LSNFmXxzm4sisMh/98h4osSV16NClrlG8nmCgvIQvzX/civ8MM9NP2qhw0OzAeL
         Y1HN3IxkaePTFx0qT0vm2pBw8vXtfpUAkRQmsP5vlpQOLpgFOwxVr3rw71l2zqvfGaV7
         qqtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=w/xqCWV6wFLx5De7JTV94zvcEhTOVYEPKfAM07Gnmzg=;
        b=DPrDD3eraMmmW5pnKNRduKYFLNFKK0XzABJdvs+p0y1GTieIGubJcaoTGhPCKSnP3T
         kgmfZKgi6TMh7RNY9LXTmAbgsupnzqhlzAfJWdC63D5m4EP/WppAaEzPYXCMf6iB671n
         MB5yIHnC8Rbep3/AR8ja2Y4r8QDXybt9H82qvhdz2RuvhiCExHSQWo3dBVGNHiIkvn4z
         /vvP1KmNqXXAT91NiQP0Yf7u5FZOB2HOW3+qPXABTxITehI7imtjE0uEj7Gj7OiNG5R1
         xMDebsig4iYufOiKmXZS1U5u1kkqrVpc7Fd4bl1I06bpP26SyMpxNQn608Bo4DwM013M
         gWHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=f8zlQw8U;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w/xqCWV6wFLx5De7JTV94zvcEhTOVYEPKfAM07Gnmzg=;
        b=XRvp9M8e0mLHIlHHmUtkKWDpxgPx85eN5kjNGXicyIXeeLsbqoZ/62rQsWhQN1/g8Y
         q9UL4Y75oT4X386VdHWUxFoZByLk8o2MWAvbZ9sTu5Pt4ZurospILHl8RJ+MyuQPCx/u
         J7T7iHmOzJETChY7H2svRxPL9VTO5BAmh/Ow6OxqN7o3dyKT4bhHalc8/co6hkgpx8F9
         vTd4O0VXmdOBKLkeUxf+7gO4480axfKRhuyjawEG8RUB5cwNdNqrPO4YtNiXDgkYPqBw
         63qrYp0OPImL/rQ2gFvS990pIX0f47xqARw840Mmi9LfD64D8uEV0g8iU37Ll8GDEX34
         vMtw==
X-Gm-Message-State: AOAM530g6ZIhqbdMnrO4QSmXRbMYii2hnIJ0eudQiurEaLUTr3GAEzCz
	TsFogPxmb9T1xJmR9MbLYS0=
X-Google-Smtp-Source: ABdhPJyOp2pE/BC09AF2H7Erer2RmrKx/qrPSNp+bKsqjJxRkSuNshL2OqrXOYd7U4DxOAzCAQAH5g==
X-Received: by 2002:a2e:a177:: with SMTP id u23mr294620ljl.286.1615835002309;
        Mon, 15 Mar 2021 12:03:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls3585307lji.6.gmail; Mon, 15 Mar
 2021 12:03:21 -0700 (PDT)
X-Received: by 2002:a2e:868e:: with SMTP id l14mr265244lji.479.1615835001236;
        Mon, 15 Mar 2021 12:03:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615835001; cv=none;
        d=google.com; s=arc-20160816;
        b=XqRO4Zio3uS6i/F7XO4cCgO35ataeXo1tIoMitTVp9nrwlGBOxgB5QTrzpfw+YUjzu
         dpugMItMwaoJyF2NVm8QROUJWFVv40mBfjPL9haN0pNwbmbNqEMdiFyJJiKOAWMr0USF
         shjh37s8Gi/Gqr0ANPj8zSuQ69ojAAq46X+CvrknSQJCSyujhGl7yGC/LlpTj5BnLXru
         wlyhhp7tYsOKbC51a4XgOlBiMsv1yviEruGHH7O2NO+Ta5vRnSigAJPkKFOPbBaWIx8F
         Ocssx90o80sP9BCp8d/jodEravJDz4sZPZHQ0rUzFsg3hZZIGEKkjFiEqviJ9PNaTfkF
         X58Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/atDwNOen7kJVJREWDwR+azIrhizELQN75Omn+9/DFE=;
        b=k2IWXDyGJ5c2i1uZSet5G9lCPpLZFqI2kGLjScoGUjgkwT+uExju3Yit/EEV6jBPhH
         h2QH/z6h5mEUGRssgWBnpHmJa7ekEB1/L9yl9fPEh2m4WKyqFsN+0XEzB9xDZNW9XzEW
         uwM3e9Rq/XDZbSBQKt2581cfEpU3/A9t1Yvj9QITqk9LeEtN6nGZFTgXisXhh6dsGB4s
         OBPvNljHxsd6VUkuOsGRE7Rw0g5v0XbMQ9YXv9UD3lx0yOGICvLmYtHZLbjMF07Y3wlD
         GU9mcN4YJBb54a2LhxYECltrSGDwwUvbJt5PISGlBB85SDNSY44E8TG/6Q217wxtWd3V
         p19Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=f8zlQw8U;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id m17si482331lfg.0.2021.03.15.12.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Mar 2021 12:03:20 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:51330)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1lLsUk-0000f4-8q; Mon, 15 Mar 2021 19:03:14 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1lLsUh-0005Xt-Si; Mon, 15 Mar 2021 19:03:11 +0000
Date: Mon, 15 Mar 2021 19:03:11 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210315190311.GM1463@shell.armlinux.org.uk>
References: <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <CACRpkda1pJpMif6Xt2JHseYQP6NWDmwwgm9pVCPnSAoeARTT9Q@mail.gmail.com>
 <20210311140904.GJ1463@shell.armlinux.org.uk>
 <CAK8P3a2JkcvH=113FhWxwSFqDZmPu_hKZeF+y6k-wf-ooWYj-w@mail.gmail.com>
 <CACRpkdatfcNp_5UnkxEuEYCmHYAbV+TV1LJT512y7pDao=JjQg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdatfcNp_5UnkxEuEYCmHYAbV+TV1LJT512y7pDao=JjQg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=f8zlQw8U;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Mon, Mar 15, 2021 at 03:01:32PM +0100, Linus Walleij wrote:
> On Thu, Mar 11, 2021 at 3:55 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > If KASAN limits the address space available to user space, there might be
> > a related issue, even when there is still physical memory available.
> 
> I'm just puzzled that OOM is not kicking in if the binary
> runs out of virtual memory (hits 0x6ee00000).

The OOM-killer has nothing to do with the virtual space for processes.
The OOM-killer is about physical page starvation in the kernel.

A process will instead find mmap() returning NULL or attempts to
increase the heap via brk() failing.

Neither of these events should result in any effect on the kernel;
the process on the other hand may make an illegal access and be
given a segfault.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315190311.GM1463%40shell.armlinux.org.uk.
