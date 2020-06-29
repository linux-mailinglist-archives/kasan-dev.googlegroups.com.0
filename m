Return-Path: <kasan-dev+bncBCSPV64IYUKBBTXZ473QKGQEI7C7LQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f60.google.com (mail-ed1-f60.google.com [209.85.208.60])
	by mail.lfdr.de (Postfix) with ESMTPS id B087020CF31
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 16:38:06 +0200 (CEST)
Received: by mail-ed1-f60.google.com with SMTP id y66sf7071637ede.19
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 07:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593441486; cv=pass;
        d=google.com; s=arc-20160816;
        b=guPra8p8BdkxyW1cwnBGjBtNSRcTGhKbfdGGGSemmjDCxMUcQqMfHXkbgnsR4yX3xA
         cms6jJCVIe05FDIy39OoWFC968swJ4jTUK3aaQzAfHCw7WB+YoQvzPJCTHC2UfO7Aa6k
         5t6tJBeb6vrMepfDEEqnjrm0Kh7IwEao9S7epT92zni750FIaQrDAEjccuyY5PGGRRfV
         hFmkgTuayaKae8xQMRBf03sdRWk8+HqFkHbPvS5QkwNj9333gOhVsbnj3ll21Kdko5Xn
         sfXeoKgB0WExdM+77v2QFTg8/Zs9WdZkDgAkOODo0cE7cq0ObZJAzM85UQiBAbOtFVSY
         eVAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=eARF0mpr9M9bQufl5UkszcQuO7dzk2vyd2Nhk7p+5qk=;
        b=GUXo9Hop8EN+GO/O6uHxwUMvqTPZ7S9FW6F94iNnEiQOTHj9ZcWwpCZp7SpeJg3Ouh
         8R/vxo0iqbKPuG14fT1aCEt/UyE1ebcfS2GOLaBm/cPjfMz39rdlVr9SQe8XyhGiQDOL
         sIMVHOmhL5NUbOSE6LXQcLCckC3kanVuIsDnjjBM461u0D5UO0FeKPm7Tz07S/44rNsx
         AyQydF8qXz6whResXZjwe6ZkavMMnWAaBQZCLVFRHMg2ZZ7kV/bYScSi6a4eHeE+QzPO
         XVY1GtFVATa7lXEa5vGPaw3dwvQYDbuWmQx/MoLXWel8H/WvYcK44+RQ50BGWc5r4Opv
         G6Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=n8pI6Aqb;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eARF0mpr9M9bQufl5UkszcQuO7dzk2vyd2Nhk7p+5qk=;
        b=fDUmmzq7nBUglAuFUdbqYAbs66n9hX8IaeV+2Z3TtO4FuxjK0gJe3e1/GCAy8u75E9
         Ef5IC7HEOYJ2sVGYW3EuyufS7Rk84Oxovqe1TWx8szn48YyEf2sQGY4fRilEM7wc01Sw
         51+Zk3NwfnmQJ0EwyNFn55x/hAMbVvfNJEReH8neLbxF56gWupB2JQuW6K4LPFL/i5J0
         GAi/523dS8LGdR4LiAIgJxuxXJo/fDURsQHf1xJ5bDBlSyXKkmaUKcH1o2wj2MasB33T
         fiI+Vk5JVS+a8Yc2ghBIAfHncFhYKofDMKYEznKkV1uAgSEEuKl7yIoVplFVnDScm5VZ
         myaA==
X-Gm-Message-State: AOAM531aRk4wcL/Yd41uzcEFmli0nENfKWZhJQSymN5ImnjUYhSnF5fH
	P2r8m4OpgYDVTD1lnK8k7y0=
X-Google-Smtp-Source: ABdhPJzFZWugq0R1qnEvTzdd74CmpqgWjF1XnXRYKAOH/xura26zUrrYxh5liU9+bZRMX3OhJJI4cw==
X-Received: by 2002:a17:906:700f:: with SMTP id n15mr2759595ejj.390.1593441486395;
        Mon, 29 Jun 2020 07:38:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:9147:: with SMTP id y7ls4929252ejw.6.gmail; Mon, 29
 Jun 2020 07:38:05 -0700 (PDT)
X-Received: by 2002:a17:907:42d0:: with SMTP id nz24mr15182980ejb.135.1593441485942;
        Mon, 29 Jun 2020 07:38:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593441485; cv=none;
        d=google.com; s=arc-20160816;
        b=hnljthr2OHb1ozVhA7DwrbksVnyx/pkY2LBK9JZz6w0xGp5/sIRbntJWrZGb09O/hL
         J7rTG0qyJW4PJ4+JEzaDh6s2DrcEMdxKdhD98+dkf3f12LsM0LLMSh7ASSedywPM9a9u
         s7oaF/DQj4+/YowjOEQuLbhF4NCAaAB7nyGvaBqTpURA05C8ZVgO+ZgdASda07/NNvam
         Z3UThbMyggGV1ZmXDz7qggH2mH2sKVP93ACiE39hua8hiUMOORTmUi0zTsIYRpToCSDy
         TyA3Y6v+Fw1/Y46Sl4bh+YhRUCAnINxMi8VA6t+8KAmKKadSBkDkDibhzp1FmpB5vU3y
         Co5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ImkFE8JbJAI6KDvvRlrXlVaOSFSsL9bPvC0VRq8yxjs=;
        b=tbth2OixJvoOTpVzUzYzBhiXSq+ImeH/zoMxznnjNZcnMUBj8FL93zlOE79AsU2uui
         59xPmhfd1L7S7dVaDnmUK6Wn7VHOmwEmfdS70+/8e0NG1mZddgK9js9movLGB9C5CaYf
         yPEw8EcZ8cn2NX+xjC438fHIpN344DfuXAcHgvsb2BYD6WKjA3N2+wTn90dV7fjFPYTy
         bexrf/6kGKBmEPGkWTXef3Q4a82Izlrq6Ty/1AS+ucfTt9HJ62fKGXI2D+9Yss/JAPm6
         7s4yWobaGjQCB6F7Bm6l7TTICITeyKxSWECW2kWOk5pvbHJsKPKslK0PIgdVoS+/8XAD
         NQSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=n8pI6Aqb;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id i18si3235edr.1.2020.06.29.07.38.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jun 2020 07:38:05 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:33122)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1jpuuw-0007kd-Iz; Mon, 29 Jun 2020 15:37:54 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1jpuut-0007Br-Q1; Mon, 29 Jun 2020 15:37:51 +0100
Date: Mon, 29 Jun 2020 15:37:51 +0100
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>, Will Deacon <will@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow
 memory
Message-ID: <20200629143751.GV1551@shell.armlinux.org.uk>
References: <20200615090247.5218-1-linus.walleij@linaro.org>
 <20200615090247.5218-5-linus.walleij@linaro.org>
 <CACRpkdbuRCXvnaKvAcqQPCWBWmJYQ9orVhWNrOdhUVJUD2Zbbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdbuRCXvnaKvAcqQPCWBWmJYQ9orVhWNrOdhUVJUD2Zbbw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=n8pI6Aqb;
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

On Mon, Jun 29, 2020 at 04:07:06PM +0200, Linus Walleij wrote:
> Asking for help here!
> 
> I have a problem with populating PTEs for the LPAE usecase using
> Versatile Express Cortex A15 (TC1) in QEMU.
> 
> In this loop of the patch:
> 
> On Mon, Jun 15, 2020 at 11:05 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> 
> > +static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> > +                                     unsigned long end, int node, bool early)
> > +{
> > +       unsigned long next;
> > +       pte_t *ptep = pte_offset_kernel(pmdp, addr);
> 
> (...)
> 
> > +       do {
> > +               next = pmd_addr_end(addr, end);
> > +               kasan_pte_populate(pmdp, addr, next, node, early);
> > +       } while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));
> 
> I first populate the PMD for 0x6ee00000 .. 0x6f000000
> and this works fine, and the PTEs are all initialized.
> pte_offset_kernel() returns something reasonable.
> (0x815F5000).
> 
> Next the kernel processes the PMD for
> 0x6f000000 .. 0x6f200000 and now I run into trouble,
> because pte_offset_kernel() suddenly returns a NULL
> pointer 0x00000000.

That means there is no PTE table allocated which covers 0x6f000000.

"pmdp" points at the previous level's table entry that points at the
pte, and all pte_offset*() does is load that entry, convert it to a
pte_t pointer type, and point it to the appropriate entry for the
address.  So, pte_offset*() is an accessor that takes a pointer to
the preceding level's entry for "addr", and returns a pointer to
the pte_t entry in the last level of page table for "addr".

It is the responsibility of the caller to pte_offset*() to ensure
either by explicit tests, or prior knowledge, that pmd_val(*pmdp)
is a valid PTE table entry.

Since generic kernel code can't use "prior knowledge", it has to do
the full checks (see, mm/vmalloc.c vunmap_pte_range() and higher
levels etc using pmd_none_or_clear_bad() for example - whether you
can use _clear_bad() depends whether you intend to clear "bad" entries.
Beware that the 1MB sections on non-LPAE will appear as "bad" entries
since we can't "walk" them to PTE level, and they're certainly not
"none" entries.)

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200629143751.GV1551%40shell.armlinux.org.uk.
