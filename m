Return-Path: <kasan-dev+bncBCSPV64IYUKBBTP4UWAAMGQE3X7PZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f59.google.com (mail-lf1-f59.google.com [209.85.167.59])
	by mail.lfdr.de (Postfix) with ESMTPS id BCE652FEB45
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:14:53 +0100 (CET)
Received: by mail-lf1-f59.google.com with SMTP id c11sf636861lfi.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:14:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611234893; cv=pass;
        d=google.com; s=arc-20160816;
        b=pB2Hr7CvdkFZGVxudIf7ByptLG3AM2wRw5J+B1LCa1ghsYBcH8+EToc6rSfeSPAAlH
         Y7MSQ+PvBGdRKu+7UI4z+NLMMJdIvhhLFn36Bh4wRAT92Ba0ow6sac0weRaGhvsQfzSm
         CXuurP+oq7KKz504I89XHtcN3Ba6560dFRRDFhlYU0QWeAGLhNNmfmQalbV0IvvepUWN
         O8ZPIpD6+M1C4cOotQrNTIPjns5/Y0jxawnYM7M3uQ+Q/OWx4aflNzAY0Hl05v9IzEQO
         He87cR68ubcz3ycBcIh0ok20cPmHga6gKeSCj5pZ2qzQke1d2iQ78WrG8KGpgb1Zj/ie
         YzRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=+eFQ7WLy7CpAq1z0+JDZkJ8d4n/8uMKxD4wmQC5/jJU=;
        b=wlmSCI9JANtmUmFyK2UvdR3qqoborwLnSGuz492GFWhtCzQLs7VW/Ev2R3VcRj9+bc
         f7gqWbXQfqSoxQba1bZ1sRn63+S2d4XrZlwoXDVS7C6AKsTKLswPW33JzmfX9MZNizsk
         XFTxsoLTVyfC1iugfTdP1RoimYE5hvSpljNFMxqRBETDeHmHinmahSX81Froxeyt2Wg5
         0Q8EaPADyBoCuAiWQsbRjL7Sl1Eg7NPynJdOeF3SeNzf1imhfMOEwx+Km3UjEjLGLjOR
         EzGHw8cwQaVRDqVkWK69DElKq4vhQjurhy4XWrSw94UQWpSF0IMp1Ti6KuuEEBdU/TmN
         Rdsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=IMmStaLB;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+eFQ7WLy7CpAq1z0+JDZkJ8d4n/8uMKxD4wmQC5/jJU=;
        b=FubpdybwubL5jl/u7UXNiMWKPlQSkgd0qO1HMs3KYDXSVzvcLi5EZhmU0Rg6plx/4X
         AwQMMMWDBNqjTrDkxFmDA3Sc3a96+BxeOiind8+heuk6R9hktOCfTlM4I+QNmmeK0BRr
         HFbnBFxnIQIkip+o783ve20+xTVF8Nhn4sPbtNneRcz9qg7GAqH6kVK8vtIFpCzbelAq
         5Tnkz/3SNjWfEvEPZoeL2jlvKpyN0XFjr7Icg55R0Ee79ZY8afBUEmFLvqs9ii+KPE4Q
         H2zjTJTBHo+5IQc1d/ps9TDPAez8m8+n3kuqMz8Tp4Y0eJjqv0CzRAspOD/jQQ/aAqIx
         0kxQ==
X-Gm-Message-State: AOAM5327EpwdturbhHfDgRTvVF5vUO/hOf4vruJYITSio7z3XwtU/mfb
	sYFEvCP+kztiH+l0/BmjjCM=
X-Google-Smtp-Source: ABdhPJzXj4swsVbNjdSPQOtFZ8Kf5IeYlKKweyXedu1UR6zQfDKcRG/afYu6TXyna7N5TOsvfit45A==
X-Received: by 2002:a05:6512:612:: with SMTP id b18mr7135678lfe.598.1611234893256;
        Thu, 21 Jan 2021 05:14:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6145:: with SMTP id m5ls520267lfk.2.gmail; Thu, 21 Jan
 2021 05:14:52 -0800 (PST)
X-Received: by 2002:a05:6512:32a2:: with SMTP id q2mr6184406lfe.625.1611234892174;
        Thu, 21 Jan 2021 05:14:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611234892; cv=none;
        d=google.com; s=arc-20160816;
        b=gYmBvzW8NnGxwSW3KOH5gAiw5S1hw4zzwL1GBkYWieBG8coOwrrBWoWf+zDS09vzdp
         wg0RZY5inByGqr+klw3BXSRtzFzaZVxNX1UUrhS841HdERRQBhPVR/Tga7NX++tX5SwV
         bmb6uKFozIthKEolzEGfpHheAz0ysmehBpYQAhzRaltyTs+UQXtKrkgAxoGwHsumDlVp
         bPdWu73rh6xywWbLYQU3WEArzemkj7qNDbB91BloP1yslCT2NClAXlqoBZmqMdgd8NsY
         KrXhOY8UDQkyIyRKpqg+SCCG41WSgXIRlsTYOWiYo4T1HQyZNDXm2XZ1n/79t0SsqgMp
         AC1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=QnSNYCkIfdmtFuRImwEJ+w/RWSw9A2ewhqLS99lWgbc=;
        b=OfvSbHSYCWfnLQQOFx35KuFe9ZUekrjWhRGdOR1Ps4+9ionwG/OlWoeqHDzGoZjEcB
         Lt4W5N5vwpshX3Cc3XmymGYjBHr+hVscx93Zs2z6QFDEyceIlAJaYYru/rG2JXtCs0up
         CCsPlLh0xXBNOUtOos8hfOJuPyyM3N6revgPBd2u7LVYSZCemVYjMfELH23Syp9n6J6E
         lAwSres0qCAGuPGhhvYSp9eg1m6A2I4DDLJRqkUruPkf3xkWlfgNe43giFwxYCGneTLK
         jTBvrWigko4UEj3L+59YYwhBlhPS2EMz6+3EFcTK/LvVnpqNrHtmyww4UMApOPuXgZup
         ogTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=IMmStaLB;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id u24si268194lfo.1.2021.01.21.05.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Jan 2021 05:14:51 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:50828)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l2ZnT-0001Pj-5F; Thu, 21 Jan 2021 13:14:47 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l2ZnQ-00075s-QL; Thu, 21 Jan 2021 13:14:44 +0000
Date: Thu, 21 Jan 2021 13:14:44 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzkaller <syzkaller@googlegroups.com>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210121131444.GP1551@shell.armlinux.org.uk>
References: <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk>
 <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk>
 <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk>
 <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210119194827.GL1551@shell.armlinux.org.uk>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=IMmStaLB;
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

On Tue, Jan 19, 2021 at 07:48:27PM +0000, Russell King - ARM Linux admin wrote:
> My knowledge about this is limited to qemu being used for KVM.
> 
> Firstly, there is are no block devices except for MTD, USB, or CF
> based block devices in the Versatile Express hardware. So, the DTB
> contains no block devices.
> 
> In your first case above, it is likely that QEMU modifies the passed
> DTB to add PCIe devices to describe a virtio block device.
> 
> In this case, because QEMU has no visibility of the appended DTB, it
> can't modify it, so the kernel only knows about devices found on the
> real hardware. Hence, any of the "special" virtio devices that QEMU
> use likely won't be found.
> 
> I'm not sure how QEMU adds those (you're probably in a better position
> than I to boot using your first method, grab a copy of the DTB that
> the booted kernel used from /sys/firmware/fdt, and use dtc to turn it
> back into a dts and see what the changes are.
> 
> I suspect you'll find that there's a new PCIe controller been added
> by QEMU, behind which will be a load of virtio devices for things like
> network and the "vda" block device.

It may also be of relevance that 5.9 + a revert of the font changes
boots for me under KVM, but 5.10 does not.

The font changes were:
6735b4632def Fonts: Support FONT_EXTRA_WORDS macros for built-in fonts

5.10-rc1 similarly does not, but bisecting that brings me to:
316cdaa1158a net: add option to not create fall-back tunnels in root-ns as well

which seems entirely unrelated, and looks like a false outcome.

I've tried going back to 5.10 and turning off CONFIG_STRICT_KERNEL_RWX.
Still doesn't boot.

I've tried reverting the changes to the decompressor between 5.9 and
5.10. Still doesn't boot.

Asking for a memory dump in ELF coredump format of the guest doesn't give
anything useful - I can see that the kernel has been decompressed, but
the BSS is completely uninitialised. It looks like the LPAE page tables
have been initialised.

The PC value in the ELF coredump seems to be spinning through a large
amount of memory (physical address) and the CPSR is 0x197, which
suggests it's taken an abort without any vectors setup.

I'm currently struggling to find a way to debug what's going on.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121131444.GP1551%40shell.armlinux.org.uk.
