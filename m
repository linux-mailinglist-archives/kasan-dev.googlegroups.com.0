Return-Path: <kasan-dev+bncBCMIZB7QWENRB7EMU2AAMGQEHQCYNMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id C42BC2FEC3C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:49:49 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id k126sf1627061qkf.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:49:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611236989; cv=pass;
        d=google.com; s=arc-20160816;
        b=fDtnBM9jqIdRK8kfiUEWys8fDLJGlvX0rvbuxp6LOeyeJy5UU0tzf1ukA9JHbSICOS
         VDnPgjsZ2RnRshJfgKqXtiLQCrk+rCzv0MHtCwOGRXFRL4cQLU1A7PFcpFGC7ddslDJa
         KRS/cbY2amg//pcrxPW196qS/68dN52Kgbpkt4/190ZYsPUVvBMRaT8vFmlHHpX41m2S
         BO8mn+4gZSOIoecXjShARFTcLFfoydzFvlhtPpGYbJ9CdVzZH2xmTj96DG5SWJbdNZf9
         nLbt3M6HL8359dZERooLQraXsEic7QHzcXkRabU5kIuEv3/L6AX2utF/G6lpX0Gsvaj1
         Vojw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PPJwN3GVfbhaZoR828si+2tw+0IVj5j1i5BH2Hzm9Ps=;
        b=045DYBbA8OYsz86kP294esWGOJjXThMyAUQB60wjReTPiitbcrczXuavH+1KmvsmQx
         cAWgsaEp/7UfoGhZc4D5Hg1r1g87Lm8Vw/gKKPG0KC4TIXNz5hfdQKdJHugAQ4Rpqvba
         mKdEC/pwri6BwRQSlrgd8vQUkSfgIUwd4QLuiTR/UihC0BAzxmZIDL3b/610Vk99WIDs
         N0teCCykfcxsMcsmjbRIkKrbd328mkvVMhRw463y72gCOhtr7thlDZyXRjeJdxTiZuND
         FmNYCLj0q+AkijHQEOcYqtUxPQYfKSRNs80xxrVz3UPKoiOzqtP4cZ5ur4im/EIsOikh
         fc/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kdj92SEQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PPJwN3GVfbhaZoR828si+2tw+0IVj5j1i5BH2Hzm9Ps=;
        b=Md4/36TqkOLnUv7RIFL++EtHEiubattL0EM+2ITPgGduADbaVYpH2Wz/FHgL2cFzGd
         KxNyla52eCuG8JRvSeO1U0NKqiL4GNrINsq6P5kPxikasO/796z6GQ6j55YUo+pC/48v
         Uiug3p2BiOWa3KKUq3zs5bRgEzTcYb6XQKP3ciU7KJppk7prObfN4zqNOKehcfWoRLZK
         gzeD2LHHATMittLWOtT6DffHqJOhXLp0jKiQYkS3BdjZKQ2ab28xmzLke4smHirZonP2
         ZW0sKj3DIrCu5snKGBiua1cNNHPOy3wXlEXKlhGM04yXXvZhOE5K7vmG3lHMf+kEL9ei
         08rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PPJwN3GVfbhaZoR828si+2tw+0IVj5j1i5BH2Hzm9Ps=;
        b=k8VloHZ4IqO24sXhJQmsp/MQeVrTzFriw4Hvex/lWDxHn36Nof/+7TnOAhaxVGF49U
         lmuNP7jDCR1i66gA3RX30daCxBxlKfJD0EiiudF9qmLyXQWIPzyK/9TJwCn8UHG9zPnc
         cVMF0PLHuomeEjioFzGas/qqIHAvEiQ57pEbGBJQaVhCmube5o3/JmuAsWYtmFOSA+FY
         kmBOx/2affACO80LyMyGFWXkQrpsPsnWXxGqSJLtgmZIbEN+vyZc/VIQSI+/YBGNsDeY
         x/biXHj5kHd6vuBq7op575skd7HbgtY751qsLx4DfrIkZ1MWSHJrl0TTPefWQio1RgJt
         p4Mw==
X-Gm-Message-State: AOAM530XR2weUkJex1MxzoVZLQLjIpYkpKk5yh886piNCG+YlJ7ZWP6Y
	TLUBjmR8+IuEViy7GaRXtIQ=
X-Google-Smtp-Source: ABdhPJwOB9yZufuAm5eCfIA/RZjmcidumGIWFzQR8D9N3anSzjbOwjbRF8fsqtmsrHopn++Ax+uwOw==
X-Received: by 2002:a37:30d:: with SMTP id 13mr1040219qkd.199.1611236988821;
        Thu, 21 Jan 2021 05:49:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls1100440qkk.1.gmail; Thu, 21 Jan
 2021 05:49:48 -0800 (PST)
X-Received: by 2002:a37:a1d6:: with SMTP id k205mr14821133qke.384.1611236988382;
        Thu, 21 Jan 2021 05:49:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611236988; cv=none;
        d=google.com; s=arc-20160816;
        b=LIxAfdDZZzR69T+WK4VjnUsofm3MOCBxq011EC2LXZR2dNnTJwShVgBBNpVPNxQ01K
         Ue2mSe/TIKiSNQInlaIiPPWIafjeT3gtWN5YPMgf5w/Ys4uuKb0FoGzJbEQAWJiyj6Cq
         vlL0dvpAj0kwjNBfGsumKOKdQAIhhn/h9J/CBn0AnZBxN2ek/iJHVqJ11ecCqbVBBniZ
         X0eUjXwFde3cKyv/ktPTnknOn5RZnSRlArvQKjtByhxm+/J644XNpYV4nhhN2QZ+nupg
         jretWHX4Kp2aH70kVdSn7GCFmW/8t3FLDdyso1TjSXNts70NnxyrJI2zDTzYxY5OiPFi
         XmtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I1uFp8IeY8Fnde7gaXz6xC0+QbudmeaaxYy0UL7lMjM=;
        b=Ywm2squ7O1nMYH+Y30likfUeNPEfEw0gDzyklZ7TAk6SOjBGmyxLDfTC9LGZOnJDxn
         boem4CjZXBSXA0MBb4yaISPwScYGsYG2ohybpSD/sfauj/zOKYneFKceMKvYougB3YrN
         qQo7XUVSQs74SJdFQR3DUa4eF5A/cKV51CKTXGKv51MqSXmKFAhjNATkzyCDauHeKK30
         zwgcPywahGyOsZfY+Qzr1ARzUKZUcSPx0nvYYApaGPXQm5KzNn0kp/VREM9+Uh5d6/vS
         SrJoOPtfcKwtbiwIMgPolW3YTwovlQwpetDmbo0L8SN/AhB5ZWMUzR7wpM7tf0ewGn6e
         EjXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kdj92SEQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id p55si508401qtc.2.2021.01.21.05.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 05:49:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id 19so1592161qkm.8
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 05:49:48 -0800 (PST)
X-Received: by 2002:a05:620a:983:: with SMTP id x3mr14661120qkx.231.1611236987731;
 Thu, 21 Jan 2021 05:49:47 -0800 (PST)
MIME-Version: 1.0
References: <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <20210121131444.GP1551@shell.armlinux.org.uk>
In-Reply-To: <20210121131444.GP1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 14:49:35 +0100
Message-ID: <CACT4Y+Yj5T8PKadhN1jL9D4EnXd04_-EvCQgYMVM2rQ0g4ARXg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kdj92SEQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jan 21, 2021 at 2:14 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Tue, Jan 19, 2021 at 07:48:27PM +0000, Russell King - ARM Linux admin wrote:
> > My knowledge about this is limited to qemu being used for KVM.
> >
> > Firstly, there is are no block devices except for MTD, USB, or CF
> > based block devices in the Versatile Express hardware. So, the DTB
> > contains no block devices.
> >
> > In your first case above, it is likely that QEMU modifies the passed
> > DTB to add PCIe devices to describe a virtio block device.
> >
> > In this case, because QEMU has no visibility of the appended DTB, it
> > can't modify it, so the kernel only knows about devices found on the
> > real hardware. Hence, any of the "special" virtio devices that QEMU
> > use likely won't be found.
> >
> > I'm not sure how QEMU adds those (you're probably in a better position
> > than I to boot using your first method, grab a copy of the DTB that
> > the booted kernel used from /sys/firmware/fdt, and use dtc to turn it
> > back into a dts and see what the changes are.
> >
> > I suspect you'll find that there's a new PCIe controller been added
> > by QEMU, behind which will be a load of virtio devices for things like
> > network and the "vda" block device.
>
> It may also be of relevance that 5.9 + a revert of the font changes
> boots for me under KVM, but 5.10 does not.
>
> The font changes were:
> 6735b4632def Fonts: Support FONT_EXTRA_WORDS macros for built-in fonts
>
> 5.10-rc1 similarly does not, but bisecting that brings me to:
> 316cdaa1158a net: add option to not create fall-back tunnels in root-ns as well
>
> which seems entirely unrelated, and looks like a false outcome.
>
> I've tried going back to 5.10 and turning off CONFIG_STRICT_KERNEL_RWX.
> Still doesn't boot.
>
> I've tried reverting the changes to the decompressor between 5.9 and
> 5.10. Still doesn't boot.
>
> Asking for a memory dump in ELF coredump format of the guest doesn't give
> anything useful - I can see that the kernel has been decompressed, but
> the BSS is completely uninitialised. It looks like the LPAE page tables
> have been initialised.
>
> The PC value in the ELF coredump seems to be spinning through a large
> amount of memory (physical address) and the CPSR is 0x197, which
> suggests it's taken an abort without any vectors setup.
>
> I'm currently struggling to find a way to debug what's going on.

I wonder if qemu has some kind of tracing that may be useful in such cases.
Some googling shows this, which seems that it can give a trace of all
PCs (which is a reasonable feature to have), it may show where things
go wrong:
https://rwmj.wordpress.com/2016/03/17/tracing-qemu-guest-execution/
https://github.com/qemu/qemu/blob/master/docs/devel/tracing.txt
But I never used such heavy-weight artillery myself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYj5T8PKadhN1jL9D4EnXd04_-EvCQgYMVM2rQ0g4ARXg%40mail.gmail.com.
