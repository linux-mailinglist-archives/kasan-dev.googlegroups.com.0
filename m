Return-Path: <kasan-dev+bncBCMIZB7QWENRBN4RU2AAMGQECWZ6NGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 796782FEC7E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 14:59:20 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id r204sf866392oia.19
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 05:59:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611237559; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUAHAAA6eAgC5mpiFj7LjgVXJFGYMPAnO5zSuNved7/hdFUrUaKP5wkbvqM0yxkL1R
         VSznIl4NfHwS1yKqy3jf3A8V6h4MFIcF8OyM3ptJrJEvGswnHz9vR243WS74U0WKmvpe
         ahQ+SVtZ87IKdQLcI+l+nkNN8r0R9BeyakXcL3AhIziThjgbbg4Uqr2Kv6ijEc09UE2s
         LKOdodeXeYG9rhWXoj1aSsmauAE4LSpHCce5inmSVGEaKDHHIOjjziN4dVG5oHfNt4yS
         grX8GUKZWgIFQcgUloBpJep72HLu8D3MMqRsY3Vqx9+xPBw74hBdv8fd3/sff5c2VPnz
         TXWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PqnVlHAayxmTmULuZge96wK462U5nFdn2juA8OwfKcM=;
        b=cF6ZN1pPxJmz2k1/DmL7GYvFvLWvSc9xbboWQge3Q1nRBPatHlFlexDDctb+yi1IvL
         HR6oXXLcGaUZNVysnCCH3ow9f/gmKsF20eV9LxPoAJMhP9IFbDgWagRSUqV58ZNYouYF
         RfJxzavFxPB7jQDKvoObG83bncCrgOVzDj2M4ETCmUUclccWp+VgvCJR41sj0VmAHbJP
         WWG8htP6FHwhN2oMGdqT8laUX+mLTkHjCKJBJcLZHA5gKwvg+OxGb2C8cpMyJNvcKHAM
         Y2EqLC3i1OSqUG3mt0JiDbS5WI2ZuwexbDYQx0S58aCb2DBqrUUkz/AFen2m7SFXIR5O
         0k5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N7hc4uVV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PqnVlHAayxmTmULuZge96wK462U5nFdn2juA8OwfKcM=;
        b=f2PIQ+kQ8OwRbMBMxfeq3zEzRsb6VOW03Ss1K6e+D4wMrYpp+Lku76ojumTdXFmqyE
         xCIWKKTnDNhFqWi9H9100sONJKa05uAJ7LDEJbdLFZOviBfxtx5r4poIVycVlxZd/7R0
         Q51M/8nrDuB9tn6N8iEwgzG9XdOo/NegT/lmAI4xvOOidQNFFrAPITUAjNiHs8ir3xaX
         uZdfPNdJ1tK5qamGD8I4RI0qeE3BqTBBVOE7sScEiMOTeUpoeHQR5SnRCJf1UR8ccQ4e
         VJDu5sjdQRY9CdPCpH8JT+a0KqJt5b5oJwLnd4VmiGLqD1vg4E2ppN1Y+Ayd+CW1FuEw
         PQAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PqnVlHAayxmTmULuZge96wK462U5nFdn2juA8OwfKcM=;
        b=d8moyt6VftzEupo0dUi9X8T/VJqheREoHcYF8m3YDE5he32De70F20DyF0N9n/C+e1
         B/SgzT6qzxAun1dCLc/rCquZdIDHQ7FYqyKvy7ZOm2de3vuIXbl56Q8yZXLAM0CYYFdQ
         CYaO3fJfEF0RiqAbNXDTrp9crueLMMspnKrJ7sHYsM9RijuknnAd5tUIuqD9X2fVx4CV
         TEIreCbeFKRpmOL25hE8+82RSCN0QiWgCRm+FGDpkDYKu4DG9xC+/jE8b6JAacxUkSHY
         18HSx6XXCWXK+crMQsXISDyH7Rxsl4+/aMkFMKHudd4N4WGXoS7xl2BOCVwwSJ7qJabF
         W/ng==
X-Gm-Message-State: AOAM5300NFed6O6r7UK/PDhyQZZwC9q5AW0b1sHDmhQ8AAuaUkJn0EH7
	2nDJgJHFKBdrLQnefeuXCeI=
X-Google-Smtp-Source: ABdhPJwW8PWmO1CqW7ytoxL6HMz8kNIZU4/o8486ZcQa8IaHav9nrmng7dire6osLtT8Ey3vx5R7Tg==
X-Received: by 2002:a9d:84d:: with SMTP id 71mr10568586oty.338.1611237559515;
        Thu, 21 Jan 2021 05:59:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1614:: with SMTP id g20ls567644otr.1.gmail; Thu, 21
 Jan 2021 05:59:19 -0800 (PST)
X-Received: by 2002:a05:6830:1ad4:: with SMTP id r20mr10201880otc.354.1611237559179;
        Thu, 21 Jan 2021 05:59:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611237559; cv=none;
        d=google.com; s=arc-20160816;
        b=UuB/8jMXT8YarkJWqyzoDBfmimDr96OIAf59bstZdSgrlKNeh0GbFDvp6oA8xH/Hqk
         b3qE1n+bGpAfEw5GXi4CFVmNaRlM9AAobs5/lH9aJwC1oCGASCoajFNLeQAQKCJ/05sU
         kJm/JJlsP2+/VoOr5SzB0MkHFhXrlNuPohjJvv5nQBul/7RQzfHjwnGz0FV8BvCdIxRo
         piGyQ7IVQ20LrkKd8552BYJwn7y1yQ39peOnFTcOZ4Ae7cTSwMZ4XklSUiGKoYcHBGWI
         S0uYJSIXDSm2mXcHWhBRRRwEPSty1kWt96S2forBerm5dGPDIKDbGkKinnnc8wplf18P
         nbXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LOMjl0XcNyBKhEF6EOGOndMi9CvSIiYUh2o1OQA+pqg=;
        b=sCi1gXd76y143H72oUL8NF9rZrLJehLB3VnoJ+lPPnGSLb5mdVyfQd4Oh8ihjRC/rA
         7RkJYWTrEKKz4DdjEii/L0wWSQhPYUzc4IYwfJ6CKilgHTY3gbRm4omQkZk8hz1J/jJP
         Cjgp/U/2OaNpk/Isx7DO7lzo+p6Nb7BwBj3UpF2tRf7ziAbY7x+tyP8hqAM2gQIB7RTt
         2jeJNiKAk3uWX1D0kIKn88KRsIDewmXJDZeMTfxGabWT+IKJvM8Bs+g5kRdrcPe5Mefz
         hFtHBUG/0ijPbRjFaohcblbBgb1u0RyRzwCknX1kHw2RVr/z2pM4jU4bb9Dn9MyLTa/k
         G02w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N7hc4uVV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id l126si391689oih.3.2021.01.21.05.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 05:59:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id 19so1648417qkh.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 05:59:19 -0800 (PST)
X-Received: by 2002:a37:9a97:: with SMTP id c145mr14410225qke.350.1611237558619;
 Thu, 21 Jan 2021 05:59:18 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk>
In-Reply-To: <20210119194827.GL1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 14:59:06 +0100
Message-ID: <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N7hc4uVV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::735
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

On Tue, Jan 19, 2021 at 8:48 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Tue, Jan 19, 2021 at 07:57:16PM +0100, Dmitry Vyukov wrote:
> > Using "-kernel arch/arm/boot/zImage -dtb
> > arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" fully works.
>
> Good.
>
> > Using just "-kernel arch/arm/boot/zImage" does not work, not output
> > from qemu whatsoever (expected).
>
> Yep.
>
> > But using just "-kernel arch/arm/boot/zImage.dtb" gives an interesting
> > effect. Kernel starts booting, I see console output up to late init
> > stages, but then it can't find the root device.
> > So appended dtb works... but only in half. Is names of block devices
> > something that's controlled by dtb?
>
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

Thanks, Russell. This makes perfect sense.

I think allowing qemu to modify dtb on the fly (rather than appending
it to the kernel) may be useful for testing purposes. In future we
will probably want to make qemu emulate as many devices as possible to
increase testing coverage. Passing dtb separately will allow qemu to
emulate all kinds of devices that are not originally on the board.

However, I hit the next problem.
If I build a kernel with KASAN, binaries built from Go sources don't
work. dhcpd/sshd/etc start fine, but any Go binaries just consume 100%
of CPU and do nothing. The process state is R and it manages to create
2 child threads and mmap ~800MB of virtual memory, which I suspect may
be the root cause (though, actual memory consumption is much smaller,
dozen of MB or so). The binary cannot be killed with kill -9. I tried
to give VM 2GB and 8GB, so it should have plenty of RAM. These
binaries run fine on non-KASAN kernel...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg%40mail.gmail.com.
