Return-Path: <kasan-dev+bncBCMIZB7QWENRB27NU6BAMGQEWYSI6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E939337096
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 11:54:37 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id f2sf6338753pjt.7
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 02:54:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615460075; cv=pass;
        d=google.com; s=arc-20160816;
        b=WlY1+VlzUtcGJEphF4XptphOz6S55Ck/FjO6DAYfossfoGbPYEOixy9VmGwXOSfQ8l
         y7FmBaAjSL1+INUWlICniVJBvsqLl3lg3fsKjbMFdcW6QMvm0I0OAXT72TyT2MY1Z+AZ
         wAWXDS8cBKgk5+XlPOQkCPKLkXzE5FUGLbDq9ETCQDtmEj1Md79ZDGiak+DfT65GisRU
         nN5n7rFu02J4APkX9P+ZbURSCiQNbjVDFMrkvGUg/f5oR8+uoPvsrEhLkssszIc/jcpB
         3rS8P/meF9ot7V7nkDdgeyTZyQBsbMzZtbCM24lUBYa8ST/Fb4XGXBtMDt6wXMsyVMoa
         n8NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UlM9L2P5Ceft3na14AcYqjFYVCvaAccNqGo1YVsY1w4=;
        b=LGMM/TazjDwyl74r4rtdC0S+qsiFs8n5ss+1EIe3W3bje5CCmOJZsMbcOdVAq8hG5K
         MBmTFEiKMpEGvqRsSABTa4xPheX7PiXmXCl+Nobxi0irIDWn7Aqag5sx2ZoSS1e7znkQ
         ouP4AYisdBbLe8Pi2iFxRjQIqGBBGZyfQ8XFBZPvH+etHUvFfFG+Xviw2apJFv2IjTdN
         +d0A3Yp1kKwuLX3YEfOe20YA0Sg1YDGNJFn4izFjoCQihWE+5Wt23qJv8lj/2pVamrh/
         6hJTRZqTQ++lQTnNDRtSskcRYRQmcy7JOcu51yV4rggEdA7w3DNYhcGF1UaQdOYxzc98
         DJAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D9AnEvF6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UlM9L2P5Ceft3na14AcYqjFYVCvaAccNqGo1YVsY1w4=;
        b=fkdjkvsC/4uuk6vw/mPfqu6DbkZZNFb0zHxN+0c8zrm6fmrKQriU2NrUprD1d0TKSD
         HNw4HYoKVZRrVNYrXuACi1w6HG7+UMjpPmO7i9ErwaTjUSBCRrD+LDXbRB9sWjuHUxlP
         /EJSAQi8/3v+AzfG5ZfMXC0Tu7W+Y4eFSM8pZSlOakGlI8u/GEgop/TxupeBdlB/A45P
         nsAIPg8xWhjGiicdqeIGKaYHdHlirgrj5vMOmzW2A7byrigyZmxtGbTTyy2WzqKmoE0h
         FI59Vxe44dFsqxUltx5W7EopvIc04PruWiy8fioescxzUPbUmHdYPU4iWB0D/sWY/la2
         cyVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UlM9L2P5Ceft3na14AcYqjFYVCvaAccNqGo1YVsY1w4=;
        b=X+71SXviAtdCuO/0PbQj8wIF1p6kifwsiJQJVyRPTz5dWZFKqGv0+9x08sjWCLb2Kg
         foxqAFJZtBE59YRVCM1NRunaGKYurFZ1FRCA10LSAO8nbMjBuXA9uBkQuouMHf8U2aEq
         NOR0eU8jwpMwAkXn3glYalMN6Wyj6PKSrHz+Czv42PV47SpqwtDUGb+/zCf76H4wproj
         yCcONxr1xuION9625J0yTzFZ2/Cm0KKAgSOUhyaDvzT/vhDNH22mnKv8LoPFw3JWP/rQ
         viKmTGaDR1uQLxl382nZqv6844leM/3O6h5YOK2J6iKBy8Z37bghkBecwrmoaLUmICUW
         V97Q==
X-Gm-Message-State: AOAM5328JyAoPKvjrz3kTXCLGQvJvXfoFCTuOMFcL8m3G6BkOiS7Tbzh
	tqi0F8jfxQurJ2yQoN4nOyQ=
X-Google-Smtp-Source: ABdhPJwn9pIbtJPS5jVok3pXvyVUslqeL+yIhNVYvfLST5KYiaM/YyfuhL0RZrEDgNPNJHOB6ShidA==
X-Received: by 2002:a17:90a:5d09:: with SMTP id s9mr8119368pji.172.1615460075762;
        Thu, 11 Mar 2021 02:54:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb0b:: with SMTP id z11ls3254754pjt.2.canary-gmail;
 Thu, 11 Mar 2021 02:54:35 -0800 (PST)
X-Received: by 2002:a17:902:e549:b029:e6:6b3a:49f7 with SMTP id n9-20020a170902e549b02900e66b3a49f7mr1843144plf.52.1615460075274;
        Thu, 11 Mar 2021 02:54:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615460075; cv=none;
        d=google.com; s=arc-20160816;
        b=hRUzR6jflVtqIi8EP8ucTieh+qLsT5vFwD/3rvzkRDqxKNGD7Dkcb8f07hAbBkalQx
         aw0brex3opY0bSqKb+Kh45JW6WowMc3hxQrdkEycGwhHrgx02EOyWpy42RHSYVII2SXM
         dZrNg0ivZIuP8m6h/ycxbXNyTO1yGJ8gNzqw/7GlbeYC1n7CoFUgi45pl8Go17tz7WEg
         I1ZdsJtwEl7CxdOXT2pVHhNu9pExuKibaiAx4gAIFbs60Ja6VptvnPTbGz5BOWBxnhm4
         QgqSx4u8Za9X+uZ1QMmvQcNa5P8JAV8ttZDOkgRqj+n90+usP9hXTb5BHFYgmeC2eg9H
         95vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fO1QKxZdT6DCDPQ6M79L4r/OoMyEbq8oxINuTJPzIYs=;
        b=sRf4SP247xTRFA9X9+CuJ+lahrZJVjZj5DDP8fjeKTf01tKZOyyHAFOj9YP4a1ESaq
         KTYpHQqCTIpzlDH+1IBC047mel+bhVHpUyzAmWtSctIPLFpfwqjHqwujdWADP1FGlD8w
         aOzCYzmlErn0tCIymSOKm9hfQZ+tUEbLhYE/f2OMH6NQuWsBsmlPSvbZRy8NzVXdMKj5
         Zg+Yj9uC6++8FrdwO81XY81WUSHfV1Uvgv9uE06NJYkczUD6avCEzJBkYDWvfe8t8TeS
         WcGv2e5TyYslTj29bkexEAUOFYOcDlKTPrsXPigt1sVCjHFH9nBEdl+9lRBa70riK+tq
         skMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D9AnEvF6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id h7si156848plr.3.2021.03.11.02.54.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 02:54:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id f124so20079270qkj.5
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 02:54:35 -0800 (PST)
X-Received: by 2002:a37:96c4:: with SMTP id y187mr7277801qkd.231.1615460074083;
 Thu, 11 Mar 2021 02:54:34 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com> <20210127101911.GL1551@shell.armlinux.org.uk>
In-Reply-To: <20210127101911.GL1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Mar 2021 11:54:22 +0100
Message-ID: <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D9AnEvF6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72d
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

On Wed, Jan 27, 2021 at 11:19 AM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Wed, Jan 27, 2021 at 09:24:06AM +0100, Linus Walleij wrote:
> > On Tue, Jan 26, 2021 at 10:24 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > > I've set up an arm32 instance (w/o KASAN for now), but kernel fails during boot:
> > > https://groups.google.com/g/syzkaller-bugs/c/omh0Em-CPq0
> > > So far arm32 testing does not progress beyond attempts to boot.
> >
> > It is booting all right it seems.
> >
> > Today it looks like Hillf Danton found the problem: if I understand correctly
> > the code is executing arm32-on-arm64 (virtualized QEMU for ARM32
> > on ARM64?) and that was not working with the vexpress QEMU model
> > because not properly tested.
> >
> > I don't know if I understand the problem right though :/
>
> There is an issue with ARMv7 and the decompressor currently - see the
> patch from Ard - it's 9052/1 in the patch system.
>
> That's already known to stuff up my 32-bit ARM VMs under KVM - maybe
> other QEMU models are also affected by it.

Status update on the arm syzbot instance:

The boot issue is finally fixed:
https://syzkaller.appspot.com/bug?id=a85a0181a55e02756ce5ffa43c71d74a4e309263

and the instance is up and running:
https://syzkaller.appspot.com/upstream?manager=ci-qemu2-arm32

The instance config:
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/upstream-arm-kasan.config

The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/

It also has KCOV disabled (so no coverage guidance and coverage
reports for now) because KCOV does not fully work on arm:
https://lore.kernel.org/linux-arm-kernel/20210119130010.GA2338@C02TD0UTHF1T.local/T/#m78fdfcc41ae831f91c93ad5dabe63f7ccfb482f0

But the instance seems to be efficient at finding 32-bit specific bugs.

The instance uses qemu tcg and -machine vexpress-a15 -cpu max flags.

The instance uses qemu emulation (-machine vexpress-a15 -cpu max) and
lots of debug configs, so it's quite slow and it makes sense to target
it at arm-specific parts of the kernel as much as possible (rather
than stress generic subsystems that are already stressed on x86). So
the question is: what arm-specific parts are there that we can reach
in qemu?
Can you think of any qemu flags (cpu features, device emulation, etc)?
Any kernel subsystems with heavy arm-specific parts that we may be
missing?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYhTGWNcZxe%2BW%2BkY4QP9m%3DZ8iaR5u6-hkQvjvqN4VD1Sw%40mail.gmail.com.
