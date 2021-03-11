Return-Path: <kasan-dev+bncBCMIZB7QWENRBENYVGBAMGQEXKMYDWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19C7C337BB6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 19:06:11 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id h26sf1735524qtm.13
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 10:06:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615485970; cv=pass;
        d=google.com; s=arc-20160816;
        b=xqGRL/mbg0JNl9gsvoZ4xypFIzEx8mp7gerj2fIE2sFxv4guSxDtXvDM72te0LhGns
         KJBpEth6HqeBV44Ivp9o6akhBz5JQkWIHQpYQY/yukLLlox5SJk7rwhBGebLlpBT9v85
         CFbac/Nq1GE4SQe7yzL0J0stH1p0+JgAry4Ct1ovqO8VjFSnYEeO4CC7p+V2oZqd0ybX
         siaMbdwdX06KVurj+bWoLWiOTQixToozNMMcUtpco/KBmz6ZaHnn+TKOWBVv0YgS8x/P
         MZw75mYUw4HxpJAfhlIdmyZWk+wOqYNJFblF7dOIzi1/N9mr4I4Fb01OcDttvOuoU+cK
         AhOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WxNzLFCM9cNWjoSV4/Uvb6zBPX0F6vc4iKlfLfItXjs=;
        b=QrwIduoOHYRKA5F45OjxGMSdNzHZZvGdOuk+pYnAzDUVzJ5Z8dSxCyWwbkVcbkPE39
         aSJJJGKIZLxV4iX0cEorBVYGWx5euYyqVMN/dNx2IFyl5cF5/icWNQKQHwhgUL0JaDyQ
         M6omiITd1ASHnoKCuax0zr/NyGFxoc5oanpPrisgFdESn2fVltNyhacXH0jFG7UT1l62
         Na9g8/6XA3qQ8B9R5+mjKn2a9oPObVBZAuTTSUXt2mLNpUcoB7ulWWMgYCkQezxyZNly
         /BQBoown5BVCIfQ9+DaFROXUc2CioyD3GHFiIIrFkpJ2cZ0MvhepPvH+xxDCHIJtAkTE
         +J8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NCa8QgA+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WxNzLFCM9cNWjoSV4/Uvb6zBPX0F6vc4iKlfLfItXjs=;
        b=VQrS2rpppJWrBcDR6OAeb5rm4qE/NK00NQgxgF+cOwIpiMeZ4tNeusxm5KAjqrv0vJ
         fGhy47lqqNmioOwCe5VSS2WNExglfI7SsRClRZJ8CnhdCDHEhrowWODBW+eAmXaLVk67
         7ZzT7Yb8xktdCWEqBr54x3XY2br5oRGag4WShP67Yjl6G0P4LOag7xOx254CqOJyjJ9C
         GvDzP0afdFI/VJRzLp594ZB48V0OVFD2ClF6/F/YZT/q0NR3LZFE29Uxa3VPNcDDQMzu
         RS/S3W0iOoxstDi3cTnbxHFEkQXVF6sVgrluuNpVl2RbpQnJs0R4No9T/PjByA3t7tef
         2DZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WxNzLFCM9cNWjoSV4/Uvb6zBPX0F6vc4iKlfLfItXjs=;
        b=YFixux1SsMgZ9dUFZGMQSkpAqzjS1kC7ruFfMDnGGKPPguHNa8Yor1vfXKItLFXaVh
         16oYoNtV+oPA7VuhMjRd430MA6DGhcbTZg0Ena5IvX3HONRm4bWmrpaCD5e+mdxSv/7O
         VAyObqEOzFs1U3mkpBxNANra7mgB9jBgKmk24LzBEeNVXSVgQSvqM1D+nZCDh43+zVYa
         AYAKUh0UCSbwPYu9FZq8Ni9J8KtEcsS9n95cNwWo6lY8CJHUK3ipliR6ejfvlLiSeVUY
         RC7amcOzGacW4q7G1ScgV6ZrJXETrkh2yIi8GzaweBuq782UAGqGqaXN169+lBpiTzIt
         9Wtw==
X-Gm-Message-State: AOAM532Zu37IygsXbVe0sYNqU6B6eQLYVTSHUTYLH3fUTKcvJtC113d7
	+wW0CSSwdKrZRAOp/LrAc/Q=
X-Google-Smtp-Source: ABdhPJw+lDoDGNKPJKWUqSHMbp/FC2Qcx2f/WSecKeMZ3XZuEfP3raAr9X2JlNrA+Agg/8C+9kZr9Q==
X-Received: by 2002:a05:6214:1085:: with SMTP id o5mr8798741qvr.5.1615485970122;
        Thu, 11 Mar 2021 10:06:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:71d9:: with SMTP id i25ls2476923qtp.8.gmail; Thu, 11 Mar
 2021 10:06:09 -0800 (PST)
X-Received: by 2002:ac8:744f:: with SMTP id h15mr8668263qtr.202.1615485969513;
        Thu, 11 Mar 2021 10:06:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615485969; cv=none;
        d=google.com; s=arc-20160816;
        b=VH6GHx01RrLUyCZkpH5jOryl2W+42AbweUHEu6hKDXsI0+qdXTQpjcuwNHXTAC/wVL
         QbDNZfVPV6yTpEFoezRsA1kGJiinVrbo8fuI2JpL7xkRKJ5jxmlG2LPXD1mspOtSPeoB
         DwSQrBlJ0LRZxwyOUDdJrVetUwdwhwGxlId8+fTBT6XswVtqLA3Oaepkw/4oQ/Ta7PVN
         OP7Io6l66Ejd3/YfmsFvJXmoXLHdKgdf4broDz0RAluGajq5nLf5N2jWuS6ItSDNK60B
         ClFodXwElyDHimBHsKJaGi+a/tfqPbJoGrokSYR/KdFcIorUZbffNHt7aKyF8upTVD7e
         Z+qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=af+eUJP62+YysTCAjqV/xWgntO8ebmMnaR+MXcIkbWM=;
        b=Fybt5oek7vQRDAQjJAnobYfOs6pZdwEqAVIuR/1OfXoWoHv8Zkb3KIRzj1+JuEuBBN
         qnDAe8r2cBjML5n7mhflRoDiGLitZRteDrUsRu5FyktB1DCOcVTBmb+KF9ypzwMA7EOe
         udy8lmVxmKGim6DPZeOzSC6wR2vRV7jhnP6yiV7JQcS3sXDYIxYRAFOwiTJPyqjaKaf2
         PzsQd0BLm8kRcFnmUtrt7yeVqj56VoNZnZsyINTGwv4WIdAnujWZKBPfjvc+mmPYBzjG
         89rmr2xNWVeuulVojvDL9lJLSAlEp/G3R6Sw+oFupWuyya4lVTlMzbDXLmncwYpPoB8r
         KuNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NCa8QgA+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id d12si162139qkn.0.2021.03.11.10.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 10:06:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id l4so21580093qkl.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 10:06:09 -0800 (PST)
X-Received: by 2002:a37:96c4:: with SMTP id y187mr9371169qkd.231.1615485968872;
 Thu, 11 Mar 2021 10:06:08 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk> <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
 <20210311134213.GI1463@shell.armlinux.org.uk>
In-Reply-To: <20210311134213.GI1463@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Mar 2021 19:05:57 +0100
Message-ID: <CACT4Y+a+xSNRQYt8ZbK1Y6CwGx06JXAVH_zgpOG8C=sAwgN-Cg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NCa8QgA+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736
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

On Thu, Mar 11, 2021 at 2:42 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Thu, Mar 11, 2021 at 11:54:22AM +0100, Dmitry Vyukov wrote:
> > The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> > https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/
>
> I suspect this is unlikely to change as it hasn't attracted any
> interest. Someone using Go and KASAN needs to debug this... I suspect
> it may be due to something being KASAN instrumented that shouldn't be.
>
> > It also has KCOV disabled (so no coverage guidance and coverage
> > reports for now) because KCOV does not fully work on arm:
> > https://lore.kernel.org/linux-arm-kernel/20210119130010.GA2338@C02TD0UTHF1T.local/T/#m78fdfcc41ae831f91c93ad5dabe63f7ccfb482f0
>
> Looking at those, they look a bit weird. First:
>
> PC is at check_kcov_mode kernel/kcov.c:163 [inline]
> PC is at __sanitizer_cov_trace_pc+0x40/0x78 kernel/kcov.c:197
>
> Why is this duplicated?

It's an artifact of the symbolization process, to add the [inline]
file:line it duplicated the PC line.
I've posted 3 unaltered crashes at the bottom.


> Second:
>
> sp : 8b4e6078  ip : 8b4e6088  fp : 8b4e6084
> ...
> Process   (pid: 0, stack limit = 0x147f9c36)
>
> The stack limit is definitely wrong, and it looks like the thread_info
> is likely wrong too. Given the value of "sp" I wonder if the kernel
> stack has overflowed and overwritten the thread_info structure at the
> bottom of the kernel stack.

Humm... this is possible...

> I've no idea what effect KCOV would have on the kernel - it's something
> I've never looked at, so I don't know what changes it would impose.
> At this point, as there's very little commercial interest in arm32,
> there's probably little hope in getting this sorted. It may make sense
> to force KCOV to be disabled for arm32.

KCOV makes the compiler insert __sanitizer_trace_pc() function call
into every basic block. This increases code size and can also increase
stack usage because of more spills. And other debug configs increase
stack usage even more.

Here 3 random crash samples:

[ 2552.083059][ T5194] 8<--- cut here ---
[ 2552.084367][ T5194] Unhandled fault: page domain fault (0x01b) at 0x00000e30
[ 2552.085401][ T5194] pgd = c87495f5
[ 2552.086224][ T5194] [00000e30] *pgd=00000000
[ 2552.088694][ T5194] Internal error: : 1b [#1] PREEMPT SMP ARM
[ 2552.090195][ T5194] Dumping ftrace buffer:
[ 2552.091249][ T5194]    (ftrace buffer empty)
[ 2552.091895][ T5194] Modules linked in:
[ 2552.092768][ T5194] CPU: 1 PID: 5194 Comm: kworker/1:4 Not tainted
5.10.0-rc1+ #19
[ 2552.093459][ T5194] Hardware name: ARM-Versatile Express
[ 2552.094153][ T5126] ------------[ cut here ]------------
[ 2552.095215][ T5194] Workqueue:  0x0 (wg-crypt-wg0)
[ 2552.099654][ T5194] PC is at __sanitizer_cov_trace_pc+0x4c/0x78
[ 2552.100071][ T5126] WARNING: CPU: 0 PID: 5126 at
net/core/skbuff.c:2206 skb_copy_bits+0x368/0x510
[ 2552.101457][ T5194] LR is at trace_hardirqs_off+0x14/0x120
[ 2552.102019][ T5194] pc : [<802b4048>]    lr : [<802e12cc>]    psr: 60000193
[ 2552.102782][ T5194] sp : 8b614060  ip : 8b614070  fp : 8b61406c
[ 2552.103590][ T5194] r10: 0000a300  r9 : 8b614000  r8 : 8b7bbe14
[ 2552.104357][ T5194] r7 : 80100a74  r6 : ffffffff  r5 : 60000193  r4
: 802b4048
[ 2552.105448][ T5194] r3 : 8b614000  r2 : 00000000  r1 : 00000000  r0
: 00000000
[ 2552.106549][ T5194] Flags: nZCv  IRQs off  FIQs on  Mode SVC_32
ISA ARM  Segment none
[ 2552.107905][ T5194] Control: 10c5387d  Table: 8acfc06a  DAC: 00000051
[ 2552.108580][ T5194] Process kworker/1:4 (pid: 5194, stack limit = 0xa47ae3aa)
[ 2552.110752][ T5194] ---[ end trace 4b8c0315965ef9d6 ]---
[ 2552.112816][ T5194] Kernel panic - not syncing: Fatal exception
[ 2552.114081][    C0] CPU0: stopping
[ 2552.115360][    C0] CPU: 0 PID: 5133 Comm: syz-executor.1 Tainted:
G      D           5.10.0-rc1+ #19
[ 2552.116483][    C0] Hardware name: ARM-Versatile Express
[ 2552.117423][    C0] Backtrace:
[ 2552.118784][    C0] [<8367729c>] (dump_backtrace) from [<83677618>]
(show_stack+0x28/0x2c)
[ 2552.120132][    C0]  r9:ffffffff r8:40000193 r7:00000080
r6:00000000 r5:841ff0ac r4:00000000
[ 2552.121629][    C0] [<836775f0>] (show_stack) from [<8368d44c>]
(dump_stack+0x124/0x170)
[ 2552.122928][    C0]  r5:00000000 r4:847241a4
[ 2552.124044][    C0] [<8368d328>] (dump_stack) from [<80118d78>]
(do_handle_IPI+0x5e4/0x618)
[ 2552.125536][    C0]  r10:8af89d68 r9:8af89dd8 r8:8af89d40
r7:814f5cc4 r6:00000014 r5:00000000
[ 2552.126748][    C0]  r4:00000002 r3:00000000
[ 2552.127815][    C0] [<80118794>] (do_handle_IPI) from [<80118dd4>]
(ipi_handler+0x28/0x30)
[ 2552.129265][    C0]  r10:8af89d68 r9:8af89dd8 r8:8af89d40
r7:814f5cc4 r6:00000014 r5:8580cc40
[ 2552.130466][    C0]  r4:00000014 r3:8454ec60
[ 2552.131534][    C0] [<80118dac>] (ipi_handler) from [<802040e8>]
(handle_percpu_devid_fasteoi_ipi+0xa8/0xbc)
[ 2552.132872][    C0]  r5:8580cc40 r4:858c8000
[ 2552.134078][    C0] [<80204040>] (handle_percpu_devid_fasteoi_ipi)
from [<801f9bc4>] (__handle_domain_irq+0xec/0x168)
[ 2552.135731][    C0]  r9:8af89dd8 r8:0000003b r7:846355b4
r6:00000000 r5:844fd41c r4:00000000
[ 2552.137183][    C0] [<801f9ad8>] (__handle_domain_irq) from
[<814f5bb8>] (gic_handle_irq+0xbc/0xe4)
[ 2552.138687][    C0]  r10:e000200c r9:00000000 r8:e0002000
r7:8af89dd8 r6:8454f53c r5:00000004
[ 2552.139827][    C0]  r4:00000404
[ 2552.140735][    C0] [<814f5afc>] (gic_handle_irq) from [<80100b30>]
(__irq_svc+0x70/0xb0)
[ 2552.141936][    C0] Exception stack(0x8af89dd8 to 0x8af89e20)
[ 2560.845970][ T5194] SMP: failed to stop secondary CPUs
[ 2560.849196][ T5194] Dumping ftrace buffer:
[ 2560.849806][ T5194]    (ftrace buffer empty)
[ 2560.850981][ T5194] Rebooting in 86400 seconds..


[ 2818.793436][ T5710] 8<--- cut here ---
[ 2818.794918][ T5710] Unhandled fault: page domain fault (0x01b) at 0x00000e30
[ 2818.797895][ T5710] pgd = 24e3cd1d
[ 2818.798832][ T5710] [00000e30] *pgd=e3d98835
[ 2818.801168][    C0] 8<--- cut here ---
[ 2818.801661][ T5710] Internal error: : 1b [#1] PREEMPT SMP ARM
[ 2818.802585][    C0] Unhandled fault: page domain fault (0x01b) at 0x00000030
[ 2818.803226][ T5710] Dumping ftrace buffer:
[ 2818.803646][    C0] pgd = 8f5822fe
[ 2818.804367][    C0] [00000030] *pgd=00000000
[ 2818.804766][ T5710]    (ftrace buffer empty)
[ 2818.805361][    C0] Internal error: : 1b [#2] PREEMPT SMP ARM
[ 2818.806139][ T5710] Modules linked in:
[ 2818.806362][    C0] Dumping ftrace buffer:
[ 2818.806743][    C0]    (ftrace buffer empty)
[ 2818.807645][ T5710] CPU: 0 PID: 5710 Comm: syz-executor.1 Not
tainted 5.10.0-rc1+ #19
[ 2818.807904][ T5710] Hardware name: ARM-Versatile Express
[ 2818.808299][    C0] Modules linked in:
[ 2818.810264][ T5710] PC is at __sanitizer_cov_trace_pc+0x4c/0x78
[ 2818.810676][ T5710] LR is at check_preemption_disabled+0x60/0x17c
[ 2818.811017][ T5710] pc : [<802b4048>]    lr : [<836bb728>]    psr: 60000193
[ 2818.811656][    C0]
[ 2818.812153][ T5710] sp : 8ad42010  ip : 8ad42020  fp : 8ad4201c
[ 2818.812954][    C0] CPU: 0 PID: 5112 Comm: kworker/u4:2 Not tainted
5.10.0-rc1+ #19
[ 2818.813291][    C0] Hardware name: ARM-Versatile Express
[ 2818.813808][ T5710] r10: 00000000  r9 : 8ad4205c  r8 : 841ca824
[ 2818.815046][    C0] Workqueue: bat_events
batadv_iv_send_outstanding_bat_ogm_packet
[ 2818.815919][ T5710] r7 : 84089a40  r6 : 836bb890  r5 : ffffe000  r4
: 00000000
[ 2818.816847][    C0] PC is at rb_erase+0x148/0x374
[ 2818.817317][ T5710] r3 : 8ad42000  r2 : 00000000  r1 : 00000000  r0
: 00000000
[ 2818.818245][    C0] LR is at 0x0
[ 2818.818563][    C0] pc : [<814dd100>]    lr : [<00000000>]    psr: 60000193
[ 2818.819014][ T5710] Flags: nZCv  IRQs off  FIQs on  Mode SVC_32
ISA ARM  Segment none
[ 2818.819558][    C0] sp : 8acffab8  ip : 8ad41dc0  fp : 8acffacc
[ 2818.820250][ T5710] Control: 10c5387d  Table: 8aebc06a  DAC: 00000051
[ 2818.820790][    C0] r10: de5c82c0  r9 : 8acfe000  r8 : de5c8320
[ 2818.821351][ T5710] Process syz-executor.1 (pid: 5710, stack limit
= 0xa8637c39)
[ 2818.822487][    C0] r7 : 00000000  r6 : 8ad41dc1  r5 : de5c834c  r4
: de5c8840
[ 2818.824313][ T5710] Stack: (0x8ad42010 to 0x8ad42000)
[ 2818.826259][    C0] r3 : 00000030  r2 : 00000000  r1 : de5c834c  r0
: de5c8840
[ 2818.827049][ T5710] Backtrace:
[ 2818.827567][    C0] Flags: nZCv  IRQs off  FIQs on  Mode SVC_32
ISA ARM  Segment none
[ 2818.827864][ T5710]
[ 2818.828367][    C0] Control: 10c5387d  Table: 8a15806a  DAC: 00000051
[ 2818.829428][ T5710] [<802b3ffc>] (__sanitizer_cov_trace_pc) from
[<836bb728>] (check_preemption_disabled+0x60/0x17c)
[ 2818.830282][ T5710] [<836bb6c8>] (check_preemption_disabled) from
[<836bb890>] (__this_cpu_preempt_check+0x24/0x28)
[ 2818.830931][ T5710]  r10:00000000 r9:8ad42000 r8:00000000
r7:80100a74 r6:ffffffff r5:60000193
[ 2818.831360][    C0] Process kworker/u4:2 (pid: 5112, stack limit =
0x209a2e04)
[ 2818.831960][ T5710]  r4:841ca824
[ 2818.832647][    C0] Stack: (0x8acffab8 to 0x8ad00000)
[ 2818.833429][ T5710] [<836bb86c>] (__this_cpu_preempt_check) from
[<836ba86c>] (lockdep_hardirqs_off+0x54/0x174)
[ 2818.833711][ T5710]  r5:60000193 r4:80100a74
[ 2818.836100][ T5710] [<836ba818>] (lockdep_hardirqs_off) from
[<802e12d4>] (trace_hardirqs_off+0x1c/0x120)
[ 2818.837807][ T5710]  r7:80100a74 r6:ffffffff r5:60000193 r4:802b405c
[ 2818.839303][ T5710] [<802e12b8>] (trace_hardirqs_off) from [<


[ 4902.579940][    C1] 8<--- cut here ---
[ 4902.580159][    C1] Unhandled fault: page domain fault (0x01b) at 0x00000e50
[ 4902.580388][    C1] pgd = bc232184
[ 4902.580542][    C1] [00000e50] *pgd=00000000
[ 4902.584882][    C1] Internal error: : 1b [#1] PREEMPT SMP ARM
[ 4902.585007][    C1] Dumping ftrace buffer:
[ 4902.585114][    C1]    (ftrace buffer empty)
[ 4902.585209][    C1] Modules linked in:
[ 4902.585674][    C1] CPU: 1 PID: 5928 Comm: kworker/1:7 Not tainted
5.10.0-rc1+ #19
[ 4902.585787][    C1] Hardware name: ARM-Versatile Express
[ 4902.589427][    C1] Workqueue:  0x0 (wg-crypt-wg1)
[ 4902.589785][    C1] PC is at __sanitizer_cov_trace_pc+0x40/0x78
[ 4902.589924][    C1] LR is at trace_hardirqs_off+0x14/0x120
[ 4902.590080][    C1] pc : [<802b403c>]    lr : [<802e12cc>]    psr: 00000193
[ 4902.590210][    C1] sp : 8b4c4020  ip : 8b4c4030  fp : 8b4c402c
[ 4902.590340][    C1] r10: 00000010  r9 : 8b4c4000  r8 : de5c7698
[ 4902.590496][    C1] r7 : 80100a74  r6 : ffffffff  r5 : 00000193  r4
: 802b403c
[ 4902.590652][    C1] r3 : 84262114  r2 : 00260100  r1 : 00000004  r0
: 84262114
[ 4902.590819][    C1] Flags: nzcv  IRQs off  FIQs on  Mode SVC_32
ISA ARM  Segment none
[ 4902.590962][    C1] Control: 10c5387d  Table: 895ac06a  DAC: 00000051
[ 4902.591127][    C1] Process kworker/1:7 (pid: 5928, stack limit = 0x4e3e8f57)
[ 4902.591245][    C1] Stack: (0x8b4c4020 to 0x8b4c4000)
[ 4902.591324][    C1] Backtrace:
[ 4902.599980][    C1] [<802b3ffc>] (__sanitizer_cov_trace_pc) from
[<802e12cc>] (trace_hardirqs_off+0x14/0x120)
[ 4902.600211][    C1] [<802e12b8>] (trace_hardirqs_off) from
[<80100a74>] (__dabt_svc+0x54/0xa0)
[ 4902.600341][    C1] Exception stack(0x8b4c4058 to 0x8b4c40a0)
[ 4902.656393][ T5953] 8<--- cut here ---
[ 4902.657475][ T5953] Unhandled fault: page domain fault (0x01b) at 0x0000003c
[ 4902.658584][ T5953] pgd = bc232184
[ 4902.659363][ T5953] [0000003c] *pgd=00000000
[ 4902.660316][ T5953] Internal error: : 1b [#2] PREEMPT SMP ARM
[ 4902.661065][ T5953] Dumping ftrace buffer:
[ 4902.661594][ T5953]    (ftrace buffer empty)
[ 4902.662235][ T5953] Modules linked in:
[ 4902.663209][ T5953] CPU: 1 PID: 5953 Comm: kworker/u4:5 Not tainted
5.10.0-rc1+ #19
[ 4902.663783][ T5953] Hardware name: ARM-Versatile Express
[ 4902.664811][ T5953] Workqueue: bat_events
batadv_iv_send_outstanding_bat_ogm_packet
[ 4902.666303][ T5953] PC is at batadv_iv_ogm_schedule_buff+0x540/0x8f4
[ 4902.666952][ T5953] LR is at batadv_iv_ogm_schedule_buff+0x540/0x8f4
[ 4902.667455][ T5953] pc : [<83588324>]    lr : [<83588324>]    psr: 800f0113
[ 4902.667987][ T5953] sp : 8a209e20  ip : 8a209e20  fp : 8a209e84
[ 4902.668495][ T5953] r10: 8b19be00  r9 : 8b16c7a0  r8 : 0000003c
[ 4902.669039][ T5953] r7 : 00000000  r6 : 00000001  r5 : 00000007  r4
: 8b1b0c18
[ 4902.669722][ T5953] r3 : 00000000  r2 : 00000000  r1 : 8b5b2dc0  r0
: 00000000
[ 4902.670686][ T5953] Flags: Nzcv  IRQs on  FIQs on  Mode SVC_32  ISA
ARM  Segment none
[ 4902.671561][ T5953] Control: 10c5387d  Table: 8b6a406a  DAC: 00000051
[ 4902.672286][ T5953] Process kworker/u4:5 (pid: 5953, stack limit =
0x0cc057c1)
[ 4902.672870][ T5953] Stack: (0x8a209e20 to 0x8a20a000)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%2BxSNRQYt8ZbK1Y6CwGx06JXAVH_zgpOG8C%3DsAwgN-Cg%40mail.gmail.com.
