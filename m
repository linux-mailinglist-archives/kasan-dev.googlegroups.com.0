Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB3OFX2IAMGQEUPIYDXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E3264BBA44
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:45:18 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id a8-20020a7bc1c8000000b0037bc4c62e97sf2872597wmj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:45:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191918; cv=pass;
        d=google.com; s=arc-20160816;
        b=ze8Ax3/celv+lHCvCMvaSAgx4QcfCNxv24TSLcge86Dg393cGROLG1Axwfa0Ed/CHn
         YHOqCv13eyJ3PmrGBhoPALUpRM0nRnkVibmev+1qOM0VoO5RptzmlBIz3ATU2Vo+UX7a
         M2Rs1kS5OocrOhlYQoI8tciXEdX+o8htWAKhuXdhbDBhInK3VrAJ6WbxkdHzo80cT9Pu
         1I8okCYrtpfQCWrp8IJzeUr3P31vTz/cjDp9UpswWkDp+ChdZEfHAqGwL2gdhvJTWsVl
         LcaQFTq44DmXfPDo6A76ddriXW33ogMa+LWDA91gxvluAKR9KdRTrO/CUo9waxY32ElI
         uylA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JXOMVwyyRtZtJbcGM+D6bn7yST/pk3NdEMGBsu7awKQ=;
        b=l+9k44daxM2qwrs6xJDQk9QkIb7kUmOqnrzmkvFcUAAEGmuF+Xb5dK6XYNugCAYKX7
         W5Oslwck4TNPK1qtpoCL+0U2edyjq+To4lpwvLVCAu/Wl3YoIEbmNsIho3t6uIihZEVy
         sLbpTtQlfbCUk01x1K8tn2DSgz98LhY6C07FV0+AhToMXZvKd2s9ioAxeDGs6WP1Ytez
         n4lVYHWyhISV4oGhoiqe+v8Y1xznaoB8r3pbwnknnkkXxPGWKllUzCw5NVWSb510BS35
         mFeK6zyiW9p0AYt9Dv4hbnoqL2sas3f42ZM4q8AyoDLLSQYGUaz/xkFct55hH4UZ+sQ7
         2WLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ZQd8Hht2;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JXOMVwyyRtZtJbcGM+D6bn7yST/pk3NdEMGBsu7awKQ=;
        b=pUM2DA3U3onV0To9ppYjhM4Ns1uwUm8qkidkWymV5JPxH2UgIou9hXiRlRfEb++lxi
         6ZrNKg3bTOQOgF5GG1KYOHTcQUwJNZpLOrQeuWtEbmdteIT7CqQ6IznBU5WXHZjT1V0Q
         eSXtdBE9sXeiDeOMJOJXKUFDdA5tpzXejgeLEOe74Ep4dwtqM+WcWDNtOvkWBgfrPxVo
         6jZYxoCpFCoEJwfAE2UTW41CWAC2haXrvONivr8NJAMVYF2QFpUmt24ekjbwixQXGp2Y
         h1aCAvByguzodSRMzeSwQg6uSGttb2/G1sQMIAcz0LO/KwSkj9duOcZT4Q8Ax6XsHDUO
         jzOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JXOMVwyyRtZtJbcGM+D6bn7yST/pk3NdEMGBsu7awKQ=;
        b=JK5kPo9u9UhjG9fSBFRNPcbyOcDstdW2c3O2UGPtIafa3Gq8Ule4dUbUdqhNbZPDtF
         bYtNl8DMJE3Z2w/HNu4osQHKvTOysEigegQacPurDli9PUDFY0RUuji+1nrLKx5tmG4u
         vyWgXARpVQ6DQqNSML/zXldfhwLcdjOdGB8Kk8ZD6hKLjz60xcC4WR6QOxwVy+4eDL5G
         8vT0B5OYbtBF6RLuUzdKw6TWJiWqs/1QGr9DNDDbQhQ8NdH0Jc2o2bxdAh8t4L+qeF4S
         LUfxNzrx5nOClkKIdFzLfv7HnKCh4FBnha3yF3AuHDUoshyVRpQfFfhamoPEpJEiv0s8
         P6gQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QeIqK6DNc51Dc5GLhT9b1l3CZVXHTnnQVGfaL5REuqTRFM4jX
	6wVtL9RrhcVxStKmHM3//+w=
X-Google-Smtp-Source: ABdhPJwEUzWJedM65NwnFcNkf0tvT8Pjf0lgFgYH+sjzasUPqMXiH6ewdqKuCPo3vUbLL2vY+szsYQ==
X-Received: by 2002:a1c:2742:0:b0:37b:b481:321f with SMTP id n63-20020a1c2742000000b0037bb481321fmr7260333wmn.56.1645191918121;
        Fri, 18 Feb 2022 05:45:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d1b:b0:37c:911f:164 with SMTP id
 l27-20020a05600c1d1b00b0037c911f0164ls3330669wms.0.gmail; Fri, 18 Feb 2022
 05:45:17 -0800 (PST)
X-Received: by 2002:a05:600c:4fc4:b0:37c:9116:ef3d with SMTP id o4-20020a05600c4fc400b0037c9116ef3dmr7047421wmq.167.1645191917256;
        Fri, 18 Feb 2022 05:45:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191917; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0U6lTZcGD5tjEkeN6nlJ368nJ0T26GYmS8Ar6vjPbrwAIWHQ+bqlhDLqNWY4QMgDB
         0ziujZocO9EzuuNQC43aF3MBqRNBTxt/QeEuhhCSIkMj2Bhwlqk2AQIRpWZ7P2vthudP
         pjsc43frBeXqtrqvG0WuQ49OlLvdehBw/c3xdA3/uKbkQaLMDeeR666Dj3ZqpbzfO8C/
         94IippM2MFw020igW/JPF9mePlaYIClB3wylVnkjxfv2V6BBlst0bZElm2awgVs3DeU7
         iAfkjs71ADybW+bjgte2tYHeRZoEKwgydcC4GP7vfynQSXvSePqw0HezTAEgkJOZ+/zm
         3COQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7FQkiu6wbxuprBukB5/j4MRrTzAJk0o7r1z/REMgVTQ=;
        b=gcFju+bxxvNtxbLRHwhOvM3hN6d47W/BtiO6Rt0gBFXiPtZNmXlPDZsMu8IzADNSYZ
         nxI0vtHGR79OKWj88IXWgBtzpv/hcjUiPOZ64sZs6HeChFDFDbFg+SoNzcPmhH21pYFG
         yFnhiaJ4uEXwb4nCovGkQ1zFS3kUq0MbJp1rpps9c5mNh/W9Z6YMbhMA83jaKKB0Vix5
         xszsFBRyVvqg+9m6kQwl4VUpJYxeY2gldEOZ9OMIP8hEq1FZDmkFdXzZpI55yEmNrOiW
         fjehEdoS3Iik8QMLS+0pJ5nRz74StFinTz52EvaeZbgQHVKALMNVB2PPsyUDQN5o2veA
         +gvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ZQd8Hht2;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id z15si275269wml.1.2022.02.18.05.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:45:17 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id A548C40257
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:45:16 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id e10-20020a056402190a00b00410f20467abso5529969edz.14
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:45:16 -0800 (PST)
X-Received: by 2002:aa7:dd1a:0:b0:410:9bb4:cba4 with SMTP id i26-20020aa7dd1a000000b004109bb4cba4mr8082044edv.364.1645191915661;
        Fri, 18 Feb 2022 05:45:15 -0800 (PST)
X-Received: by 2002:aa7:dd1a:0:b0:410:9bb4:cba4 with SMTP id
 i26-20020aa7dd1a000000b004109bb4cba4mr8082028edv.364.1645191915416; Fri, 18
 Feb 2022 05:45:15 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com> <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
In-Reply-To: <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 18 Feb 2022 14:45:04 +0100
Message-ID: <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=ZQd8Hht2;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Hi Aleksandr,

On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Hi Alex,
>
> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > Aleksandr,
> >
> > On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > First, thank you for working on this.
> > >
> > > On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >
> > > > If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > > to boot, but overwhelms me with tons of `virt_to_phys used for
> > > > non-linear address:` errors.
> > > >
> > > > Like that
> > > >
> > > > [    2.701271] virt_to_phys used for non-linear address:
> > > > 00000000b59e31b6 (0xffffffff806c2000)
> > > > [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > > __virt_to_phys+0x7e/0x86
> > > > [    2.702207] Modules linked in:
> > > > [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > > >   5.17.0-rc1 #1
> > > > [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > > [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > > [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > > [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > > ffff8f800021bde0
> > > > [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > > ffffffff80eea56f
> > > > [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > > ffff8f800021be00
> > > > [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > > ffffffff80e723d8
> > > > [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > > 0000000000000000
> > > > [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > > ffffffffffffffff
> > > > [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > > ffffffff806c2000
> > > > [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > > 0000000000000001
> > > > [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > > 00000000000000cc
> > > > [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > > ffffffffffffffff
> > > > [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > > [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > > cause: 0000000000000003
> > > > [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > > [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > > [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > > [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > > [    2.710310] ---[ end trace 0000000000000000 ]---
> > > >
> > >
> > > I was able to reproduce this: the first one regarding init_zero_pfn is
> > > legit but not wrong, I have to check when it was introduced and how to
> > > fix this.
> > > Regarding the huge batch that follows, at first sight, I would say
> > > this is linked to my sv48 patchset but that does not seem important as
> > > the address is a kernel mapping address so the use of virt_to_phys is
> > > right.
> > >
> > > > On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >
> > > > > On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > >
> > > > > > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > >
> > > > > > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > >
> > > > > > > > Hi Alex,
> > > > > > > >
> > > > > > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > > > > > >
> > > > > > > > > Hi Dmitry,
> > > > > > > > >
> > > > > > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > > > > > >> Hi Aleksandr,
> > > > > > > > > >>
> > > > > > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > > >>> Hello,
> > > > > > > > > >>>
> > > > > > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > > > > > >>
> > > > > > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > > > > > >>> to the following commit:
> > > > > > > > > >>>
> > > > > > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > > > > > >>>
> > > > > > > > > >>>      riscv: Fix asan-stack clang build
> > > > > > > > > >>>
> > > > > > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > > > > > >>> enabled. In the previous message syzbot mentions
> > > > > > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > > > > > >>>
> > > > > > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > > > > > >> I'll take a look at that today.
> > > > > > > > > >>
> > > > > > > > > >> Thanks for reporting the issue,
> > > > > > > > > >
> > > > > > > > >
> > > > > > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > > > > > from the inline instrumentation, I have no problem with the outline
> > > > > > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > > > > > to fix this for 5.17.
> > > > > > > >
> > > > > > > > Thanks for the update!
> > > > > > > >
> > > > > > > > Can you please share the .config with which you tested the outline
> > > > > > > > instrumentation?
> > > > > > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > > > > > but it still does not boot :(
> > > > > > > >
> > > > > > > > Here's what I used:
> > > > > > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > > > >
> > > > > > > Update: it doesn't boot with that big config, but boots if I generate
> > > > > > > a simple one with KASAN_OUTLINE:
> > > > > > >
> > > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > >
> > > > > > > And it indeed doesn't work if I use KASAN_INLINE.
> > > > > >
> > > > > > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > > > produce hugely massive .text. It may be hitting some limitation in the
> > > > > > bootloader/kernel bootstrap code.
> > >
> > > I took a quick glance and it traps on a KASAN address that is not
> > > mapped, either because it is too soon or because the mapping failed
> > > somehow.
> > >
> > > I'll definitely dive into that tomorrow, sorry for being slow here and
> > > thanks again for all your work, that helps a lot.
> > >
> > > Thanks,
> > >
> > > Alex
> > >
> > > > >
> > > > > I bisected the difference between the config we use on syzbot and the
> > > > > simple one that was generated like I described above.
> > > > > Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > > >
> > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >
> > > > > And the resulting kernel does not boot.
> > > > > My env: the `riscv/fixes` branch, commit
> > > > > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> >
> > I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> > maybe KASAN  + KCOV.
> >
> > With those small fixes, I was able to boot your large dotconfig with
> > KASAN_OUTLINE, the inline version still fails, this is my next target
> > :)
> > I'll push that tomorrow!
>
> Awesome, thank you very much!
> Looking forward to finally seeing the instance run :)

I sent a patchset which should fix your config with *outline* instrumentation.

However, as you'll see in the cover letter, I have an issue with
another KASAN config and if you can take a look at the stacktrace and
see if that rings a bell, that would be great.

Don't hesitate next time to ping me when the riscv syzbot instance fails :)

Alex


>
> --
> Best Regards,
> Aleksandr
>
> >
> > Thanks again,
> >
> > Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.
