Return-Path: <kasan-dev+bncBCMIZB7QWENRB4MYYOKAMGQEZCZLZ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id B0FF4536325
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:04:50 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id r8-20020a056402018800b00428b43999fesf3031814edv.5
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:04:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653656690; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ywxz91kni65/Zf0zWgOdjuKXiybGx4yHjaC+ZhgDY5yOnD9G1PmIU2KkM5+Jqr0kdb
         YU7/lQgxnrqqmG2u92FkpoHfWDdqonkNEOkZIcgY9epfORoLGq2c6f9Bn9ajUWQpskzv
         wEringt3abAwq/nBpDN3L30Bq6p0bdkrBhb9WrGerAE1t2ty8BFAuhNb136U0NsScmF7
         R5eUikDH4Ne3vW160Wfi4ge4ez9/RX2tG3vPC5op3dGNOAz2LWG1v73wxdpuriuZPFmj
         A1fiuf6nzrBTbFxWHlk57CcCAbLRCe2d6h9gzYhMCMQ9RYy/8Mm0zR5AggiDRtnFn50M
         xbXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mKq5gYImpxStko5fhkTNpKDBCWw5NBHkqSfrCnxGrbk=;
        b=nvM1GK662TmJoB7R3ICqIIFtSztQs+em2iJxIhWDC/ODJx9wyev32dp5HD6Mg01RSq
         GZ4Rc5SJIb3GYgjCERtBkMrQh21A8T2WqQEh73bvMhJo3XSX9dUYt5uX/sDcBOQow89J
         QTybrubpr8yePtw4KL1vmTgCGBL4iA6xQoWr37wKuydfKRJpHTzgoJXh3bKrfO2/w8in
         YB+O7HgrMuvYlutqRJ6BVG3JuqoDTCG5mBt6ZcnQ+5RaOm+XT+N99yGTmLAHV90zqbTt
         SIsrUigu43nw+q2Q8kBgkDkJeRxi5/oFCBoDV4xfEOltJcCd1bukPJrc2Npa2kG4cHGq
         bA1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="N6O/fB2x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mKq5gYImpxStko5fhkTNpKDBCWw5NBHkqSfrCnxGrbk=;
        b=Pz59NA805N2qrtWNVfY4XEsY9LFrUlNfAVa64DJWmf4/ieiyw8Xknri4PhcAxrx7en
         GAz9/B5NiPvH2ni0W9d5VrbI6c0n+qkYnOiPZgVAd3vZm6dTDw7Sd96Di/5ZGl85hitQ
         f7tdxqjyH+4tqDXRdJ/XcE+FEea96H0tsR63Rz2l521z3hdj+Pz0vPnUTPkAG2L84w0Z
         Gyx20TIjE+ViNeXum9Ta9ZTIkSKlX5gekUETqC+yKjxLAgaB6UZp3ByFDH6lFnTsampJ
         ucvRragDOj3AyrnKzPmDCsJK4Cd1vY95SpgGBu0wvwg7vuLEh7EpSyRw/FeoNSEwsrnT
         X/xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mKq5gYImpxStko5fhkTNpKDBCWw5NBHkqSfrCnxGrbk=;
        b=Rkue7koHtxDrLvzSjH/oXwbq6FDC3H55Kt3YFTDT8PjVHacRSWdMJGx41KJlbePwQG
         bAOCeR5b88GHmF/gU3xlAYFg/yUuEX5dcJarP/lZmTcDXhZRjmSEG7+eujqBjMhWMf+D
         XjOFIaRKiRviQypnIhqo57KHVoY+qkz1OqfGQ29Fh0bX9ixlOsbcx1xFbP+VR47MKO+7
         cNkOgvGpJpebUL93hdamxv6xJs/b6Lc91ddBZPOPO7iJpTQe8Ye+Sk4EyITE57832wFq
         faMGPZOsbIkbWBncc8F9bF+hIMvL4EI7+jnPCUQdMaCmC2lKHxKgF60dbesxgXNj5sEI
         ibqA==
X-Gm-Message-State: AOAM530nM22zulHaSFrhofQ/Y68hawdj+pPQLQL3O7AEXgaU1/EGSB+U
	q597wWYAHABv/3yIG15RNQY=
X-Google-Smtp-Source: ABdhPJxYw3JIvS3dRS2ecDZWEAyYZxhM3SHNrNZY5sBvUalbVTRoNaXWbBHjpEIejt5LYiLHGbtf7g==
X-Received: by 2002:a17:907:2d91:b0:6fe:e517:7356 with SMTP id gt17-20020a1709072d9100b006fee5177356mr22841895ejc.328.1653656690227;
        Fri, 27 May 2022 06:04:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6e11:b0:6ff:232a:2406 with SMTP id
 sd17-20020a1709076e1100b006ff232a2406ls2952916ejc.0.gmail; Fri, 27 May 2022
 06:04:49 -0700 (PDT)
X-Received: by 2002:a17:907:2167:b0:6ff:8ed:db67 with SMTP id rl7-20020a170907216700b006ff08eddb67mr14855386ejb.764.1653656688978;
        Fri, 27 May 2022 06:04:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653656688; cv=none;
        d=google.com; s=arc-20160816;
        b=DxhIZCsvw+qOev7+AAozGmS6NJ/8ouy7Mhik+9R5z8R8pD674KV8WdNQPQpqADmhju
         Tb8o4YbQo1a3RjqId9YXaz9PplA1tBR5uQqqsAP2NWDomV1vjKf4iluJNSXE7cLd24tZ
         jj3HVh5YW4MpUYymr8xnptKrVkxG+xCLkaBzPNrQck7+tuLyc52tOdsN0a3VmYATq5+i
         QzvRmCjL9IcpWCICI4Tk5tkqwljPu9Z/143kpvbyTy2RuZRCV/69Du1saSVBmkDffO3n
         KlXMW7s847NUzXWwziANvnE7Uhz3PArF/IyN53MpvG6MHHHSyOPcUXVCOWlxIOopYhrD
         rt7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YjJnblK4U3NCIbGYCswwX+gF+Gis3UKa2COyN188bL4=;
        b=eHhXow+bKcI31RQOV9syyufZruOJbmqw9C7x3OLp/uvFyglfysHzaJHYe1cMElz9ND
         gOtjB2xY4p/6dqLS9CJdxpyF3qVLyptVfENe5nrIUKfdA2roI6oo8KXA6KHV5oWpekCf
         lHiQwwyHHc74YAJ2g8j45RxhUDP4M185IaUHupqvrtdpyOvfFqfbefkC0zbrL0O+lXfX
         6e1wXrJUuUsAnN6tfndEGxb+1SZCeSft/kWbNoeP/jgnYu8RxjbK2EoMdWD/vk8LDVel
         HHQmAD+GgT2PXy/0S7dIbAktZ5WkF8vG/hufmeoBHeBG15RiFNKDGxxHvcCzMYJht4t1
         e9eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="N6O/fB2x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id w8-20020aa7cb48000000b0042af0958d51si199546edt.5.2022.05.27.06.04.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 06:04:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id l30so1684835lfj.3
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 06:04:48 -0700 (PDT)
X-Received: by 2002:a05:6512:3c94:b0:477:ba25:de54 with SMTP id
 h20-20020a0565123c9400b00477ba25de54mr30098024lfv.137.1653656688036; Fri, 27
 May 2022 06:04:48 -0700 (PDT)
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
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
 <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
 <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
 <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr> <CAOnJCULgP_-D3cY2m39k9N912Q55FS7X9JcrRVoUt0GC92tx7w@mail.gmail.com>
 <CAOnJCUKBWx+wEKaq8WOPC1j7jgn38iWcrTh4gO+FzfF-mhPkQg@mail.gmail.com> <CA+zEjCuK7NitU_tdjBo+qmhkN_qmH=NCryffb466E7ebVq0GDw@mail.gmail.com>
In-Reply-To: <CA+zEjCuK7NitU_tdjBo+qmhkN_qmH=NCryffb466E7ebVq0GDw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 15:04:36 +0200
Message-ID: <CACT4Y+Y7tS+OnEaZMFPh73tTmTVY1X2TZ4vfd2S2THwReBF97w@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Atish Patra <atishp@atishpatra.org>, Alexandre Ghiti <alex@ghiti.fr>, 
	Aleksandr Nogikh <nogikh@google.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="N6O/fB2x";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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

On Fri, 27 May 2022 at 09:33, Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Atish,
> > > > On 5/12/22 13:48, Dmitry Vyukov wrote:
> > > > > On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
> > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > >> Hi Aleksandr,
> > > > >>
> > > > >> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>> Hi Alex,
> > > > >>>
> > > > >>> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> > > > >>> <alexandre.ghiti@canonical.com> wrote:
> > > > >>>> Aleksandr,
> > > > >>>>
> > > > >>>> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> > > > >>>> <alexandre.ghiti@canonical.com> wrote:
> > > > >>>>> First, thank you for working on this.
> > > > >>>>>
> > > > >>>>> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>>>>> If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > > >>>>>> to boot, but overwhelms me with tons of `virt_to_phys used for
> > > > >>>>>> non-linear address:` errors.
> > > > >>>>>>
> > > > >>>>>> Like that
> > > > >>>>>>
> > > > >>>>>> [    2.701271] virt_to_phys used for non-linear address:
> > > > >>>>>> 00000000b59e31b6 (0xffffffff806c2000)
> > > > >>>>>> [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > > >>>>>> __virt_to_phys+0x7e/0x86
> > > > >>>>>> [    2.702207] Modules linked in:
> > > > >>>>>> [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > > > >>>>>>    5.17.0-rc1 #1
> > > > >>>>>> [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > > >>>>>> [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > > >>>>>> [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > > >>>>>> [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > > >>>>>> ffff8f800021bde0
> > > > >>>>>> [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > > >>>>>> ffffffff80eea56f
> > > > >>>>>> [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > > >>>>>> ffff8f800021be00
> > > > >>>>>> [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > > >>>>>> ffffffff80e723d8
> > > > >>>>>> [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > > >>>>>> 0000000000000000
> > > > >>>>>> [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > > >>>>>> ffffffffffffffff
> > > > >>>>>> [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > > >>>>>> ffffffff806c2000
> > > > >>>>>> [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > > >>>>>> 0000000000000001
> > > > >>>>>> [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > > >>>>>> 00000000000000cc
> > > > >>>>>> [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > > >>>>>> ffffffffffffffff
> > > > >>>>>> [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > > >>>>>> [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > > >>>>>> cause: 0000000000000003
> > > > >>>>>> [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > > >>>>>> [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > > >>>>>> [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > > >>>>>> [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > > >>>>>> [    2.710310] ---[ end trace 0000000000000000 ]---
> > > > >>>>>>
> > > > >>>>> I was able to reproduce this: the first one regarding init_zero_pfn is
> > > > >>>>> legit but not wrong, I have to check when it was introduced and how to
> > > > >>>>> fix this.
> > > > >>>>> Regarding the huge batch that follows, at first sight, I would say
> > > > >>>>> this is linked to my sv48 patchset but that does not seem important as
> > > > >>>>> the address is a kernel mapping address so the use of virt_to_phys is
> > > > >>>>> right.
> > > > >>>>>
> > > > >>>>>> On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>>>>>> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > >>>>>>>> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>>>>>>>> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>>>>>>>>> Hi Alex,
> > > > >>>>>>>>>>
> > > > >>>>>>>>>> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > >>>>>>>>>>> Hi Dmitry,
> > > > >>>>>>>>>>>
> > > > >>>>>>>>>>> On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > >>>>>>>>>>>> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > >>>>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
> > > > >>>>>>>>>>>>> Hi Aleksandr,
> > > > >>>>>>>>>>>>>
> > > > >>>>>>>>>>>>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>>>>>>>>>>>>> Hello,
> > > > >>>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > >>>>>>>>>>>>> That's a longtime, I'll take a look more regularly.
> > > > >>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > >>>>>>>>>>>>>> to the following commit:
> > > > >>>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > >>>>>>>>>>>>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > >>>>>>>>>>>>>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > >>>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>>       riscv: Fix asan-stack clang build
> > > > >>>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > >>>>>>>>>>>>>> enabled. In the previous message syzbot mentions
> > > > >>>>>>>>>>>>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > >>>>>>>>>>>>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > >>>>>>>>>>>>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > >>>>>>>>>>>>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > >>>>>>>>>>>>>> For convenience, I also duplicate the .config file from the bot's
> > > > >>>>>>>>>>>>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > >>>>>>>>>>>>>>
> > > > >>>>>>>>>>>>>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > >>>>>>>>>>>>> I'll take a look at that today.
> > > > >>>>>>>>>>>>>
> > > > >>>>>>>>>>>>> Thanks for reporting the issue,
> > > > >>>>>>>>>>> I took a quick look, not enough to fix it but I know the issue comes
> > > > >>>>>>>>>>> from the inline instrumentation, I have no problem with the outline
> > > > >>>>>>>>>>> instrumentation. I need to find some cycles to work on this, my goal is
> > > > >>>>>>>>>>> to fix this for 5.17.
> > > > >>>>>>>>>> Thanks for the update!
> > > > >>>>>>>>>>
> > > > >>>>>>>>>> Can you please share the .config with which you tested the outline
> > > > >>>>>>>>>> instrumentation?
> > > > >>>>>>>>>> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > >>>>>>>>>> but it still does not boot :(
> > > > >>>>>>>>>>
> > > > >>>>>>>>>> Here's what I used:
> > > > >>>>>>>>>> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > >>>>>>>>> Update: it doesn't boot with that big config, but boots if I generate
> > > > >>>>>>>>> a simple one with KASAN_OUTLINE:
> > > > >>>>>>>>>
> > > > >>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > >>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >>>>>>>>>
> > > > >>>>>>>>> And it indeed doesn't work if I use KASAN_INLINE.
> > > > >>>>>>>> It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > >>>>>>>> produce hugely massive .text. It may be hitting some limitation in the
> > > > >>>>>>>> bootloader/kernel bootstrap code.
> > > > >>>>> I took a quick glance and it traps on a KASAN address that is not
> > > > >>>>> mapped, either because it is too soon or because the mapping failed
> > > > >>>>> somehow.
> > > > >>>>>
> > > > >>>>> I'll definitely dive into that tomorrow, sorry for being slow here and
> > > > >>>>> thanks again for all your work, that helps a lot.
> > > > >>>>>
> > > > >>>>> Thanks,
> > > > >>>>>
> > > > >>>>> Alex
> > > > >>>>>
> > > > >>>>>>> I bisected the difference between the config we use on syzbot and the
> > > > >>>>>>> simple one that was generated like I described above.
> > > > >>>>>>> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > > >>>>>>>
> > > > >>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > > >>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >>>>>>>
> > > > >>>>>>> And the resulting kernel does not boot.
> > > > >>>>>>> My env: the `riscv/fixes` branch, commit
> > > > >>>>>>> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> > > > >>>> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> > > > >>>> maybe KASAN  + KCOV.
> > > > >>>>
> > > > >>>> With those small fixes, I was able to boot your large dotconfig with
> > > > >>>> KASAN_OUTLINE, the inline version still fails, this is my next target
> > > > >>>> :)
> > > > >>>> I'll push that tomorrow!
> > > > >>> Awesome, thank you very much!
> > > > >>> Looking forward to finally seeing the instance run :)
> > > > >> I sent a patchset which should fix your config with *outline* instrumentation.
> > > > > Was this fix merged? The riscv instance still does not boot:
> > > > > https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127
> > > >
> > > >
> > > > Yes it has been in Linus tree since 5.18-rc1. I'll take a look at that
> > > > this week.
> > > >
> > >
> > > Are you seeing this error or a different one ? I used the
> > > syzkaller_defconfig from the patch below on v5.18.
> > >
> > > https://lore.kernel.org/all/20220419174952.699-1-palmer@rivosinc.com/
> > >
> > > [   15.076116][    T1] Mandatory Access Control activated.
> > > [   15.158241][    T1] AppArmor: AppArmor Filesystem Enabled
> > > [   16.150870][    T1] NET: Registered PF_INET protocol family
> > > [   16.166167][    T1] IP idents hash table entries: 32768 (order: 6,
> > > 262144 bytes, linear)
> > > [   16.188727][    T1] Unable to handle kernel paging request at
> > > virtual address ffebfffeffff2000
> > > [   16.192727][    T1] Oops [#1]
> > > [   16.193479][    T1] Modules linked in:
> > > [   16.194687][    T1] CPU: 3 PID: 1 Comm: swapper/0 Not tainted
> > > 5.18.0-00001-g37ac279268bf-dirty #9
> > > [   16.196486][    T1] Hardware name: riscv-virtio,qemu (DT)
> > > [   16.197836][    T1] epc : kasan_check_range+0x9e/0x14e
> > > [   16.199104][    T1]  ra : memset+0x1e/0x4c
> > > [   16.200091][    T1] epc : ffffffff804787e0 ra : ffffffff80478f30 sp
> > > : ff600000073ffb70
> > > [   16.201420][    T1]  gp : ffffffff85879e80 tp : ff600000073f0000 t0
> > > : 7300000000000000
> > > [   16.202762][    T1]  t1 : ffebfffeffff21ff t2 : 73746e6564692050 s0
> > > : ff600000073ffba0
> > > [   16.204047][    T1]  s1 : 0000000000001000 a0 : ffebfffeffff2200 a1
> > > : 0000000000001000
> > > [   16.205312][    T1]  a2 : 0000000000000001 a3 : ffffffff803a4f32 a4
> > > : ff5ffffffff90000
> > > [   16.206592][    T1]  a5 : ffebfffeffff2000 a6 : 0000004000000000 a7
> > > : ff5ffffffff90fff
> > > [   16.207865][    T1]  s2 : ff5ffffffff90000 s3 : 0000000000000000 s4
> > > : ffffffff8467ea90
> > > [   16.209134][    T1]  s5 : 0000000000000000 s6 : ff5ffffffff90000 s7
> > > : 0000000000000000
> > > [   16.210394][    T1]  s8 : 0000000000001000 s9 : ffffffff8587ca40
> > > s10: 0000000000000004
> > > [   16.211952][    T1]  s11: ffffffff858a03a0 t3 : 0000000000000000 t4
> > > : 0000000000000040
> > > [   16.213469][    T1]  t5 : ffebfffeffff2200 t6 : ff600000073ff738
> > > [   16.214853][    T1] status: 0000000200000120 badaddr:
> > > ffebfffeffff2000 cause: 000000000000000d
> > > [   16.216910][    T1] Call Trace:
> > > [   16.217816][    T1] [<ffffffff803a4f32>] pcpu_alloc+0x844/0x1254
> > > [   16.219110][    T1] [<ffffffff803a59a0>] __alloc_percpu+0x28/0x34
> > > [   16.220244][    T1] [<ffffffff8328824a>] ip_rt_init+0x17e/0x382
> > > [   16.221606][    T1] [<ffffffff8328861c>] ip_init+0x18/0x30
> > > [   16.222719][    T1] [<ffffffff8328a0ee>] inet_init+0x2a6/0x550
> > > [   16.223863][    T1] [<ffffffff80003204>] do_one_initcall+0x130/0x7dc
> > > [   16.225002][    T1] [<ffffffff83201fbc>] kernel_init_freeable+0x510/0x5b4
> > > [   16.226273][    T1] [<ffffffff8319842a>] kernel_init+0x28/0x21c
> > > [   16.227337][    T1] [<ffffffff80005818>] ret_from_exception+0x0/0x10
> > > [   16.229910][    T1] ---[ end trace 0000000000000000 ]---
> > > [   16.231880][    T1] Kernel panic - not syncing: Fatal exception
> > >
> > >
> >
> > Enabling CONFIG_KASAN_VMALLOC=y solves the issue and I am able to boot
> > to the userspace.
> > I have tried enabling/disabling CONFIG_VMAP_STACK as well. Both works fine.
> >
> > Looking at the ARM64 Kconfig, KASAN_VMALLOC is enabled if KASAN is enabled.
> > This diff seems to work for me.
> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > index 00fd9c548f26..cbf0fe227c77 100644
> > --- a/arch/riscv/Kconfig
> > +++ b/arch/riscv/Kconfig
> > @@ -122,6 +122,7 @@ config RISCV
> >         select TRACE_IRQFLAGS_SUPPORT
> >         select UACCESS_MEMCPY if !MMU
> >         select ZONE_DMA32 if 64BIT
> > +       select KASAN_VMALLOC if KASAN
> >
> > I am not a kasan expert so I am not sure if this is the correct fix or
> > just hides the real issue. pcpu_alloc seems to use vmalloc though.
>
> When this type of thing happens, generally this is because of an error
> in the kasan page table, I'll take a look this time, sorry I did not
> do this before.
>
> Thanks for finding this,
>
> Alex

Unfortunately riscv still does not work for syzbot, other bugs piled up.
Something has changes wrt user-space pointers:
https://groups.google.com/g/syzkaller-bugs/c/lU0GQTZoNQQ/m/iuRBTgU3AAAJ
https://syzkaller.appspot.com/bug?extid=2c5da6a0a16a0c4f34aa

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY7tS%2BOnEaZMFPh73tTmTVY1X2TZ4vfd2S2THwReBF97w%40mail.gmail.com.
