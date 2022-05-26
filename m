Return-Path: <kasan-dev+bncBDFKDBGSFYIK73F4SQDBUBAX6ZVV2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7D9E534B34
	for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 10:11:31 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id u64-20020a1fdd43000000b00357451148aasf78524vkg.11
        for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 01:11:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653552688; cv=pass;
        d=google.com; s=arc-20160816;
        b=M9xfVZdrf+7mbOSxlCWnx8ssLL0SMIsO337++7lCSY52NWC8JDLQH4ymRg2Yix5DMT
         /uJzX2MjquwvQ0QMEzWisWPSZqd+qfyGFfWkJhVLXIRdnukWh5HXUbrQS0+l5h9+phsa
         4P4ko1RoML/4a0FkldfUAZrr2RbF4a+MoC49OQFB9RgoqEQw+ngujzXSAv6WHVecQ8jZ
         E5OnNP/cp9L/5gWaNcSKxALomneaZmjMwpZO813tHcBqzqYMkBHCaD+klHB/8nPxhFhE
         xi3/5EYLpdSq2ehmytYpv52X4/coY1YPYW957juGMaeZUeYMxD5KmSiXpy+Bvf/ZlM2h
         frmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=iiYIvcm9K8KaZg4HM+okJgzDM4+T1z6tjAZx2MTKUVs=;
        b=ASyX0TS4+8lCcPVXVu/M0Oli9zE0kSIX6+mwT4chBDGylTegw5KVazjVaMPp/erpnE
         vh37oVxU6kZHSfjCZpucQTxb14hsjxbjuZRPd5PRRk1hOtGccyxG7wtj5GeBCZ+DCyG3
         HPKWKR9J0J4ZlHT9MzFVUITB4mDcD5ZipNxLzi5ZveRPS7uAiklgz77+hOCXrF1vl014
         xAoBW2uD4k+TORWupvAhH0kaLN4b644X9cLY+kpSJz3IHG8oHaLUj/ScXh30ENxT8hJG
         krRUnhm8Eq48XSxZ8zhAd6sukMU7qd732F6tLvy+CCeymzRHYe8uOWCkNRLZxXFFGAOY
         n3Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=opEsQf9x;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=atishp@atishpatra.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iiYIvcm9K8KaZg4HM+okJgzDM4+T1z6tjAZx2MTKUVs=;
        b=BRhjKPSdgQKf+ygn5gwxELAR3nvujrOc9ADMPGwa1ZKDvqMKszogPiVba9lEPNs6en
         F+LstvtYn+9CVwBNLAmegQmK17Qw9O9Wm0aXhF5FBsQelxWMt3lxewvN3U4oh63sXMxi
         ryvX4Rf2tIgbVFHCuUo6YQyMqMzZnSq9pC2kdKrufJap6DQaK9NDcOYm0TM8PehZlojI
         zPpCwX/5PFC1NYQzi+lNzMjYrx5VAP/lmnQm/2k4/8pRvCjnI0rTGefECRrwmnC+U36e
         DXbDnPYpmm+nBqHe1YfcF+V+y7fUlJhMjyyUaeTObn5YQpSpizVexbN7h5+hh29LTSWb
         z40Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iiYIvcm9K8KaZg4HM+okJgzDM4+T1z6tjAZx2MTKUVs=;
        b=4YA6HcLMgy+cUNXRIhZRIFSFsx3Rte1E8E+zwoE7Ened4Pr/Ocuhbn6t7yjBniehes
         XRZrfG2G5YFpgAVVWwC8JLF5WtoHgg0n6g8aPDFuzFJq0RnZeiFkij7NyIDXkQFuretk
         9VwBtwB2kh1B8UpRAV3TcWo87M3MJyoMigTqUub/WXqt1tRJlwfeAyyaYGLXfLRMP/92
         2/NKCNRlXsVbi7VDxKMc904YP3PeIoazfD9XGzlyFM3rhB3tS+SPTXlJp1q75mLRUu3C
         I88H+lqjSZ/yCQ74GLSF4j+rBxxDaIRcS+uzWTb+sJ4VwyABm4WsL9YPfhQh9OmSioOs
         VV7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Nx13GeJaP4kfi3V60/berhsjBEJ6YQgcwDBWcAt50tVvZf1aK
	QwAZmY0PFFhhQ+llVpQLaeo=
X-Google-Smtp-Source: ABdhPJzUGAD+BYaHU9xlAs3lRo1/qWDqwrLwgyWVGVMkXBnMR2z9peMXLo2pPfsw/tHM1Vuh0v41Mg==
X-Received: by 2002:a05:6122:17a5:b0:357:239e:7b9e with SMTP id o37-20020a05612217a500b00357239e7b9emr13484101vkf.18.1653552687774;
        Thu, 26 May 2022 01:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fad4:0:b0:335:c3d4:7ea2 with SMTP id g20-20020a67fad4000000b00335c3d47ea2ls4446895vsq.8.gmail;
 Thu, 26 May 2022 01:11:27 -0700 (PDT)
X-Received: by 2002:a67:e00c:0:b0:337:d9c5:af6d with SMTP id c12-20020a67e00c000000b00337d9c5af6dmr4544902vsl.1.1653552687142;
        Thu, 26 May 2022 01:11:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653552687; cv=none;
        d=google.com; s=arc-20160816;
        b=L+aLKbhT8a6lPLBC/pSUshusITNirwzaGq3be83gISuGSEr/1ujSMPrbvM/pcVb+i2
         uR0tHoPxbxquUq19IwgsUONgIlucntD+uGMqTuaYO/VJxUXdgStiNuu1RDoDTzX9Owq9
         r0FFVcwfyuPcAgdifDO/eR57IUuCptdSPB4ofdF93VgSnon6V8EgYgY+K7ZU9lNYFqoY
         qIywQ/hHpopoMkCIc6phFiDS2OfFTgrEyPZgEVpB+tJp0eZP41vO9S5REtGC7Z7Z0b7N
         abMTjPQhzD07o2+ThQGnOyXy06Q/Ez6jiZhnBfYToyjJDZO3Re4wU8T3lbrY/CVKJwvj
         TllQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sT3GYIdUUQSNPmdWz8uq9qvx3kbQYZ8o49KqW4VxGGM=;
        b=y+DRxe6BWppNRveAKMXyAJIv8ToKeinnQOlrCSJm2p4VnA0V/GVWmQ6rca8FhP/FXX
         XnySNTun/ksuGpyf5RQkYwqpdCArItUaB/ZvdCk1/pQMAkxSHC9E43OX8RtC/GruSD5v
         U6eoXzNaPhStoTJNgcMbc42cgjaXaPizdmc8XfdR0JRSAFZEVnxg/XDhXgSZkyugPcps
         6o+RsHd1GxlvAB5r5MH2JX8ojvJMAkCR6WMLCsamm0Aqfx0nu9/krrmpbxiqdrQV1/DX
         JOerdSHIE/ssoGzeAKwPoHoI3+kZVxOL2mvxpZc0uPYdio2IaW606hI4p6UofaKUT16z
         RhYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=opEsQf9x;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=atishp@atishpatra.org
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id e9-20020a056122040900b00357324ba38csi44471vkd.5.2022.05.26.01.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 May 2022 01:11:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-30007f11f88so7442297b3.7
        for <kasan-dev@googlegroups.com>; Thu, 26 May 2022 01:11:27 -0700 (PDT)
X-Received: by 2002:a81:fc7:0:b0:301:9fd7:27e4 with SMTP id
 190-20020a810fc7000000b003019fd727e4mr3387760ywp.341.1653552686698; Thu, 26
 May 2022 01:11:26 -0700 (PDT)
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
 <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com> <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr>
In-Reply-To: <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr>
From: Atish Patra <atishp@atishpatra.org>
Date: Thu, 26 May 2022 01:11:15 -0700
Message-ID: <CAOnJCULgP_-D3cY2m39k9N912Q55FS7X9JcrRVoUt0GC92tx7w@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	Aleksandr Nogikh <nogikh@google.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: atishp@atishpatra.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@atishpatra.org header.s=google header.b=opEsQf9x;       spf=pass
 (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=atishp@atishpatra.org
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

On Mon, May 16, 2022 at 5:06 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
>
>
> On 5/12/22 13:48, Dmitry Vyukov wrote:
> > On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> >> Hi Aleksandr,
> >>
> >> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>> Hi Alex,
> >>>
> >>> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> >>> <alexandre.ghiti@canonical.com> wrote:
> >>>> Aleksandr,
> >>>>
> >>>> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> >>>> <alexandre.ghiti@canonical.com> wrote:
> >>>>> First, thank you for working on this.
> >>>>>
> >>>>> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>>>>> If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> >>>>>> to boot, but overwhelms me with tons of `virt_to_phys used for
> >>>>>> non-linear address:` errors.
> >>>>>>
> >>>>>> Like that
> >>>>>>
> >>>>>> [    2.701271] virt_to_phys used for non-linear address:
> >>>>>> 00000000b59e31b6 (0xffffffff806c2000)
> >>>>>> [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> >>>>>> __virt_to_phys+0x7e/0x86
> >>>>>> [    2.702207] Modules linked in:
> >>>>>> [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> >>>>>>    5.17.0-rc1 #1
> >>>>>> [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> >>>>>> [    2.703051] epc : __virt_to_phys+0x7e/0x86
> >>>>>> [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> >>>>>> [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> >>>>>> ffff8f800021bde0
> >>>>>> [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> >>>>>> ffffffff80eea56f
> >>>>>> [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> >>>>>> ffff8f800021be00
> >>>>>> [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> >>>>>> ffffffff80e723d8
> >>>>>> [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> >>>>>> 0000000000000000
> >>>>>> [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> >>>>>> ffffffffffffffff
> >>>>>> [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> >>>>>> ffffffff806c2000
> >>>>>> [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> >>>>>> 0000000000000001
> >>>>>> [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> >>>>>> 00000000000000cc
> >>>>>> [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> >>>>>> ffffffffffffffff
> >>>>>> [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> >>>>>> [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> >>>>>> cause: 0000000000000003
> >>>>>> [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> >>>>>> [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> >>>>>> [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> >>>>>> [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> >>>>>> [    2.710310] ---[ end trace 0000000000000000 ]---
> >>>>>>
> >>>>> I was able to reproduce this: the first one regarding init_zero_pfn is
> >>>>> legit but not wrong, I have to check when it was introduced and how to
> >>>>> fix this.
> >>>>> Regarding the huge batch that follows, at first sight, I would say
> >>>>> this is linked to my sv48 patchset but that does not seem important as
> >>>>> the address is a kernel mapping address so the use of virt_to_phys is
> >>>>> right.
> >>>>>
> >>>>>> On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>>>>>> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >>>>>>>> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> >>>>>>>>> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>>>>>>>>> Hi Alex,
> >>>>>>>>>>
> >>>>>>>>>> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> >>>>>>>>>>> Hi Dmitry,
> >>>>>>>>>>>
> >>>>>>>>>>> On 2/15/22 18:12, Dmitry Vyukov wrote:
> >>>>>>>>>>>> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> >>>>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
> >>>>>>>>>>>>> Hi Aleksandr,
> >>>>>>>>>>>>>
> >>>>>>>>>>>>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>>>>>>>>>>>>> Hello,
> >>>>>>>>>>>>>>
> >>>>>>>>>>>>>> syzbot has already not been able to fuzz its RISC-V instance for 97
> >>>>>>>>>>>>> That's a longtime, I'll take a look more regularly.
> >>>>>>>>>>>>>
> >>>>>>>>>>>>>> days now because the compiled kernel cannot boot. I bisected the issue
> >>>>>>>>>>>>>> to the following commit:
> >>>>>>>>>>>>>>
> >>>>>>>>>>>>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> >>>>>>>>>>>>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> >>>>>>>>>>>>>> Date:   Fri Oct 29 06:59:27 2021 +0200
> >>>>>>>>>>>>>>
> >>>>>>>>>>>>>>       riscv: Fix asan-stack clang build
> >>>>>>>>>>>>>>
> >>>>>>>>>>>>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> >>>>>>>>>>>>>> enabled. In the previous message syzbot mentions
> >>>>>>>>>>>>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> >>>>>>>>>>>>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> >>>>>>>>>>>>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> >>>>>>>>>>>>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> >>>>>>>>>>>>>> For convenience, I also duplicate the .config file from the bot's
> >>>>>>>>>>>>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> >>>>>>>>>>>>>>
> >>>>>>>>>>>>>> Can someone with KASAN and RISC-V expertise please take a look?
> >>>>>>>>>>>>> I'll take a look at that today.
> >>>>>>>>>>>>>
> >>>>>>>>>>>>> Thanks for reporting the issue,
> >>>>>>>>>>> I took a quick look, not enough to fix it but I know the issue comes
> >>>>>>>>>>> from the inline instrumentation, I have no problem with the outline
> >>>>>>>>>>> instrumentation. I need to find some cycles to work on this, my goal is
> >>>>>>>>>>> to fix this for 5.17.
> >>>>>>>>>> Thanks for the update!
> >>>>>>>>>>
> >>>>>>>>>> Can you please share the .config with which you tested the outline
> >>>>>>>>>> instrumentation?
> >>>>>>>>>> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> >>>>>>>>>> but it still does not boot :(
> >>>>>>>>>>
> >>>>>>>>>> Here's what I used:
> >>>>>>>>>> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> >>>>>>>>> Update: it doesn't boot with that big config, but boots if I generate
> >>>>>>>>> a simple one with KASAN_OUTLINE:
> >>>>>>>>>
> >>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE
> >>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >>>>>>>>>
> >>>>>>>>> And it indeed doesn't work if I use KASAN_INLINE.
> >>>>>>>> It may be an issue with code size. Full syzbot config + KASAN + KCOV
> >>>>>>>> produce hugely massive .text. It may be hitting some limitation in the
> >>>>>>>> bootloader/kernel bootstrap code.
> >>>>> I took a quick glance and it traps on a KASAN address that is not
> >>>>> mapped, either because it is too soon or because the mapping failed
> >>>>> somehow.
> >>>>>
> >>>>> I'll definitely dive into that tomorrow, sorry for being slow here and
> >>>>> thanks again for all your work, that helps a lot.
> >>>>>
> >>>>> Thanks,
> >>>>>
> >>>>> Alex
> >>>>>
> >>>>>>> I bisected the difference between the config we use on syzbot and the
> >>>>>>> simple one that was generated like I described above.
> >>>>>>> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> >>>>>>>
> >>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> >>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >>>>>>>
> >>>>>>> And the resulting kernel does not boot.
> >>>>>>> My env: the `riscv/fixes` branch, commit
> >>>>>>> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> >>>> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> >>>> maybe KASAN  + KCOV.
> >>>>
> >>>> With those small fixes, I was able to boot your large dotconfig with
> >>>> KASAN_OUTLINE, the inline version still fails, this is my next target
> >>>> :)
> >>>> I'll push that tomorrow!
> >>> Awesome, thank you very much!
> >>> Looking forward to finally seeing the instance run :)
> >> I sent a patchset which should fix your config with *outline* instrumentation.
> > Was this fix merged? The riscv instance still does not boot:
> > https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127
>
>
> Yes it has been in Linus tree since 5.18-rc1. I'll take a look at that
> this week.
>

Are you seeing this error or a different one ? I used the
syzkaller_defconfig from the patch below on v5.18.

https://lore.kernel.org/all/20220419174952.699-1-palmer@rivosinc.com/

[   15.076116][    T1] Mandatory Access Control activated.
[   15.158241][    T1] AppArmor: AppArmor Filesystem Enabled
[   16.150870][    T1] NET: Registered PF_INET protocol family
[   16.166167][    T1] IP idents hash table entries: 32768 (order: 6,
262144 bytes, linear)
[   16.188727][    T1] Unable to handle kernel paging request at
virtual address ffebfffeffff2000
[   16.192727][    T1] Oops [#1]
[   16.193479][    T1] Modules linked in:
[   16.194687][    T1] CPU: 3 PID: 1 Comm: swapper/0 Not tainted
5.18.0-00001-g37ac279268bf-dirty #9
[   16.196486][    T1] Hardware name: riscv-virtio,qemu (DT)
[   16.197836][    T1] epc : kasan_check_range+0x9e/0x14e
[   16.199104][    T1]  ra : memset+0x1e/0x4c
[   16.200091][    T1] epc : ffffffff804787e0 ra : ffffffff80478f30 sp
: ff600000073ffb70
[   16.201420][    T1]  gp : ffffffff85879e80 tp : ff600000073f0000 t0
: 7300000000000000
[   16.202762][    T1]  t1 : ffebfffeffff21ff t2 : 73746e6564692050 s0
: ff600000073ffba0
[   16.204047][    T1]  s1 : 0000000000001000 a0 : ffebfffeffff2200 a1
: 0000000000001000
[   16.205312][    T1]  a2 : 0000000000000001 a3 : ffffffff803a4f32 a4
: ff5ffffffff90000
[   16.206592][    T1]  a5 : ffebfffeffff2000 a6 : 0000004000000000 a7
: ff5ffffffff90fff
[   16.207865][    T1]  s2 : ff5ffffffff90000 s3 : 0000000000000000 s4
: ffffffff8467ea90
[   16.209134][    T1]  s5 : 0000000000000000 s6 : ff5ffffffff90000 s7
: 0000000000000000
[   16.210394][    T1]  s8 : 0000000000001000 s9 : ffffffff8587ca40
s10: 0000000000000004
[   16.211952][    T1]  s11: ffffffff858a03a0 t3 : 0000000000000000 t4
: 0000000000000040
[   16.213469][    T1]  t5 : ffebfffeffff2200 t6 : ff600000073ff738
[   16.214853][    T1] status: 0000000200000120 badaddr:
ffebfffeffff2000 cause: 000000000000000d
[   16.216910][    T1] Call Trace:
[   16.217816][    T1] [<ffffffff803a4f32>] pcpu_alloc+0x844/0x1254
[   16.219110][    T1] [<ffffffff803a59a0>] __alloc_percpu+0x28/0x34
[   16.220244][    T1] [<ffffffff8328824a>] ip_rt_init+0x17e/0x382
[   16.221606][    T1] [<ffffffff8328861c>] ip_init+0x18/0x30
[   16.222719][    T1] [<ffffffff8328a0ee>] inet_init+0x2a6/0x550
[   16.223863][    T1] [<ffffffff80003204>] do_one_initcall+0x130/0x7dc
[   16.225002][    T1] [<ffffffff83201fbc>] kernel_init_freeable+0x510/0x5b4
[   16.226273][    T1] [<ffffffff8319842a>] kernel_init+0x28/0x21c
[   16.227337][    T1] [<ffffffff80005818>] ret_from_exception+0x0/0x10
[   16.229910][    T1] ---[ end trace 0000000000000000 ]---
[   16.231880][    T1] Kernel panic - not syncing: Fatal exception


> Thanks,
>
> Alex
>
>
> >
> >> However, as you'll see in the cover letter, I have an issue with
> >> another KASAN config and if you can take a look at the stacktrace and
> >> see if that rings a bell, that would be great.
> >>
> >> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
> >>
> >> Alex
> >>
> >>
> >>> --
> >>> Best Regards,
> >>> Aleksandr
> >>>
> >>>> Thanks again,
> >>>>
> >>>> Alex
> >> --
> >> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> >> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> >> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv



-- 
Regards,
Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnJCULgP_-D3cY2m39k9N912Q55FS7X9JcrRVoUt0GC92tx7w%40mail.gmail.com.
