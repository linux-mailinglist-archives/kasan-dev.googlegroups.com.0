Return-Path: <kasan-dev+bncBC7PZX4C3UKBBI5TY6KAMGQE33NJFLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 912B1536B90
	for <lists+kasan-dev@lfdr.de>; Sat, 28 May 2022 10:13:24 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id u12-20020a05600c19cc00b0038ec265155fsf6145253wmq.6
        for <lists+kasan-dev@lfdr.de>; Sat, 28 May 2022 01:13:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653725604; cv=pass;
        d=google.com; s=arc-20160816;
        b=NqNdTL3+J/w8rVpYoW1Tno1j1no2B/lNJXQW0FMWUWlYzjMk/emYGK2Xo/3U8mZx6G
         Dqvp9zT6uhgxdsHyHAY/SA0YmCrY5VgL2baJRVfAsA5K13cX2NxPAckFszX6/z6DD+Pm
         795ztp1/tHHZlb4GnnV7V2t1kCU1n3kYdWnFIABZXkGbKt55FGxaBmModWYwjgHjEEum
         /mU5I3capjiYC6CnbzJcWbTAkgw7NCp1XPSiwk2wGyesa+0pQPqxNVRccfsjs9zxkCM3
         j2hdQh7qrLd3hJYsw1DgjIlj5rdpm5vJ1XmOLDZno1UhKO3bAm5i9p2enSKUNZbGisQ+
         8whQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=o3jEsFCVPePAGbgP3wKhmpV8YXvpFvCXKUgjUUecXQk=;
        b=icHDeNoLNRvxwAS8tZMuZVSeNdsdOZfK1PXuGogyLemMAePUvdcjpjdYdCUtSK0BB8
         O0he18POf9dZZiswPomZpCsgdvag58PjnRe0XKwZH52G5uVjDG7rOZQRAVYeqb9R11TI
         VjrUHgDu5LLtx00D6Y/L6zUFaA92+/4TFyKokECbApMqMEJYOah8kC6Rk9PxE89tCkKT
         +Ufsk0v4MjxiiDxZPHLS9MBf7fCWpAd3T3dhiUq9Vh4mib21kPuUY9WnG3WAcSlTPmQN
         A99SXb+w/fkeZD9NjJdfKEOsKrjxvGybLeWDVCC5WgKAYThuflKVEN6qkJhxVFKW/Smw
         BQRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o3jEsFCVPePAGbgP3wKhmpV8YXvpFvCXKUgjUUecXQk=;
        b=V/iFqdgfrDQowCXdbqDl6KVFYijowhVkTy1E9VjTg3ASVHadGy3fTgv1JQyLfOIsNp
         kUTCmhPqP/iNmtEFvSfQP2Li+r+KRZxqmE724s1zy/0XX0ODAMTKO3/m8od2nEA5qR9m
         K+vd2mtsJCBkv5HyXemJkZIB8LuI+Wr70Jcs2WMG0/dMwIrIQEKmBZXOD4seUHBlSj7j
         K7eXjPODZX+rpVCs7rb5ZMTBCAKuaweXyvwbo5PELBMuuWpDEDWDgvzcJ3HOc3AIH+Q3
         6Ew05De7lZwfME0veOq5Drk/a6dvTZeKSthQRFo0HJe21I3kcxTwtqUDjbgghSgd25oI
         uV4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o3jEsFCVPePAGbgP3wKhmpV8YXvpFvCXKUgjUUecXQk=;
        b=g31r4HxWuBClwoECzP7JBCLAeQrhIsV97DYGWkcXxTWFzsnKtQu4TXuhw5aIaA62Fx
         DYHjBuRe4ON5ONp//Gf7P6x4avd3sNIx1QTwRnK/GoFoNzc4u/MI+qXtx0MjMKzecCI6
         M2mRmWT0sgBAK4E9VNSfVY6B0g96dJrEPBqgQlQRI10DasZ7KIr7twUZY9/IidLra54d
         gmOrNuoZw8Tx8k5t6b92vxmv79JobzpezKgRWRA/7FngxQSpPor2WobcGaZIaknGBwSU
         n6mFoXn2Yy/znNVKR7JIFL3Q5DTx/m9g15wmNVAZ/6f7+f77Qwx1bOQxogQMZH/dnuZC
         ajNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531N7yO7YQtmf+3s9Jue5EOed8cxG0W6u/+kScWYyCl+iKUG+Q3a
	hjSxzRJawpD7eyYQgBPfrc0=
X-Google-Smtp-Source: ABdhPJwYupWLlqVrRNlyY1d5/SXh5cFdldO1hVfEXtGZ/g8Mes42ijehkf3PPpKv14cZQOAWkVmWyQ==
X-Received: by 2002:a05:6000:1685:b0:20f:e86d:2c96 with SMTP id y5-20020a056000168500b0020fe86d2c96mr20973174wrd.587.1653725603947;
        Sat, 28 May 2022 01:13:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1563:b0:210:11d0:6765 with SMTP id
 3-20020a056000156300b0021011d06765ls2683883wrz.3.gmail; Sat, 28 May 2022
 01:13:22 -0700 (PDT)
X-Received: by 2002:a5d:620f:0:b0:20c:c1ba:cf8e with SMTP id y15-20020a5d620f000000b0020cc1bacf8emr37293317wru.426.1653725602713;
        Sat, 28 May 2022 01:13:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653725602; cv=none;
        d=google.com; s=arc-20160816;
        b=VocM5bpz8hRMHMaVOkK33HrIW35BFmwqM6znem+8m6qD8/pz+otTUfPa1Ws2CygEh1
         g5I71vFETkVKbu3FKKe75rttDKwevP1mJyqXUFzvC3RcEWuHW3ACxdpoAcZ7/qmRXyFI
         D0dsYIo915NCJv2hV3/n5J1kvblV1AgxE44iwJvwVDog1vgXysqOVGrY+saqLeGw3uEK
         +ksJAAelJ8O21JsdCkd8Fq82Qwmow9I8RVfCh8w1VKlOwezN44m6rEWBp/55QPnE+bI5
         nj4rF8Ct49Nz3j3BencTNleJF6m65JonL8ld4Ww3N6pnxwvwYRpG4K1Ta1caLUy2qRA8
         cDVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=gWPQ3t1nl0lZcTbui0D6P7xO7AkRlleS/rhr3nFAC/4=;
        b=xZsEee+TrTjQemofRD+9o5yrOSsLuqSWfNj83ZfNSpZ1NYJn4TS0HVG9IesBphlUR0
         tD/H8oEw3MlIf3eGOo3VWYheqdRHCroXOaj8Upawopqf3nEZOZcs5iuOEqdXIXK3bjd1
         YKbk5jgGw2/EjRj5cQtwSe/hQchfbhTcFuq+UiYtoXah4qbliWUU4HFK7MC95pxCfg4g
         nEKs0rA164R/G25Auf8cmKThZGudmRXI/JmeOnjy4Sr9GDm0mOgQ6cTU6j3dUNLNRgfL
         jrkyO6w6lXS25L5qUZjwfpXxOdIahJqpHu8c8GTmRmcSujQsaZ5bJCux2FgPkZLVrQ6Q
         rddQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id f17-20020a05600c155100b0038ebc691b17si719227wmg.2.2022.05.28.01.13.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 28 May 2022 01:13:22 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.195;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id 1A76160006;
	Sat, 28 May 2022 08:13:18 +0000 (UTC)
Message-ID: <9684825e-036b-5d1d-acbf-91677e8f8f92@ghiti.fr>
Date: Sat, 28 May 2022 10:13:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
Content-Language: en-US
To: Atish Patra <atishp@atishpatra.org>,
 Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>,
 linux-riscv <linux-riscv@lists.infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
References: <00000000000038779505d5d8b372@google.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
 <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
 <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
 <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr>
 <CAOnJCULgP_-D3cY2m39k9N912Q55FS7X9JcrRVoUt0GC92tx7w@mail.gmail.com>
 <CAOnJCUKBWx+wEKaq8WOPC1j7jgn38iWcrTh4gO+FzfF-mhPkQg@mail.gmail.com>
 <CA+zEjCuK7NitU_tdjBo+qmhkN_qmH=NCryffb466E7ebVq0GDw@mail.gmail.com>
 <CAOnJCUL5=y2QEdJbkR6NtrrwDjw7KALnw2JEqMmXPnKTqEavDQ@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CAOnJCUL5=y2QEdJbkR6NtrrwDjw7KALnw2JEqMmXPnKTqEavDQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.195 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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


On 5/28/22 00:50, Atish Patra wrote:
> On Fri, May 27, 2022 at 12:33 AM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>> Hi Atish,
>>
>> On Thu, May 26, 2022 at 11:02 AM Atish Patra <atishp@atishpatra.org> wrote:
>>> On Thu, May 26, 2022 at 1:11 AM Atish Patra <atishp@atishpatra.org> wrote:
>>>> On Mon, May 16, 2022 at 5:06 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>>
>>>>> On 5/12/22 13:48, Dmitry Vyukov wrote:
>>>>>> On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
>>>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>>>> Hi Aleksandr,
>>>>>>>
>>>>>>> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>> Hi Alex,
>>>>>>>>
>>>>>>>> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>>>>>> Aleksandr,
>>>>>>>>>
>>>>>>>>> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>>>>>>> First, thank you for working on this.
>>>>>>>>>>
>>>>>>>>>> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>> If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
>>>>>>>>>>> to boot, but overwhelms me with tons of `virt_to_phys used for
>>>>>>>>>>> non-linear address:` errors.
>>>>>>>>>>>
>>>>>>>>>>> Like that
>>>>>>>>>>>
>>>>>>>>>>> [    2.701271] virt_to_phys used for non-linear address:
>>>>>>>>>>> 00000000b59e31b6 (0xffffffff806c2000)
>>>>>>>>>>> [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
>>>>>>>>>>> __virt_to_phys+0x7e/0x86
>>>>>>>>>>> [    2.702207] Modules linked in:
>>>>>>>>>>> [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
>>>>>>>>>>>     5.17.0-rc1 #1
>>>>>>>>>>> [    2.702806] Hardware name: riscv-virtio,qemu (DT)
>>>>>>>>>>> [    2.703051] epc : __virt_to_phys+0x7e/0x86
>>>>>>>>>>> [    2.703298]  ra : __virt_to_phys+0x7e/0x86
>>>>>>>>>>> [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
>>>>>>>>>>> ffff8f800021bde0
>>>>>>>>>>> [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
>>>>>>>>>>> ffffffff80eea56f
>>>>>>>>>>> [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
>>>>>>>>>>> ffff8f800021be00
>>>>>>>>>>> [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
>>>>>>>>>>> ffffffff80e723d8
>>>>>>>>>>> [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
>>>>>>>>>>> 0000000000000000
>>>>>>>>>>> [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
>>>>>>>>>>> ffffffffffffffff
>>>>>>>>>>> [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
>>>>>>>>>>> ffffffff806c2000
>>>>>>>>>>> [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
>>>>>>>>>>> 0000000000000001
>>>>>>>>>>> [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
>>>>>>>>>>> 00000000000000cc
>>>>>>>>>>> [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
>>>>>>>>>>> ffffffffffffffff
>>>>>>>>>>> [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
>>>>>>>>>>> [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
>>>>>>>>>>> cause: 0000000000000003
>>>>>>>>>>> [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
>>>>>>>>>>> [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
>>>>>>>>>>> [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
>>>>>>>>>>> [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
>>>>>>>>>>> [    2.710310] ---[ end trace 0000000000000000 ]---
>>>>>>>>>>>
>>>>>>>>>> I was able to reproduce this: the first one regarding init_zero_pfn is
>>>>>>>>>> legit but not wrong, I have to check when it was introduced and how to
>>>>>>>>>> fix this.
>>>>>>>>>> Regarding the huge batch that follows, at first sight, I would say
>>>>>>>>>> this is linked to my sv48 patchset but that does not seem important as
>>>>>>>>>> the address is a kernel mapping address so the use of virt_to_phys is
>>>>>>>>>> right.
>>>>>>>>>>
>>>>>>>>>>> On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>>> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>>>>>>>>>>>>> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>>>>> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>>>>>> Hi Alex,
>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>>>>>>>>>>>>> Hi Dmitry,
>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>> On 2/15/22 18:12, Dmitry Vyukov wrote:
>>>>>>>>>>>>>>>>> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
>>>>>>>>>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>>>>>>>>>>>>>>> Hi Aleksandr,
>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>>>>>>>>>> Hello,
>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>> syzbot has already not been able to fuzz its RISC-V instance for 97
>>>>>>>>>>>>>>>>>> That's a longtime, I'll take a look more regularly.
>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>> days now because the compiled kernel cannot boot. I bisected the issue
>>>>>>>>>>>>>>>>>>> to the following commit:
>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
>>>>>>>>>>>>>>>>>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>>>>>>>>>>>>>>>>>>> Date:   Fri Oct 29 06:59:27 2021 +0200
>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>>        riscv: Fix asan-stack clang build
>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
>>>>>>>>>>>>>>>>>>> enabled. In the previous message syzbot mentions
>>>>>>>>>>>>>>>>>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
>>>>>>>>>>>>>>>>>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
>>>>>>>>>>>>>>>>>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
>>>>>>>>>>>>>>>>>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
>>>>>>>>>>>>>>>>>>> For convenience, I also duplicate the .config file from the bot's
>>>>>>>>>>>>>>>>>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
>>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>>> Can someone with KASAN and RISC-V expertise please take a look?
>>>>>>>>>>>>>>>>>> I'll take a look at that today.
>>>>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>>>>> Thanks for reporting the issue,
>>>>>>>>>>>>>>>> I took a quick look, not enough to fix it but I know the issue comes
>>>>>>>>>>>>>>>> from the inline instrumentation, I have no problem with the outline
>>>>>>>>>>>>>>>> instrumentation. I need to find some cycles to work on this, my goal is
>>>>>>>>>>>>>>>> to fix this for 5.17.
>>>>>>>>>>>>>>> Thanks for the update!
>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>> Can you please share the .config with which you tested the outline
>>>>>>>>>>>>>>> instrumentation?
>>>>>>>>>>>>>>> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
>>>>>>>>>>>>>>> but it still does not boot :(
>>>>>>>>>>>>>>>
>>>>>>>>>>>>>>> Here's what I used:
>>>>>>>>>>>>>>> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
>>>>>>>>>>>>>> Update: it doesn't boot with that big config, but boots if I generate
>>>>>>>>>>>>>> a simple one with KASAN_OUTLINE:
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE
>>>>>>>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> And it indeed doesn't work if I use KASAN_INLINE.
>>>>>>>>>>>>> It may be an issue with code size. Full syzbot config + KASAN + KCOV
>>>>>>>>>>>>> produce hugely massive .text. It may be hitting some limitation in the
>>>>>>>>>>>>> bootloader/kernel bootstrap code.
>>>>>>>>>> I took a quick glance and it traps on a KASAN address that is not
>>>>>>>>>> mapped, either because it is too soon or because the mapping failed
>>>>>>>>>> somehow.
>>>>>>>>>>
>>>>>>>>>> I'll definitely dive into that tomorrow, sorry for being slow here and
>>>>>>>>>> thanks again for all your work, that helps a lot.
>>>>>>>>>>
>>>>>>>>>> Thanks,
>>>>>>>>>>
>>>>>>>>>> Alex
>>>>>>>>>>
>>>>>>>>>>>> I bisected the difference between the config we use on syzbot and the
>>>>>>>>>>>> simple one that was generated like I described above.
>>>>>>>>>>>> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
>>>>>>>>>>>>
>>>>>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
>>>>>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>>>>>
>>>>>>>>>>>> And the resulting kernel does not boot.
>>>>>>>>>>>> My env: the `riscv/fixes` branch, commit
>>>>>>>>>>>> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
>>>>>>>>> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
>>>>>>>>> maybe KASAN  + KCOV.
>>>>>>>>>
>>>>>>>>> With those small fixes, I was able to boot your large dotconfig with
>>>>>>>>> KASAN_OUTLINE, the inline version still fails, this is my next target
>>>>>>>>> :)
>>>>>>>>> I'll push that tomorrow!
>>>>>>>> Awesome, thank you very much!
>>>>>>>> Looking forward to finally seeing the instance run :)
>>>>>>> I sent a patchset which should fix your config with *outline* instrumentation.
>>>>>> Was this fix merged? The riscv instance still does not boot:
>>>>>> https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127
>>>>>
>>>>> Yes it has been in Linus tree since 5.18-rc1. I'll take a look at that
>>>>> this week.
>>>>>
>>>> Are you seeing this error or a different one ? I used the
>>>> syzkaller_defconfig from the patch below on v5.18.
>>>>
>>>> https://lore.kernel.org/all/20220419174952.699-1-palmer@rivosinc.com/
>>>>
>>>> [   15.076116][    T1] Mandatory Access Control activated.
>>>> [   15.158241][    T1] AppArmor: AppArmor Filesystem Enabled
>>>> [   16.150870][    T1] NET: Registered PF_INET protocol family
>>>> [   16.166167][    T1] IP idents hash table entries: 32768 (order: 6,
>>>> 262144 bytes, linear)
>>>> [   16.188727][    T1] Unable to handle kernel paging request at
>>>> virtual address ffebfffeffff2000
>>>> [   16.192727][    T1] Oops [#1]
>>>> [   16.193479][    T1] Modules linked in:
>>>> [   16.194687][    T1] CPU: 3 PID: 1 Comm: swapper/0 Not tainted
>>>> 5.18.0-00001-g37ac279268bf-dirty #9
>>>> [   16.196486][    T1] Hardware name: riscv-virtio,qemu (DT)
>>>> [   16.197836][    T1] epc : kasan_check_range+0x9e/0x14e
>>>> [   16.199104][    T1]  ra : memset+0x1e/0x4c
>>>> [   16.200091][    T1] epc : ffffffff804787e0 ra : ffffffff80478f30 sp
>>>> : ff600000073ffb70
>>>> [   16.201420][    T1]  gp : ffffffff85879e80 tp : ff600000073f0000 t0
>>>> : 7300000000000000
>>>> [   16.202762][    T1]  t1 : ffebfffeffff21ff t2 : 73746e6564692050 s0
>>>> : ff600000073ffba0
>>>> [   16.204047][    T1]  s1 : 0000000000001000 a0 : ffebfffeffff2200 a1
>>>> : 0000000000001000
>>>> [   16.205312][    T1]  a2 : 0000000000000001 a3 : ffffffff803a4f32 a4
>>>> : ff5ffffffff90000
>>>> [   16.206592][    T1]  a5 : ffebfffeffff2000 a6 : 0000004000000000 a7
>>>> : ff5ffffffff90fff
>>>> [   16.207865][    T1]  s2 : ff5ffffffff90000 s3 : 0000000000000000 s4
>>>> : ffffffff8467ea90
>>>> [   16.209134][    T1]  s5 : 0000000000000000 s6 : ff5ffffffff90000 s7
>>>> : 0000000000000000
>>>> [   16.210394][    T1]  s8 : 0000000000001000 s9 : ffffffff8587ca40
>>>> s10: 0000000000000004
>>>> [   16.211952][    T1]  s11: ffffffff858a03a0 t3 : 0000000000000000 t4
>>>> : 0000000000000040
>>>> [   16.213469][    T1]  t5 : ffebfffeffff2200 t6 : ff600000073ff738
>>>> [   16.214853][    T1] status: 0000000200000120 badaddr:
>>>> ffebfffeffff2000 cause: 000000000000000d
>>>> [   16.216910][    T1] Call Trace:
>>>> [   16.217816][    T1] [<ffffffff803a4f32>] pcpu_alloc+0x844/0x1254
>>>> [   16.219110][    T1] [<ffffffff803a59a0>] __alloc_percpu+0x28/0x34
>>>> [   16.220244][    T1] [<ffffffff8328824a>] ip_rt_init+0x17e/0x382
>>>> [   16.221606][    T1] [<ffffffff8328861c>] ip_init+0x18/0x30
>>>> [   16.222719][    T1] [<ffffffff8328a0ee>] inet_init+0x2a6/0x550
>>>> [   16.223863][    T1] [<ffffffff80003204>] do_one_initcall+0x130/0x7dc
>>>> [   16.225002][    T1] [<ffffffff83201fbc>] kernel_init_freeable+0x510/0x5b4
>>>> [   16.226273][    T1] [<ffffffff8319842a>] kernel_init+0x28/0x21c
>>>> [   16.227337][    T1] [<ffffffff80005818>] ret_from_exception+0x0/0x10
>>>> [   16.229910][    T1] ---[ end trace 0000000000000000 ]---
>>>> [   16.231880][    T1] Kernel panic - not syncing: Fatal exception
>>>>
>>>>
>>> Enabling CONFIG_KASAN_VMALLOC=y solves the issue and I am able to boot
>>> to the userspace.
>>> I have tried enabling/disabling CONFIG_VMAP_STACK as well. Both works fine.
>>>
>>> Looking at the ARM64 Kconfig, KASAN_VMALLOC is enabled if KASAN is enabled.
>>> This diff seems to work for me.
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index 00fd9c548f26..cbf0fe227c77 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -122,6 +122,7 @@ config RISCV
>>>          select TRACE_IRQFLAGS_SUPPORT
>>>          select UACCESS_MEMCPY if !MMU
>>>          select ZONE_DMA32 if 64BIT
>>> +       select KASAN_VMALLOC if KASAN
>>>
>>> I am not a kasan expert so I am not sure if this is the correct fix or
>>> just hides the real issue. pcpu_alloc seems to use vmalloc though.
>> When this type of thing happens, generally this is because of an error
>> in the kasan page table, I'll take a look this time, sorry I did not
>> do this before.
>>
> No worries. But the above diff is applicable anyways. Correct ?


Yes, we can use that until I fix the underlying issue.


>
>> Thanks for finding this,
>>
>> Alex
>>
>>>>> Thanks,
>>>>>
>>>>> Alex
>>>>>
>>>>>
>>>>>>> However, as you'll see in the cover letter, I have an issue with
>>>>>>> another KASAN config and if you can take a look at the stacktrace and
>>>>>>> see if that rings a bell, that would be great.
>>>>>>>
>>>>>>> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
>>>>>>>
>>>>>>> Alex
>>>>>>>
>>>>>>>
>>>>>>>> --
>>>>>>>> Best Regards,
>>>>>>>> Aleksandr
>>>>>>>>
>>>>>>>>> Thanks again,
>>>>>>>>>
>>>>>>>>> Alex
>>>>>>> --
>>>>>>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>>>>>>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>>>>>>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.
>>>>> _______________________________________________
>>>>> linux-riscv mailing list
>>>>> linux-riscv@lists.infradead.org
>>>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>>>
>>>>
>>>> --
>>>> Regards,
>>>> Atish
>>>
>>>
>>> --
>>> Regards,
>>> Atish
>
>
> --
> Regards,
> Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9684825e-036b-5d1d-acbf-91677e8f8f92%40ghiti.fr.
