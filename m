Return-Path: <kasan-dev+bncBC7PZX4C3UKBBJP4RCKAMGQES6WF7OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C39335283D3
	for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 14:05:58 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf6366974lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 05:05:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652702758; cv=pass;
        d=google.com; s=arc-20160816;
        b=dPpjz5MVIcpB8Qa22RtqqzkLBybw4dMjMZw/5X9K/Aj+N/ztah2kjJWYqKKdaFXFW3
         rCVYkB2AUk8Gqp9zV1OSCWmuJF90HgLeuZ7lrRPdXJI3MPxkb4FH5llYFW65/XH+ullB
         Os9aakV5KKmZAWShXZ7OXPV7WtRwQf9QpaiUJsY7ipXasch6jcSd/oFO/T0hWfteBrZU
         iCysvzQAj9kBSPcbQ/uaX8jkOlGW8Ulvt3Wa0Zg5cnsDrWitnUiEYC/zq1GT4ihUrfWL
         HQotivxuhD1czYo6yIof9lwvb9uu5xatuGRuidKcl/w77QqSE0JztVoZWW5BklsmUPtl
         0TPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=t9nrsoWk00Q666o8tbxLjlq2rxOxAAtT/fr05sKa00A=;
        b=tJtfqnvRmbbSn5jn5udAsycdiM2rzAhQkJJVnKWnSINvN3jPMiIURBMyb7CiUK9wgh
         Yw9c+o29JWUBQPhfeuQOhlcA5mrT1KbOj+fQShKkx7a9hXVtnlD5Sw66bEbD2cw9Z+LH
         Kzk3ZUb1yklggOgvu/4e3NPb1zDLxBbZTAr4Fzfl7yYKRpikn6BbiieYSr0mcEr0AmvH
         hY/FvJkYocurM3HFQNUcYwnI8QQANbzlNUNFixO2XvhXdFkKNlqkFkwv4glSdtHCmSjj
         I/aP5k6/8jhyI9rP7xDrA8exZIj4krzKJZ3g8QSUkP/VqBBjjFn+noXs1p5zesdJalGZ
         XKGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::223 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t9nrsoWk00Q666o8tbxLjlq2rxOxAAtT/fr05sKa00A=;
        b=d7VtdJnRBJQ7oOD8vR1J1wqlR2x09Dat4fJTNge4P1+lcx7qiO/mSshiCcaQlPSeUv
         C+WLwLaBT2ZOI+GkMj1IHgm6jwUcYM8fNHxJUWPIb5AdskWAWletKetkHGdzGKYahucq
         LWY1n2uQqwPaj6SighrLOxfVnH2Znl2zFvQKUC/PQmjF6zeesmaLNKYErXHo8wtjzXLL
         3/cBM9AACHv0inNF8uCKYbiTvhAvCuMKzF/AgSEQbloXfFtu07LVGKlXX40PbtwCDXcY
         QRX8W2WZn2hOsGGLbczyXd7bCgBW2tdr9eZxzYJEBNozsCwCIiddZ9OQmro7j7PWKZxh
         cKwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=t9nrsoWk00Q666o8tbxLjlq2rxOxAAtT/fr05sKa00A=;
        b=dSNlmYX/yA8kVfs/FvhSndQdNTDHzqIXd3QhfIhswvRp3wXrlGeibb42aFI4TDeh+u
         Du7tDPJGDK+SqJK6xXHYNVzv8VSCe1NX7iCxyu70dfhpiA0onIUmRrmAWqtGp4t/xeHW
         7qC4JlTVUWw4kcaK+pLdMgbdRuV6CFoqukjhDQUkClQ98ppobpRLaGw2FBONveIUkMwv
         ztXwyVDEHbRXo94PGq5E/QcHdPwH/DhkkSyseV+T/pvnvQ6ZEWt6z9tF92eqdMg6y0Tb
         x5SwGO3ZRZkCd863S3vkS6lP+76Is3am6VrnRSThcQuaXV54i+9HKiksYIuOyjkpq6hs
         0MrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QjMRFDRgKuSzH+tt+GCvPckvQDldew2K9yKrVdIGc6Hq2TQm5
	uhgACfgoDToUT4BqtUp+BbE=
X-Google-Smtp-Source: ABdhPJwys1QyvpqPYowdJsI+FX13bjDIh31ytffdWw5N6NOvD413oQUdybJD1ZcSvesvpA8oIXtd7w==
X-Received: by 2002:a05:6512:150f:b0:45d:ccac:c43c with SMTP id bq15-20020a056512150f00b0045dccacc43cmr13492593lfb.604.1652702757987;
        Mon, 16 May 2022 05:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls8709653lfu.0.gmail; Mon, 16 May 2022
 05:05:56 -0700 (PDT)
X-Received: by 2002:a05:6512:108a:b0:473:bdb1:1b28 with SMTP id j10-20020a056512108a00b00473bdb11b28mr12541434lfg.509.1652702756414;
        Mon, 16 May 2022 05:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652702756; cv=none;
        d=google.com; s=arc-20160816;
        b=xuju0QFaKv/WX67y2OlXGXG63LGdk2qPf5J5vp2QHgJvLS26w6Uuun4FiMHTq7wxTh
         rvQ4jP5CJZE0Vt9lZxuQhAqNov6TNTHkuww+QH37JBobWsGnWFfpqpL3jrq57/7LfsNw
         ITukpItzrh2wWKMgMo8dmJNW0qrk6lAuCfyYLL8GIfNKbYx1+ZoBstaVzIRP4y8aRYUq
         1tpiFYn1gjZQo0YvM4tPu4Vj521tN8SVWT+VJznYs4DglbYNRT3YWS2uHfr2NGaQxAhd
         DyZAQ1ZEa/XQ2pMwvKAF8oEDHVt+/W+eWOEZsOpjXI27HNfcG/gZHLq4su9UnIKC4Fd4
         QMqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=HM9OmrIYt4KZVAUF/LgZXFBhNT8wq4MdfyogYKs/OFg=;
        b=eaCRVG48evEzcYtD/bB+y7u51TbG9vQSyX0gKnnAwtMnrhnBVwWtLmdwdBUJNc2tR/
         jP0u2rol/sU0YlYXvF3hGrJ/g1O4FzBeUV9w7M+vPoc7uftcMBdaSKhT6hUvjuo9ZIqJ
         XiV2EFa0OcFEwwspNQ/xgzYGxtNIaBl1WX5q4dPCLNs2Q8Wst0oSNpUcxKt9+YqLIMsB
         6FG17qLmoPHaMcPSaakyMczvt2TVrmZLIur2xk/k2nY5OAnQ0le9Hou9qHy8DLNMf6q2
         PdNrJOBRUpPayUvN3kJv4E4uHLwF1EIqcphPTbn59EkTGtTZCeLVgcyoBIJs2CYAdOkf
         wVdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::223 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [2001:4b98:dc4:8::223])
        by gmr-mx.google.com with ESMTPS id j10-20020a05651231ca00b0047193d0273asi436200lfe.8.2022.05.16.05.05.56
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 16 May 2022 05:05:56 -0700 (PDT)
Received-SPF: neutral (google.com: 2001:4b98:dc4:8::223 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=2001:4b98:dc4:8::223;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id A5E1C60008;
	Mon, 16 May 2022 12:05:53 +0000 (UTC)
Message-ID: <5e702296-9ce0-f1e6-dae8-cc719bc040b9@ghiti.fr>
Date: Mon, 16 May 2022 14:05:53 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>,
 Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, linux-riscv@lists.infradead.org,
 kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
References: <00000000000038779505d5d8b372@google.com>
 <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr>
 <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com>
 <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
 <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2001:4b98:dc4:8::223 is neither permitted nor denied by best
 guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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


On 5/12/22 13:48, Dmitry Vyukov wrote:
> On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>> Hi Aleksandr,
>>
>> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>> Hi Alex,
>>>
>>> On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
>>> <alexandre.ghiti@canonical.com> wrote:
>>>> Aleksandr,
>>>>
>>>> On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>> First, thank you for working on this.
>>>>>
>>>>> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>> If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
>>>>>> to boot, but overwhelms me with tons of `virt_to_phys used for
>>>>>> non-linear address:` errors.
>>>>>>
>>>>>> Like that
>>>>>>
>>>>>> [    2.701271] virt_to_phys used for non-linear address:
>>>>>> 00000000b59e31b6 (0xffffffff806c2000)
>>>>>> [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
>>>>>> __virt_to_phys+0x7e/0x86
>>>>>> [    2.702207] Modules linked in:
>>>>>> [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
>>>>>>    5.17.0-rc1 #1
>>>>>> [    2.702806] Hardware name: riscv-virtio,qemu (DT)
>>>>>> [    2.703051] epc : __virt_to_phys+0x7e/0x86
>>>>>> [    2.703298]  ra : __virt_to_phys+0x7e/0x86
>>>>>> [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
>>>>>> ffff8f800021bde0
>>>>>> [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
>>>>>> ffffffff80eea56f
>>>>>> [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
>>>>>> ffff8f800021be00
>>>>>> [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
>>>>>> ffffffff80e723d8
>>>>>> [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
>>>>>> 0000000000000000
>>>>>> [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
>>>>>> ffffffffffffffff
>>>>>> [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
>>>>>> ffffffff806c2000
>>>>>> [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
>>>>>> 0000000000000001
>>>>>> [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
>>>>>> 00000000000000cc
>>>>>> [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
>>>>>> ffffffffffffffff
>>>>>> [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
>>>>>> [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
>>>>>> cause: 0000000000000003
>>>>>> [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
>>>>>> [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
>>>>>> [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
>>>>>> [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
>>>>>> [    2.710310] ---[ end trace 0000000000000000 ]---
>>>>>>
>>>>> I was able to reproduce this: the first one regarding init_zero_pfn is
>>>>> legit but not wrong, I have to check when it was introduced and how to
>>>>> fix this.
>>>>> Regarding the huge batch that follows, at first sight, I would say
>>>>> this is linked to my sv48 patchset but that does not seem important as
>>>>> the address is a kernel mapping address so the use of virt_to_phys is
>>>>> right.
>>>>>
>>>>>> On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>>>>>>>> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>> Hi Alex,
>>>>>>>>>>
>>>>>>>>>> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
>>>>>>>>>>> Hi Dmitry,
>>>>>>>>>>>
>>>>>>>>>>> On 2/15/22 18:12, Dmitry Vyukov wrote:
>>>>>>>>>>>> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
>>>>>>>>>>>> <alexandre.ghiti@canonical.com> wrote:
>>>>>>>>>>>>> Hi Aleksandr,
>>>>>>>>>>>>>
>>>>>>>>>>>>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>>>>>>>>>>>>> Hello,
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> syzbot has already not been able to fuzz its RISC-V instance for 97
>>>>>>>>>>>>> That's a longtime, I'll take a look more regularly.
>>>>>>>>>>>>>
>>>>>>>>>>>>>> days now because the compiled kernel cannot boot. I bisected the issue
>>>>>>>>>>>>>> to the following commit:
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
>>>>>>>>>>>>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>>>>>>>>>>>>>> Date:   Fri Oct 29 06:59:27 2021 +0200
>>>>>>>>>>>>>>
>>>>>>>>>>>>>>       riscv: Fix asan-stack clang build
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
>>>>>>>>>>>>>> enabled. In the previous message syzbot mentions
>>>>>>>>>>>>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
>>>>>>>>>>>>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
>>>>>>>>>>>>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
>>>>>>>>>>>>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
>>>>>>>>>>>>>> For convenience, I also duplicate the .config file from the bot's
>>>>>>>>>>>>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
>>>>>>>>>>>>>>
>>>>>>>>>>>>>> Can someone with KASAN and RISC-V expertise please take a look?
>>>>>>>>>>>>> I'll take a look at that today.
>>>>>>>>>>>>>
>>>>>>>>>>>>> Thanks for reporting the issue,
>>>>>>>>>>> I took a quick look, not enough to fix it but I know the issue comes
>>>>>>>>>>> from the inline instrumentation, I have no problem with the outline
>>>>>>>>>>> instrumentation. I need to find some cycles to work on this, my goal is
>>>>>>>>>>> to fix this for 5.17.
>>>>>>>>>> Thanks for the update!
>>>>>>>>>>
>>>>>>>>>> Can you please share the .config with which you tested the outline
>>>>>>>>>> instrumentation?
>>>>>>>>>> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
>>>>>>>>>> but it still does not boot :(
>>>>>>>>>>
>>>>>>>>>> Here's what I used:
>>>>>>>>>> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
>>>>>>>>> Update: it doesn't boot with that big config, but boots if I generate
>>>>>>>>> a simple one with KASAN_OUTLINE:
>>>>>>>>>
>>>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE
>>>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>>>
>>>>>>>>> And it indeed doesn't work if I use KASAN_INLINE.
>>>>>>>> It may be an issue with code size. Full syzbot config + KASAN + KCOV
>>>>>>>> produce hugely massive .text. It may be hitting some limitation in the
>>>>>>>> bootloader/kernel bootstrap code.
>>>>> I took a quick glance and it traps on a KASAN address that is not
>>>>> mapped, either because it is too soon or because the mapping failed
>>>>> somehow.
>>>>>
>>>>> I'll definitely dive into that tomorrow, sorry for being slow here and
>>>>> thanks again for all your work, that helps a lot.
>>>>>
>>>>> Thanks,
>>>>>
>>>>> Alex
>>>>>
>>>>>>> I bisected the difference between the config we use on syzbot and the
>>>>>>> simple one that was generated like I described above.
>>>>>>> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
>>>>>>>
>>>>>>> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
>>>>>>> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>>>>>>>
>>>>>>> And the resulting kernel does not boot.
>>>>>>> My env: the `riscv/fixes` branch, commit
>>>>>>> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
>>>> I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
>>>> maybe KASAN  + KCOV.
>>>>
>>>> With those small fixes, I was able to boot your large dotconfig with
>>>> KASAN_OUTLINE, the inline version still fails, this is my next target
>>>> :)
>>>> I'll push that tomorrow!
>>> Awesome, thank you very much!
>>> Looking forward to finally seeing the instance run :)
>> I sent a patchset which should fix your config with *outline* instrumentation.
> Was this fix merged? The riscv instance still does not boot:
> https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127


Yes it has been in Linus tree since 5.18-rc1. I'll take a look at that 
this week.

Thanks,

Alex


>
>> However, as you'll see in the cover letter, I have an issue with
>> another KASAN config and if you can take a look at the stacktrace and
>> see if that rings a bell, that would be great.
>>
>> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
>>
>> Alex
>>
>>
>>> --
>>> Best Regards,
>>> Aleksandr
>>>
>>>> Thanks again,
>>>>
>>>> Alex
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e702296-9ce0-f1e6-dae8-cc719bc040b9%40ghiti.fr.
