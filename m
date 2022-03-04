Return-Path: <kasan-dev+bncBCRKNY4WZECBBJNDQ2IQMGQEYKKHMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA584CCC7B
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Mar 2022 05:12:23 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id k10-20020a056902070a00b0062469b00335sf6287569ybt.14
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Mar 2022 20:12:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646367142; cv=pass;
        d=google.com; s=arc-20160816;
        b=mW9wI91YRrtcSrEnCVEfzbjwm2KVppkEtHL/H1tCSvHFJUig68FDBU2BtTCKvxvbW/
         J444AzfocTranuqNDjOMRPdQ7szmJbuJLxVEu/AX7saS2+wH+AAIY6wBSFszeeiUyu9t
         oqOrPmrMrBkBPH4hyh+ZE5VrhPum8MMdkzoaNoasYdBmC4lm13ogZU9eOVQFOWrccp2D
         djbbZQW/hg9OkuEF61ETynNrAfVpFEyedVxgmfQWKC+2g+wpRsoSl3TdSRou0KjuJ8HW
         FAti4WPbystnuWs1RsnUxoQNKxmreSwiDUU+oTY5iybUQFT8NcaTllY2S0RusMIhDRgY
         g05A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :message-id:to:from:cc:in-reply-to:subject:date:mime-version:sender
         :dkim-signature;
        bh=CQY359AeWKnEe4wgZ7uvZnAsxOPURpXklf4E/Lnn5Og=;
        b=F9FTb/UZ/N4aWardOrIsGW3A/NqU5FNiPrkhB5JYRabjjUdO9RipzMjcLhZDneZtaV
         qhAHPOq5s69ivCT9b6ltXmtIcwEINcvXVGIqgMHDfHtcgOzSHfQbxfCGd4r9vvFRg1hA
         EK18qNtWF9zgyFmaV7meG6TWVoVN3a/Gg93Mfj8hSEH8ZtYwCyGIjQFdIWQSm3QWuD/g
         5DjHWXlz7DYCJbiTbo2wWKAsWbev46atpg6iIb77fPvjTFSwQwAei1iHkyQJ028v7EtT
         EvM/mP5DpF0eeVSl+urVcsgxn5Z7Hhec6DnnqLNIxYxB6d8yImXCGKSu8m9LGICG1oBX
         g41A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b="CkkA0/mo";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:subject:in-reply-to:cc:from:to:message-id
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CQY359AeWKnEe4wgZ7uvZnAsxOPURpXklf4E/Lnn5Og=;
        b=es7fNNJeAch22203CeUeoq98Zv8+nGALsCX2N9m2psX7+lISujM1hGP2DcQCZm0hbf
         dTEo5SgDzgzAqCwYq+BqqRvyufqX2p6z7zoOZMpeustymrSORNwgTG0bgtGldyyofnaJ
         VArlKY5u8YSeVi7Dz3J/Mad5Gqotgyrmv8yz1oV+4a+WnMzcS2D4KNNUDotzXtNmZY1U
         qqS6iDbbk/qH78g5YGlFENAsm0NAeaZq8pmZX9wUV/fdCLAdrnLjJ0pwhOsrM2Kh++ya
         kHWlKnNGfycvqyTWxBllo/bhzTbb8PMG086StTbA9wKwuuVXR3RsS/mJGN1y3K/IA89W
         fC9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:subject:in-reply-to:cc
         :from:to:message-id:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CQY359AeWKnEe4wgZ7uvZnAsxOPURpXklf4E/Lnn5Og=;
        b=A6b7xgXkbpDkENNJYArvQ9LgLQrbpPZUbk3F/4ce594SBZm2pFfit2Rt6DOBpHJyY9
         pi0zYAcxOB7+OPC36g8JpNH3DSYh2vXItoMOm23cZzOqmbuOma7AOSwKTu9B/1bEMIcq
         6G4WMlh8R3rTTnFsCCgXhWFH8k61kk0SXrwcOV7ecxV1kXOHqqr7b05AnHb+7WQLm2//
         99I74CEV3Bp7nIGJpY3KIRQY/Dk76NL5AyPnPDdyPD6b/u3+xXmAE7+2oMIhb9i4S20S
         CoFeVw7wZeD1hqt/cvcyOoXSnPgoC7+NIBaArYKcUjXUpLXnxwT5xjpNSzKRLXgvyLvd
         NCTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533S80/3NWcO5X6ql0Ym0DMto0u+fbC+yaLpeYMkKMz9CHaCSo/s
	+PvRvRWJjbFNYR9lN+shcoQ=
X-Google-Smtp-Source: ABdhPJzO5vQwfGOAtJlKXOe5DS0GRyYIZ8T31ZU1vo1UxGWbqKP06dSUy9FqI4AxRC33UoCXwj+B+A==
X-Received: by 2002:a25:ab8e:0:b0:628:7c01:de65 with SMTP id v14-20020a25ab8e000000b006287c01de65mr16199487ybi.524.1646367141984;
        Thu, 03 Mar 2022 20:12:21 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1106:b0:628:9969:5026 with SMTP id
 o6-20020a056902110600b0062899695026ls3203991ybu.4.gmail; Thu, 03 Mar 2022
 20:12:21 -0800 (PST)
X-Received: by 2002:a25:7407:0:b0:628:97bf:39e5 with SMTP id p7-20020a257407000000b0062897bf39e5mr12200052ybc.597.1646367141395;
        Thu, 03 Mar 2022 20:12:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646367141; cv=none;
        d=google.com; s=arc-20160816;
        b=hUr93Hpgqw+hV/iYOrM0z6nCAfQfKkvlgGQTEfNjzs0fe1N69Hmh/qoxgUNfM9XnBS
         s03f+kOPCWMP+0M7wgfHYg0GE1a6bDPK9zxawffuu/4GRpINj4U6fEzwdDRmfuu6aUxA
         V53NhtujjSMS32uebDNOXvTxtmrYLMjLzn30QF2W6iZG+dDK2fL5EFIN24TztM4oBRLv
         uMRNA9oqbDrHyolevkcJX1+JlazNOCMi/frM6c4+sLGS/Ctpm7b+sqhHWEZ5Jh2qowa9
         /3xnuVAJ4zu9wMEF9JYZFLgMfSx8KmrTMyZ+sbEp2196z6085ZIC+cwc1QIIURxZYNNq
         OxWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:to:from:cc:in-reply-to:subject:date:dkim-signature;
        bh=+d5M5Lb/1zkG36m0uGpnpPesPt+KsHy1eBe0GK/XMwc=;
        b=sZ5CAlTDCXn5Nznd2CtfIHRfKbxteKB4GrLsma3y0ZRMan024XeCL0RRXf2mV1FNxp
         iwiZt2iQPsbdl9GoFnw4MutHVHb+r727nVEehhmXKUt53Jdc8F0FrbnZqq8D8ZzZH8of
         8KIqjxuX1x9qDZyPM0PJ3FlTfqwzgBbrkUOSW0msMU8SLMvH0fNOsOHc4GpKf80EMpy6
         VNMx6IwNiTv6C1E2f3H/OAIlMjA2iz6oxoNnEN+d4vN47Z+mWRY0CsfHujY/KHhABzFm
         e+2WIKPWqDcyCvG30CCzzMweqlVQX3jJgGzNMjZ83Axr9G0TwVBmOjfyNss7J8kvPU+H
         12vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b="CkkA0/mo";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id bg7-20020a05690c030700b002d7da374fa6si271351ywb.2.2022.03.03.20.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Mar 2022 20:12:21 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id g7-20020a17090a708700b001bb78857ccdso9644200pjk.1
        for <kasan-dev@googlegroups.com>; Thu, 03 Mar 2022 20:12:21 -0800 (PST)
X-Received: by 2002:a17:90a:7385:b0:1b9:6492:c107 with SMTP id j5-20020a17090a738500b001b96492c107mr8682494pjg.103.1646367140345;
        Thu, 03 Mar 2022 20:12:20 -0800 (PST)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id z7-20020a056a00240700b004e1cde37bc1sm4075952pfh.84.2022.03.03.20.12.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Mar 2022 20:12:19 -0800 (PST)
Date: Thu, 03 Mar 2022 20:12:19 -0800 (PST)
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
In-Reply-To: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014>
CC: elver@google.com, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, andreyknvl@gmail.com, dvyukov@google.com,
  nogikh@google.com, nickhu@andestech.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: glider@google.com, alexandre.ghiti@canonical.com
Message-ID: <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9>
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b="CkkA0/mo";       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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

On Tue, 01 Mar 2022 09:39:54 PST (-0800), Palmer Dabbelt wrote:
> On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote:
>> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
>> alexandre.ghiti@canonical.com> wrote:
>>
>>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.com>
>>> wrote:
>>> >
>>> >
>>> >
>>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
>>> alexandre.ghiti@canonical.com> wrote:
>>> >>
>>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.c=
om>
>>> wrote:
>>> >> >
>>> >> >
>>> >> >
>>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
>>> alexandre.ghiti@canonical.com> wrote:
>>> >> >>
>>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com>
>>> wrote:
>>> >> >> >
>>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
>>> >> >> > <alexandre.ghiti@canonical.com> wrote:
>>> >> >> > >
>>> >> >> > > As reported by Aleksandr, syzbot riscv is broken since commit
>>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This comm=
it
>>> actually
>>> >> >> > > breaks KASAN_INLINE which is not fixed in this series, that w=
ill
>>> come later
>>> >> >> > > when found.
>>> >> >> > >
>>> >> >> > > Nevertheless, this series fixes small things that made the sy=
zbot
>>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
>>> >> >> > >
>>> >> >> > > Note that even though the config at [1] boots fine with this
>>> series, I
>>> >> >> > > was not able to boot the small config at [2] which fails beca=
use
>>> >> >> > > kasan_poison receives a really weird address 0x40757063010000=
00
>>> (maybe a
>>> >> >> > > kasan person could provide some hint about what happens below=
 in
>>> >> >> > > do_ctors -> __asan_register_globals):
>>> >> >> >
>>> >> >> > asan_register_globals is responsible for poisoning redzones aro=
und
>>> >> >> > globals. As hinted by 'do_ctors', it calls constructors, and in
>>> this
>>> >> >> > case a compiler-generated constructor that calls
>>> >> >> > __asan_register_globals with metadata generated by the compiler=
.
>>> That
>>> >> >> > metadata contains information about global variables. Note, the=
se
>>> >> >> > constructors are called on initial boot, but also every time a
>>> kernel
>>> >> >> > module (that has globals) is loaded.
>>> >> >> >
>>> >> >> > It may also be a toolchain issue, but it's hard to say. If you'=
re
>>> >> >> > using GCC to test, try Clang (11 or later), and vice-versa.
>>> >> >>
>>> >> >> I tried 3 different gcc toolchains already, but that did not fix =
the
>>> >> >> issue. The only thing that worked was setting asan-globals=3D0 in
>>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
>>> >> >> I tried to bisect this issue but our kasan implementation has bee=
n
>>> >> >> broken quite a few times, so it failed.
>>> >> >>
>>> >> >> I keep digging!
>>> >> >>
>>> >> >
>>> >> > The problem does not reproduce for me with GCC 11.2.0: kernels bui=
lt
>>> with both [1] and [2] are bootable.
>>> >>
>>> >> Do you mean you reach userspace? Because my image boots too, and fai=
ls
>>> >> at some point:
>>> >>
>>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wrap=
s
>>> >> every 4398046511100ns
>>> >> [    0.015847] Console: colour dummy device 80x25
>>> >> [    0.016899] printk: console [tty0] enabled
>>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
>>> >>
>>> >
>>> > In my case, QEMU successfully boots to the login prompt.
>>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr
>>> shared with me (guess it was built according to this instruction:
>>> https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-=
host_qemu-vm_riscv64-kernel.md
>>> )
>>> >
>>>
>>> Nice thanks guys! I always use the latest opensbi and not the one that
>>> is embedded in qemu, which is the only difference between your command
>>> line (which works) and mine (which does not work). So the issue is
>>> probably there, I really need to investigate that now.
>>>
>>> Great to hear that!
>>
>>
>>> That means I only need to fix KASAN_INLINE and we're good.
>>>
>>> I imagine Palmer can add your Tested-by on the series then?
>>>
>> Sure :)
>
> Do you mind actually posting that (i, the Tested-by tag)?  It's less
> likely to get lost that way.  I intend on taking this into fixes ASAP,
> my builds have blown up for some reason (I got bounced between machines,
> so I'm blaming that) so I need to fix that first.

This is on fixes (with a "Tested-by: Alexander Potapenko=20
<glider@google.com>"), along with some trivial commit message fixes.

Thanks!

>
>>
>>>
>>> Thanks again!
>>>
>>> Alex
>>>
>>> >>
>>> >> It traps here.
>>> >>
>>> >> > FWIW here is how I run them:
>>> >> >
>>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
>>> >> >   -device virtio-rng-pci -machine virt -device \
>>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
>>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -=
device \
>>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
>>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
>>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
>>> "root=3D/dev/vda
>>> >> >   console=3DttyS0 earlyprintk=3Dserial"
>>> >> >
>>> >> >
>>> >> >>
>>> >> >> Thanks for the tips,
>>> >> >>
>>> >> >> Alex
>>> >> >
>>> >> >
>>> >> >
>>> >> > --
>>> >> > Alexander Potapenko
>>> >> > Software Engineer
>>> >> >
>>> >> > Google Germany GmbH
>>> >> > Erika-Mann-Stra=C3=9Fe, 33
>>> >> > 80636 M=C3=BCnchen
>>> >> >
>>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
>>> >> > Registergericht und -nummer: Hamburg, HRB 86891
>>> >> > Sitz der Gesellschaft: Hamburg
>>> >> >
>>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherwei=
se
>>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
>>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen =
Sie mich bitte
>>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
>>> >> >
>>> >> >
>>> >> >
>>> >> > This e-mail is confidential. If you received this communication by
>>> mistake, please don't forward it to anyone else, please erase all copie=
s
>>> and attachments, and please let me know that it has gone to the wrong
>>> person.
>>> >>
>>> >> --
>>> >> You received this message because you are subscribed to the Google
>>> Groups "kasan-dev" group.
>>> >> To unsubscribe from this group and stop receiving emails from it, se=
nd
>>> an email to kasan-dev+unsubscribe@googlegroups.com.
>>> >> To view this discussion on the web visit
>>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujX=
kMXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
>>> .
>>> >
>>> >
>>> >
>>> > --
>>> > Alexander Potapenko
>>> > Software Engineer
>>> >
>>> > Google Germany GmbH
>>> > Erika-Mann-Stra=C3=9Fe, 33
>>> > 80636 M=C3=BCnchen
>>> >
>>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
>>> > Registergericht und -nummer: Hamburg, HRB 86891
>>> > Sitz der Gesellschaft: Hamburg
>>> >
>>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise =
erhalten
>>> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
>>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich=
 bitte wissen,
>>> dass die E-Mail an die falsche Person gesendet wurde.
>>> >
>>> >
>>> >
>>> > This e-mail is confidential. If you received this communication by
>>> mistake, please don't forward it to anyone else, please erase all copie=
s
>>> and attachments, and please let me know that it has gone to the wrong
>>> person.
>>>
>>> --
>>> You received this message because you are subscribed to the Google Grou=
ps
>>> "kasan-dev" group.
>>> To unsubscribe from this group and stop receiving emails from it, send =
an
>>> email to kasan-dev+unsubscribe@googlegroups.com.
>>> To view this discussion on the web visit
>>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96=
bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
>>> .
>>>
>>
>>
>> --
>> Alexander Potapenko
>> Software Engineer
>>
>> Google Germany GmbH
>> Erika-Mann-Stra=C3=9Fe, 33
>> 80636 M=C3=BCnchen
>>
>> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
>> Registergericht und -nummer: Hamburg, HRB 86891
>> Sitz der Gesellschaft: Hamburg
>>
>> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erh=
alten
>> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich =
bitte wissen,
>> dass die E-Mail an die falsche Person gesendet wurde.
>>
>>
>>
>> This e-mail is confidential. If you received this communication by mista=
ke,
>> please don't forward it to anyone else, please erase all copies and
>> attachments, and please let me know that it has gone to the wrong person=
.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74%40palmer-ri-x1c9.
