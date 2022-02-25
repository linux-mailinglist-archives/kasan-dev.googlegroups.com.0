Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBY6X4OIAMGQEXWGD54Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CA4DF4C47DE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 15:46:59 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id v24-20020adf8b58000000b001eda5c5cf95sf957233wra.18
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 06:46:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645800419; cv=pass;
        d=google.com; s=arc-20160816;
        b=GQ6E3baU5ZHcq/KGYflvyzD+gT2+IC7Jg0Xeav/j2lIyqa2ZdKPAL8Mknp7UXtyzux
         BMPKdSRgHRscYodvHj6nq7y3aFT+F720b+BBBJT8KPWrsC+Rcy50WtHJV58hL02CaSKc
         H6WET9cRL2zh5sZ2f7H7afUyXOGsdDwJOXIDmfsNUWt6ir99Blld+9lOs5584RzC0iI8
         vJL94cUfK47yAe5TWBSVWf1kraPXnqK6Rzl+Y+flLHR5DxzG7jCYFb09vJXnE2xNl0YW
         QhBQVfBRjYcS4jOk8cJQPccKq6JIvnFejKv+eU4E2HkHf7Tik29Jwei4s/GdBNAPPXxS
         EKJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=95lhVOmpmRFM4B3wzLDyVvu0QhvUuBl7CUgSVX1ay/s=;
        b=0MpEkmXj9xQBVH2PmK/H8FigcEjPO+ey3IXpnmckHPcpvILGLlnG1ou6F5VkX9zQ2p
         v4iW+c/VBRh9gwc5q8fC3hVPD4JNcIeLqZaQ4RFtxk7WbnZZnCLxPj1JiVFja26BPaQf
         7cNEoGF7nSsmf0t15SfjqEgNlTijUxr6X6+77f2eZC1JhCVclsKo3E7I8lTwj4JHQ5cj
         lh1jd8IfcRnIzKo2/hmJXK2YexKTAbCHYLjoSpW6Ggd5PL1KFNTOhQPFiPWw15AgUiNd
         OYcnWQUdutojSOpt/2SgIXRMnzUyUl4vkLVrJ1xnzOI6tPS/XtXNQngecCwzSFCd/m9T
         lYhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a7TdkWuI;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=95lhVOmpmRFM4B3wzLDyVvu0QhvUuBl7CUgSVX1ay/s=;
        b=fDo0Mtsu+DesUzzucoFuC4kRfR7MOK7ZBa1bK7pPtr/sbzQIZLqqHUZBTlRhyE3Tdc
         b/NuRJRajdS/8mbnsyLisg50BIympJYVxXccSNV/8pgiudYEHxeBqg30IUVepZs6Yhra
         fNBQdtOiv1sS+RX1ZkDs4q5mcMZV0CVlYMWXD1g6MClG6lONpWKt9Zchx2c4h41BRtUI
         aCLkv24rQ3PBXtYl8TWyqdrvtO7Pp27vr0EvWYjtU8Q0dSDL7EHkrDNAvjBPbxAj/I12
         kg9fMA1GCvVEfO27sUS7GjcIAhVKUqjwYrbdL/RJs6yOSMFnLBS6Z/yasKnpBs7SX2AF
         +T2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=95lhVOmpmRFM4B3wzLDyVvu0QhvUuBl7CUgSVX1ay/s=;
        b=4TAZgTk/VmSFL1Nl0ri8893nKgEV5cuPRLOX9ZyIJhQqRvNW7G7+4wEZI1wK4kGqxh
         Aj3j40TWH3UQlCsCkVS1II0vZ41RSWEIHRSa/jiJMgpIu+BhnrqCI9YbE6u49i5Y3TOI
         5FiN9kbjP3QDEKZe2913qqXr659ErPIMPVgrtel6NjcLnNNANBt34OvZ2m9v31rvwVqw
         d0YEPntztIJdZ4SkqgZ6PLBXTD487RcPloIECCB86aASDNqakkZdaDX/V4kZd6sod32N
         Lk3VK9OC3sYq2oic3sqEN2XaID7FAkOmlKhNTYn+fRX+ENRPcVzthZEHpkSG6yPm7r08
         DUrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ejqdjqavVG5DyR0/kCw1+ewbj5HWBFhEvh7yVPkZwZMFuBtf2
	p0IVNOyIYiSTZEqt1LK+c3k=
X-Google-Smtp-Source: ABdhPJzHI1SZkdPSXTUpYiCE1zR9tnxV2AZ2G1jJ2TX1HECkar/uintisABg5B14JR2rpuZES243Fw==
X-Received: by 2002:a5d:6389:0:b0:1ed:bc35:cda4 with SMTP id p9-20020a5d6389000000b001edbc35cda4mr6630135wru.350.1645800419555;
        Fri, 25 Feb 2022 06:46:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d84:b0:37c:dec7:dbbf with SMTP id
 p4-20020a05600c1d8400b0037cdec7dbbfls674793wms.3.canary-gmail; Fri, 25 Feb
 2022 06:46:58 -0800 (PST)
X-Received: by 2002:adf:a4d7:0:b0:1ed:b579:eac7 with SMTP id h23-20020adfa4d7000000b001edb579eac7mr6196488wrb.623.1645800418551;
        Fri, 25 Feb 2022 06:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645800418; cv=none;
        d=google.com; s=arc-20160816;
        b=xPv2T/ZlL6TmXsPWVkpUyuhQNWXUwQKi19/+SbZTICohgBb9SfwKIsjqxTYThexsfc
         ILr/vzkOVZj2sDZZ54iXjT/i5yLh1n4haoTNoyDS1Vw2MX/7ABZ87q1j1dV8W6HD7H74
         KRJR+9w3ycPDTl+tCggVDyJ5cKNwNZDMRCqmM6qA1tDkJcJuYiV0ehNz3cczFW0fbpm6
         21iCuExVdvPvSn9L4yPq2d/8aeyyLX6LzxzZe/ZuJPI8b78PKmWXB59fTPfOuOe0IH0S
         6XB7g6+CWhYPKYK6Fr6ptuPF2hImoBmmnO1uRTcCslRoCmawHRYA/D4pINHFJ5oO62E7
         G+dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dOC9NztcOZs3DksWle8GHoaYwka1l2lDGqOy4HRLA/c=;
        b=ekNRe+Xoh/c3ssqkv+KyvNoWhaGZPIA96/AHBnMRiU1OuLGYwTYy308vZLsBO0MTp2
         PNEIjMaKbSIOoQRKPhM3B1wNKfmsvfzmXi8FqJB+Thdsc8/RLwu/0h2kjNKV9yFnCsxH
         yARBRXcn35y8RAjz1ni3/GHVLAVrDIODx7a6r0YIob3H4tbFjH9+ckBKOegXuq4qV7+x
         +OPbldyQWpNYVJfdCF8lJJe0ld9SsMDgHPpUZUwFnmW6jNiKdDBXCqSUH/LdEgNHOZvx
         wfsh+KZfR5A/ohbSPxZJPpo/v4z4zzBse+rY4ucOrmT+3Wszib3YtORtkSDzF5gSbSHo
         JOWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a7TdkWuI;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id t9-20020a5d42c9000000b001e9d3847897si130243wrr.8.2022.02.25.06.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 06:46:58 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 177323F33A
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 14:46:56 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id l24-20020a056402231800b00410f19a3103so2436850eda.5
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 06:46:56 -0800 (PST)
X-Received: by 2002:a05:6402:1681:b0:410:a467:833b with SMTP id a1-20020a056402168100b00410a467833bmr7405668edv.412.1645800415656;
        Fri, 25 Feb 2022 06:46:55 -0800 (PST)
X-Received: by 2002:a05:6402:1681:b0:410:a467:833b with SMTP id
 a1-20020a056402168100b00410a467833bmr7405642edv.412.1645800415364; Fri, 25
 Feb 2022 06:46:55 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
 <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
 <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
 <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com>
 <CA+zEjCsQPVYSV7CdhKnvjujXkMXuRQd=VPok1awb20xifYmidw@mail.gmail.com> <CAG_fn=VZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q@mail.gmail.com>
In-Reply-To: <CAG_fn=VZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 25 Feb 2022 15:46:44 +0100
Message-ID: <CA+zEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=a7TdkWuI;       spf=pass
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

On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.com> wro=
te:
>
>
>
> On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <alexandre.ghiti@canonica=
l.com> wrote:
>>
>> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.com> =
wrote:
>> >
>> >
>> >
>> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <alexandre.ghiti@canon=
ical.com> wrote:
>> >>
>> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
>> >> >
>> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
>> >> > <alexandre.ghiti@canonical.com> wrote:
>> >> > >
>> >> > > As reported by Aleksandr, syzbot riscv is broken since commit
>> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit a=
ctually
>> >> > > breaks KASAN_INLINE which is not fixed in this series, that will =
come later
>> >> > > when found.
>> >> > >
>> >> > > Nevertheless, this series fixes small things that made the syzbot
>> >> > > configuration + KASAN_OUTLINE fail to boot.
>> >> > >
>> >> > > Note that even though the config at [1] boots fine with this seri=
es, I
>> >> > > was not able to boot the small config at [2] which fails because
>> >> > > kasan_poison receives a really weird address 0x4075706301000000 (=
maybe a
>> >> > > kasan person could provide some hint about what happens below in
>> >> > > do_ctors -> __asan_register_globals):
>> >> >
>> >> > asan_register_globals is responsible for poisoning redzones around
>> >> > globals. As hinted by 'do_ctors', it calls constructors, and in thi=
s
>> >> > case a compiler-generated constructor that calls
>> >> > __asan_register_globals with metadata generated by the compiler. Th=
at
>> >> > metadata contains information about global variables. Note, these
>> >> > constructors are called on initial boot, but also every time a kern=
el
>> >> > module (that has globals) is loaded.
>> >> >
>> >> > It may also be a toolchain issue, but it's hard to say. If you're
>> >> > using GCC to test, try Clang (11 or later), and vice-versa.
>> >>
>> >> I tried 3 different gcc toolchains already, but that did not fix the
>> >> issue. The only thing that worked was setting asan-globals=3D0 in
>> >> scripts/Makefile.kasan, but ok, that's not a fix.
>> >> I tried to bisect this issue but our kasan implementation has been
>> >> broken quite a few times, so it failed.
>> >>
>> >> I keep digging!
>> >>
>> >
>> > The problem does not reproduce for me with GCC 11.2.0: kernels built w=
ith both [1] and [2] are bootable.
>>
>> Do you mean you reach userspace? Because my image boots too, and fails
>> at some point:
>>
>> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps
>> every 4398046511100ns
>> [    0.015847] Console: colour dummy device 80x25
>> [    0.016899] printk: console [tty0] enabled
>> [    0.020326] printk: bootconsole [ns16550a0] disabled
>>
>
> In my case, QEMU successfully boots to the login prompt.
> I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr shar=
ed with me (guess it was built according to this instruction: https://githu=
b.com/google/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_risc=
v64-kernel.md)
>

Nice thanks guys! I always use the latest opensbi and not the one that
is embedded in qemu, which is the only difference between your command
line (which works) and mine (which does not work). So the issue is
probably there, I really need to investigate that now.

That means I only need to fix KASAN_INLINE and we're good.

I imagine Palmer can add your Tested-by on the series then?

Thanks again!

Alex

>>
>> It traps here.
>>
>> > FWIW here is how I run them:
>> >
>> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
>> >   -device virtio-rng-pci -machine virt -device \
>> >   virtio-net-pci,netdev=3Dnet0 -netdev \
>> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -devi=
ce \
>> >   virtio-blk-device,drive=3Dhd0 -drive \
>> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
>> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append "root=3D/dev=
/vda
>> >   console=3DttyS0 earlyprintk=3Dserial"
>> >
>> >
>> >>
>> >> Thanks for the tips,
>> >>
>> >> Alex
>> >
>> >
>> >
>> > --
>> > Alexander Potapenko
>> > Software Engineer
>> >
>> > Google Germany GmbH
>> > Erika-Mann-Stra=C3=9Fe, 33
>> > 80636 M=C3=BCnchen
>> >
>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
>> > Registergericht und -nummer: Hamburg, HRB 86891
>> > Sitz der Gesellschaft: Hamburg
>> >
>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise e=
rhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes weite=
r, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich =
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.
>> >
>> >
>> >
>> > This e-mail is confidential. If you received this communication by mis=
take, please don't forward it to anyone else, please erase all copies and a=
ttachments, and please let me know that it has gone to the wrong person.
>>
>> --
>> You received this message because you are subscribed to the Google Group=
s "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send a=
n email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msg=
id/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPok1awb20xifYmidw%40mail=
.gmail.com.
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg
>
> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erha=
lten haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter, =
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen, dass die E-Mail an die falsche Person gesendet wurde.
>
>
>
> This e-mail is confidential. If you received this communication by mistak=
e, please don't forward it to anyone else, please erase all copies and atta=
chments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmai=
l.com.
