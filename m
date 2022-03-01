Return-Path: <kasan-dev+bncBCRKNY4WZECBB3FU7GIAMGQEZ45W77I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 786A44C91ED
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Mar 2022 18:39:57 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id c3-20020aca3503000000b002d48224d7e8sf7759122oia.4
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Mar 2022 09:39:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646156396; cv=pass;
        d=google.com; s=arc-20160816;
        b=umGC7V2RWrLQd6cvL7SAdrrFKRRNDgq9v/lUmTjYb2YW2N1YK0cPPnZmXV/mgi9v1Z
         CitZ/W85WvdipUkFGGWxP9etRnVFYMisfj33k/i/LTs/rdF7f0DoQig0M83J62SWdD8e
         eGEem4r2GQlFFef5D3jvEvxNY29zF0d2KEUPHsphbIArK/dRn36aOy8nAU09IYMb1+83
         6qUMF/cmYxEVTFYZRLitU8Er0vzYICQWeDYOuPELCAYqK3VR63NwLHKhA3OeoJavzpL+
         kzQE2xkWoX/beAp/tEnefQrmX6dsc4rs1BMVIjen63jyJLE+tDpIFo0Xs7PPRQP+ylnc
         V7gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=vGkmsrDcQli+rcnkfqriVO+DAH7fM7hH4h639jRrBtM=;
        b=IhaXa9UY6+nd+NBTa45Q+NNjQ27BZHHBQgb80xP6fwQ/7x18RXLgo27JtklTr+tZb2
         LEsf6ROun5chRSbGSMi3BQ9vhVnNH6wAoq9Lm0ELJ2cRtYKtpqkgpztNufhmuw2+PK3a
         KF96Ixj8GbVSy4n9At1hL8mHdmDo7wWrmxfW2S11FbAeQxNye86xsQJwCGtzphm06EY6
         KQ78rC7+jmOdov4vZjlx5tAynpILge9W+UM5Vn0dAnopGGq/mc+0Yh5KiPqtph7onp/C
         dhFKhmFW9PXNavsmTnIv0XXVKPKxYpB9bIxg62h/gq/itinBMhWzG9rHNEUqcaO12NW8
         UPRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=Qp4DFDQQ;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vGkmsrDcQli+rcnkfqriVO+DAH7fM7hH4h639jRrBtM=;
        b=qcsBBa+j5tga5R/kqeL+Yo+edW1KKUBzVbnab1/4wGxXVWNygCOYZUifv6fiKUnTZr
         +QlJVY7QYaqc4Vpm2JuuQvCYb6ywGxz+FFdpM/UpsHVHYqluoAtvX3QxFHCP52h0pH93
         IjWuUo/1jSdB1y+qU6KARP2cO1jjxkv9hWI1dpGcr6sTLPz4u9xH1RckUeOb/erJOoVP
         AT4byBXia/Dx1n6I9HYDWFOk/tY99Uhj+VrUVCFZL2+3l2Htiz3uBTjaF5/UsFqm2lhH
         4tKy6tSKLe4ZtjEK2xm16cv+UIG5lX0cX8p6w0W7eHsWlUj+a3k8n2uYFwgb/VYYOrCV
         JGkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vGkmsrDcQli+rcnkfqriVO+DAH7fM7hH4h639jRrBtM=;
        b=koomSbzDv4diudJavNQOAkgVxAL070PsM83VJde7SMRBRvVYgcdGij0wlMb1ABDaPd
         wD8kxpbQEf8g26hjj/gFK2ZCZmptUG5hQcuICWb9w8p8TyVPiM1+DSxVM4SngXT7QCBr
         cmc+b8+GZc0ESxLKoROcsaChvmvfx+uFebT0p0MHsvuK12weXWQI/uOg1RbwcIeJlIwU
         Lacymut1WpO4RjdvYCwVRhxfaDbd4RaVsMgX+t4QjL5bnTZyM+I+OTQrHUzeAl9bmc/s
         PNNz3sHhsfS/7p89kEMxZBkglCSTQWjr6Gr3XdvkkxGWKnDFbxjIJodH83MD9BPNCSAb
         7HDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532H4+DPKhfzzoUR13iya9j3/+V3l3bhUOmbewBN7ZXb492Q3WpC
	9DQ/4U2QVrip8s3OFmy2Vro=
X-Google-Smtp-Source: ABdhPJwSpXKGYCmGVxtziuHFm3Xbq+3GlOnF2iU9yQ/Z9R6vrBYR/a/RZFOyDTG0T1Hly5d2xWLzUQ==
X-Received: by 2002:a05:6870:2302:b0:d7:4f1f:b78b with SMTP id w2-20020a056870230200b000d74f1fb78bmr3431492oao.37.1646156396157;
        Tue, 01 Mar 2022 09:39:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2390:b0:2d4:a1bd:6b2e with SMTP id
 bp16-20020a056808239000b002d4a1bd6b2els4960205oib.10.gmail; Tue, 01 Mar 2022
 09:39:55 -0800 (PST)
X-Received: by 2002:a05:6808:13c6:b0:2cf:84a3:fdfa with SMTP id d6-20020a05680813c600b002cf84a3fdfamr14014545oiw.55.1646156395747;
        Tue, 01 Mar 2022 09:39:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646156395; cv=none;
        d=google.com; s=arc-20160816;
        b=vg1s2J34RSfnM4ke+kjEKsaQGV+h9qVk6tK6AitBYLu2YOhcYS1MaXW+9xw+7csuZe
         Xqoaot1iIudztFGi4Der6Mr042D8xBhQyuTv+mXPMHJz0OHLKJmQfDmGEbZyeScBy0WB
         mTm/jpW5Lk1q1epUH9fTpJ4iiJJfxhLTTdhQdqwqU+gQjQ25yra3CVVGbMIent7aBgZB
         o50EzRwcODSIls9NKWXllwkdEhM8hNSJGMnoY+vKl5x97THdmOv2+Bp44/zPx3xcZA+O
         hFbkwBqrms2kxgqe/tUKUhxT7DDwz3dxbMM0XPaOEB7Hw8ROnKBfRvkSvHW9SeU8r4R4
         Acbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=W4+GVkOQautzlTAwXMD1MQXzOa874amFJWoTUzo/RMw=;
        b=nnoYvTtEjfumc1TxC+Y9RqsJaYjXmQda7iLJkMkiqJIWPyH+q64/h3ToghhCG01Hvj
         Jw/mK2+U+7cqaFILtQg2wrHRzpzWFIDiRIPFwOXCDWzaV9X08Q2/4ojI08TIPrGavzGe
         qrBzX0mNJp+kqPUxvvcKT5UfeK7Eimy92z0IdEOkmz38sq32CVHKgy8PbJFPFiTKWpbN
         l6ILz8Nc7uzpGiX1tMbX38FcneyY0rXiYexWHyPnLNW+uZRW42EGBU8BLxCI5FLNifmk
         B38J1dUt9gJZk2wOWmQSjp99M2wRmAeKCeRbx5h66Q52HwhUxFaJ8E1DgWZanhr6E2D3
         5vww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=Qp4DFDQQ;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id r128-20020aca5d86000000b002d62816075bsi1826596oib.2.2022.03.01.09.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Mar 2022 09:39:55 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id t5so5844006pfg.4
        for <kasan-dev@googlegroups.com>; Tue, 01 Mar 2022 09:39:55 -0800 (PST)
X-Received: by 2002:a63:d1e:0:b0:372:c1cd:9e16 with SMTP id c30-20020a630d1e000000b00372c1cd9e16mr22534900pgl.421.1646156394767;
        Tue, 01 Mar 2022 09:39:54 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id p128-20020a622986000000b004e1366dd88esm16677413pfp.160.2022.03.01.09.39.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Mar 2022 09:39:54 -0800 (PST)
Date: Tue, 01 Mar 2022 09:39:54 -0800 (PST)
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
In-Reply-To: <CAG_fn=WTJF24TH6ENGD-3S0B_AV4=-39=2ry-uDguZ8Q7f=z=Q@mail.gmail.com>
CC: alexandre.ghiti@canonical.com, elver@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
  dvyukov@google.com, nogikh@google.com, nickhu@andestech.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: glider@google.com
Message-ID: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=Qp4DFDQQ;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote:
> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
> alexandre.ghiti@canonical.com> wrote:
>
>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.com>
>> wrote:
>> >
>> >
>> >
>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
>> alexandre.ghiti@canonical.com> wrote:
>> >>
>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.co=
m>
>> wrote:
>> >> >
>> >> >
>> >> >
>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
>> alexandre.ghiti@canonical.com> wrote:
>> >> >>
>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com>
>> wrote:
>> >> >> >
>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
>> >> >> > <alexandre.ghiti@canonical.com> wrote:
>> >> >> > >
>> >> >> > > As reported by Aleksandr, syzbot riscv is broken since commit
>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commi=
t
>> actually
>> >> >> > > breaks KASAN_INLINE which is not fixed in this series, that wi=
ll
>> come later
>> >> >> > > when found.
>> >> >> > >
>> >> >> > > Nevertheless, this series fixes small things that made the syz=
bot
>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
>> >> >> > >
>> >> >> > > Note that even though the config at [1] boots fine with this
>> series, I
>> >> >> > > was not able to boot the small config at [2] which fails becau=
se
>> >> >> > > kasan_poison receives a really weird address 0x407570630100000=
0
>> (maybe a
>> >> >> > > kasan person could provide some hint about what happens below =
in
>> >> >> > > do_ctors -> __asan_register_globals):
>> >> >> >
>> >> >> > asan_register_globals is responsible for poisoning redzones arou=
nd
>> >> >> > globals. As hinted by 'do_ctors', it calls constructors, and in
>> this
>> >> >> > case a compiler-generated constructor that calls
>> >> >> > __asan_register_globals with metadata generated by the compiler.
>> That
>> >> >> > metadata contains information about global variables. Note, thes=
e
>> >> >> > constructors are called on initial boot, but also every time a
>> kernel
>> >> >> > module (that has globals) is loaded.
>> >> >> >
>> >> >> > It may also be a toolchain issue, but it's hard to say. If you'r=
e
>> >> >> > using GCC to test, try Clang (11 or later), and vice-versa.
>> >> >>
>> >> >> I tried 3 different gcc toolchains already, but that did not fix t=
he
>> >> >> issue. The only thing that worked was setting asan-globals=3D0 in
>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
>> >> >> I tried to bisect this issue but our kasan implementation has been
>> >> >> broken quite a few times, so it failed.
>> >> >>
>> >> >> I keep digging!
>> >> >>
>> >> >
>> >> > The problem does not reproduce for me with GCC 11.2.0: kernels buil=
t
>> with both [1] and [2] are bootable.
>> >>
>> >> Do you mean you reach userspace? Because my image boots too, and fail=
s
>> >> at some point:
>> >>
>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps
>> >> every 4398046511100ns
>> >> [    0.015847] Console: colour dummy device 80x25
>> >> [    0.016899] printk: console [tty0] enabled
>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
>> >>
>> >
>> > In my case, QEMU successfully boots to the login prompt.
>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr
>> shared with me (guess it was built according to this instruction:
>> https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-h=
ost_qemu-vm_riscv64-kernel.md
>> )
>> >
>>
>> Nice thanks guys! I always use the latest opensbi and not the one that
>> is embedded in qemu, which is the only difference between your command
>> line (which works) and mine (which does not work). So the issue is
>> probably there, I really need to investigate that now.
>>
>> Great to hear that!
>
>
>> That means I only need to fix KASAN_INLINE and we're good.
>>
>> I imagine Palmer can add your Tested-by on the series then?
>>
> Sure :)

Do you mind actually posting that (i, the Tested-by tag)?  It's less=20
likely to get lost that way.  I intend on taking this into fixes ASAP,=20
my builds have blown up for some reason (I got bounced between machines,=20
so I'm blaming that) so I need to fix that first.

>
>>
>> Thanks again!
>>
>> Alex
>>
>> >>
>> >> It traps here.
>> >>
>> >> > FWIW here is how I run them:
>> >> >
>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
>> >> >   -device virtio-rng-pci -machine virt -device \
>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -d=
evice \
>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
>> "root=3D/dev/vda
>> >> >   console=3DttyS0 earlyprintk=3Dserial"
>> >> >
>> >> >
>> >> >>
>> >> >> Thanks for the tips,
>> >> >>
>> >> >> Alex
>> >> >
>> >> >
>> >> >
>> >> > --
>> >> > Alexander Potapenko
>> >> > Software Engineer
>> >> >
>> >> > Google Germany GmbH
>> >> > Erika-Mann-Stra=C3=9Fe, 33
>> >> > 80636 M=C3=BCnchen
>> >> >
>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
>> >> > Registergericht und -nummer: Hamburg, HRB 86891
>> >> > Sitz der Gesellschaft: Hamburg
>> >> >
>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweis=
e
>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen S=
ie mich bitte
>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
>> >> >
>> >> >
>> >> >
>> >> > This e-mail is confidential. If you received this communication by
>> mistake, please don't forward it to anyone else, please erase all copies
>> and attachments, and please let me know that it has gone to the wrong
>> person.
>> >>
>> >> --
>> >> You received this message because you are subscribed to the Google
>> Groups "kasan-dev" group.
>> >> To unsubscribe from this group and stop receiving emails from it, sen=
d
>> an email to kasan-dev+unsubscribe@googlegroups.com.
>> >> To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXk=
MXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
>> .
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
rhalten
>> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich =
bitte wissen,
>> dass die E-Mail an die falsche Person gesendet wurde.
>> >
>> >
>> >
>> > This e-mail is confidential. If you received this communication by
>> mistake, please don't forward it to anyone else, please erase all copies
>> and attachments, and please let me know that it has gone to the wrong
>> person.
>>
>> --
>> You received this message because you are subscribed to the Google Group=
s
>> "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send a=
n
>> email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit
>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96b=
zKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
>> .
>>
>
>
> --=20
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
lten
> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich b=
itte wissen,
> dass die E-Mail an die falsche Person gesendet wurde.
>
>
>
> This e-mail is confidential. If you received this communication by mistak=
e,
> please don't forward it to anyone else, please erase all copies and
> attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9%40palmer-mbp2014.
