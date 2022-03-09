Return-Path: <kasan-dev+bncBCXKTJ63SAARBW4KUKIQMGQECCKH3AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 912BA4D2D53
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 11:45:48 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id t26-20020ac8739a000000b002e06aa03d4csf1319224qtp.13
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 02:45:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646822747; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ns7RSfpvMR8Uvio2Lr7ViYx2DYt/oaffPlR6LwysonUAqrsrJJOS+F16ZbJ+TIseSG
         wYl46CpFt2Zov0AqxG1J0DKLtDoRZyRKC3aJOiCPc3Mb5ChOWDhD5YoCSIFZbrZg4vgd
         Iu0fraZn+0SXsKyvWLFaHCFNuHE6jxkquBj8gintWU8pS9uvs+DINl4kpLnUDNdnfUi1
         5pnEjdJlr9ss/37QwUSK1VVsTbcprdi42TsmfVFPgLwvhzSHIRgOD4h0fBCiusyUQBBc
         XlZ3MvLZE4MKW3CFDaxKq23Q5whAXtsetOYlV4Z0gNYJQWJvfpvZLh8PR3aWcZA6KKNl
         o6RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S+x7sZFZRdNnMOz3MZzAsWMRp5EJktfeV/nodz5YZP4=;
        b=P6TdELf4hoY3iJLrxcVEUi/1KIn4Zjepa0xmHS+SkJXWToI9j/z28KFwy7jYssKpEB
         CSMK8sadj4bTruaYstFSUabPVbpCmLqk62FKB/ciz4X/FNpj8fU7QXcKCwuakaAg7G0c
         g/ZAZOvusltO1airnQ2zfXX/6bVQ7OI9nvrLUMTBccT3hIhdq4wXsiALQgZibxLWG8wj
         RtgGPD4D/sYGCmoRIEaV75DLNmxkQJd1a+kEmt/I3FRTc7pSRTSR0FSNZ3lNBS0BuRZU
         ohVX1LiBI+jN9JRx86ly6xE9zqGdvoOnaOX0QhJ9aRAMn84/SxHjvFbXYGuv6eTYZCJQ
         u4XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eEQrO/Lt";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=S+x7sZFZRdNnMOz3MZzAsWMRp5EJktfeV/nodz5YZP4=;
        b=fivYVuLqZRFuC4K6s5AfL3RYzMG1zLc30NKBV51IsO4C2i9sBhC2+kVxOiIEq4SSKy
         QutdyzQG2cC/mxbVWYFyw728F9+FtRddXL655x5IndhvW+zjjdpOWy9tZez1DwqZAJ5X
         GQ7V9qx3mSrHWqz9xmqTm6AgOF3QUVzLGewWgdTeHWeSmTPKPZt+2FptD7xnxndSTvJf
         xLrKFHYqTs9nDjEsZFUPCFnS2w84Ut8tee7ekwJywUaY1gMTjC6jAvCrkZOuPjcH/6+a
         LhI9qO3v68XuNAn5JP/1LOEziq7eulLJOkgiUvt3qdgeHrxt7xu4haeXWqH+0Y74zHSk
         M2YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S+x7sZFZRdNnMOz3MZzAsWMRp5EJktfeV/nodz5YZP4=;
        b=2wopwQbY8d9BRIRzjzRsQeI0S3amKv4GXCy6dPRmKxyKMyQoBf7oTZHJ7Mhwe4BQkf
         a6x01JCWp/VOXbzhOEQ4yd1zIAYz8UTdYZrnui+iWwb25Sy21oFx1GIsgrSimSDndegx
         XEJcnt00bcBJEyeMUmXWvRMVuSKGWuNRM82+NnSgg1vcfiwA3pNNT56j3gmiueb8lxW7
         40Be22t7eWN6pk96SQnNz7ImijH6B5Ci4Zb1bg1W/aL3sjdLMDp+T7UOX4DzgiL8vuUI
         HpymYKpNZEaEeOli7RCrKvuU3TAFSN4G6ExpqygOAJ9aD3BiOCA5Y9JF9DZETqK2WgA+
         ij8w==
X-Gm-Message-State: AOAM532nROgSvG9ppDKGrX6cmp0D6DDiTgO4lWQkrz1+cDRK/XSXJ+b1
	V78Y+5ZCrfSYpbIX/eo1Tfw=
X-Google-Smtp-Source: ABdhPJw7lXtrMUvc4imaV04nDcnP+revhTxH6zIO49ZDDkoIhTe8NGKnT0Di9tF+0nPzvYns/Zcygw==
X-Received: by 2002:a05:622a:10e:b0:2de:6400:eda3 with SMTP id u14-20020a05622a010e00b002de6400eda3mr17235044qtw.256.1646822747516;
        Wed, 09 Mar 2022 02:45:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eb4d:0:b0:435:ab0a:b2ca with SMTP id c13-20020a0ceb4d000000b00435ab0ab2cals767985qvq.8.gmail;
 Wed, 09 Mar 2022 02:45:47 -0800 (PST)
X-Received: by 2002:a05:6214:29c6:b0:435:ad11:b3c4 with SMTP id gh6-20020a05621429c600b00435ad11b3c4mr5329890qvb.16.1646822747020;
        Wed, 09 Mar 2022 02:45:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646822747; cv=none;
        d=google.com; s=arc-20160816;
        b=vEfjYRSzUFSD5nLsMU9L0cd21Gn+nCWkQvJFn5Nn+BQxdAtCz6yd7nc+hpkmIYl6g0
         1C8iwIipgj2wDFNetyslWQ/jkccKLMiAhUrLF39O4ZG+l6PbBiywH3gDJc3AUSykeMr6
         4Ixlg/sPiF7NZlMtWIVdqJMPs0LwwbD3DgW+Hi8SL4dfu1Mw9I7J3rd4ZPrPPVDHwbq5
         f2sguUFR51hhbHkpf+039/0KK/a5nas0eDtBX9qfMK/jDS7G8tpaycwol4PGZcEwC+cq
         oVoBNgQMZ7jIiDVUZGSNIDk5Jq5+HXp8ADY/T5t6ZWp8idwcxGVaNUutER1+HvV3vpby
         T4DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7cN9sV0/WTN4NHzm+ToLCSOMFSuq20yVNECoj1P44SQ=;
        b=o1w25jBy4j1D8L1/tkWg/TYcyUThxsRalRHMTx1ktRtVQ/s3ra4DmcBX2K2ZNI22kq
         NrI8qK3rsD9te9RpZ8CS/tzIKyqJnQuHoNm0mhVpNX+JkBFHvRFWN6YdYI60ELkuHL42
         rXP+JAq84gPsnvTHXK7gDi8MaFirZOxXETcV6GayYT8BUsJmYz0hXGXPJny+924qYrt4
         wwumf/E2ScqPGBiu7rm1mo1fuj+LXMZTBFvzVMlxlpiTVrtX9YW17MH5Ldm5EK4W3N0+
         hdvhT2/4R86qQXnehJl/PJyAloRgULTQPy1Lj9S/yIF3io07ykO3IzX01p/I7yzkL94g
         q67w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eEQrO/Lt";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id f23-20020ae9ea17000000b0067bf948c7cfsi104490qkg.5.2022.03.09.02.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 02:45:47 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id x4so2188805iom.12
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 02:45:46 -0800 (PST)
X-Received: by 2002:a05:6638:3789:b0:317:7763:46 with SMTP id
 w9-20020a056638378900b0031777630046mr19500601jal.42.1646822745978; Wed, 09
 Mar 2022 02:45:45 -0800 (PST)
MIME-Version: 1.0
References: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014> <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9>
In-Reply-To: <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 11:45:34 +0100
Message-ID: <CANp29Y6MvZvx4Xjwx=bxZ86D7Kubg0JPwBzP6HH8A6+Zj7YeLQ@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Alexander Potapenko <glider@google.com>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nick Hu <nickhu@andestech.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="eEQrO/Lt";       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d35 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

I switched the riscv syzbot instance to KASAN_OUTLINE and now it is
finally being fuzzed again!

Thank you very much for the series!

--
Best Regards,
Aleksandr

On Fri, Mar 4, 2022 at 5:12 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>
> On Tue, 01 Mar 2022 09:39:54 PST (-0800), Palmer Dabbelt wrote:
> > On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote:
> >> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
> >> alexandre.ghiti@canonical.com> wrote:
> >>
> >>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.co=
m>
> >>> wrote:
> >>> >
> >>> >
> >>> >
> >>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
> >>> alexandre.ghiti@canonical.com> wrote:
> >>> >>
> >>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google=
.com>
> >>> wrote:
> >>> >> >
> >>> >> >
> >>> >> >
> >>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> >>> alexandre.ghiti@canonical.com> wrote:
> >>> >> >>
> >>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com>
> >>> wrote:
> >>> >> >> >
> >>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> >>> >> >> > <alexandre.ghiti@canonical.com> wrote:
> >>> >> >> > >
> >>> >> >> > > As reported by Aleksandr, syzbot riscv is broken since comm=
it
> >>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This co=
mmit
> >>> actually
> >>> >> >> > > breaks KASAN_INLINE which is not fixed in this series, that=
 will
> >>> come later
> >>> >> >> > > when found.
> >>> >> >> > >
> >>> >> >> > > Nevertheless, this series fixes small things that made the =
syzbot
> >>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
> >>> >> >> > >
> >>> >> >> > > Note that even though the config at [1] boots fine with thi=
s
> >>> series, I
> >>> >> >> > > was not able to boot the small config at [2] which fails be=
cause
> >>> >> >> > > kasan_poison receives a really weird address 0x407570630100=
0000
> >>> (maybe a
> >>> >> >> > > kasan person could provide some hint about what happens bel=
ow in
> >>> >> >> > > do_ctors -> __asan_register_globals):
> >>> >> >> >
> >>> >> >> > asan_register_globals is responsible for poisoning redzones a=
round
> >>> >> >> > globals. As hinted by 'do_ctors', it calls constructors, and =
in
> >>> this
> >>> >> >> > case a compiler-generated constructor that calls
> >>> >> >> > __asan_register_globals with metadata generated by the compil=
er.
> >>> That
> >>> >> >> > metadata contains information about global variables. Note, t=
hese
> >>> >> >> > constructors are called on initial boot, but also every time =
a
> >>> kernel
> >>> >> >> > module (that has globals) is loaded.
> >>> >> >> >
> >>> >> >> > It may also be a toolchain issue, but it's hard to say. If yo=
u're
> >>> >> >> > using GCC to test, try Clang (11 or later), and vice-versa.
> >>> >> >>
> >>> >> >> I tried 3 different gcc toolchains already, but that did not fi=
x the
> >>> >> >> issue. The only thing that worked was setting asan-globals=3D0 =
in
> >>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
> >>> >> >> I tried to bisect this issue but our kasan implementation has b=
een
> >>> >> >> broken quite a few times, so it failed.
> >>> >> >>
> >>> >> >> I keep digging!
> >>> >> >>
> >>> >> >
> >>> >> > The problem does not reproduce for me with GCC 11.2.0: kernels b=
uilt
> >>> with both [1] and [2] are bootable.
> >>> >>
> >>> >> Do you mean you reach userspace? Because my image boots too, and f=
ails
> >>> >> at some point:
> >>> >>
> >>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wr=
aps
> >>> >> every 4398046511100ns
> >>> >> [    0.015847] Console: colour dummy device 80x25
> >>> >> [    0.016899] printk: console [tty0] enabled
> >>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
> >>> >>
> >>> >
> >>> > In my case, QEMU successfully boots to the login prompt.
> >>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksand=
r
> >>> shared with me (guess it was built according to this instruction:
> >>> https://github.com/google/syzkaller/blob/master/docs/linux/setup_linu=
x-host_qemu-vm_riscv64-kernel.md
> >>> )
> >>> >
> >>>
> >>> Nice thanks guys! I always use the latest opensbi and not the one tha=
t
> >>> is embedded in qemu, which is the only difference between your comman=
d
> >>> line (which works) and mine (which does not work). So the issue is
> >>> probably there, I really need to investigate that now.
> >>>
> >>> Great to hear that!
> >>
> >>
> >>> That means I only need to fix KASAN_INLINE and we're good.
> >>>
> >>> I imagine Palmer can add your Tested-by on the series then?
> >>>
> >> Sure :)
> >
> > Do you mind actually posting that (i, the Tested-by tag)?  It's less
> > likely to get lost that way.  I intend on taking this into fixes ASAP,
> > my builds have blown up for some reason (I got bounced between machines=
,
> > so I'm blaming that) so I need to fix that first.
>
> This is on fixes (with a "Tested-by: Alexander Potapenko
> <glider@google.com>"), along with some trivial commit message fixes.
>
> Thanks!
>
> >
> >>
> >>>
> >>> Thanks again!
> >>>
> >>> Alex
> >>>
> >>> >>
> >>> >> It traps here.
> >>> >>
> >>> >> > FWIW here is how I run them:
> >>> >> >
> >>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> >>> >> >   -device virtio-rng-pci -machine virt -device \
> >>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> >>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22=
 -device \
> >>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
> >>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
> >>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
> >>> "root=3D/dev/vda
> >>> >> >   console=3DttyS0 earlyprintk=3Dserial"
> >>> >> >
> >>> >> >
> >>> >> >>
> >>> >> >> Thanks for the tips,
> >>> >> >>
> >>> >> >> Alex
> >>> >> >
> >>> >> >
> >>> >> >
> >>> >> > --
> >>> >> > Alexander Potapenko
> >>> >> > Software Engineer
> >>> >> >
> >>> >> > Google Germany GmbH
> >>> >> > Erika-Mann-Stra=C3=9Fe, 33
> >>> >> > 80636 M=C3=BCnchen
> >>> >> >
> >>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> >>> >> > Registergericht und -nummer: Hamburg, HRB 86891
> >>> >> > Sitz der Gesellschaft: Hamburg
> >>> >> >
> >>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherw=
eise
> >>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand andere=
s
> >>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lasse=
n Sie mich bitte
> >>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
> >>> >> >
> >>> >> >
> >>> >> >
> >>> >> > This e-mail is confidential. If you received this communication =
by
> >>> mistake, please don't forward it to anyone else, please erase all cop=
ies
> >>> and attachments, and please let me know that it has gone to the wrong
> >>> person.
> >>> >>
> >>> >> --
> >>> >> You received this message because you are subscribed to the Google
> >>> Groups "kasan-dev" group.
> >>> >> To unsubscribe from this group and stop receiving emails from it, =
send
> >>> an email to kasan-dev+unsubscribe@googlegroups.com.
> >>> >> To view this discussion on the web visit
> >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvju=
jXkMXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
> >>> .
> >>> >
> >>> >
> >>> >
> >>> > --
> >>> > Alexander Potapenko
> >>> > Software Engineer
> >>> >
> >>> > Google Germany GmbH
> >>> > Erika-Mann-Stra=C3=9Fe, 33
> >>> > 80636 M=C3=BCnchen
> >>> >
> >>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> >>> > Registergericht und -nummer: Hamburg, HRB 86891
> >>> > Sitz der Gesellschaft: Hamburg
> >>> >
> >>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweis=
e erhalten
> >>> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
> >>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mi=
ch bitte wissen,
> >>> dass die E-Mail an die falsche Person gesendet wurde.
> >>> >
> >>> >
> >>> >
> >>> > This e-mail is confidential. If you received this communication by
> >>> mistake, please don't forward it to anyone else, please erase all cop=
ies
> >>> and attachments, and please let me know that it has gone to the wrong
> >>> person.
> >>>
> >>> --
> >>> You received this message because you are subscribed to the Google Gr=
oups
> >>> "kasan-dev" group.
> >>> To unsubscribe from this group and stop receiving emails from it, sen=
d an
> >>> email to kasan-dev+unsubscribe@googlegroups.com.
> >>> To view this discussion on the web visit
> >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM=
96bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
> >>> .
> >>>
> >>
> >>
> >> --
> >> Alexander Potapenko
> >> Software Engineer
> >>
> >> Google Germany GmbH
> >> Erika-Mann-Stra=C3=9Fe, 33
> >> 80636 M=C3=BCnchen
> >>
> >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> >> Registergericht und -nummer: Hamburg, HRB 86891
> >> Sitz der Gesellschaft: Hamburg
> >>
> >> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise e=
rhalten
> >> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
> >> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mic=
h bitte wissen,
> >> dass die E-Mail an die falsche Person gesendet wurde.
> >>
> >>
> >>
> >> This e-mail is confidential. If you received this communication by mis=
take,
> >> please don't forward it to anyone else, please erase all copies and
> >> attachments, and please let me know that it has gone to the wrong pers=
on.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y6MvZvx4Xjwx%3DbxZ86D7Kubg0JPwBzP6HH8A6%2BZj7YeLQ%40mail.gm=
ail.com.
