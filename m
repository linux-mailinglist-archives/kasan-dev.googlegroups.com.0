Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLO64OIAMGQEBU4RJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E5304C4839
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 16:01:03 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id h7-20020a0cf407000000b00432843fb43fsf5899542qvl.7
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 07:01:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645801262; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fmx5y7NMcYAz99wW+o5BOJN/0yb8YE0hfaMNyP8bAgEEHFufaUOj7q/dIB0tEFqNbt
         YR19nTcJZGsY2cO6MFma78Id310kjk5TRzRaTXf9BYULEq/bF/q3yPWu5/yud1VMmtyS
         p0UobvIDSwfSAgWSYWuFPmWdm2VoX3YH3drThJekAkWCRC1mNbXAqT96HxI31NGq3drg
         MTes8a6n27OfdOEN9sTYd3GLiigypeHUCH76J38qJJYp6QGmEfcnTtvCYPOLrmAH/daV
         krfV+MkE2cG6S3aczxaXbWzY1tLBfNsds2QImUI7F1MfypugHfTEdho04xhCyfguEpoJ
         87FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GvvySHV9k5GlnWFbhKA+mTMUrQ50hpU6ouDpZI1jFTI=;
        b=FlwwBjBnQ/VUF36kfKQx+LJ4RoJ6CK2K4S1gIaxdk7x5hfxRrv7ANbBAT/WcskTbLL
         C7Apb2rHIuI2g7QYbXyuKW6WLRjMxkAoSEwpyqj2cWHgPVV6GrOEoSLLgY4NNTzMsce1
         rhLP796hU1byJB0G6aq9h71ejgm5fsyDGZ1xqXi+wsywDkCblUfx5SpbL4TwROKKPQKA
         8dRHSysFh2xmiWr5j+mJ/YeFANnBZPcV5tG70ya1Gwy3rlQ8sTumQ1aR26GNNohIR1kz
         xQSEaw5GirlyOiX5NBmeY/NTOIme0cUayyxBzQQByC3nKHfIIucK6/FBsEz7MIjgABe9
         O8Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q9NMDUCG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GvvySHV9k5GlnWFbhKA+mTMUrQ50hpU6ouDpZI1jFTI=;
        b=egpplYoL0EeeoXlL4SP6xYJzgev+An8ksdXprYRbX8InKBVFAfMMrJ8q3HGvTGWgGj
         y0xF0PXtXU5gifF1Sz8cwr3+pXSbJ4ROipdgVOI8jXtsZy+pblI2jkaKrNpbL8/cTLNy
         JNlMx4S/TC59rQZCE4JOn7zEDi8jKGbKMdoGx3J0ldRmA03T+PsnXRVRQeP6+mreqmxH
         PYzAOb0h9qroqlclLJvA9yeBx/kndvIHttHq78y83IRtOJ8MDz3e8vJsY4uc/tQuxoMv
         z/9ZT6TgdowiXREDKJEHNMYVNKij7NH7DSlnT7QoKPK/8OeGky+mwOfDK+D7aooPaxQx
         DOjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GvvySHV9k5GlnWFbhKA+mTMUrQ50hpU6ouDpZI1jFTI=;
        b=iO772wnjFhR11/94IWe8MrcEiUgnrCXvLqzab09RdIuh6FBAi+DgIlJcPnl4r4APFE
         bGfY+tKS3SgY/bRJrV0P3ihDmv+As4uf97LIhI3Fi3jGoiBXlc1tS+maDHP8Dheq+CZg
         GOVw6Lef+0CEW7nybpWKWR9Djo9mnfbNrKUBm/27p+P7qO5TQhiN0sS8o0KIRa3P7IrJ
         Rt1JYNoNtNrhuFIKcJlY74XUYd8XW9nqzH/f5JgNhFFTAn5toe+SZAh2i0nw5UiQPgbl
         bu4wmBk57QY9o3Mq477IWg8RrC7J+4qVVzY/zRuyDpDer2L990EN6ZBgu/Q0H1xDmNh9
         iMiQ==
X-Gm-Message-State: AOAM530mRYCEseBCpOEBkuto0n5Ez7ztsYTZVTIqHq6owyvRafr3mnxF
	6gsA9257vyB23JtgTN3IezQ=
X-Google-Smtp-Source: ABdhPJyt2pCWwi5fYpwpVDRmynjRsWMNFTDy8iigLRYk4rRAHLULtOy85Ttx2hTkvCEQZo1lhGpBQA==
X-Received: by 2002:a05:6214:29cd:b0:432:3f0d:a071 with SMTP id gh13-20020a05621429cd00b004323f0da071mr6225535qvb.86.1645801261735;
        Fri, 25 Feb 2022 07:01:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:290:b0:2de:640a:6144 with SMTP id
 z16-20020a05622a029000b002de640a6144ls4757708qtw.6.gmail; Fri, 25 Feb 2022
 07:01:01 -0800 (PST)
X-Received: by 2002:ac8:594d:0:b0:2dd:ff9c:f26 with SMTP id 13-20020ac8594d000000b002ddff9c0f26mr7147095qtz.242.1645801261084;
        Fri, 25 Feb 2022 07:01:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645801261; cv=none;
        d=google.com; s=arc-20160816;
        b=egQnTUqDfqxmc+a3DLHKi51SeEpRu/ujhTK1h+oXi5EMJHCMZw+WnIipeamf6Ai4Tg
         DoSh8GMpAvKYuN6anVBfhxTbc8ESMYV6gK+cW9R95yydN7cgyyFbVekqv7pYZX2/0+gA
         SPqmVf/rGtFc6UkjyrsGU/jzfTG2geFyo1vNe2yl4SYRpEbLfI4Qa8gu+9plMavl1ZEG
         gxMHP3/7uYGjcViJtIrmVPbzRugliVRdgneVW+hUqZpy6cD/9ByHEBGgnnpJ+toZQz/J
         nROgMqGCFsySMIIHQqE1beSjIOXqM8MuOlinsM/efTsErCh6MSyCbjlmgcDvKXnWwZMz
         th4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sQRkewVQhkOzmmAgEeMRqumOsiHBfGrSzmcXzCmfsVo=;
        b=mH3CsqhKLDFa6oRD1/2LOjlju0ruxgUHj0AgDXETJSpXLp7xEdPG/Zab375k23RKYo
         BNAADTIX0BZvDM8Z6yhMagnyP75XZvwlpXUnOJJiNS0n+5HB8la/E6AdCyDG3BK/gRyN
         jjnS1PyyVgXVuTYZb0LEjfV6E4YJ105ASVCIolxbS/D6XPxviCnSh4txRHqkEnVuzwnN
         lwnmKN+RO1e4nBYOzEH9LDPQ6zY5bSwT+yFIhqvi7YeynOkTk/6JNFm/gjGjbs3xysDt
         Sz0IrwclMWl/19NiOOlicZ3hkAK/PCkV98P8jpwh5mz8gESKIEl6GwTNUv1uYJnKk3Xc
         zqkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q9NMDUCG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id l6-20020a05622a174600b002dced03ce81si189430qtk.0.2022.02.25.07.01.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Feb 2022 07:01:01 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id w1so2628572qtj.2
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 07:01:01 -0800 (PST)
X-Received: by 2002:a05:622a:15d2:b0:2de:323e:e964 with SMTP id
 d18-20020a05622a15d200b002de323ee964mr7160717qty.79.1645801260471; Fri, 25
 Feb 2022 07:01:00 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
 <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
 <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
 <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com>
 <CA+zEjCsQPVYSV7CdhKnvjujXkMXuRQd=VPok1awb20xifYmidw@mail.gmail.com>
 <CAG_fn=VZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q@mail.gmail.com> <CA+zEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg@mail.gmail.com>
In-Reply-To: <CA+zEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Feb 2022 16:00:23 +0100
Message-ID: <CAG_fn=WTJF24TH6ENGD-3S0B_AV4=-39=2ry-uDguZ8Q7f=z=Q@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="00000000000080f9a005d8d8f71b"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q9NMDUCG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--00000000000080f9a005d8d8f71b
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
alexandre.ghiti@canonical.com> wrote:

> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.com>
> wrote:
> >
> >
> >
> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
> alexandre.ghiti@canonical.com> wrote:
> >>
> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.com=
>
> wrote:
> >> >
> >> >
> >> >
> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> alexandre.ghiti@canonical.com> wrote:
> >> >>
> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com>
> wrote:
> >> >> >
> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> >> >> > <alexandre.ghiti@canonical.com> wrote:
> >> >> > >
> >> >> > > As reported by Aleksandr, syzbot riscv is broken since commit
> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit
> actually
> >> >> > > breaks KASAN_INLINE which is not fixed in this series, that wil=
l
> come later
> >> >> > > when found.
> >> >> > >
> >> >> > > Nevertheless, this series fixes small things that made the syzb=
ot
> >> >> > > configuration + KASAN_OUTLINE fail to boot.
> >> >> > >
> >> >> > > Note that even though the config at [1] boots fine with this
> series, I
> >> >> > > was not able to boot the small config at [2] which fails becaus=
e
> >> >> > > kasan_poison receives a really weird address 0x4075706301000000
> (maybe a
> >> >> > > kasan person could provide some hint about what happens below i=
n
> >> >> > > do_ctors -> __asan_register_globals):
> >> >> >
> >> >> > asan_register_globals is responsible for poisoning redzones aroun=
d
> >> >> > globals. As hinted by 'do_ctors', it calls constructors, and in
> this
> >> >> > case a compiler-generated constructor that calls
> >> >> > __asan_register_globals with metadata generated by the compiler.
> That
> >> >> > metadata contains information about global variables. Note, these
> >> >> > constructors are called on initial boot, but also every time a
> kernel
> >> >> > module (that has globals) is loaded.
> >> >> >
> >> >> > It may also be a toolchain issue, but it's hard to say. If you're
> >> >> > using GCC to test, try Clang (11 or later), and vice-versa.
> >> >>
> >> >> I tried 3 different gcc toolchains already, but that did not fix th=
e
> >> >> issue. The only thing that worked was setting asan-globals=3D0 in
> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
> >> >> I tried to bisect this issue but our kasan implementation has been
> >> >> broken quite a few times, so it failed.
> >> >>
> >> >> I keep digging!
> >> >>
> >> >
> >> > The problem does not reproduce for me with GCC 11.2.0: kernels built
> with both [1] and [2] are bootable.
> >>
> >> Do you mean you reach userspace? Because my image boots too, and fails
> >> at some point:
> >>
> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps
> >> every 4398046511100ns
> >> [    0.015847] Console: colour dummy device 80x25
> >> [    0.016899] printk: console [tty0] enabled
> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
> >>
> >
> > In my case, QEMU successfully boots to the login prompt.
> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr
> shared with me (guess it was built according to this instruction:
> https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-ho=
st_qemu-vm_riscv64-kernel.md
> )
> >
>
> Nice thanks guys! I always use the latest opensbi and not the one that
> is embedded in qemu, which is the only difference between your command
> line (which works) and mine (which does not work). So the issue is
> probably there, I really need to investigate that now.
>
> Great to hear that!


> That means I only need to fix KASAN_INLINE and we're good.
>
> I imagine Palmer can add your Tested-by on the series then?
>
Sure :)

>
> Thanks again!
>
> Alex
>
> >>
> >> It traps here.
> >>
> >> > FWIW here is how I run them:
> >> >
> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> >> >   -device virtio-rng-pci -machine virt -device \
> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -de=
vice \
> >> >   virtio-blk-device,drive=3Dhd0 -drive \
> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
> "root=3D/dev/vda
> >> >   console=3DttyS0 earlyprintk=3Dserial"
> >> >
> >> >
> >> >>
> >> >> Thanks for the tips,
> >> >>
> >> >> Alex
> >> >
> >> >
> >> >
> >> > --
> >> > Alexander Potapenko
> >> > Software Engineer
> >> >
> >> > Google Germany GmbH
> >> > Erika-Mann-Stra=C3=9Fe, 33
> >> > 80636 M=C3=BCnchen
> >> >
> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> >> > Registergericht und -nummer: Hamburg, HRB 86891
> >> > Sitz der Gesellschaft: Hamburg
> >> >
> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
> erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Si=
e mich bitte
> wissen, dass die E-Mail an die falsche Person gesendet wurde.
> >> >
> >> >
> >> >
> >> > This e-mail is confidential. If you received this communication by
> mistake, please don't forward it to anyone else, please erase all copies
> and attachments, and please let me know that it has gone to the wrong
> person.
> >>
> >> --
> >> You received this message because you are subscribed to the Google
> Groups "kasan-dev" group.
> >> To unsubscribe from this group and stop receiving emails from it, send
> an email to kasan-dev+unsubscribe@googlegroups.com.
> >> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkM=
XuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
> .
> >
> >
> >
> > --
> > Alexander Potapenko
> > Software Engineer
> >
> > Google Germany GmbH
> > Erika-Mann-Stra=C3=9Fe, 33
> > 80636 M=C3=BCnchen
> >
> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > Registergericht und -nummer: Hamburg, HRB 86891
> > Sitz der Gesellschaft: Hamburg
> >
> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise er=
halten
> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich b=
itte wissen,
> dass die E-Mail an die falsche Person gesendet wurde.
> >
> >
> >
> > This e-mail is confidential. If you received this communication by
> mistake, please don't forward it to anyone else, please erase all copies
> and attachments, and please let me know that it has gone to the wrong
> person.
>
> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96bz=
KqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
> .
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erhalt=
en
haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter,
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen,
dass die E-Mail an die falsche Person gesendet wurde.



This e-mail is confidential. If you received this communication by mistake,
please don't forward it to anyone else, please erase all copies and
attachments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWTJF24TH6ENGD-3S0B_AV4%3D-39%3D2ry-uDguZ8Q7f%3Dz%3DQ%40m=
ail.gmail.com.

--00000000000080f9a005d8d8f71b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Feb 25, 2022 at 3:47 PM Alexa=
ndre Ghiti &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com">alexandre.g=
hiti@canonical.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote=
" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);=
padding-left:1ex">On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko &lt;<=
a href=3D"mailto:glider@google.com" target=3D"_blank">glider@google.com</a>=
&gt; wrote:<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti &lt;<a href=3D"mailto:=
alexandre.ghiti@canonical.com" target=3D"_blank">alexandre.ghiti@canonical.=
com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko &lt;<a href=3D=
"mailto:glider@google.com" target=3D"_blank">glider@google.com</a>&gt; wrot=
e:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti &lt;<a href=
=3D"mailto:alexandre.ghiti@canonical.com" target=3D"_blank">alexandre.ghiti=
@canonical.com</a>&gt; wrote:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; On Fri, Feb 25, 2022 at 2:06 PM Marco Elver &lt;<a href=
=3D"mailto:elver@google.com" target=3D"_blank">elver@google.com</a>&gt; wro=
te:<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti<br>
&gt;&gt; &gt;&gt; &gt; &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com"=
 target=3D"_blank">alexandre.ghiti@canonical.com</a>&gt; wrote:<br>
&gt;&gt; &gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; &gt; As reported by Aleksandr, syzbot riscv is broke=
n since commit<br>
&gt;&gt; &gt;&gt; &gt; &gt; 54c5639d8f50 (&quot;riscv: Fix asan-stack clang=
 build&quot;). This commit actually<br>
&gt;&gt; &gt;&gt; &gt; &gt; breaks KASAN_INLINE which is not fixed in this =
series, that will come later<br>
&gt;&gt; &gt;&gt; &gt; &gt; when found.<br>
&gt;&gt; &gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; &gt; Nevertheless, this series fixes small things th=
at made the syzbot<br>
&gt;&gt; &gt;&gt; &gt; &gt; configuration + KASAN_OUTLINE fail to boot.<br>
&gt;&gt; &gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; &gt; Note that even though the config at [1] boots f=
ine with this series, I<br>
&gt;&gt; &gt;&gt; &gt; &gt; was not able to boot the small config at [2] wh=
ich fails because<br>
&gt;&gt; &gt;&gt; &gt; &gt; kasan_poison receives a really weird address 0x=
4075706301000000 (maybe a<br>
&gt;&gt; &gt;&gt; &gt; &gt; kasan person could provide some hint about what=
 happens below in<br>
&gt;&gt; &gt;&gt; &gt; &gt; do_ctors -&gt; __asan_register_globals):<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; asan_register_globals is responsible for poisoning r=
edzones around<br>
&gt;&gt; &gt;&gt; &gt; globals. As hinted by &#39;do_ctors&#39;, it calls c=
onstructors, and in this<br>
&gt;&gt; &gt;&gt; &gt; case a compiler-generated constructor that calls<br>
&gt;&gt; &gt;&gt; &gt; __asan_register_globals with metadata generated by t=
he compiler. That<br>
&gt;&gt; &gt;&gt; &gt; metadata contains information about global variables=
. Note, these<br>
&gt;&gt; &gt;&gt; &gt; constructors are called on initial boot, but also ev=
ery time a kernel<br>
&gt;&gt; &gt;&gt; &gt; module (that has globals) is loaded.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; It may also be a toolchain issue, but it&#39;s hard =
to say. If you&#39;re<br>
&gt;&gt; &gt;&gt; &gt; using GCC to test, try Clang (11 or later), and vice=
-versa.<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; I tried 3 different gcc toolchains already, but that did =
not fix the<br>
&gt;&gt; &gt;&gt; issue. The only thing that worked was setting asan-global=
s=3D0 in<br>
&gt;&gt; &gt;&gt; scripts/Makefile.kasan, but ok, that&#39;s not a fix.<br>
&gt;&gt; &gt;&gt; I tried to bisect this issue but our kasan implementation=
 has been<br>
&gt;&gt; &gt;&gt; broken quite a few times, so it failed.<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; I keep digging!<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; The problem does not reproduce for me with GCC 11.2.0: kernel=
s built with both [1] and [2] are bootable.<br>
&gt;&gt;<br>
&gt;&gt; Do you mean you reach userspace? Because my image boots too, and f=
ails<br>
&gt;&gt; at some point:<br>
&gt;&gt;<br>
&gt;&gt; [=C2=A0 =C2=A0 0.000150] sched_clock: 64 bits at 10MHz, resolution=
 100ns, wraps<br>
&gt;&gt; every 4398046511100ns<br>
&gt;&gt; [=C2=A0 =C2=A0 0.015847] Console: colour dummy device 80x25<br>
&gt;&gt; [=C2=A0 =C2=A0 0.016899] printk: console [tty0] enabled<br>
&gt;&gt; [=C2=A0 =C2=A0 0.020326] printk: bootconsole [ns16550a0] disabled<=
br>
&gt;&gt;<br>
&gt;<br>
&gt; In my case, QEMU successfully boots to the login prompt.<br>
&gt; I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr s=
hared with me (guess it was built according to this instruction: <a href=3D=
"https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-hos=
t_qemu-vm_riscv64-kernel.md" rel=3D"noreferrer" target=3D"_blank">https://g=
ithub.com/google/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_=
riscv64-kernel.md</a>)<br>
&gt;<br>
<br>
Nice thanks guys! I always use the latest opensbi and not the one that<br>
is embedded in qemu, which is the only difference between your command<br>
line (which works) and mine (which does not work). So the issue is<br>
probably there, I really need to investigate that now.<br>
<br></blockquote><div>Great to hear that!</div><div>=C2=A0</div><blockquote=
 class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px so=
lid rgb(204,204,204);padding-left:1ex">
That means I only need to fix KASAN_INLINE and we&#39;re good.<br>
<br>
I imagine Palmer can add your Tested-by on the series then?<br></blockquote=
><div>Sure :)=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:=
0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">
<br>
Thanks again!<br>
<br>
Alex<br>
<br>
&gt;&gt;<br>
&gt;&gt; It traps here.<br>
&gt;&gt;<br>
&gt;&gt; &gt; FWIW here is how I run them:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \<br=
>
&gt;&gt; &gt;=C2=A0 =C2=A0-device virtio-rng-pci -machine virt -device \<br=
>
&gt;&gt; &gt;=C2=A0 =C2=A0virtio-net-pci,netdev=3Dnet0 -netdev \<br>
&gt;&gt; &gt;=C2=A0 =C2=A0user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.=
0.1:12529-:22 -device \<br>
&gt;&gt; &gt;=C2=A0 =C2=A0virtio-blk-device,drive=3Dhd0 -drive \<br>
&gt;&gt; &gt;=C2=A0 =C2=A0file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -=
snapshot \<br>
&gt;&gt; &gt;=C2=A0 =C2=A0-kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -=
append &quot;root=3D/dev/vda<br>
&gt;&gt; &gt;=C2=A0 =C2=A0console=3DttyS0 earlyprintk=3Dserial&quot;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Thanks for the tips,<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Alex<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; --<br>
&gt;&gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; Software Engineer<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian<br>
&gt;&gt; &gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt;&gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlich=
erweise erhalten haben sollten, leiten Sie diese bitte nicht an jemand ande=
res weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen =
Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet wurde=
.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; This e-mail is confidential. If you received this communicati=
on by mistake, please don&#39;t forward it to anyone else, please erase all=
 copies and attachments, and please let me know that it has gone to the wro=
ng person.<br>
&gt;&gt;<br>
&gt;&gt; --<br>
&gt;&gt; You received this message because you are subscribed to the Google=
 Groups &quot;kasan-dev&quot; group.<br>
&gt;&gt; To unsubscribe from this group and stop receiving emails from it, =
send an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com=
" target=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt;&gt; To view this discussion on the web visit <a href=3D"https://groups=
.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPok1awb=
20xifYmidw%40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">https://g=
roups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPo=
k1awb20xifYmidw%40mail.gmail.com</a>.<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; --<br>
&gt; Alexander Potapenko<br>
&gt; Software Engineer<br>
&gt;<br>
&gt; Google Germany GmbH<br>
&gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; 80636 M=C3=BCnchen<br>
&gt;<br>
&gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian<br>
&gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt; Sitz der Gesellschaft: Hamburg<br>
&gt;<br>
&gt; Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise e=
rhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes weite=
r, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich =
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; This e-mail is confidential. If you received this communication by mis=
take, please don&#39;t forward it to anyone else, please erase all copies a=
nd attachments, and please let me know that it has gone to the wrong person=
.<br>
<br>
-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" target=
=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg%=
40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">https://groups.googl=
e.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8=
Hg%40mail.gmail.com</a>.<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br><br>Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4ls=
chlicherweise erhalten haben sollten, leiten Sie diese bitte nicht an jeman=
d anderes weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte wissen, dass die E-Mail an die falsche Person gesendet=
 wurde. <br><br>=C2=A0 =C2=A0 =C2=A0<br><br>This e-mail is confidential. If=
 you received this communication by mistake, please don&#39;t forward it to=
 anyone else, please erase all copies and attachments, and please let me kn=
ow that it has gone to the wrong person.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DWTJF24TH6ENGD-3S0B_AV4%3D-39%3D2ry-uDguZ8Q7f%=
3Dz%3DQ%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://gr=
oups.google.com/d/msgid/kasan-dev/CAG_fn%3DWTJF24TH6ENGD-3S0B_AV4%3D-39%3D2=
ry-uDguZ8Q7f%3Dz%3DQ%40mail.gmail.com</a>.<br />

--00000000000080f9a005d8d8f71b--
