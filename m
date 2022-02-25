Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOGQ4OIAMGQEZT3DXZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id BE3944C477C
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 15:31:21 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id q14-20020a17090311ce00b001501afc15e2sf2524434plh.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 06:31:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645799480; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrNJPpmL6sOQ4EfEyiNFipbEPnjzMgxaOGKbathzvLxFupFnVIsWc1haw38uWHgYr+
         4gpuraMQe9kNfQQopRvr8S1rExyRShkhyL6w8TlDphF3yDV/mHaFSAgJoHlP03rXTbSQ
         r0y9eXbm+wXbj4XNKv0fkPg7jT0SaP0XO8sev9wcgCK0qYJqt9nYZYOXBthIHxbBqnXO
         1KW+TgqCUGBeTLaL/U4L66emQFixfnWYTFb2fQc0rc+gZJhQseps6ECM5vPW+aQYD1kr
         FUxLPfr8z6h5MfKaOkKHLGa4i1ht0K2GJ1++sjAV65clfBzjbIWbp9TLGMkZb/GVxKmI
         6CpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QUYQvc3856IsQTSYooQoJ1rGlrieMI6ukhJ2iyVcx5A=;
        b=UYyLGgV/0qbrX8pbN9nRwK4hVB5qxASv3c6XyPoQTuhivlZd15DPJu0/LwrbJf6NWo
         FeF5/eXbC3vOb/EwboEiQl6kqFq2i3Kl6t7BKL1x1fP3IPayLt2LBOV2eSsQYY7lsqbq
         Ya6vog7r/YiUSHzodmgswt5PxZXHVYXPzDi0FotNli5c419vpiohK1/e+sHvMIjnLMT/
         79J10sa4YnqB8ExQMewkDIITDbNi3TCMYRwzQ06mCJfy/nf/xHvF01WoRG/kMs2qSwgl
         ut3N6Q7BDJLCVKpklSN+OvoFXkkG3slOiM2WuUxXoA8j9wAXBvTpqlDU9jXI/JzxW6Sw
         Knvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PifH5ZiI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QUYQvc3856IsQTSYooQoJ1rGlrieMI6ukhJ2iyVcx5A=;
        b=tUf7TjcsX/CnwZBjGwXpxhQA0ZdTky+3/Fo7jyb/5qd8YCRpafFdOqPIU04Q2sOGPA
         0atlHj6rYajkmBEMVD9OxenlooaYSCvB3VGHHs35n085KeVUzksO+8PdI1IgyE/8cqBh
         gjoIgy24LH9liwZdFXry/EZ3BKc+QGa7evp1nlNbac5+POq6UPp5tlrTL/n6tMpbuO+S
         z8zYOeL3aFU1JS4RBxsgXIRg6uQiMSTvaPVKCXNQdM5MuMTwy9ZO/vrhwZcA7jwO2aOt
         GRMMZM3vKD0vlQ9LhJb8xaAGkwyeqFGIoiHC+gZb48dJqt0Rp+daB2AcE/lIktY0xr6L
         tZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QUYQvc3856IsQTSYooQoJ1rGlrieMI6ukhJ2iyVcx5A=;
        b=uRUypBXHYsbBtzLeS220QK24R6wESzrIxMSZ+t3rDmW4OLUnsr28TntwF81OD4kY/V
         7F3VjEVwSvnhD8sW+dwBVomwmC2qcMiji+zkHegSAJe055uKk7nu/bAzHrBv55smCUI3
         wGngS+A0O2i8kGwXERKED7zZYgshPBTo/bDyH32mCNbR1JtAWZNe+smDqj7SOTc6L//l
         V2MXSlTHabnflm8PeEh+xhaeASJG2rEGHRWWZJNg55B5BPgGNaARqZTpg99KfduMgmW/
         IJ7q7X6599NCnEf4d5IQSlSqW3GMZeFqv6PxfvfU7Q+9M4nJwwyxO0++rsEImx3dD2Cz
         b4nQ==
X-Gm-Message-State: AOAM531DmM4n3iW2ByMFKDCS6LYhtSHCtJL7JnsTDwkHu1gIlN9+vqOD
	pShHsZj2RbUTbdtqUw/h4Uo=
X-Google-Smtp-Source: ABdhPJw9X4dzbugh+sZTx05JlONh5aHhPYmQDx4vHUo5LEfrm8WQkEm7hYp7UJhHxFNMievaXmEEHw==
X-Received: by 2002:a17:902:8b8c:b0:14e:d959:7bdb with SMTP id ay12-20020a1709028b8c00b0014ed9597bdbmr8006815plb.41.1645799480377;
        Fri, 25 Feb 2022 06:31:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d082:b0:1b8:a954:e0cc with SMTP id
 k2-20020a17090ad08200b001b8a954e0ccls1833250pju.3.gmail; Fri, 25 Feb 2022
 06:31:19 -0800 (PST)
X-Received: by 2002:a17:90a:5505:b0:1b8:ebd4:d602 with SMTP id b5-20020a17090a550500b001b8ebd4d602mr3392146pji.147.1645799479653;
        Fri, 25 Feb 2022 06:31:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645799479; cv=none;
        d=google.com; s=arc-20160816;
        b=RfJ5hvxXcjnyLpgkkP2Nyf3tiRPDSqA8YPt8qOlaQ6kDIZK7eXQCF0tKCeG55LAnsx
         5bG2ej5n4VzB+aBbM94Wk4bfHfjkBtbO+FYIgLAoMjjKdWWBuSbEyLWojASGNQH2VRBP
         RFs+pIDkEmvNM96qY1a3q3R0Wo6Qh0WKneyzPsCWhXRuj/WnvYziPvhVDxpgfqjjX8Xm
         hgm7A83zZKDkIfBOGeuftJrWR86WT0/wVc/PbtqJWm9A86yt7AA7DDrsOzgkn90lp878
         aA+ejk07jmt8W/Ow9WC9cC67tCZmqcjdDr/ExS4kckMVtyNp2NJm2blksXe8oSII+1J4
         8K5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q3/pGJWT55wNTVWZyeUml4a5i1wfDKM71A95xWVO/MM=;
        b=zxKozXFgnB8rXfI5ah7gGtDEXn9OdEGiC30oV0oExCcgbsuYGT8Dy3ambstMBe0Ttb
         hJmPELG/y8nlGiQR1zNE4hFhfBX8gdgdLLUiN9Ie4mU+cPCvUmFJKswhAu5tVMgrN11I
         Va1QVHeQ6Id/3UP5G1DPIzaYZsTFwXR6ZIp/9tJzoVjM1QPYPrWYgDgymuzQFltPNsk5
         EHeFYNtmASs56dxWc9xdEpVSz533caKFASHSNq1ZwTmA7JBr7FyolmC3Nb1cybcj5KfE
         w04LPsPSfOB+Dg9h5gcVKtq8LmgxJXKmrkGeZGLDjLl6le3ShI5oeTbi7flKoaLAAIJ2
         vJwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PifH5ZiI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id p11-20020a17090a930b00b001b97a1bfec2si606575pjo.3.2022.02.25.06.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Feb 2022 06:31:19 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 8so6828707qvf.2
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 06:31:19 -0800 (PST)
X-Received: by 2002:ad4:4e61:0:b0:42d:1b44:44c4 with SMTP id
 ec1-20020ad44e61000000b0042d1b4444c4mr5927507qvb.44.1645799478536; Fri, 25
 Feb 2022 06:31:18 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
 <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
 <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
 <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com> <CA+zEjCsQPVYSV7CdhKnvjujXkMXuRQd=VPok1awb20xifYmidw@mail.gmail.com>
In-Reply-To: <CA+zEjCsQPVYSV7CdhKnvjujXkMXuRQd=VPok1awb20xifYmidw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Feb 2022 15:30:42 +0100
Message-ID: <CAG_fn=VZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="0000000000004abcc205d8d88dea"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PifH5ZiI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

--0000000000004abcc205d8d88dea
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
alexandre.ghiti@canonical.com> wrote:

> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.com>
> wrote:
> >
> >
> >
> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> alexandre.ghiti@canonical.com> wrote:
> >>
> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
> >> >
> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> >> > <alexandre.ghiti@canonical.com> wrote:
> >> > >
> >> > > As reported by Aleksandr, syzbot riscv is broken since commit
> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit
> actually
> >> > > breaks KASAN_INLINE which is not fixed in this series, that will
> come later
> >> > > when found.
> >> > >
> >> > > Nevertheless, this series fixes small things that made the syzbot
> >> > > configuration + KASAN_OUTLINE fail to boot.
> >> > >
> >> > > Note that even though the config at [1] boots fine with this
> series, I
> >> > > was not able to boot the small config at [2] which fails because
> >> > > kasan_poison receives a really weird address 0x4075706301000000
> (maybe a
> >> > > kasan person could provide some hint about what happens below in
> >> > > do_ctors -> __asan_register_globals):
> >> >
> >> > asan_register_globals is responsible for poisoning redzones around
> >> > globals. As hinted by 'do_ctors', it calls constructors, and in this
> >> > case a compiler-generated constructor that calls
> >> > __asan_register_globals with metadata generated by the compiler. Tha=
t
> >> > metadata contains information about global variables. Note, these
> >> > constructors are called on initial boot, but also every time a kerne=
l
> >> > module (that has globals) is loaded.
> >> >
> >> > It may also be a toolchain issue, but it's hard to say. If you're
> >> > using GCC to test, try Clang (11 or later), and vice-versa.
> >>
> >> I tried 3 different gcc toolchains already, but that did not fix the
> >> issue. The only thing that worked was setting asan-globals=3D0 in
> >> scripts/Makefile.kasan, but ok, that's not a fix.
> >> I tried to bisect this issue but our kasan implementation has been
> >> broken quite a few times, so it failed.
> >>
> >> I keep digging!
> >>
> >
> > The problem does not reproduce for me with GCC 11.2.0: kernels built
> with both [1] and [2] are bootable.
>
> Do you mean you reach userspace? Because my image boots too, and fails
> at some point:
>
> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps
> every 4398046511100ns
> [    0.015847] Console: colour dummy device 80x25
> [    0.016899] printk: console [tty0] enabled
> [    0.020326] printk: bootconsole [ns16550a0] disabled
>
>
In my case, QEMU successfully boots to the login prompt.
I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksandr shared
with me (guess it was built according to this instruction:
https://github.com/google/syzkaller/blob/master/docs/linux/setup_linux-host=
_qemu-vm_riscv64-kernel.md
)


> It traps here.
>
> > FWIW here is how I run them:
> >
> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> >   -device virtio-rng-pci -machine virt -device \
> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -devic=
e \
> >   virtio-blk-device,drive=3Dhd0 -drive \
> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append "root=3D/dev/=
vda
> >   console=3DttyS0 earlyprintk=3Dserial"
> >
> >
> >>
> >> Thanks for the tips,
> >>
> >> Alex
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
> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkM=
XuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
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
kasan-dev/CAG_fn%3DVZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q%40mail.gmai=
l.com.

--0000000000004abcc205d8d88dea
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Feb 25, 2022 at 3:15 PM Alexa=
ndre Ghiti &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com">alexandre.g=
hiti@canonical.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote=
" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);=
padding-left:1ex">On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko &lt;<=
a href=3D"mailto:glider@google.com" target=3D"_blank">glider@google.com</a>=
&gt; wrote:<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti &lt;<a href=3D"mailto:=
alexandre.ghiti@canonical.com" target=3D"_blank">alexandre.ghiti@canonical.=
com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Fri, Feb 25, 2022 at 2:06 PM Marco Elver &lt;<a href=3D"mailto:=
elver@google.com" target=3D"_blank">elver@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti<br>
&gt;&gt; &gt; &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com" target=
=3D"_blank">alexandre.ghiti@canonical.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; As reported by Aleksandr, syzbot riscv is broken since c=
ommit<br>
&gt;&gt; &gt; &gt; 54c5639d8f50 (&quot;riscv: Fix asan-stack clang build&qu=
ot;). This commit actually<br>
&gt;&gt; &gt; &gt; breaks KASAN_INLINE which is not fixed in this series, t=
hat will come later<br>
&gt;&gt; &gt; &gt; when found.<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; Nevertheless, this series fixes small things that made t=
he syzbot<br>
&gt;&gt; &gt; &gt; configuration + KASAN_OUTLINE fail to boot.<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; Note that even though the config at [1] boots fine with =
this series, I<br>
&gt;&gt; &gt; &gt; was not able to boot the small config at [2] which fails=
 because<br>
&gt;&gt; &gt; &gt; kasan_poison receives a really weird address 0x407570630=
1000000 (maybe a<br>
&gt;&gt; &gt; &gt; kasan person could provide some hint about what happens =
below in<br>
&gt;&gt; &gt; &gt; do_ctors -&gt; __asan_register_globals):<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; asan_register_globals is responsible for poisoning redzones a=
round<br>
&gt;&gt; &gt; globals. As hinted by &#39;do_ctors&#39;, it calls constructo=
rs, and in this<br>
&gt;&gt; &gt; case a compiler-generated constructor that calls<br>
&gt;&gt; &gt; __asan_register_globals with metadata generated by the compil=
er. That<br>
&gt;&gt; &gt; metadata contains information about global variables. Note, t=
hese<br>
&gt;&gt; &gt; constructors are called on initial boot, but also every time =
a kernel<br>
&gt;&gt; &gt; module (that has globals) is loaded.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; It may also be a toolchain issue, but it&#39;s hard to say. I=
f you&#39;re<br>
&gt;&gt; &gt; using GCC to test, try Clang (11 or later), and vice-versa.<b=
r>
&gt;&gt;<br>
&gt;&gt; I tried 3 different gcc toolchains already, but that did not fix t=
he<br>
&gt;&gt; issue. The only thing that worked was setting asan-globals=3D0 in<=
br>
&gt;&gt; scripts/Makefile.kasan, but ok, that&#39;s not a fix.<br>
&gt;&gt; I tried to bisect this issue but our kasan implementation has been=
<br>
&gt;&gt; broken quite a few times, so it failed.<br>
&gt;&gt;<br>
&gt;&gt; I keep digging!<br>
&gt;&gt;<br>
&gt;<br>
&gt; The problem does not reproduce for me with GCC 11.2.0: kernels built w=
ith both [1] and [2] are bootable.<br>
<br>
Do you mean you reach userspace? Because my image boots too, and fails<br>
at some point:<br>
<br>
[=C2=A0 =C2=A0 0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, w=
raps<br>
every 4398046511100ns<br>
[=C2=A0 =C2=A0 0.015847] Console: colour dummy device 80x25<br>
[=C2=A0 =C2=A0 0.016899] printk: console [tty0] enabled<br>
[=C2=A0 =C2=A0 0.020326] printk: bootconsole [ns16550a0] disabled<br>
<br></blockquote><div><br></div><div>In my case, QEMU successfully boots to=
 the login prompt.</div><div>I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) =
and an image Aleksandr shared with me (guess it was built according to this=
 instruction:=C2=A0<a href=3D"https://github.com/google/syzkaller/blob/mast=
er/docs/linux/setup_linux-host_qemu-vm_riscv64-kernel.md">https://github.co=
m/google/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_riscv64-=
kernel.md</a>)</div><div>=C2=A0</div><blockquote class=3D"gmail_quote" styl=
e=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);paddin=
g-left:1ex">
It traps here.<br>
<br>
&gt; FWIW here is how I run them:<br>
&gt;<br>
&gt; qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \<br>
&gt;=C2=A0 =C2=A0-device virtio-rng-pci -machine virt -device \<br>
&gt;=C2=A0 =C2=A0virtio-net-pci,netdev=3Dnet0 -netdev \<br>
&gt;=C2=A0 =C2=A0user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529=
-:22 -device \<br>
&gt;=C2=A0 =C2=A0virtio-blk-device,drive=3Dhd0 -drive \<br>
&gt;=C2=A0 =C2=A0file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot =
\<br>
&gt;=C2=A0 =C2=A0-kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append &q=
uot;root=3D/dev/vda<br>
&gt;=C2=A0 =C2=A0console=3DttyS0 earlyprintk=3Dserial&quot;<br>
&gt;<br>
&gt;<br>
&gt;&gt;<br>
&gt;&gt; Thanks for the tips,<br>
&gt;&gt;<br>
&gt;&gt; Alex<br>
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
om/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPok1awb20xifYmid=
w%40mail.gmail.com" rel=3D"noreferrer" target=3D"_blank">https://groups.goo=
gle.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPok1awb20xi=
fYmidw%40mail.gmail.com</a>.<br>
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
om/d/msgid/kasan-dev/CAG_fn%3DVZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWfVP_Q%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DVZ3fS7ekmJknQ6sW5zC09iUT9mzWjEhyrn3NaAWf=
VP_Q%40mail.gmail.com</a>.<br />

--0000000000004abcc205d8d88dea--
