Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ6G4OIAMGQEKFHBCGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 720A04C471E
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 15:10:49 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id e7-20020a17090a4a0700b001bc5a8c533esf3336233pjh.4
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 06:10:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645798248; cv=pass;
        d=google.com; s=arc-20160816;
        b=G9YJesE92xBZMsThp4ruppsjcldx7wSE6IVOpibMzN6BXWbvFiIHzOjDLcW4lpUFjd
         3TnooxmeMzey4CfVahi1Jw8Zgrpd5KZvgGeIXrwlBluWVyPH59vaAePWNjMpY0HawinN
         FsUca72ISU10mkD8iGuwZHg03GBPlCmmqn2kTsU2z3Bjc+7+f6Nvob8kMw3TjmMvLHQ0
         uIQeEFt5g1BZG4KWgpyMJQoy1H4PsS7RvWhNxlLWk/z3tMnULTQnQmCLNp7RGlWgjCtM
         tv90jwGfbHyzjEUg0bCz423keDsHmKL8egT8/qCyGJABrgVf5lgX6ObamfK/qO0A04t3
         zS5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t0LORBSr/zDQy+fEmSN7hmtHV+uLfoqg5Qj9Z1JTm+4=;
        b=DGAVHzciQ6DeCYJEuCdN83avTFPTAibCJdit5TRH0SHEUW7SikwFG7OKAkMg6kdrQV
         GDZ979EwuQEYhELyzw+oJXXsfaJfWe5ect0pWP5tyxZIUtMf7nUKH3oynLNqr41rnXAJ
         vOkQOooPxQTSMX9w6NKyGPzTzVmvYh0rwev50G1ntay+mXPvosw5GNUlbIyNm/hDbbe0
         QPBCjn8VVj3/c3YCrDJ/pyYjf7MtBcdZ3jix7+RWVi2Y3zX4Mb3v48HOgphcMu7KxQkf
         k0/H52HL5TFodZUktaSMqN8p0MPMYPMVlweSr2LOL079MkFI8WI5R8VpfKDVi9ChSRwu
         JHSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAPDZ67o;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t0LORBSr/zDQy+fEmSN7hmtHV+uLfoqg5Qj9Z1JTm+4=;
        b=GIuIodOvdbbOiXleS77gBOraL+BcIGN10/FSqRbhweD6b7UbFFObDVt+4Np+9EoYbZ
         hDKk3lXJdxbHCMfWCqFRsOnYIIXzwKyqqBYqtPlqlJ5OK4iOQFjVktc8K8iONXcHL2lP
         WX/x6m7TYo18OJpc2Y+WXCEVWyeRR0ksfi2k1bqLBDyVIl6c8EgLwInujH8LNE8ej1v2
         YjcW0YlCKeE2AN+/DwPVgFPtRV6DqMS9wQbk9bOmWsXCf6PAs85GqTrZXPEENmn/kEnZ
         PxfG2SzOIiIQa5egR7bAPUg1gb9thcIs7nv2gyDPGAsWQK2TqaJ7UFIn3jJC4QU7fE8x
         eIJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t0LORBSr/zDQy+fEmSN7hmtHV+uLfoqg5Qj9Z1JTm+4=;
        b=Ca8B6xQsqVYHDGGxwzqNhQ95L0Th4C0LiJFugWgJraf6ZSzhTYB0LUXZnXCf5E0n3J
         kgMBCAvxLsOs86O1AkSsvL4pnsX0Wcr6xkCeX2RPsb4b1u7z8Qhpp3ngHrpvTprFjDzf
         vSxxuLw6ztu9/pZUzQ1XiV4FaRZYJMwj5nJsrtvOqIXoZ30C/KdwiKEFWXfs0PRB3HY8
         YiSA8llQDhxvrk0CLZrSwFDyGzXpUwZlGhVZF1EbRbcB40MCn6A3Y5GDcEraw6Hss1Rh
         mszROXMqs5yar7KlKrVOckNkySLZetAa8WdALHeDKeAt+92nf5sHuLZZBmHsbVWCojCu
         iJrQ==
X-Gm-Message-State: AOAM5306hWK0t8FuueifTG4t/M/yVAHAKXc/hppiNVo+Flz+IYRDp4e+
	2rUH0TZRAZ4+bFfQq1YxpFA=
X-Google-Smtp-Source: ABdhPJw77V6Vrp5JSk/RAUdR/y1e2Ti+YYzuIiO8AxeotmGElOzlY5jY8rWRMu7EO/aRm2kSFlgD+A==
X-Received: by 2002:a63:e52:0:b0:374:7b9f:1467 with SMTP id 18-20020a630e52000000b003747b9f1467mr6178685pgo.178.1645798247765;
        Fri, 25 Feb 2022 06:10:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2281:b0:4bb:fb5e:8a19 with SMTP id
 f1-20020a056a00228100b004bbfb5e8a19ls2847312pfe.0.gmail; Fri, 25 Feb 2022
 06:10:47 -0800 (PST)
X-Received: by 2002:a65:5888:0:b0:374:5575:ba08 with SMTP id d8-20020a655888000000b003745575ba08mr6212308pgu.375.1645798247065;
        Fri, 25 Feb 2022 06:10:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645798247; cv=none;
        d=google.com; s=arc-20160816;
        b=XF7YERn+GosVLucSLUFebjao5NiK0VIWd6sJyO/2gEyc7lDGuNAXag72+qn5MkicTG
         yVPgK2dIhCWMQ3T+2KX1gawzDXZ+WiMswFhWjN9utwfWzO1BNAGWpHIwTDwG6swkN57+
         fKv39Jwm4fr0OrWCJOShKzp0HjZfzNuaxZogm83EVXWoZzycwkcdS3mlB1RbTivcbrr5
         ETT0L6I9bK9Y2nEIastCyYQOwP/6jddInPdKMzbsZlDU1CP9E4+YWoqE7+qXxBVtjRmv
         WTykMDXmlvZZc6pGaeZxg7Cp5Ew0pK/Wb5VV16foKtcE+V73jc7DsWIPoW+Cuolx2ppM
         yYjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=71c21WSmodoMP+jfj0UBMna3f3BLsuJwnWcdBkHE/Tw=;
        b=pk+wgmMNRr6pGlZIqfmBibxKy1YTm1H9OVZNAZzr4pLvCq/IsmSaabgbmrBL1s8y2F
         nlIGbuRuD7pvSU2e8+EHgF3Y8gcvnAMV+Cu+sMBB/GR3tT2kTC7ahd+lIs5Fhlayrn+q
         p7PsIwmdEnzroAM6DcRnhuw1wvDb2PLZxACjUfq9gR7H9kx5KlYbU16wyqoqU7pG+Zwt
         DeBBSzcJFn+0+uGObe9SnneDjFtrEZ2W8feaeam/B5PpNESxA4Sa0L0MCHyU+0PY4l5/
         Ho7m44PN38lkBOZ2Kjj/40VHuQuFCZ6dXQQBq1pAJpp7Pz7Zg74VwV4KxFZQmEV60Dl4
         LZeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAPDZ67o;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id j4-20020a170902c08400b0014f88317850si158131pld.10.2022.02.25.06.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Feb 2022 06:10:47 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id z66so4523352qke.10
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 06:10:47 -0800 (PST)
X-Received: by 2002:a37:a505:0:b0:60d:df5e:16c7 with SMTP id
 o5-20020a37a505000000b0060ddf5e16c7mr4917144qke.448.1645798246033; Fri, 25
 Feb 2022 06:10:46 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
 <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com> <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
In-Reply-To: <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Feb 2022 15:10:10 +0100
Message-ID: <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000d433f205d8d843ab"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sAPDZ67o;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
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

--000000000000d433f205d8d843ab
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
alexandre.ghiti@canonical.com> wrote:

> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > As reported by Aleksandr, syzbot riscv is broken since commit
> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit
> actually
> > > breaks KASAN_INLINE which is not fixed in this series, that will come
> later
> > > when found.
> > >
> > > Nevertheless, this series fixes small things that made the syzbot
> > > configuration + KASAN_OUTLINE fail to boot.
> > >
> > > Note that even though the config at [1] boots fine with this series, =
I
> > > was not able to boot the small config at [2] which fails because
> > > kasan_poison receives a really weird address 0x4075706301000000 (mayb=
e
> a
> > > kasan person could provide some hint about what happens below in
> > > do_ctors -> __asan_register_globals):
> >
> > asan_register_globals is responsible for poisoning redzones around
> > globals. As hinted by 'do_ctors', it calls constructors, and in this
> > case a compiler-generated constructor that calls
> > __asan_register_globals with metadata generated by the compiler. That
> > metadata contains information about global variables. Note, these
> > constructors are called on initial boot, but also every time a kernel
> > module (that has globals) is loaded.
> >
> > It may also be a toolchain issue, but it's hard to say. If you're
> > using GCC to test, try Clang (11 or later), and vice-versa.
>
> I tried 3 different gcc toolchains already, but that did not fix the
> issue. The only thing that worked was setting asan-globals=3D0 in
> scripts/Makefile.kasan, but ok, that's not a fix.
> I tried to bisect this issue but our kasan implementation has been
> broken quite a few times, so it failed.
>
> I keep digging!
>
>
The problem does not reproduce for me with GCC 11.2.0: kernels built with
both [1] and [2] are bootable.
FWIW here is how I run them:

qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
  -device virtio-rng-pci -machine virt -device \
  virtio-net-pci,netdev=3Dnet0 -netdev \
  user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -device \
  virtio-blk-device,drive=3Dhd0 -drive \
  file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
  -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append "root=3D/dev/vda
  console=3DttyS0 earlyprintk=3Dserial"



> Thanks for the tips,
>
> Alex
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
kasan-dev/CAG_fn%3DWYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA%40mail.gmai=
l.com.

--000000000000d433f205d8d843ab
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Feb 25, 2022 at 3:04 PM Alexa=
ndre Ghiti &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com">alexandre.g=
hiti@canonical.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote=
" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);=
padding-left:1ex">On Fri, Feb 25, 2022 at 2:06 PM Marco Elver &lt;<a href=
=3D"mailto:elver@google.com" target=3D"_blank">elver@google.com</a>&gt; wro=
te:<br>
&gt;<br>
&gt; On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti<br>
&gt; &lt;<a href=3D"mailto:alexandre.ghiti@canonical.com" target=3D"_blank"=
>alexandre.ghiti@canonical.com</a>&gt; wrote:<br>
&gt; &gt;<br>
&gt; &gt; As reported by Aleksandr, syzbot riscv is broken since commit<br>
&gt; &gt; 54c5639d8f50 (&quot;riscv: Fix asan-stack clang build&quot;). Thi=
s commit actually<br>
&gt; &gt; breaks KASAN_INLINE which is not fixed in this series, that will =
come later<br>
&gt; &gt; when found.<br>
&gt; &gt;<br>
&gt; &gt; Nevertheless, this series fixes small things that made the syzbot=
<br>
&gt; &gt; configuration + KASAN_OUTLINE fail to boot.<br>
&gt; &gt;<br>
&gt; &gt; Note that even though the config at [1] boots fine with this seri=
es, I<br>
&gt; &gt; was not able to boot the small config at [2] which fails because<=
br>
&gt; &gt; kasan_poison receives a really weird address 0x4075706301000000 (=
maybe a<br>
&gt; &gt; kasan person could provide some hint about what happens below in<=
br>
&gt; &gt; do_ctors -&gt; __asan_register_globals):<br>
&gt;<br>
&gt; asan_register_globals is responsible for poisoning redzones around<br>
&gt; globals. As hinted by &#39;do_ctors&#39;, it calls constructors, and i=
n this<br>
&gt; case a compiler-generated constructor that calls<br>
&gt; __asan_register_globals with metadata generated by the compiler. That<=
br>
&gt; metadata contains information about global variables. Note, these<br>
&gt; constructors are called on initial boot, but also every time a kernel<=
br>
&gt; module (that has globals) is loaded.<br>
&gt;<br>
&gt; It may also be a toolchain issue, but it&#39;s hard to say. If you&#39=
;re<br>
&gt; using GCC to test, try Clang (11 or later), and vice-versa.<br>
<br>
I tried 3 different gcc toolchains already, but that did not fix the<br>
issue. The only thing that worked was setting asan-globals=3D0 in<br>
scripts/Makefile.kasan, but ok, that&#39;s not a fix.<br>
I tried to bisect this issue but our kasan implementation has been<br>
broken quite a few times, so it failed.<br>
<br>
I keep digging!<br>
<br></blockquote><div><br></div><div>The problem does not reproduce for me =
with GCC 11.2.0: kernels built with both [1] and [2] are bootable.</div><di=
v>FWIW here is how I run them:</div><div><br></div><div>qemu-system-riscv64=
 -m 2048 -smp 1 -nographic -no-reboot \<br>=C2=A0 -device virtio-rng-pci -m=
achine virt -device \<br>=C2=A0 virtio-net-pci,netdev=3Dnet0 -netdev \<br>=
=C2=A0 user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -devi=
ce \<br>=C2=A0 virtio-blk-device,drive=3Dhd0 -drive \<br>=C2=A0 file=3D${IM=
AGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \<br>=C2=A0 -kernel ${KERNEL=
_SRC_DIR}/arch/riscv/boot/Image -append &quot;root=3D/dev/vda <br>=C2=A0 co=
nsole=3DttyS0 earlyprintk=3Dserial&quot;<br></div><div><br></div><div>=C2=
=A0</div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8e=
x;border-left:1px solid rgb(204,204,204);padding-left:1ex">
Thanks for the tips,<br>
<br>
Alex<br>
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
om/d/msgid/kasan-dev/CAG_fn%3DWYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DWYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWz=
RJfA%40mail.gmail.com</a>.<br />

--000000000000d433f205d8d843ab--
