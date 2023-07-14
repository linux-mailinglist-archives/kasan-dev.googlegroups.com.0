Return-Path: <kasan-dev+bncBCKMP2VK2UCRBL5CYWSQMGQEUGXQW4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 30AE5753BF4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 15:44:17 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3476d004218sf9605975ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 06:44:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689342255; cv=pass;
        d=google.com; s=arc-20160816;
        b=gynfipqrDLBZzRr2mj3wAAXLPyiHfsNUu+nw4Ls8XREpasle2JLlVsRaOyIcZTt1zL
         69WmweKfmVXPhHoTxdf4uHngt5UVbPbV9gX9+lFk81CIoc2dq9gBK1fi4fSlULWr+ljQ
         u3FKPXJA+Daz69YAtM8JKM/NWcJap3x3FgYyNMJk40F1rUtkLr1nvaT16eOI2GpYQUIy
         jrsjaSFbz0dtK1s44fS/362PLiKDBmyVLuD0rqjE1m3Y3rJzBMaPYaS+F4z0zDmq8Ltq
         ab7OLJyCh9ai3A4r7BFg9m58WFnLVFzNIB8mpOBReANLX92NiDN7aeAmJ2tQIcAIyr2o
         d+Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=LSv/Q5jIe1Pyu1yKZYjLBbb7sKrrf9P27r0j4cDJaqU=;
        fh=lXFUZMS941d04+4jU8I8x/fMNcWRuf86qM1jb1eonG4=;
        b=iLvMgFxQGwamEisCRmUOP1aU+XyzIDOfZJu1KpaFGngN8/D39uJv0CUaapyE37YGy1
         YbHe8CJ0oD+L/UZHtQLVZVu+HNPwBXEHGMYp98QlX4y0QBPBF+1XACWgP8MX2rWWv+5R
         l8KvlwRNpiHZcouEMoeO3+ryzwOCUzINR70Nrxr8hAWbLLa/NnETwGG9uyXF32Kj7V8A
         tZaAa3aUuhOgVpbCbnP88Tw4ULwJX4vFu578PeSDDjlEESDg7BvS++5lRRM4z8LPogQp
         qyN79L1sTqydjBniP9ho/8iLIOs10bS7oA48Gi8+T/Fm3RKOZHTFrlMzWty0O47abrLN
         vvxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.179 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689342255; x=1691934255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LSv/Q5jIe1Pyu1yKZYjLBbb7sKrrf9P27r0j4cDJaqU=;
        b=XP266Xolgg/xoushPN6+LeJNnNPInrxiqztVkpWI1ll/yMVAYa0IvuCJWJntG2wAjH
         WCHKs8WeVKD9rCXpm26NW3ISDKBLSVqTb8FBHmSk4ATw58bpG8CsHhPyu01Gopm4qeBw
         077MQYPfmgC0YrblfPMXVPFCIG8r0YVb39V6VEs+qV7udZhVwxdyfbVxrV0RHAAQfX2K
         zvpOseSCLItPrv/KEHWWQNolQJpzVNa8yVa82/Ob9D2YS++YIi/ufSdQUQHzfzHQChIn
         uJ66zm7GXXrQxbT3tSEXTedeEx7IbmN51wIF59RFdseT1f2sQewnAA8IDsIpblVfXZE4
         Avtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689342255; x=1691934255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LSv/Q5jIe1Pyu1yKZYjLBbb7sKrrf9P27r0j4cDJaqU=;
        b=j/lTaLdyvqO9a0DTtSkk+HnRJs6lecsaaQBtU7Bk29Okwb3j3IFy7UqeK6W5R6p5G8
         RaMyReLmcqydupcwaxi2MeENmoYdAsgdNxcqhxQ7DVOiFSB3y9oVllcp1d7R+q8xaCFH
         9prp49dee/0t/jQNrREBfJsUtsK+rZmbW8PHfgQxa+ruHpn5YQ4gBuFm0xxTDzSExNyR
         IQmF9ax7dytcRLnij8bi+JHoetRH15VBwk75B3xvu/9htMLihvUZuqS5CfIj7lTvi0qw
         qY4UUleIhjOH0unP4Sy86NhZtsy75lgHr+Uz79sfo2/KKoVk+sHVzHB7eMdPQyBkTcud
         O0UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbWzPEpsXHDwiPGknYkX3mus4dpBfw0Pymqlxp4VQNcO5E7BZVJ
	aPWCbOp81WPbrhUHpU7+6tY=
X-Google-Smtp-Source: APBJJlHfhFq8O3u+vIwJAyl8Mjrbs6yyCsSAnccMhRT+6k90yjfmYByuNkCDXhGdF2LRe8r4+ekIMA==
X-Received: by 2002:a92:d1cf:0:b0:347:712c:dc9 with SMTP id u15-20020a92d1cf000000b00347712c0dc9mr3721344ilg.22.1689342255391;
        Fri, 14 Jul 2023 06:44:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a4a:b0:331:3e55:550f with SMTP id
 u10-20020a056e021a4a00b003313e55550fls106038ilv.0.-pod-prod-06-us; Fri, 14
 Jul 2023 06:44:14 -0700 (PDT)
X-Received: by 2002:a6b:7502:0:b0:785:ccac:a4db with SMTP id l2-20020a6b7502000000b00785ccaca4dbmr4396715ioh.2.1689342254594;
        Fri, 14 Jul 2023 06:44:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689342254; cv=none;
        d=google.com; s=arc-20160816;
        b=hyY3DNXwQvBdFhTK30/BgbqkiheDzvw2b6bXxMrlHaaWPGC8pfH8s2Y7tFV3uVDPqC
         UVo070QO4QBVY2avPXVOxIIODXuPnmqNDPWi7X12lNXHO9Nqbb3jqxpWzA4hqNs9WDn7
         gQ2S6yI4UisguTfRoZakopdm8fbelr/bxPkoGwhtv8MbFYTO2p2rrRrorzBfJQY57icI
         2UmsmiePY1F4z8Ojhrk1VGKHw7kBxbeXH5teJThmvyD4q+xjjqFnvTEZtH6SkcNld6dd
         Jo+20S5Z8xdxzVrv5p29jAMJcDeh0Gfto0OFDkW7Urirh9NGsK9s311NEA0HBZYkCTFo
         1nYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=Kunn7mBXj6lSBqc54P84TAqC3feuCArqGOrvRUo14ag=;
        fh=lXFUZMS941d04+4jU8I8x/fMNcWRuf86qM1jb1eonG4=;
        b=VceTPM6COoAuzBvJUNrmOUKVDmCw7ouph76k507hGeGFo9nOuxjgoLmhath1IEZhCo
         P+o4jgMZQma2uHxoTPbxovdib3rOVGxApRjaRSmX9N5YQbYhC779VpoXtEU7eswrPxQY
         SYV9xrOQAT3+fUKi04qnTJF5VxM7SoKqELew7WZyZ/Mz/o0jNwaG1zaLn0S7AiPt3mZG
         5hhqALbN1y+kSMXlvuh8p4R7hObj8IiiqgoI3JjrIVOQXvRfpuqTmqMbHtTeNXwiPw7z
         wlW0pgRBR3if/q/DvI/670RIGQ2NeoYjXkFRg8nFqaL2WDk+xbmQSAZ2I+YCde2L2dCO
         yJxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.179 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-yb1-f179.google.com (mail-yb1-f179.google.com. [209.85.219.179])
        by gmr-mx.google.com with ESMTPS id ee7-20020a056602488700b0078360746879si494359iob.0.2023.07.14.06.44.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jul 2023 06:44:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.179 as permitted sender) client-ip=209.85.219.179;
Received: by mail-yb1-f179.google.com with SMTP id 3f1490d57ef6-cae0ad435b6so1881330276.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 06:44:14 -0700 (PDT)
X-Received: by 2002:a25:ad1f:0:b0:c3e:2a69:7937 with SMTP id y31-20020a25ad1f000000b00c3e2a697937mr4361550ybi.22.1689342253579;
        Fri, 14 Jul 2023 06:44:13 -0700 (PDT)
Received: from mail-yb1-f177.google.com (mail-yb1-f177.google.com. [209.85.219.177])
        by smtp.gmail.com with ESMTPSA id f8-20020a25cf08000000b00c64533e4e20sm1866649ybg.33.2023.07.14.06.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Jul 2023 06:44:13 -0700 (PDT)
Received: by mail-yb1-f177.google.com with SMTP id 3f1490d57ef6-cb7b6ecb3cdso1280560276.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 06:44:13 -0700 (PDT)
X-Received: by 2002:a25:848d:0:b0:cb5:f3da:6583 with SMTP id
 v13-20020a25848d000000b00cb5f3da6583mr3378457ybk.44.1689342253022; Fri, 14
 Jul 2023 06:44:13 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
 <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
 <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
 <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
 <CANpmjNN-zypOUdJ-7XW0nN+gbGFwxC-JPFs=WA8FipsKiBhbKw@mail.gmail.com> <CAAhV-H7YLDQjVi8YKSv2ezz+d_wj3RPhnNchsh=HRwrf02rrCw@mail.gmail.com>
In-Reply-To: <CAAhV-H7YLDQjVi8YKSv2ezz+d_wj3RPhnNchsh=HRwrf02rrCw@mail.gmail.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Fri, 14 Jul 2023 15:43:55 +0200
X-Gmail-Original-Message-ID: <CAMuHMdUPnzfwPcTLUReVpbX5UyBdBVocWdLVAEYTyJryZ8VRcQ@mail.gmail.com>
Message-ID: <CAMuHMdUPnzfwPcTLUReVpbX5UyBdBVocWdLVAEYTyJryZ8VRcQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Huacai Chen <chenhuacai@loongson.cn>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.179
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Huacai,

On Fri, Jul 14, 2023 at 8:23=E2=80=AFAM Huacai Chen <chenhuacai@kernel.org>=
 wrote:
> On Thu, Jul 13, 2023 at 6:09=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> > On Thu, 13 Jul 2023 at 11:58, Huacai Chen <chenhuacai@kernel.org> wrote=
:
> > > On Thu, Jul 13, 2023 at 4:12=E2=80=AFPM Marco Elver <elver@google.com=
> wrote:
> > > > On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org> w=
rote:
> > > > > On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andrey=
knvl@gmail.com> wrote:
> > > > > > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuaca=
i@loongson.cn> wrote:
> > > > > > >
> > > > > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for m=
emset()/
> > > > > > > memcpy()/memmove() if instrumentation is needed. This is the =
default
> > > > > > > behavior but some archs pass -ffreestanding which implies -fn=
o-builtin,
> > > > > > > and then causes some kasan tests fail. So we remove -ffreesta=
nding for
> > > > > > > kasan tests.
> > > > > >
> > > > > > Could you clarify on which architecture you observed tests fail=
ures?
> > > > > Observed on LoongArch [1], KASAN for LoongArch was planned to be
> > > > > merged in 6.5, but at the last minute I found some tests fail wit=
h
> > > > > GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches ar=
e
> > > > > dropped. After some debugging we found the root cause is
> > > > > -ffreestanding.
> > > > [...]
> > > > > > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > > > > > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
> > > >
> > > > It makes sense that if -ffreestanding is added everywhere, that thi=
s
> > > > patch fixes the test. Also see:
> > > > https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.com
> > > >
> > > > -ffreestanding implies -fno-builtin, which used to be added to the
> > > > test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).
> > > >
> > > > But ideally, the test doesn't have any special flags to make it pas=
s,
> > > > because ultimately we want the test setup to be as close to other
> > > > normal kernel code.
> > > >
> > > > What this means for LoongArch, is that the test legitimately is
> > > > pointing out an issue: namely that with newer compilers, your curre=
nt
> > > > KASAN support for LoongArch is failing to detect bad accesses withi=
n
> > > > mem*() functions.
> > > >
> > > > The reason newer compilers should emit __asan_mem*() functions and
> > > > replace normal mem*() functions, is that making mem*() functions
> > > > always instrumented is not safe when e.g. called from uninstrumente=
d
> > > > code. One problem is that compilers will happily generate
> > > > memcpy/memset calls themselves for e.g. variable initialization or
> > > > struct copies - and unfortunately -ffreestanding does _not_ prohibi=
t
> > > > compilers from doing so: https://godbolt.org/z/hxGvdo4P9
> > > >
> > > > I would propose 2 options:
> > > >
> > > > 1. Removing -ffreestanding from LoongArch. It is unclear to me why
> > > > this is required. As said above, -ffreestanding does not actually
> > > > prohibit the compiler from generating implicit memset/memcpy. It
> > > > prohibits some other optimizations, but in the kernel, you might ev=
en
> > > > want those optimizations if common libcalls are already implemented
> > > > (which they should be?).
> > > >
> > > > 2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
> > > > aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
> > > > you'd have to invert how you currently set up __mem and mem functio=
ns:
> > > > the implementation is in __mem*, and mem* functions alias __mem* -o=
r-
> > > > if KASAN is enabled __asan_mem* functions (ifdef
> > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers work =
as
> > > > well).
> > > >
> > > > If you go with option #2 you are accepting the risk of using
> > > > instrumented mem* functions from uninstrumented files/functions. Th=
is
> > > > has been an issue for other architectures. In many cases you might =
get
> > > > lucky enough that it doesn't cause issues, but that's not guarantee=
d.
> > > Thank you for your advice, but we should keep -ffreestanding for
> > > LoongArch, even if it may cause failing to detect bad accesses.
> > > Because now the __builtin_memset() assumes hardware supports unaligne=
d
> > > access, which is not the case for Loongson-2K series. If removing
> > > -ffreestanding, Loongson-2K gets a poor performance.
> > >
> > > On the other hand, LoongArch is not the only architecture use
> > > -ffreestanding, e.g., MIPS, X86_32, M68K and Xtensa also use, so the
> > > tests should get fixed.
> >
> > That's fair - in which case, I would recommend option #2 or some
> > variant of it. Because fixing the test by removing -ffreestanding is
> > just hiding that there's a real issue that needs to be fixed to have
> > properly working KASAN on LoongArch.
>
> After some thinking, I found we can remove -ffreestanding in the arch
> Makefile when KASAN is enabled -- because it is not the performance
> critical configuration. And then, this patch can be dropped, thank
> you.

Doesn't this introduce an unwanted impact?

And it's not just arch makefiles:

crypto/Makefile:CFLAGS_aegis128-neon-inner.o +=3D -ffreestanding
-march=3Darmv8-a -mfloat-abi=3Dsoftfp
crypto/Makefile:aegis128-cflags-y :=3D -ffreestanding -mcpu=3Dgeneric+crypt=
o
lib/Makefile:CFLAGS_string.o :=3D -ffreestanding
lib/raid6/Makefile:NEON_FLAGS :=3D -ffreestanding

Gr{oetje,eeting}s,

                        Geert

--=20
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdUPnzfwPcTLUReVpbX5UyBdBVocWdLVAEYTyJryZ8VRcQ%40mail.gmail.=
com.
