Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZU2X6SQMGQESJHEECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CB16751E78
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 12:09:44 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2b6fdb7eeafsf5000041fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 03:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689242983; cv=pass;
        d=google.com; s=arc-20160816;
        b=aXW9FIqOLjdvgDRYnwOZUpPSqk/dnaSn4Ta1Z3llrjZ0JqzzE+DZqP7HzNfdKg6jZP
         ACjwfisrsScg0S9VRYtgZk0niw9PRKmDzMtMhKmScpPS9zxVDqu5qnQj+lF7cBCi5hXo
         UDOj7zJsVcaX1Rmrv2XKoocSHguicr/+3Bb+2hHgvYJqpuCyTRH45EW8uZ+HAQ9kqYHh
         4xcjJcV64yE//LyqWWmZfMcvfBYBev2GWZXMe6e4jUzTDWs0hBepz9znzCMKVHSvO0H4
         rilTmS1moenq9z440dpgyWpPOgEULr4KqAkw0v5lqzXkjwzPlJ0VlK+a85h2O4QwpDIK
         T6CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N8bqsO0lJShsEcs3OEAsNFi5sf7qYCyWM0zANouCJJ4=;
        fh=HEeri+fgzgF1pvJBLUJC/ziUJ55VCcdomH/MOUdH4TA=;
        b=w8W87uwOrQTR9pLRkAZkw7HJgBTha8M2s8SRkleU2qYFTEqZ5MADTEE1OZr7MxwwKu
         r0MZRcFTzKLPdr/yU/sB5OfH9IzbJPsMBE2sqYPLf3u8ATQV+Xzxj5n6I2dtip3gU3JX
         gKJ6rqR6IncyEbeFn7EJ+EXkxyEWTIChk9o/m0EUwpLYfQBWRxgzTNmILYsPdNaHMh0J
         CZosLkxWUuBYE7DgCFK9/IfXW/JPPqkM8uJDyPv4FZ5od63l/YzS6AJ/AZ+oQhBocwgC
         P6blZMKZeDMhm9L0nLKJt9MGc+lL+TfBunbvtfkFG0rwOj8TsQ1IqSfFMN1CNz6lo5Rq
         w9XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DgKqY0bq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689242983; x=1691834983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N8bqsO0lJShsEcs3OEAsNFi5sf7qYCyWM0zANouCJJ4=;
        b=HYcbtYzOHpnslbBOaLurcHHu2j4KFhRDNG9579LI281w0nNr5nrYQR1wD26r43hVHb
         0cuqsKzOWScElEHZ5nOTnqfICLfOzv17cByColg2FZG53TJadVFTBheuGdFr5ZD55MER
         z9f6VSYbrxWDKOG1+CnbkQwEAbhLbtIm6KqkOAcfUOG+EZUVyJKJhS4WXssqav2ucVJ2
         XhEFsHxx45Kee+YlacRYOWSYAyK7jJI8IakJ5BmLgA/h/jZgs2V95PXLtyX9cLZLadxK
         SKW0GvkaIVZHvH7+c/fGuBOuiZ8S7fMMaa5NyP7haFCFO65OjRuSd8ke/0OZQBcE++Wl
         QDTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689242983; x=1691834983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N8bqsO0lJShsEcs3OEAsNFi5sf7qYCyWM0zANouCJJ4=;
        b=IoYE3OfDvzb6XXI8VEIK7dpjZdcwN6/QYKcjJpnZNI8RuDjdFsO/aJZ9dPlq5VZhjH
         D7dReN31cHbpP26HtQ6YjnVVAiKZ3V/0nxooxnOnAUlOJRJC6lZAB6Cw8EKX5dpl3kYJ
         2B8zC+AKS5mFXZnOnDu+RKcwJafCGzvoolufSKY3f64RPjzRC5p3o1HGAVfzEbwTfSZp
         OeH+LbTSVfivNcquC5LoQYIXDuyEur/GniNPKVE2smEL6u63AHxbeJb2T7YAwQUy4SiM
         AuWpOun8Q49Lv1BmyOdhM8qoAxu+PcuDMwlkIyMe02zn+LvfbQUmhMOJNPWnLv8N11IJ
         UEeA==
X-Gm-Message-State: ABy/qLbV+r4NgGJ49qQGo6TGMCSi/jgAoI92wYfekW6xISaYVvLcbin9
	klAWeNM1j5hiWZCuai0I6mM=
X-Google-Smtp-Source: APBJJlH/uHzJQU2HlBKxtibeaGQPiszlk34nToZ2UR3j/LD8ynHBjTJuXWk4OJOz7gV7YvviXXwYAw==
X-Received: by 2002:a2e:8807:0:b0:2b7:18ff:ba63 with SMTP id x7-20020a2e8807000000b002b718ffba63mr910180ljh.37.1689242982898;
        Thu, 13 Jul 2023 03:09:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c7:b0:2b6:ec06:1821 with SMTP id
 d7-20020a05651c01c700b002b6ec061821ls171144ljn.0.-pod-prod-01-eu; Thu, 13 Jul
 2023 03:09:40 -0700 (PDT)
X-Received: by 2002:a05:6512:b2a:b0:4f8:5e49:c613 with SMTP id w42-20020a0565120b2a00b004f85e49c613mr879415lfu.43.1689242980517;
        Thu, 13 Jul 2023 03:09:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689242980; cv=none;
        d=google.com; s=arc-20160816;
        b=JpXBz45A4JDfnkKjHrSwxTReFeZRqQ7hYFg/EkgwcnIWQyLg3Sc4X9YGQ+FBo7O7t8
         SgpjqPssdrIzhR86XS8wV3Y5i6fuwb8FnjAZZrlsh/HHYosKrGf3+dgdMoC7E1VS3vMn
         R+qLltEt8UviSreXlFT4FS7aeQVcEk2DL8TewBKLVSgKxbvS55ml7OH3VWOvKop/8RyZ
         uV6d7LeXIvap35n7HaerkPhzKoNyg/uSpRM/PEmRJcqua9Xp83BFf6OJuIssIdSC3nZa
         8ICPl3HTPgY4HX5nmarcqhkwp/8aNXiaqvv/gBsk3EwfZKO56o5ad8OcVMY9eQJl+3fM
         q7Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HlEGorW8l9E/UYv5LNvre41VRn1sbOFHWBTcePkBvLM=;
        fh=2hAGxa7g7VqtPPlK3wVxmTgQGiCIRbvXF89XdKNrIsE=;
        b=q6kn9IvQfrBHXk5lITca4ngksU0iu8IYpTvXaja8cpBCcmGBm7IefPldIJ8+e4uR5G
         hb4GEaFJ03OPKQxHwJU8Lu9ptnADpw8EFdUaz8QoM10VivsMaknDTV9sRlzyJH0znfBq
         N9joQ6jIi0EtM3l6l0Our0Wvji2zU3D5uD+R3lNsncDskV47BywafB4EtvJvDzlquIXr
         PzwT1UXEoVj8YBkwF1U6JiJqLCsBY3gC9gTCSdfWZTOqUoshlo7o103mfbuF9rqnbiT+
         r445D+dqxgL/MYwi9nbQMTziVU8ythtFSjhO41F5XTG1SSqiGMvkezWqnXOuqGSC1uNt
         ki5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=DgKqY0bq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id k41-20020a0565123da900b004fba307ab75si543009lfv.7.2023.07.13.03.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Jul 2023 03:09:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-2b703caf344so7209351fa.1
        for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 03:09:40 -0700 (PDT)
X-Received: by 2002:a2e:9054:0:b0:2b6:a22f:9fb9 with SMTP id
 n20-20020a2e9054000000b002b6a22f9fb9mr988809ljg.27.1689242979968; Thu, 13 Jul
 2023 03:09:39 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
 <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
 <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com> <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
In-Reply-To: <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Jul 2023 12:09:03 +0200
Message-ID: <CANpmjNN-zypOUdJ-7XW0nN+gbGFwxC-JPFs=WA8FipsKiBhbKw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Huacai Chen <chenhuacai@loongson.cn>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=DgKqY0bq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 13 Jul 2023 at 11:58, Huacai Chen <chenhuacai@kernel.org> wrote:
>
> Hi, Marco,
>
> On Thu, Jul 13, 2023 at 4:12=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org> wrote=
:
> > >
> > > Hi, Andrey,
> > >
> > > On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andreyknvl=
@gmail.com> wrote:
> > > > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@lo=
ongson.cn> wrote:
> > > > >
> > > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for memse=
t()/
> > > > > memcpy()/memmove() if instrumentation is needed. This is the defa=
ult
> > > > > behavior but some archs pass -ffreestanding which implies -fno-bu=
iltin,
> > > > > and then causes some kasan tests fail. So we remove -ffreestandin=
g for
> > > > > kasan tests.
> > > >
> > > > Could you clarify on which architecture you observed tests failures=
?
> > > Observed on LoongArch [1], KASAN for LoongArch was planned to be
> > > merged in 6.5, but at the last minute I found some tests fail with
> > > GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches are
> > > dropped. After some debugging we found the root cause is
> > > -ffreestanding.
> > [...]
> > > > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > > > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
> >
> > It makes sense that if -ffreestanding is added everywhere, that this
> > patch fixes the test. Also see:
> > https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.com
> >
> > -ffreestanding implies -fno-builtin, which used to be added to the
> > test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).
> >
> > But ideally, the test doesn't have any special flags to make it pass,
> > because ultimately we want the test setup to be as close to other
> > normal kernel code.
> >
> > What this means for LoongArch, is that the test legitimately is
> > pointing out an issue: namely that with newer compilers, your current
> > KASAN support for LoongArch is failing to detect bad accesses within
> > mem*() functions.
> >
> > The reason newer compilers should emit __asan_mem*() functions and
> > replace normal mem*() functions, is that making mem*() functions
> > always instrumented is not safe when e.g. called from uninstrumented
> > code. One problem is that compilers will happily generate
> > memcpy/memset calls themselves for e.g. variable initialization or
> > struct copies - and unfortunately -ffreestanding does _not_ prohibit
> > compilers from doing so: https://godbolt.org/z/hxGvdo4P9
> >
> > I would propose 2 options:
> >
> > 1. Removing -ffreestanding from LoongArch. It is unclear to me why
> > this is required. As said above, -ffreestanding does not actually
> > prohibit the compiler from generating implicit memset/memcpy. It
> > prohibits some other optimizations, but in the kernel, you might even
> > want those optimizations if common libcalls are already implemented
> > (which they should be?).
> >
> > 2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
> > aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
> > you'd have to invert how you currently set up __mem and mem functions:
> > the implementation is in __mem*, and mem* functions alias __mem* -or-
> > if KASAN is enabled __asan_mem* functions (ifdef
> > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers work as
> > well).
> >
> > If you go with option #2 you are accepting the risk of using
> > instrumented mem* functions from uninstrumented files/functions. This
> > has been an issue for other architectures. In many cases you might get
> > lucky enough that it doesn't cause issues, but that's not guaranteed.
> Thank you for your advice, but we should keep -ffreestanding for
> LoongArch, even if it may cause failing to detect bad accesses.
> Because now the __builtin_memset() assumes hardware supports unaligned
> access, which is not the case for Loongson-2K series. If removing
> -ffreestanding, Loongson-2K gets a poor performance.
>
> On the other hand, LoongArch is not the only architecture use
> -ffreestanding, e.g., MIPS, X86_32, M68K and Xtensa also use, so the
> tests should get fixed.

That's fair - in which case, I would recommend option #2 or some
variant of it. Because fixing the test by removing -ffreestanding is
just hiding that there's a real issue that needs to be fixed to have
properly working KASAN on LoongArch.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN-zypOUdJ-7XW0nN%2BgbGFwxC-JPFs%3DWA8FipsKiBhbKw%40mail.gm=
ail.com.
