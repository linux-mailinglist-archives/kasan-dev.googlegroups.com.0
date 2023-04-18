Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4Q7KQQMGQEWOMVTXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33F6E6E609D
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 14:07:37 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-63b64ada305sf1612418b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 05:07:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681819655; cv=pass;
        d=google.com; s=arc-20160816;
        b=XA7ZNAhkpiZ9SrxtVlrjAiLvLmZJiokik2zyzisS12AK42FftzAarWDGlssjShH/KQ
         scbfpZJ/NbJuUYJliloMvg3tsnYCwwksqxHwx5oMY8Vsan9kq1A7iTJy4qMFDPCQKz8z
         VM11kcPxpV1uSuy00WU4X54GCJ2ZI1oOY1rlrLaqr+KfWu5BhsqXUIGN+cnP38yYTkcp
         39c5UfRqyWF1sq9x3Y31HzowxBja6uJO2d6whEclofuTZrWOevnzguOzz0CqRycWH8rW
         AEEQHa+ouse8v0sy5XONrqw08YQGpM4pd+bbU9qeJRn9/0syvOT72I7GH7LQFlgR0/2C
         bH2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Gv5OTKUFPHh5i2eqhlTiNsPiMExun4okAPSqj5LcdyQ=;
        b=wpozuXvVqvFo52lt25xF073l57iJOvNpo/DiGLo8ZTmVr2HL6qHIUvwT6YF++Nxo1g
         iF4x5vbl/Cw1014JAiufO0Az1o75Qx6v88q5lCoFvvSns/LgIlHQlqTs4W6VAsfmK96T
         0aGiUhWdmEX4NIBMQuvT30j50U7ly/3jklP0mhVMbxJROqnM14bZkTgxEdzQFpfLzuse
         fD+BjjTak0fhHxy20IixdlD29HZIxiG/nx7C6DTiI2uZ6X1V7AEBYO2SFyRvYo6RWt+t
         zt/f53rMT12CINhJSwCFgC+FSiX2td4bBYYpMR/JTd+J9zMSFS8q8UlHISkwTlaGmeH4
         3z2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WOcobd9V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681819655; x=1684411655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Gv5OTKUFPHh5i2eqhlTiNsPiMExun4okAPSqj5LcdyQ=;
        b=EqT/y3lLx1yvSIyOuQLdhARltAWm9ERPzXb0FkqKNALbhUk5vwKVsebeXVkKHoUQtg
         PWzIZXDhsdOubpyazVyaGmdmdsadZgdSfN8JImUKTV666vuFOpn9XVj3hGBJnV48takR
         L9dWBduB6qAUFl7HmaQU6JIBQHICPJSDOGdXE2C6/pePvBaFITRplRDRN71DtIuuGMd2
         sa9FSKn9ynCgAMAEM7SNgHCgXE6ORIReeqS3/M6um/qiAK6fgQ1kNIplIuEFgdvScuI8
         B/S3xykZN2zGofLdFJ3AFk/Zs2FqvnVbaXO+iZ7nS5Z8Qz2hXF2U9fW3Hw02b85LdeVG
         7ymg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681819655; x=1684411655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Gv5OTKUFPHh5i2eqhlTiNsPiMExun4okAPSqj5LcdyQ=;
        b=hoVZWUvweo5SyLE4Tf2TfOer/uitQWfX9FqdT6QhdsUBaYbfdnVOQzmN697no28dKv
         mH2nubzx2cSAOpO0YlGgH0dcxaZr1VXIQ/1hlljKVxPW0w2+s3DRZYtL8g7QiTFWym/d
         GWO+EPzCM/KAeKZ0GkF14StcJeBroxj4x5aRoHQO9Ah7VIwTvhItQDN+6+V8p7kvwY7V
         a292zXWVnn1coH7gLXAt+SiUNagLllmaPvX5dB5NM5W7bNRolgOoMuWjmPyxd3hwD04n
         k63NQkSwoTKWM0KsdbTdDyVgccvaYFR4bFhnkiuvAAPLnXbQOBfGTRrGa04j9HyPtU9p
         qZcQ==
X-Gm-Message-State: AAQBX9e8mgBNpzF/ZLEEFY7djRfCwpklECCCPVHYHvKLuuJ+P1wUi2Vm
	3KLJrmp8Ti4Z5m+rdPpbX0VTTA==
X-Google-Smtp-Source: AKy350Z2qzaWfX98rjbl1FjAGIEX4ZBh3jGLrRGiJqRIiovZcJ+YdtOhWzu7h89DOjJiqaq7j7lP1g==
X-Received: by 2002:a05:6a00:2e82:b0:626:2343:76b0 with SMTP id fd2-20020a056a002e8200b00626234376b0mr9232358pfb.6.1681819655431;
        Tue, 18 Apr 2023 05:07:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c3ca:b0:1a1:a83b:2ab with SMTP id
 j10-20020a170902c3ca00b001a1a83b02abls9924440plj.7.-pod-prod-gmail; Tue, 18
 Apr 2023 05:07:34 -0700 (PDT)
X-Received: by 2002:a17:90a:7c06:b0:23d:15d8:1bc3 with SMTP id v6-20020a17090a7c0600b0023d15d81bc3mr1764473pjf.39.1681819654448;
        Tue, 18 Apr 2023 05:07:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681819654; cv=none;
        d=google.com; s=arc-20160816;
        b=bkih7vRcV8ZUQmaRRRAfhEHjyntNvEOL8Cvs16bpPgD70x9D8NcX0LN/glDoIICCAh
         +yIy8p5842l5RUFzrQUnrl6PAvrz0Xxf9PrMVfR9K+EeKGiuLOTgTOi6FFeFMVigCqCW
         ArlVm3tqTthVIqHxmmMdkZX4ppn7kDZUxAf4OCN2KARRk2Xo6DlMPvQIhLliPPm2FYFR
         B7mBDfofvm/qE3RqFnayNOxKG6VGEdUovxi6YwTd6JLc+gNV3zC8EK1+lbfFk1Xg4m1a
         BxCLHj99uuSC2g957yKEf7nUH2s++ggPI2y5iTcBWFPc9pzj/Z7/HuBrOe6mANThMOYm
         fS2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P5YkRvYf1yCuUPW+Kk1SNC+gRw+VoF5jM1xlyDbolaQ=;
        b=yDcH1zNelt+onRv2Ne/YN2C+GK9KmHT3D1+TmH+Gr6HEZmAfgrPMMfN92qM8XP+PEi
         K323IksXGVWyH+iNxjhsXYpkovLjmVfoEpcKDCtN7w70eplTqGnQnDpja24g+Dt9gNfB
         VsuBLk0wz/sjz93Uj/T+Vf+WLDkVVCZRNS7Q0R6yxIu8qLFQf7p5OAoRo+o1o5zzPupC
         Y3CeWKXkA+OdLLax58C8IT/e8HzRXNk7Llwn6sgSczUoHpkAEjUObH1lFcB0HybpY0wv
         EQtM/PStHoZdQzzuHdN02GEX5UTKy8v8X9tEiSCDOyjIb1lr+NzZ+JnhgIoRPfwzlWl2
         NYNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=WOcobd9V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id oc3-20020a17090b1c0300b00246fa2ea350si132146pjb.1.2023.04.18.05.07.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 05:07:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-760a5e0f752so53181739f.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 05:07:34 -0700 (PDT)
X-Received: by 2002:a6b:e216:0:b0:74c:8cec:548e with SMTP id
 z22-20020a6be216000000b0074c8cec548emr1574390ioc.4.1681819653797; Tue, 18 Apr
 2023 05:07:33 -0700 (PDT)
MIME-Version: 1.0
References: <20230414082943.1341757-1-arnd@kernel.org> <20230414162605.GA2161385@dev-arch.thelio-3990X>
In-Reply-To: <20230414162605.GA2161385@dev-arch.thelio-3990X>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 14:06:57 +0200
Message-ID: <CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com>
Subject: Re: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for clang-14
To: Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Arnd Bergmann <arnd@arndb.de>, Nicolas Schier <nicolas@fjasle.eu>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Tom Rix <trix@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, "Peter Zijlstra (Intel)" <peterz@infradead.org>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=WOcobd9V;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as
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

On Fri, 14 Apr 2023 at 18:26, Nathan Chancellor <nathan@kernel.org> wrote:
>
> On Fri, Apr 14, 2023 at 10:29:27AM +0200, Arnd Bergmann wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > Unknown -mllvm options don't cause an error to be returned by clang, so
> > the cc-option helper adds the unknown hwasan-kernel-mem-intrinsic-prefix=1
> > flag to CFLAGS with compilers that are new enough for hwasan but too
>
> Hmmm, how did a change like commit 0e1aa5b62160 ("kcsan: Restrict
> supported compilers") work if cc-option does not work with unknown
> '-mllvm' flags (or did it)? That definitely seems like a problem, as I
> see a few different places where '-mllvm' options are used with
> cc-option. I guess I will leave that up to the sanitizer folks to
> comment on that further, one small comment below.

Urgh, this one turns out to be rather ridiculous. It's only a problem
with hwasan...

If you try it for yourself, e.g. with something "normal" like:

> clang -Werror -mllvm -asan-does-not-exist -c -x c /dev/null -o /dev/null

It errors as expected. But with:

> clang -Werror -mllvm -hwasan-does-not-exist -c -x c /dev/null -o /dev/null

It ends up printing _help_ text, because anything "-h..." (if it
doesn't recognize it as a long-form argument), will make it produce
the help text.

> > old for this option. This causes a rather unreadable build failure:
> >
> > fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
> > make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
> > fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
> > make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2
> >
> > Add a version check to only allow this option with clang-15, gcc-13
> > or later versions.
> >
> > Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> > ---
> > There is probably a better way to do this than to add version checks,
> > but I could not figure it out.
> > ---
> >  scripts/Makefile.kasan | 5 +++++
> >  1 file changed, 5 insertions(+)
> >
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index c186110ffa20..2cea0592e343 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -69,7 +69,12 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> >               $(instrumentation_flags)
> >
> >  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> > +ifeq ($(call clang-min-version, 150000),y)
> >  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> > +endif
> > +ifeq ($(call gcc-min-version, 130000),y)
> > +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> > +endif
>
> I do not think you need to duplicate this block, I think
>
>   ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
>   CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>   endif

We just need the clang version check. If the compiler is gcc, it'll do
the "right thing" (i.e. not print help text). So at a minimum, we need
if "clang version >= 15 or gcc". Checking if gcc is 13 or later
doesn't hurt though, so I don't mind either way.

So on a whole this patch is the right thing to do because fixing old
clang versions to not interpret unrecognized options that start with
"-h.." as help isn't something we can realistically do.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMwYosrvqh4ogDO8rgn%2BSeDHM2b-shD21wTypm_6MMe%3Dg%40mail.gmail.com.
