Return-Path: <kasan-dev+bncBCCMH5WKTMGRBH4YRSLAMGQEXBFL7VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 316F8565A57
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:49:53 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id b18-20020aa78ed2000000b0052541d34055sf2712904pfr.23
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:49:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656949791; cv=pass;
        d=google.com; s=arc-20160816;
        b=OuLr36Xmxd1nICT8SpQ7EfmQRwH7TyAJPirCSCrHyStlHQClOD70ahBusmprY5sqJT
         Dacbz45yuS4/QXjj0+YRJVJ2TY+B4UtcVqya/NeaB1I9+viq+heuoA28mYrKfywetS1k
         dY5kF04iUbPU/e8eXkB3r1axz6FGluRjW4j8z7fwufG86Gmq4e2vQnChKeFhNwkXC+uD
         V4XP3xbatmgQxeD++n9fSKdwPmS3m5xVPtovad4LfsDG3ijrcGxCsFqXbGmeG0ylexxT
         UrtRSSfyqe75BDWnxphXeOcWrewPkYLmM4vt1MJ5x4XhQd7fEkAZsPrgVTfamn/043Hl
         27Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j3hmQKQRcRJw1YTfse9X/vUZlbZIScz1s0TR+7F2RTg=;
        b=GS/97H9S3Sp0t9UUUGfHgd30JRR3DmoKXVWu5fjX/BwCeqsFdfcGnEU6PcNHGKiAXu
         xgXMAuhbQxAZQG6TneNVuyH6eeml6kev2s/AuG7kmfpH/uFeD7/6d/sKfiph8jVs2no+
         9bTMCMPjI3vjFbVRG3UHBXGMwGEnDMTce9FZTLnmewS9iA7z8a0FGWKd3b03KY3kUqss
         8hlZ5goRslZ5vOiirDkZ4afvi1PG29n9B84uADFCbppiHgmJQFJdxII4YiLkLkS4CE1W
         33vaByAjnEKPdJNFRb0McH3reoBqpKTO/Ser5B7xIc7haFmcAhrTAIZUjL2QPuhcCuF0
         FacQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="BsVN/T+C";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=j3hmQKQRcRJw1YTfse9X/vUZlbZIScz1s0TR+7F2RTg=;
        b=tIcGZKEhMOfA2gSgurp3+0h5IoCuaBBfYlhcLKSMFMsNVugRLiJ7ydJUk1GtbFAtYt
         Cjjsxb2k7zSF/v4qVCEtOlN0+a05WajjIrKjognUvdM2E5Fp9eVXR0q7l4noynsQfFo2
         lPXIq/Jusq3QAVi3VKtHjFfw+Nn8mgrlMzJ4OQrAwK3wMBjnSpkpQEb8fuMq0GNdg2xV
         /LEeibc955YgMEUZRJB1bqMd4Z3IiVlbvhv+VLuv8XSmWronkOh5zmnrt3KGUooHc18I
         lOVrkKFhwn54XIHH7z94Jg7fBageCiL6YvoYsPrUfc7+MUlRYACK6rHTExzVs0Gbd5Mv
         vfMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j3hmQKQRcRJw1YTfse9X/vUZlbZIScz1s0TR+7F2RTg=;
        b=dkWZyhAOJCd7X7/xjfz3Kj1wu+trWPpIiCYIipq01FpoqraCvhzYNROPOsAqwSUb7c
         3mvwwjTHTSaHDfbzDCF9nYtSFHDqXR+OYf/pF9u6Opo50dzI4NnIv2BFQKkBzNpQW71T
         Gb8HBMq3yIDRTTPeTt/CzDXW4POZhDCw3C98T6TjNy137A8ds/MY6fMoApO/mGPpA2A+
         Xt5cHZyL1PrfAsNHNGzLoeVQAMfxKFEU/oyqUq8CZIMV1h8tOeIoKFBlmAFeZy+G8Yp/
         jv8E4hW55v6Per37F67NisOL1uptm4OO5Fg2jdyEVd3mRgAW032W1Kg0lXEycYEC7j/K
         Etjg==
X-Gm-Message-State: AJIora9Oo26+6hW4+K+GaASyjc5SXnMp/YotnRovQ35RcIOCHlQGp5Cs
	kFsdLWSWLa6Dsu1o/v0tlUk=
X-Google-Smtp-Source: AGRyM1tTd5A7ALa3iwEZl7UAafUZBdMCB6tdIxlJi03CuA2h7sdXtmkYtj6e2gYnMuF1WjQmkquwUw==
X-Received: by 2002:a17:90b:3802:b0:1ed:2434:eb44 with SMTP id mq2-20020a17090b380200b001ed2434eb44mr38129849pjb.85.1656949791556;
        Mon, 04 Jul 2022 08:49:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1b2b:b0:1ec:847c:ca01 with SMTP id
 q40-20020a17090a1b2b00b001ec847cca01ls410486pjq.2.-pod-prod-gmail; Mon, 04
 Jul 2022 08:49:51 -0700 (PDT)
X-Received: by 2002:a17:90b:895:b0:1ec:827c:ef0f with SMTP id bj21-20020a17090b089500b001ec827cef0fmr37193421pjb.10.1656949790905;
        Mon, 04 Jul 2022 08:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656949790; cv=none;
        d=google.com; s=arc-20160816;
        b=hVYGG00ei3dT+86IrJ66bS6XLi7ap6cfIYayQNSk2gd0hYmiBhkyUf4bOq/Vwf37hY
         tB5I099g/y8BnAcwcwgQh2sRogeYTUgFDUN5Z4CTsUe+O8p0NCeMqfeO5cib7bGMp4q/
         Bg0z53PRTEPbyGkPmH006TgTq7u4wpRHKF3ib0K3OZq/xn9hEN5naYxWl2VRmdqtbMMG
         SkYRLv3kPycXLuc8id1j1AgvO/vHAQuc3s7zEj924djJ/Q4hLzdWz7h02p86whWtAr4d
         VfOtXyxmkWx9znZIIcoclmWRMm7i+Tn6jFAMmj1Ipqmn3jgUsLjLKsc5czdaET/I8MqA
         lQow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kB0Q9EykRhYRQy5w/R9rD3NHZHzS133LEDTFMEV0gnQ=;
        b=NXkydGtY9lbaLWwq91YS7nAv1S1CfjFkSdR7t+cx6saCCF1fjhl7UQwyTvud6wDLbd
         Zk0UkD7KYMi+7hLuyiFvLs96IXMwCKj53eV3GCK8dbklbTBx934mg0mbJNLhNMXbgxNH
         RE2JpIajnei59bzdr0bpzFkB9rc/KxL2CVVqU6G+iIaXkNMrm+PWqg1CHGKH7LotwwmX
         RVdiqrJyswUbs64TSYgjky6uOGpJsIw3W7q+wccUT5qd+h1QwbsEFv5eY5torCIEVDI8
         MjzUVBVdjvMyYlW2h9a9ErPSBTdIPHWo43IP4cwc+EgXFqrW6burdcUIJvy+OlTFSoFG
         Nglg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="BsVN/T+C";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b001ecb6b8678fsi826439pjb.2.2022.07.04.08.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:49:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-31c9b70c382so23323217b3.6
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:49:50 -0700 (PDT)
X-Received: by 2002:a81:a847:0:b0:31c:7dd5:6d78 with SMTP id
 f68-20020a81a847000000b0031c7dd56d78mr15737307ywh.50.1656949789965; Mon, 04
 Jul 2022 08:49:49 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV>
In-Reply-To: <YsLuoFtki01gbmYB@ZenIV>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 17:49:13 +0200
Message-ID: <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="BsVN/T+C";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Jul 4, 2022 at 3:44 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> On Mon, Jul 04, 2022 at 10:20:53AM +0200, Alexander Potapenko wrote:
>
> > What makes you think they are false positives? Is the scenario I
> > described above:
> >
> > """
> > In particular, if the call to lookup_fast() in walk_component()
> > returns NULL, and lookup_slow() returns a valid dentry, then the
> > `seq` and `inode` will remain uninitialized until the call to
> > step_into()
> > """
> >
> > impossible?
>
> Suppose step_into() has been called in non-RCU mode.  The first
> thing it does is
>         int err =3D handle_mounts(nd, dentry, &path, &seq);
>         if (err < 0)
>                 return ERR_PTR(err);
>
> And handle_mounts() in non-RCU mode is
>         path->mnt =3D nd->path.mnt;
>         path->dentry =3D dentry;
>         if (nd->flags & LOOKUP_RCU) {
>                 [unreachable code]
>         }
>         [code not touching seqp]
>         if (unlikely(ret)) {
>                 [code not touching seqp]
>         } else {
>                 *seqp =3D 0; /* out of RCU mode, so the value doesn't mat=
ter */
>         }
>         return ret;
>
> In other words, the value seq argument of step_into() used to have ends u=
p
> being never fetched and, in case step_into() gets past that if (err < 0)
> that value is replaced with zero before any further accesses.

Oh, I see. That is actually what had been discussed here:
https://lore.kernel.org/linux-toolchains/20220614144853.3693273-1-glider@go=
ogle.com/
Indeed, step_into() in its current implementation does not use `seq`
(which is noted in the patch description ;)), but the question is
whether we want to catch such cases regardless of that.
One of the reasons to do so is standard compliance - passing an
uninitialized value to a function is UB in C11, as Segher pointed out
here: https://lore.kernel.org/linux-toolchains/20220614214039.GA25951@gate.=
crashing.org/
The compilers may not be smart enough to take advantage of this _yet_,
but I wouldn't underestimate their ability to evolve (especially that
of Clang).
I also believe it's fragile to rely on the callee to ignore certain
parameters: it may be doing so today, but if someone changes
step_into() tomorrow we may miss it.

If I am reading Linus's message here (and the following one from him
in the same thread):
https://lore.kernel.org/linux-toolchains/CAHk-=3Dwhjz3wO8zD+itoerphWem+JZz4=
uS3myf6u1Wd6epGRgmQ@mail.gmail.com/
correctly, we should be reporting uninitialized values passed to
functions, unless those values dissolve after inlining.
While this is a bit of a vague criterion, at least for Clang we always
know that KMSAN instrumentation is applied after inlining, so the
reports we see are due to values that are actually passed between
functions.

> So it's a false positive; yes, strictly speaking compiler is allowd
> to do anything whatsoever if it manages to prove that the value is
> uninitialized.  Realistically, though, especially since unsigned int
> is not allowed any trapping representations...
>
> If you want an test stripped of VFS specifics, consider this:
>
> int g(int n, _Bool flag)
> {
>         if (!flag)
>                 n =3D 0;
>         return n + 1;
> }
>
> int f(int n, _Bool flag)
> {
>         int x;
>
>         if (flag)
>                 x =3D n + 2;
>         return g(x, flag);
> }
>
> Do your tools trigger on it?

Currently KMSAN has two modes of operation controlled by
CONFIG_KMSAN_CHECK_PARAM_RETVAL.
When enabled, that config enforces checks of function parameters at
call sites (by applying Clang's -fsanitize-memory-param-retval flag).
In that mode the tool would report the attempt to call `g(x, false)`
if g() survives inlining.
In the case CONFIG_KMSAN_CHECK_PARAM_RETVAL=3Dn, KMSAN won't be
reporting the error.

Based on the mentioned discussion I decided to make
CONFIG_KMSAN_CHECK_PARAM_RETVAL=3Dy the default option.
So far it only reported a handful of errors (i.e. enforcing this rule
shouldn't be very problematic for the kernel), but it simplifies
handling of calls between instrumented and non-instrumented functions
that occur e.g. at syscall entry points: knowing that passed-by-value
arguments are checked at call sites, we can assume they are
initialized in the callees.


HTH,
Alex

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ%40mail.gmai=
l.com.
