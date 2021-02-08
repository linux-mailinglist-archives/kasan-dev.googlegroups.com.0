Return-Path: <kasan-dev+bncBDUPB6PW4UKRBA4RQKAQMGQEKX2QKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B8DA31289F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 01:40:36 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id w12sf7407638ooo.7
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Feb 2021 16:40:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612744835; cv=pass;
        d=google.com; s=arc-20160816;
        b=qMK/9oQ9uAFB5Mv38fZDEG8IAiCJZpTaKHs6UmB7D7R0PTuZjKmYUbzfH8ul1Y83lg
         eVOkD0zK0AeUGcsPyylQyUNojHMV/pHa+1uG+OJXt/FCZIrYOswX7Xs8f2sVhWIrLPTN
         P0uXM0tPbe/IFuNj3oY+Gj8qNJm7vylwjSkWr1r1kU0/pcKDQM6hOdg3wlT3LSgUEDyB
         6J+rsVIpzY4TloT/MnGKZYmGmRglezCcujSMbNTBWEc+dCknKFB/Pr4U6gulplMwt7Df
         j/esKJtWgcN7IFGurIN6WPfmtDSU3PX9/QmT36i83mzPyUyLNM/ilmNZvSxyj1VzuaBU
         H8Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=KfgqW5KI59lnvKJciWKWdq6kIdEr4EeZDy6apY1PRSg=;
        b=ih2ZrlGLF2LPP3MoUSWAnUwUYdZS8So0xtJ2qAXXA7mRRkUzHFCTIngSc4dzJciXq5
         hD/oLFYqCqys3mwcLpjXxl8NP3aMxhzd3hqrNXi9rxEc/otlpWTRJMX2QW66Z6z6b0xn
         spNjr/FukFPUPrAODl9iqOx/qsH3iaUvg0Lrymnad2gByvZVjFWqWoybf2Vmu+klxbYd
         bvNjwsPQhPfAF/BqJ2FCym1B1PqGu4D7IQlKuYOGYssRTri4Q4KCQqb1gyZGd7DJJ8Ah
         xpmg7hO9UQq1FAu87c58mCURiv7t9nttaejXBlkT5yhVEfkdVK772DTRR7YwOezD5IJd
         C4jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UJfgwkWd;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfgqW5KI59lnvKJciWKWdq6kIdEr4EeZDy6apY1PRSg=;
        b=hCQCMhxNISu5CMiweRpgJgbAntSVRP4pR/wA6I+mWmZ8Gn9n34mYp5XqXqTpSaxbdI
         QIzx2eTtfVQw8VXEXocIXMTkZAEIr+XtC3XOJGo2ETjoaDkVp3/Th22+TCo3+1I7rDf+
         JdQE2oLmmJ7TZ58LRUrh4n7wFf3SfCyzjagc+Qs4yZeq2FiLzh6xjVmQymD/AijwBLqA
         B2NUZfoZxnbqd7vypu3csjV9Uelm0MKsu0LYsA1zW53edNkSq3Hk6r47h358V8c7DrWm
         TJVKXxCKvyB6475sFBB0h8mr9UXAIt/bNhpj3XhBF4QK4la1NaPeT9BXktQGSfp7nZdT
         ljMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfgqW5KI59lnvKJciWKWdq6kIdEr4EeZDy6apY1PRSg=;
        b=FR/QKUA1miuBEXiphk+qOE3K8gWde4zyFbUFwajkwcNIeIGA+u3ljShFeBEA32hdic
         Sd15o1+kiJYTVdDs05k56W2SUZurtW1yA+um5ls0ZD3EnnGS1dzciDPAfuqWK4HHt/sC
         l5cbtDfFDlk0S9n4cHH3ALRWXcR1cA80BwCSJo9c/qIP39T9ILluLrYTuqYb8QNp/zDh
         /i7NGMH6T4leWiwZ+Fy22rPfuzEfweEA9aoiRR6rQBV12wXK5CUxZgFG3U5z0CyR734o
         2XjcllaxJ3ydMwLEHVEZ8bgrk/AaSG+jNqDnV0NC7XfwWLk0PVvw9brMWdrGWqPHNbSz
         GesQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfgqW5KI59lnvKJciWKWdq6kIdEr4EeZDy6apY1PRSg=;
        b=RwZrTOjJlIk3rgLzpwEbiIm1yMfFfNy3/7FxSDZz8SIkk+WyJCLT0xACBhQTvxl7Z7
         NsoKsTJLlO+mxD0UcWNg9MRfcI2zWNuBBSYKhb17Zjq5QOPODJGgoV6zYozJCZpBdpn7
         X7rjq6n19oO0udxl82A7Dg09FyRHI8egjhqMSoTt6L3Sm0QFWarJVKEjdJtZKFLABVci
         3gmqFj/RSKkgmP6afZDBJ3EZHujtAooR36ZoFnr91pZYYdpogNDLmlxbONKMbw8qjS8X
         1t8/vNYLN3g19Gl52dIgpTlFgLXYuy3R6oC4bwbLJwlX84wXxfDi3jJdt2a8FB2WqA3q
         bksg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530R2VCCSgfovdk+0JJoJHLnKeoYtmwDpIu7HBAYb195bWZ7CIaz
	RlEUwFTo8kZ2qL78QEBmWYM=
X-Google-Smtp-Source: ABdhPJxbzrNV49T29sZ7sLqAlhG0KzTFqFktKlDkbSxMLyfXNb/PPo+QO7dUe7LBGBzxiltel1HyRg==
X-Received: by 2002:a9d:2265:: with SMTP id o92mr10724559ota.188.1612744835358;
        Sun, 07 Feb 2021 16:40:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3407:: with SMTP id v7ls3687009otb.9.gmail; Sun, 07 Feb
 2021 16:40:35 -0800 (PST)
X-Received: by 2002:a05:6830:4129:: with SMTP id w41mr9758228ott.332.1612744834985;
        Sun, 07 Feb 2021 16:40:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612744834; cv=none;
        d=google.com; s=arc-20160816;
        b=VpS8hqDw4R7W56STD+iJ2iUTZQ9caXU6XZPmugWpr5o3vYWH01l5ePDlzmJfc+bvF2
         P2HBeQHIMXRv/mBf0+cIdqcNnK+1/eitrGTNjXGVAPZMMF4r7j+Vcch2GSNWQ+XxP9g+
         Pqca0fPjfylt/X0eyicbXjGDRNL85DxYqXbDgzwHN0ZTo2SqQS5pOVKnzzJZTPUVW261
         pf7jnJHEpEfkB8nHQ7rhbxcqiPHQ5H0/m9NYZ0sPXpSqGtX9kNk8HoNxvvm8DFlROqWO
         rN/RVttmCSWM/TwXCgFvC5ks42fTYv67zOqo2fbe0kdX/NjDeU4ObN7iu4crphGp1NrG
         ji0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=k8kyS5NcNbcb+l8f+ny89WYmgXi+Pxs4HtJo/I4TE4I=;
        b=prsPTMiEgrsnRDopLUKgVbk6uNf7qCihzSoyb3krOFMUE2MJ0ezrgo4g/90ZecXWsG
         /5sBXys8U6xGSodFWc37ns3hhx2w6lKhZtuj73gFaBtnOwXhyaZ8Dttp9IZ1lS5kNQfd
         p65TjBOnWTgTB30ORQslOnI+tEGvpU/dM1D0gBqU8Zg6ImdubriQobP8YwWl8sgjpYL+
         slFRqrP4VQ/bCUui5nDxN/8h5a6TgM8/DoMXutnVF47SsrASGHWDHNd7R4THnC5L+qYs
         py7KgPokmV3STsCqyu2Dvwm1oHTEfy43U39Iw2h3lR7ah2QJFYl3WVAF+mtoE7z/m9GX
         pArw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UJfgwkWd;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id b11si682369otq.0.2021.02.07.16.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Feb 2021 16:40:34 -0800 (PST)
Received-SPF: pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id z32so9273098qtd.8
        for <kasan-dev@googlegroups.com>; Sun, 07 Feb 2021 16:40:34 -0800 (PST)
X-Received: by 2002:ac8:5887:: with SMTP id t7mr13538561qta.182.1612744834574;
        Sun, 07 Feb 2021 16:40:34 -0800 (PST)
Received: from arch-chirva.localdomain (pool-68-133-6-116.bflony.fios.verizon.net. [68.133.6.116])
        by smtp.gmail.com with ESMTPSA id t71sm15755390qka.86.2021.02.07.16.40.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 Feb 2021 16:40:34 -0800 (PST)
Date: Sun, 7 Feb 2021 19:40:32 -0500
From: Stuart Little <achirvasub@gmail.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>
Cc: linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, jpoimboe@redhat.com, nborisov@suse.com,
	bp@suse.de, seth.forshee@canonical.com,
	yamada.masahiro@socionext.com
Subject: Re: PROBLEM: 5.11.0-rc7 fails =?utf-8?Q?to?=
 =?utf-8?Q?_compile_with_error=3A_=E2=80=98-mindirect-branch=E2=80=99_and_?=
 =?utf-8?B?4oCYLWZjZi1wcm90ZWN0aW9u4oCZ?= are not compatible
Message-ID: <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
 <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
X-Original-Sender: achirvasub@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=UJfgwkWd;       spf=pass
 (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::832
 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

And for good measure: reverting that commit=20

20bf2b378729c4a0366a53e2018a0b70ace94bcd

flagged by the bisect right on top of the current tree compiles fine.=20

On Sun, Feb 07, 2021 at 07:26:01PM -0500, Stuart Little wrote:
> The result of the bisect on the issue reported in the previous message:
>=20
> --- cut ---
>=20
> 20bf2b378729c4a0366a53e2018a0b70ace94bcd is the first bad commit
> commit 20bf2b378729c4a0366a53e2018a0b70ace94bcd
> Author: Josh Poimboeuf <jpoimboe@redhat.com>
> Date:   Thu Jan 28 15:52:19 2021 -0600
>=20
>     x86/build: Disable CET instrumentation in the kernel
>    =20
>     With retpolines disabled, some configurations of GCC, and specificall=
y
>     the GCC versions 9 and 10 in Ubuntu will add Intel CET instrumentatio=
n
>     to the kernel by default. That breaks certain tracing scenarios by
>     adding a superfluous ENDBR64 instruction before the fentry call, for
>     functions which can be called indirectly.
>    =20
>     CET instrumentation isn't currently necessary in the kernel, as CET i=
s
>     only supported in user space. Disable it unconditionally and move it
>     into the x86's Makefile as CET/CFI... enablement should be a per-arch
>     decision anyway.
>    =20
>      [ bp: Massage and extend commit message. ]
>    =20
>     Fixes: 29be86d7f9cb ("kbuild: add -fcf-protection=3Dnone when using r=
etpoline flags")
>     Reported-by: Nikolay Borisov <nborisov@suse.com>
>     Signed-off-by: Josh Poimboeuf <jpoimboe@redhat.com>
>     Signed-off-by: Borislav Petkov <bp@suse.de>
>     Reviewed-by: Nikolay Borisov <nborisov@suse.com>
>     Tested-by: Nikolay Borisov <nborisov@suse.com>
>     Cc: <stable@vger.kernel.org>
>     Cc: Seth Forshee <seth.forshee@canonical.com>
>     Cc: Masahiro Yamada <yamada.masahiro@socionext.com>
>     Link: https://lkml.kernel.org/r/20210128215219.6kct3h2eiustncws@trebl=
e
>=20
>  Makefile          | 6 ------
>  arch/x86/Makefile | 3 +++
>  2 files changed, 3 insertions(+), 6 deletions(-)
>=20
> --- end ---
>=20
> On Sun, Feb 07, 2021 at 06:31:22PM -0500, Stuart Little wrote:
> > I am trying to compile on an x86_64 host for a 32-bit system; my config=
 is at
> >=20
> > https://termbin.com/v8jl
> >=20
> > I am getting numerous errors of the form
> >=20
> > ./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-branch=
=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
> >=20
> > and
> >=20
> > ./include/linux/kcsan-checks.h:143:6: error: =E2=80=98-mindirect-branch=
=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
> >=20
> > and
> >=20
> > ./arch/x86/include/asm/arch_hweight.h:16:1: error: =E2=80=98-mindirect-=
branch=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
> >=20
> > (those include files indicated whom I should add to this list; apologie=
s if this reaches you in error).
> >=20
> > The full log of the build is at
> >=20
> > https://termbin.com/wbgs
> >=20
> > ---
> >=20
> > 5.11.0-rc6 built fine last week on this same setup.=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YCCIgMHkzh/xT4ex%40arch-chirva.localdomain.
