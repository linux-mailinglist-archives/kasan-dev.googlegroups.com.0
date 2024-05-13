Return-Path: <kasan-dev+bncBDT2NE7U5UFRB7NSRKZAMGQEY6LQY5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 367058C49C2
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 00:51:43 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2b294c5ebc1sf4346470a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 15:51:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715640702; cv=pass;
        d=google.com; s=arc-20160816;
        b=ro8Zk4I4rMXh4rZtTAEQYbNuo3mIYU+e7HsrZw3W8eXW+1VO6SlghCGIGW6HL7Vrqn
         CvtfNFfWgOyGJtM2mJWoMFGoXy+WwXxXn9mEwX0CeGZV8erfoByeq7epzkB/E4XoRyTZ
         oBPQOomUjk4jydxpPlRGcMhmDT1pCRinGq5rxZOkoE7ou6KiyLmTKdHa+T0WyxYPhSXb
         XzK8yu/pGH11GHkJjE4om6ZD2/XsRGjVg2ZpZIQ8cy3CQ5IwlDw+ycDHKxnA0Pm73Jfl
         7swOnL7X6b88iJY98WpijVdwRVQY0XYa8cGL/PLmn7rftzrs5XZEq8YMyRlnlXfScg0p
         VmoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=5yDaXZ4vpIX/PDYMCsdeJOWVPLz7gsBGtnzxtGpiwpA=;
        fh=LQ8ZPU18Pd3XwuqTNAoFOwDQGrF2koczKeBYWhiqzjE=;
        b=CNVQL7/EauRQ5h7Sk0/jHglBqJQYfp2XMMIOB5JBvRsalzaJah0ZKm2bHMXazSEK5d
         GZHHb6YfAEnd60vta62b0qU2FB7DhSSSeXzknXocVzIPnkKKOTTy3tTmXv3Gd9VRusuA
         yND6cyW9Il3+INTw/8V9iYkEWDjVLPrA2ML9KoVYKHr6qv3XS4kPpNzzn0R484la/Gb9
         USGXNsQrglA10FgQaIdOWCS2vw174xDyCQySD9HmJwzgPDixKCMefmivxTwFFsowWORc
         Sj/jD8XhrP7pVMiVmj2CWq8HF69Hf8J0I+NyScnrTBtYzQmhwRqkIK941khE3ypz8f0G
         wGlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ccm7AzJr;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715640702; x=1716245502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5yDaXZ4vpIX/PDYMCsdeJOWVPLz7gsBGtnzxtGpiwpA=;
        b=SeYy8vBy4GlXadvmi25fedRrDjycfrd6vP3/HfiTpg274bKJrkj70k47/AZDAO1vXS
         UblCL57GjXRRFBsNEKYbyOSxudx/lVUcyp5rtIOG4Tp86DdVUdlgUe7YfVuJZH1pZoFP
         E+m3UaiKXJwYBqf87oX9p5NmQBfYE7pmo+KD/J1Cqwz85OP68xpBSkxEkLDsjY/v6K47
         9eQBBX8PlYKZERm/fXat2eotxR72ZbnfcQEZsGRQXvCVsKUnJYatSRUDyqufD8TCDM6I
         H2KLk+GmyYCI8fLnzznN+Ax+uB+dAThGqUvZXleKSizX72z7JK3vKdRpGEK13FgSQHR9
         Yr3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715640702; x=1716245502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5yDaXZ4vpIX/PDYMCsdeJOWVPLz7gsBGtnzxtGpiwpA=;
        b=B2O0KstsUfQXJYvfaj3FwZzr5hC/hoEXnJe7Sn2F10hMtpDY7GN2buNOv01JDkB96r
         dPqSoNzZIFxvS0ZPkjCCnSw92AdVrAd+zscn0ce7ea4ctmeEzSpZmXUBr2wvSs1hrha6
         ZfaIE6hmiDRxRlIxQzQiOYJSYAjFT7e2SXKdpOiqU4k6il/y5u8gH3jCbsYzZj+foL66
         TeP0GqC/CJhbaNJYgKaYA4YvoLYZJII0k5d2c0eRRUmAZSuvwrbhBdA1YNI/ueGHyHae
         XW6QsF1vewryPkDQegZ9MiwCCqUxtfLftvVgYG6QjHDehFh8N0LtsrGwkrOm1SmDRktW
         Wb5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtGCvWaymlh9bTw2xFz88wZ7ZbUVh8SyEZmaRuZafUD/LmJ7Qw+v3e7qTfDONDxGDyTD0Qwy74/BEXiUtKvn67z/uIDShqzw==
X-Gm-Message-State: AOJu0Yz4R+OhyG3ldjD4Vju3L8z5jiiZ8gIowQKz77d1XzXpPEdrlDJ3
	/nk+AnnJ0/1xSDowbdknUq7he7ftXB01yO/40G6LdF9v/2patEcM
X-Google-Smtp-Source: AGHT+IG6WjoaBtUdiAiAZe9hmA+7YVwMcHGk3jOz0+eJnN7/YsR2EFyafZYYtIImKoNbzcN4aTQVUQ==
X-Received: by 2002:a17:90a:2e84:b0:2b2:7e94:c5e0 with SMTP id 98e67ed59e1d1-2b6cc758cfemr8598519a91.20.1715640701816;
        Mon, 13 May 2024 15:51:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf10:b0:2a2:6c35:b46f with SMTP id
 98e67ed59e1d1-2b6623aaaf7ls2936283a91.1.-pod-prod-09-us; Mon, 13 May 2024
 15:51:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgVQSPoJ9sTJk3HSH6+qg86tm+cyWMagL3rViCMfc6+ajQ/uTG6XGEKgJ2F9bC16Se+9OnWtMgA2Ixid5xLDnbQlC9Djss1VTmVA==
X-Received: by 2002:a17:90a:b785:b0:29d:dd93:5865 with SMTP id 98e67ed59e1d1-2b6ccef64bdmr8273774a91.46.1715640700577;
        Mon, 13 May 2024 15:51:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715640700; cv=none;
        d=google.com; s=arc-20160816;
        b=UKSXKr8qjygUoJAP0bHhhyMeT8U1j/sQ8sN2MNxCoy9ZbJQJam0mZZzCM/AmU1SOPX
         X0ihtp3DlrM5rZhnmEHMBcnflOrmZoGNj0YJJu4oISlW5NsXrBq1Xiknhic4lo/98XyR
         mAuZtj/H0sGQzJv5bRdA9WYD3jqAWY2un06v8mOT2QB86Hxp1xvvBfjvgJoSiGYXSxl6
         k7V+Pl0RMj9icucgdM8y+6vFJ8J4tuQYWeD6kpQTfp3aWWb0mPmvNtyH++phfMh/hdDi
         /2McgL//LuoDVLCM+7K7LdvEIuYta1yFXU9QVwae9RZe8Scqikh3ODIa86GQBuW6XM2r
         38Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=R9nb6AKCiNXgoFXe291EdQ1c6gS62P3/lGO+GjHmbyY=;
        fh=3H6xJdwhlq5ZJvxwqLzzrO9FGLiaHLzY0xh/hwv3Edc=;
        b=pZU+Av9cv1CglDTnGBH8ScmfdU1yOPFKxqDULU6s7TznRipjzdQghArETtRLCwjfro
         8U/uIf8LR6aLpgfo/qnC56KmyZbXgV3RWmbDcpWBPrZEsC6bBn0ldF5B+0Oz2gjLSJws
         rshNSqGk0yFGhRwHgpGneIrBQ1Tgluj0X58/zyd4xAEV1aSgOfaks9PRXBufem6asQmB
         CKnEphSFJYLZP2ErOKBRz8v5kczHbdXcQm4H0OLFB2g8zSSoInptUBPz3gT3i+YRYeKZ
         MYuUEstK9MF+l6ZQJEXdQELe8HWbRXWfc0LWWzqyB5ulhohXa6Eo89uh0MLtrThoGZJr
         Obsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ccm7AzJr;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2b5e01c2c85si1061111a91.1.2024.05.13.15.51.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 15:51:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 64259CE0FA4
	for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 22:51:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 553DFC4AF08
	for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 22:51:37 +0000 (UTC)
Received: by mail-lj1-f172.google.com with SMTP id 38308e7fff4ca-2dcc8d10d39so58124361fa.3
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 15:51:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFVW21wmN1XwaU5qYX0Pg7sOs15n84QehLFxAmI1ujgXErz+MK76f9WFZAxVk9GPBLSa4DCkkDH3dc9rpSIMYiirQS0Eqt0blBeA==
X-Received: by 2002:a05:6512:3151:b0:513:1a9c:ae77 with SMTP id
 2adb3069b0e04-5220fe799c9mr5293673e87.52.1715640695978; Mon, 13 May 2024
 15:51:35 -0700 (PDT)
MIME-Version: 1.0
References: <20240506133544.2861555-1-masahiroy@kernel.org>
 <202405131136.73E766AA8@keescook> <CANpmjNO=v=CV2Z_PGFu6ChfALiWJo3CJBDnWqUdqobO5X_62cA@mail.gmail.com>
In-Reply-To: <CANpmjNO=v=CV2Z_PGFu6ChfALiWJo3CJBDnWqUdqobO5X_62cA@mail.gmail.com>
From: Masahiro Yamada <masahiroy@kernel.org>
Date: Tue, 14 May 2024 07:50:59 +0900
X-Gmail-Original-Message-ID: <CAK7LNATvr9-K2Hwv=Qx9stSTyFTC8Bc7EAHemVnCSo-geZUL+A@mail.gmail.com>
Message-ID: <CAK7LNATvr9-K2Hwv=Qx9stSTyFTC8Bc7EAHemVnCSo-geZUL+A@mail.gmail.com>
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, linux-kbuild@vger.kernel.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Peter Oberparleiter <oberpar@linux.ibm.com>, 
	Roberto Sassu <roberto.sassu@huaweicloud.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ccm7AzJr;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, May 14, 2024 at 4:55=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Mon, 13 May 2024 at 20:48, Kees Cook <keescook@chromium.org> wrote:
> >
> > In the future can you CC the various maintainers of the affected
> > tooling? :)
> >
> > On Mon, May 06, 2024 at 10:35:41PM +0900, Masahiro Yamada wrote:
> > >
> > > This patch set removes many instances of the following variables:
> > >
> > >   - OBJECT_FILES_NON_STANDARD
> > >   - KASAN_SANITIZE
> > >   - UBSAN_SANITIZE
> > >   - KCSAN_SANITIZE
> > >   - KMSAN_SANITIZE
> > >   - GCOV_PROFILE
> > >   - KCOV_INSTRUMENT
> > >
> > > Such tools are intended only for kernel space objects, most of which
> > > are listed in obj-y, lib-y, or obj-m.
>
> I welcome the simplification, but see below.
>
> > This is a reasonable assertion, and the changes really simplify things
> > now and into the future. Thanks for finding such a clean solution! I
> > note that it also immediately fixes the issue noticed and fixed here:
> > https://lore.kernel.org/all/20240513122754.1282833-1-roberto.sassu@huaw=
eicloud.com/
> >
> > > The best guess is, objects in $(obj-y), $(lib-y), $(obj-m) can opt in
> > > such tools. Otherwise, not.
> > >
> > > This works in most places.
> >
> > I am worried about the use of "guess" and "most", though. :) Before, we
> > had some clear opt-out situations, and now it's more of a side-effect. =
I
> > think this is okay, but I'd really like to know more about your testing=
.
> >
> > It seems like you did build testing comparing build flags, since you
> > call out some of the explicit changes in patch 2, quoting:
> >
> > >  - include arch/mips/vdso/vdso-image.o into UBSAN, GCOV, KCOV
> > >  - include arch/sparc/vdso/vdso-image-*.o into UBSAN
> > >  - include arch/sparc/vdso/vma.o into UBSAN
> > >  - include arch/x86/entry/vdso/extable.o into KASAN, KCSAN, UBSAN, GC=
OV, KCOV
> > >  - include arch/x86/entry/vdso/vdso-image-*.o into KASAN, KCSAN, UBSA=
N, GCOV, KCOV
> > >  - include arch/x86/entry/vdso/vdso32-setup.o into KASAN, KCSAN, UBSA=
N, GCOV, KCOV
> > >  - include arch/x86/entry/vdso/vma.o into GCOV, KCOV
> > >  - include arch/x86/um/vdso/vma.o into KASAN, GCOV, KCOV
> >
> > I would agree that these cases are all likely desirable.
> >
> > Did you find any cases where you found that instrumentation was _remove=
d_
> > where not expected?
>
> In addition, did you boot test these kernels?


No. I didn't.




> While I currently don't
> recall if the vdso code caused us problems (besides the linking
> problem for non-kernel objects), anything that is opted out from
> instrumentation in arch/ code needs to be carefully tested if it
> should be opted back into instrumentation. We had many fun hours
> debugging boot hangs or other recursion issues due to instrumented
> arch code.


As I replied to Kees, I checked the diff of .*.cmd files.

I believe checking the compiler flags for every object
is comprehensive testing.

If the same set of compiler flags is passed,
the same build artifact is generated.



--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK7LNATvr9-K2Hwv%3DQx9stSTyFTC8Bc7EAHemVnCSo-geZUL%2BA%40mail.gm=
ail.com.
