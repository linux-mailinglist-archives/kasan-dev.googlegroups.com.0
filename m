Return-Path: <kasan-dev+bncBD5N3VM65EKRBQXM3GYAMGQECUXTLYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B2DC789F08D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 13:21:39 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2d86787efa3sf40619981fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 04:21:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712748099; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkFvmSx6h1qihXGIUyHBwWfUrJnRaIgeO9stAZGwbwip8YBUoDMGGiGAWPYE5fNlG4
         xzTd3pABoPeeEO/sPLwoX05TU97Kn5vQxhi2EVebUht1TluGXRUzmbDn22jea1BjLyFi
         CDV2zNhUVX3JOLf+cERGsyoaRyzDrxN9oMF+CIWJloVf/P+lHnqAopdwbVR5dbhwc0ww
         uMBUMZVKYSRk6/z0mtlyHgjF1dC8Y79TpVULPbefGzKsah/x+JYhvg25E8BX6ghMHQt2
         IKzW5AfuVwHeO0PKxQQol0Tg9qPFoFkHSSOYWr/vIaHN1ORrKC++YJbvrjcGn2mG3wxT
         W75Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wFsl2g+zTbG2X07IbXjgS144+aSGFJ4fSGhN4EB8VHg=;
        fh=ZuKBmfylc1a5IKfD9KNA6pyzBB4I9XFqclO96LCS7Bs=;
        b=xFCG74xy3keagTOXh3SeW4dYlFs36BtvOAj5kLAfugyLm6vReNnsvhC8CEzfO6iS3Y
         X3yyWT1Tb+ed3o8SdyOElQnTu8SfEmJ/E2QIrvuasi4hJ0tqRN1et9cWCj5LsP10XoaC
         QrGlO4FeZ7XYWB53SkEs/yikgQm7db1xgQXiBNq8/DdZZC2NIrHyHo6NzRX3EVDfJuGr
         LE5X+wzs5pdeEvrTK3a/EXSz6kjLKMRRe5I1/VtH0Ye8XizBP1Lhy0slc8b/E3tk6iqy
         je6Qyx6dqVbPlg55LqvWBqdnTpi7PDNL/tuPJUN+Tf8eQqS4JfUdjgIrI6OE9qAwcag/
         FC3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hi44lmti;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712748099; x=1713352899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wFsl2g+zTbG2X07IbXjgS144+aSGFJ4fSGhN4EB8VHg=;
        b=CI4eSpaUmWuPPO+54w/Zb2TcoviTbB1lN0JLtMmsU9eWjvOCFDHjV91D0pL1fHx5UY
         BDe9WIHlSn6/NNh3FXJLNI15wYVFYkKdXsNHSDX5bjEPmzWNQV6BFJhsfWxndDLBV5kX
         CltEYU/aOZZaAQNcfm7UF1BkQEQoax+SK3lGdNWKzPkxyPXGZagrbkgbObe6w6/xtNP4
         hWlDnqzm/Q+OVH0bTj+lHbXaqHPN/CQOeyr399u4Wa1swznm4LfuWg21kcz+AQ502oK8
         ATZSno8gSkGsByYKr5i88ie06aW1SoKohCc9BtbjL6jKe93sW1C4b59cClDM8ipiU8wq
         3P4w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712748099; x=1713352899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wFsl2g+zTbG2X07IbXjgS144+aSGFJ4fSGhN4EB8VHg=;
        b=jVse1vmjeWVNM+p+ap5FTAkXsjb+Rc+H2tZ/zW5JDQJGQ9rpBC1ORTjLcs2ymd+XBf
         UTe3E/jYENExr7Fy/RbA++wAp4aLJJtimXp3OsDAmrjG7jiR4ZoiT1h6ylaUmwEj0zkh
         Ns/vESqP2G5BCHYqVRpxiNP/HO1R5AiWCglQ5tc2RxIxc+iTNZ0DXW1G3VOg5o7THhar
         sZRgERR1p3szWK9cbW1Nw8nAa1FqTMSTlyx5gBHOLQaWdCHdNSjiCL2AYXD591VYKxRk
         5YLDzjf6NSaq0PKbkitAxsEtgnXED27hHOR2J+fvDCxg3RD6nH42qkJWliTdR5xe9mQe
         eHYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712748099; x=1713352899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wFsl2g+zTbG2X07IbXjgS144+aSGFJ4fSGhN4EB8VHg=;
        b=TmIhPZTa/viV6O38IdrxKQUlKsw0n8mcvaCoT2alUadrDFmsYzvg9iQld+gRVPvRwx
         egnPXra4SB0G3XfbhvIWLcCjyfRS7IDhvBW0Gwzb19m0m0b6uKULIoD7JYx4wxB14HMq
         qk2b/2L77OaU+Kwg/yJBMGztEOreNnz/IL5+LM1H4nQjwoceDKzUiNL4yPiK3vPrEfnE
         GG96XCIUJeUU4KSzInKS7sfO8f3XVzvGurMlNRFtA9m/6Iug5J9vmfh6R8g48fARUO+a
         MlqetEQbRncfMZW+O+jjZHijn3q9EZXw9BNywTHnhHVAwi22b99Nk8yZoWoxDVm0jcKE
         e4tA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSZpls2L5gnl72008VCpnD9GXQ1zPxg67jGIaDizBOGzo/i7MP6hqockXZg4YOtCCg85rH4+0/QbngYAUbk4FXAG49co7aAA==
X-Gm-Message-State: AOJu0YyAYLrcqYa5O+wgOUpt8cnxoqRtto3j0UuXtgC02t5BP7nGkwJ5
	a9mvLIhoqtuz4x6pLyXWvjTQeKaftiSw4snRJMeNJieA+NDIjXyg
X-Google-Smtp-Source: AGHT+IFHi+ANu3flhkl7pK5aBC8NyJ7/8YW5QyPPbP0GWH7pb8XezoHCzxbtRmQESAYtQjnHtpuT1A==
X-Received: by 2002:a2e:a4b7:0:b0:2d8:d8f4:f6bf with SMTP id g23-20020a2ea4b7000000b002d8d8f4f6bfmr866444ljm.1.1712748098491;
        Wed, 10 Apr 2024 04:21:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b99:0:b0:2d4:3db9:669e with SMTP id z25-20020a2e9b99000000b002d43db9669els2408575lji.2.-pod-prod-05-eu;
 Wed, 10 Apr 2024 04:21:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0Ae9GcbiNmxfO4kivw7AjKAniHP73F92bxbQ39ey6EkSAAKeEN9KSLd6p8b4kt0WhOnj0mbGkNJ34pubEns4rWF6s4slOM8IjqA==
X-Received: by 2002:ac2:5e9e:0:b0:516:d4c2:53f8 with SMTP id b30-20020ac25e9e000000b00516d4c253f8mr1998798lfq.30.1712748096499;
        Wed, 10 Apr 2024 04:21:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712748096; cv=none;
        d=google.com; s=arc-20160816;
        b=SK544lHNsD2Jn86bA6dSJZ92cNEYstNhSqZcFNSAalpWG95s9tG8O28y6IsrXTCva5
         OUpLZsC0nm6aa//lSdstfXEHB/z9TaVOllOJWFt2aPRu/G41vghtahpkSjEysxDhRL7h
         V1IV5NsxJ/TYu5qRYul8C0TW23ZlNdIOy60KZUyP3RK03xrt/42BW9R+VL10VXuw4Ba9
         WH7M9p4hweJmc8R36rRO9TAqDwlvjFYJyx5eQjGqeIHaCxcuUSSicCoIn2bC80/uVrGC
         qwUT2BretUUXL0tvewNiHUxVtergp01ZiIVwREAU4VGs3aYDaT4J6r6Prn93cPiJCzhP
         fOBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ud+517cbK3MIdJCHymhuRgamDd5LkAQgdCc6QwW3VM0=;
        fh=LV6bqxpZGVdEWzqNR5vgUBHVnZ4eTNBj8/QSeIulpqE=;
        b=lgnVI58noh0xqMJrRTqmPMLAIY57D3ZaFV8QBiJlOXpZ7S25y06c0wU+9YsdZuz3nB
         GBLC/iZFTNs3WY0OOlVfn/BPCESPBQFxdFOwkdSmikDcF4JTCSuJvIHKmnheG4BAc+R0
         N+1fKyH1Sn9pgiZT6PkjtWQeItVvp4MwOLhAw1Cg2wWROHdV8dG14Yc5sW15P2pl4aqg
         eH6nVkEzTcMCykeht6m1eOTbDlpfbHGQDtC7TMTf9e9zbRkDkl3O8MarfSBFh7WOc9ps
         Nm0KnZzbK+JHcudowdW/PkWW/vhrnbcCG1OaTLaDUdRRAWbfeY3dArOFUVNq8wsH3PDL
         28iA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hi44lmti;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id qw16-20020a1709066a1000b00a51ad0c647csi424208ejc.0.2024.04.10.04.21.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Apr 2024 04:21:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-2d89346eb45so39012301fa.0
        for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 04:21:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUTgIhSpEv/Htq/VKmZcpzvW3T3gyKKuThHGHh7HuNB9bjAYbLIrZ06FadFNsfQBIY8Vsf0YHIBWPWpkbO9p+OGjcedUS9Qs6xkJw==
X-Received: by 2002:a05:651c:b8c:b0:2d8:5a4b:17b1 with SMTP id
 bg12-20020a05651c0b8c00b002d85a4b17b1mr2109029ljb.15.1712748095459; Wed, 10
 Apr 2024 04:21:35 -0700 (PDT)
MIME-Version: 1.0
References: <20231004145137.86537-1-ubizjak@gmail.com> <20231004145137.86537-5-ubizjak@gmail.com>
 <CAHk-=wgepFm=jGodFQYPAaEvcBhR3-f_h1BLBYiVQsutCwCnUQ@mail.gmail.com>
 <CAFULd4YWjxoSTyCtMN0OzKgHtshMQOuMH1Z0n_OaWKVnUjy2iA@mail.gmail.com>
 <CAHk-=whq=+LNHmsde8LaF4pdvKxqKt5GxW+Tq+U35_aDcV0ADg@mail.gmail.com>
 <CAHk-=wi6U-O1wdPOESuCE6QO2OaPu0hEzaig0uDOU4L5CREhug@mail.gmail.com>
 <CAFULd4Z3C771u8Y==8h6hi=mhGmy=7RJRAEBGfNZ0SmynxF41g@mail.gmail.com>
 <ZSPm6Z/lTK1ZlO8m@gmail.com> <CAFULd4Z=S+GyvtWCpQi=_mkkYvj8xb_m0b0t1exDe5NPyAHyAA@mail.gmail.com>
 <CA+fCnZen+5XC4LFYuzhdAjSjY_Jh0Yk=KYXxcYxkMDNj3kY9kA@mail.gmail.com>
In-Reply-To: <CA+fCnZen+5XC4LFYuzhdAjSjY_Jh0Yk=KYXxcYxkMDNj3kY9kA@mail.gmail.com>
From: Uros Bizjak <ubizjak@gmail.com>
Date: Wed, 10 Apr 2024 13:21:23 +0200
Message-ID: <CAFULd4aJd6YKXZr=AZ7yzNkiR4_DfL5soQSvhMhNiQEPUOS87g@mail.gmail.com>
Subject: Re: [PATCH 4/4] x86/percpu: Use C for percpu read/write accessors
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Ingo Molnar <mingo@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, Andy Lutomirski <luto@kernel.org>, 
	Nadav Amit <namit@vmware.com>, Brian Gerst <brgerst@gmail.com>, 
	Denys Vlasenko <dvlasenk@redhat.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ubizjak@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hi44lmti;       spf=pass
 (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::230 as
 permitted sender) smtp.mailfrom=ubizjak@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Apr 10, 2024 at 1:11=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Mon, Oct 9, 2023 at 4:35=E2=80=AFPM Uros Bizjak <ubizjak@gmail.com> wr=
ote:
> >
> > On Mon, Oct 9, 2023 at 1:41=E2=80=AFPM Ingo Molnar <mingo@kernel.org> w=
rote:
> > >
> > >
> > > * Uros Bizjak <ubizjak@gmail.com> wrote:
> > >
> > > > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > > > index ecb256954351..1edf4a5b93ca 100644
> > > > --- a/arch/x86/Kconfig
> > > > +++ b/arch/x86/Kconfig
> > > > @@ -2393,7 +2393,7 @@ config CC_HAS_NAMED_AS
> > > >
> > > >  config USE_X86_SEG_SUPPORT
> > > >       def_bool y
> > > > -     depends on CC_HAS_NAMED_AS && SMP
> > > > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
> > > > +     depends on CC_HAS_NAMED_AS && SMP && !KASAN
> > >
> > > So I'd rather express this as a Kconfig quirk line, and explain each =
quirk.
> > >
> > > Something like:
> > >
> > >         depends on CC_HAS_NAMED_AS
> > >         depends on SMP
> > >         #
> > >         # -fsanitize=3Dkernel-address (KASAN) is at the moment incomp=
atible
> > >         # with named address spaces - see GCC bug #12345.
> > >         #
> > >         depends on !KASAN
> >
> > This is now PR sanitizer/111736 [1], but perhaps KASAN people [CC'd]
> > also want to be notified about this problem.
> >
> > [1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D111736
>
> Filed a KASAN bug to track this:
> https://bugzilla.kernel.org/show_bug.cgi?id=3D218703

Please note the fix in -tip tree that reenables sanitizers for fixed compil=
ers:

https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=3Dx86=
/percpu&id=3D9ebe5500d4b25ee4cde04eec59a6764361a60709

Thanks,
Uros.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAFULd4aJd6YKXZr%3DAZ7yzNkiR4_DfL5soQSvhMhNiQEPUOS87g%40mail.gmai=
l.com.
