Return-Path: <kasan-dev+bncBCG5FM426MMRBXMSZ63QMGQEZ7LIZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 68A3798556D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 10:27:11 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-27b703c9603sf544130fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 01:27:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727252830; cv=pass;
        d=google.com; s=arc-20240605;
        b=FpOJ0JFjceYs7/H8s2SwEtw3bDffa0tIKwku8AeJYByqTTiKCK4Dm68vWNUVrtvG4I
         lCJsfojg82+vmb+mcYJpbrLFmhYzWFUz9I1NSAj/6bgKXdmgekII7sreCzl2mgGwlLWI
         VIcMWAkIoVn4JWAa1TaSd5xaJZSj3751sIZ9kJw7kzqGs0QC8Q4T4Pp6aJlCxV5253yy
         YplHnKOhdrkyDn3pUcg+XOmePy0TEgYw41w2FOXKU8R1JAwVjJvc90PHrtsR3n0p/gjZ
         znPayF1LRcUR29A+kAfS86gt+1bCQONPC5O21y6nFbciCim7eE3NB5rsYFyg7eseVXzh
         pafA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OuoNyFhS8kbUNMJ63TJwVEBPJq4v2s5TD5vzRm4aSqQ=;
        fh=8TN1uAbNNIEHpgl6svAiHP+GvjbvSRP5IcENvmGAOlA=;
        b=VfQ3G0TloAyRQdN+zXNJ2MswAJionJ9qHcyO2/DKBfh0FR+QPeEnKxtFj4kkVaGJGu
         evc6N4ptuucuqzeJIecLcaQZsFnQJydhY5vQNPmr3OnV1dTQ4BGG06kV+w3dr8ANB/8m
         pxkRZWZpkhNIC+ewBUHJ40tGnRWeDDWmlK3+BuPKhhX1s3QNbaR7D2QAtf+/ygrGbwvD
         9Zm5jx+0nQI8PeXBU923oMzm/G3bv4d3CSHrbR8ziVe9EveNmbpRGuIQoAizH/EJPAJw
         z5cp3T5VR+iIee8g3e//yAbAOgj5/nJrI3nJht3EcZjsb3gXXyZJ8/ousT2d0l5Y3pTl
         62tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G213qyjX;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727252830; x=1727857630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OuoNyFhS8kbUNMJ63TJwVEBPJq4v2s5TD5vzRm4aSqQ=;
        b=QWKG/anDWJtWy+G6tJ23yfuCpW5yjVrV5ZxDC9OyxAHld2/dFtp+MJwLpJFxu+PCX6
         JN9I6QKR3YhWy2csvaw8CGTs/GXg1dHvNL3R5G9mwaEtlBVbWn8Ncye2fUWne3emvaib
         5F+6qYWcQ46mhmVzulRFVMKDz+0dXKxJzfafzrRIPzXOuQZG2RPHwa0xNbx9CO0rlSQe
         1UFyjw8E71jfBktLAEhxKVPfgj8G+G17GvV5BoZcDzCsi0SQgBsTWXWNf3Kp8WtD8tWU
         A42WphbfliutkmvaGbWeb0xHq2sNXZHno0Go0E1Z/s5jKAJN8dLiXY4CqEV2LHfMQEAW
         +Aiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727252830; x=1727857630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OuoNyFhS8kbUNMJ63TJwVEBPJq4v2s5TD5vzRm4aSqQ=;
        b=PZR9PbOOvCMjFhyF92n9Xl5PZm0no2yLHL/e/zRY07bs/aW8Rx5B3CEyQRWJ0hpKrf
         SWBLZDV/7NixTU2S5zWnamWyaovGBVrlFm4C+XfcZbPWEu+Nrg3PJIvwnAZwHsQ6J1xa
         75cpnE1BUvS/x8BSBC8mgYpb0inlemed6ggktTwr3HEq+PqVQzSYWtQUfWwQekXMzowX
         B6ShzVsSrlx9yUGygchKF4yzizU+AuHwt9K+JApix1wstqfegm6TSj8ojmdvVJ6R7Oim
         QRzeCAoksJmtJd9TOr7IGfw541SZdPN2kINpPc5UcAKZ2q+AtnwP+3bPnXLd3OjZb4JE
         8gPw==
X-Forwarded-Encrypted: i=2; AJvYcCUqC/08RVBNSluJIVVKH0EDqqSqdchG3Fn9+Sor0+HIqo7H6DWbtEq6g3JUEpL91lCwEQ+4Xw==@lfdr.de
X-Gm-Message-State: AOJu0YwtxJDsnnBXcHSAx8UZwQsKkBnyhZ/zgeABeVbeHDhjvsQ108KA
	uaexcqzOTCqClkOx7rGBOvWTqp0zLd+aKfdmM8I9cd95twL3ZKC9
X-Google-Smtp-Source: AGHT+IG9pKMjpI8Zc53/SGPBjxzKUZDQrMwJl4SnLRzAxdEZGncn+PnOwQwse2G3aDDF2B2f33ijvg==
X-Received: by 2002:a05:6870:168e:b0:278:a71:2659 with SMTP id 586e51a60fabf-286e2b7a4bdmr939715fac.14.1727252829991;
        Wed, 25 Sep 2024 01:27:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e06:b0:277:fe8a:7e8b with SMTP id
 586e51a60fabf-27d09345548ls2460328fac.2.-pod-prod-00-us; Wed, 25 Sep 2024
 01:27:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+k7RG72r63wStLV3d03UESr0lfLhac3i4O73ampvXlqqIZVZlufLnyfpSruGzmpu8VMAQdiKkSsY=@googlegroups.com
X-Received: by 2002:a05:6870:90c8:b0:267:ab12:7fbe with SMTP id 586e51a60fabf-286e25c32f1mr836480fac.0.1727252829222;
        Wed, 25 Sep 2024 01:27:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727252829; cv=none;
        d=google.com; s=arc-20240605;
        b=a8RYMuJkataNRk4751LFiut07PvGyRaOCkm7iwOClK18ZhrWltqcf3FKdZ5twrJkNI
         guaXDg5Mp9EoIDjsbBqrT+Eq6H7rbr21ygT77LeJ+I/hGSVsPJYG6+R/qVl++tmsxMrZ
         xEY3C+Sa7QRm8BUIq2l+K7TGdeLIkRIJ5CY/UkpDl+pMCoDgGu+KPQB4MgWSD6Dl4YaS
         QIK/o0IRZozPCaWNvlhnqPnPok05VeLn9ViIaBSr1aaNIJzY8yqSq5IRnw0vg/mDiaub
         P4Bry53BRERG3fTmA8SXdz/PsLPCVKrf4kFBsRxHvzvuTv3yxpUn0G4odyhXHfpDv4Z6
         7dPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=25jgtKw05cLljXTa9ioZMmKXC7JJSPXQkmgPPZPPAvI=;
        fh=6+FJ5iSxzEep5+zRly2QWAD1no0K4JyHitJOXK+Hq8Y=;
        b=bQiEVTyZy1+ehMOwuvtfOH/xTxmv+q32NUk6jGrlx6qUPf8n0V9hqlNvx0MkOPJUwy
         YdqGs1XKLn0/c1wmVuirDAdToz+QGGbN1O4ierEBdT+qKElmjMhEw0V9oP0PeRe0t5vw
         HiwRzhNdea2g2aSwEWrz9DNSpFIII5RpbYekE1e9L7hojNcWk/XDiRVDKPkICwP8qSo+
         wrak3yJfN9GmhLz2Jr/9xueaZi4+pAbLGuSZfJQr0ss9F1HwGZAjmJ+hoiJHL6NPsdvN
         uERZKYuTgEI73FaQBwkG50X4nqn13Qe3VpP+Xrz6JlIApOU6D1+J3IJYfDhnbwamEjOT
         b0vA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G213qyjX;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-283afc2dae9si171595fac.5.2024.09.25.01.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 01:27:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-718d91eef2eso502513b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 01:27:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfaJ4PgQw+GFtdYK0ACTlt586hWcryKw1GlPriBEQtx431NKmImr7co09Oxwyj+fUS7Cp5cjRDJHw=@googlegroups.com
X-Received: by 2002:a05:6a00:17a1:b0:706:aa39:d5c1 with SMTP id
 d2e1a72fcca58-71b0b21dda5mr2945661b3a.8.1727252828232; Wed, 25 Sep 2024
 01:27:08 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
 <CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y=C+m3vVA_8g@mail.gmail.com>
In-Reply-To: <CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y=C+m3vVA_8g@mail.gmail.com>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Sep 2024 10:26:54 +0200
Message-ID: <CAH5fLgheG47LdgJGX6grHXL6h08tsSM1DACRkkzQk_1U8VAOxQ@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Matthew Maurer <mmaurer@google.com>, andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=G213qyjX;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

On Mon, Sep 16, 2024 at 6:47=E2=80=AFPM Miguel Ojeda
<miguel.ojeda.sandonis@gmail.com> wrote:
>
> On Mon, Sep 16, 2024 at 6:15=E2=80=AFPM Miguel Ojeda
> <miguel.ojeda.sandonis@gmail.com> wrote:
> >
> > Applied to `rust-next` -- thanks everyone!
>
> Also, for KASAN + RETHUNK builds, I noticed objtool detects this:
>
>     samples/rust/rust_print.o: warning: objtool:
> asan.module_ctor+0x17: 'naked' return found in MITIGATION_RETHUNK
> build
>     samples/rust/rust_print.o: warning: objtool:
> asan.module_dtor+0x17: 'naked' return found in MITIGATION_RETHUNK
> build
>
> And indeed from a quick look the `ret` is there.
>
> Since KASAN support is important, I decided to take it nevertheless,
> but please let's make sure this is fixed during the cycle (or add a
> "depends on").

I figured out what the problem is. I will follow up with a fix soon.

Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAH5fLgheG47LdgJGX6grHXL6h08tsSM1DACRkkzQk_1U8VAOxQ%40mail.gmail.=
com.
