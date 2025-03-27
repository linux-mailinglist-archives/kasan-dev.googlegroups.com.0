Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBC6FS27QMGQETZYHE3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DE5BA73E61
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Mar 2025 20:10:05 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30d8de3f91esf10133831fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Mar 2025 12:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743102604; cv=pass;
        d=google.com; s=arc-20240605;
        b=ESjuVFF1AN1lzVn8mD0yUZR/wAQpozpYB9TFVeB+ab5EWLdEG6aDz5qPIQKqvh0aKQ
         iesQdUCAm0YLGXpEKkOmjPMnG0IesDBzynxWR3d/wqAq5Ty4DF0EOCM62Q+wps/+I8VH
         L8iIj8mrnKSVxAP9PqwKU4bctfRsr9pG3E9Dnr+xllRIrJGIPcmyNjF528ucJv2IRTH1
         ++lPYTd7BLX6x46GTvhYVc3HeSQgiIBYfZ3OTz1rLIjNcjRbUhHr48p9JGrF4l0riI0D
         C00fnjx0395BLdrThE2Ks5TrAhVLFVYZ8WNHGf9C1EuUG0JjXxIXYqypmKoobmcu0Jcq
         JHpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+NBkzSbraRAk2EnCcB0w/pGMeYntxV6x7Ln1royr5QA=;
        fh=X6CwXsMflqFjr7uqboFrRPKRJRcp3f6QsaulkaLLkbY=;
        b=W5PojBM6jorxlsx/6IgbCNJK3dBqVaQfefZcc9mCm7LMuRvBG5seI4kDARleyXTao8
         a54DS7ENf0kc4h3VESqjrjhb/bm0689nHi2Tjf38CbHpOFQRGLMDZQ2hz4bvnVR1P2OD
         46504wft02XQmCu9x+CSyo3VHGFhM59ubTjuL5pj+fIbD+jaxe1f7ogBj/NSyP+EGA8L
         ooauxXFa4kogzyzJuxaTVv0q82ZF6GRWsqelHiDI2Rhd1zcafEqdPLhO5npWHa8N+qlq
         gfltEWV2xmboV0t9J83rd7FUvbJoAnpQSSlvsExynIzArWvZHN3LRiRPvK4H3YcNaubb
         Fnnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3FSNcX7l;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743102604; x=1743707404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+NBkzSbraRAk2EnCcB0w/pGMeYntxV6x7Ln1royr5QA=;
        b=k6C7IdvHJqd20ku6riJGDuZZC68yfDncWppVL6wGBZ34LFquzdyy4zKzoIj3fbpg1k
         t6/KmuImspEaRUpOzIETalvowmqzxMUQu0w5ZLG9lIfEzgIpwCdBthTppVq9hXAOCOCq
         atIRDdz+fMYG4Khc9WlBkYwXujhaELkQpuE1E81vM54GYt0fPWJ1FiOwlhQnHeA1idzZ
         rR2um2cvtYAMBkwuzexT5WHnY+N8RC03d0VQDWChDRDh0iLNMPxEWioSCCQHFPtBcDdL
         cobplolfvzNYG054lLEATgUg/BhZE4sK9YtNJg5Ra1sY1uineTj441BQMhSSvIKvBpcR
         PD7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743102604; x=1743707404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+NBkzSbraRAk2EnCcB0w/pGMeYntxV6x7Ln1royr5QA=;
        b=wFNYcfzNKNGiVC3c8b3zcqevLwOMVyn2es2OLZ+c8lj0eeEpqpjd06YcIo4mHE5c0W
         CoY8GWU1DyWai2I8Id06mpGyyTUnMW6amO98Ebqg+FtEFye70j+6oHHcjWaf5aU+5Xym
         hsQ50j+Yw/n7qVP3MaTaSUKDx7hmFN4W6olxF3Fg0FDgV7oaIPYtpztkF/CE/YfhphnY
         xAcdeD7z3aCSVGnAn2eq//9ieIYDI78meDPC0W23SABl5mOLrFArlxtDa1Xktumfbt6H
         5W5bODXYt6+3NP8S2ESlw/uPF1rMv/p5HhM0PekDGc4BpNummrVGnIHc/xoEtgaqwgDQ
         QLyw==
X-Forwarded-Encrypted: i=2; AJvYcCWxvxigzGlEScipbMW7vpCHeBnIKvxJsjHORDYAxJJ/XgWKMGq8kz071N/RetDUYGt5xYifVA==@lfdr.de
X-Gm-Message-State: AOJu0YwlnPuSck6qM6mr5z2rzpAmJwrjw1w+fSp5x7xQCXRv+z5gQfR2
	ktBDladwciO9SiHOxKgO+iEYVBLFA9NbrhifrOdjVQVkQxx9/wVv
X-Google-Smtp-Source: AGHT+IGl2yu2Lg3FKENgz8JSoK3MqrTz9pUAIBcruJTsr5kHhOrVgUizId1ra6wCWMluzF/tGkCy9A==
X-Received: by 2002:a2e:a984:0:b0:30b:f775:bae5 with SMTP id 38308e7fff4ca-30dc5dd2aa7mr20236531fa.6.1743102603797;
        Thu, 27 Mar 2025 12:10:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALAFBZlfLPElxUfmL9FOHoGOjT9u3EJKpN0aoKu9YPo+w==
Received: by 2002:a05:651c:1056:b0:30c:453f:c433 with SMTP id
 38308e7fff4ca-30dc65b6731ls2240081fa.1.-pod-prod-03-eu; Thu, 27 Mar 2025
 12:10:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzkrBUwbofNYJA/uOeBdFhVd9er+zybV3mG2c9OIILeqagJ7e50DkfksTwJpm++sdwyR4d0wnkVgM=@googlegroups.com
X-Received: by 2002:a05:6512:3b9f:b0:549:8c86:7407 with SMTP id 2adb3069b0e04-54b01289d7dmr2017457e87.52.1743102600941;
        Thu, 27 Mar 2025 12:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743102600; cv=none;
        d=google.com; s=arc-20240605;
        b=IPqw3dPz+n/SvM/XmKmfOFtNlrpeslc5aBDJJ5jNnh4lD9uZNuZ93XeYI9/itFnS/H
         hYuqvRFbLZCm9Dabw7SUojX9Vj5jWJGNboFiCLXbPqz3DNti5QZXIKZllJm7VYJrU8c/
         FPkABpqqai7r4bpb0ku1Fre+tP4E47WWZLgv2WFuufP82Ud8cr2jXy2w6g9wl8XFZlZC
         gTkYVgnmuO/R8PVNDw3ceb5H3uEO6uXvJhBEi+U8ZaPDM9ts37BMCNpnDW7ww1TCqriV
         T4eX91S4+DglHeJAufhVG6B83p+2F+SOaVAOmFWTbBAwMFaPalrTzjTj6rdz5noW7rM2
         wRmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RUuFRox/uRP18i3K1c7cQBFPt0r8UQeqKMMt0JvYusg=;
        fh=79KCVXXYn417gNB6GOT5sEPUIyKO4LiVuewTLqV2t4M=;
        b=lIK0gAB9WWeKrCP258MCVa4JwWtLJz5+vOwP3v7Ey7C3i67gfOn98E99Q3dR7HmASh
         lCC899CrxxqW1Z7QNeOFeAOcYqpV95COWTLduB4YnQ9PrOE0VDv9qxkkT5GLWsyhdTiB
         jmBjkyBjkG9fiYGSSLwharjNzcBujc072AM1ZwCym9P97E0zD1yNbZF1w6t6EnOQei03
         SxvHv7/uH9jzlCoQDCcicu6OpfOwNazIP4tsiONCpiIOhjwzxPEP+Kh//wxlk5bjNFLA
         F2XL+C4rtaXXc9+Ip5Pl10pOI4V23oB4Aych8sGhfBAtq4U8y28XBQCg88lGwCNqSqCd
         6AQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3FSNcX7l;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54b094baebcsi14753e87.2.2025.03.27.12.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Mar 2025 12:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-5e5cbd8b19bso2472a12.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Mar 2025 12:10:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUbPgHILQnhRA7Ta9Jfo2xNVGnNw4UlvsPcy7NQNDeaRyFJBSdzuRCm0e+uABlB04Egm00OSa0dgnw=@googlegroups.com
X-Gm-Gg: ASbGnctCpxdCqSpokeP5oSTd00kMpCVwCPhKOqNhNEBVJADJkBKees3jF2ULCSfNaS/
	CRdTh18X1xOcmnxFNlJrI/kbyjGvyeSnnKRCHicqa4KFQSk9tNAy3rwWwFzy+/2loD6+foA+jK9
	NqPqR7HVS+vW9sGmG/MfhHCw4ImsU4QnNX0naAwzZK5a5FaRyBHXx378n1cwG0PH92
X-Received: by 2002:a50:d613:0:b0:5e6:15d3:ffe7 with SMTP id
 4fb4d7f45d1cf-5edc31eb882mr9171a12.7.1743102599869; Thu, 27 Mar 2025 12:09:59
 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ=A@mail.gmail.com>
 <CAG_fn=UF1JmwMmPJd_CJQSzQAfA_z5fQ1MKaKXDv3N5+s3f6qg@mail.gmail.com>
In-Reply-To: <CAG_fn=UF1JmwMmPJd_CJQSzQAfA_z5fQ1MKaKXDv3N5+s3f6qg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Mar 2025 20:09:23 +0100
X-Gm-Features: AQ5f1Jr5wNbIvQR1MW-T7jQhq0ywmSJ9hxwgEvhc7yrF336jp7xpkEVq02UK2vU
Message-ID: <CAG48ez1w3YO=dwuGqVF3PdHec6=vbYr3GmabY-qQHbZ0fko2JA@mail.gmail.com>
Subject: Re: does software KASAN not instrument READ_ONCE() on arm64 with LTO?
To: Alexander Potapenko <glider@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kernel list <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3FSNcX7l;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Mar 27, 2025 at 8:29=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
> On Thu, Mar 27, 2025 at 12:10=E2=80=AFAM Jann Horn <jannh@google.com> wro=
te:
> > Hi!
> >
> > I just realized - arm64 redefines __READ_ONCE() to use inline assembly
> > instead of a volatile load, and ASAN is designed to not instrument asm
> > statement operands (not even memory operands).
>
> Nice catch!
>
> > (I think I may have a years-old LLVM patch somewhere that changes
> > that, but I vaguely recall being told once that that's an intentional
> > design decision. I might be misremembering that though...)
>
> We have some best-effort asm instrumentation in KMSAN (see
> https://llvm.org/doxygen/MemorySanitizer_8cpp_source.html#l04968) and
> could potentially do something similar for KASAN, but if I remember
> correctly there were some corner cases with unknown argument sizes and
> with percpu instrumentation (at least on x86 percpu accesses receive
> an offset of the variable in .data..percpu, not the actual address).

Ah, I see. Annoying that memory operands are used for that...

> > So because __READ_ONCE() does not call anything like
> > instrument_read(), I think instrumentation-based KASAN in LTO arm64
> > builds probably doesn't cover READ_ONCE() accesses?
> >
> > A quick test seems to confirm this: https://godbolt.org/z/8oYfaExYf
>
> So should it be enough to call instrument_read()?

Sort of, I think; but I'm not sure whether instrument_read() is
available in this header or whether that would create an include
dependency loop because READ_ONCE is so fundamental
(linux/instrumented.h depends on linux/compiler.h, which pulls in
asm/rwonce.h). So instrument_read() might maybe need to be open-coded
if we want to use it here? IDK...

And also I think this would probably cause ASAN false-positives in
__read_once_word_nocheck(), because I think disabling ASAN
instrumentation per-function with __no_sanitize_or_inline probably
does not disable explicit instrumentation through instrument_read()?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez1w3YO%3DdwuGqVF3PdHec6%3DvbYr3GmabY-qQHbZ0fko2JA%40mail.gmail.com.
