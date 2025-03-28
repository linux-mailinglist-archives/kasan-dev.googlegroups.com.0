Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NKTO7QMGQEX4Q3Y5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30461A74EBC
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Mar 2025 17:59:39 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6e8feea216asf65192786d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Mar 2025 09:59:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743181178; cv=pass;
        d=google.com; s=arc-20240605;
        b=RXpMPldkVgoSYW4Yt2+hDnI1nhaqDZ/ytYb0DYCQi5wG6Fyx7yacCBAa4Is4P+VCNg
         AmRTdU2/Rlkj+pO4JOD5ZVQhqNOxhQvrAABs5AfqCijvGYdu5Poc2MWKjZwndp7Ow+nJ
         ihHhKJMHU0HtrClljEEzBwZ27PmKPkRYx0mCOQiKkxdiWJB1NyRRcswrlpPb8+6HguF7
         cL59kUg5Pdz0B52HPNnb+uAIayV3DFkzKJD0GB9Fc1MVgu2qSUoFuDronwF5jFIKqW7t
         uiVatSzh9MV+fd0U2e9e6HTs1D0QEyhz5qngeGzYxFj/y+VJI6NUBLhnDS6tVrdrXYZZ
         jp4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pdL4qM1p1UPICvRk3kvl1/iowjAP8tiLCVcSCeOVIkg=;
        fh=Uk6Md3zYVnyw3d9zL1BRsbRKJEcA0F95s4irNiD/Y8Q=;
        b=CNbEzuqAAaoFMQs6zw3nAV5dT1SeyYyKq3bEukGjLAOPSgFjS+aV/B02KuksfwawMj
         3lsNkrGilQ1JFqLVCJs5KhOyC8XnqcyaCUaLA46DaU9FW+kVN1eu0kTFavG41ldOAfeN
         5QoQaFHyGQNSJHveVfT09CyYJnqKWs29B/8tGPtATY1FAW2IV11TI2O2WJvvVxxD5Wor
         7pUEF02bN+id1YJBLf8rS/AstNJs/mFsQp8lAkKBr9Ncv1TRSD6c3AM0APPeyZHb1iYV
         zL7S30RKwo9ajdsiE5lXjWGdMNqCZyOouofMFMRs5zU7r9lCKgpjIV+1x8QlbwoqIXby
         431w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yj1leCp+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743181178; x=1743785978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pdL4qM1p1UPICvRk3kvl1/iowjAP8tiLCVcSCeOVIkg=;
        b=NbfYLgsh525ydHyeJf2YRcaQRhZE136mlGQHCfm73jNYCJkplWtIfrWlVYdtIF4BUR
         6X4QevrGbHTzhztyUmpJxXTvwu78dw4hc0xCWzTeerz1QeARrVeJZgPesmg67Nx4TzUF
         i/5TIWWB5t7BcgrnJAqTrQJsBW6xpW788Pya6tfUjqm0cUky3lw7z8bJ1KVdWkyH+UkH
         RFTVXv62jRFgj1MgcE/QTsPTHnZkB3oaZ1QpV7yIN+9LTpxZywFFO54sR7DoXSrzKnj3
         kZjGoxykme5eERRtmskPgatpwPrScTGlZj1Ux5nGB4EN0MQhYT3AdPz4FitGAexE4/rn
         nsCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743181178; x=1743785978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pdL4qM1p1UPICvRk3kvl1/iowjAP8tiLCVcSCeOVIkg=;
        b=BWvs/aTfqoBwR9rE9xTiOVhccgsRuBENckdkFukTI9eRgZje6EfrU24Kiyb1h0I6nE
         JT33bv4VOnopJj+bThNer9NAUrwfa/ztF3Wn+Lmbd6+c5UYhrKVFCDSgVG5usCGgnf7X
         w3067h+L0fnTsj6ObjT1L/fQq+U7LaTVSDv4UZN0hxqAa+ju2rNEs0nscAFOQT9EQWNn
         igynA/hMWPjQbUdvhvmJCakLKVzwZwj2VVNVELK+T2jGQSIjhnGF6h07G9QxWXNiHxAV
         NSx0U0TGqIPRrpMqjD7uWmoDHufh5eEMvLAcHIE58tUSOco+R1bELPHjdKHoH6Spl+Qu
         aiAg==
X-Forwarded-Encrypted: i=2; AJvYcCVuAbyIMzJC0RyDrTOlL0BzvsTi5yrxC2EZyLj61dNFLem1OgG8BSKsgNYh7RaXryl6PG35sg==@lfdr.de
X-Gm-Message-State: AOJu0YzA+DTKtV6y+1ByzdIYzza94NSC6i2F9Zcs/uc/PjNxgL6WrQuE
	nyCwZ8KA2aNVlyLkn2SBf7Fb7WLeDPPjDYEjSODZkFrPuhprnPBy
X-Google-Smtp-Source: AGHT+IGs67NVg4i6FbQwIE8miDwoTCWV3/SFye2tz8zgmnIrvIBJujUg9M0bCgDXVTbCgelSyShopw==
X-Received: by 2002:a05:6214:234f:b0:6eb:1c42:a14b with SMTP id 6a1803df08f44-6eecb86924amr47925426d6.1.1743181177518;
        Fri, 28 Mar 2025 09:59:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIsWP2GaHRWZlNLkN9RpJ7kcncp3XYm6gey+WCEJV1PhQ==
Received: by 2002:a0c:e842:0:b0:6e6:58a1:caec with SMTP id 6a1803df08f44-6ed23281735ls7110426d6.2.-pod-prod-00-us;
 Fri, 28 Mar 2025 09:59:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUo7vqzv85bmHWa2rChPwE+rwpp1uqVQMgrCLxW+DeFZiWF+KpbclJ96FERDpRYl2dPRnYNDdMHOt8=@googlegroups.com
X-Received: by 2002:a05:620a:244c:b0:7c5:a681:1b42 with SMTP id af79cd13be357-7c61db6b8d8mr36564285a.3.1743181176398;
        Fri, 28 Mar 2025 09:59:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743181176; cv=none;
        d=google.com; s=arc-20240605;
        b=VWXBYMurjNJuh0NrcjqQvapPoj0wTYUwhCeXdJhOB2CMmqEhQckve3jIxvv1urlsJl
         K5KKFMnEekSqBlzdVYEVgbQBWYPTZZ8/DDO2CRnDO/xHCalxbRmXREBk4/UCPYX0O1qZ
         2c8MIJNQEnb1LWV5tMKjZIcdXfCnlRnRU0SEAfQmLEG7ZPi/Lf0MiiW/PSciKd+wNWug
         1uiCxKxpeUngm4i2IRd1kih9CuDIdLy33y+vwiKAqYdjtYtqu84KC5JXamUmTM1DLzem
         TZKZJy8yZIMudonlpTKj9snft0pad0Nbq+MQTkSteoaD05sSdvxH9yhr35Rh0CcaS/AD
         Lh4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Co4RpiFV+ly6UFErhco3vS5kdG2BX+IOkv6UHpq96sI=;
        fh=z90GfN55aoQIxIARxtnhjFuyykx38MBnbYcnIXXCk0I=;
        b=F/1KHZYt5CWQu6RZlkYON/4Qf+reXJUtsvEtazIzZYm3d8QLzF9V2ULh3Rv5tRDhWr
         O7ON0s9dH6g7JnirkOVm92y1b/wJZwFfWAm7tzJA8bE9oX1uHIBO52lYQT8yrIS/+Ud0
         uyQBBXGKGh4dlSE8LAIJJh+M3ME3dq9e3skqXrnsdJCSB8GR9oP4qS2NNX8H4a5vKj8X
         IN6VjEB0eZoboE14GQa5P/2yfKg9frBTFFFg16nnhPScxDnIR//1bAROoGCSXY/IwjKb
         X78Wt4Z/XxXjNDw+D6r03wSS63ymFh9SismklNbzW2rR0uoBX6wZeCz3Lr78UowKx2hD
         xxyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yj1leCp+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c5f7735fcesi9533185a.4.2025.03.28.09.59.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Mar 2025 09:59:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-30185d00446so3374364a91.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Mar 2025 09:59:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUWB4CDdAmVlbeHcE2jghhTs/ng8tQd7jmL/acbgq2wpunTGa1EOsTYyt5snjdEZpNFscaTzCww+sg=@googlegroups.com
X-Gm-Gg: ASbGncsmk1ghuHd2AJgP8CwOlW+NgPLLo+vs/m5yoPpT1h8+Aw7QfQB+Q197IQdSCYx
	H1MSwdv9adqF3MKk4Zf4p/y+wCwfZGKHirfNx9c+rGtyQxTcvefDS/AZS2veSaYnmCRGMBDeGmu
	8LGMjIT+Fvpc0Eu2qrolDRmhJGA1XsvfaWk7Ns8huCOC5KJMQhcj8Jr1q3aA==
X-Received: by 2002:a17:90b:42:b0:2fa:4926:d18d with SMTP id
 98e67ed59e1d1-3051c952251mr6075406a91.13.1743181175080; Fri, 28 Mar 2025
 09:59:35 -0700 (PDT)
MIME-Version: 1.0
References: <CAG48ez2jj8KxxYG8-chkkzxiw-CLLK6MoSR6ajfCE6PyYyEZ=A@mail.gmail.com>
 <CAG_fn=UF1JmwMmPJd_CJQSzQAfA_z5fQ1MKaKXDv3N5+s3f6qg@mail.gmail.com> <CAG48ez1w3YO=dwuGqVF3PdHec6=vbYr3GmabY-qQHbZ0fko2JA@mail.gmail.com>
In-Reply-To: <CAG48ez1w3YO=dwuGqVF3PdHec6=vbYr3GmabY-qQHbZ0fko2JA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Mar 2025 17:58:57 +0100
X-Gm-Features: AQ5f1Jo5avP8gathSpZrvGuQ9hpBAo8b9sd-f-ysvgj_1b3jBP--BO4MKJWn5D8
Message-ID: <CANpmjNM_+gkQ2VwykXxu+7DL2ib2-4O-jDnn=+rXQn_e4=BnBA@mail.gmail.com>
Subject: Re: does software KASAN not instrument READ_ONCE() on arm64 with LTO?
To: Jann Horn <jannh@google.com>
Cc: Alexander Potapenko <glider@google.com>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kernel list <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yj1leCp+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 27 Mar 2025 at 20:10, 'Jann Horn' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, Mar 27, 2025 at 8:29=E2=80=AFAM Alexander Potapenko <glider@googl=
e.com> wrote:
> > On Thu, Mar 27, 2025 at 12:10=E2=80=AFAM Jann Horn <jannh@google.com> w=
rote:
> > > Hi!
> > >
> > > I just realized - arm64 redefines __READ_ONCE() to use inline assembl=
y
> > > instead of a volatile load, and ASAN is designed to not instrument as=
m
> > > statement operands (not even memory operands).
> >
> > Nice catch!
> >
> > > (I think I may have a years-old LLVM patch somewhere that changes
> > > that, but I vaguely recall being told once that that's an intentional
> > > design decision. I might be misremembering that though...)
> >
> > We have some best-effort asm instrumentation in KMSAN (see
> > https://llvm.org/doxygen/MemorySanitizer_8cpp_source.html#l04968) and
> > could potentially do something similar for KASAN, but if I remember
> > correctly there were some corner cases with unknown argument sizes and
> > with percpu instrumentation (at least on x86 percpu accesses receive
> > an offset of the variable in .data..percpu, not the actual address).
>
> Ah, I see. Annoying that memory operands are used for that...
>
> > > So because __READ_ONCE() does not call anything like
> > > instrument_read(), I think instrumentation-based KASAN in LTO arm64
> > > builds probably doesn't cover READ_ONCE() accesses?
> > >
> > > A quick test seems to confirm this: https://godbolt.org/z/8oYfaExYf
> >
> > So should it be enough to call instrument_read()?
>
> Sort of, I think; but I'm not sure whether instrument_read() is
> available in this header or whether that would create an include
> dependency loop because READ_ONCE is so fundamental
> (linux/instrumented.h depends on linux/compiler.h, which pulls in
> asm/rwonce.h). So instrument_read() might maybe need to be open-coded
> if we want to use it here? IDK...
>
> And also I think this would probably cause ASAN false-positives in
> __read_once_word_nocheck(), because I think disabling ASAN
> instrumentation per-function with __no_sanitize_or_inline probably
> does not disable explicit instrumentation through instrument_read()?

Correct, the attribute doesn't kill explicit instrumentation.

Easiest way to "fix" this is to disable the promotion to acquire by
arm64 when built with a *compiler-based* (i.e. not KASAN_HWTAGS)
sanitizer + LTO. This promotion was only made because of fear of
overaggressive compiler optimizations with LTO. If there's a bug due
to the compiler breaking dependency ordering [1], it'd actually be
very nice to see a sanitizer splat, but I doubt we'd ever be so lucky.

[1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/St=
atus%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Ke=
rnel.pdf

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNM_%2BgkQ2VwykXxu%2B7DL2ib2-4O-jDnn%3D%2BrXQn_e4%3DBnBA%40mail.gmail.c=
om.
