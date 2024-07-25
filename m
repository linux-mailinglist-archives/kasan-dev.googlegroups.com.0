Return-Path: <kasan-dev+bncBDW2JDUY5AORBWWMRO2QMGQEK7MFLTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD12F93CB83
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 01:57:15 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-42807a05413sf7327695e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 16:57:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721951835; cv=pass;
        d=google.com; s=arc-20160816;
        b=WIiYKsb3D0x0RWO0fbQqqO4PHtPDr4KwVcLEcjv07lnhWNBZb0sR+J2RGDqvbxf+rb
         GTzs/jg3kCme/SHqadxZly3HEPgnVaXcKXzqu8XkpFOlfw5DzVQ7I5ADdME+xbGkmGeH
         hWSh+WdiApwhlYt1pTdLfdpCNsfXe7oGQGPTnlFTvQxlxV9zsmEYpKfd738p/7dFofhf
         zB0AjguNh9yr+bWl8Q6BfV/vWOaLiFN8eSDRFwAQzKVOg6GOsjB+3mmdu9+IRska4RYA
         5WOikdSbDO8utqh4uVSEjQAOT9ZgWQhzkpZpJt7eiSlVlXuQRHvz29s3y5BHsjcNNyyj
         ENRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=euN6FREumlz1F7E3OhyuO1KmfqbzfBtn4wCzlGKPptk=;
        fh=XR9jS8dh3uThM2VTCHqervvQwDEgk+me/JBCxxuXW38=;
        b=qQiEZubLMQ5X+ayfi9pEixSaYBhmkAtKjwiM7V/wCLUtDQI8DTYx6n8zu45xMUBIdU
         JQ72765sxUAlxIlgjmRSW9lo7G0a2huAmpK53bcJ24SQ35/TnQwNdBG4Orv6HJHiKVBu
         25qihMdWnoXUqktTwWgjdjDxkYPu8lk7g24pik9OExQEMQU8E1OlpRei/Setfo49uzlA
         c/+bNDymL6/G+GMSe+as/jtg5KwFhUsute3QWoi8QRz4M4saH4PFdBHSuecxV0O3sBk4
         P9pRvFrf/7Toa4erhRp4jUKYDzCGpFnlkrbqdkt2FVGbYjHXZRPJqDd3tSTOXPgjM9WS
         o4vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ETF1+awv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721951835; x=1722556635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=euN6FREumlz1F7E3OhyuO1KmfqbzfBtn4wCzlGKPptk=;
        b=ks4Z1tCke36FJGJJf4DdlVj8wCd6opA99hUY25fgKHWeE8BDyHeYLTQkDbrnLzPgDB
         a0NpqRaT1lbjMvvnEpKiihGZktuSGCjrUgBRQicWEokGAsNJA+e2eGZ8BPSDWrNVy0yY
         BL4h9HWkTNAysZqFcj5lJlHTQHuRyC832LXzeKrYG2v0W3/1RRQTSai9qAbnGCG65dCk
         r0vfhBjlYWG82yA7otwI50LOFeSXVDF2gZ8aEqtKdAvrON9yVwQf5QU9cHaf9DU9Ccrd
         CPDxsFE5MP12w3uta6uyLvbjKjDmU5kNG2/1GmytcANBD4JUEVlJkyLf/pml/9X6dW7Y
         V0ag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721951835; x=1722556635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=euN6FREumlz1F7E3OhyuO1KmfqbzfBtn4wCzlGKPptk=;
        b=GCPw2M9q4OVOxq0PTsTZVj8XgfDwiQXmXm1uEpP6xUryEuOLq0xKqwVJo0TvTcyIGL
         CotG/6jnyv/I9eu9vnvjG5qEY3mbYfuKI6lgKs4unneL4zTrYVSqHR9iZCEmEdRinRMJ
         TjgdUqFQINqXfH16OtmOI5IUB85Ym/KmBoPhZIJhgqJur03tGytnOCkaDNUw7CRrNEMd
         lUSZJu9b2b5f4w8N7EGlm0NzNCB7z8gHr7+xb2uxgNxQuVqiq6A+4+ZNw23zKA2wQnod
         Q2071Ux8zDQUQzrLUY+y8B3e0Za2pBZtbCPnwbF1U1rmqP8iLqH2PxUxuCJ7GV9VV1LT
         yiiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721951835; x=1722556635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=euN6FREumlz1F7E3OhyuO1KmfqbzfBtn4wCzlGKPptk=;
        b=FRGnRXqLhWKsU3rTY3vJ/Ll7EmwaHqmmGk4swmpJZOGWM2FdP7IeOxuWR5poRo+EGP
         DO7xOKNKrY78WURdyRTdKcD8g7KPWUGcEUi0dGRSnCxNmX8Ph+LLTJ6mNFWuQn336sTA
         lawNFnO1U3JUAKQtIEgoMByN+h635pEyCybaet6S14V6doatHOK9fyc+o6+rC7ywPbIm
         To+rx0Q1NHniaIPvSzfe2SXTBbQ+9p4OqLgVq7YVHv6UkDjtO9zip3eT2DO+Ip5PWWOS
         Uz9/I2xHi32BZ/thTp4YKBiAFSkKz6tNFN/PtWsXyl2m4smsoxRaBr8aDGT5w2m7RSim
         thlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRhV+LHMmeg8PDFaMXw5sWYkz9WLPrb0D2BScRa9EItKBVOyrpENbqf3y+RUZszgIKwLjw97WPnszpJn36Q5Q0J4yV90kk3A==
X-Gm-Message-State: AOJu0YxfgpcmZU1MzfeDCTzwJwapnBys13gN8IaL7XJEmBwGmMrdwqzq
	W6ubqn+m6RD4G0FKbVSvqtYNc+ePBn8MTdmPCALDtfczRXjff+m+
X-Google-Smtp-Source: AGHT+IFz8JIAXzKvdPrNSxFqdtltIWQHF1wtUts3yBog1X5a5xJTDjpu4NnS62GnibMD6FTlREMMJA==
X-Received: by 2002:a05:600c:1c1f:b0:426:6153:5318 with SMTP id 5b1f17b1804b1-4280570fe50mr26307465e9.19.1721951834820;
        Thu, 25 Jul 2024 16:57:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:426:6c3e:18f9 with SMTP id
 5b1f17b1804b1-42803b7a708ls6780135e9.2.-pod-prod-01-eu; Thu, 25 Jul 2024
 16:57:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSXln97UMBvTVbthyMhxmMC+LkLEhTCE3SeKDhFF5WrNZth4Ks6iubAbyj5UP1SYxLezyWLqW4WTGmhZsheDkvl6wgXF0pa8PBZg==
X-Received: by 2002:a05:6000:10c2:b0:368:7a04:7f5b with SMTP id ffacd0b85a97d-36b31a41dd7mr2579423f8f.40.1721951833030;
        Thu, 25 Jul 2024 16:57:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721951833; cv=none;
        d=google.com; s=arc-20160816;
        b=ueMYE2DEWQnAIVlPPGALO6GBXG87IchgM7z49Yqo9cJGTwe4u7CAlKmGtqELsAqhsa
         xyp15fMJUHYbjZ2scQbFck62s8o62LwXySHcFgdm9RZxpsDo+NI5eUTgzPaF1effMybr
         ZMF8z7gVIFZOT/yDu7lepGRISNu31mHbxlGdg2aJTMPVsjUiIHpH8nyuk7j7bkvDZwKD
         P9QQV/OjebXFdeJVIPmQc+HguTvTjwlk/+C5yb2IGGxz9Eg17AQbwnbaG9JPJODuA1s8
         cv4q7vpGP9L1sj4t5yIfslPcTq6rN0boHlyBpv8mEQK/4OBPNmEw0jSKLV7RaHtvVdME
         Fgow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Qi/pzfQRC02iIIyUSX4FZkWNmHAKRwkz4IYJvMytXBE=;
        fh=of3h4SWUQUzIfOa5o0t/lPYorFrQI5i4Tah0WAfJQQc=;
        b=HgqbNS+Gq8Pd0iTepNoE4pzeI8YBk/Lbq9EBJu2a99uF11/uz19FzvFvlM+CaiiqJe
         DYUDrXOuXnp1Jmsi3Wl9Zfzg2XlflCdQdVasZAJwwJ4UouBoYZz7CuW5A7Q9CXJ27kYh
         oi/tL0Yo715uq+WK9OMyyyWFr3RoMmrqOMSAwXFouChFoDg0I2l6zPahuUtuYJHs77/0
         qlp6gcL7ComWhFZ1TQon2JZnd8Pe1n412IcAOtgBQkhG5ZaYROZ8Wnt1xYPtQR0Ic/CC
         iBh5jxzvJKfbsMtd60rh9U5IjV3M2nRcljH0OSz528DfA5dfEd4TMDon4kuhAH7WDsRM
         I4pQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ETF1+awv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b3685c516si58608f8f.8.2024.07.25.16.57.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 16:57:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-368f92df172so820102f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 16:57:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6hTqoW5eZCYtAJJtAQ1Qjn0hjaeq5s3cNd+JevGrKORknORSWyZhthMLzk5PVWtCerfTJuAQvY6imHt+/XTZJIXFrGCOLpnd/pA==
X-Received: by 2002:a5d:5043:0:b0:368:4e86:14cc with SMTP id
 ffacd0b85a97d-36b319da8e3mr3167018f8f.10.1721951832106; Thu, 25 Jul 2024
 16:57:12 -0700 (PDT)
MIME-Version: 1.0
References: <20240725232126.1996981-1-mmaurer@google.com> <20240725232126.1996981-3-mmaurer@google.com>
In-Reply-To: <20240725232126.1996981-3-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 26 Jul 2024 01:57:01 +0200
Message-ID: <CA+fCnZdwRcdOig0u-D0vnFz937hRufTQOpCqGiMeo5B+-1iRVA@mail.gmail.com>
Subject: Re: [PATCH 2/2] kbuild: rust: Enable KASAN support
To: Matthew Maurer <mmaurer@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Nathan Chancellor <nathan@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Alice Ryhl <aliceryhl@google.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ETF1+awv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jul 26, 2024 at 1:21=E2=80=AFAM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> Rust supports KASAN via LLVM, but prior to this patch, the flags aren't
> set properly.
>
> Suggested-by: Miguel Ojeda <ojeda@kernel.org>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>

Hi Matthew,

>  CFLAGS_KASAN_MINIMAL :=3D -fsanitize=3Dkernel-address
> +RUSTFLAGS_KASAN_MINIMAL :=3D -Zsanitizer=3Dkernel-address -Zsanitizer-re=
cover=3Dkernel-address

If I recall correctly, the reason we need CFLAGS_KASAN_MINIMAL is
because older compilers don't support some of the additional options.
With Rust, this shouldn't be needed, as it requires a modern compiler
that does support all needed options. E.g., for CONFIG_KASAN_SW_TAGS,
we also don't have the MINIMAL thing for the same reason. (Possibly,
we also already don't need this for GENERIC KASAN, as the GCC version
requirement was raised a few times since KASAN was introduced.)

>         # Now add all the compiler specific options that are valid standa=
lone
>         CFLAGS_KASAN :=3D $(CFLAGS_KASAN_SHADOW) \
>          $(call cc-param,asan-globals=3D1) \
>          $(call cc-param,asan-instrumentation-with-call-threshold=3D$(cal=
l_threshold)) \
>          $(call cc-param,asan-instrument-allocas=3D1)
> +       ifdef CONFIG_RUST
> +               RUSTFLAGS_KASAN :=3D $(RUSTFLAGS_KASAN_SHADOW) \
> +                $(call rustc-param,asan-globals=3D1) \
> +                $(call rustc-param,asan-instrumentation-with-call-thresh=
old=3D$(call_threshold)) \
> +                $(call rustc-param,asan-instrument-allocas=3D1)

I'm wondering if there's a way to avoid duplicating all options for
Rust. Perhaps, some kind of macro?

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdwRcdOig0u-D0vnFz937hRufTQOpCqGiMeo5B%2B-1iRVA%40mail.gm=
ail.com.
