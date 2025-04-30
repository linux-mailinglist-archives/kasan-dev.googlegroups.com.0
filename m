Return-Path: <kasan-dev+bncBDRZHGH43YJRBXUXZHAAMGQEYE54IMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B900AA513E
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:12:16 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2da802bd11esf48906fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746029534; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVc5Gi4qJq9AZrz8sQ7AR02BSvlsZcROiu0q8YB/CF9YzbDu3J+SSvODd5MofM9TqO
         qsxhDGNcOGr21Q4f5K9/ZV+7d0RFdU0/CMtPQ9X6xk91rXUKHeZMGajZfO1UH5ZUAp9t
         hOFGlcM4e++huZxHnJY13K8qPefB1FVuo7IAbEve9sHnqXCj1hzeYrXqxBwccBxpeW8S
         /F2qkTWejsL9HtcONkadWBYrtEwt+qwsaU3gdRG9dteT4M98yz/g2L9ufstvTIm16Jll
         e4ljGc6bhfmPYaNDdHrT5dcxvVnDGtNLDt0YwlrXsbeEzYT80Gp1TvVXtjMWgLz7+cOs
         ZWFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=b2Whl8R5iMEAjH5MAya/TCGboVGm+l+cSi2cP1XPJ4o=;
        fh=sWmZJ0f7auKwRhTR5OLSLclDJ0eCGjzo5du7h9/SoZ0=;
        b=h3iGR2933WDLZ9tMZcVEe4h4BQr5d6KZ67kt+chkBfOeT22xmdLT/W13dezg4c2wV6
         e9O3rRJMjzSqxNnPvmiO5BLu3bi63mQNvIDX42A7cXiagQaQylXI8kMVlE8zz1MCQpG9
         pSmPL6HbAb+/dTgleE4H/n6gjnqH7kpSS8w7mAC2D0emCP3QNgFHZNaU3E4Cj6fGXxe1
         ppuhGgoTKEkt+5kbQsrJHo0Na8fmVnROGYDEEadsYYwk8/vPPoNCFDbYmnKpcLa3IgFU
         pdnkdK8NnhoaM9EV4zVHP7sn5L5lBQh4g1p8m2uy2xlSsZSXyOUhryDADCWCs/MmlpRO
         J3AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZwYgNACm;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746029534; x=1746634334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b2Whl8R5iMEAjH5MAya/TCGboVGm+l+cSi2cP1XPJ4o=;
        b=UY8jEoF6ggoP9vnPcJy9xYyhk9LWVzFslmg2hFP/tipfMonGY/cUBXq3n5xWLeZQl8
         BsBuU3VyVFY5CYpxmxVZZVALckt+ZGWdPWSIBehbXaKuRStuX7Ioq3RL5NXerDJv9aXS
         EHQXdYs90C/k29N+ga7kssyeha8Jq2RfmjIEKML+nxFiS6GkeLDV21rasliZQ5zu7UcT
         7Qu5aHszqz2d5+qXUvf/dRJ6w36xxRpC1LuetG+G49FGBplV3EFzoCN9GC1I7Z/oVY1p
         0/iPKYFfGwcP7HsDpMNM4gB3phSaT1fYfmYv3Lm20txyEpmu38KOYoAXKS+v8R+i4sUK
         l/+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1746029534; x=1746634334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b2Whl8R5iMEAjH5MAya/TCGboVGm+l+cSi2cP1XPJ4o=;
        b=cH5TSD6qTK+qoMhEt76wZhyauX1EPsmq/xHVu8x52VScfxrwqINfnsNxSXBK7pvbSK
         mHDmuVOIYnFkmDexlV25gki1wU8U9LPnu3+ATRn79xXSPZgAENCcA/Fn5hEDoRHFvxOC
         TTBPQnbwGLiOCOQ4BnDPraBppFjTzfBlSet6Ae6Ac3D7a+bEg6wNpETQg8DdXOi5kGvD
         7Rxkvu5mYWP1YPgxRGvmRBmVIq51p+Kipc7xcVHlgiIVWv5hfJEL5Q8usHRQzoucIAR6
         HBMz1Pcpt7AY/dBerIduLty6diNC+bTTjKIX1W1O9K6il+9OFxs+1qNChGm2//UgFVSI
         y82g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746029534; x=1746634334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b2Whl8R5iMEAjH5MAya/TCGboVGm+l+cSi2cP1XPJ4o=;
        b=mBmVplgFcE98JidTb3dfGIG7DJYUpdQxsd6IVf55EYTz8sdaS4BykB56+wV8i/VU9I
         oYTlvEPkMF8XwJHe6tEpQon9SiSFk/nfQpIVY/wUZLnzWl6tT60ciQJpEcLB+yHcmn/V
         mZ/JkXk8NfZkLbEkvUokh84UYM6KjvXQMj2DZ6G/8DS8hYXnuZigS6HcRezTlmGagWUa
         /Lbr/4VQXIqgtfQE/NuXhlZKRFy2c9vm0ALL2sAipLu43QcqmKiI/QyOEIwxOZhqfxvm
         UoledXeYe7VlBMlWuXP036dB+0kPN0fcEpAYnPqJ5j4cD/rj9+piD125JRp2Q3TEdr/i
         7Cww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUO1XEUKmbj5NwEQr0cNXA5jtHRg/WCx6gnBsgF+3ixWhAQupCJrdvRVMjCNeKBaHf/UZZL9g==@lfdr.de
X-Gm-Message-State: AOJu0Yyiulo1WuFuhNaJfhOeEEn6woEYVcL47cL1rGNe3cYTn0argtRS
	k6pWncROZSLRn+dL0X1kvCWCOMRTODeiCb6CK8v+icUZxavIqQJD
X-Google-Smtp-Source: AGHT+IHfCP6L2KwX2ui5kz9R7SDJLGPGLdTxfFYPdjOT0gdHjzn8AEb7eefL3AepPzhKgGnJc6p6uw==
X-Received: by 2002:a05:6870:a7a7:b0:29e:67cd:1a8f with SMTP id 586e51a60fabf-2da6d24cf05mr1686348fac.37.1746029534374;
        Wed, 30 Apr 2025 09:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFsmyaU89aTBSbLQge4C6GmdEpNXys7fV8UMJLEDxFt2g==
Received: by 2002:a05:6870:ce92:b0:2d5:b2af:47ad with SMTP id
 586e51a60fabf-2da8a5202e5ls14130fac.1.-pod-prod-04-us; Wed, 30 Apr 2025
 09:12:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUw8u8Ba6rDIW6VKDkMH9NXWe7GzmnxU4JMaK/9/PoXEY8p718pwZJvTUBqe4T0fUOejKzmHPYbgco=@googlegroups.com
X-Received: by 2002:a05:6870:3052:b0:2c6:72d3:fc93 with SMTP id 586e51a60fabf-2da6cdc06b8mr1787204fac.12.1746029533563;
        Wed, 30 Apr 2025 09:12:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746029533; cv=none;
        d=google.com; s=arc-20240605;
        b=PaCLumge3ThW0bmwVFVpKF1DlgKeKC6YHIQkpkCHgIpXICJ05rcMwvV5zqs9qZ9rvL
         ktFTswWmW+H8WkDtbZ4SkBktKHg+wOxqstJ48R1d1pIngo5Wf9rYm57UU4crDOx4ih9S
         1bLSQ9NuqGZTq6FXeWaDe6SWg+2i75+McS05S9Ot0Mm6RjXy18oVlbo5nT9DcCCa/Ewx
         01qYLCObT0Sjp/fGiZ5eQjjq9reYwf3y0xSY3ARWcPQ1wdSCZ3sTCPxNbJ6wfKmeZhK8
         z7ViiAM+6g8tDWP0Ga8O27/5C9MtCF7eAoJiH6xDHAo0YZw2MM3woNBfW6QvvVfRuepa
         JUpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=d4mNU2googKmhmlSZf1BhrbHafu+MKvI216e5vmdtsU=;
        fh=L0ErKYeFHEWS+04calpjo+M7Q5WhhtIeQKaBaFgzfVU=;
        b=Phiif5+VVt6oU91nx6f0dBqLsHXYIyBayDMe6fHb/bbb1XSd7tWai2K7GXWbKq3DZA
         RJ0C1J8PhHAr+IAfU3UvjsUc49QJLFYQChRQHGgzr9YD7VVqeaN9wEuDIOUlQzghYPwz
         s5X4mnmy755PVtSMt+i8ENz8VsuXfBUJNa/o8r6+iyxcIhGUBEk7nMnFuULqzSLICDpL
         7v0GNSgRlOVofiEQYdHg8cAqGTeDBpTbPDfnccwOSOi4BYpCC7xu018jOILne4wEAwZh
         o8A2bgXSl1o0ASzPlXn9AX9NGy5FBZRv7ZzjBnYNNpvsS64n0Q+IiSDpkT8yeTLRHT0J
         t6vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZwYgNACm;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2da6e48e709si86349fac.4.2025.04.30.09.12.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:12:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-b16c64b8cbcso581974a12.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:12:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6OIaUBlRZHsyGo4d7qbf7xexXHgMyqz7SCvBWJ44Pmq8Sx+FXPwP2YlgsJgfq6V5i0jRiOn6N1Q0=@googlegroups.com
X-Gm-Gg: ASbGncu9gi5mKHcbU0tu1DKZUUWlIlGN6leiMDAHcTDo2TPfC8R+IZiodv8b+N3/sYI
	FuXPl7ot6EqOH/aebLra0KuxQ6M+fW22x8KHIRFisStf4EDnQw6kd5nj5jAZZ6wbw1O7rKR7hPK
	UB7WfduR3epYikJOK03a2Uog==
X-Received: by 2002:a17:90b:4d92:b0:2ff:7970:d2b6 with SMTP id
 98e67ed59e1d1-30a3bb7eb00mr654907a91.5.1746029532604; Wed, 30 Apr 2025
 09:12:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
 <CANp29Y4o8o6gz6GbM6NhP9sJUi94q29=aa+tLc1aCk0UVpgj0w@mail.gmail.com> <CAGSQo01gLXKWLWcrxSytmCB4YmRnGDX++ZizTws0bEjJ1amWtA@mail.gmail.com>
In-Reply-To: <CAGSQo01gLXKWLWcrxSytmCB4YmRnGDX++ZizTws0bEjJ1amWtA@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 30 Apr 2025 18:12:00 +0200
X-Gm-Features: ATxdqUFaNOBfPlrz_zIIOgpzIG1_Zn-Ke3TH9fa3F3oDE9TplG5KBv8TWq9-lvI
Message-ID: <CANiq72mazsVZxXaw6RD66CfFXRR-sHWf6eVr3jke1mWxBcrTBA@mail.gmail.com>
Subject: Re: [PATCH] kcov: rust: add flags for KCOV with Rust
To: Matthew Maurer <mmaurer@google.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, Alice Ryhl <aliceryhl@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZwYgNACm;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Apr 30, 2025 at 5:52=E2=80=AFPM Matthew Maurer <mmaurer@google.com>=
 wrote:
>
> `kernel.o` I think we should probably keep at least for now, because
> it's kernel-created source that we'd still like proved out. In a
> theoretical world where Rust has become more normalized in a decade,
> we could filter it out to refocus fuzzers on driver code rather than
> bindings, but right now the bindings themselves are worth fuzzing IMO.

Agreed, I think we should definitely keep `kernel` for a while.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72mazsVZxXaw6RD66CfFXRR-sHWf6eVr3jke1mWxBcrTBA%40mail.gmail.com.
