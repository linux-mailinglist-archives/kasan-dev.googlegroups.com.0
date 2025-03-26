Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB2WOSG7QMGQEG5YHLRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C861FA72019
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 21:45:32 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43941ad86d4sf1291045e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 13:45:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743021932; cv=pass;
        d=google.com; s=arc-20240605;
        b=gxpkGX2mDPVvnS/1KZv6mntH7I4A1+zUzq0oJI6KHKZKZZ5du0Ax//RNnLroYUorip
         /32PKvVatPPyoaUo0ZNoKdnbpe2dUXNuBRAjrq4oj+WAGL008i6Sg4EE1HwmAgGqSZIo
         g8H3HPtiIrlAxhVtpEVBGGm1IQc9xfgFhOBQi0LHWl7YG/Nhis5GZ3oN3J/N+VqLsUfC
         gIDWJWrRnA23CYnAc1gk8jP369ytpDfNoTycpLzcxQ48MXN8zRfeCPIi/yE/LNKYsQZt
         une+PNazv/bPAsw0PVH9saOelXnra6sJqTakIgC7UL3r8NKxf9zoFhm4dHNHQWEemzMD
         O9Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KobPLxbSijSCIhcX6nZEZ5xor+Z3NsDFp7DEboFgbNE=;
        fh=D+Ap2eNWk4O58qwEpAdOSh8Ky1kZkfoln1qE6e1jV/c=;
        b=HlnUJm0ao054+jp5z6HkZi+D2Xy6w4SXKXHKnc3mnm3Z6KMgKVMBGEZsH8cM6x9hy2
         72i2IuMdS2dREbt85Ec1Je+WBb4piYou9pDybwvsaS0nFXRRrzZaN5fFrceFA0W6++4K
         zMhwC54obMieieokaUmFkCLyO81SgfLHC6dSphGTCP54cR59GGNiRi+4icAaXueN/FAC
         8V+ghBG6DrftlisKLsxVh2EHdnjlsRoA5UQu/H9LZv6FXkEkOhiw62wKsyVQxV9/9BkS
         FD7Ws+7iSPicL+aAjAKBLMMSFXG2YM6yfayqrzH9BJ2MR9oVM6j657turUccazsxN4Cg
         rb1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1qkIEf1H;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743021932; x=1743626732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KobPLxbSijSCIhcX6nZEZ5xor+Z3NsDFp7DEboFgbNE=;
        b=K6nih3GQG6aGPbRBdq4kNmgcWPimKSwQAqcOaAgFBrAKsAjemAFtyPMKkA4MhZa4VG
         YAmEZsKq9Pie25SBtq6bXDatWZ/s5yLakfNYReMqKnu6XELAC3sBv03HubOb/6ggY+Az
         N5qXfDSXfEnvKrYvHMbRyQEcmJr38U3vPMjMTbl3ahHGLfHUxzBw8KIk9FchFaSwzpA5
         tt4ro9/iwZPW4f0jSR53AcIZnp6M0EH0mPBU7/MSSEn+hU20EdbNV3iTk5VRJDxZurH0
         5R5ReB8ULCaT4QqCffH+874J4eNTnC/quntLsNfWpVnLP1PkkpuDS+Ob90NFlrmqgthv
         2upQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743021932; x=1743626732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KobPLxbSijSCIhcX6nZEZ5xor+Z3NsDFp7DEboFgbNE=;
        b=jjncdK71ZJ5VC8hySfes1ja7PmkRVs4YV/V4gd6CMswHx159xXCeGBvl3+xqRtJGs+
         SOkbTxqnh/QB8kgMIbyBEV/iPXdpOvhXeq6pZibMXLo5NajXNk1EfnRAEUERGclTKRfH
         AB/KsrE3ivLDRBAVH1vyHX7gd0RxkluAhAbR8OZlQyuesybYoNym29JXNrozWP388TjT
         d3L+Hp862rC3O3y41QY3UpaJjsUTLjmGx8EHO0riZTd5M/tjLJkAdAw2A4h995TYvj2Y
         BmHJxPMpqb0xTVBbiqIAJ2aE7zXYnX+Q2rhdhgUlWhn58NbET9CpB3Pw5pcI10KdFk9f
         ayfw==
X-Forwarded-Encrypted: i=2; AJvYcCU7jlH5EYtrGqHfQAUQNTi5hUmEgKBuNmmZtzyPJxN+MCTBoAJZDwY3n96A2iHdKTMS3ZyWqA==@lfdr.de
X-Gm-Message-State: AOJu0YzdY8qs5djP9OZu+366QuLkIDVp60GxoN6kHSf99j8p0GnS6Nt5
	m64eDdn9c501dZHtP3fFqGJEwyl7MyVtrmzafjM1jphqmk3YDd7A
X-Google-Smtp-Source: AGHT+IEfOO5xSX6fCy7CVtlfPPObJRXGfyQ/oQF88mwWemFLyrpIGvFmQ2AzLKSEn5dp5QfIk4QtRA==
X-Received: by 2002:a05:600c:45d3:b0:43c:ea40:ae4a with SMTP id 5b1f17b1804b1-43d850bebbbmr8510015e9.31.1743021931410;
        Wed, 26 Mar 2025 13:45:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJsUBj3C6ll/ss0K4XuljVqkbCEsnKpxx3/5aWiXky1rA==
Received: by 2002:a05:600c:1383:b0:43c:f7b4:5d58 with SMTP id
 5b1f17b1804b1-43d84ed93ecls870585e9.1.-pod-prod-03-eu; Wed, 26 Mar 2025
 13:45:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSbEXVwUxpltpFlThd6ZKSWdYyzzegkxJGY4Jdon9Dg5EmRcLOqkSjMeLxBbsY8QxQQce6NvLXEKI=@googlegroups.com
X-Received: by 2002:a05:600c:1ca9:b0:43d:172:50b1 with SMTP id 5b1f17b1804b1-43d85096428mr9224125e9.29.1743021928460;
        Wed, 26 Mar 2025 13:45:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743021928; cv=none;
        d=google.com; s=arc-20240605;
        b=b+caIkcyTLfBXLgarxJIgx0FhdWqfCF3L2nzHXY1TRlIfP0G21iyg7TzcedZct/8ch
         Bn/EA7Ch5hrsf+sBBzz/anyWgfHq32uvyPy9HBaBlXTxbcvQ4GY+zDZLjT40DE4YKVeH
         OOn7N6Dn4lgo31k8RAjG/VZtvDEHf7sBvpl0dJWjrxwcExuAxhODUNLIQnwPb165bD9g
         kAfPQBDGtVqCxqb4JcxebRlPWFs1Slp9sy85hBWqPoqiqbyV2bJFTP18eBHHDYR9He7Y
         NWRlpjB1ytw+9C1ZhtJhMFxE7a1hjcl8oHJGtJRvB9gLn7UlSw8AaxiXjQOryE6w5+Xz
         Gb7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z7ktHXesu2kfcG5Dhn1yOjglQsPkU7kg2rXgHib344o=;
        fh=VYJL4l1RTFDeqRbf5uD8yrLEsecP97D73bZwfKejgzE=;
        b=EItXQm4yVAKjK2QP/SzOLyyKj9AcYigl0Ygkv/WCFT6Vw3nTIBGNwm+b7gF7QfIddB
         urHFeqFYsW+LWf+LP49jvkXxv7sFxiEAoJAAUGG0NYm5oCqfAKUv8NMFH27qUdFPRkYp
         IM42OXjQmjD33KuA5o2lcv/IKTKCsvXN+84j5kY8yW1dErmEQ/aP7cvZAZzQQ2KWUcS2
         Vh0myvngXUkpgaLznytMqtOori9LF1YboS5P/LheEyH9tEzpKm/DO7V3oBftl07HNDHx
         6j7faeC3G51L/Q5NfzpRcUmOAOoHIsP2nGbxqfzImUfmWnvZ4k/LfQsjk9Z1F1AthG52
         TIVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1qkIEf1H;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d7ae66b92si499895e9.0.2025.03.26.13.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Mar 2025 13:45:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5dbfc122b82so3177a12.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Mar 2025 13:45:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNCsV4fAdwJsPZF1JEToWbEspD5qF7sBsmyOripbWt8ITZjY5rNrSJRwgt2q60+nx2WQUMHzxHt8o=@googlegroups.com
X-Gm-Gg: ASbGncu3R67dbnTAmnbwUvxai+yLL3c7JcMxTOgZ/q3DgHRRpfnV5dkJeGZEJz0S44r
	1MfArhU5dThST6akERso8ua+bq1RgTI3Bgv83ZSHzkF33IUAR0HO/u1vT2byXTSdxFNHcULEbO/
	labUuMemK6I8GLxrk0NrjSVywNTcqLx6zJiJMHVxkNxSzZo7CPrcfO+sY=
X-Received: by 2002:aa7:db89:0:b0:5e5:606e:d5a8 with SMTP id
 4fb4d7f45d1cf-5edaad0f6d7mr5611a12.4.1743021927533; Wed, 26 Mar 2025 13:45:27
 -0700 (PDT)
MIME-Version: 1.0
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com> <20250326203926.GA10484@ax162>
In-Reply-To: <20250326203926.GA10484@ax162>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Mar 2025 21:44:50 +0100
X-Gm-Features: AQ5f1JrP1Q2mctLjPTyd7EAIrLTDiLFwqKWpzfLsUtx5LAsqHO0kWByN0mYn4cM
Message-ID: <CAG48ez05PsJ3-JUBUMrM=zd5aMJ_ZQT4mhavgnCbXTYvxFPOhQ@mail.gmail.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
To: Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1qkIEf1H;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as
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

On Wed, Mar 26, 2025 at 9:39=E2=80=AFPM Nathan Chancellor <nathan@kernel.or=
g> wrote:
> On Tue, Mar 25, 2025 at 05:01:34PM +0100, Jann Horn wrote:
> > Also, since this read can be racy by design, we should technically do
> > READ_ONCE(), so add that.
> >
> > Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrastru=
cture")
> > Signed-off-by: Jann Horn <jannh@google.com>
> ...
> > diff --git a/include/asm-generic/rwonce.h b/include/asm-generic/rwonce.=
h
> > index 8d0a6280e982..e9f2b84d2338 100644
> > --- a/include/asm-generic/rwonce.h
> > +++ b/include/asm-generic/rwonce.h
> > @@ -79,11 +79,14 @@ unsigned long __read_once_word_nocheck(const void *=
addr)
> >       (typeof(x))__read_once_word_nocheck(&(x));                      \
> >  })
> >
> > -static __no_kasan_or_inline
> > +static __no_sanitize_or_inline
> >  unsigned long read_word_at_a_time(const void *addr)
> >  {
> > +     /* open-coded instrument_read(addr, 1) */
> >       kasan_check_read(addr, 1);
> > -     return *(unsigned long *)addr;
> > +     kcsan_check_read(addr, 1);
> > +
> > +     return READ_ONCE(*(unsigned long *)addr);
>
> I bisected a boot hang that I see on arm64 with LTO enabled to this
> change as commit ece69af2ede1 ("rwonce: handle KCSAN like KASAN in
> read_word_at_a_time()") in -next. With LTO, READ_ONCE() gets upgraded to
> ldar / ldapr, which requires an aligned address to access, but
> read_word_at_a_time() can be called with an unaligned address. I
> confirmed this should be the root cause by removing the READ_ONCE()
> added above or removing the selects of DCACHE_WORD_ACCESS and
> HAVE_EFFICIENT_UNALIGNED_ACCESS in arch/arm64/Kconfig, which avoids
> the crash.

Oh, bleeeh. Thanks for figuring that out. I guess that means we should
remove that READ_ONCE() again to un-break the build. I'll send a patch
in a bit...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez05PsJ3-JUBUMrM%3Dzd5aMJ_ZQT4mhavgnCbXTYvxFPOhQ%40mail.gmail.com.
