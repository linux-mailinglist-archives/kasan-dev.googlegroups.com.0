Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR7OUL7AKGQEZMVLZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A7E4D2CD313
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 11:00:40 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id z83sf1978708ybz.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 02:00:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606989639; cv=pass;
        d=google.com; s=arc-20160816;
        b=l3AyHrvvhqOr7+JHdsqTfPqKIt76LxBIDWKUNFnLOz46M5mUi+1k0RhX4qTOSzd7mb
         nSXY8HeKyXkSqxHrkw5NliLW71BnXfeGB8AtxfJ+nt72U8/YZBCER+eX8Cn16vGSq3jj
         MVkpPKi4gg/QNV/vpirLEiIQ0mrW3NMUQbvjxD7LCapEA9CuZhACBdBN4PlLDmID6mzN
         tIoXY9L1+LFgTbu8xpjXgygqS9KhuwZHSVLC5HVcgR+mEY9bPcqKUyVXIbgTYEo0UzYT
         CPJ0fNfKmsxIGMxColUQVR0Q9Z1U8PTCPfgJboiEMnMpYkRwWvTl4GO7e+GYO+p0dAzz
         lj0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=ZaffuKJ8Wohl/FfcNyrzEcdaGR51h/2ilbihe3kNPTA=;
        b=Yp/NTnLgn55DKbFe9zfgcGqsKEItz2p7ZDI59brNm1n/xvj1nbKEWRpXNgvtqmXA1a
         Hajx0xDhc8N1LSvH+OAPZYqBy6oW1SOPAYJPCd24A+RQ6/ZKiRAC3WpdsbDJpmwupYD8
         gL1DZGj1QliKn3qoOp+R+A3xRy5+w05/y+hblKy3+8+WHJL/x6WiB92Z9HK4JFBwC2a1
         J2K9wiEi/AWqPQ64Cl8QvP3NZeoTByH8GkLOm2BgUqeYEyvUk3YxC0wL8s8+ucT+1Crp
         Mn5DHOIznB3oAvPD4fjnq5OIw2meXWVe8+g6UCCxDwnYndSIGuCk2y5V5Ya24f017jyD
         Bu/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UdvdHOlc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZaffuKJ8Wohl/FfcNyrzEcdaGR51h/2ilbihe3kNPTA=;
        b=i/JH/diAQAHd6AvoepOtgbkoXzSoNjgYBF4WAmL9RoAKFeKciC8Ete66DD0My+bBuH
         HEH5kTz2EYcAWIHLoErr1qHKlpQ5hrimsG3lHd1ewcradDcyKLbbOpHOQYlaXkeuY+2b
         wcokoQZpdQ8hdEdXsUvSU5WpKzrXGETpBi064I8ebfVc2zTXR/Um7vPFWKwwUUV+noWi
         1Bi42d5n3zw1fk/lWhj+oAGhLNEzFbksGoGo2l5432E8y7OvJpdSYSkYtc1o86AgDorz
         x419IFJyDqnB47xo53ew1dXUqerFmomWeUhSJL+asljm6FR2SdalaTDJriRR5R9eOdiJ
         Ugow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZaffuKJ8Wohl/FfcNyrzEcdaGR51h/2ilbihe3kNPTA=;
        b=DbyLooipktni0rXdrjIZvIqfYBMFAbJaCQJrmukHSG68TOTjCYDWKYP81bu85DZM29
         nQj1P2Ut+ql0hAa5ztbE91oL0A7AhVf+VbpqcR1JWJGhDIj5c/jI7SWC+mwSSnQ5A4zk
         OmKvsSix7+eFSyW6LoFapF7M/dCf4H8GGjpBj+yINXVMw7JlI1koKNu9suK5y/wkHRof
         +dJ+gGCjTjKTvZQv6dWnE9Zvm76FV5UH9NUbXhlpPPHh65cAkCb/jGBuMAQ+RC6XExgZ
         bP+i8Z4s2UeYtaImYmgR38zoc/GP8y6Xp7Iv5fC6nNIMl1tiidLFao3JQSpMyulUIW4l
         nhgg==
X-Gm-Message-State: AOAM533PgT+mmE0PJO9J6koQS2F0PI9w2EeqzvG/zEAYQscs4QPhtsxn
	sG2r5Evr+lgQktu+e18E2pY=
X-Google-Smtp-Source: ABdhPJwsbBldzIclHUt91roX9/yPHzQ67jR00qfp2TyGXe6rlik4jUOIbTcF4Jbt8vKVaM/41c9Tgw==
X-Received: by 2002:a25:b281:: with SMTP id k1mr3367029ybj.303.1606989639750;
        Thu, 03 Dec 2020 02:00:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:344b:: with SMTP id b72ls2473829yba.1.gmail; Thu, 03 Dec
 2020 02:00:39 -0800 (PST)
X-Received: by 2002:a25:6951:: with SMTP id e78mr3615526ybc.42.1606989639270;
        Thu, 03 Dec 2020 02:00:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606989639; cv=none;
        d=google.com; s=arc-20160816;
        b=Rruoru7zON9Hjl5dvGrESlgWboD7VILX8PgmwlJsH6BL3kf+QW2XGjC/+e0Fru/RGV
         j7bl38qEdOU6K689twSlWTL+ANJX8GRWHX3E9xn6AX5NFIdPzlYccCJ3Ha0A6bAHvIX8
         KUjhbpTs5K/IQkZtIuvucoLBF5eQYVzgV025zIFBQWIgnBlWOwBoGfr02Tq8y9mi+2na
         DEhxvZ1lXDpNYtrHOZQK07j3XZ3MpUKO3IQm/hmouu22f7KMcxxKPCzT8qbqBDEDRr89
         cEt5ldUpnLbOaUqJ68SXg7sFkZc5h+w1ln1TuGx39ZO1ApzHWZj+RKbrCacwvbEM0rQt
         Z0ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UqF6jZGLUWuIUckbUkk1aPFfKz7MT94ASBM3bHp887E=;
        b=0SAHbtSRW6kL7sw7PBd2kjYMz+ZypU8Vjz2NRu9wxzwH0qwdB7TTgikQL4cE6MtMpF
         f8vSTGdCn5jttzutqhsaHnM8K2oraLxotrtDM3R0cRlzD5+tZwzPm8LlH3O0PrDEtsj+
         Z/Ahb0LY4Evs9lNXwfSikJ+JPNFJFaQe8ibstR8Lyu3EncRymOfLfHHYTuRuD4My1zDk
         mXAcwTydFZFYoPHQv+VaMXxXpjgc4i8f3pcsEacbbz3GVgRDmSTGMwhZjfRd/fu7SV6e
         RpyX0V3FbRAowib1tZjPg+g+MUQfXVFAl7NA7vs2JRSH37lY64FLZNFGm68oxITCRBSL
         To3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UdvdHOlc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id y4si44190ybr.2.2020.12.03.02.00.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Dec 2020 02:00:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id z24so1203106oto.6
        for <kasan-dev@googlegroups.com>; Thu, 03 Dec 2020 02:00:39 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr1502355otn.233.1606989638710;
 Thu, 03 Dec 2020 02:00:38 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
 <20201202124600.GA4037382@elver.google.com> <CAD-N9QXrnO66jZS_B3YKQF8dt6BvsSiOu-cmhEAxS5sZ=ztLhw@mail.gmail.com>
In-Reply-To: <CAD-N9QXrnO66jZS_B3YKQF8dt6BvsSiOu-cmhEAxS5sZ=ztLhw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Dec 2020 11:00:27 +0100
Message-ID: <CANpmjNNdn=E9OyUtkoLA-56nAOWUFLijDA5BzDBwrUL+Lw__pA@mail.gmail.com>
Subject: Re: Any cases to prove KCSAN can catch underlying data races that
 lead to kernel crashes?
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UdvdHOlc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, 2 Dec 2020 at 15:15, =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangabcd@g=
mail.com> wrote:
[...]
>> > I am writing to kindly ask if you know of any cases or kernel bugs tha=
t
>> > prove KCSAN is able to catch underlying data races that lead to kernel
>> > crashes.
>>
>> Have a look at the last slide in:
>>
>>         https://github.com/google/ktsan/raw/kcsan/LPC2020-KCSAN.pdf
>>
>
> I tried some cases in this slide by disabling KCSAN and enabling KASAN. B=
ut unfortunately, I did not find an observable crash.

I want to ensure there is no misunderstanding: a race-condition bug
does *not* imply a memory safety bug. It might, but race conditions
can cause all kinds unsafe behaviour. K_A_SAN detects a specific set
of unsafe behaviour which are known to be very harmful (memory safety
bugs).

A race detector on the other hand detects, as the name says, races --
they are not magic, as it can't read the programmer's mind to know
what unsafe behaviour is. Not all races are bad: we have to specify
what an unsafe race condition is.

The race detectors we build are actually "data race" detectors (TSAN,
KCSAN)! "Data races" have been defined (at the language level) to be
unsafe behaviour (e.g. C11, C++11 say they are undefined behaviour),
primarily due to unsafe compiler optimizations (the type (A) bugs).
But, a data-race-free program also allows us to infer stronger
guarantees, specifically that all plain accesses have been properly
synchronized and there are no race-condition bugs due to them (no more
bugs of type (B)). We can still have harmful race conditions that are
not detectable as data races, the type (C) bugs, so we need some way
to specify that -- see my other email on the 3 types of concurrency
bugs to be aware of.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNdn%3DE9OyUtkoLA-56nAOWUFLijDA5BzDBwrUL%2BLw__pA%40mail.gm=
ail.com.
