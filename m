Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFI4OIAMGQELJXPQYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2B9F4C454B
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 14:06:21 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id h17-20020ab03351000000b00341f4df8bbbsf2621471uap.18
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 05:06:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645794380; cv=pass;
        d=google.com; s=arc-20160816;
        b=lMkxG8+14Q9V77MLVwQLMEPqqriY0vBvwusGPn3wFS3CEYfOq0M6V0l+Cxr5786gps
         dwg/V4AFIhtwhAlwxGP1DzFGYufJ6SK/5/OjpvgVtEfUQuVj2sEhXnSUQiDZkptBYocb
         ibNhn3xuNt6FX0QqXFIuOJxSZKmyaI9I4cyAXuaOGQuNFWVOnp+BGnkBVbwvrEnxGd/R
         iW0gyM3ExVUl7ChoXrdOmwJJPaupiJ6X8/A2Rdrw3lCT9L4j1CGtalvZNSIfjjTO+EFI
         UdKPNpoMEZaCLIUF/7ubbVgMh7psAEaCYFbvuSoj9mYRWlGxuhUO33/WClHkgkuSr90e
         hv6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nNC0TpLQhXtGbWplfMYWCeD/VOdiHvfOm2/PDjJBkbI=;
        b=dw38X1Tqvn1kC5NvqjrK5ng9ZzTC4nHNwWX9wTgBtW2ZuCRiBlGzWnvkQqMCvxrZYD
         cEnK1uDbnDs53Yc0bGFbokWIEE6KzGs9LR3Aei1MxnGV0HFm7nHCcUdUNQMZwCunIHMJ
         z1VccQ3UPZGVYNj0bQso5zM+KTXsM6R5C126+GX9qPOAv/Slq6D5+ibHjinAZuKK6ICY
         Q3g/QxNuLsIBPWdjYvAxjHWT1UTI9MXl3KF654L8JxHg7H+xmiAxqDSZ4vQ4losajEUg
         a2aQ+OSM0NnLA7o0mnAmyOGINmqUMEdHvWbRFtDgYwlNc/NonB9HVBuZbsJQAM3i/guO
         ajcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E+tFHAQ5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nNC0TpLQhXtGbWplfMYWCeD/VOdiHvfOm2/PDjJBkbI=;
        b=JTlV6Qi5zKWZV1ojBTrTKfFWxka4VfKvgfO17MLSlbTSFwprVdxeN4xiI16SxYrTTT
         b2Myc7tfdsS3gSGnFEdpiMLhqO5fC9glWx+Cc1xEJ4Id3M4ZaP01Lzezw0/VCxcHkJ/o
         1t8L3kUFluaqzYdfli/+vBuQZ8WwEY+6iYKv74BnVDKUM5+I5/67l0Sl3YaevPxun/i8
         AdLpgIiembBgYDL+6J/V6d6584tHFCmN18chXsXAZY9JnU/8q6QZzy8fIV7+NlVrJ2FZ
         opDwyOXSYnGBaC+V/J+p2u/TggBQjtNOsaB2e1nvwyYzmndH0Gy8mhhfJD+Ajl1O39By
         J8/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nNC0TpLQhXtGbWplfMYWCeD/VOdiHvfOm2/PDjJBkbI=;
        b=HWQf1Kxsc+5vmiZlwYpRBxC5KHjhtcF1RMz7Pfl+AWyKnbFrzXG9btcZ6NeuIWLy+t
         7QNK/U+jxcyPoOHlvwW0S0AoL4+eWtI8YWaF64php2PIoDkjbtoqbgwQSpoJbqwYHSnr
         2SFGgBA6yaOOJSXduLPFtqMLu5kv//SlpDJwAMHQUJhslNCPdvS3jPlfo7w0RYGD23ki
         YIq5xcJg9TOYsPN39Ff8brzViFUM02GIQabr0RkpZBkcJSGjr30NDEYbix97TuJWxhQ2
         ppKDrxJqz2vgUa75SxQN1KU7qPFcvX1Ce0CuMO9naL/DoTfzQIbakdkBmjXMbVmnxB7q
         mFHw==
X-Gm-Message-State: AOAM531BUqEReSL41P9/rHPwnZljdViLijjQAzaUuejomfDFV+6PQg8d
	yUa3KqRlt+9bYzTFlbePYE8=
X-Google-Smtp-Source: ABdhPJzhBTYIushtBaGY1cYqz1ffVxHfWNQXfRE9lIQY7fR5ZgK3+mINT2G8AlyX5HqxB0oGSx7j1A==
X-Received: by 2002:a67:d31c:0:b0:31b:725:1fcf with SMTP id a28-20020a67d31c000000b0031b07251fcfmr3520298vsj.64.1645794380734;
        Fri, 25 Feb 2022 05:06:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2e97:0:b0:31b:6bb:cd0d with SMTP id u145-20020a672e97000000b0031b06bbcd0dls1157534vsu.8.gmail;
 Fri, 25 Feb 2022 05:06:20 -0800 (PST)
X-Received: by 2002:a67:ca8f:0:b0:31b:bb24:5b55 with SMTP id a15-20020a67ca8f000000b0031bbb245b55mr3121365vsl.63.1645794380149;
        Fri, 25 Feb 2022 05:06:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645794380; cv=none;
        d=google.com; s=arc-20160816;
        b=k0lKGhpIcQtOmwiVPGaQGaCpdTk64MjkbD/P5hF7+MJvwbHYIfsEYf3cvo3I5j8+kY
         NuVvwx4MsrBFtepfAKxouQCgC5MZu3pPcDw59KjhbjN04X6w0GZDQQkLQsyNcSylS5w+
         cRHhJgryL3mA1a7s44KySqmnAeG3d5Pcr6tHLsG0fNByP0lYomXND8M5JOAvZHHfgJa2
         tvamX3gYKDOkBEeccNNHIiAzVN3wTgJP1lVo7kVOhnP3447Oyh2F94uQtHdLX1Wf4T1Q
         D/8HGuY2a9t5DcBUz1XZioXBwLbs0rqJFvZlK8dl6q7w0JP2NFwx931DL+f01/l9jH9V
         Rx0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=91lfqerMyrhcvkt/Xxml96fIqw1rCGTngu2Yekjv2ZI=;
        b=TE8s1ERUlE3aPPwyx06dlW+asfLzkOlm7FMe5kWLNWAUVNgACulJEojbzDOgsjecnm
         cv2LXfYK7729nPYKRYdwZvtO93H9FpOFsSmu1zrvp3M33HqQHNNdOmBDWAV29Z7vzYcQ
         XJ/VVMkHEXFmbOqVCY2zO/DA/YyXkKMrC3jpPpGZEgyuMmYW4xlqVrIpi54ord/o1rrz
         chfW2c/ouo0F8H+XwARgV1XrQesERUJDWijfJax8TQ7chvA2kJ+MKtGH+D29xOJedcxv
         ra8yuAQGUuW2Df+ztlUo3krk7RzAvRihvbvemZ4M44MlF4C33lBb2wHX4UF147b7sW8V
         WpeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E+tFHAQ5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id b194-20020a1f1bcb000000b0032db64783e0si135602vkb.5.2022.02.25.05.06.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Feb 2022 05:06:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id u3so5746241ybh.5
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 05:06:20 -0800 (PST)
X-Received: by 2002:a05:6902:2:b0:624:4cb5:fd3b with SMTP id
 l2-20020a056902000200b006244cb5fd3bmr7286257ybh.1.1645794379723; Fri, 25 Feb
 2022 05:06:19 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Feb 2022 14:05:42 +0100
Message-ID: <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E+tFHAQ5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
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

On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> As reported by Aleksandr, syzbot riscv is broken since commit
> 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit actually
> breaks KASAN_INLINE which is not fixed in this series, that will come later
> when found.
>
> Nevertheless, this series fixes small things that made the syzbot
> configuration + KASAN_OUTLINE fail to boot.
>
> Note that even though the config at [1] boots fine with this series, I
> was not able to boot the small config at [2] which fails because
> kasan_poison receives a really weird address 0x4075706301000000 (maybe a
> kasan person could provide some hint about what happens below in
> do_ctors -> __asan_register_globals):

asan_register_globals is responsible for poisoning redzones around
globals. As hinted by 'do_ctors', it calls constructors, and in this
case a compiler-generated constructor that calls
__asan_register_globals with metadata generated by the compiler. That
metadata contains information about global variables. Note, these
constructors are called on initial boot, but also every time a kernel
module (that has globals) is loaded.

It may also be a toolchain issue, but it's hard to say. If you're
using GCC to test, try Clang (11 or later), and vice-versa.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ%40mail.gmail.com.
