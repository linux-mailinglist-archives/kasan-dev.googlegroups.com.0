Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2MZSD5AKGQE7MIRQVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F3C25250887
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 20:54:34 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id o18sf1519241ioa.21
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 11:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598295273; cv=pass;
        d=google.com; s=arc-20160816;
        b=GGbhtrdHoNTjtpmH+BDWjXXOPWPSGb4VDARh3e4gZqmg+kguabyrXI6HG3cjZodwBQ
         MbjS2pOm8sTUoTc/GcQSFdaNkkGa9s0p7MBSGxsQX1d33tzvZI+Vor9XW7B5OlyfmzA2
         SnJy/XY/HG3O3pQfTTN3/kFYm8dKJtu876UZnA5LGYo+weenQ3VCRm3l3n7bCkZM9uim
         fBgJTvtbR7mg3SCwpTjzXCFKNIOQ5KZIzPaNGVzPW0OGxRjJ0f7TZBuAGvkAZmk2iNfO
         IvQ7rg+94pY82TCCI9ZWxez0WzpvAkqwVyjNxYoUnxAmTGTJjzFB4p+QUkRyD7xn97C3
         S8aQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=BplbLKD0ub9IPaZNwwzNEfAyR0sk4lNYBMn3dBIDo1Q=;
        b=0wfjQd43gdkulyFq++LD0IDT/F7ZCwrORuOgnDxlhItDBhA7D0mF2tzSfPAnq/n61u
         d86U8Os6keyV0q6motEZe4uMUnX8weXvixbLgjx1N6v9nYoi1vyp4lEIg5rukti5/Jtc
         weKOCTVKaPPFAQC9PQn1UTIhVLIa5s691jk70S4RPbwx1lkiwA5xZyd3gruwcYvLGKLc
         hEuL7+naB0PkVcedub07VJqzChcXo0xftilI57ulb90T30+WGKw7qED1DP4GznLXE0df
         Leu1fyN7o7/YKL0dOR9jio1IL9CdgQlc5WS6BUYihH3LKmDhPOfadCSSjW7jqcyfG928
         sRnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tfU47MCx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BplbLKD0ub9IPaZNwwzNEfAyR0sk4lNYBMn3dBIDo1Q=;
        b=dYYQh7JZ5YJBTQ3uvcBW+3WCKmRbZBraysYeeSKHFTsvXUhJlKXeNIvrefbQRKURdP
         h3dA9rpEGge6a5+aEy/Alrznd9moea4SldLAu5wkO/aQXjLKyeATP+8tUgajytGS7deJ
         15VtVUo+hVpn8lOM0HZsK5MYgkAfYwFbl2+PVHW+rhrSVwgN3Mem2mEpVwZMxZvKiuVT
         MkMokTkBpJCtndx6DzzKyyfrIAkmXKuw8uIdzClcKTJGO303k0j9J+tt/wFGr4/thGwY
         hrbvCkZUss0Ff4yVsEL6qbQ8gGS2yYdlWVeOrjt/HTyAHlyxCDia44Lv27p/aip02+Vn
         9Z4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BplbLKD0ub9IPaZNwwzNEfAyR0sk4lNYBMn3dBIDo1Q=;
        b=VQHkWwi1upogEUX2XmDzrxzZTIQIXhMUvkm95i/XPK6KjHYmBrMYcbcjFgqgqfLnvp
         sOUgSRGigsprHxDdQOqMAgah1k8EoTzu856OkX00+GHIJH1chu2Gv3aAE4kvg0RtdvAC
         IB0IrEZbBh+9+FLPnS55YJE8sKYWZczMbxrUg2rQ2zhupHpTnecyVret2IntON6lLy+g
         Tdc5LgSRivvoLSSwYe8Z9xC47UkiPFHdsb0257YmRWzuS2XtmYu854264auIPYwErcIB
         YHp7vhPwh2fsyHQlPjBRgDfc9vKXWmPejrALf9XxaQZ090stb5xiXb39xeLkik6MfyhX
         3oDw==
X-Gm-Message-State: AOAM531rsah/NH9oUidta0Kk+AfDxavSjD+iA5SqgaFFZQV+wp1as36k
	59Vy2YSkwDGmmcM6e0jeDl4=
X-Google-Smtp-Source: ABdhPJwlMHWnd6/ezxcBdemtRYV1NgcDDEI5BTbMbnFySK8wU3RCnvYQqIVwVLpWIpXxAAnnQ9gKWg==
X-Received: by 2002:a92:499b:: with SMTP id k27mr5976544ilg.280.1598295273760;
        Mon, 24 Aug 2020 11:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2254:: with SMTP id o20ls743349ioo.6.gmail; Mon, 24
 Aug 2020 11:54:33 -0700 (PDT)
X-Received: by 2002:a6b:1601:: with SMTP id 1mr5964109iow.155.1598295273276;
        Mon, 24 Aug 2020 11:54:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598295273; cv=none;
        d=google.com; s=arc-20160816;
        b=vEXC/0a3yaXysM+JBweShmYuEAe48efn1Aa+ExEDJYmvdJWurEH61AZr9r7GzS+Q+2
         soTkvUdhlAD7sNeKf2UV/ev9ybt8mrkRZ+o2OZY+pBMDZJJTArLandV6Wjb3wZ60MgFc
         Vub5THfqlO7Cpp61/3hXain3OWAnCu+6hPCV1A47YTpYyBWjEEYixWXp6mSGitkdUPVk
         VofEtAqKUe+KyqeZuGye0FmwpfesxryYrXqVCEWegHz8Cj8c1+hYlOHT73K7AI+rcOSY
         K6FMUXopsaTnIbJmh8nzbeKeQqAiU051y+Z0Be9Infi4FhCZhMUB2SU5eXwSKN3yDKku
         mPWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=07wQipKjUjq60Q5QZCOLOt60dF5U3PsR3+q9GUuCFRk=;
        b=InAVEBvNz2OCX62desun2+SZ78AV8H1BwxA1IuBwAuldnWwS1t+b8GKMTEayHOgVTP
         zbSECjSf0XOz9HcGpMpPojfoBt+sYnpFlBAKR4RPKbE403ycKPhMrvH624G9R/iyIoaE
         6dZCyp1rS4Q3fQUzaw2/EItoYFY5XAhdV8IXPEXo3QUyR/i8xjLb8NTi0ngyIVvUcpJK
         5nryhROXwtuuR1TsuBKgJVX4CHg6BR+ePH6bAME4P4PNdH8l2UU16j7GK/xQLBhFqv2K
         wz79UDFGiPJaoFXC4BB7LE4j+ModhY3MACu5Xyoomc7DOffbWvsIe9XItJhEjJ1TzMw2
         qQfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tfU47MCx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id o74si577284ili.4.2020.08.24.11.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Aug 2020 11:54:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id z18so8218673otk.6
        for <kasan-dev@googlegroups.com>; Mon, 24 Aug 2020 11:54:33 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr4721835otc.233.1598295272680;
 Mon, 24 Aug 2020 11:54:32 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Aug 2020 20:54:20 +0200
Message-ID: <CANpmjNPFNhTaQ0=PmQ4GT+rf-q3ugQomHzAaiXtzAhoD=fdhiw@mail.gmail.com>
Subject: Question about KCSAN
To: Julia Lawall <Julia.Lawall@lip6.fr>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tfU47MCx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

Hi Julia,

Apologies, I completely missed your question, but maybe it's also
better answered in an Email:

 "The point is that you reduce the window of time in which a race is
considered to occur, which reduces false positives, but you don't
actually do anything to ensure that the races cause problems?"

If I interpreted correctly, you're asking if KCSAN does anything to
check if a race causes harm to the kernel.

The short answer to this is: no, it doesn't -- this seems impossible
without wiring up models of *all* compilers *and* architectures, as
well as wire up a model of what the behaviour of the kernel code is
supposed to do. It would also be incredibly slow, because at this
point we'd have a model checker. I can imagine that one day, we might
have some post-processing steps that could analyze data races and
perform additional static analysis, but I honestly don't know if this
is worthwhile. Simply for the reason that you need some understanding
of what compiler and architecture do, and given the sheer size of such
an undertaking (e.g. look at CompCert), it's not a quick fix. And by
the time we have something like that, 10 years have passed, and such
an approach is no longer necessary because everything we want to do
can be done in the scope of the memory model we evolved. :-)

This question also really goes back to the LKMM, and why we ought to
have a memory model. The answer to this is _abstraction_. If we stick
to the rules of the LKMM, we won't have to reason about all possible
compilers and architectures. And what KCSAN is, is a data race
detector that tells you about data races according to the LKMM (+ some
relaxations). Plus the addition of the ASSERT_EXCLUSIVE macros, which
can let you specify slightly more complex properties (likely, if one
of those fires, it's a serious problem).

I'd also highly recommend this section:
https://lwn.net/Articles/816850/#Why%20should%20we%20care%20about%20data%20races?

If you want to chat more, I'm happy to chat at the conference.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPFNhTaQ0%3DPmQ4GT%2Brf-q3ugQomHzAaiXtzAhoD%3Dfdhiw%40mail.gmail.com.
