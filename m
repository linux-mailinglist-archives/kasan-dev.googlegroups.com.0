Return-Path: <kasan-dev+bncBDYJPJO25UGBBXMI632QKGQEYY45WFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 271961D38A2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 19:48:15 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id j84sf18752905oib.21
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 10:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589478494; cv=pass;
        d=google.com; s=arc-20160816;
        b=pxFVO0+mmHt24jhY5UlO1ggxNJPAx7eZLym1UgIPWP1j01vRNNvdvTYAot10gd4RK3
         V0hUQrTu6TsuZUb0/9v/+lrPEUteoqYTePQmB+NZ8QZark7x8ArN/OsrfWJsLI1q+jpV
         wpxMtTK42OWg+bCmIQxP/WQKSvlRxpV7lEoHSxDezDhrPPTaSsPsJZfGxyzvImT5e2A5
         ii+qS8tu/1jP3ExixrzNG1EMzpL3xfK/LzLyTwhGiTr025SAlZce+sGGvYI9GiYFIrxX
         o+SalX9VOuTWmXMt7cKx0fe5figjF3bUsbb6g7kb35AkNvnxYEaCVH3GDUpDpFcYdSsM
         euQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ydGq0URguzpNjvm3Jvu6ryqPIOgRGT2jx7AkGv8TWdE=;
        b=YKdRfPGY1RwzDQ2AwfX+WGeiREyTUUia8/H+sOVkbDnxvCi72WgPl1w8U2Kafc7AgV
         uZg98t89tWI5ORv88jE04EI7AEAnyLRrro+6ZlhOqcff7WDoRNrrrTH6QLr5SInCBIEh
         hMcXzbs/FCPPi29yUZ5sKLksXVkbb7pXdWXaBkPPbBG6HufZoWL3KorjcH+VdjT10N5c
         fLbjD2TiJM5vldB/L08Vc1YuqoJln/zUNVNkAsDI6LI3Z0KSL8YxtJiaSfT5ktXFR7+n
         ACUT4DM6kuFN6BwQhCN8azd+cpftGkIBnwFnL++i/Wnba3ybRzoOtUdbVBXOut/i0Al4
         TXdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cYbSCl8e;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydGq0URguzpNjvm3Jvu6ryqPIOgRGT2jx7AkGv8TWdE=;
        b=SojpFS6Es1jaEI73hoLXF7y3e1p3u1oUfuzrFVcJGd7AsP0OlZDeZ1rW45FdJA9ugR
         cSmALtOuwCJ86vdqoUhDfDrk80i384McKbkAaEmNw9vzBlbTTfneoJqppMahn1FHJL7c
         aahQwg3+Qh8kaeYIaVaUHVkZ0QjTyZuiXMtPU5GT7EQh5Sb1Rszn4cSRAcLlcrOGiGtL
         v21QDj/M5sY15g7yJhhFfVpZwm6jd4dEK2rJVS6ytHXwyI+KIH9Tf0mzF9BauefpuaxP
         jkOuM1gJbggyUT3nO91YcSKaHGdRflejmQT6apz2Aelqck8QpH65uF1C2JqydtE6jt9t
         i58g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ydGq0URguzpNjvm3Jvu6ryqPIOgRGT2jx7AkGv8TWdE=;
        b=N8cpKq6x+vNs8NKQvbz3F9BoOUd3WbelrOtD9mVrqSNXHtNMFUxniMMTQ/JVT4Vqb0
         RWMqP4ESpUMVUaj9ODN0zOY8lywuSY1QTNHCu0PxmOkuwKxFg6dIhXZhdOhRXP+/Tf1o
         ZZCYre5IJsl5Bv0VqZK0d4KDvJG3F/5ZezIlfC0rBzo56swfavn5HN9csIVvL1fwhVQG
         IYQQq6jy0zIzbvs4meTLWyjKUBH2xGzvuuW3v++gA0mLXmL7IA2D1HJlM7B8y3eWz+qK
         TbtxNRSy41YZFEvFiQ0GWmizuLqmFX60ihAJrS7cy1iFNak6jsVqfbQTU8DjBYSsvFUz
         SCdw==
X-Gm-Message-State: AOAM530UDJaQQPT12e8bh6RqtjjXG5X4W+lwBkyrde0NWomt3VnhYTpK
	rg3ZwM0+Jiq7705RzqnFzjM=
X-Google-Smtp-Source: ABdhPJx4Ip4+iCQ4rK7OLemX6hG44awa2abiPiZgETiQViu0/e2AnU7lsFupUykYm1Kt4icecXISMg==
X-Received: by 2002:a9d:12e3:: with SMTP id g90mr4252252otg.247.1589478494090;
        Thu, 14 May 2020 10:48:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c38e:: with SMTP id t136ls1203981oif.9.gmail; Thu, 14
 May 2020 10:48:13 -0700 (PDT)
X-Received: by 2002:aca:4541:: with SMTP id s62mr32446225oia.100.1589478493768;
        Thu, 14 May 2020 10:48:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589478493; cv=none;
        d=google.com; s=arc-20160816;
        b=0Y/TBQWCzpbcHynIv399xIEVnu1YPp15dpgNlwKqiRI6X3SYjdE9Pcrj/wApGfhPuh
         8sea0HCRpqvwfAhidFxv4dyAf6F7bI9kQ/b8VsuU8XUueZauYQogZhNY+URPnpJ8qc46
         RwXVQNEhKxHO/p3Q4dwUYJcfGIGQ8OS8anj7z7jA7frWlxKBkIV+fQxqi5nJzsTGFySS
         lM7TuvcJ2lA1UapL0g9GHe6PW9UUFQxKyRARpg4YjrL82+W4+U15q2CMcL0fNFiXdGhJ
         /v9n+eUxUsqISNJjIkq3aUzM4/4KPbB0qKVjDyFA0eGVVv9UkvMJE9yRPJ0vOXhV3PoH
         eIjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a0d1fR05uC5N0bTQGOD8OPAM3HHdnc9gOnIFkNAWXyA=;
        b=aCwv8308axcoQE33ehr7eWjIYUgtIwE8BTxBlzM0xBX2PI50Sn1Hyrkhx6RJ7X2Bki
         dqkNjKgK4RlhOBOdTSYD1eTrvHud9RQGgw5SbSoU4FU/uo/cmJjLu/g69mYWpuJWSHO0
         nGPp9IX+UjuoPUfL8zx9GWZex1bHerOwqbkfl0UAGUhz0m0dh+dHpVYmZJptktunEHrz
         0skGBCtQKb60fU5WiLmeWGyeQvrD/MivUGUxzorDoWKUkXYWHocA0yoyIVbzMlTUDVoS
         VNkBq0xLyCQwMTpB6DQbhP+JG8Qxl+10c+XWvJ3xhaDAzn4WfCUTC+KMcMZFVONl3Svs
         kTNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cYbSCl8e;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id x23si165058otq.4.2020.05.14.10.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 10:48:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r22so1528193pga.12
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 10:48:13 -0700 (PDT)
X-Received: by 2002:a63:6546:: with SMTP id z67mr4893469pgb.10.1589478492739;
 Thu, 14 May 2020 10:48:12 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
In-Reply-To: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 10:48:02 -0700
Message-ID: <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
Subject: Re: ORC unwinder with Clang
To: Marco Elver <elver@google.com>
Cc: clang-built-linux <clang-built-linux@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cYbSCl8e;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

+ Josh, Peter

On Thu, May 14, 2020 at 10:41 AM Marco Elver <elver@google.com> wrote:
>
> Hi,
>
> Is CONFIG_UNWINDER_ORC=y fully supported with Clang?

We're down to 4 objtool warnings in an allyesconfig build.  3 I
understand pretty well, and patches exist for them, but I haven't
looked into the 4th yet.  Otherwise it works (to the best of anyone's
knowledge).  Though kbuild test robot has dug up 4 new reports from
randconfigs that I need to look into.

Here's our list of open issues with the objtool label:
https://github.com/ClangBuiltLinux/linux/issues?q=is%3Aopen+is%3Aissue+label%3A%22%5BTOOL%5D+objtool%22

I remember Josh mentioning
https://github.com/ClangBuiltLinux/linux/issues/612 which I haven't
had time to look into.

>
> I'm seeing frames dropped in stack-traces with
> stack_trace_{dump,print}. Before I dig further, the way I noticed this
> is when running the KCSAN test (in linux-next):
>
> CONFIG_KCSAN=y
> CONFIG_KCSAN_TEST=y
>
> The test-cases "test_assert_exclusive_access_writer" for example fail
> because the frame of the function that did the actual access is not in
> the stack-trace.
>
> When I use __attribute__((disable_tail_calls)) on the functions that
> do not show up in the stack traces, the problem goes away. Obviously
> we don't want to generally disable tail-calls, but it highlights an
> issue with the ORC unwinder and Clang.
>
> Is this a known issue? Any way to fix this?

First I've heard of it.  Which functions, and what's the minimal set
of configs to enable on top of defconfig to reproduce?
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdnQaeQ2bLqyXs-H3MZTPBd%2ByteVG4NiY0Wd05WceAad9g%40mail.gmail.com.
