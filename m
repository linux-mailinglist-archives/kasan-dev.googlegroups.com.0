Return-Path: <kasan-dev+bncBC7OBJGL2MHBB36XYL7AKGQE5F7BV4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C422D404A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 11:50:24 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id a5sf559141oob.4
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 02:50:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607511023; cv=pass;
        d=google.com; s=arc-20160816;
        b=yOQ1vMzJG5mR1ebJCe8f4ywQW++34AJho5oVRMvPClwbe8NkdblzSe6ka6a6ekAvbM
         FdUjgxYxDgxztq3C4zRKSrdfmMc1AmCqLJqnoh1v97CSukOYF06vNrCXgTzdJ08G0kC7
         s/ypDX2x6jEiztVIKtnZlDK7d+x5Fq3S52j4idVXLRpAwClRGpUz6gBzvbo0xU9LC7Za
         hpBpZohGzlVxKblRmCmrJ/SN2SVKlrZFwTZiBYs3GhfeKAbJ8LPpBfpqYFUvbCForzTg
         Vh2Zxw7Hh6tKaWW55/rJzo/Lr7REj6sH5owAeHiDBtBa1RIEflWTnR37HCJ0JIWxdVOq
         fYbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JyukQ5LTKNMGxn6fj29tww5MYR9GrgQ2slSK07BClkI=;
        b=B/bz6ypijkhgjqGgGT0cddsQ1LtwOYKZlsFchCG5Fb0cNan5/0Ky8iWY94dXKs5PJ2
         yFcGmS+yF/ZBAsnTQI85QaFzRShD9KAUiZZzAN/IKUy8ESLyPvnSi/tvxVMcgez8Qte6
         ZwG5TpIyBkF4ibrL29ml6vkWen4RpwvBjRQb7ObZADcwEIWikKMFqJas+03bD48UT7I2
         LlXGfXUJU510YAkoEDwsdooNp8vw/bnJYg7UXJLcCHk8QVLiGzNJ8sUz0KrFyMQPMFHr
         9CpmDCjUI4VEbGE+DgexOcVvTIS6QqQ4aMLyitquTUpryHHcu04WuiJzg7Mspkizv1yC
         So8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7Tqu+yg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyukQ5LTKNMGxn6fj29tww5MYR9GrgQ2slSK07BClkI=;
        b=LNTOWbxEId65l34G6AFNUGY7+cw33+clMNgS2+A0ESyMGKm4Rl+RJ3QaXXzxNggjch
         9PmrljjYQXVNj/2ycjqnmq4GZsOhHIRNI/KXhk7TTTNvcjDAWPCmet8qCSSRSELuaW6/
         H4Nr1u0kFwj172/ekxGgXyEk3uqtq1KF6OJk1h5sqZJ/7QTVh/oxXVD3ZQs5/Jvl26of
         5CFTQiwv4WbIAIfeVkGoOo2H69BeOn+QyCfmxERZvOmeBcN+RbyHw4ViiFPKMZWT2Zm/
         mKnP8UvHDHvghBwA4EGLs8K3E9OocIwgVVsUFeEl4dU5e8kI7/7N6Oz4V0kumLOJBKVs
         jzog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JyukQ5LTKNMGxn6fj29tww5MYR9GrgQ2slSK07BClkI=;
        b=DygfBTsaOAugEZynqjb3Zk9k+qrX75m0NeRfaaFpC4kXQR2bkO1TNrvx1fK+AkpbTX
         uTR/o6vVJbh+S7PUmu5WrtVkF9LJA1Qw8mEYitdcqjmik0bgc4hnmdY1TiUu9LHviHwK
         4WF75fSVdRmD6if3RJf201slzICOa7awZLTY9Xug3Cd9L0v9kaJDRWCBPFYgu6iAYxNG
         MgyUy9OdOquDnVHcrwnFfsAx8BfDxnPWhZnqjSEh6n74XuGXANQMJjxcjx9Ydy+OT2xn
         kj6xufz9VVMYVB1smbTGq0XTXkJbV++iv90T/5Emd9XEGUUCZXgVJRhaAZSAiKKnslhE
         EeQg==
X-Gm-Message-State: AOAM5321pqKqaipSh+6tc9c9vYjgiDldVkf54tvfqVMmrRVK0/0DdXuc
	TuI4lotNKr7RYBHMtwvDO/4=
X-Google-Smtp-Source: ABdhPJwaSGN3BHoaoj1jli+fEqxRrH3j9xLrY5gvDPj6GdrIVJV8Yx5varemOhXhOrYMnR2KeTT9Qw==
X-Received: by 2002:a9d:6c44:: with SMTP id g4mr1164638otq.246.1607511023425;
        Wed, 09 Dec 2020 02:50:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:8cb:: with SMTP id 194ls281451oii.3.gmail; Wed, 09 Dec
 2020 02:50:23 -0800 (PST)
X-Received: by 2002:aca:ef44:: with SMTP id n65mr1343466oih.90.1607511023083;
        Wed, 09 Dec 2020 02:50:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607511023; cv=none;
        d=google.com; s=arc-20160816;
        b=HmdynEXpuykTrIzWGYpOuMRBLkQ6bfy/y226xdvp7lmzIB103spxgQvlYUzIB6hLHi
         Dv2I7tQwZ+cIrK6wcIw2X3YSGI6bRyERWYmR08zsXHZj6gxL8GBSiu4pyKM6Zq5FzdC4
         +yiLbgPuINEHib+4OKG4EsmymOf2lDDjaxe1Ij5shub/z00vAkjqJ1EwRaLg1n4Omjdl
         a+ZrE72pNDd080sXYkqCqv2cMARrtFXlbxisnI2NWrHPWS3ymlkHNpObtZ6agOYUHpmb
         wMP3n5PeOlmqcEYXKBT9Z5pPpBsBEQF/i+wwu7IDS5Y0PQUqHPQtDo6ahl5WTNI4UlxP
         O4lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MX94nPIGSLB0DB1OT3/FAuNxRnHj49zF47rxa5iMU8o=;
        b=OJmkBzdoCImdYkznk6eWJ+nFSHlQIY0PW2fc/L+3P7HWsWpltkmW+Aw4w/Sb+isHjW
         QS8cEq+1Vau9jQ2AmBdWvuejlhLp1111aSlkL2EoZWLaISC3XPyFTQwddZEC6QQT+af6
         +PumT81ClbkIB6Nrcq9P6e6Jk7gAyHs/Hw94U1NGwJr1xZBHi9xMwi3Npx5mEl/evb9i
         RmQ+kfHqKTd3zjuMfEYuvBrrP4/CFvl91sd6lAXlEQBtLc825ZThM4hTRRyh+xe5hAPD
         DIpHY4Xjtg7zfeMKy373urUvDiGNSaBZGSW5+tzJnlp6y2++biCM09sFkFHG9jfcMfN2
         Nifw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W7Tqu+yg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id w68si97740oia.4.2020.12.09.02.50.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 02:50:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id q25so878153otn.10
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 02:50:23 -0800 (PST)
X-Received: by 2002:a9d:7cc8:: with SMTP id r8mr1180342otn.233.1607511022660;
 Wed, 09 Dec 2020 02:50:22 -0800 (PST)
MIME-Version: 1.0
References: <20201209100152.2492072-1-dvyukov@google.com>
In-Reply-To: <20201209100152.2492072-1-dvyukov@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 11:50:11 +0100
Message-ID: <CANpmjNNpZWAKeeWSwkNX6=Ngr9W0bk3oEdpHN2i41BHzc7LkpQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't instrument with UBSAN
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W7Tqu+yg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 9 Dec 2020 at 11:01, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> Both KCOV and UBSAN use compiler instrumentation. If UBSAN detects a bug
> in KCOV, it may cause infinite recursion via printk and other common
> functions. We already don't instrument KCOV with KASAN/KCSAN for this
> reason, don't instrument it with UBSAN as well.
>
> As a side effect this also resolves the following gcc warning:
>
> conflicting types for built-in function '__sanitizer_cov_trace_switch';
> expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
>
> It's only reported when kcov.c is compiled with any of the sanitizers
> enabled. Size of the arguments is correct, it's just that gcc uses 'long'
> on 64-bit arches and 'long long' on 32-bit arches, while kernel type is
> always 'long long'.
>
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Marco Elver <elver@google.com>


> ---
>  kernel/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index aac15aeb9d69..efa42857532b 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -34,8 +34,11 @@ KCOV_INSTRUMENT_extable.o := n
>  KCOV_INSTRUMENT_stacktrace.o := n
>  # Don't self-instrument.
>  KCOV_INSTRUMENT_kcov.o := n
> +# If sanitizers detect any issues in kcov, it may lead to recursion
> +# via printk, etc.
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
> +UBSAN_SANITIZE_kcov.o := n
>  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
>
>  obj-y += sched/
> --
> 2.29.2.576.ga3fc446d84-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNpZWAKeeWSwkNX6%3DNgr9W0bk3oEdpHN2i41BHzc7LkpQ%40mail.gmail.com.
