Return-Path: <kasan-dev+bncBCMIZB7QWENRBYUQYHWQKGQEHBORTGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 52EC6E1A54
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 14:32:36 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id q1sf15017476pgj.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 05:32:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571833955; cv=pass;
        d=google.com; s=arc-20160816;
        b=XyJyHunYeLVesAH2eyZKzCkl4kufYS7rH1xKJv380e995wR49uXGgBNWJ5XEQmwKw7
         PDPSn5q/P/Kz4jTfwGKDtuyN5KIKym8RYxaDxqAGgSIraswpI34A9ArJIJxfvoAk/1SK
         fOmvWUtHmjBs/Jps0BH/QvViHrFwFpHH5oBjXfs8vsR3gg9ul/IAlpFYMfQpupftKMyC
         yy/ie6nbUKtHInPhGi1vaRaYDOrm2HQk23CZe9cYj64YcW8CjjMm676zdMGepJfgMjcd
         BWXPgdbx5a9Z7VFlydHokGbUofvdCU2nrgSIBL+inMQdt5e4jSxZcygzrMUz87VtjpAL
         Dd0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/cFMjw/cUSQKQli74eOrJh6r6v9kZL0hnXPvv4p3yNA=;
        b=l+XBW4eBxCkf85bRiQPeRosN0gr/BlroSvxDAqJTrj9sFnJBijcOYhI2Zptl0pkOhf
         5o6og44bR7FzNKx+VsMGseEfKnyAz3jVBAZiN75L9ungPuYaS+8Hryi9wpIoI6C5Bydy
         bto1mt9c1F8XsUPOa0Cns8a7lmiPJKGt5ljTZv5PdtVeWyXduhyJQ1hUERJ/77duiNQF
         B8AMHEOnysDZUpU6r16IM7zrjAaXs+PDdSZ5CtGKjMJ5YMD84yHWBPUeerpmzrSrGJZa
         NZ2Z4RboGeTSq7tlwPISl+G3mmYfxncfuvjnAUmg4kPEaGixe6aZYWtvLUIrWlUK5km/
         Sp0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C5bfrMkM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cFMjw/cUSQKQli74eOrJh6r6v9kZL0hnXPvv4p3yNA=;
        b=tAAkLshK0gyMn853KAwjNDAt3Zfxxod2yRDIs9ACeYlktJvGG9ORARrs1fonQ7Xr0r
         F/pmFG7AzyflqX9iG9HTVKa1rnM3Tr5Vis64U9ca2h5TeGKEknF2u1BoQAB51bP5wb3Z
         jWErjKPvk5j8HDWTZc/1q3Q29Uf/FiImSwjiTam/EIjqYWm4mB+BHvxQDNniLNVZpEqE
         4OyiUZ+3oVU8dRlMb55FA5x5GzhFQnMqsvFFj+m9Fq7tKvVlvCZUTvXAYd5T8Yfwf/EU
         m76OlI4G8/gH5X6ADQRaFHWi3AgInzacu5umKlmb12ByPmTZzkeFxOWME2vQcziOlHWE
         d1Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cFMjw/cUSQKQli74eOrJh6r6v9kZL0hnXPvv4p3yNA=;
        b=iJok8/lnMP5FLwSxag4Hb/TAAqLqNmGFR302+i1hj/dYhRv/G1Qk4zF0Pz986+IwUu
         gb65ppRGXs/UfbivVM9V/UrvClzZ5VpgI+BYITOXKkmeQvkxBMmnhhG/In0pBlzBhyEB
         9KeUs3Vi7gacnE6o63C9XdNO0+Eskqh8jR0PEHxzcCyGoKrbIKr7beHcsmrSS1x5+jtP
         PAUouEpFmRrHMJ/M1ykgKDdYrjMi2HEXwh2T93Mv3rRm8rgXfaI0HDxnLELgRQT5mfcT
         U9Hk3cOI5SgON/ua+1JagFgz62gyPkeRgm9Z7rywjiAQmFAAJ++OPDU7uiW1y1YxDjNU
         D1Nw==
X-Gm-Message-State: APjAAAWrAZgIP7mkXlLISZf085LCHqLuWD6/IiwlYc3k01Kq9/xHtoBh
	8B6ph3bb/6ZY7aTUTQuKlGM=
X-Google-Smtp-Source: APXvYqzdHvC0zDMqlWv0iKvwzBFQ/ob2ltaYzc3mVBbRafO9nNxuDQ8J5utO/XfrVwesM0cYvuNycA==
X-Received: by 2002:a63:f844:: with SMTP id v4mr9922077pgj.248.1571833954836;
        Wed, 23 Oct 2019 05:32:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2527:: with SMTP id j36ls760043pje.1.canary-gmail;
 Wed, 23 Oct 2019 05:32:34 -0700 (PDT)
X-Received: by 2002:a17:902:968d:: with SMTP id n13mr9647773plp.261.1571833954293;
        Wed, 23 Oct 2019 05:32:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571833954; cv=none;
        d=google.com; s=arc-20160816;
        b=QgUQlTb/XxSL4Mglv+5ypRHV/dZkfUo6W/WMXUtWTa/AygKX17FSKV5yZvO3LYHGAa
         R9ZptIop6nApAsWVnzIR2rxfPBPBToUJaAJn5j7bnJNYHkgf5c/bhoNPZQLPapEGIyUs
         7/bLjgFM18/NVj9Q0inHkV5zOHtTfqIBY2WuQA0dUp9iSTG/4MDWRY2dh/ctM+JVLY8w
         C3vMVdw5gbrK392SEsWICGebYzHlWjxIG1q6eX7QkbhTGwwG+JK03avgARfJo4dKJpot
         iFt3yhfjG4OSbCOcKH45wB0zjmT1KmMtwRqGmcx85fY28gWVzurNO8vTZElTZ9PPlmwj
         o/Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B49NIMe9Qp45m4n7j4yBsM/w0U/Y5dSRw5y61/jmg/U=;
        b=RoY2qVd4M0T7YzBFPCgyL3xtRtuJh4IlVLW2ixtjmPv6O646nrcWi+sFXQoTm2qqhQ
         HOAjY4CcHYVwgFtAs4VPrZ1PhIsgrX3Mh75wBNA6/HWHLMcUpvUMj/bhH24iOFujyCBE
         2x9Ouq9pFOv+U8EYMfuO5Vp1Fi48+tVaylX3Q0rGLY/4amq9u7YOwRvM4HzdiacshrEk
         2xTv2k+85/v1j/6Kzky0F71F4GghJWyVePRHoVPZyid5Ma+ed8BdSb4WBolyPSYbT0bO
         TLJ8ve5JvBSkDo+XBaC40dRV5dacdNG1xWom/z81lvNZ5rdV10M7878JfB87z5299I7/
         SRWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C5bfrMkM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id 91si850932plf.0.2019.10.23.05.32.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2019 05:32:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id q70so11995635qke.12
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2019 05:32:34 -0700 (PDT)
X-Received: by 2002:a37:4a87:: with SMTP id x129mr7970246qka.43.1571833952687;
 Wed, 23 Oct 2019 05:32:32 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
In-Reply-To: <20191017141305.146193-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Oct 2019 14:32:20 +0200
Message-ID: <CACT4Y+bfVpu4017p64rc-BBAevs2Ok2otxUYpbwJGYkCbUNYVA@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C5bfrMkM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 17, 2019 at 4:13 PM Marco Elver <elver@google.com> wrote:
>
> Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> See the included Documentation/dev-tools/kcsan.rst for more details.

I think there is some significant potential for improving performance.
Currently we have __tsan_read8 do 2 function calls, push/pop, the
second call is on unpredicted slow path.
Then __kcsan_check_watchpoint and __kcsan_setup_watchpoint do full
load of spills and lots of loads and checks that are not strictly
necessary or can be avoided. Additionally __kcsan_setup_watchpoint
calls non-inlined kcsan_is_atomic.
I think we need to try to structure it around the fast path as follows:
__tsan_read8 does no function calls and no spills on fast path for
both checking existing watchpoints and checking if a new watchpoint
need to be setup. If it discovers a race with existing watchpoint or
needs to setup a new one, that should be non-inlined tail calls to the
corresponding slow paths.
In particular, global enable/disable can be replaced with
occupying/freeing all watchpoints.
Per cpu disabled check should be removed from fast path somehow, it's
only used around debugging checks or during reporting. There should be
a way to check it on a slower path.
user_access_save should be removed from fast path, we needed it only
if we setup a watchpoint. But I am not sure why we need it at all, we
should not be reading any user addresses.
should_watch should be restructured to decrement kcsan_skip first, if
it hits zero (with unlikely hint), we go to slow path. The slow path
resets kcsan_skip to something random. The comment mentions
prandom_u32 is too expensive, do I understand it correctly that you
tried to call it on the fast path? I would expect it is fine for slow
path and will give us better randomness.
At this point we should return from __tsan_read8.

To measure performance we could either do some synthetic in-kernel
benchmarks (e.g. writing something to the debugfs file, which will do
a number of memory accesses in a loop). Or you may try these
user-space benchmarks:
https://github.com/google/sanitizers/blob/master/address-sanitizer/kernel_buildbot/slave/bench_readv.c
https://github.com/google/sanitizers/blob/master/address-sanitizer/kernel_buildbot/slave/bench_pipes.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbfVpu4017p64rc-BBAevs2Ok2otxUYpbwJGYkCbUNYVA%40mail.gmail.com.
