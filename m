Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6XTPWQKGQEIMJYNVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02219D8D48
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 12:07:05 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id m21sf5189209uao.20
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 03:07:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571220424; cv=pass;
        d=google.com; s=arc-20160816;
        b=alNJkSEdiWqor1hqGRlR50nDPw7p4wgW8vTmOP65PnA1QG2cszkSkTDf2OPQ4M05vH
         3ACM/fPY8TSO7jDqQk6hYlQ+iV6OZPVPVh5WTFfhOub5cxI+UKNOQSLeWYyV829Dnn8n
         7fZuFeDPGAphe30Q05AKlKwTiweL+t22/egG5O/DYtiee+0dbCqomWEx+6/zw/V7bryr
         XW6BmpQgoXKx5v00OgD31AKEzQpcuO3kojrG4jVO8E1Zkd2oz2lZAdUHPeI0M9jCYd5R
         0bjM5gsVHa5TqbufJ2tu2IkN/mw0Pm7S7Yy2A2mNZ1UTYYDAjxNsw3heb4gbXnPfOlMF
         V94w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dsuddd43cNKc/6U9RovfGOZS52ukAgjWL8QGo4IknoA=;
        b=bM7IEqljdFoWh/FZRXb45URNdJ8gZLs24dM/ikRTEYtRpe/9l7MoO20ZdEfb3Rqm6/
         Fm6VH+0inlSWOZ98oAsPzVXUBLyvcMUod8ZpD+35ieSw2EWhvybsSWkVWTRJvvxGQEFm
         kH9zAdTbQMPd//OQe1nCDfdroY7JnDxI+49aqrXW128llkZyQKARzZOQNQU6OINihHIR
         95Gcz9f6TbcFMu/a4RCWJKJ0esVGMlDqN9I4mdjK8PerpC0O/SSXuGBrAx1ZQbBdUaVf
         eyntMxlQktOdFfh6hvzUD3t7cblLQ53+zytBohwcj9kp7zc4r8wezidN6oDDIghRJ3Qq
         kNWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IzhRqtVY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsuddd43cNKc/6U9RovfGOZS52ukAgjWL8QGo4IknoA=;
        b=ZwJj9OHCYdrnWzpvU7sBkt9llCaob6l/ZXyHGVL4YTaH8EPE253l+3uz8Zkk5KJ75/
         5Io2dz0Unc5gm/t3abPkzfkiXzorP1tbzBskQhAaJt/7goVw/6CmAYQC2uQ8UDqcraF8
         GxU0zm64Tru29YdgSZpAS78yw7TTMIPn3XqHdemr8UpaSCTkTZnAO8JVxwjhW0VSUrgu
         0jBpOTkq6zxaNBY88e8DSllWLNWnWzVpbGel2/3mMUAlNTMXkgbhlDmU7hAYvPaJwDtR
         nyo6Zwjow619/GXvvawuMj3F0ySeZxxUB5r/W0PXvA0FqeaCtQKTPfYFLyIaA2aFAaUN
         ZdPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsuddd43cNKc/6U9RovfGOZS52ukAgjWL8QGo4IknoA=;
        b=AP+SDfF87dBEY0d+L7cLyaWx0+z3MesATLI76w+T/BdfsXLVk5OFiCzu+aJ3Ifwe33
         ukk1QmWhZiUOXhYbN9UtLxDHmXYf0EcnEh0We9B4+usx2+aCDdXMh9dVC0uOqFyJZK3R
         bw0SFw5ca14rn1L7bL/b7luDmCxZeT2Ijxk4O1OBHTZ6aQRNqT3eVCzFouDTERGllav5
         hQgXMAu5j5DRYlmsl9S9pw723QTEFphPUq5nNacwzNFgzDV+7FurBJaQRVns5AmZ4bnf
         7qYLgY36gaK6DpcMGG6GDVQ+IySR6iUwwhOPv19UmUwqHnf3514ieVkkJOD/ydzvgjN5
         DS/A==
X-Gm-Message-State: APjAAAW+k7MdfYQ1J1Irys6TNJuZo7S14bw90YqpTGfQqXZpzble9tbD
	I7EhCPPBvs0Vitod+wM7G0o=
X-Google-Smtp-Source: APXvYqwYUvhF5AnXtLkzUDFzgmYUQ0dADzN5hXhppkdpe7AxPfFFyRfrfvhxmsiBxO2IVPIzM64HDg==
X-Received: by 2002:a67:e446:: with SMTP id n6mr2336907vsm.56.1571220423979;
        Wed, 16 Oct 2019 03:07:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c28e:: with SMTP id k14ls2082248vsj.3.gmail; Wed, 16 Oct
 2019 03:07:03 -0700 (PDT)
X-Received: by 2002:a67:d095:: with SMTP id s21mr22003033vsi.183.1571220423549;
        Wed, 16 Oct 2019 03:07:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571220423; cv=none;
        d=google.com; s=arc-20160816;
        b=xvvVO1iSwoxVBY4LYLYDm9CT76FWFGNLfdiMvKQ0K291zNHIdSeQ+vAgCYSQXjaCSZ
         SK8X52TOtDwzIe9NAPCUCvhInVQbo9lPYthS95K9SkI1rV5BuSLZ25UNszmmBH/wU2lI
         BDxgg2ZD7FHfwqJazodlgbh1e3wA8FVJ+HR1VqoCQHeWuIn/PjHqU/H5FlCQlKgBufd5
         NURuBnl3q+2qfbmtnNhWZYJOc6MKlvH5nptcxDo2RHDQBmRvHZ4KBGb2DsPy0tQgyF4s
         wc0JRyp2/srq5s66XM7Hqj4pX66QQjlpvEtWdMDOQndn/UnH6AKs9hXQmItEKMxPm199
         0wmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qMLDRlP6KAQbJ6EBR+tTwOR/BZha8QBB781yjh9f+vI=;
        b=atm24I8mnORZeEYW9yHyCOtYImVg/da/lYkN0R7YiorP382rWOvybweIuptXp+wdwL
         MMnUOsyCDOM+A/0zNVVyN8alPf55nUNrTjyQZYHMDshq5Rej4AWMEJm5BL0yvQPbw14X
         j1rVOIJLBNuqU+rCPUHtDZ/SG1TFkuvK8l6C1pN3EsRQmSYxTxMN4UXFRjnLq2PgoSS/
         GQ/qucs1SP8LKdRE2B5fTUal04sCEmzc630n+LvWAI7Lts16c5SZf91j6IWOk49CsKBH
         dB9L2j81qWR6OZAELKC9VLDFlOepXll9Hk+1FxR/4Gw5UU256KrlmcRqzQt9DrGXALNh
         HrzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IzhRqtVY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id r72si2248904vke.5.2019.10.16.03.07.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 03:07:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id g81so1340636oib.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 03:07:03 -0700 (PDT)
X-Received: by 2002:aca:f492:: with SMTP id s140mr2789533oih.83.1571220422532;
 Wed, 16 Oct 2019 03:07:02 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-2-elver@google.com>
 <20191016094234.GB2701514@tardis>
In-Reply-To: <20191016094234.GB2701514@tardis>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 12:06:51 +0200
Message-ID: <CANpmjNOxmQDKin=9Cyi+ERVQ-ehH79AaPjRvJNfFfmgOjJAogA@mail.gmail.com>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Boqun Feng <boqun.feng@gmail.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, ard.biesheuvel@linaro.org, 
	Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, dhowells@redhat.com, 
	Dmitry Vyukov <dvyukov@google.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IzhRqtVY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Wed, 16 Oct 2019 at 11:42, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> Hi Marco,
>
> On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
> [...]
> > --- /dev/null
> > +++ b/kernel/kcsan/kcsan.c
> > @@ -0,0 +1,81 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +
> > +/*
> > + * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
> > + * see Documentation/dev-tools/kcsan.rst.
> > + */
> > +
> > +#include <linux/export.h>
> > +
> > +#include "kcsan.h"
> > +
> > +/*
> > + * Concurrency Sanitizer uses the same instrumentation as Thread Sanitizer.
>
> Is there any documentation on the instrumentation? Like a complete list
> for all instrumentation functions plus a description of where the
> compiler will use those functions. Yes, the names of the below functions
> are straightforward, but an accurate doc on the instrumentation will
> cerntainly help people review KCSAN.

As far as I'm aware neither GCC nor Clang have documentation on the
emitted instrumentation that we could reference (other than look into
the compiler passes).

However it is as straightforward as it seems: the compiler emits
instrumentation calls for all loads and stores that the compiler
generates; inline asm is not instrumented. I will add a comment to
that effect for v2.

Thanks,
-- Marco

> Regards,
> Boqun
>
> > + */
> > +
> > +#define DEFINE_TSAN_READ_WRITE(size)                                           \
> > +     void __tsan_read##size(void *ptr)                                      \
> > +     {                                                                      \
> > +             __kcsan_check_access(ptr, size, false);                        \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_read##size);                                      \
> > +     void __tsan_write##size(void *ptr)                                     \
> > +     {                                                                      \
> > +             __kcsan_check_access(ptr, size, true);                         \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_write##size)
> > +
> > +DEFINE_TSAN_READ_WRITE(1);
> > +DEFINE_TSAN_READ_WRITE(2);
> > +DEFINE_TSAN_READ_WRITE(4);
> > +DEFINE_TSAN_READ_WRITE(8);
> > +DEFINE_TSAN_READ_WRITE(16);
> > +
> > +/*
> > + * Not all supported compiler versions distinguish aligned/unaligned accesses,
> > + * but e.g. recent versions of Clang do.
> > + */
> > +#define DEFINE_TSAN_UNALIGNED_READ_WRITE(size)                                 \
> > +     void __tsan_unaligned_read##size(void *ptr)                            \
> > +     {                                                                      \
> > +             __kcsan_check_access(ptr, size, false);                        \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
> > +     void __tsan_unaligned_write##size(void *ptr)                           \
> > +     {                                                                      \
> > +             __kcsan_check_access(ptr, size, true);                         \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_unaligned_write##size)
> > +
> > +DEFINE_TSAN_UNALIGNED_READ_WRITE(2);
> > +DEFINE_TSAN_UNALIGNED_READ_WRITE(4);
> > +DEFINE_TSAN_UNALIGNED_READ_WRITE(8);
> > +DEFINE_TSAN_UNALIGNED_READ_WRITE(16);
> > +
> > +void __tsan_read_range(void *ptr, size_t size)
> > +{
> > +     __kcsan_check_access(ptr, size, false);
> > +}
> > +EXPORT_SYMBOL(__tsan_read_range);
> > +
> > +void __tsan_write_range(void *ptr, size_t size)
> > +{
> > +     __kcsan_check_access(ptr, size, true);
> > +}
> > +EXPORT_SYMBOL(__tsan_write_range);
> > +
> > +/*
> > + * The below are not required KCSAN, but can still be emitted by the compiler.
> > + */
> > +void __tsan_func_entry(void *call_pc)
> > +{
> > +}
> > +EXPORT_SYMBOL(__tsan_func_entry);
> > +void __tsan_func_exit(void)
> > +{
> > +}
> > +EXPORT_SYMBOL(__tsan_func_exit);
> > +void __tsan_init(void)
> > +{
> > +}
> > +EXPORT_SYMBOL(__tsan_init);
> [...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOxmQDKin%3D9Cyi%2BERVQ-ehH79AaPjRvJNfFfmgOjJAogA%40mail.gmail.com.
