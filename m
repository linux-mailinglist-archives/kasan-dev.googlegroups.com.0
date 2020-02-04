Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4OQ43YQKGQE47TKTSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C02A151F50
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 18:22:58 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id h66sf27436315ywc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 09:22:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580836977; cv=pass;
        d=google.com; s=arc-20160816;
        b=EAvOLjog1wyP1QZag+SpxhP+81Lb8wXK/+OsBWdHjDy4835ZhMEbpTWfZ7bN5K/Auc
         dCfQpM4lEwXNGl4lofnYqxKIIq9akeOGP/qOz1PYEgHf5bQe9BDePG1K2+CmDs4ZI8wK
         aioK1jW0sZXmrHNiPKG2K9ZB1l2402a6TbQpCsSo7nY0KZmqOHo8GROI/pc+b1NRqWIK
         aCmUYOcM7OYZAYPv5+8Jm7CVeN2fZLnJ+sqqw7jBDC4iJRcI3lwHvq5miR8rFGfLZ9zR
         SsbabX2po7UmJiCWPWiinTT5gli8nM1ft9SKC5StovAaXbZvGJT4e2pKY/jSI2uEWQBQ
         0ZEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lizgL4msUI5N8gdrDZlHY/TklB7OBkU5xkGCR64MDcA=;
        b=PvnaUDO2INL6JF6hgv0rhLw7rx67e0y5Qa5BXzA5LDiX1RRQ2a3Snk745fYQ02mFXv
         7FJKxGEwmCeCZyV2tJdZVD1NAvzKWrVcTLfTkaAG65lhSbpkActWWMWPByqYGJSH+je9
         LmsnOoGLxlJyQpyGFKAgu7K6IpioKzSqeD6XaG7bAm+YEoEn5R6r7ysLFKW34i+6yDk9
         TCgGMEbc3uM1gKqaZCMwxHeUAp6u7VEa+PIBFBh0/DjybteubL3V8T+9PinRGbrPw0Gt
         G+8KDqMpnWtNOHKbnpA1YaOEt2M6Gq7KxbF2CqEhFSyCbVLM5qkdB+QDaYKPbEbaT6SK
         N5ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iPVZGvXG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lizgL4msUI5N8gdrDZlHY/TklB7OBkU5xkGCR64MDcA=;
        b=FxKbM0gAw5fbq0Ota+3C7fQkVGHNuGcyKa0ZyrQuzDAjVSVE8dP4EePEqiHq61fS5p
         CY4wI6LJ769BBm7NY+Vy+Q2UEHBFV8pR9pCVPMULHdtaI2FFpXeMdG09SoqwalCdH2ki
         6NHJSQsJNeOwQ5e5jNPZMtslxrdm7/H+7jTLmGgPOkEH+ogShwEDwEOtOaOyKBboe5X4
         EJalANNQnMVm9j4WyU1q5KZH6geO153EOHoiFwsO2dC7nCe33mDTJOT6uZ4zbmu9o+d+
         C912+DrGlPIohZV/gf7Jy1EpPhvdsXR6NDSdc1j/BIKWz36cnYGoqOlCA9NQIFBu34cZ
         LC9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lizgL4msUI5N8gdrDZlHY/TklB7OBkU5xkGCR64MDcA=;
        b=qbd6oUZva8S2qSuZgzKkLc+d1/FiFuW9lVhjIIfMsABp6xtGkqDMmHcQUPXkJrBYyY
         w64E9fwEU+iSrv8/uy426bKpClM06tZ3R8G1HIe0q9eR/WKLsmRGG1JMxMsnZiGb9HWD
         kKfoQkw+raFD7n80uVqn7+WFe6SCCjtDlxNNoX/wGIB6/ss+Yw1DRXhIEL7xKebmLrGR
         hYeSQJOkWCxvtdIUJbgyodZng2fkbqDRgp1wAuCE06gaFWmg0prwxHV9kkw4itddYI0R
         DbZoLzyr7xf9dL+xTbZhXVTchLOJ5eRwd6vtJnj4/M6MK8Cle7Ms0/cRw/lZH3zrsvzo
         jLlw==
X-Gm-Message-State: APjAAAXORILLm9BwasjD7rB7TgsrxjZdK7IH96/PP4JjtVshN/8qNZo5
	X8aDWvqDyw0IP4SyVGo44gg=
X-Google-Smtp-Source: APXvYqyKNvjj//94He0BLt4QxDsP4V8jNAA7urB9+tb+NtqP91O/MVvIkWzCp2n1T/VGVlNG8lbcSw==
X-Received: by 2002:a25:84cd:: with SMTP id x13mr24948254ybm.426.1580836977439;
        Tue, 04 Feb 2020 09:22:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:381:: with SMTP id 123ls865768ywd.9.gmail; Tue, 04 Feb
 2020 09:22:57 -0800 (PST)
X-Received: by 2002:a0d:f583:: with SMTP id e125mr1841860ywf.176.1580836977022;
        Tue, 04 Feb 2020 09:22:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580836977; cv=none;
        d=google.com; s=arc-20160816;
        b=FGDAeoOQM33O71OpEwWsokU1PuLCX7moaCCToESelHBVCMnnR/hhJBiLM2FNfDhY5n
         I3nlaoYCKRxy14t7aIV0tyX/gJQU1KBJ3SJb2DaKxZjvMCqbx0hyoDaKSG64ngAdTbgZ
         N3BXg56AFMgo+qoBJyY8vyO49sfYBpl8SkQfVZ/SRttseRK3DoWfSWdJzVxKkCt8gm4J
         zUbKbMus48Yrpa7rzhNuqcL5a9nk8qg1WoXSryXE5gZbWjmMW4UoMjWRh6yBHR1h1R40
         YIr2JKjHFBl65qC/8INWcJbTArOy3x62iR5wbBow32dJRZDxA5W74VAztBHLfvoDBqQ+
         soaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WdU/+EXQPN08tVx0Omqu46OD1KCs9yfQsxA+mu440FM=;
        b=ZZjm0dCNeg6FstDoK+VXIIuW4GI1x1CMYHpIluosxeJakZzRS596Ubhk3QctNVFhEU
         d0KDj9LgWDqmX2VN69vOo6UKA+h665FxKkmcsyJn3ZqVYAvUXKXU+Au97sjtGF4AXkPm
         z22t16Q9f8dT0qVlCc2Wch9/nUf9xZZjXH7LRG0Gh4zEU3b9wbUVNidVNy9apNWD3dgS
         XneteADdfUoSsR553Y5F9QSQbLBXYlgXiszSSAiIeh3/ubYZb5DMX71mVPAwiH9/TRWi
         PWtVoKZiGiCA7nBe/uu8wPWe2Xs4ZWqW+FwLjV2XQl1PAQ3QFJZUsrAGBEuQNU9mZs/j
         3mxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iPVZGvXG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id l1si587462ybt.2.2020.02.04.09.22.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 09:22:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id q81so19288367oig.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 09:22:56 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr47816oiz.155.1580836976510;
 Tue, 04 Feb 2020 09:22:56 -0800 (PST)
MIME-Version: 1.0
References: <20200204140353.177797-1-elver@google.com> <CANpmjNMF3LpOUZSKXigxVXaH8imA2O5OvVu4ibPEDhCjwAXk0w@mail.gmail.com>
 <20200204154015.GQ2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200204154015.GQ2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Feb 2020 18:22:45 +0100
Message-ID: <CANpmjNOeHTMtTPFt1b3bzFanYrtswG-GUZgURaJzchgX7E5psA@mail.gmail.com>
Subject: Re: [PATCH 1/3] kcsan: Add option to assume plain writes up to word
 size are atomic
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iPVZGvXG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Tue, 4 Feb 2020 at 16:40, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Feb 04, 2020 at 04:28:47PM +0100, Marco Elver wrote:
> > On Tue, 4 Feb 2020 at 15:04, Marco Elver <elver@google.com> wrote:
> > >
> > > This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
> > > writes up to word size are also assumed to be atomic, and also not
> > > subject to other unsafe compiler optimizations resulting in data races.
> >
> > I just realized we should probably also check for alignedness. Would
> > this be fair to add as an additional constraint? It would be my
> > preference.
>
> Checking for alignment makes a lot of sense to me!  Otherwise, write
> tearing is expected behavior on some systems.

Sent v2: http://lkml.kernel.org/r/20200204172112.234455-1-elver@google.com

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> > > This option has been enabled by default to reflect current kernel-wide
> > > preferences.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  kernel/kcsan/core.c | 20 +++++++++++++++-----
> > >  lib/Kconfig.kcsan   | 26 +++++++++++++++++++-------
> > >  2 files changed, 34 insertions(+), 12 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > index 64b30f7716a12..3bd1bf8d6bfeb 100644
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -169,10 +169,19 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
> > >         return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> > >  }
> > >
> > > -static __always_inline bool is_atomic(const volatile void *ptr)
> > > +static __always_inline bool
> > > +is_atomic(const volatile void *ptr, size_t size, int type)
> > >  {
> > > -       struct kcsan_ctx *ctx = get_ctx();
> > > +       struct kcsan_ctx *ctx;
> > > +
> > > +       if ((type & KCSAN_ACCESS_ATOMIC) != 0)
> > > +               return true;
> > >
> > > +       if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
> > > +           (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long))
> > > +               return true; /* Assume all writes up to word size are atomic. */
> > > +
> > > +       ctx = get_ctx();
> > >         if (unlikely(ctx->atomic_next > 0)) {
> > >                 /*
> > >                  * Because we do not have separate contexts for nested
> > > @@ -193,7 +202,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
> > >         return kcsan_is_atomic(ptr);
> > >  }
> > >
> > > -static __always_inline bool should_watch(const volatile void *ptr, int type)
> > > +static __always_inline bool
> > > +should_watch(const volatile void *ptr, size_t size, int type)
> > >  {
> > >         /*
> > >          * Never set up watchpoints when memory operations are atomic.
> > > @@ -202,7 +212,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
> > >          * should not count towards skipped instructions, and (2) to actually
> > >          * decrement kcsan_atomic_next for consecutive instruction stream.
> > >          */
> > > -       if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
> > > +       if (is_atomic(ptr, size, type))
> > >                 return false;
> > >
> > >         if (this_cpu_dec_return(kcsan_skip) >= 0)
> > > @@ -460,7 +470,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
> > >         if (unlikely(watchpoint != NULL))
> > >                 kcsan_found_watchpoint(ptr, size, type, watchpoint,
> > >                                        encoded_watchpoint);
> > > -       else if (unlikely(should_watch(ptr, type)))
> > > +       else if (unlikely(should_watch(ptr, size, type)))
> > >                 kcsan_setup_watchpoint(ptr, size, type);
> > >  }
> > >
> > > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > > index 3552990abcfe5..08972376f0454 100644
> > > --- a/lib/Kconfig.kcsan
> > > +++ b/lib/Kconfig.kcsan
> > > @@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
> > >           limiting reporting to avoid flooding the console with reports.
> > >           Setting this to 0 disables rate limiting.
> > >
> > > -# Note that, while some of the below options could be turned into boot
> > > -# parameters, to optimize for the common use-case, we avoid this because: (a)
> > > -# it would impact performance (and we want to avoid static branch for all
> > > -# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
> > > -# without real benefit. The main purpose of the below options is for use in
> > > -# fuzzer configs to control reported data races, and they are not expected
> > > -# to be switched frequently by a user.
> > > +# The main purpose of the below options is to control reported data races (e.g.
> > > +# in fuzzer configs), and are not expected to be switched frequently by other
> > > +# users. We could turn some of them into boot parameters, but given they should
> > > +# not be switched normally, let's keep them here to simplify configuration.
> > > +#
> > > +# The defaults below are chosen to be very conservative, and may miss certain
> > > +# bugs.
> > >
> > >  config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> > >         bool "Report races of unknown origin"
> > > @@ -116,6 +116,18 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
> > >           the data value of the memory location was observed to remain
> > >           unchanged, do not report the data race.
> > >
> > > +config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> > > +       bool "Assume that plain writes up to word size are atomic"
> > > +       default y
> > > +       help
> > > +         Assume that plain writes up to word size are atomic by default, and
> > > +         also not subject to other unsafe compiler optimizations resulting in
> > > +         data races. This will cause KCSAN to not report data races due to
> > > +         conflicts where the only plain accesses are writes up to word size:
> > > +         conflicts between marked reads and plain writes up to word size will
> > > +         not be reported as data races; notice that data races between two
> > > +         conflicting plain writes will also not be reported.
> > > +
> > >  config KCSAN_IGNORE_ATOMICS
> > >         bool "Do not instrument marked atomic accesses"
> > >         help
> > > --
> > > 2.25.0.341.g760bfbb309-goog
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOeHTMtTPFt1b3bzFanYrtswG-GUZgURaJzchgX7E5psA%40mail.gmail.com.
