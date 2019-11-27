Return-Path: <kasan-dev+bncBCMIZB7QWENRBLMG7HXAKGQE5H6TJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B3C010ACA7
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 10:34:39 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id cu13sf10760497pjb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 01:34:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574847277; cv=pass;
        d=google.com; s=arc-20160816;
        b=fp7n/BfpVNSrhUp6qe3wpIY3xp6xNTtadUPXT2yuD/U3orb3d9pQfWE2t64jcSbUUm
         VNe/AwbiDZolc0rlPRB29m8p066M+JDfV1fI01ksFVOdOZZTon7KLCJwTRRpeWv5ikrb
         maK0SFXkzwSfP6rb8RjznZXIkAk8T9l6TpDUqjUSB1IQ8fofX4h95csFwBoN3HK9m9Fb
         u6BSowcuG6GHo4yBQ7c1/oNkcXWqfo2QPBsyX6eYTvQfUe2niOkdazsMabtrXGEgUqXy
         jQWrYArw6Av+d31aXJSXgoMZnGQYJ6qilXnaVF2NDUlvyddqa2IGT3BQz9v9VuJQ25nX
         rCig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=la7WlKxIq/k5EWUdzuFHRXwZoI+J4CtVWZ6K5gcKZpI=;
        b=qZ3sEftl6WtFllcHUgqsTixOSW75tr+r8OcZ+zJvRa8XIKWxFMNj9A9vZV9rEUlnXm
         4seqNQz0OfZqLhdiibCmYc5bV2Umd1TbMRAUUzAUoQcbYA7EmvX0zkVi7cFn7xpqArBo
         8EyuNQ07NccnW2OgeBkMDGhxP9+hExj5HcjuAnd3RVAzZ25V0Ulwq3MB/8ql8QKXzXFo
         FZL2LcpBfwiiymZEoP0BcJsdCRU3VF0tGcKBT6X+SlUHUPcvspwstOVGHzsluTSp3Ht7
         tqgNecDck4ZYh7qtPRbDLJsA/jDEWDp2wmIMETl/FjeyJTZcWzbPXfoQGhxb/9Sk5qrA
         aeuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHr2i8Bk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=la7WlKxIq/k5EWUdzuFHRXwZoI+J4CtVWZ6K5gcKZpI=;
        b=PjPA6S758nbPI4UNRQIHD3XNuwCidpsCswPP3QR5TzEQgc9MB4LS61PEKYwRTiFtEN
         dtvxqxnOK/vV302UVquqqqw2iP87rLkbeKqZNCfp7Mr5NZuWdR7XFCzu/45yKissbnIA
         zKB98qmefyge2YOZk0n6a6h+etcNMkkFgUSU2x3P8N1fGHDZFP2HRiWfIkLERDjgJgFn
         beAfECbmx38IlyGMHqgE+ibTgmQdrLn1m3vLRkfoLch/ohbnYP6jocoe40tjXvhNyEtO
         DxKdP2m5bWWaOjlUBg1N4kNNoXgJ+DZtUvql3eM7/nv8ms9b0xLfErafguz7dFLzkilf
         OuOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=la7WlKxIq/k5EWUdzuFHRXwZoI+J4CtVWZ6K5gcKZpI=;
        b=YbJfSjynNm+yMlT5Z90Hc2HR+c9cEbwnP2IsvxCRB0f2TcU7hLPfJSzkWikb1v9+Xf
         NVItkHv3uwalz8TbAZz/1EzlVi0wWNBqrhEi77ufK0lYSDJHzs3NIWlqoyBuPwI6yw8c
         Z6BNO3jadHUm4f37zEMjAsVGWL0FbSZGX3kSbU7x/Jsfh/+/Z0Kf9qP4A8AwAC512tLu
         vB7zW1pGP8JB6d8uBMPDLqTXoU6mtIjmAWidAUcFleLn8yltPE8DDNXmQT34LCDGoJqI
         4gI9zCFygUZka80yWXEw8jtJSi8TOMnq9g3Dqu+qPr8lVjQbtOLrvP3ks4bZZ3Glrnpm
         x/rw==
X-Gm-Message-State: APjAAAUY+Suo6XtW2uezx2niUIn+0ViaPMbCaWZEnG5uaZeQK9/dgM/m
	7XZtC9rbOvzwKu1KnRTXmag=
X-Google-Smtp-Source: APXvYqy6t0XmB1JpWawAiicbi+w3bEvdyxj6rI0UM1xqg1rl3r+3AmfPWQBVAZsYkxvfB0SP5kWzqw==
X-Received: by 2002:a17:90a:9a9:: with SMTP id 38mr4925465pjo.45.1574847277691;
        Wed, 27 Nov 2019 01:34:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:868f:: with SMTP id g15ls5684803plo.11.gmail; Wed,
 27 Nov 2019 01:34:37 -0800 (PST)
X-Received: by 2002:a17:902:142:: with SMTP id 60mr3209808plb.38.1574847277183;
        Wed, 27 Nov 2019 01:34:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574847277; cv=none;
        d=google.com; s=arc-20160816;
        b=Qexr47AJwSFsUf8qE0MrDF1A4PG2UJaSeiR1+iXd6AMRMUP0JccjeMLXb3nI8T34WP
         ElBOIgEIfWDGgUZyyIFH9verEl6Ls9UWmdFNLEiWlQM6cNrtuLz3+FVLX0hIRiAhRqUf
         2dkEL4Ys+XLYxB5Wajs1eORB+jMLqTW9xWLrm10YjDjAhcYoan+MuF2Umaf9nVbJV8ix
         Trg6hoDDATqJWr60HJKhFqcj+gv2Se9ZI8LqlCbPPclf0+nTBAx43IzyROurx5u8i3H+
         C43ZnfOlP47m/WvK71SrQV30FpZNn+vh60yQ7eJp6bSnweWSen/ebCRXDUURokuBfech
         gtfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qQIP56rqElFFT/7mHw3od0WDBa9u5FIpMQVZJMPUUzI=;
        b=htx0oHjJ1eXDWY6D7JanIZxAF7pjg5WOoG9C+e36xuZ6dYLOH2Eqq9g7sd/6lJuBCl
         y/RgTMfctMvaHWjFH6ixkPm0rbPJZ8ZMhyFtv+apwxd+XIGiCpGn0BbGmUqQ3KdrtQnT
         ROX91dVB2dvlJhHhj+ouUWDr/2OHlXCuUm1Eoo6rPaM24rZ3rXH5NsS6ss0TddzW1Ft0
         V/VZ9zCK5C2FSo65AOWU12LhEvtkbwZ6QlKuWtV82f3ztc5ekaJ3/rJDADMlbrUbCiUO
         ry2kWSEyMHKDCcFxs7zsT/e9f87zM2MTmfPx6DWT4pXiD0YOwrBj1xQoLojAAhoX6X8P
         TZ/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UHr2i8Bk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id j19si615199pff.4.2019.11.27.01.34.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 01:34:37 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id i17so24700332qtq.1
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 01:34:37 -0800 (PST)
X-Received: by 2002:ac8:3905:: with SMTP id s5mr22440899qtb.158.1574847275676;
 Wed, 27 Nov 2019 01:34:35 -0800 (PST)
MIME-Version: 1.0
References: <20191121181519.28637-1-keescook@chromium.org> <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
 <201911262134.ED9E60965@keescook> <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
In-Reply-To: <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Nov 2019 10:34:24 +0100
Message-ID: <CACT4Y+aFiwxT6SO-ABx695Yg3=Zam5saqCo4+FembPwKSV8cug@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UHr2i8Bk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Wed, Nov 27, 2019 at 7:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Nov 27, 2019 at 6:42 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> > > On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> > > >
> > > > v2:
> > > >     - clarify Kconfig help text (aryabinin)
> > > >     - add reviewed-by
> > > >     - aim series at akpm, which seems to be where ubsan goes through?
> > > > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> > > >
> > > > This splits out the bounds checker so it can be individually used. This
> > > > is expected to be enabled in Android and hopefully for syzbot. Includes
> > > > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> > > >
> > > > -Kees
> > >
> > > +syzkaller mailing list
> > >
> > > This is great!
> >
> > BTW, can I consider this your Acked-by for these patches? :)
> >
> > > I wanted to enable UBSAN on syzbot for a long time. And it's
> > > _probably_ not lots of work. But it was stuck on somebody actually
> > > dedicating some time specifically for it.
> >
> > Do you have a general mechanism to test that syzkaller will actually
> > pick up the kernel log splat of a new check?
>
> Yes. That's one of the most important and critical parts of syzkaller :)
> The tests for different types of bugs are here:
> https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
>
> But have 3 for UBSAN, but they may be old and it would be useful to
> have 1 example crash per bug type:
>
> syzkaller$ grep UBSAN pkg/report/testdata/linux/report/*
> pkg/report/testdata/linux/report/40:TITLE: UBSAN: Undefined behaviour
> in drivers/usb/core/devio.c:LINE
> pkg/report/testdata/linux/report/40:[    4.556972] UBSAN: Undefined
> behaviour in drivers/usb/core/devio.c:1517:25
> pkg/report/testdata/linux/report/41:TITLE: UBSAN: Undefined behaviour
> in ./arch/x86/include/asm/atomic.h:LINE
> pkg/report/testdata/linux/report/41:[    3.805453] UBSAN: Undefined
> behaviour in ./arch/x86/include/asm/atomic.h:156:2
> pkg/report/testdata/linux/report/42:TITLE: UBSAN: Undefined behaviour
> in kernel/time/hrtimer.c:LINE
> pkg/report/testdata/linux/report/42:[   50.583499] UBSAN: Undefined
> behaviour in kernel/time/hrtimer.c:310:16
>
> One of them is incomplete and is parsed as "corrupted kernel output"
> (won't be reported):
> https://github.com/google/syzkaller/blob/master/pkg/report/testdata/linux/report/42
>
> Also I see that report parsing just takes the first line, which
> includes file name, which is suboptimal (too long, can't report 2 bugs
> in the same file). We seem to converge on "bug-type in function-name"
> format.
> The thing about bug titles is that it's harder to change them later.
> If syzbot already reported 100 bugs and we change titles, it will
> start re-reporting the old one after new names and the old ones will
> look stale, yet they still relevant, just detected under different
> name.
> So we also need to get this part right before enabling.
>
> > I noticed a few things
> > about the ubsan handlers: they don't use any of the common "warn"
> > infrastructure (neither does kasan from what I can see), and was missing
> > a check for panic_on_warn (kasan has this, but does it incorrectly).
>
> Yes, panic_on_warn we also need.
>
> I will look at the patches again for Acked-by.


Acked-by: Dmitry Vyukov <dvyukov@google.com>
for the series.

I see you extended the test module, do you have samples of all UBSAN
report types that are triggered by these functions? Is so, please add
them to:
https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
with whatever titles they are detected now. Improving titles will then
be the next step, but much simpler with a good collection of tests.

Will you send the panic_on_want patch as well?


> > I think kasan and ubsan should be reworked to use the common warn
> > infrastructure, and at the very least, ubsan needs this:
> >
> > diff --git a/lib/ubsan.c b/lib/ubsan.c
> > index e7d31735950d..a2535a62c9af 100644
> > --- a/lib/ubsan.c
> > +++ b/lib/ubsan.c
> > @@ -160,6 +160,17 @@ static void ubsan_epilogue(unsigned long *flags)
> >                 "========================================\n");
> >         spin_unlock_irqrestore(&report_lock, *flags);
> >         current->in_ubsan--;
> > +
> > +       if (panic_on_warn) {
> > +               /*
> > +                * This thread may hit another WARN() in the panic path.
> > +                * Resetting this prevents additional WARN() from panicking the
> > +                * system on this thread.  Other threads are blocked by the
> > +                * panic_mutex in panic().
> > +                */
> > +               panic_on_warn = 0;
> > +               panic("panic_on_warn set ...\n");
> > +       }
> >  }
> >
> >  static void handle_overflow(struct overflow_data *data, void *lhs,
> >
> > > Kees, or anybody else interested, could you provide relevant configs
> > > that (1) useful for kernel,
> >
> > As mentioned in the other email (but just to keep the note together with
> > the other thoughts here) after this series, you'd want:
> >
> > CONFIG_UBSAN=y
> > CONFIG_UBSAN_BOUNDS=y
> > # CONFIG_UBSAN_MISC is not set
> >
> > > (2) we want 100% cleanliness,
> >
> > What do you mean here by "cleanliness"? It seems different from (3)
> > about the test tripping a lot?
> >
> > > (3) don't
> > > fire all the time even without fuzzing?
> >
> > I ran with the bounds checker enabled (and the above patch) under
> > syzkaller for the weekend and saw 0 bounds checker reports.
> >
> > > Anything else required to
> > > enable UBSAN? I don't see anything. syzbot uses gcc 8.something, which
> > > I assume should be enough (but we can upgrade if necessary).
> >
> > As mentioned, gcc 8+ should be fine.
> >
> > --
> > Kees Cook
> >
> > --
> > You received this message because you are subscribed to the Google Groups "syzkaller" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/201911262134.ED9E60965%40keescook.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaFiwxT6SO-ABx695Yg3%3DZam5saqCo4%2BFembPwKSV8cug%40mail.gmail.com.
