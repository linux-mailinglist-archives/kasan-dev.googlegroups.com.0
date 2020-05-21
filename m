Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45KTH3AKGQEFV7C2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 29D6C1DCADC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 12:18:28 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id s23sf3182660ook.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 03:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590056307; cv=pass;
        d=google.com; s=arc-20160816;
        b=VV+hsH8Dx4W0TnQT7QgT3U1Y2arnlr8epJz+V1xT6kjznjzJdU5KQopx14Voq2S0up
         cbpi5PStNliwSBrtBLs7hXDANiRyBrs3UwFEm7JOvY79DYsQ6EY0zmdFyknPmNbEELRX
         e5rbjh3gzT15CzcP37y06p1qwOuE3ujLk4rEYpaB+pgftmrFarCMy51ab+Upoemyb+Zq
         WL0vgB1UzctEwOc6qOFTo8wAzquBK+b3LhO16b0ELUxJcSwZqD5YUV81QsUCQgmQ7e7O
         mGgoMbVrVWX1RR46jso4AaBAUEsdoU4sIw3rceyqaEnCFKcg14Bba1ihHREcbgP2WmuJ
         CH9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/s7CBJiF/qVf2MdP+g1BlSQszJUhtF3SIezSRUTzViE=;
        b=OOrff41xm/Yo81tY/uRe6Kv56sU4HYcQQC/nMUl3kJrvSFXx9ZUw5m8vOj/d1yJmgx
         3qBQ0NBOokEAbsXtD4KYt4z13iDaWOyRadgD45obvpRjDlKSPxtYx+qdeKR6KQoq6RMs
         Fysto7c2EtHAJ9SZvIF/I7c88LfMscqMLsDwPocodJnrumRUjaipBwCT3pwtorLbGuDd
         LMXKezqfETR9Qn88WiBtVJTN7JcE7xoa0VDd4/2f3wY9Ra4U5lkovSQYYWMn5YtHW24F
         syDE/+6yUSaNWeu/vKOR8AZMf1pmtCcCRI1OdGQ41VYFXZFc3lyEuJLJkhtWYZjUhfnQ
         2xRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g3fbfIYD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/s7CBJiF/qVf2MdP+g1BlSQszJUhtF3SIezSRUTzViE=;
        b=YQDn4oE891ioFb4zP3PoTQ5v4T8SJwrYmHN+gMD0bGVKL2ecxleugikoOZTDxh9rF5
         gQNIhHXdx/zShlNe+j2iypr9aRnMlpSjIqKpKKZniieLAM1TJflCzz5I5aNxXGF2GxLs
         JJJvPAmsqmPKG9b5C0tI5yraeqTsagdHZ84BvPaDFSu0NwOdSDzxl5+TkRLasPyDcRzs
         z5kJuR7BQXWk0oBfSQUqDncFmFNTlmJimsAbUlOok6bzt1ahHWdh9yFBRJrDO6GH4Zd8
         5S9hdHzYXvTBtxS3sw6x6pZ0Re2bSzb40cMMswUKD+ZIulTYWU18Vxz/4TxJtW58oIvF
         1dJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/s7CBJiF/qVf2MdP+g1BlSQszJUhtF3SIezSRUTzViE=;
        b=CEpQOUK+mfl8Fg+PafCQpOyUhs6TYG9b+ws4tkDoPVY56TepaBPG/Z/DjZV4mbUWB9
         bzTltg8Y5uvWG+djb5a2FhpZ5cn0gxHUXmlbuVXsDza6ljgNiBm42oep/Uj0eO57/Qc4
         r2UeczEiANQ4ZX9LmkjWKN5g4GWW8XPk4sfHQpnEFSFE6eJDZPpvxhrT69xxK97eVzWh
         IYDuDUPBX0XdyMyuff/A1/F+iteZ4Gs3DWdD/9yMXCdbG8T4D+2QQ967N5mxjwWu/iHf
         lmL33xaxQm4dvHXWdgGwDAFBR7KMNzMNQNzN+9+jLog51ljtJT+Cw7Kjc+RCZx2qYCMT
         xZQA==
X-Gm-Message-State: AOAM533gvwFLz37bPuwPn4olKQcOYeDReUCx1BWUKDlxLLYnk/2n/GuL
	dqKaiGp9JRNG4SM/n2P7rBQ=
X-Google-Smtp-Source: ABdhPJxL+j79HaaUus3KxM2MRde0A8VwR9Q4ZRPOit6EBZ22WV8Z3m06MwpqNB29YKJt56s7xU1r0A==
X-Received: by 2002:aca:eb96:: with SMTP id j144mr5721890oih.48.1590056307080;
        Thu, 21 May 2020 03:18:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:502:: with SMTP id 2ls304507oif.11.gmail; Thu, 21 May
 2020 03:18:26 -0700 (PDT)
X-Received: by 2002:aca:3883:: with SMTP id f125mr6331122oia.28.1590056306816;
        Thu, 21 May 2020 03:18:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590056306; cv=none;
        d=google.com; s=arc-20160816;
        b=gMUsLWgGiujZXEX+Axsn7cJjfelyUw3CB7pwJWWDDz3i16o+HjsYCh6P1qiPTC1fav
         9Wf7uZiCEVfQl/855Mez81mBlQtM1XlhRCUcl6HA96j1e/OE/i0Y5XyhdZNYIfC96LNz
         VjDPm1ZenE2Ptxg6NimffQmSFm9CvD+BjGwE1NnaDuKyCVA+hLXbhQ5Go9rsJ5qwF87S
         Ckdm+4xqB9up3Y+6yNwTYWiJ3bP+t51cxNeSeJ2A3mk/vKqn1XOpoohD+uA/QwEjK480
         7eteBmb1TJlvsXVOCM487qM7OXmzfmR5O35oO/V3Z8NSe5m40jx1bifFkJ2w/b1FFbHe
         YTQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=izKU/C7ocKPbE+164Qwv+Ka88gTqLAT8wcuVjIle3sU=;
        b=jrAObOOJp3XpCb3W0Cui+sZl4unh2tJ0elnQeGakGANM4h5jHLVyh25vgnYKwxjywD
         A5QfLAnIr8n/QWXiPJuXQCEJe4E0QRnENzMSAWIISNJZ+kgoEYtZcj1Ayzf06NoLNjIg
         jczNq8juZP/STWdiSm41XiZPA5bYDgZfGv+aXgsn/LOShkdlDSROw53jHr5tEunF+VKc
         33dSNMcOfdf+x/vVwOrbGY9G+R8+Uw6Dm6bEl/NTpha9NQgf3gvVr99B04n5iPl+KFvg
         lRtrKzrHCM4SBomp/gPrhbo62ZFV2yqTtvK7AUXFQfRAddhcTPSiRnYe8T3/gHT7g4gk
         7DyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g3fbfIYD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc43.google.com (mail-oo1-xc43.google.com. [2607:f8b0:4864:20::c43])
        by gmr-mx.google.com with ESMTPS id k65si472330oib.2.2020.05.21.03.18.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 03:18:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) client-ip=2607:f8b0:4864:20::c43;
Received: by mail-oo1-xc43.google.com with SMTP id a83so1335253oob.9
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 03:18:26 -0700 (PDT)
X-Received: by 2002:a4a:6241:: with SMTP id y1mr4526981oog.14.1590056306345;
 Thu, 21 May 2020 03:18:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200515150338.190344-1-elver@google.com> <20200515150338.190344-9-elver@google.com>
 <CANpmjNNdBrO=dJ1gL+y0w2zBFdB7G1E9g4uk7oDDEt_X9FaRVA@mail.gmail.com>
In-Reply-To: <CANpmjNNdBrO=dJ1gL+y0w2zBFdB7G1E9g4uk7oDDEt_X9FaRVA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 12:18:14 +0200
Message-ID: <CANpmjNPLVMTSUAARL94Pug21ab4+zNikO1HYN2fVO3LfM4aMuQ@mail.gmail.com>
Subject: Re: [PATCH -tip 08/10] READ_ONCE, WRITE_ONCE: Remove data_race() wrapping
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g3fbfIYD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as
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

On Thu, 21 May 2020 at 11:47, Marco Elver <elver@google.com> wrote:
>
> On Fri, 15 May 2020 at 17:04, Marco Elver <elver@google.com> wrote:
> >
> > The volatile access no longer needs to be wrapped in data_race(),
> > because we require compilers that emit instrumentation distinguishing
> > volatile accesses.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/compiler.h | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > index 17c98b215572..fce56402c082 100644
> > --- a/include/linux/compiler.h
> > +++ b/include/linux/compiler.h
> > @@ -229,7 +229,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> >  #define __READ_ONCE_SCALAR(x)                                          \
> >  ({                                                                     \
> >         typeof(x) *__xp = &(x);                                         \
> > -       __unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));  \
> > +       __unqual_scalar_typeof(x) __x = __READ_ONCE(*__xp);             \
> >         kcsan_check_atomic_read(__xp, sizeof(*__xp));                   \
>
> Some self-review: We don't need kcsan_check_atomic anymore, and this
> should be removed.
>
> I'll send v2 to address this (together with fix to data_race()
> removing nested statement expressions).

The other thing here is that we no longer require __xp, and can just
pass x into __READ_ONCE.

> >         smp_read_barrier_depends();                                     \
> >         (typeof(x))__x;                                                 \
> > @@ -250,7 +250,7 @@ do {                                                                        \
> >  do {                                                                   \
> >         typeof(x) *__xp = &(x);                                         \
> >         kcsan_check_atomic_write(__xp, sizeof(*__xp));                  \
>
> Same.

__xp can also be removed.

Note that this effectively aliases __WRITE_ONCE_SCALAR to
__WRITE_ONCE. To keep the API consistent with READ_ONCE, I assume we
want to keep __WRITE_ONCE_SCALAR, in case it is meant to change in
future?

> > -       data_race(({ __WRITE_ONCE(*__xp, val); 0; }));                  \
> > +       __WRITE_ONCE(*__xp, val);                                       \
> >  } while (0)
> >
> >  #define WRITE_ONCE(x, val)                                             \
> > --
> > 2.26.2.761.g0e0b3e54be-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPLVMTSUAARL94Pug21ab4%2BzNikO1HYN2fVO3LfM4aMuQ%40mail.gmail.com.
