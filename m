Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJX7XTWQKGQE3O6EX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E464E0ADB
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 19:43:03 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id s3sf17425230qkd.6
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 10:43:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571766182; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/c7rdfNevYUGGOc1j5T1UtujS/WEHrdCrGDClEMuI/eLm9wleEluRnJ30NAlu2aI1
         6+GwyWzKbSwgxdNJ/3vlwEpNO3femfIH7+m/w4xheyNDuptks7fX6utQ8coF23Lxg6z4
         Mg1Vx6R6kSRhz1HAknqqDQT0hrnqno+m9/HGS9JQ951GqNGagNDd+JW6OoV8BYflGqHG
         1y8yYG2NHgvYGufbGUfyH3EeuZTjXzz/SFETgG3oBEGeSXmI5Yeg31rF/+itUd5hMNbh
         XIDX4T16P64j34IWPJpn0Y27B/DwSBE7Hfi8r69kl814LQ9hXj8tOOhataNFlKPyn7K+
         s+0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EYyHEOZeBeinhrjrcajOc+ckAgVm5fzNLW0uIo0M+xk=;
        b=HxLpHII3XTeGLhIvy7o5erStMbe9AeA0WgqCFEYm/xpjfc+/bh3INT4pwPYihCBDnF
         r4QlGOp2brctdDgjjjUUKoTWF/Gwxpz2aKe3EB8utWt5X+gsWeezjOszfuEtytQUlBv2
         y/M9J52wmczS6i30yI7yBBa5ZA+3j6PNA6uY7Kc5EUZmZyn+Ps9E9qYUGwq5n3jz4rVh
         JqRMz9uUNhfzPYd/OFVUTOX6aZfGtc5/9yER0FU1uawCCbzvVTrw9eXmQa2vtzVVmGRB
         Sk67x+oFtlE6je4lBXaXJE3c/+lzb25ej8WQYNstsCXuJfi8gFcMxKnntYnPsD+yScUF
         o3Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8bfP3dY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EYyHEOZeBeinhrjrcajOc+ckAgVm5fzNLW0uIo0M+xk=;
        b=rGVJaYJe/DpmilFy7NEOQ8yPeStYz8slLfOpn0dXqY/3NKLKVFbuxgVKXtjcxSACBo
         uAGI6ECDKg3w3rb7ShK2yrOVQn6vN4rWc3/uf8WZX7EdDtF/oYXma255DBozAeRGxPLt
         w/nHfulMY3a9GDJuJgcMk3okF8umU+9oIEd8/QnVCxEU5MxgBo86/CX8WIpu27HTsRLU
         FnkdI5jnQrH7QYSCREypSGe9YPym3MXn8qYubsf8bJERKRaCbp0QPx0OiLSZ0QpjTpQP
         8k5IDp9ZT/ZwEcSTOZbKwQcuw7KRgDdNDd81hVhZ4WFH/F+3+c+O8240ovpZb60R/Sij
         4jEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EYyHEOZeBeinhrjrcajOc+ckAgVm5fzNLW0uIo0M+xk=;
        b=Nq3UDTBaioM54LS8kvhcdm1c7V9Vj6FTiXaIieXvX8+NS/9Eqwe1cQIPxPuK/H7LR2
         SRuzQ6Z0+d/ILMeoYEoiZVCzvSITYVyS1fyznVETUTi6LIWgbvWD9Vcjy64TyO8v8tSg
         pLfmswDJTyMZvmHTAbxjMpSvFTCebGeO19PP2E5eILp3qS9M72DR89kXAbIx8KK1uxDN
         Wu4o3+MA3UWA7XbNNzAl6XDTnrQX8hTyMJnvmJK7dK3sXlrikOW3UxbOJxBW2/1Rfok4
         0prJakJqBVllRJ0POXD3ealzkEh9Vu9tQrLlHBinP6Y3xygDfLpmAXlgWao6Vj0/S5GK
         g5jg==
X-Gm-Message-State: APjAAAW73eJjR2zQlJLSK7kkMCKk5U3Xsj1BgpN9TI5pld7bd0z49oTx
	NL+UqmG2M24i7tODd+GzGb4=
X-Google-Smtp-Source: APXvYqwrBaYqPVvz9AKFK3O9ufeRfHTCOd2jZT6jrYC/eiTRzCVgRYzQbkjqVYZ36p2UbVvUYVvIcg==
X-Received: by 2002:ac8:31c5:: with SMTP id i5mr4750366qte.33.1571766182312;
        Tue, 22 Oct 2019 10:43:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3c70:: with SMTP id u45ls1766127qte.16.gmail; Tue, 22
 Oct 2019 10:43:02 -0700 (PDT)
X-Received: by 2002:ac8:4294:: with SMTP id o20mr4163601qtl.341.1571766182009;
        Tue, 22 Oct 2019 10:43:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571766182; cv=none;
        d=google.com; s=arc-20160816;
        b=KenzzRYa5LPYI89mvPp9ZKy2XHagjG3tVCuKw1H6gdwalyK1VM4F7CjGeNGlcj92Io
         idd0TzjMa8PyKgbt4iYbdMqqi5w2l6zQA6yge8L9PO7QL+N+Hz8Rqq2W1lfjtF9hO0DO
         GZhR2kkWTpQXtA+DeKQmwad6h2C5ptEx+t6vPxRrnSmoJoiQC1kwtZtLRv/0TklWbuPl
         LZG9EP5NX/R3BoXOqnriIsDvN2sCS38au7q6lzuBf7yuQR0cb3qNBUhrN4bxohfgZtHb
         HSuzSDMcsOWX7zmVn6xSzQSnW0hc3eX5IxUOjLahjK8ZfvLL2aTbewYXwEE2dh8Veda3
         YQmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MHo+bPZ3FyZTrXrvFae5gOHqYffPj0NYcnQ23J1Mtd8=;
        b=O/xt92sAMdLJ+A0RT0i7tbQMUJiAJGhdidbN/aF2tdqpVPFjYINLDu/ASmBTMDbqIz
         rx5yMmfJ68ToJHh57vmrk8aP4Q/FciYrnWW5khmtTk0pAczteHkyu4S9OWVtmPmhP5Eo
         +IhoUe4gGvcjKrfQOne3qKKWQLNGIyXYOTGIjzibjeFzgbA+WPy32okv23vvJvEJMCFH
         UxUdkuLTyLDuvuk6m2/M1aCTre/8tFJCbbCRXOfBt6BdiLU7XYY8TIHS/F569K+PUOCo
         I0ZbL8C2HLRvds/lylyZztdxK6RjNUXjPfJF81BOpxg8xTaeXKZm+SVEQBzCrDOLzWoo
         NgHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8bfP3dY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id t186si706497qkf.3.2019.10.22.10.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Oct 2019 10:43:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id w144so14945075oia.6
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2019 10:43:01 -0700 (PDT)
X-Received: by 2002:aca:f492:: with SMTP id s140mr4056153oih.83.1571766180963;
 Tue, 22 Oct 2019 10:43:00 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
 <20191022154858.GA13700@redhat.com>
In-Reply-To: <20191022154858.GA13700@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2019 19:42:48 +0200
Message-ID: <CANpmjNPUT2B3rWaa=5Ee2Xs3HHDaUiBGpG09Q4h9Gemhsp9KFw@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Oleg Nesterov <oleg@redhat.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D8bfP3dY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Tue, 22 Oct 2019 at 17:49, Oleg Nesterov <oleg@redhat.com> wrote:
>
> On 10/17, Marco Elver wrote:
> >
> > +     /*
> > +      * Delay this thread, to increase probability of observing a racy
> > +      * conflicting access.
> > +      */
> > +     udelay(get_delay());
> > +
> > +     /*
> > +      * Re-read value, and check if it is as expected; if not, we infer a
> > +      * racy access.
> > +      */
> > +     switch (size) {
> > +     case 1:
> > +             is_expected = expect_value._1 == READ_ONCE(*(const u8 *)ptr);
> > +             break;
> > +     case 2:
> > +             is_expected = expect_value._2 == READ_ONCE(*(const u16 *)ptr);
> > +             break;
> > +     case 4:
> > +             is_expected = expect_value._4 == READ_ONCE(*(const u32 *)ptr);
> > +             break;
> > +     case 8:
> > +             is_expected = expect_value._8 == READ_ONCE(*(const u64 *)ptr);
> > +             break;
> > +     default:
> > +             break; /* ignore; we do not diff the values */
> > +     }
> > +
> > +     /* Check if this access raced with another. */
> > +     if (!remove_watchpoint(watchpoint)) {
> > +             /*
> > +              * No need to increment 'race' counter, as the racing thread
> > +              * already did.
> > +              */
> > +             kcsan_report(ptr, size, is_write, smp_processor_id(),
> > +                          kcsan_report_race_setup);
> > +     } else if (!is_expected) {
> > +             /* Inferring a race, since the value should not have changed. */
> > +             kcsan_counter_inc(kcsan_counter_races_unknown_origin);
> > +#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> > +             kcsan_report(ptr, size, is_write, smp_processor_id(),
> > +                          kcsan_report_race_unknown_origin);
> > +#endif
> > +     }
>
> Not sure I understand this code...
>
> Just for example. Suppose that task->state = TASK_UNINTERRUPTIBLE, this task
> does __set_current_state(TASK_RUNNING), another CPU does wake_up_process(task)
> which does the same UNINTERRUPTIBLE -> RUNNING transition.
>
> Looks like, this is the "data race" according to kcsan?

Yes, they are "data races". They are probably not "race conditions" though.

This is a fair distinction to make, and we never claimed to find "race
conditions" only -- race conditions are logic bugs that result in bad
state due to unexpected interleaving of threads. Data races are more
subtle, and become relevant at the programming language level.

In Documentation we summarize: "Informally, two operations conflict if
they access the same memory location, and at least one of them is a
write operation. In an execution, two memory operations from different
threads form a data-race if they conflict, at least one of them is a
*plain* access (non-atomic), and they are unordered in the
"happens-before" order according to the LKMM."

KCSAN's goal is to find *data races* according to the LKMM.  Some data
races are race conditions (usually the more interesting bugs) -- but
not *all* data races are race conditions. Those are what are usually
referred to as "benign", but they can still become bugs on the wrong
arch/compiler combination. Hence, the need to annotate these accesses
with READ_ONCE, WRITE_ONCE or use atomic_t:
- https://lwn.net/Articles/793253/
- https://lwn.net/Articles/799218/

> Hmm. even the "if (!(p->state & state))" check in try_to_wake_up() can trigger
> kcsan_report() ?

We blacklisted sched (KCSAN_SANITIZE := n   in kernel/sched/Makefile),
so these data races won't actually be reported.

Thanks,
-- Marco

> Oleg.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPUT2B3rWaa%3D5Ee2Xs3HHDaUiBGpG09Q4h9Gemhsp9KFw%40mail.gmail.com.
