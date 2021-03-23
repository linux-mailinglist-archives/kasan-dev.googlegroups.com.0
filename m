Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUL46BAMGQELZRAFYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C830C345C10
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 11:41:35 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id t5sf926490qti.5
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 03:41:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616496095; cv=pass;
        d=google.com; s=arc-20160816;
        b=R0SKnMJJkRZgD8lG2LA19JVjQByE9zB70FzQcswH+GblAPXzV06sDCLDZ/kdutoL3T
         PLLd16+LAFZ0g8lzs5Y3KBbDyOm7b564j505B8oXYfzvqwPH+ZU8QfUHzSV7XFClVlwo
         v26qRnWf8Nm6yyODDswhZwE8bPdexrYW1EIXqyheyZzExchHiu1C/mnDWhzqeOlSEnuK
         aSt7WSqIK0isB02D9QLRmgQsF4yy7/vZp4jPHFpMrp66eH92j52YwjBSil5kIF6AkxE/
         WrWZteS8Xjv6oQ+PArPxXHSMTYpgB6ORnxItGx1aKhZhuhSy1RFAFw3NXb7P3cTTTrvL
         +FdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/7D0SAaLHYQwA0Ln5pSY0u8Uj9sCHwRMdSwMfUJB+fM=;
        b=ZwOKC+zQR8MOaf26zkBr354K7T8RvuUc299x4v6QsZGtW7+fEY6mv8BUA5XGgmMsAr
         Yp2kVCzu2IcF3IlWQPsb7ycvuV4PVBcJ7q47sqb1HkHags+bhAVpNWqfWku7l3cYWqIN
         4rBPCqm9NqT4g06WNAemSvy9O0YBte6lQHtUj9U4AAAuoizyhvPwdXAUH0GQalFnpACm
         D6/4N5HVSwkA8EVy9rDwjtbV8L58yMBe7GxQLTIRq/7PvsFr8PH4GYGsmYVKQa7R3TvN
         jdAfvp58I438dJj8Bx73/AQNQi8Qwtdu4Wu6PYkaXN2wTu35nGG8Nf5gv3/u1LUgcgmP
         2jGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HaI/Ls3X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/7D0SAaLHYQwA0Ln5pSY0u8Uj9sCHwRMdSwMfUJB+fM=;
        b=VEBrtzNoUNab3lbdzkiViUW8ltnhZUb3xbyE1FdhmSjC2Ut64+3pXWhqxdKny+i02D
         A3E+KhZY5eIs58Y+UcB/XdrwKVHSAWhvwWILh0Lh43sbyaH1ZezsEkakEgcB94DMT/wK
         PRzK2PLfbQdDe4nop0C0I2Dw/Y8Fk1HUGisQmIsW9pjT1eIhWMD5cU00AMmvr8Pk6wkt
         GXkNEp6dpQ6K/81ZXTZJ1XEGLECT7ljJpQH/lW8aX+N3vESd+5UkWEWn2OyVXcYI2I3n
         7IqznGN3FtCSB28Gg4Vu2HfxE9jw531vUflpsEfOXy9jFoHbYt93jYX952a903y0xmUe
         oOAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/7D0SAaLHYQwA0Ln5pSY0u8Uj9sCHwRMdSwMfUJB+fM=;
        b=N+Lu7/EJXaruNrg5ydzFhuyCXbcs3g4h69Y0E8eHHqwE1nyeT2Ijf5Mi3fUtzhI0v8
         ihm7L4SyTk8e84U3Gl0sbM1Zvbx5P4GqD76Zo1vdhW6DplCxeT4s3x/pjEJiF3XelOCS
         Yq60sIp0W/MKoXLjj7A97TrxwAaRFQzUkLEufyIGZ5APTfn9JijMVJqIFHhDOaB9r9oT
         N8rErZWIQUI0Sd/VKj2Gja9kpV1FCb6ANMuMx7Nmc1VBnQJM5H2SjouDXHIIKtSBX2w7
         XwIrHv6stlyjIGjWP4R2PfjUurT+UOSFMbVq8HFqaA8+gYryMq75DnH7vHM11nIo+znM
         S4Nw==
X-Gm-Message-State: AOAM530dsQCcg6LRD6FFB9eYrveqkl6dQKJHZkeCnDDVTknBZSYPc7gJ
	o9Ig7yHnwmAYs3g+aYbSb1U=
X-Google-Smtp-Source: ABdhPJwWIJhbePO5uie5ufeP3sthW93+pExlCTAwqRYzSr2rjnGjaZS0BALWQd8h+CLy6kcniBHpyA==
X-Received: by 2002:a37:a515:: with SMTP id o21mr4573195qke.307.1616496094882;
        Tue, 23 Mar 2021 03:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e82:: with SMTP id 2ls5995988qtp.2.gmail; Tue, 23 Mar
 2021 03:41:34 -0700 (PDT)
X-Received: by 2002:ac8:4755:: with SMTP id k21mr3744484qtp.102.1616496094436;
        Tue, 23 Mar 2021 03:41:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616496094; cv=none;
        d=google.com; s=arc-20160816;
        b=o/8aBxofPO7pMjLWX6Ve1LlIBbC9RUlB130p6Rd32jC+BFlAXQdfoTgjKewmLj6bHG
         EVuqo6nOxVCh1P5q0Eu3qNxzG103KABNmFXUqEjiXkmF6hIpGkb9fWZZqhcUvy3BGr7s
         nsgVQ7KRKwhr0e1c5XFBp6YHRMnPtlB3XyGbzTyY5ziT0PPm3zMzKfVWuQdFRYk8ITfP
         bQCbWDa+vuUJIJ1KM3c6D3idxpUCjJ737JbW7xrQRfhah8QXe11suFW7fgUz8ibd53/2
         aojUU+X2vQMv15t85SMyGLLOaaEg0sRSfPCd354jzSTjAFIdyDoaz9aX/mFAI3oLnO3W
         3bFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qaMgAdM2KItPrKUMCZHabW9a3SL1RYlGywDdCoOttJE=;
        b=jHVTEjaSic8tq3y72uwRrzaz2jKvKsD9ayWVB3r/qCm3EMzaGGO6c9p8DudvqmQ13Z
         QGQyDS9xt102ajmqonq2FoHstKrnyvob2C2WWqYXCv5BkY3SscI5P6p9Eyhw+YWVv7QD
         mw0u6dltpgtvp2dC3T5CxXkY+Eruw3MCMFlWDdhhwVANYGXgArBMmuu87jQQi8ihehPH
         9pZS+/D9BrtLIcAWODHq+nYEXk4djOUe+4JC49VdarVIIl/IXhFNJp0K2PvR1kfeuOCX
         h/6Jz/PgYAqviUSh+LugbmG0uPfRLUxhUkvIWgXGSDP57bamnBlpC50I3TdY9snLreDd
         7+Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HaI/Ls3X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc32.google.com (mail-oo1-xc32.google.com. [2607:f8b0:4864:20::c32])
        by gmr-mx.google.com with ESMTPS id h28si1037174qkl.1.2021.03.23.03.41.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 03:41:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) client-ip=2607:f8b0:4864:20::c32;
Received: by mail-oo1-xc32.google.com with SMTP id p2-20020a4aa8420000b02901bc7a7148c4so4815948oom.11
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 03:41:34 -0700 (PDT)
X-Received: by 2002:a05:6820:273:: with SMTP id c19mr3310170ooe.54.1616496093820;
 Tue, 23 Mar 2021 03:41:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210310104139.679618-1-elver@google.com> <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com> <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com> <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
In-Reply-To: <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 11:41:22 +0100
Message-ID: <CANpmjNO1mRBFBQ6Rij-6ojVPKkaB6JLHD2WOVxhQeqxsqit2-Q@mail.gmail.com>
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for remove_on_exec
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="HaI/Ls3X";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as
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

On Tue, 23 Mar 2021 at 11:32, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Mar 23, 2021 at 10:52:41AM +0100, Marco Elver wrote:
>
> > with efs->func==__perf_event_enable. I believe it's sufficient to add
> >
> >       mutex_lock(&parent_event->child_mutex);
> >       list_del_init(&event->child_list);
> >       mutex_unlock(&parent_event->child_mutex);
> >
> > right before removing from context. With the version I have now (below
> > for completeness), extended torture with the above test results in no
> > more warnings and the test also passes.
> >
>
> > +     list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
> > +             struct perf_event *parent_event = event->parent;
> > +
> > +             if (!event->attr.remove_on_exec)
> >                       continue;
> >
> > +             if (!is_kernel_event(event))
> > +                     perf_remove_from_owner(event);
> >
> > +             modified = true;
> > +
> > +             if (parent_event) {
> >                       /*
> > +                      * Remove event from parent, to avoid race where the
> > +                      * parent concurrently iterates through its children to
> > +                      * enable, disable, or otherwise modify an event.
> >                        */
> > +                     mutex_lock(&parent_event->child_mutex);
> > +                     list_del_init(&event->child_list);
> > +                     mutex_unlock(&parent_event->child_mutex);
> >               }
>
>                 ^^^ this, right?
>
> But that's something perf_event_exit_event() alread does. So then you're
> worried about the order of things.

Correct. We somehow need to prohibit the parent from doing an
event_function_call() while we potentially deactivate the context with
perf_remove_from_context().

> > +
> > +             perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
> > +             perf_event_exit_event(event, ctx, current, true);
> >       }
>
> perf_event_release_kernel() first does perf_remove_from_context() and
> then clears the child_list, and that makes sense because if we're there,
> there's no external access anymore, the filedesc is gone and nobody will
> be iterating child_list anymore.
>
> perf_event_exit_task_context() and perf_event_exit_event() OTOH seem to
> rely on ctx->task == TOMBSTONE to sabotage event_function_call() such
> that if anybody is iterating the child_list, it'll NOP out.
>
> But here we don't have neither, and thus need to worry about the order
> vs child_list iteration.
>
> I suppose we should stick sync_child_event() in there as well.
>
> And at that point there's very little value in still using
> perf_event_exit_event()... let me see if there's something to be done
> about that.

I don't mind dropping use of perf_event_exit_event() and open coding
all of this. That would also avoid modifying perf_event_exit_event().

But I leave it to you what you think is nicest.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO1mRBFBQ6Rij-6ojVPKkaB6JLHD2WOVxhQeqxsqit2-Q%40mail.gmail.com.
