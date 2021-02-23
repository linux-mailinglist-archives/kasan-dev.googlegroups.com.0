Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75V2SAQMGQEUFHC4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C2EF322D2C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 16:10:56 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id e12sf12114768ioc.23
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 07:10:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614093055; cv=pass;
        d=google.com; s=arc-20160816;
        b=oaTHT5oUM8jg9V9nV+QVCyEbcxUeXQid7q3FTCVhTz+AwqNjQwWdmCzaPBGj7x1uBG
         T++M4Q98H684EO1DL9IpXDHsdQNsthxBB+zcGGryXdlCQJ/dylfGmuA4upbCs6cazf1U
         ics0LgrIoQXNEGm36NlJbaT7qmOTKrYIvzo3nStIlEa0LZbk2ZYm2v+gT4pQhjPTFnfz
         JNZfSXUkZk4dS0YwAJ+m4QRAmNbHJktkFk8OWFRk8vcxo0U77D7A+KnsnZeF+8L6nV1Z
         8UAYPTPBYjulHj6wiEB2W4XnBbdv5ndplFGJ3Gijrjz4znU+T72EzDNWPKyDji2M8TlF
         8p/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DOiXknBWUHW/29i6mRVjgNmED20pKWsyk+ZRHQj2msE=;
        b=HZpB+whd4hS9vHad/66EN3xXYUY74sp/Qad2uiEsKRo7UTekfv4NSAr+Ya2EDrT2wQ
         LpoPHywa5Y/kAM9h5zH1g0lFAXHnYjn55UpchSwsHK8z72bsyFqMFPROT3AIEQ6UpA/0
         LGHoVPw5BnjTsSv7kFGXyJG5QAjnvADvCVmPhMsmQnVYHeIFPYaKqAQNNquBy+6L+882
         SNVQWu+Pa3ctlJcioBBd48IaShOnLuQfmtzJ+/dpFXIajkel1YsM8y8k/YkKDBJyY5Uj
         dKIurhTaPcmWG94AJPKs3LInSTgE8wQuYqmEV+mFbWBTqCWj0PqTuE6v2qOW+8S5gx6G
         fjmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jvghciHC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DOiXknBWUHW/29i6mRVjgNmED20pKWsyk+ZRHQj2msE=;
        b=kfAahgTbrqb3qD9BdYXEUXgYkSgKnxO6EveFmMotY67mLGTYjffbxp2kit0rCeuxXk
         aadnJSOIlSmnqwf4UYO/RiG+S2r/Jto//JAucgRDKwomYZnzzKSqYeJ990+bh5h2a0BZ
         GNedhh7zYnAhzff263bW7oi+Xgl5NHTrdjaIakVHWqzk0UQRN3zp56D50K3fAWUsLpjX
         x9KY3yOUCsh82BQ4NKaTMXCNC1phjqfeq4PmIvQc58y8DUNYeRb/Qb7/IudN5JDmxwwU
         FTe0SW88Cg105bDczz7LNgYs0sAtFfgQdHQifJqDCxO3jHn0hQ/qqmY1WXsiD3kQkJvy
         0ZIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DOiXknBWUHW/29i6mRVjgNmED20pKWsyk+ZRHQj2msE=;
        b=ui/t9KfiIy085879XAbCEP9Z0vJgdWgXHZh14+ECal8PPrd5hzHWql7dWPCd0MF2Mr
         zitv7R5tRyxUnnc6v6tq82N7WKX2bjmVZHKOKm+Li7fOD4dwv3O0pIwKhP+uQ37ykcui
         f6KoqnUjAZKBm3NJBx7rK/0nbOG7XhEYH4v3vhlvz6ZyolBWDSK5jP0VZ51Ma/zTb6V1
         n5hhD+cC+z3WaDIZlvkJKf5YUwWjD2MEP029U7z+w++MSLtVjnHApCkvaTnQuxAJYdlu
         lUsZGQtCqUo4jXgnCG1O8Js6xd+D0R2DhvXr1IxHW3hWH37LtsmNVLqEyg+HnNo3SIBa
         FPvg==
X-Gm-Message-State: AOAM532rXrHu9tSiIz7xwLhtcIaaIumbw6rrhFKYUw0YBwZXrusyj22T
	31NaAAsV/JBy3vdPUvLEz2k=
X-Google-Smtp-Source: ABdhPJxMVNYTlOl/hAWET+PowNrvKSsY9kIu6HJHixiQXT1aOvAHYOAOO2Z+rsEVD7X0iO4ol+SK1A==
X-Received: by 2002:a92:2c08:: with SMTP id t8mr19333025ile.72.1614093055397;
        Tue, 23 Feb 2021 07:10:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1032:: with SMTP id o18ls5267517ilj.5.gmail; Tue,
 23 Feb 2021 07:10:55 -0800 (PST)
X-Received: by 2002:a92:c607:: with SMTP id p7mr13127643ilm.148.1614093054888;
        Tue, 23 Feb 2021 07:10:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614093054; cv=none;
        d=google.com; s=arc-20160816;
        b=LoNpvpR6Hgl2dxWK2KbfWEtAhfUXCupmOpDSlrZ2zRwkCAGn9jaFsZCT0T3f4LjrPn
         tBeG2uNe7INYYCkBAY+6UKtMQBH5SpF1p5GJ1Xdg7zq8mvICE6SkIZGpkGM/aYzMNFB4
         zMKOYWGWcIXXKq+H5dPyd6sRCX38PjN1Ya5O+WwZVm4qW8NER8YU8A/waTdIRUoy20XA
         kX+D8XtnGw6SNp3IpUpA9ghCwnUHUuezeRMSSgh+TB79PYAyBExjUL5c5jobJnRuSaFy
         Vjw3r0LOGlfA0MpanHtdNmR05pK4t3wQlpyNbbNCVQk6F2X8Dv0yYRRudAW8tn4pZNU2
         K62A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TAvFxow2tg8sBdIKol2WVfke34KD7HcGzBLgosBBq0o=;
        b=GhJsy132Q49ubaN2qNb43x7rZ9EHM+PbGhxHSdsO1/Bn4NMdOu6fFUS6TMZ+wq8zQy
         l6ErSypFPGfzBp+0Y7D9RFAqAROJizL7KDX5ZKqE7QCV6fxCgEWZ66jE7bEbP7Ihb3Mx
         7j3aXMKsmH1ZDnCBlmZxqbmPE+gmleeD/ScV95cY6dItoyXTBFC5C4RzIUcipgNVdeUS
         pNMJrfqdHkrWTz3XrSyGLZVnP8uPHRs0wgx0A8Dp3uDp8f/+DLWJVLraMNxsyggZoDnv
         AXojOZYzxm3BEC5Kylv2D5TpUAGEVz+hK3fHBo8G7OrM/rOB+oSk6pczZrxdvvgnWceb
         gX7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jvghciHC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id d2si1176602ila.5.2021.02.23.07.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 07:10:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id d9so1697800ote.12
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 07:10:54 -0800 (PST)
X-Received: by 2002:a9d:5a05:: with SMTP id v5mr21074835oth.17.1614093054391;
 Tue, 23 Feb 2021 07:10:54 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-5-elver@google.com>
 <CACT4Y+aq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ@mail.gmail.com>
In-Reply-To: <CACT4Y+aq6voiAEfs0d5Vd9trumVbnQhv-PHYfns2LefijmfyoQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 16:10:42 +0100
Message-ID: <CANpmjNP1wQvG0SNPP2L9QO=natf0XU8HXj-r2_-U4QZxtr-dVA@mail.gmail.com>
Subject: Re: [PATCH RFC 4/4] perf/core: Add breakpoint information to siginfo
 on SIGTRAP
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jvghciHC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Tue, 23 Feb 2021 at 16:01, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Feb 23, 2021 at 3:34 PM Marco Elver <elver@google.com> wrote:
> >
> > Encode information from breakpoint attributes into siginfo_t, which
> > helps disambiguate which breakpoint fired.
> >
> > Note, providing the event fd may be unreliable, since the event may have
> > been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> > triggering and the signal being delivered to user space.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  kernel/events/core.c | 11 +++++++++++
> >  1 file changed, 11 insertions(+)
> >
> > diff --git a/kernel/events/core.c b/kernel/events/core.c
> > index 8718763045fd..d7908322d796 100644
> > --- a/kernel/events/core.c
> > +++ b/kernel/events/core.c
> > @@ -6296,6 +6296,17 @@ static void perf_sigtrap(struct perf_event *event)
> >         info.si_signo = SIGTRAP;
> >         info.si_code = TRAP_PERF;
> >         info.si_errno = event->attr.type;
> > +
> > +       switch (event->attr.type) {
> > +       case PERF_TYPE_BREAKPOINT:
> > +               info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> > +               info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
> > +               break;
> > +       default:
> > +               /* No additional info set. */
>
> Should we prohibit using attr.sigtrap for !PERF_TYPE_BREAKPOINT if we
> don't know what info to pass yet?

I don't think it's necessary. This way, by default we get support for
other perf events. If user space observes si_perf==0, then there's no
information available. That would require that any event type that
sets si_perf in future, must ensure that it sets si_perf!=0.

I can add a comment to document the requirement here (and user space
facing documentation should get a copy of how the info is encoded,
too).

Alternatively, we could set si_errno to 0 if no info is available, at
the cost of losing the type information for events not explicitly
listed here.

What do you prefer?

> > +               break;
> > +       }
> > +
> >         force_sig_info(&info);
> >  }
> >
> > --
> > 2.30.0.617.g56c4b15f3c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP1wQvG0SNPP2L9QO%3Dnatf0XU8HXj-r2_-U4QZxtr-dVA%40mail.gmail.com.
