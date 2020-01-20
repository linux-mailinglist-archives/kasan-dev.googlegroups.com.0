Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEU2S7YQKGQE6CKFILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BF29142F0D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 16:53:55 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id s6sf12922769iod.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 07:53:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579535634; cv=pass;
        d=google.com; s=arc-20160816;
        b=aA1Zarf24CEvIHGDG83NBgTlnykiKO7KMiFkutf4WTkw3ZUuE5JvfwT0RypxVs871y
         jOPVLW5G7cXnEuSm4UFoK0iVswJzo8xuGDgL8BpNXT66TJiU+db9HC2oDiONUq61W2eD
         A1twtFII76V175nJIr1S4xvlnNg/bLsyA/ifXd9ujbhll45j680Mls1eogVve7bi13LX
         YLMUajBRqT0Pm108iWP/ptsH25uE8BM0ewmn3dUpuDuaSbjgeHbb+JdSJc+/hnfEvFS2
         WpJt0uZFJm2KZmb5iYNCyVlunYwnvgna1vX6RiA7Tcq960EldGiz1YvQqeLKFojLlMYH
         xwvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zJTeX8bBUNYWujP1zQa+yomngBiaZ/GsnqRpDftsMKU=;
        b=Kn6rHWmIYS95pxwt+YXiS65TcpopVUQTk350lIxRG9roqjQnQh2DQpdyy7ifO/EBEs
         TkGLblic28ooH58KlGxGd9pP93nqXGyZnvlAu2ruzyByb0TGBmMS9Sevek6XICZjo+Iy
         ail+OGoyVnyV4Ki0WsXtQe7o7RRCmhd4R25A+yH6k+z0GtOpZbQKTcFZicV1MwYK4PPw
         4jjUJYKIS2AkFD2FykdDh3NlVqvpUps3fXNRRSbrdBvG63jWNSJZYt+9VNrVz5tQ8660
         G7vScr0HCEZBEhQEklQEqBRIgvfZUqhHL9Yy5Vy/egIYubFRxOpYwWYv7D5s7FNhmRwO
         /3Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gBOINAIW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJTeX8bBUNYWujP1zQa+yomngBiaZ/GsnqRpDftsMKU=;
        b=FsPczbTl2xQlaJncWpRpIpgdO3rmZ0tSmLf+Hketij/zGZ4hi9ZnktrzcoFyiP4sUN
         QBQiZcAgpqfZ7cJym10/sxzdFAfanUsLOy6/H+mfdy+xgjtcnze/ZVsxyYMIEmuqKNmp
         UGJiP5M9PqdugzO1y7aBlllX/iY3wkzWdiQW8oLdu+Q9PE6KrOlmOnu/xcaL0W70KnSe
         1R7fBuSmn8oz8LKWJvd6y66iO2GGSg1UuRExUYYF1fb3xi4mlrLrQGoGpIHo6nbuC0AC
         1f8LZQx0JVu8YTH1jADOd9qvCOfLC5TTkcm9kuVREr43hpWYXnowAWpR+PDxfMz/INYV
         4q6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJTeX8bBUNYWujP1zQa+yomngBiaZ/GsnqRpDftsMKU=;
        b=FXpxg/wt8qliuYQbvzFbH/MCKzAdPFypkstuXW6LCDkR2HFS57JK2iRs2fRq4oiuQn
         Aki9sMI8FUHZLjbd+zWXWoAuDeLDiMTLwHxk8q2bINF//YNlIxouNaaH+RR7G7tINEIA
         n8uO2aANnwG/0br5guyi7rFWReb36pyEzOBxorrtp2TmZj4JzrieN1UmLtINPrzH5+de
         PipvNmctwix0cWrShxF13teCkeOB7ZJgEdorNL9UKTYR2zkg8GPOtyJpU+EIc77+Tce7
         +ySQD8n0XDKovIMFrpwtOiim+qwi04sMx8ZjyBVxNMXjmjHtCbsah5g/djpCtwIsRwpz
         Lx/g==
X-Gm-Message-State: APjAAAVox0/TtnHYqtcBL+IclihDQpnWlkZ1MbRr2MWCiQIOIpKFSoaC
	vJgZPexTHeJQmfJ9TUDPpNI=
X-Google-Smtp-Source: APXvYqw2eNVqr6Nskg/DH+wxzjMsrpzktuYxysbIEqDJb0aaazWzBo2UEDV5DFgpdAAGQ7aIUekTTA==
X-Received: by 2002:a05:6e02:4cc:: with SMTP id f12mr10950301ils.90.1579535634217;
        Mon, 20 Jan 2020 07:53:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e8f:: with SMTP id t15ls5753652ilj.9.gmail; Mon, 20
 Jan 2020 07:53:53 -0800 (PST)
X-Received: by 2002:a92:60f:: with SMTP id x15mr11017708ilg.181.1579535633715;
        Mon, 20 Jan 2020 07:53:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579535633; cv=none;
        d=google.com; s=arc-20160816;
        b=yq9Z35fsxNrWidVm5ZhJ5W2cLaVZLlkTxhm94O//UhoFaaXRyHUm7EqAh79M7x3911
         PAOhGxjwodwu4XObi7hOzkwVzEbbhYsKOCP0LOFLnfjRR0IhJ0SimOQeqYsQ3LDTGE5W
         OVPedqR8SuNDEBOUxlKxFbcAUCIrSBdpi6MIZaHeI5bcIA/D3qXk6KpcrumvpwyfS4V8
         SxP2Gw9eKkKTTs931C2Mqma10OhkxZMTxmxcAgm78/K9Jfl9elb/g+yT6Gmc/aWi1ERs
         b8JwbVGccEjhR7hn3xmroHHDzHGHEgZkbUDm1qQw1lm55I9GsGFkLYtT+56PaTp0ix1i
         p7wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qiceCXFRSUBzYMQE2f4OjMMcZXcb2LTrkgPg5J2K4zg=;
        b=Fp+/bd85OpAE84YuWQ7nTN8eM8EWrL+nBwBArgds7MPEmbJjNaJdcIDKMUHV38Qtsf
         0sNhLusE/MFUWyTo+Ga0tIwgzIjsXLNw6M/uNf1pCKuJ5CXYpoEDj13/2xambxx+rLvD
         OFAweTcWgb8r5QV4pXNC/JH1kliX9jN6TIoxg5Bd50Sx7pZqefFGRj8TE7kyfYcAZ3xo
         gcvUYZIo4TV0Y5N7wgIxr2ME+SGGU8p1mmeTo2+K1Ue11Oz3vF8S1k0EaACMQhl4owzp
         Ebp2+pW6n1dcu23J50RJcClTnu7MKN5eFcOU5AUL+EW3iZa06Cgb2dz0HKFYJ9dh3C2o
         iQ+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gBOINAIW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id z20si1547330ill.5.2020.01.20.07.53.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 07:53:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 13so28837802oij.13
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 07:53:53 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr12680928oiz.155.1579535633036;
 Mon, 20 Jan 2020 07:53:53 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+ajkjCzv2adupX9oVKjNppn-AKsGkGqLMExwjHXG37Lxw@mail.gmail.com>
In-Reply-To: <CACT4Y+ajkjCzv2adupX9oVKjNppn-AKsGkGqLMExwjHXG37Lxw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 16:53:41 +0100
Message-ID: <CANpmjNN4XhU6WL35bHF2Wu76fJMXO5++uRBk0nh_s6BiRV9jdA@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gBOINAIW;       spf=pass
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

On Mon, 20 Jan 2020 at 15:34, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> >
> > This adds instrumented.h, which provides generic wrappers for memory
> > access instrumentation that the compiler cannot emit for various
> > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > future this will also include KMSAN instrumentation.
> >
> > Note that, copy_{to,from}_user require special instrumentation,
> > providing hooks before and after the access, since we may need to know
> > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > also relevant in future for KMSAN).
>
> How will KMSAN instrumentation look like?
>
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> >  1 file changed, 153 insertions(+)
> >  create mode 100644 include/linux/instrumented.h
> >
> > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > new file mode 100644
> > index 000000000000..9f83c8520223
> > --- /dev/null
> > +++ b/include/linux/instrumented.h
> > @@ -0,0 +1,153 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +/*
> > + * This header provides generic wrappers for memory access instrumentation that
> > + * the compiler cannot emit for: KASAN, KCSAN.
> > + */
> > +#ifndef _LINUX_INSTRUMENTED_H
> > +#define _LINUX_INSTRUMENTED_H
> > +
> > +#include <linux/compiler.h>
> > +#include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
> > +#include <linux/types.h>
> > +
> > +/**
> > + * instrument_read - instrument regular read access
> > + *
> > + * Instrument a regular read access. The instrumentation should be inserted
> > + * before the actual read happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_read(v, size);
> > +       kcsan_check_read(v, size);
> > +}
> > +
> > +/**
> > + * instrument_write - instrument regular write access
> > + *
> > + * Instrument a regular write access. The instrumentation should be inserted
> > + * before the actual write happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_write(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_write(v, size);
> > +       kcsan_check_write(v, size);
> > +}
> > +
> > +/**
> > + * instrument_atomic_read - instrument atomic read access
> > + *
> > + * Instrument an atomic read access. The instrumentation should be inserted
> > + * before the actual read happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_read(v, size);
> > +       kcsan_check_atomic_read(v, size);
> > +}
> > +
> > +/**
> > + * instrument_atomic_write - instrument atomic write access
> > + *
> > + * Instrument an atomic write access. The instrumentation should be inserted
> > + * before the actual write happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_write(v, size);
> > +       kcsan_check_atomic_write(v, size);
> > +}
> > +
> > +/**
> > + * instrument_copy_to_user_pre - instrument reads of copy_to_user
> > + *
> > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted before the accesses. At this point the
> > + * actual number of bytes accessed is not yet known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + */
> > +static __always_inline void
> > +instrument_copy_to_user_pre(const volatile void *src, size_t size)
> > +{
> > +       /* Check before, to warn before potential memory corruption. */
> > +       kasan_check_read(src, size);
> > +}
> > +
> > +/**
> > + * instrument_copy_to_user_post - instrument reads of copy_to_user
> > + *
> > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted after the accesses. At this point the
> > + * actual number of bytes accessed should be known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + * @left number of bytes left that were not copied
> > + */
> > +static __always_inline void
> > +instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
> > +{
> > +       /* Check after, to avoid false positive if memory was not accessed. */
> > +       kcsan_check_read(src, size - left);
>
> Why don't we check the full range?
> Kernel intending to copy something racy to user already looks like a
> bug to me, even if user-space has that page unmapped. User-space can
> always make the full range succeed. What am I missing?

Fair enough. I can move this into the pre-hooks in v2.

However, note that, that leaves us with a bunch of empty post-hooks in
the patch. While this will probably change when we get KMSAN, is it
reasonable to keep them empty for now?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN4XhU6WL35bHF2Wu76fJMXO5%2B%2BuRBk0nh_s6BiRV9jdA%40mail.gmail.com.
