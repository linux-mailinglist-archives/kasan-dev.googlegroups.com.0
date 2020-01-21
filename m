Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWWGTTYQKGQEZULD3AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D20A1441CD
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:14:19 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id v188sf1318298vkf.10
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579623258; cv=pass;
        d=google.com; s=arc-20160816;
        b=bEXwGET7NnP8wbJIIc9/z1cLtHYKZYs5hLoySHVAhSkgafTqe/nU/kQFkT54gFM6t+
         EwSL5UWaVb/PWNqyxh29T5qBezpZkpGW7RITwGygxIixbImCsu5md9YzuUIR84+MELIe
         tmj4JoXqXPSJNWiBdXojUTp9ZO22LOjw2j1T54L5+GpmXhLB9dtXfmFHXffnw9QL21tK
         6QINmiOLnLDSGGU+Ew6/rdSf6mnrpaFeooKmIafdrnwKcEM+sUjrZqGwX7MUt1AiY9FY
         Imqp8io5lcc+CpcHpunYWCV2+gCoJpc/nKpUHCwRzabLRG7mib23IJjiRkU0L4syaeCb
         NLmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oBdnBh7Ju5pdSL6Em5gA3cxfDUk/X07122Ll0XVWrsU=;
        b=ncweRB5TIvj4FfiHiSqw37xtvhOIgcEzKD/jUqNOBBuq9kAKPb4xwywqlgNWskVAoY
         A4q7a663q+445xCj9P35E8BpKkIdcAruGMxPhvDkYhDSJOeswIU1ELdEmxX/SMoXn/gn
         hEsku0oHptGETZw+vrnkKTl82BMBru1pwPa3CsGt3ML/yPY2ySP74e3FoYSEAbbukudZ
         6+vmFMi9LG8cEz5DagOu90Du/qqLXy1I3AT5Xh2e1Jx7ndBTzz3xmnfepfkv9PaIr1ON
         dKg7/zKgPl5icUeSc9NmnRKdmnLAfZnQF/iW2lXK1TA+Pd3/4/ZhI8IFvxzMTVYZYzkX
         XgGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="D/Pop3pi";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBdnBh7Ju5pdSL6Em5gA3cxfDUk/X07122Ll0XVWrsU=;
        b=q3FYfVYSMwp1m7tAx10ERjQ0OmKdN+MPOs83ZJmvTfnOs9NQQf+U6OjxQ0qqOCoxGA
         cyROt5+Uj1DVBh4Gsmp8varcB78Iip0+/YJLCLmjmyavnn7lgNW0HI3c86SR+As20VsB
         eXzscTuFe9IDjBJy47tbi7fCIm4HBZtHn4BsRgxueJewc2daURVcIIqt7h66XDAbn4yD
         g9uP2dzGLS6FRFEjoQF4saCacJlfofmvNBtq1h0EHpXqO/s74QaaSAWWFtCsuTjbMqUr
         rbjCsUThJAtAEw4nZSCTYtVFPDvTUVrYX2OBh7lJqz6nS1W+8dAJL4TFjjazlDyCyrpW
         pFHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBdnBh7Ju5pdSL6Em5gA3cxfDUk/X07122Ll0XVWrsU=;
        b=Lsy6NgJ9SzZHVB3x5xjKzBSP1CDuXAAfLHg0TL0aHOnN/OvTZn3/tlisK+pi6hiFwl
         kJjiAII+dsgkNniSw3tXiWFfEP4ZN1DGhyp/1jU1HGgUarvm4f7CFh5UeMQ5YVUbyGXC
         aBYZKulNtio8ZwIcVbNsb2YL9n/X9lYjNpSWnFq/EnUpeePw+SI9XYqBX6Z1bWFPGIdd
         c2+k4UHVq8aQuleM/CA/sODKkAx5B+poVmF5dosE78jmv0OrDIoKmMso61N1wgVwVfqk
         LFeW77v1M5vOmcGlBLmblTi9BN+8UEsHYc0MiCLISpc0PV5TjWLuDMqFiuxNmGNIjZCd
         F8gQ==
X-Gm-Message-State: APjAAAXF1UusEEN9/4dSFxFhEtsOqx0Qgzaf7QXpVPdY91lrNgS3PqwE
	BFGrGjLbw8xVnr8xmWrSQ7s=
X-Google-Smtp-Source: APXvYqx3LBOcjWB38JgICqWiS419znAHiSV9FaG70CtcjAavG7jpKnA2DWgaTtJyrunqONpW3ogvbQ==
X-Received: by 2002:a67:3145:: with SMTP id x66mr3323502vsx.157.1579623258163;
        Tue, 21 Jan 2020 08:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:c1c7:: with SMTP id r190ls1530422vkf.11.gmail; Tue, 21
 Jan 2020 08:14:17 -0800 (PST)
X-Received: by 2002:a1f:7cc2:: with SMTP id x185mr3298264vkc.1.1579623257669;
        Tue, 21 Jan 2020 08:14:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579623257; cv=none;
        d=google.com; s=arc-20160816;
        b=rqtHAtJGe8lART0hRRXi3YqC2z+Gfkz0/lqr9/s2zV6I4n/wlhdVoYn5vkNrP4WWCd
         xjGbm06bqmt5xGf9BM4rPZHUvQpqTj9TTViD+0He9dFIPcqvwxvLbedMfzpBSLXgb7qW
         vh3rYXOf98LJCWExzRxHJJrYkPkqDw2GxkfoCgtTpgNIb6r5OzDx2/7m4jFzKK7hbvLY
         iIVIcNc3a/zXBg/BSAueo+ddUHGrLlMqcT6dG8UWYVPoxT5HkuGXS+fNNH1nC/1WFlco
         BSbbIgQKBV0EKRt5Jk78WUQyv0m22gsanyGJ+3b82MrTogndnY+GSooybG8MsocuqTIK
         Z1NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IXf7v5u4QW5b0oUhqlEbSYsuPaK7kUXwuaQl8tSfrCE=;
        b=aAqtnF6bvvTCw7bf5fUjbN4QyzATCaSrS48ONIz6KAP+3NWnKVe1D2oRUDK4HmiyWr
         fChgH43cka+SeUGGV24dYCbKiiwnxjM2+tQMs4zRG4eXJBwGHaZzODouQ9s3TKwt2Hea
         8s4jsfVqhbnK0OxsW7ALNPtOFgtqd7Vc4ZQiGJSrPYKLTeIe8W0uvOZp9kSNr1xVUdAi
         ZvYCnBfYLltZyAsnx/WHUYXPT4hbJCO1bt7xTsusYYpTuIomUj9PNIDJHZZtcWC8aL71
         WWQhsfVcTSSQIk7mGJShkdTKBGotnRBlwYsOO5R7IuBqWsJMoBd0B8QwsNibtM+72hRb
         gQsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="D/Pop3pi";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id o19si1721186vka.4.2020.01.21.08.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:14:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id z64so3062583oia.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:14:17 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr3379090oiz.155.1579623256839;
 Tue, 21 Jan 2020 08:14:16 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+bjAn0g980ZCxCn4MkgCsg7KrA69CExCeJZ63eRON5fXw@mail.gmail.com>
In-Reply-To: <CACT4Y+bjAn0g980ZCxCn4MkgCsg7KrA69CExCeJZ63eRON5fXw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jan 2020 17:14:05 +0100
Message-ID: <CANpmjNOQPwn-+iL38RkfsJ6tWj8pZyB_dfh8174FmaYz5tfBTA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="D/Pop3pi";       spf=pass
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

On Tue, 21 Jan 2020 at 14:01, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:45 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> > >
> > > This adds instrumented.h, which provides generic wrappers for memory
> > > access instrumentation that the compiler cannot emit for various
> > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > future this will also include KMSAN instrumentation.
> > >
> > > Note that, copy_{to,from}_user require special instrumentation,
> > > providing hooks before and after the access, since we may need to know
> > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > also relevant in future for KMSAN).
> > >
> > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > >  1 file changed, 153 insertions(+)
> > >  create mode 100644 include/linux/instrumented.h
> > >
> > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > new file mode 100644
> > > index 000000000000..9f83c8520223
> > > --- /dev/null
> > > +++ b/include/linux/instrumented.h
> > > @@ -0,0 +1,153 @@
> > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > +
> > > +/*
> > > + * This header provides generic wrappers for memory access instrumentation that
> > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > + */
> > > +#ifndef _LINUX_INSTRUMENTED_H
> > > +#define _LINUX_INSTRUMENTED_H
> > > +
> > > +#include <linux/compiler.h>
> > > +#include <linux/kasan-checks.h>
> > > +#include <linux/kcsan-checks.h>
> > > +#include <linux/types.h>
> > > +
> > > +/**
> > > + * instrument_read - instrument regular read access
> > > + *
> > > + * Instrument a regular read access. The instrumentation should be inserted
> > > + * before the actual read happens.
> > > + *
> > > + * @ptr address of access
> > > + * @size size of access
> > > + */
> >
> > Based on offline discussion, that's what we add for KMSAN:
> >
> > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > +{
> > > +       kasan_check_read(v, size);
> > > +       kcsan_check_read(v, size);
> >
> > KMSAN: nothing
> >
> > > +}
> > > +
> > > +/**
> > > + * instrument_write - instrument regular write access
> > > + *
> > > + * Instrument a regular write access. The instrumentation should be inserted
> > > + * before the actual write happens.
> > > + *
> > > + * @ptr address of access
> > > + * @size size of access
> > > + */
> > > +static __always_inline void instrument_write(const volatile void *v, size_t size)
> > > +{
> > > +       kasan_check_write(v, size);
> > > +       kcsan_check_write(v, size);
> >
> > KMSAN: nothing
> >
> > > +}
> > > +
> > > +/**
> > > + * instrument_atomic_read - instrument atomic read access
> > > + *
> > > + * Instrument an atomic read access. The instrumentation should be inserted
> > > + * before the actual read happens.
> > > + *
> > > + * @ptr address of access
> > > + * @size size of access
> > > + */
> > > +static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
> > > +{
> > > +       kasan_check_read(v, size);
> > > +       kcsan_check_atomic_read(v, size);
> >
> > KMSAN: nothing
> >
> > > +}
> > > +
> > > +/**
> > > + * instrument_atomic_write - instrument atomic write access
> > > + *
> > > + * Instrument an atomic write access. The instrumentation should be inserted
> > > + * before the actual write happens.
> > > + *
> > > + * @ptr address of access
> > > + * @size size of access
> > > + */
> > > +static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
> > > +{
> > > +       kasan_check_write(v, size);
> > > +       kcsan_check_atomic_write(v, size);
> >
> > KMSAN: nothing
> >
> > > +}
> > > +
> > > +/**
> > > + * instrument_copy_to_user_pre - instrument reads of copy_to_user
> > > + *
> > > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > > + * variants).
> > > + *
> > > + * The instrumentation must be inserted before the accesses. At this point the
> > > + * actual number of bytes accessed is not yet known.
> > > + *
> > > + * @dst destination address
> > > + * @size maximum access size
> > > + */
> > > +static __always_inline void
> > > +instrument_copy_to_user_pre(const volatile void *src, size_t size)
> > > +{
> > > +       /* Check before, to warn before potential memory corruption. */
> > > +       kasan_check_read(src, size);
> >
> > KMSAN: check that (src,size) is initialized
> >
> > > +}
> > > +
> > > +/**
> > > + * instrument_copy_to_user_post - instrument reads of copy_to_user
> > > + *
> > > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > > + * variants).
> > > + *
> > > + * The instrumentation must be inserted after the accesses. At this point the
> > > + * actual number of bytes accessed should be known.
> > > + *
> > > + * @dst destination address
> > > + * @size maximum access size
> > > + * @left number of bytes left that were not copied
> > > + */
> > > +static __always_inline void
> > > +instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
> > > +{
> > > +       /* Check after, to avoid false positive if memory was not accessed. */
> > > +       kcsan_check_read(src, size - left);
> >
> > KMSAN: nothing
>
> One detail I noticed for KMSAN is that kmsan_copy_to_user has a
> special case when @to address is in kernel-space (compat syscalls
> doing tricky things), in that case it only copies metadata. We can't
> handle this with existing annotations.
>
>
>  * actually copied to ensure there was no information leak. If @to belongs to
>  * the kernel space (which is possible for compat syscalls), KMSAN just copies
>  * the metadata.
>  */
> void kmsan_copy_to_user(const void *to, const void *from, size_t
> to_copy, size_t left);

Sent v2: http://lkml.kernel.org/r/20200121160512.70887-1-elver@google.com
I hope it'll satisfy our various constraints for now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOQPwn-%2BiL38RkfsJ6tWj8pZyB_dfh8174FmaYz5tfBTA%40mail.gmail.com.
