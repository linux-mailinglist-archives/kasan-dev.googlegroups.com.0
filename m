Return-Path: <kasan-dev+bncBAABB3NSY7YQKGQEVUBBICI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CDE914D10E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 20:13:50 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id x127sf383900qkb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 11:13:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580325229; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJmb2zbJyJk1fv8oH8grItUOjC9OO02X9ZSiTCrRO3qLlftwfIMSITwVDDaHQHZsWI
         /iH11HI3MKH/KrFZKeSxvgFLW9JR4fpcurvi5gxqIOvfGr/Yj4cc5KOgElAkr/VAVMcq
         gJcaBm9pzkI0X0gLzLK7XP45d0O/TcRTr2In8pWQlhW4MpGjacBhYMNpiV6Es+hwjJe9
         R0YNUgzbqqJChrM2CD8RLOahZKyMplrAKPWT+6cCC4jZ6UD27XF0ezVD71iPqGHlvgHz
         stoxFo92hUWbZ8q9nDlXNbD121RIZg9CV6Lo82G9ApcU12/q5y+MZMbIpWfG27mSvgCu
         l63g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=pZdZ37+ROK8g+QRDmlHouTNhofzz374VR/JCQeabUG0=;
        b=kvvbEUlK18h4ogYewkkD0caUUYmpzxHZOL/JXTRSrLc1U5z73/kGEG7KfJJIYyVjJ+
         7Nwrgcfup0FazdDbHi+U3qWxnbX1pEuQdUH6DUJzG/SZCIhtIDGYggJ0phBG3HLSKEbB
         tU64hDu2kLQXkoMM49d2Dcq1KDS1qwaALWIhruBhGm6j/gBnoV6gBZ/Ob/RylI/MPEqJ
         aI/rThPRM0SApc6BV/Z9qRgnHKmoS13DTtjEGKKNz+T89yw8YIvBtULJox2292LQ3X9P
         lp6EoBjgTSVXXn05fseUeAERJgkuaOkYX5Kh3neqHw7fPXREFLnVfnOGZuCuS8iAEwX0
         u2dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0zQWbA7V;
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pZdZ37+ROK8g+QRDmlHouTNhofzz374VR/JCQeabUG0=;
        b=EtDjY2em5mbt+QDLR3XsckQqovWMfkM+RnSMhLnUKISJVs0EXzVjKJG9V7mbmdT8DG
         nYWbk/cRLve5fP00PK2Ax0mnEgejelHZp5Qa9G/w8QZOmHZDVzOx3XN4fTwKCKlIxuIw
         E8ZAV8RAF/b1FswYXGTZH5GYTCfVvL24SssKrmU3xot6HjixXIY/YaNc0sRjfg5rksrV
         7PH/Z23CFjcA1gXB8fU7piC7JIlJO0NTEndVbQ3WbVsQ6ZaS+AqQaRXD3OIP+LJrcVFT
         n94drqqOOhBCXfoAzd17fcLKAUa6JEme1Jw/+bSQvDeg8lDEbhhrpkTM+nxUYrgXXeqS
         WxJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pZdZ37+ROK8g+QRDmlHouTNhofzz374VR/JCQeabUG0=;
        b=sk7grpM6saHLfiYlwpVgtuXohc8VliW7WfbEDEuWPMfaXmP0lBd1/KeYg79tHnEEXr
         AnQHQxzHY/4kEhp9NPDu42PZsURdhxd45ikMMSiT4XG2QFdO2AN7XoYMuOIvWIRBTWer
         3RSXf2GbtF5GG9AVAcSwayP84BhvpEXtYWPbupYxHtgMhncM4hgtYyI9OZoHaorfur/i
         lKVpCdcQNrm8oDco9qkxTAL5q9/0VgJcd3sARdg4tAphxc0FRRzcpdAF5jrjJsJ2m7Ai
         l+DRWHeMdOSK+EZggI8hXEZqlFp3qe0oFI3v20Fn6CJT/LMrJyQ0D3+M6Xs1I3HrFRTY
         luRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWlcYK/IvdxM27FbpAG4+DkT/gKvtBLYIGpWvpMULYeSC78BH5d
	K7qRO4cSMwOaFbcm0KQkIZo=
X-Google-Smtp-Source: APXvYqzQUzLMdJkf/QBmzpHDKOfvz1ZwAjZCquZr2dcorL3wUcTJ9oUGQzT2QYg6QM800rrni26QDg==
X-Received: by 2002:a05:620a:1358:: with SMTP id c24mr1297634qkl.285.1580325229347;
        Wed, 29 Jan 2020 11:13:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f507:: with SMTP id l7ls480254qkk.0.gmail; Wed, 29 Jan
 2020 11:13:49 -0800 (PST)
X-Received: by 2002:a37:a558:: with SMTP id o85mr1308918qke.435.1580325229047;
        Wed, 29 Jan 2020 11:13:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580325229; cv=none;
        d=google.com; s=arc-20160816;
        b=GHFTYDTOcZzrCAuiFIN5Vlw2vK62YUmUjrjWowUuH9m8V6Mr4cpcHOUTw6NkVSfp8u
         V9XHGBvh/5aDznxJY+IeYcfQuSEhqVGYuFd6l7bc7vK8RFuSXWvDqQdMQwXcgOwkNcf/
         rgDlf33n50hMKY0a54jnO8n+QMzr7MI2GqqdbDST3PrUGTEBvU06WB33N4xAJ9GmKkW9
         tHAcPzVaPfHFgd7XVy35hYkaLwp5CFzCjoHWNOEYoWzS+vlyLjAexz1tzdsfHmGZ3APs
         LaG1AbxxmGFHDMEEKfNN0lO2DKuJw7PqTrjupqPb3Tmmct0SJcvUiBeMRrtfWOCY8dIn
         V9oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=0eOPfy4DrkPraPiOe/HVjWqrk7rNFafSm7glsZ1rliQ=;
        b=vnWOR50O8u84PUJvVBs0eJ1+EovM84TAhInZAQBFqvRcKJF3gyAuAOJ3AB8pStiscZ
         QFh7dc/sPbW6nmBrSZpTOBpR4sqdjn3cQ/vW9C6LyZtiCGnVezsp5q7phW6yrmqOfoqP
         H0NXLzsTIpfIgoNnkFNiWWBA4SgJ4Emx0spZyvF13rhN8afQH/K7SrscmJeb28K52j0s
         c5QFmMqC2khl+eoYZKsmXz88F7J1FDvkLvBqLjfCoCGEJglA9lwoYkGI1wjCbt7Uudm3
         gKKjtFd4qLRP7VSkvVo9ffoiSrUVJyFO7E3cfOZwXnk6Vo7OWMqn/uDNxeqZJdBuELV5
         fi/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0zQWbA7V;
       spf=pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l18si155290qtb.4.2020.01.29.11.13.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jan 2020 11:13:49 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C476B205F4;
	Wed, 29 Jan 2020 19:13:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 668C53521AEF; Wed, 29 Jan 2020 11:13:47 -0800 (PST)
Date: Wed, 29 Jan 2020 11:13:47 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Al Viro <viro@zeniv.linux.org.uk>, Daniel Axtens <dja@axtens.net>,
	Christophe Leroy <christophe.leroy@c-s.fr>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ingo Molnar <mingo@kernel.org>,
	Christian Brauner <christian.brauner@ubuntu.com>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Kees Cook <keescook@chromium.org>, cyphar@cyphar.com,
	linux-arch <linux-arch@vger.kernel.org>
Subject: Re: [PATCH v2 1/5] include/linux: Add instrumented.h infrastructure
Message-ID: <20200129191347.GA21972@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200121160512.70887-1-elver@google.com>
 <CACT4Y+aRk5=7UoPb9zmDm5XL9CcJDv9YnzndjXYtt+3FKd8maw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aRk5=7UoPb9zmDm5XL9CcJDv9YnzndjXYtt+3FKd8maw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=0zQWbA7V;       spf=pass
 (google.com: domain of srs0=gagg=3s=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Gagg=3S=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jan 24, 2020 at 12:22:56PM +0100, Dmitry Vyukov wrote:
> On Tue, Jan 21, 2020 at 5:05 PM 'Marco Elver' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > This adds instrumented.h, which provides generic wrappers for memory
> > access instrumentation that the compiler cannot emit for various
> > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > future this will also include KMSAN instrumentation.
> >
> > Note that, copy_{to,from}_user should use special instrumentation, since
> > we should be able to instrument both source and destination memory
> > accesses if both are kernel memory.
> >
> > The current patch only instruments the memory access where the address
> > is always in kernel space, however, both may in fact be kernel addresses
> > when a compat syscall passes an argument allocated in the kernel to a
> > real syscall. In a future change, both KASAN and KCSAN should check both
> > addresses in such cases, as well as KMSAN will make use of both
> > addresses. [It made more sense to provide the completed function
> > signature, rather than updating it and changing all locations again at a
> > later time.]
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

I have applied this and the other four with Dmitry's Reviewed-by.

Thank you all!

							Thanx, Paul

> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Acked-by: Alexander Potapenko <glider@google.com>
> > ---
> > v2:
> > * Simplify header, since we currently do not need pre/post user-copy
> >   distinction.
> > * Make instrument_copy_{to,from}_user function arguments match
> >   copy_{to,from}_user and update rationale in commit message.
> > ---
> >  include/linux/instrumented.h | 109 +++++++++++++++++++++++++++++++++++
> >  1 file changed, 109 insertions(+)
> >  create mode 100644 include/linux/instrumented.h
> >
> > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > new file mode 100644
> > index 000000000000..43e6ea591975
> > --- /dev/null
> > +++ b/include/linux/instrumented.h
> > @@ -0,0 +1,109 @@
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
> > + * instrument_copy_to_user - instrument reads of copy_to_user
> > + *
> > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > + * variants). The instrumentation must be inserted before the accesses.
> > + *
> > + * @to destination address
> > + * @from source address
> > + * @n number of bytes to copy
> > + */
> > +static __always_inline void
> > +instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
> > +{
> > +       kasan_check_read(from, n);
> > +       kcsan_check_read(from, n);
> > +}
> > +
> > +/**
> > + * instrument_copy_from_user - instrument writes of copy_from_user
> > + *
> > + * Instrument writes to kernel memory, that are due to copy_from_user (and
> > + * variants). The instrumentation should be inserted before the accesses.
> > + *
> > + * @to destination address
> > + * @from source address
> > + * @n number of bytes to copy
> > + */
> > +static __always_inline void
> > +instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
> > +{
> > +       kasan_check_write(to, n);
> > +       kcsan_check_write(to, n);
> > +}
> > +
> > +#endif /* _LINUX_INSTRUMENTED_H */
> > --
> > 2.25.0.341.g760bfbb309-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-1-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129191347.GA21972%40paulmck-ThinkPad-P72.
