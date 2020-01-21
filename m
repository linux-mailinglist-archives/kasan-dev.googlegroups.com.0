Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44PTPYQKGQEPYJVZVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id EEFCB1439BA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 10:44:20 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id k24sf295926uag.18
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 01:44:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579599860; cv=pass;
        d=google.com; s=arc-20160816;
        b=myfp2EvCytrMI0dt4OlMBwjFAps9QMSGR71TNZp+L4QrY+qMi0N7D2PbXdGiL43yVv
         XTsJQkG3tSK4+ppkIsIOeXW7iMm6inQxdWT/kggum7VjL+HiwtVWp15oocM6kt+/Is2S
         RI9RenZdM7cETVv2dKtfu2qwH4FHpFGXinxPFPkZ2tv/Ny40tsIeRdYKUXIBmCgBBLK0
         9f1uKT4M0/xNbTLh2dTHlNExszzuu/Ym9Cq/2iiHTsDsCqfAfhUwxrJx1PDrhHsmAUMB
         IBtgRzwOsq6/8hCj4HK9U+816Jhc4pj19JNxE2w+MnA0P77ddoDStgxWMYzAGsC6T8na
         K2mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tL6FYQY3JzdgSxTgQzPPtlY9HzgNKYuWMXbaz3Jp+/A=;
        b=DsXTpr2Gzq1y7djvzQvS/uDwoE2BAaeJxf3ErCl85j0XSs++HrBdiMfLsyFVQkNGBy
         csy4faYAvpie7/B2JuWafJdLJAvBM4z/QC8TtdY+D+eFGFC0R2cg8GNcSE5JYi06T6m3
         THzbVAyBQ837Ry6YcVP/1bbaTzxhbjaspUHsPgtVzO57z0t7g7JoHc8hy5lepiSXI42k
         9FL32DtH5CrKMqwHdnN2hNQWRKZ49H/4Hy4D7Vywc+zGou3o4Fn3IedITYMnuwVNgsOI
         1JifpNSicGR5m5JOuQVekrhksULNbE1bepWSlXqKSwf75qvGPs/mFT3lC2CfmXz9gaSD
         xRrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TJpn6ykw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tL6FYQY3JzdgSxTgQzPPtlY9HzgNKYuWMXbaz3Jp+/A=;
        b=m16aN4Gux916rjCl2+lCsh6joSSIZmP4xpXlerv4yKqvdt2U/bLgxlBrEp6OiWGGGq
         S5vmxifAkTLONyzRztzVge0FnT9Hs2+AEETZig+68pKi3U6llo8GO1FZLURhf1J6U+M4
         t8HzFv8kBzF5leo63echsC2AU7x52WyapPe3sEEtBmeUDH5b2qZq/G6t3236NgRS88tR
         GX2zYqUo3x5Q0jZQzB8TnWWLNBK6DegI2z7N03pSLwg+tUTnUl4XrDt80xSuLTUhQ/hU
         v9FohDLwSKLwu1f4knPHqba2Ufc5SyiHBEzDkZ9jDRehzpbfcl16ReQtAxfq6RM7Bxa1
         JXOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tL6FYQY3JzdgSxTgQzPPtlY9HzgNKYuWMXbaz3Jp+/A=;
        b=HOQEoISJRbScGNOSUQdVVxUJmdG1sMGzTk9ag277be/6kqK93bxi+ZAl/o7x4pP4Pd
         rZyun/77JRgABubP87eWetTZ8guY4VS4JboAOg/tL0gsJdApxaM/tUy4amtyTKMAJE8n
         H6uhjBmlB4cXLj/ZqLsFJ/dGhKPTjkPK9hItB6z2pBQIWUxvkTSSYLjpPXNtiEBihyXK
         jxqphAkEEuibx++dqEAqtev7/UCHS/4+vtCVFXFCEdvLnRmY/r3M+w862YbbRAYIiW6a
         feyt4gJj68XfQ0FZEHVUmbzgSQucypOaS+JcE4dzjmTOryKzS29NSl8x/9PsNJ0MJJmg
         uBuw==
X-Gm-Message-State: APjAAAWtrlgntCSwmVohOxef7dXzpZpeeKmqAfbP0XPjJ2dIopZzBPfa
	JExAsj+7OyJJkEOYfGZ/ibE=
X-Google-Smtp-Source: APXvYqyS/pIo/sXwn00wlQGk2K7RLE2Xzcor47mO8faiVCMmHRbgO4IOCSZretJvMeQGPV0ibdPCtA==
X-Received: by 2002:ab0:1c0e:: with SMTP id a14mr2263020uaj.141.1579599859736;
        Tue, 21 Jan 2020 01:44:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b304:: with SMTP id a4ls3131338vsm.13.gmail; Tue, 21 Jan
 2020 01:44:19 -0800 (PST)
X-Received: by 2002:a67:e954:: with SMTP id p20mr2054477vso.3.1579599859304;
        Tue, 21 Jan 2020 01:44:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579599859; cv=none;
        d=google.com; s=arc-20160816;
        b=zSZe/uCsi2lWTCw4G/zm8wXAxHALoJ4mChkpGzGEjUs68kgrROzj9EYpGh20tNn+33
         ZK29x0oalRnB0T/aybDelJJhciZwjOyIPnf4KgOFFacmQWzlo7eLNPidSRiMwOxqYkht
         rgWnZ1kC33jvHOZquBKDwJY3zxsIcd0si7hCWnaurjM7cngJ+Ijc8mICRdPivG4Nlpfq
         4kx1gMaxxkTtLlzkTN2Stb6l7grwCLGAPsJ6RCGENAXwy0leNoq+AsAwhBKDEUvLweTw
         kUDctlT8rKLlWLJtBteWRZTGpZ+QkiDMENUHXW30f/r2GGmgDIU5wsxEpq/D3n5gw1ma
         2Nyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HBcIIfisjpHPiUGpBDs8d1gs27EtkgCyjibCW2LJEj4=;
        b=dmSSJvGMZ7Esl0dxI0TwGyVNUdXp0n/QQZXn/JPk9zcjT3J4PnIpDqIDL3UFFd0fLy
         Gs3ZSZ1+viRzqnC/d7PD00ymaG88oOWBt9HYnRmKDy4Zd8P3gqittjTFdQsJHy7q7ycJ
         eDsJBw/TjnaopAVM87YWsxyX92QyLjbGTrwJLEvEH9Ti5/fSq4CKu7T8R8JLY0Swv3Ci
         hKuxXgYl/VsYVjXFkaXmYkIvB27kuTGVgOfcKekquyuXC3HY4Skmb4YUErEa+dsk9Y6/
         e9zMgbXgreNm0Nycqr5JdZP/wtPjHLQM1KHwK5e3QegRQYrrX6ftGWQ+N1v9iFKQE3Y7
         VLkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TJpn6ykw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k26si1652449uao.0.2020.01.21.01.44.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 01:44:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id 13so1929475oij.13
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 01:44:19 -0800 (PST)
X-Received: by 2002:aca:b183:: with SMTP id a125mr2373497oif.83.1579599858446;
 Tue, 21 Jan 2020 01:44:18 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
 <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
 <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com>
 <CACT4Y+bD3cNxfaWOuhHz338MoVoaHpw-E8+b7v6mo_ir2KD46Q@mail.gmail.com>
 <CANpmjNN-8CLN9v7MehNUXy=iEXOfFHwpAUEPivGM573EQqmCZw@mail.gmail.com> <CACT4Y+bgLy=AiCdLauBaSi_Q1gQsqQ08hr1-ipz60k+WFdmiuA@mail.gmail.com>
In-Reply-To: <CACT4Y+bgLy=AiCdLauBaSi_Q1gQsqQ08hr1-ipz60k+WFdmiuA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jan 2020 10:44:06 +0100
Message-ID: <CANpmjNPCGM9V++Vq_UtLJoLbzLdVfgJg0kWAkK=E+829may9Uw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=TJpn6ykw;       spf=pass
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

On Mon, 20 Jan 2020 at 17:39, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 5:25 PM Marco Elver <elver@google.com> wrote:
> > > > > > > > This adds instrumented.h, which provides generic wrappers for memory
> > > > > > > > access instrumentation that the compiler cannot emit for various
> > > > > > > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > > > > > > future this will also include KMSAN instrumentation.
> > > > > > > >
> > > > > > > > Note that, copy_{to,from}_user require special instrumentation,
> > > > > > > > providing hooks before and after the access, since we may need to know
> > > > > > > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > > > > > > also relevant in future for KMSAN).
> > > > > > > >
> > > > > > > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > > > ---
> > > > > > > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > > > > > > >  1 file changed, 153 insertions(+)
> > > > > > > >  create mode 100644 include/linux/instrumented.h
> > > > > > > >
> > > > > > > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > > > > > > new file mode 100644
> > > > > > > > index 000000000000..9f83c8520223
> > > > > > > > --- /dev/null
> > > > > > > > +++ b/include/linux/instrumented.h
> > > > > > > > @@ -0,0 +1,153 @@
> > > > > > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > > > > > +
> > > > > > > > +/*
> > > > > > > > + * This header provides generic wrappers for memory access instrumentation that
> > > > > > > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > > > > > > + */
> > > > > > > > +#ifndef _LINUX_INSTRUMENTED_H
> > > > > > > > +#define _LINUX_INSTRUMENTED_H
> > > > > > > > +
> > > > > > > > +#include <linux/compiler.h>
> > > > > > > > +#include <linux/kasan-checks.h>
> > > > > > > > +#include <linux/kcsan-checks.h>
> > > > > > > > +#include <linux/types.h>
> > > > > > > > +
> > > > > > > > +/**
> > > > > > > > + * instrument_read - instrument regular read access
> > > > > > > > + *
> > > > > > > > + * Instrument a regular read access. The instrumentation should be inserted
> > > > > > > > + * before the actual read happens.
> > > > > > > > + *
> > > > > > > > + * @ptr address of access
> > > > > > > > + * @size size of access
> > > > > > > > + */
> > > > > > >
> > > > > > > Based on offline discussion, that's what we add for KMSAN:
> > > > > > >
> > > > > > > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > > > > > > +{
> > > > > > > > +       kasan_check_read(v, size);
> > > > > > > > +       kcsan_check_read(v, size);
> > > > > > >
> > > > > > > KMSAN: nothing
> > > > > >
> > > > > > KMSAN also has instrumentation in
> > > > > > copy_to_user_page/copy_from_user_page. Do we need to do anything for
> > > > > > KASAN/KCSAN for these functions?
> > > >
> > > > copy_to_user_page/copy_from_user_page can be instrumented with
> > > > instrument_copy_{to,from}_user_. I prefer keeping this series with no
> > > > functional change intended for KASAN at least.
> > > >
> > > > > There is also copy_user_highpage.
> > > > >
> > > > > And ioread/write8/16/32_rep: do we need any instrumentation there. It
> > > > > seems we want both KSAN and KCSAN too. One may argue that KCSAN
> > > > > instrumentation there is to super critical at this point, but KASAN
> > > > > instrumentation is important, if anything to prevent silent memory
> > > > > corruptions. How do we instrument there? I don't see how it maps to
> > > > > any of the existing instrumentation functions.
> > > >
> > > > These should be able to use the regular instrument_{read,write}. I
> > > > prefer keeping this series with no functional change intended for
> > > > KASAN at least.
> > >
> > > instrument_{read,write} will not contain any KMSAN instrumentation,
> > > which means we will effectively remove KMSAN instrumentation, which is
> > > weird because we instrumented these functions because of KMSAN in the
> > > first place...

I missed this. Yes, you're right.

> > > > > There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
> > > > > does not seem to map to any of the instrumentation functions.
> > > >
> > > > For now, I would rather that there are some one-off special
> > > > instrumentation, like for KMSAN. Coming up with a unified interface
> > > > here that, without the use-cases even settled, seems hard to justify.
> > > > Once instrumentation for these have settled, unifying the interface
> > > > would have better justification.
> > >
> > > I would assume they may also require an annotation that checks the
> > > memory region under all 3 tools and we don't have such annotation
> > > (same as the previous case and effectively copy_to_user). I would
> > > expect such annotation will be used in more places once we start
> > > looking for more opportunities.
> >
> > Agreed, I'm certainly not against adding these. We may need to
> > introduce 'instrument_dma_' etc. However, would it be reasonable to do
> > this in a separate follow-up patch-series, to avoid stalling bitops
> > instrumentation?  Assuming that the 8 hooks in instrumented.h right
> > now are reasonable, and such future changes add new hooks, I think
> > that would be the more pragmatic approach.
>
> I think it would be a wrong direction. Just like this change does not
> introduce all of instrument_test_and_set_bit,
> instrument___clear_bit_unlock, instrument_copyin,
> instrument_copyout_mcsafe, instrument_atomic_andnot, .... All of these
> can be grouped into a very small set of cases with respect to what
> type of memory access they do from the point of view of sanitizers.
> And we introduce instrumentation for these _types_ of accesses, rather
> than application functions (we don't care much if the access is for
> atomic operations, copy to/from user, usb, dma, skb or something
> else). It seems that our set of instrumentation annotations can't
> handle some very basic cases...

With the ioread/write, dma, skb, urb, user-copy cases in mind, it just
appears to me that attempting to find a minimal unifying set of
instrumentation hooks might lead us in circles, given we only have the
following options:

1. Do not introduce 'instrumented.h', and drop this series. With KMSAN
in mind, this is what I mentioned I preferred in the first place, and
just add a few dozen lines in each place we need to instrument. Yes,
yes, it's not as convenient, but at least we'll know it'll be correct
without having to reason about all cases and all sanitizers all at
once (with KMSAN not being in any kernel tree even).

2. This patch series, keeping 'instrumented.h', but only keep what we
use right now. This is knowing we'll likely have to add a number of
special cases (user-copy, ioread/write, etc) for now. Again,
KASAN/KCSAN probably want the same thing, but I don't know how much
conflict there will be with KMSAN after all is said and done. We will
incrementally add what is required, with unifying things later. This
will also satisfy Arnd's constraint of no empty functions:
http://lkml.kernel.org/r/CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM+G4X-hMgpBsXMA@mail.gmail.com

3. Try to find a minimal set of instrumentation hooks that cater to
all tools (KASAN, KCSAN, KMSAN). Without even having all
instrumentation (without the 'instrumented.h' infrastructure) in
place, I feel this will not be too successful. I think we can do this
once we have instrumentation for all tools, in all places. Then
unifying all of them should be a non-functional-change refactor.
Essentially, this option depends on (1).

However, now we have some constraints which are difficult to satisfy
all at once:
1. Essentially we were told to avoid (1), based on Arnd's suggestion
to simplify the instrumentation. Therefore we thought (2) would be a
good idea.
2. Now that we know what (2) looks like, it seems you prefer (3),
because we should also cater to KMSAN with this patch series.
3. No unused hooks.

Given we have a KMSAN<-(1)<-(3) dependency, but we were told to avoid
(1), empty functions, and KMSAN hasn't yet landed, we can't reasonably
do (3). Since you dislike (2), we're stuck.

Any options I missed?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPCGM9V%2B%2BVq_UtLJoLbzLdVfgJg0kWAkK%3DE%2B829may9Uw%40mail.gmail.com.
