Return-Path: <kasan-dev+bncBCMIZB7QWENRBV5PS7YQKGQEFGFVGRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E6942143016
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 17:39:52 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id p8sf98800ilp.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 08:39:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579538392; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kujd4YtQgP2tSAZVkUNfWf/NOOt8IdOZPpMDapuNRe793wdSOWP0pPxo3Mki3RF0jj
         qBi4zMA/74+v9ziQoF7qzHqWVJ+Abx/4Fvz7i1LsbmBM2NRh/Uyzf5zISlA28lOm8EVZ
         cfv0VUwaHWwMXsjywJJIwiu5sjR6LI8DFSWbgRw/n0mJWlHnv9R2/cxIWDoyAeLhcZy6
         MmLkLMuZFGmI00AMf1RDPTHTticOccyfG69JRDgF+d1FUyGC/aWRiuRBMpDCwm8mAuwB
         n4bPETG6bsn44OMYPspzCzNuiUFsXqRDjIrHaTxW7OMih4JrcGbNVgD7RIWflEw5PfJj
         FVTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ozvFnulFbhzk6xI7bnHridVD/qUsyhpYTef7jL0rXR8=;
        b=rR2Vx35ox0DNcd0vrWoLBcadq9Gk5MAlTvhBEzD22KIg9YI6SIEKkUQe+ZL3fn4doG
         CLPMvD3NLM91yPGV256GP0CbzqD+aFqGYempemomJzFruoe/g2sucqaCt2GTaKZHLDT/
         EhAYQmHO88oq0QcaebBXcsklJ5kVznpDCCjuko093GQkWBJcXnf03JfmebKxvwMIhDzv
         wW760n9+ljhZxSCCFgL2xuSxUYVfvxVfGSTKZbXYmhxyDm9obT6X+yfFLBO6hyVu14ZY
         1m8i+OQ+FCYckMrTajNtys0jU759W3RDfJIAsw79QpyqeGOfmzOc2tYensBgzF8nL1y9
         tRqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tMSVAicR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ozvFnulFbhzk6xI7bnHridVD/qUsyhpYTef7jL0rXR8=;
        b=BSB1oSEjmH1u6kkQpLJ+vo0Sx75YErANEwHBDbjoD4G7w79XExgqtrVqZPGCeuzpdb
         n7j1j3MIjVEdsB8sTlM7xgq3VVc2B9MeDb0iHgFwmAXhVefVlmkBL8Jli5e1cic4aA4z
         y/IccHwU2apk7cZsvJNs8fX7galNM1/tYnl3U/6X7qAGcJW1zeoGOr4CgvFf14q3ncOA
         UhCzK1Q9aripcNismrna+shbG+tCOXAF8Oc9bmlqOz68g6BUaiWmhnNepAsDys/MnAxE
         +W5YatOeKr+xfj/5pTnX3sIQRmSnFijKT0WN7sTuRdCN3LVjvGigwa9F98gJdC1XDipu
         w0Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ozvFnulFbhzk6xI7bnHridVD/qUsyhpYTef7jL0rXR8=;
        b=eQPBIoGte/MyvfRnJbMOi3fzGODPYKPqNZsuyMLdLpC7N/P96T1+lJFt/Xpw5j/qhC
         BM/QpVTf2QzJdkxjP/WNQPrOgfaR8bb6wAXd0BLoBDAnP+okTPnO9fjwmmcOVTsLXH9H
         G6gs+YcMqQlxcf+4h3AoPByAubcE97CBHQx/yCoEe+nzi/Ff5EkzXvOCgvDYrvekq/zc
         jVY9+t+vA0NlAum0TnHKri8ez9Sa+32/S3ioMoxZf5JV3EIpW6qhzaFrakrFaSRrjCKU
         dYc/vD73MWzCF04Ex+Exb/Nupozo80K37TjmUUV1k6PxCihiOHXvc9T9Dfxn5bjstNNs
         UL2A==
X-Gm-Message-State: APjAAAXbeAjoOKkpzOguBOA0FZ8JeIA12z2UmqiVsEfie94PAafKHQTz
	lZfMNxSLIM3F+H37Jz9sZ+U=
X-Google-Smtp-Source: APXvYqydVvsGYf3Gy0dVIM9npdNqtUxtpbPN5gepogYPIlj6W7MWnW0bpIciHeZANA4D4BZ9ZH57xg==
X-Received: by 2002:a6b:731a:: with SMTP id e26mr40967283ioh.254.1579538391777;
        Mon, 20 Jan 2020 08:39:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cb49:: with SMTP id f9ls5773366ilq.7.gmail; Mon, 20 Jan
 2020 08:39:51 -0800 (PST)
X-Received: by 2002:a92:3a95:: with SMTP id i21mr11305216ilf.249.1579538391383;
        Mon, 20 Jan 2020 08:39:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579538391; cv=none;
        d=google.com; s=arc-20160816;
        b=VS992wtbEMsg5UvKud2/Sjp7uflBAM8yU1rjyup11NUK+MFTVfToPLkV/6YM6x4ypn
         PDh+Egp73gmOdrrtSIg1h2imi0y5Q1QSUl9nLAUC3yPTzbGlHJu82NQlZCCenPls69D7
         M74Yn/EFr4ZZaAjEiVyyaOYicffk46uAmrr/n0GHjQUaBADFEkWx+WMswW5L77mOerKj
         flfKwOswnsOwUsjvOx+XVCFeTHjDdyX6UxaLt22M4GG2blVpdCWUxgxmJ37szbrCzo4p
         Gh+0nO1cT8lRZklXifCwBdGpI65VHmWUpgPzXicuc6rR2SVRisDd2pAc0DHMuma5zLhv
         fZaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sZcsttqoOqoppbG6e/pqRXCvsc9U04ANxonvw6+R+xA=;
        b=eN0XOOLAfKR5QU8Nhzz3pk1+tGF58DXxMbXnYbuNbTC25eMamQuAio4QxwzqThpCmS
         uO93p0FA3ujpyO1L65dWl9B4hfnyMfzp1ZdEDWgCrKIfhngknrvyZvPKQ8lW/MZrxfdr
         M5P7RYeR+CW6TWfb/8Mxg8h+3ZMniMjMmAivmDFlHZ26WP+V7zCoqK6QOeq5A8ECUIJw
         3rhgF0OQxZHWPeTRvG2OqZ8ZzmTiXWozVVkmI8U+oofoEDP96R93s7ysR3/LGIDif80O
         za6YqWsl+uD1LB7ZEwvT+a3L3Gqz4LxhZmLTDVwuirOR4n2hXPYeeLytfyZXudVVi38I
         SiXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tMSVAicR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id z6si1320870iof.2.2020.01.20.08.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 08:39:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id w8so218439qts.11
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 08:39:51 -0800 (PST)
X-Received: by 2002:aed:3b6e:: with SMTP id q43mr129761qte.57.1579538390395;
 Mon, 20 Jan 2020 08:39:50 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
 <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
 <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com>
 <CACT4Y+bD3cNxfaWOuhHz338MoVoaHpw-E8+b7v6mo_ir2KD46Q@mail.gmail.com> <CANpmjNN-8CLN9v7MehNUXy=iEXOfFHwpAUEPivGM573EQqmCZw@mail.gmail.com>
In-Reply-To: <CANpmjNN-8CLN9v7MehNUXy=iEXOfFHwpAUEPivGM573EQqmCZw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 17:39:39 +0100
Message-ID: <CACT4Y+bgLy=AiCdLauBaSi_Q1gQsqQ08hr1-ipz60k+WFdmiuA@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tMSVAicR;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Mon, Jan 20, 2020 at 5:25 PM Marco Elver <elver@google.com> wrote:
> > > > > > > This adds instrumented.h, which provides generic wrappers for memory
> > > > > > > access instrumentation that the compiler cannot emit for various
> > > > > > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > > > > > future this will also include KMSAN instrumentation.
> > > > > > >
> > > > > > > Note that, copy_{to,from}_user require special instrumentation,
> > > > > > > providing hooks before and after the access, since we may need to know
> > > > > > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > > > > > also relevant in future for KMSAN).
> > > > > > >
> > > > > > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > > ---
> > > > > > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > > > > > >  1 file changed, 153 insertions(+)
> > > > > > >  create mode 100644 include/linux/instrumented.h
> > > > > > >
> > > > > > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > > > > > new file mode 100644
> > > > > > > index 000000000000..9f83c8520223
> > > > > > > --- /dev/null
> > > > > > > +++ b/include/linux/instrumented.h
> > > > > > > @@ -0,0 +1,153 @@
> > > > > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > > > > +
> > > > > > > +/*
> > > > > > > + * This header provides generic wrappers for memory access instrumentation that
> > > > > > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > > > > > + */
> > > > > > > +#ifndef _LINUX_INSTRUMENTED_H
> > > > > > > +#define _LINUX_INSTRUMENTED_H
> > > > > > > +
> > > > > > > +#include <linux/compiler.h>
> > > > > > > +#include <linux/kasan-checks.h>
> > > > > > > +#include <linux/kcsan-checks.h>
> > > > > > > +#include <linux/types.h>
> > > > > > > +
> > > > > > > +/**
> > > > > > > + * instrument_read - instrument regular read access
> > > > > > > + *
> > > > > > > + * Instrument a regular read access. The instrumentation should be inserted
> > > > > > > + * before the actual read happens.
> > > > > > > + *
> > > > > > > + * @ptr address of access
> > > > > > > + * @size size of access
> > > > > > > + */
> > > > > >
> > > > > > Based on offline discussion, that's what we add for KMSAN:
> > > > > >
> > > > > > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > > > > > +{
> > > > > > > +       kasan_check_read(v, size);
> > > > > > > +       kcsan_check_read(v, size);
> > > > > >
> > > > > > KMSAN: nothing
> > > > >
> > > > > KMSAN also has instrumentation in
> > > > > copy_to_user_page/copy_from_user_page. Do we need to do anything for
> > > > > KASAN/KCSAN for these functions?
> > >
> > > copy_to_user_page/copy_from_user_page can be instrumented with
> > > instrument_copy_{to,from}_user_. I prefer keeping this series with no
> > > functional change intended for KASAN at least.
> > >
> > > > There is also copy_user_highpage.
> > > >
> > > > And ioread/write8/16/32_rep: do we need any instrumentation there. It
> > > > seems we want both KSAN and KCSAN too. One may argue that KCSAN
> > > > instrumentation there is to super critical at this point, but KASAN
> > > > instrumentation is important, if anything to prevent silent memory
> > > > corruptions. How do we instrument there? I don't see how it maps to
> > > > any of the existing instrumentation functions.
> > >
> > > These should be able to use the regular instrument_{read,write}. I
> > > prefer keeping this series with no functional change intended for
> > > KASAN at least.
> >
> > instrument_{read,write} will not contain any KMSAN instrumentation,
> > which means we will effectively remove KMSAN instrumentation, which is
> > weird because we instrumented these functions because of KMSAN in the
> > first place...
> >
> > > > There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
> > > > does not seem to map to any of the instrumentation functions.
> > >
> > > For now, I would rather that there are some one-off special
> > > instrumentation, like for KMSAN. Coming up with a unified interface
> > > here that, without the use-cases even settled, seems hard to justify.
> > > Once instrumentation for these have settled, unifying the interface
> > > would have better justification.
> >
> > I would assume they may also require an annotation that checks the
> > memory region under all 3 tools and we don't have such annotation
> > (same as the previous case and effectively copy_to_user). I would
> > expect such annotation will be used in more places once we start
> > looking for more opportunities.
>
> Agreed, I'm certainly not against adding these. We may need to
> introduce 'instrument_dma_' etc. However, would it be reasonable to do
> this in a separate follow-up patch-series, to avoid stalling bitops
> instrumentation?  Assuming that the 8 hooks in instrumented.h right
> now are reasonable, and such future changes add new hooks, I think
> that would be the more pragmatic approach.

I think it would be a wrong direction. Just like this change does not
introduce all of instrument_test_and_set_bit,
instrument___clear_bit_unlock, instrument_copyin,
instrument_copyout_mcsafe, instrument_atomic_andnot, .... All of these
can be grouped into a very small set of cases with respect to what
type of memory access they do from the point of view of sanitizers.
And we introduce instrumentation for these _types_ of accesses, rather
than application functions (we don't care much if the access is for
atomic operations, copy to/from user, usb, dma, skb or something
else). It seems that our set of instrumentation annotations can't
handle some very basic cases...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbgLy%3DAiCdLauBaSi_Q1gQsqQ08hr1-ipz60k%2BWFdmiuA%40mail.gmail.com.
