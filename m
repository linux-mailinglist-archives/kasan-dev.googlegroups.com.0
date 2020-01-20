Return-Path: <kasan-dev+bncBCMIZB7QWENRBR4FS7YQKGQE343MESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 714A7142E6E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 16:10:00 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id e7sf19925581iog.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 07:10:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579532999; cv=pass;
        d=google.com; s=arc-20160816;
        b=M5CXhGSoBY1COPfPktGFrEPLSXkYa58X/EFFaQlMrd74QVzuYCoBT/c82Je5gOL/ld
         9v0FlFP7EWHN9qnNDZFoHWnX0eOmleVPknF842JrpcXAE4AdHw3RDu8M88pH7oGxtwvB
         KYBetf150dpPwGBKFi6kmf5BlLZKcYAx1/GGf+veFMIJ6ll7UEAQR82g4AAGaKo+E8Sm
         ehYJkOHbZSzR2H6bkcVGOSCavi04in4NjKqglBpHRvURzESuw71leZwayU8Bj0bp35dn
         y2XJu08BuKl0NjyKXqrJqR2Q73T+PCima5Xwg5UFFoUcjWPgU8bVFtKZ0+NOEMXP3cRv
         VVag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wJeerT+N7L8sJMohr8IJEYBdRu3pXzrrzttjC5uX5Fw=;
        b=QV2uFUFqo5He5JE0BVuhWrrXV4iHZ+vnoWd0aPSy9vewkf/tixGx4Ga9sVOr5VPNb2
         1zd5nmvlxtr/FoTTXPzKcsOV64yuOf4WjIEBa79//ID5uth3Mub3ukUEAH2zUeA9vCia
         0DEKFSRP9WwBEnyLl/OBGCavc7u/b5UG+LF4WE/3eIVoPfMlnzSgeXtP+NJqfRSADDPE
         arb18KEFkAz57EyqeICVmsMX9HxNPJsF3ZhKbmOy7TaT1DNTfhcCdBaIDFXTOw+V03iX
         JlRP2PE0i5mQAN/AiUwRtHblcNvwth91VNrFpXQd6ejyqIEllaoL6TwDe22uOWbEfir5
         LZjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PQ+9HJwk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJeerT+N7L8sJMohr8IJEYBdRu3pXzrrzttjC5uX5Fw=;
        b=rfmjAtvrBqXM+CxtykffuC75+Aiec/mBgyK8cEGv/ehyRUKijd4K2u0Aa1u0Hg7Pfb
         OTYlKh1j6nEvyLy/sJLjjXnJKCbJh0ZD/TBOCwNW0x4MJBprjVJurm1TexcnHHKZQ9li
         JukbDoiO/0SscGippQpCMnPK0h9qwR+f4fe5PcDkM72QllbrKEZYv3pVzD9kkYX2aFCK
         u5KAooOXM6tw17kHYWgsfryGtep7oGGCICv8tOekYp5IVdft5QPq9/1ZdbzInezh53Sn
         l0RSiS53dndAoIL71ZXenarxkUg2GJ5EF2i+3zwHgJzB5E7VTCPxfldXjmPFVX9Klzqq
         WiRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJeerT+N7L8sJMohr8IJEYBdRu3pXzrrzttjC5uX5Fw=;
        b=OP8LX3Y5dXxxn3VDNxOwaH8ebyU3qkf8f8zMrXV7wvgzTrU8AJHrHkrTlMf4qrGuj4
         lNivhQOX1quXNPUkrB/IfoZfMo/uOH+gRlpEkN1gTwdgJyUaEH4vgPLTVPJTeDuxQ4ZQ
         sjHqxL40GFlC2TKs5Kyeq944Y2vmU8ut25bmDO6ESQhtiKSIWckZiIg5vlcwrH5UkxAe
         yzboyDy5of1DaN0YTspiI9CuATHR7D0KcPqGmI19s4pOuCDaG7PpSS2yvBb4oLSwbOMC
         bd6YSaRYaF4lhkpzYfWUl9AFpLolDlaQp0aGa3UI1FpBxtYCzYRmm87eFnbqG+CZqeb7
         J8jA==
X-Gm-Message-State: APjAAAVu6YF4zfX3SULjEoM7L8oAWpmY8YPBctFK6nH9lDfOmyp8/7tU
	QtCDlJRR/9Dm6iIEP6yZc/o=
X-Google-Smtp-Source: APXvYqz9hzcuIznl8OELK/iuAEwJTcGM/pDGwjkfCOCy2i4bifjUjVLVaQixOikpP+AOJyX5ewDT9w==
X-Received: by 2002:a6b:3b54:: with SMTP id i81mr40686854ioa.249.1579532999340;
        Mon, 20 Jan 2020 07:09:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:22c9:: with SMTP id e9ls5135595ioe.2.gmail; Mon, 20
 Jan 2020 07:09:58 -0800 (PST)
X-Received: by 2002:a6b:6c0f:: with SMTP id a15mr43296644ioh.13.1579532998782;
        Mon, 20 Jan 2020 07:09:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579532998; cv=none;
        d=google.com; s=arc-20160816;
        b=DB9iB+6yxBhKx/EkJvofKMGAv2ab1IZi6UCbngrB8UVn7beoau/J7oJru8Tn5IsP8x
         TWSa8f4dmHuIvywXzwsn8+/nFMqkuouk+zKjo2wZEdl84HtRPieXMxIGTcbr79xCl0Fz
         rJzxCvaK3nWCBKnfB74lHNi8AaAeuJx4ekc1s7titLE4Q4QAeaS/oG8VTtflOZKcoF/w
         Fv999MWD3QDfuEK3zgNbbb1A/UA0rmu7a9ZjSEcm6bCRTQ4PaKYOV9npNd777iXnCxwX
         qWtfjjR/CMWCirffAH+SKgVoggjRW1jXLz27HA8mV5rebvAqQJ6r0qa/wrfgUvRcyzfj
         j3dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RILlv2/4lxhYaS+kKGTocXUc7rBZNj6liYWIdFAYLvQ=;
        b=j/DnVnFYQkWUwkKEYcFkupTkQfabzGVdUEek81fOMhphjpgZMNJkCNq5yidFW6AMw9
         weohz9Ofwyf3QyWIEjyTU0Gq84yfJ5cuab2bqgAnehVkSyR3pmgK0gN292BWuE5LwVV+
         wnODlmcR1WDH54TW+nq3TaIj6rOiEepmcE9h42cRUKcJRjBiW37+SM/c6RhzoAt5wUdP
         iF76J7fs4hUc/WC26LliA4WqzV86WQAxLf+0sjhR/VUJEsiOQHig7gR5fTebGbU9m9dq
         Au//2yheoo69VZsOW1YzNjQWKKG2FDQl7dc0bT0DJ8KoPSOdPDCUVZMHkQu/Es2i2C39
         Zz6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PQ+9HJwk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id z6si1311875iof.2.2020.01.20.07.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 07:09:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x129so30357387qke.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 07:09:58 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr52522165qkk.8.1579532997947;
 Mon, 20 Jan 2020 07:09:57 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
In-Reply-To: <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 16:09:46 +0100
Message-ID: <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
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
 header.i=@google.com header.s=20161025 header.b=PQ+9HJwk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Jan 20, 2020 at 3:58 PM Dmitry Vyukov <dvyukov@google.com> wrote:
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
>
> KMSAN also has instrumentation in
> copy_to_user_page/copy_from_user_page. Do we need to do anything for
> KASAN/KCSAN for these functions?


There is also copy_user_highpage.

And ioread/write8/16/32_rep: do we need any instrumentation there. It
seems we want both KSAN and KCSAN too. One may argue that KCSAN
instrumentation there is to super critical at this point, but KASAN
instrumentation is important, if anything to prevent silent memory
corruptions. How do we instrument there? I don't see how it maps to
any of the existing instrumentation functions.

There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
does not seem to map to any of the instrumentation functions.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BacrXkA-ixjQXqNf1EC%3DfpgTWf3Rcevxxon0DfrPdD-UQ%40mail.gmail.com.
