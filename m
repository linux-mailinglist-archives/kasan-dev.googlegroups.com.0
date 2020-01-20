Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4US7YQKGQES77G7FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ECEF142EF4
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 16:40:56 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id c202sf20760804qkg.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 07:40:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579534855; cv=pass;
        d=google.com; s=arc-20160816;
        b=RV6W79yNcyphRTZEOvC6j9+0kl4Wq6pr6iNT//TE93WBrjh1caIrAzKFYgDKj3gjTV
         ykAUNbUsBDJkmpzmFnachtrKe04u1B4QB422OkFdcPgRHkFa57IYtClCfct7TU/Nr7G+
         mShyaXuwGcLRG22uowUmH4Lei9rk08dtfXmp/FdXtPQfln1Q6Hmy4PcsqWGeuTHU47Lt
         vZGUjFGrR3fbI2EvPKLuroqkapyxXNnRgemwUGLj5cxrdT7P5LdJs51NooLWDVKCY0Z8
         Olv+wTnxKau3vOyD3d2aewIKnIk7B+Fj0JnMA7TpP/OfhP8/M8Ou/fSWYmk+hm298N1m
         136w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B1t1PLF7I0Qo0TVlJNF527RQ682tiSU+5Wh/X+OyEho=;
        b=ZnL4T3ZPGf4kw57wWNLjcyw1jWCZqILl7IXacN14x9Uvp26lxkTWBI7P40s7u+tK5t
         mykSgZ6QY/KrmMZ0+Ve49jEnX1eE6w3dTOR/XHHx96WimjWZO+I3hqit0tfvTH+PtsC+
         4PruxMpd8DDdO1xe/0rWmbkLKHTlL0NxZAnBXStixB+36RQymMF2NLNLbGe8lRPQB+Oq
         64C57cfhe0t/zIn54jlaIZs1oCll907aPzhvRrdHn45femiSrPbUTJN55JcgnXZZlKdb
         8LJHeiiF33LhHWnAN4Cc/0SWbZCMyIeDwcc/zbNnBjJHINdMkIqryUK0yG5WG/u/z3NH
         2K6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VbUJNHV1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B1t1PLF7I0Qo0TVlJNF527RQ682tiSU+5Wh/X+OyEho=;
        b=EhazSyh5NAZC0ieGKhV11HxeqUbjL6pkyI+2mv53z9YLwEe45+wHCusAt6ZimZs3Kw
         w2Ts8C9Vm92BW+WKBUmJtZwca+YiOIhnr+vAadfCUAzphX6Y/Ds2kIf6vgwk90lNuAp+
         8eB77ZsrKzncNQQMupiCC5DiphQpDTNgjCXn+SAB8v1voctOvn7ktVNb6GkNhhZZ46KS
         cB5f//OaVEyz28VTaW5JFcgAmhU0ve9Cb2HN86H4nPo1ooYn/5/WsKPUbtS7Lar0bKaW
         ngex1WpnnS2CIeHfyC1bE3cGEDVjZ2vRrEe4ahoyrMS73rsmSkgKjsKi0emRCTb7CWf5
         KDOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B1t1PLF7I0Qo0TVlJNF527RQ682tiSU+5Wh/X+OyEho=;
        b=TT8IvH7O6a2Uvwx0L0EKzK2q3qWxvNof9NlbPWRis0IWId74ou5YZ6xYtieOLIIwT/
         L6MAlqF3DkNbVX3ghMaTfT2t3ESbtJwQ51AuyTvkBPQ9DQ/iByRGODpkoowGI7bmLiMu
         KNH3IgM0Vyd71AmaDgqEEhM/1Kz9VRGGZoR78nt5/6sCoMp1ubFaxax0mPRt6fd5WDqx
         aY/8G6ialELsK8Pb8nBSR9uoBvj0WEufIiXklcBp5bh3Zu8RRcSvtV83X0TIP0bS6qfv
         ypAUkTfBs923Zfn0mD0/c2yF4cGnWeksooQaOBNeMIuvyNoigF8K6wxo6Xuh1bbUR24x
         q72A==
X-Gm-Message-State: APjAAAWYlV7aRl7c2rSDpkqFJ4gmalGZ+mWmID8wTNfjbw6HoPR51Jzm
	9tbA/x1gjPv1bsPgAecmzeM=
X-Google-Smtp-Source: APXvYqyVftzhIyXko7F93ObCMo+NUBTMtBg15m7sywy09nt+Y9Umvmu5k/Qjh5fWuJ7bY4W2WWnkPQ==
X-Received: by 2002:a05:6214:923:: with SMTP id dk3mr313809qvb.96.1579534855058;
        Mon, 20 Jan 2020 07:40:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1a68:: with SMTP id q37ls7380604qtk.6.gmail; Mon, 20 Jan
 2020 07:40:54 -0800 (PST)
X-Received: by 2002:ac8:65ce:: with SMTP id t14mr21013952qto.72.1579534854678;
        Mon, 20 Jan 2020 07:40:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579534854; cv=none;
        d=google.com; s=arc-20160816;
        b=uDp2/nv7ciXpEBhBkJ325VNxMZLLh5slUEs3DdXtJQKrBEetWlq4m0H1SrBR9MmMSd
         z+/A08FHyO71WIa+kBsurZw0HZm8WuzcAPsDz/iRl7NPgKBkPsqUjvCBA5IVVCK2+TaA
         Py+VvrBvQePBA6rNia/4UfVBD8l6TGyCaSZnR38UluVDfGu4n4fqNUVDtix+XzhgalaR
         W3ai6WrSOOuton/1MSaml2aV6Ku1Ht0xWKBouSzGGPPcSFImFbOdUai4DSuMY/nxyOJk
         hV+OtoeTdwu0f7U3viW5+nyvL9qCrQiIv/5390pOai86vD1O6k+3B9t+GVNDVqR4lFWt
         ndFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bW+iYMzyJar5RkTMPGCcQG+bJOCaKWAlm479KJ6EAJc=;
        b=D0Ux+oBXMWzBoK0PxwGomczXRDnQnY2Dyqw6ZKy75DMlkZOs3bTQXQbOls2VPGi41I
         D+SP2T71ltLkwVnMR1oiiPFltg7fM9LenNk887iwQ6soSUHbmEiwlPohwcYdCpIjRbtX
         JIdHuPbgfci5DfA5Q/O0RdoLSR6FbpqJdieOB1d84qTRJnaUgBaOO+Dsjqq7YGEiwLPS
         Edi2YAvkHif2q7zvqsJ4/NqJfhtcwQKqxt+RWolmC0jKfvS3+wkLF95eh6kTzzwACGb3
         LhkB7LMECF0OEq8pYUtfDbfHzHt8zhCplp1uJNnZc0ZSFRJ5Pn4YgfVYjPUQcmHwlfll
         uiIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VbUJNHV1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id d135si1304475qke.7.2020.01.20.07.40.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 07:40:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id i15so138024oto.2
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 07:40:54 -0800 (PST)
X-Received: by 2002:a05:6830:1d7b:: with SMTP id l27mr15490059oti.251.1579534853838;
 Mon, 20 Jan 2020 07:40:53 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com> <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
In-Reply-To: <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 16:40:42 +0100
Message-ID: <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=VbUJNHV1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Mon, 20 Jan 2020 at 16:09, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:58 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Jan 20, 2020 at 3:45 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > This adds instrumented.h, which provides generic wrappers for memory
> > > > access instrumentation that the compiler cannot emit for various
> > > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > > future this will also include KMSAN instrumentation.
> > > >
> > > > Note that, copy_{to,from}_user require special instrumentation,
> > > > providing hooks before and after the access, since we may need to know
> > > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > > also relevant in future for KMSAN).
> > > >
> > > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > > >  1 file changed, 153 insertions(+)
> > > >  create mode 100644 include/linux/instrumented.h
> > > >
> > > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > > new file mode 100644
> > > > index 000000000000..9f83c8520223
> > > > --- /dev/null
> > > > +++ b/include/linux/instrumented.h
> > > > @@ -0,0 +1,153 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > +
> > > > +/*
> > > > + * This header provides generic wrappers for memory access instrumentation that
> > > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > > + */
> > > > +#ifndef _LINUX_INSTRUMENTED_H
> > > > +#define _LINUX_INSTRUMENTED_H
> > > > +
> > > > +#include <linux/compiler.h>
> > > > +#include <linux/kasan-checks.h>
> > > > +#include <linux/kcsan-checks.h>
> > > > +#include <linux/types.h>
> > > > +
> > > > +/**
> > > > + * instrument_read - instrument regular read access
> > > > + *
> > > > + * Instrument a regular read access. The instrumentation should be inserted
> > > > + * before the actual read happens.
> > > > + *
> > > > + * @ptr address of access
> > > > + * @size size of access
> > > > + */
> > >
> > > Based on offline discussion, that's what we add for KMSAN:
> > >
> > > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > > +{
> > > > +       kasan_check_read(v, size);
> > > > +       kcsan_check_read(v, size);
> > >
> > > KMSAN: nothing
> >
> > KMSAN also has instrumentation in
> > copy_to_user_page/copy_from_user_page. Do we need to do anything for
> > KASAN/KCSAN for these functions?

copy_to_user_page/copy_from_user_page can be instrumented with
instrument_copy_{to,from}_user_. I prefer keeping this series with no
functional change intended for KASAN at least.

> There is also copy_user_highpage.
>
> And ioread/write8/16/32_rep: do we need any instrumentation there. It
> seems we want both KSAN and KCSAN too. One may argue that KCSAN
> instrumentation there is to super critical at this point, but KASAN
> instrumentation is important, if anything to prevent silent memory
> corruptions. How do we instrument there? I don't see how it maps to
> any of the existing instrumentation functions.

These should be able to use the regular instrument_{read,write}. I
prefer keeping this series with no functional change intended for
KASAN at least.

> There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
> does not seem to map to any of the instrumentation functions.

For now, I would rather that there are some one-off special
instrumentation, like for KMSAN. Coming up with a unified interface
here that, without the use-cases even settled, seems hard to justify.
Once instrumentation for these have settled, unifying the interface
would have better justification.

This patch series is merely supposed to introduce instrumented.h and
replace the kasan_checks (also implicitly introducing kcsan_checks
there), however, with no further functional change intended.

I propose that adding entirely new instrumentation for both KASAN and
KCSAN, we should send a separate patch-series.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNcXUF-%3DY-hmry9-xEoNpJd0WH%2BfOcJJM6kv2eRm5v-kg%40mail.gmail.com.
