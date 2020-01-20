Return-Path: <kasan-dev+bncBCMIZB7QWENRBBNAS7YQKGQESDALB7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A108142F3B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 17:06:30 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id x194sf30683912ywd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 08:06:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579536389; cv=pass;
        d=google.com; s=arc-20160816;
        b=f1I6yH/XAo4Pj7gh50UL59ApGdjwbl+QExQu7sYPD1+aIt91RbdkEyrC/fLEofSBQX
         9Jhm241UzkGK7zE84YwKrFTZTUOwp0l3qhSOSCxys9rAYiPAoMevroFF9w7BO81j00/4
         /ZWU1jBlC5BwmBa9oYcVUaOKbqxhg2QYg5KFpzYuocdJ+CFNWcA2MOxXupz5Ke0TswT8
         yuzaZJdV9G0uA0qWX/cKro3qGmzZGI9NIvWkFtLJvbfG5rvZES5/+A77WCkCSWPKGwip
         0wo5QuP+olmzg7JPHkO7ZWYxgCkPpJswM098OBw9icrBioG6jmrg+EZg/mnEhWYZpAdj
         NpDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hwDarntvLN6FFpPGLXBmZ4HynHWSLpMaGFByErjMQFk=;
        b=lKC1eU1CNj41LNb4R8KZbeuQU1gXlPVoQ3E6a4AJqtekfyj2j/zdMthr7MoqmX9q/k
         VX478N3Xeq+l2A3bIKvq0vY50i2kdrzz8lFM5KxkQMWXQ14SmeVVm7aowZty5ns8CBmN
         hG9Z7jedgFmzFe5U7kZhO/HQbDEcC7xoOk9QW+4c7LcHu2qD5pM0BzOkVpGLKszGVQ/6
         A1LsSapdk8kwX+4G0k8SaS1U9wpeA7Ie9TjQl13wQtGWhlu4e/NUo+C4TOYcSYyA0un9
         G+EOpYDQnPKr1XLBs1JV42g9Qcz+XjjZhedSr+SaOTb1BWAx4xQItr713YlP8QkgqQbV
         IPmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Baf6RJnN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hwDarntvLN6FFpPGLXBmZ4HynHWSLpMaGFByErjMQFk=;
        b=UMRMn+svSfSD7ohCc4rVvNQA3sg9T6U5srhr7oPJoBgZx1IM9XYZBiSsN3FtnsaqQm
         /vVDKGyAs94THmXZoTE6R1IJHo/MFURMCnNAs71RBJssx8hKFxCwRcsQ9KzgnL87gSE1
         lVikjaEG0d/GPxcLl6uOyz5Q6m+xldqi8hVpTNmNDG1t0xYNvlDj48GEBNdYDhNZMZz5
         Kk00oS1nqm0YFXKrCdB9SsGSWpl6dH5eq8vhp/yY3zPzZF0wCBcYwn2CTbgMyFvDT3j/
         ekrYRRSD268lYz9uiu4KmxBGet+IrnE3Ioj4/8XSRrVFc+J4Gi+0eXz4sGUuDX5X10pW
         f7ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hwDarntvLN6FFpPGLXBmZ4HynHWSLpMaGFByErjMQFk=;
        b=rLBtugxh+DzhbMInzGL2RqqNoK5ASK1kqLhV9UT2tur9eowYhg6x8TgSxTe/FbICK1
         DzOfm65rRBj7UwB8qW80dc+HpbCl6q5ChaSZ9we08pIDShNLrtEQZZca9EG5hIy1JVf1
         NZBYv+6tEhQMhQwPurt4NO3qmM6GAULBWesM5MMPR8IhI1kktvh9BxDLvqjqcmL7F3RW
         w40nUqEKPujkaqdNBciowFqPMTC2fuz5F6oq9m2npWT8B9oPynXKed49QFBl2jzQ+kId
         bD2a7G7kPAC9XHBtfBCMDAW+QhAWN4govAg3iSaPxXlUZ/2BY0WrUnw64nCRw5R5vge/
         kpxQ==
X-Gm-Message-State: APjAAAWSHtGqzuG0E7skOzva+M57wF+lJjwCYvSxUQgUrd/0M5zJl0xG
	3V/Y9uhWNz3j7OHCxA9HG7w=
X-Google-Smtp-Source: APXvYqxhbPRL4S9SraItZZkdwux6q5fzxj3bcrxranIkQvxWBsKEGeyhzaE4ywTCThBaKpdrihBy3A==
X-Received: by 2002:a0d:e9c7:: with SMTP id s190mr38722150ywe.429.1579536389129;
        Mon, 20 Jan 2020 08:06:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca8c:: with SMTP id a134ls3140385ybg.0.gmail; Mon, 20
 Jan 2020 08:06:28 -0800 (PST)
X-Received: by 2002:a25:a2d1:: with SMTP id c17mr370840ybn.492.1579536388706;
        Mon, 20 Jan 2020 08:06:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579536388; cv=none;
        d=google.com; s=arc-20160816;
        b=nPJMChPJ9QqSjA3yc/JLF/WFvQNrT+xIBAB83xDYAvnZtgvWJMR3PV32H4y3vHnlQG
         E2z4H7B0FV0hFLbS9ePXasqIoJ+LTrdaD4RtG+pEsW2uI+G4MoN1zwoJejGTlzW4GNAM
         QndI/CUst4zRiBdjH2m2k0njbwbjyY9v/EKdu+FrMNcfq6yF8oPMuidn2//e7u26nifQ
         HpF1SAKjkbNmap9wMuxy33tUb+AQ6dSIteAgfsBpTDY91hcDFFEP/4iAOb1KtV5bA/Wk
         DBxiE/54puS89tdpIhigMQAKy1bVNkfBuvPczpePQBXxYHEEYXJ7Jap0gCdlqxXRxfQ9
         iPlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rKBXxvKIRJE9r95Oq/vyPWMrKks8UEDi+Qo4dUocXJw=;
        b=I2IIMgwlBo81BiFdFEo91EOVqcnR+WoA3eU5lkdZ0H6SUeU27sTxQxFqTpJg2QmDrJ
         Mn0Qz29HDuPgyM0xCszOTBrCl8+V0bDl93hYdvE2GJ6R27rJVEGDQKXBcR3i2g5qobP0
         KDT9oY8VBqjEEQrltx4WJfq0wMFWV5Ggn2ZNZDpbrK1g5UT+ZwU0M3o9iX/z/BM5y0gd
         BJ3NmngylMv76hE5HgHwbiKXM2L/wzYNsZKwJqutP0C/zKI82qHfzFS9ZbInQJUWRVK5
         pcxTRV9DxCtoqeIbViEausyA41Z/UiCS3MmE3RU8aC+nrqdTlGlMQRVI0iq36B+zt9+/
         Jw7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Baf6RJnN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id p15si1630010ybl.5.2020.01.20.08.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 08:06:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x129so30536778qke.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 08:06:28 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr240817qkk.8.1579536388045;
 Mon, 20 Jan 2020 08:06:28 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
 <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com> <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com>
In-Reply-To: <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 17:06:16 +0100
Message-ID: <CACT4Y+bD3cNxfaWOuhHz338MoVoaHpw-E8+b7v6mo_ir2KD46Q@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Baf6RJnN;       spf=pass
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

On Mon, Jan 20, 2020 at 4:40 PM Marco Elver <elver@google.com> wrote:
> > > > > This adds instrumented.h, which provides generic wrappers for memory
> > > > > access instrumentation that the compiler cannot emit for various
> > > > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > > > future this will also include KMSAN instrumentation.
> > > > >
> > > > > Note that, copy_{to,from}_user require special instrumentation,
> > > > > providing hooks before and after the access, since we may need to know
> > > > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > > > also relevant in future for KMSAN).
> > > > >
> > > > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > ---
> > > > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > > > >  1 file changed, 153 insertions(+)
> > > > >  create mode 100644 include/linux/instrumented.h
> > > > >
> > > > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > > > new file mode 100644
> > > > > index 000000000000..9f83c8520223
> > > > > --- /dev/null
> > > > > +++ b/include/linux/instrumented.h
> > > > > @@ -0,0 +1,153 @@
> > > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > > +
> > > > > +/*
> > > > > + * This header provides generic wrappers for memory access instrumentation that
> > > > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > > > + */
> > > > > +#ifndef _LINUX_INSTRUMENTED_H
> > > > > +#define _LINUX_INSTRUMENTED_H
> > > > > +
> > > > > +#include <linux/compiler.h>
> > > > > +#include <linux/kasan-checks.h>
> > > > > +#include <linux/kcsan-checks.h>
> > > > > +#include <linux/types.h>
> > > > > +
> > > > > +/**
> > > > > + * instrument_read - instrument regular read access
> > > > > + *
> > > > > + * Instrument a regular read access. The instrumentation should be inserted
> > > > > + * before the actual read happens.
> > > > > + *
> > > > > + * @ptr address of access
> > > > > + * @size size of access
> > > > > + */
> > > >
> > > > Based on offline discussion, that's what we add for KMSAN:
> > > >
> > > > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > > > +{
> > > > > +       kasan_check_read(v, size);
> > > > > +       kcsan_check_read(v, size);
> > > >
> > > > KMSAN: nothing
> > >
> > > KMSAN also has instrumentation in
> > > copy_to_user_page/copy_from_user_page. Do we need to do anything for
> > > KASAN/KCSAN for these functions?
>
> copy_to_user_page/copy_from_user_page can be instrumented with
> instrument_copy_{to,from}_user_. I prefer keeping this series with no
> functional change intended for KASAN at least.
>
> > There is also copy_user_highpage.
> >
> > And ioread/write8/16/32_rep: do we need any instrumentation there. It
> > seems we want both KSAN and KCSAN too. One may argue that KCSAN
> > instrumentation there is to super critical at this point, but KASAN
> > instrumentation is important, if anything to prevent silent memory
> > corruptions. How do we instrument there? I don't see how it maps to
> > any of the existing instrumentation functions.
>
> These should be able to use the regular instrument_{read,write}. I
> prefer keeping this series with no functional change intended for
> KASAN at least.

instrument_{read,write} will not contain any KMSAN instrumentation,
which means we will effectively remove KMSAN instrumentation, which is
weird because we instrumented these functions because of KMSAN in the
first place...

> > There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
> > does not seem to map to any of the instrumentation functions.
>
> For now, I would rather that there are some one-off special
> instrumentation, like for KMSAN. Coming up with a unified interface
> here that, without the use-cases even settled, seems hard to justify.
> Once instrumentation for these have settled, unifying the interface
> would have better justification.

I would assume they may also require an annotation that checks the
memory region under all 3 tools and we don't have such annotation
(same as the previous case and effectively copy_to_user). I would
expect such annotation will be used in more places once we start
looking for more opportunities.

> This patch series is merely supposed to introduce instrumented.h and
> replace the kasan_checks (also implicitly introducing kcsan_checks
> there), however, with no further functional change intended.
>
> I propose that adding entirely new instrumentation for both KASAN and
> KCSAN, we should send a separate patch-series.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbD3cNxfaWOuhHz338MoVoaHpw-E8%2Bb7v6mo_ir2KD46Q%40mail.gmail.com.
