Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4HZ5OMAMGQER4SGUUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D4B5B320B
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:44:33 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id dc10-20020a056a0035ca00b0053870674be9sf739003pfb.12
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:44:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662713072; cv=pass;
        d=google.com; s=arc-20160816;
        b=c+J6NV904LilC20eLdKRl29oyahYypt+cAwxKGXcUnmDsAkNN/3ehEfotrZL6FgFk3
         jjzx/DJAk45VyGGZ0XyezkD6keUEAzE4aMWTb26ow5PgsgZ2A1cQtVWxxxabhU+Pv/hk
         tSNFxH4IlPL/Z65j/AthQMorskmEdB03Y3eGTmcFSmFOMSiy3t2TN/ES4jLk7kuocz1/
         SvhCnANZoSZxYJ7S3kt/D2NdTSIJUQv5T4tSCYL5PK3VvjnpegaMVYm1OxnFa8fEU5rj
         stzaGOOqvRxZiQBHH4ToVy61KEG+YLnIY5qjSdNfxwxHrzWKFQZsr5EM9ef0QOh2/hRE
         NXWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dqLGOcOVphSJGqfZP1PzDG1ytD9sTsZVEIEr4DnyGw8=;
        b=oERgehNZxgLH/56Xif2MPpcYWa48RB+zmpaC46zKOuwvCDrmhvSS9ykrEuiyyT0Gi7
         p7Ow6vyyROqz79jO3FEXc5ym0yGM8GMu+Dd7OIPksEfrOD/9JrwoObHOiXyq/jBVUyik
         Bjhbelp/mxstNZqHaI5BSLAcvSx80glf2pO83VJQHKQOOyu1TKn58Ha7Ctt2EOlDEfKO
         mJRMA/Ja26h9MGFq9G83J1ageh/qyzwlXX0vjfQvFlyAGQa4aRWeopS0p+wv8s51uqkU
         GhlEycbEWQNrPGTnMLtRAsXvt8ECKiLZ9hexadh3VQnifN6RCHCozPsjclPNPrQdr7Tr
         ErAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sw9SXPNg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=dqLGOcOVphSJGqfZP1PzDG1ytD9sTsZVEIEr4DnyGw8=;
        b=hsVuHSGie9FYuOc4jTjC2jrSCbLGFLxK5Dtr0w2PqzD1R07UzGnROq4pfTWuj7T/v/
         BrDsV9iXP329gV+WvlWHqv5F6MPq00na3Ny/N7USsaVtWr7/7UcpLDa1qi9UONPZm3eO
         7g+WhaZwa9RAQhAz15pi4gvAtlwFB+2pxJbFCzO7O3vPLCw45iqRRH/lixRrT+y8jj/l
         UWLeo0ke8TlPSHFpR/mVASRz8FBOs//F0MLpDqfOld9zYw4+bgn2pH/dRN/oQ5H0Yc4D
         Kifxot3pmuJVtZcrZca1fPyWWSkuKi+T4bQ3GYdU+i0SLpLgL86owcogD8iyebUY/zRN
         +HVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=dqLGOcOVphSJGqfZP1PzDG1ytD9sTsZVEIEr4DnyGw8=;
        b=AI4OfGcAm/4yCy6j9IQBxrU7xIuFP0FF4w5B4jYWl3ZSAmw4+634q0mvDsXfRdX4dQ
         ZLg5lE/lXUD8kIVoGz857AIS8TOFu5Z77PVV7gob2cfkTR1zleIZCF9b2XLJBcMgxjr3
         MEi0npHgkjGZEX0r0N4h2hN7zZzGUwQyeEznP3obbzymTT2IF0Z6LLxnO9k/04zwNLPW
         y2qCUZQka1CDuRP8e24UdwOjEaC1ruZ421ni6JfVyFZJfAHUBahIHS3UulnyspTaXbyd
         Sefpxwu+NjqN+CtXEYC0byQRA4yF3vIN0H23or3eWl4uiqrIM2thO+RPHhdDHhne6aKx
         qiWQ==
X-Gm-Message-State: ACgBeo0DUyPYLG/DMf20+LGSbdyYaOTiKqluvEv5QW+QqXArBgtcRUJP
	xd8KVizXiIqTXS2FOC1kXHk=
X-Google-Smtp-Source: AA6agR7T/FaFAhoXdgIn8992h5gMMrDel1XAOAurCiQeM5kjTVKGtgxHgF2xkbrAx/1fDQsAaaxSZg==
X-Received: by 2002:a63:ec55:0:b0:434:a8e6:7d0 with SMTP id r21-20020a63ec55000000b00434a8e607d0mr11434546pgj.390.1662713072213;
        Fri, 09 Sep 2022 01:44:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:8143:0:b0:41a:63e8:2535 with SMTP id t64-20020a638143000000b0041a63e82535ls2249471pgd.2.-pod-prod-gmail;
 Fri, 09 Sep 2022 01:44:31 -0700 (PDT)
X-Received: by 2002:a05:6a00:1889:b0:540:acee:29e4 with SMTP id x9-20020a056a00188900b00540acee29e4mr5826069pfh.49.1662713071412;
        Fri, 09 Sep 2022 01:44:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662713071; cv=none;
        d=google.com; s=arc-20160816;
        b=gg88W5pxY30TbjGkX62NcolPuUdpGGzBknvPr46Oa7Xb47aHqnsYgBbrqAXkDNopp0
         MK2aiuxkvs0wBhgYHKSISg7WnifM040gbLR2IfxYbQONanHXfT4jOvR+Ni9VP0CZet24
         UucKsZd/By9NDQVuv6KNx/Jls7WvRf7rPiulcTN2Bng2uUZGACBl6V0HsfHzikqqiGBy
         kPAkLkGV6WGcwBCU9Z7I4kRbLbAnptNDYBGMfM8Z3PhuBqzJ4jMcmAPVrncoIFn7sANO
         nrW/GmZ3IQTL92YnFdFeJFvLUr326A23gluPiyofUMUhdbZqmdhol8ej6HyJPdaINJ4W
         Z+7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UxHqcjqLV5SMzyyvdPn90TGI1ZaTqe/aoS8WhMGAgLo=;
        b=tyxs70LfUxf9JGBSaeg0bTvgoTSOnCkv6H8t1L7uhaWHIN3KQuX4hPz2r3Fyd+sgvP
         NsE8Wf6U2xDEGvLU82sTyyST8JirzNLUHPQor0C3F3ntH83/qVfuxcuy4DAleiZKKDhG
         UuYF1QKRJXp9oOqAjrTOi/DpBh8fQtth+UdqN7a5Ju9Tm2coY6729xxbqzZG/TrXKWk0
         JZMxb2iqVKiryZS5CPfj+4nSUdkNhpfshfeNew2M195a3AkUrFN35qVQYSlL/8mHHV6O
         SvPumVwf3Dj2F8X1PSl/awCUpgmtYAd01o67qdzrMbv8PRIqwirJ6slOHBAkHnAQlo+n
         wsmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sw9SXPNg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id rj14-20020a17090b3e8e00b00200aab9c815si346pjb.0.2022.09.09.01.44.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:44:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 130so1648738ybw.8
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:44:31 -0700 (PDT)
X-Received: by 2002:a25:d686:0:b0:6a8:e9a8:54f7 with SMTP id
 n128-20020a25d686000000b006a8e9a854f7mr10920047ybg.611.1662713070956; Fri, 09
 Sep 2022 01:44:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220909073840.45349-1-elver@google.com> <20220909073840.45349-2-elver@google.com>
 <CACT4Y+Zuf+ynzSbboTAN0_VLedeVErO6qm49H4YzuR1e8EgJUQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Zuf+ynzSbboTAN0_VLedeVErO6qm49H4YzuR1e8EgJUQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Sep 2022 10:43:54 +0200
Message-ID: <CANpmjNOz9bomQv=Zem6kw9xamhp1yPKf3iCrVvhkzHxE2pcp0A@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kcsan: Instrument memcpy/memset/memmove with newer Clang
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sw9SXPNg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
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

On Fri, 9 Sept 2022 at 10:38, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, 9 Sept 2022 at 09:38, Marco Elver <elver@google.com> wrote:
> >
> > With Clang version 16+, -fsanitize=thread will turn
> > memcpy/memset/memmove calls in instrumented functions into
> > __tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.
> >
> > Add these functions to the core KCSAN runtime, so that we (a) catch data
> > races with mem* functions, and (b) won't run into linker errors with
> > such newer compilers.
> >
> > Cc: stable@vger.kernel.org # v5.10+
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Fix for architectures which do not provide their own
> >   memcpy/memset/memmove and instead use the generic versions in
> >   lib/string. In this case we'll just alias the __tsan_ variants.
> > ---
> >  kernel/kcsan/core.c | 39 +++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 39 insertions(+)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index fe12dfe254ec..4015f2a3e7f6 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/percpu.h>
> >  #include <linux/preempt.h>
> >  #include <linux/sched.h>
> > +#include <linux/string.h>
> >  #include <linux/uaccess.h>
> >
> >  #include "encoding.h"
> > @@ -1308,3 +1309,41 @@ noinline void __tsan_atomic_signal_fence(int memorder)
> >         }
> >  }
> >  EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> > +
> > +#ifdef __HAVE_ARCH_MEMSET
> > +void *__tsan_memset(void *s, int c, size_t count);
> > +noinline void *__tsan_memset(void *s, int c, size_t count)
> > +{
> > +       check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);
>
> These can use large sizes, does it make sense to truncate it to
> MAX_ENCODABLE_SIZE?

Hmm, good point - that way it can still set up watchpoints on them.
I'll do a v3.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOz9bomQv%3DZem6kw9xamhp1yPKf3iCrVvhkzHxE2pcp0A%40mail.gmail.com.
