Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHV3TUQKGQELZQXPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FC6F71D1C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 18:49:18 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q9sf26273488pgv.17
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2019 09:49:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563900557; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZUkZNzQmBeLF0LfEy1v4Bay9JSLab12Z8FA6wHvHX5GCZDKtEB+F6itT362KoI2eNg
         v0SzLCZnyrbo/u+uPuAWfnQnQ8PF/4m5PGfST6lMQSEr6drDujIyfj285SKI+i+m9nvP
         b/apXP2D/7vsIP5rQ7Pv/ceqvlQ2NNu2UHVPpbRJECBEgEDKSR/zTz2RNxcZoheFCS8Q
         +rDbZwyulSuBvau1yVcCnUWx/2YkNYBIEv2GBnN7Dm3cYR5+vcxWXWWA/E5biMaLshqr
         pLlcumDWe7w29nwdsJ4lFYgQve6E6p6E+I+hEMgy20Rt4CYxJIzecpyIHka/ifATLk6b
         Qo2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oA/e76P0uLmdPs3o4rEBrInxVwgBPXNkusjS/VKrxts=;
        b=TiG7r4WfNZt0FwCQFNquq+V2QvkQf3LDpYN0a4fEmXrsHiLp9KJ0Gc6B014r33pwMD
         eeP/uLg0/m73JAQRwaUwDYTHNAez9mOIkaM5rozdTHmqtxnl1VlKq1uUu8vWEyc0kHr6
         pNs6sQqfqn0+6Z/V2n2pG8sZ4FICnRmCjhkzPUU+HsaSoQU+BeXnAEWVvu0au8WPlCpw
         xXDgHlDMBje+hh/FCBUqTiHr2AE059zLoPKkcklzRITUiNFvsyjlFCeQMKrC7ooeiBn7
         8kxUtaeo/TcN2PdUIGMPlFdlHysSvz7AuEamP9Fg1XmMa60tq1GcQF/gzk5+oMnQBQxu
         IniA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XRAh43Dh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oA/e76P0uLmdPs3o4rEBrInxVwgBPXNkusjS/VKrxts=;
        b=QsgB5jgNAOAGCrPKK5e0/2MWnXuM4FjdG1JvcM1Va4B9rEgUbM2gtez/6g2Ru4BjTc
         g4+LDcBumC8iwRw2ZUwBLoCWFDd7SvsQjmtNEUv1uUY4uLhhwedhu9Aqgx9U/A5B/tYQ
         ETTSAIdaI6ipriqs4t3wdwZXIx0vlerBx5V6T8cFnYgFbZLPTh+ioBdLh1KcIgctSHFd
         QouzGKgRjZ+SBasM5rbjRQwk34wRcU6D2HT80Dho/j2d3K1VlzCqSFnn5thovc9GNcqu
         okHTFHYFTBgQtwN1ivOMZ2UVES/muXs2DEH1VaSsKzLiXyzeDCMbVynUaf3qMXmMZcwK
         +iSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oA/e76P0uLmdPs3o4rEBrInxVwgBPXNkusjS/VKrxts=;
        b=JObaPohNb76/8ALbdqGe1BL10Tstb6RAVjlET+GvzsYSZ6C2ODXPQf8m0KjqPFodAn
         t1Jc+lRUkf7rJGRZXkb/6a4Xl/dYqN0E62rB8shQF1+VGYWS4ZEO0od7sHdrAFQdFYAo
         fPg5kUNWe4P1hL3oDvBdxq2L7xIEnaQVO32MDAXJQH75ac4NINJCLbtECqGDhpF2p29Z
         aCTQf6NeIzPkmsJhvb+U32LCuD4azFmo8dZzda1wUpNNqv3eCNiWfVP7W0oK9aVwd67+
         cOb/1ST17vMhw+J6OZF7LQ2P8eUWeiFTwoqjTTvIw/Trx5khlqDQgiKui9vL8k2CnZzN
         9xBA==
X-Gm-Message-State: APjAAAVtVgJd74+Ou94B1Z1/NRFglanPRi5WqPK7C4mm/7l6KPRf7D/8
	j8cbCYNw7cdSyHbzSh5u7eg=
X-Google-Smtp-Source: APXvYqxg1EQ/o6iITxPt/aFP7TsAR2QBaM90JgATkocv7w/AGU0Jhq1xo1tBGbUCopO4SyRelBtV3A==
X-Received: by 2002:a63:d555:: with SMTP id v21mr55035666pgi.179.1563900556740;
        Tue, 23 Jul 2019 09:49:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:62c9:: with SMTP id k9ls505370pjs.2.experimental-gmail;
 Tue, 23 Jul 2019 09:49:15 -0700 (PDT)
X-Received: by 2002:a17:90b:d8a:: with SMTP id bg10mr83527743pjb.92.1563900555849;
        Tue, 23 Jul 2019 09:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563900555; cv=none;
        d=google.com; s=arc-20160816;
        b=bv+GmTUQDKU03rB9KSys26NMQvaOTxEp/UnLXquwcDUBavTxuhIqzDipO3urjOGLAS
         VBf9E9iAe4+V5TzysmpN8iE8PWCEma/k94wF+4yl1KFkfLAVh6orAHp0RVtuST5rrPJg
         3T8mVhpWsBgoanHmD1iShjvN7NurRO5UUVqUuYWtoB71R8C1ZHo7kW2T1eyvIkcUsoEa
         zc4bKESWx6zhspfU5fFww8svtP7xLhLEpYqiV3fR6MnDTj1VMy8MIxOgfHdm7iU5yP8l
         ZXNjuK/5+Ec+662OyMoQ17952021Hbo4h4KkHKZp5Ao4qa4awqdsCYspoabM6eDWN4Po
         0vTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P/ukJIx+SOx9JE2DP2ABaOJWk92MtaCXggShecwUP5o=;
        b=kSl3u1+u2QJ2sgATDHaKBV0u8wzJ5iUx774MPkNL0Q0tK4K+leesIVg5Ej2hKhBJTo
         oKFcS5+OyptqKAxFfRriBxfIuZZSlB78Dc1CWHUc8bukF9hkvVvwHpmciMm45rRxT6Oo
         IFSxqXAMsSP0V4bj6mCcPYXABvHLVxz8OdoFsK7y3oE1MqaoBLak1HjLx//AV/1fIkH7
         TfneJ648ocIk2qkR54G4tkUKVfMppAzS+ndqOKgPPghhjkAZJEnfV335pATjjxRYH9Hd
         v0OH5FRL/SXw6f/ky48r0deRscfnzyZKf/cgLReN5YIQk2wnSFqZqbBodjMbJm+Uy2kT
         19Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XRAh43Dh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id z9si1988572pjp.0.2019.07.23.09.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jul 2019 09:49:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id d17so44762848oth.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Jul 2019 09:49:15 -0700 (PDT)
X-Received: by 2002:a9d:560f:: with SMTP id e15mr22483518oti.251.1563900554830;
 Tue, 23 Jul 2019 09:49:14 -0700 (PDT)
MIME-Version: 1.0
References: <20190719132818.40258-1-elver@google.com> <20190719132818.40258-2-elver@google.com>
 <20190723162403.GA56959@lakrids.cambridge.arm.com>
In-Reply-To: <20190723162403.GA56959@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jul 2019 18:49:03 +0200
Message-ID: <CANpmjNPBNUQXoPUNw46=iieH3SS1Pk8PxNvQ1FPdNCoU4g8F2w@mail.gmail.com>
Subject: Re: [PATCH 2/2] lib/test_kasan: Add stack overflow test
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XRAh43Dh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Tue, 23 Jul 2019 at 18:24, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Jul 19, 2019 at 03:28:18PM +0200, Marco Elver wrote:
> > Adds a simple stack overflow test, to check the error being reported on
> > an overflow. Without CONFIG_STACK_GUARD_PAGE, the result is typically
> > some seemingly unrelated KASAN error message due to accessing random
> > other memory.
>
> Can't we use the LKDTM_EXHAUST_STACK case to check this?
>
> I was also under the impression that the other KASAN self-tests weren't
> fatal, and IIUC this will kill the kernel.
>
> Given that, and given this is testing non-KASAN functionality, I'm not
> sure it makes sense to bundle this with the KASAN tests.

Thanks for pointing out LKDTM_EXHAUST_STACK.

This patch can be dropped!

-- Marco

> Thanks,
> Mark.
>
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: Ingo Molnar <mingo@redhat.com>
> > Cc: Borislav Petkov <bp@alien8.de>
> > Cc: "H. Peter Anvin" <hpa@zytor.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Mark Rutland <mark.rutland@arm.com>
> > Cc: Peter Zijlstra <peterz@infradead.org>
> > Cc: x86@kernel.org
> > Cc: linux-kernel@vger.kernel.org
> > Cc: kasan-dev@googlegroups.com
> > ---
> >  lib/test_kasan.c | 36 ++++++++++++++++++++++++++++++++++++
> >  1 file changed, 36 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b63b367a94e8..3092ec01189d 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -15,6 +15,7 @@
> >  #include <linux/mman.h>
> >  #include <linux/module.h>
> >  #include <linux/printk.h>
> > +#include <linux/sched/task_stack.h>
> >  #include <linux/slab.h>
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> > @@ -709,6 +710,32 @@ static noinline void __init kmalloc_double_kzfree(void)
> >       kzfree(ptr);
> >  }
> >
> > +#ifdef CONFIG_STACK_GUARD_PAGE
> > +static noinline void __init stack_overflow_via_recursion(void)
> > +{
> > +     volatile int n = 512;
> > +
> > +     BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> > +
> > +     /* About to overflow: overflow via alloca'd array and try to write. */
> > +     if (!object_is_on_stack((void *)&n - n)) {
> > +             volatile char overflow[n];
> > +
> > +             overflow[0] = overflow[0];
> > +             return;
> > +     }
> > +
> > +     stack_overflow_via_recursion();
> > +}
> > +
> > +static noinline void __init kasan_stack_overflow(void)
> > +{
> > +     pr_info("stack overflow begin\n");
> > +     stack_overflow_via_recursion();
> > +     pr_info("stack overflow end\n");
> > +}
> > +#endif
> > +
> >  static int __init kmalloc_tests_init(void)
> >  {
> >       /*
> > @@ -753,6 +780,15 @@ static int __init kmalloc_tests_init(void)
> >       kasan_bitops();
> >       kmalloc_double_kzfree();
> >
> > +#ifdef CONFIG_STACK_GUARD_PAGE
> > +     /*
> > +      * Only test with CONFIG_STACK_GUARD_PAGE, as without we get other
> > +      * random KASAN violations, due to accessing other random memory (we
> > +      * want to avoid actually corrupting memory in these tests).
> > +      */
> > +     kasan_stack_overflow();
> > +#endif
> > +
> >       kasan_restore_multi_shot(multishot);
> >
> >       return -EAGAIN;
> > --
> > 2.22.0.657.g960e92d24f-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190723162403.GA56959%40lakrids.cambridge.arm.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPBNUQXoPUNw46%3DiieH3SS1Pk8PxNvQ1FPdNCoU4g8F2w%40mail.gmail.com.
