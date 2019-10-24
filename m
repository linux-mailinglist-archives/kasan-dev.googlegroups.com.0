Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOMJY3WQKGQEYASJDMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C619E2FB6
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 13:02:18 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id w9sf18271470ybg.17
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 04:02:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571914937; cv=pass;
        d=google.com; s=arc-20160816;
        b=fIu+aSPQKUb5v06M1F3vk4nfisaT9P0iY1KKpLm4i2JknRF/4KdNbe/juFQP2iCcCO
         EkBRiNbThN4VblLBgAZ9L5R7BX5OUc2wQuY6acBUdPq0beUAAsP/IVnPwAAmFf/K/A9c
         9ChorYtL9crCtacLJOkgOdhwG9s8pHD5tbSAkTIut46TQwrRKRSaUWIaw0XbzoQhs2fa
         2YWtmG+RxthwQL6bUmgiSIBE6jV+1vjKCS/RkqV3NV666IlIQ+sE+rFDLJ7PwXDdCdi+
         GCCwRTVX04Pf3IaR8he1OhvzGZUEXZv/T6FFWZdJ7AV0DACNz9yJb6kYie+g/sgkqYQL
         rJ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ds2Hp+L9YmoOGOIoRN9j5+ygwJdYPur2APJV0aKW5+k=;
        b=GX/HIyVyDM075aCEg/zN2F1/uzedz3R59eYdrqkHQuFgyX4nrpC7cw57LevQzon43+
         nAnAC65Tr1y7RFtv+RRtChGCdC9OtHlRAm1ha1eh1LGA0YtLLUpp2msBYvqsyIYzrFpU
         VjpMKD9QWjS01nZyXQpCXm9xFX3gZUjk89UAgWzAc6j0CfMZwJV4WPM+wuMCHoKVDF8z
         /h/ziaHPwjD9XbgwtTI4l3rIxOqfLvokGVq5T2A8yGSRxN5dBHo3Bn20yqrm1Z5tAOmo
         HYYq0xB1wuzEAzp2jvjiYkfCq5+Wu5yZbgrwpexHkXv5a8Be1Cpjaq5q65IV75ep0GEQ
         xu8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GSxZTUgn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ds2Hp+L9YmoOGOIoRN9j5+ygwJdYPur2APJV0aKW5+k=;
        b=h8My1k86uNLzXU9I0ufF1Xh1tsIg8FnLTezmZ3U2rnRqwJBRQyHTVWgy0Oki5oHNCk
         4GHq5gSYvu3X2oZ82uMU7LsqFcjtP8lK+zwXNeDxXkJRPp3utk1I+7pP+6Z5jBn5TbMe
         gRfhGVRe8I7IDEhsygcMW11zAZMhE2YIet3KCw0VymT9EboT17FQp/Q4QIRR0r9KmqUJ
         I9q8qkk53gXsr5crjOhy31+jENaE7pzJGXbuZtZ4tiDWlaqxZIU+KuxtXUrR9XfJpX+b
         vJ4op6pL/bIdad+EOz+bmT2ftXHVcVPCRq8NSbc009a2fQY+VSzR/zPbFft/+PnB3iqC
         /Rig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ds2Hp+L9YmoOGOIoRN9j5+ygwJdYPur2APJV0aKW5+k=;
        b=ZGVfrGojIaiQeMyVGqGWT+YKaJUJLZYRJQtyHWFPKD9R/BwZqmO9xuEbQbksJ66a+3
         mffrL4Ikl2RTStx1xw35quMm8SewEzMqmZQJkOqhAffnXdr2ybqxIyT+KZs3pVNdWrTr
         TEH2TqspUmYDmmjlCEAsv67lxT9TLavVcuCwWjyRpjAoKgi7CR6IfTWUKUqlQZIe618N
         W0IViyAaPpG5Qn/mM90JMGfKB9jjc0yIrvFSDBpytexl1+0mRI9ygATjy5Y6qhLfs+za
         71vE5nCapcO3uZ7ztU9VN7qIWy+DUH3SS36Q+l5lNMdW4t9+unJIzCIBtqodTV2BcFy3
         YH+w==
X-Gm-Message-State: APjAAAVBqNEH3HvC5XV82o9KQFhPY0znKipeWRIJsaCLNVvruzTYJ5pJ
	b0cTSMJuBKjkOAXHLHwWbLA=
X-Google-Smtp-Source: APXvYqyrmcWUCXojo9WeiRNtp4nnpqM4kU8S4a0GJG0p9TTjIUXfNYntSa4aHrdRelJ6rGtgbzUCLw==
X-Received: by 2002:a25:6044:: with SMTP id u65mr9964465ybb.335.1571914937250;
        Thu, 24 Oct 2019 04:02:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d98d:: with SMTP id q135ls879448ybg.9.gmail; Thu, 24 Oct
 2019 04:02:16 -0700 (PDT)
X-Received: by 2002:a25:3b51:: with SMTP id i78mr10001326yba.186.1571914936775;
        Thu, 24 Oct 2019 04:02:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571914936; cv=none;
        d=google.com; s=arc-20160816;
        b=GIHZlwXicKfKLwaeY4Ei4eH/UnDYm4DVUvibq6Wi0RbSwf7LsRDiAcQQevACdCgpzR
         60jQeb8pvGITuhlLU9CjbD1+so0z4FRvgCAnVlBVD1w2xL8tnFMnh0bHnwFn+c/ZpcQY
         W0hT+dhI67bR6GjlfIeDgwaRvLOGiaki/jPs27vnsLJc7ClUQg2PmeE5OJuhxV3LfUTb
         0X2ENLIetR+q5CLUKL381m7Elde0Mp6WV3Xo53nGHe34DRRfSltXPLaJACN+qfmWiSIt
         hs128t5Z2ZvSpEM+XhtuGJjtmR0rAVA0uwMW0mXAvWp8fDR1Ogq/maMe1cf2Vvmpb550
         II6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wp7j55fCu8VBbV3w6xxbpPhvOdRSu/ha8VU4hcpzHdY=;
        b=hNBd/I/7VVZeR18acPSh7687s6uvL0Xl2IB8tDu1xwDuKDEwXKiGjbKHm+DOJtSJrD
         Kib+PSUtkTtW2oah+fX6Pal1eSKizAut7PHq3VpAxN39PSaMZ4KuyuYSTmY/RrJcpTF7
         MRojVvOOwu6UVL9UkhGcAKIwDuexY3lnlZ9HjQJQjkbyTNIgYnYjiGAF6xyfinlf/umN
         ohq6rFIYRABv3ztEqlSu0F5/edDIEd/sixU6qiN+0GZLOkpihC/+Fe3aNMhTXvPHZKmn
         kAvHfhGLApc1utam7AWPpKaGlPrgm9Pg2wuwIdg2/3jWLx/rzG8fN0bz2UjtGXTj/2K/
         pNFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GSxZTUgn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id l3si983038ybj.5.2019.10.24.04.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2019 04:02:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id b16so9462146otk.9
        for <kasan-dev@googlegroups.com>; Thu, 24 Oct 2019 04:02:16 -0700 (PDT)
X-Received: by 2002:a9d:82e:: with SMTP id 43mr8537524oty.23.1571914935893;
 Thu, 24 Oct 2019 04:02:15 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
 <20191022154858.GA13700@redhat.com> <CANpmjNPUT2B3rWaa=5Ee2Xs3HHDaUiBGpG09Q4h9Gemhsp9KFw@mail.gmail.com>
 <20191023162432.GC14327@redhat.com>
In-Reply-To: <20191023162432.GC14327@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Oct 2019 13:02:03 +0200
Message-ID: <CANpmjNOOT+KR7m8KpETk1czyJLr3TeHsvvejwyuY3JXKr=eajg@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Oleg Nesterov <oleg@redhat.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GSxZTUgn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Wed, 23 Oct 2019 at 18:24, Oleg Nesterov <oleg@redhat.com> wrote:
>
> On 10/22, Marco Elver wrote:
> >
> > On Tue, 22 Oct 2019 at 17:49, Oleg Nesterov <oleg@redhat.com> wrote:
> > >
> > > Just for example. Suppose that task->state = TASK_UNINTERRUPTIBLE, this task
> > > does __set_current_state(TASK_RUNNING), another CPU does wake_up_process(task)
> > > which does the same UNINTERRUPTIBLE -> RUNNING transition.
> > >
> > > Looks like, this is the "data race" according to kcsan?
> >
> > Yes, they are "data races". They are probably not "race conditions" though.
> >
> > This is a fair distinction to make, and we never claimed to find "race
> > conditions" only
>
> I see, thanks, just wanted to be sure...
>
> > KCSAN's goal is to find *data races* according to the LKMM.  Some data
> > races are race conditions (usually the more interesting bugs) -- but
> > not *all* data races are race conditions. Those are what are usually
> > referred to as "benign", but they can still become bugs on the wrong
> > arch/compiler combination. Hence, the need to annotate these accesses
> > with READ_ONCE, WRITE_ONCE or use atomic_t:
>
> Well, if I see READ_ONCE() in the code I want to understand why it was
> used. Is it really needed for correctness or we want to shut up kcsan?
> Say, why should wait_event(wq, *ptr) use READ_ONCE()? Nevermind, please
> forget.
>
> Btw, why __kcsan_check_watchpoint() does user_access_save() before
> try_consume_watchpoint() ?

Instrumentation is added in UACCESS regions. Since we do not access
user-memory, we do user_access_save to ensure everything is safe
(otherwise objtool complains that we do calls to non-whitelisted
functions). I will try to optimize this a bit, but we can't avoid it.

> Oleg.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOOT%2BKR7m8KpETk1czyJLr3TeHsvvejwyuY3JXKr%3Deajg%40mail.gmail.com.
