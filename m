Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVD3L3AKGQED6CALWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6525F1EC162
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:51:56 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id l25sf8422165pgn.8
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591120315; cv=pass;
        d=google.com; s=arc-20160816;
        b=bHWYCNOckpoAY5hWH4nN45J0zMyv83QZxJgUzPLM7mEw011PwNDkWCbrQA+a2iP3cn
         PqCwXd0g5jbp7dTSB5BDOmhiVvOBIHzfEGI9RWR96OUfUPS41dEX1sqdMAhEiMIk3xLL
         Hzun6fmq5VcaE7oEuYtt8HaloR3kvddLXRbutFbB05ZuXv0CDpw8ZvXtS3orE67fclbH
         uWXdOt9E3TKKJTi0tADnKBr+0XPiZs7g+A88kaFRYUJcYRcCjTCosMsElehBFj6+2p4X
         xnkJVJuhhhV7eyc5ijgGcSblpmIzTRHU+mlFXvKfrS8fvbcoJwBnMTpJSODjAIca+9gi
         jgHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HC8PeBdUI/u+pTNArR96EGBS8/hThQHRQV/VI4ntjvs=;
        b=QE7zIDvKwpifcIdwg7y/Loc+iesCLI+V8z+udFfWB2zM86Ol0hHJ06rU8ZamQL+krV
         O58EsFI/LM7tqDMrcmW8NHG+hP9EUHCvLd0XNeyvHmrAtmuY+97IZ1KxE3Zd6pwYa5Zi
         R8I/qvsoBfkB9RlIaKyI4dBhtB+bE4dmHNFF+mSsuFAzD6smowq/Iqff4Z30WVMA3H3Q
         fFp19AZhCWI9vICEzc/Fx7JawhqWuHIwwf9/oAA6LB+Izr+0RlPNGBAblGB7VQBDvqp8
         gO9B3O02gqft0cwAhWYWZqGMXbN2eROjbkCmWnDmw/fA+6m+d9fI1YvGWl+zoBvbCy8w
         BgLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoqpL1g4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HC8PeBdUI/u+pTNArR96EGBS8/hThQHRQV/VI4ntjvs=;
        b=pmiY4oBVqBACe68jWP9xTHd+zrwXTnQO9VM8pbZb89LJ1OIGTi0y0jdxXVidbybgb5
         ZsPLwPVBpaLeVSzpv/uI2uVK/eOsfc/jSGxpzUv44kMtxAWKeN3Q479g8O8JOIllF6Jh
         xptjB81BbtaznXDkkgDBTbhSMQqeSfMGtFfA4I7qv6XWyPyd4yxLrdR76cWmgkZSHFTh
         gkgD+kiRt19ZDlU6J2pE3ROX56C9paZx5Wq0doYkdiCKpmN4PR8jAlnBzjFaCVQZUo9b
         q6Yn1GKoJ3wc0gt8gKXognANZTuei9ekiw7tZa4Yx+HjVbJ1n24WzGtqRmp9cTt7X5jD
         fsKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HC8PeBdUI/u+pTNArR96EGBS8/hThQHRQV/VI4ntjvs=;
        b=NacZFgvtq4zCNIg1M0etJFDMXHSE12Bfph8qFyxhlg2U8UASB9OY/XCgam9BaaLNFS
         t/wkt/nIvChGpaJVdboe6kZXrjg+QGGqDeCOkLVXcQUInQwzhOMPc1ibPaFVFbpKqHP8
         ljo5dzraw4661GgZ0rJSc2qtliCjoSl0OuctCqHN47LSitE4iQ0AdUcjRsES9JRi8AeZ
         KfQrvb2XFOfkn6QgTTN6/0XUECdMUQYkwOzijhytufPI8wLadpsNGmge1sr0dCDBzM9/
         CVl9pAVSp12eCxqZD7VMgsVUFQr9/jqYAyluWGt8yRn5mthmEqs06dGfff9uJ9uvb5H/
         +7+Q==
X-Gm-Message-State: AOAM533fAg/UDDGF4as9WYjuUdW/oUTCmVwZV/7n/FzY7a2Ch6zr0eZi
	wOwKqo1ZGoYRkk1Q9r9w80g=
X-Google-Smtp-Source: ABdhPJwbr1OJNYKie8hkdFCMw0vsuLkXeLjdwEkNvSxLcYgHrLv85h82P07z0CVAQRMWkb8k1dVQMw==
X-Received: by 2002:a17:902:8b88:: with SMTP id ay8mr26000001plb.235.1591120314858;
        Tue, 02 Jun 2020 10:51:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:94b5:: with SMTP id a21ls1797319pfl.5.gmail; Tue, 02 Jun
 2020 10:51:54 -0700 (PDT)
X-Received: by 2002:a63:1650:: with SMTP id 16mr12428523pgw.23.1591120314362;
        Tue, 02 Jun 2020 10:51:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591120314; cv=none;
        d=google.com; s=arc-20160816;
        b=oi7rIW0XF7EyDxaPhK7qmEzWgnmwYCOFakXZfBudRWZA7/mN5vZW8Wlm/r9IGCeLhS
         z2LgoniVnpJS2glSrSTDH6uZOKAdha33Be7/bTa63aH3UPBKo/rzHQDuM+NEQRyY5m6T
         enCY6IHzT6ib+OJ2ngThB9Wcck/yBmlPmaU/dtwPDa/7WWpyoEDrRrZHaJzJJr+wKv2I
         JZV3RZn4qvUk+d/eYCMgXtQ7rlblG2FGftMetL1d+/TkPdQdFUgjHiqvUM3HXDsoUQDO
         KQjEZjb7B77/I2jel+r3fBQ2M5aK8Tm7I6izAPuL/3LkajdVaYb//1QUllZgjmp8PNiD
         dMTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2z7vnRyBy5ncoXlkW8cnatBQyrXfqejt94sDIEUP2j4=;
        b=UppR+gFh0aJZvgAllj8c/qEAIbz9nM8SvL7rYo4hL5KexY5l0RzQEtYtR8GlohpOyx
         zBbpPBtrZA7/ZFy3xE6DJ8dsmSdDwGwNd+60KOZ0ptmnocoF0rkpiXNnCyYhqrf9tTWk
         Amz5sdtIiifnyksDUoPV8WcnCX6FsPYS6q56Wj3MOD2bcksjJ5AEZNOuIbZcdhTJqBYy
         j7qkDjPHOVRC66LOjQtFKcRPc16sIRXqs/3ZTLP47bDsMzCWw7oEWjofBjGpx42GLpLw
         4lBCr42bM6nNw+MJvumlK66+hCxiy2yUU8QxsFRHH0Le7uUb3z2f4ZRsfWF9U6VbqD0l
         CgMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoqpL1g4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id i15si157188pfd.2.2020.06.02.10.51.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 10:51:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id o7so7153157oti.9
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 10:51:54 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr330184otb.233.1591120313403;
 Tue, 02 Jun 2020 10:51:53 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d2474c05a6c938fe@google.com> <CACT4Y+ajjB8RmG3_H_9r-kaRAZ05ejW02-Py47o7wkkBjwup3Q@mail.gmail.com>
 <87o8q6n38p.fsf@nanos.tec.linutronix.de> <20200529160711.GC706460@hirez.programming.kicks-ass.net>
 <20200529171104.GD706518@hirez.programming.kicks-ass.net> <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
 <CANpmjNP7mKDaXE1=5k+uPK15TDAX+PsV03F=iOR77Pnczkueyg@mail.gmail.com> <20200602094141.GR706495@hirez.programming.kicks-ass.net>
In-Reply-To: <20200602094141.GR706495@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 19:51:40 +0200
Message-ID: <CANpmjNOqSQ38DZxunagMLdBi8gjRN=14+FFXPhc+9SsUk+FiXQ@mail.gmail.com>
Subject: Re: PANIC: double fault in fixup_bad_iret
To: Peter Zijlstra <peterz@infradead.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YoqpL1g4;       spf=pass
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

You were a bit faster with the other patches ;-) I was still
experimenting the the patches, but let me briefly respond here.

On Tue, 2 Jun 2020 at 11:41, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Jun 01, 2020 at 02:40:31PM +0200, Marco Elver wrote:
> > I think Peter wanted to send a patch to add __no_kcsan to noinstr:
> > https://lkml.kernel.org/r/20200529170755.GN706495@hirez.programming.kicks-ass.net
> >
> > In the same patch we can add __no_sanitize_address to noinstr. But:
> >
> > - We're missing a definition for __no_sanitize_undefined and
> > __no_sanitize_coverage.
>
> Do those function attributes actually work? Because the last time I
> played with some of that I didn't.

__no_sanitize_coverage won't work, because neither compiler has an
attribute to disable coverage instrumentation. I'll try and add this
to compilers, but KCOV_INSTRUMENT := n is in the right places right
now it seems. More on that in the patch adding this.

> Specifically: unmarked __always_inline functions must not generate
> instrumentation when they're inlined into a __no_*san function.
>
> (and that fails to build on some GCC versions, and I think fails to
> actually work on the rest of them, but I'd have to double check)

We'll probably need to bump the required compiler version if anybody
still attempts to use these old compilers with sanitizers. The precise
versions of compilers and what mixes with what is a bit of a
nightmare. For now I'd just say, let's add the attributes, and see
where that gets us. Surely it won't be more broken than before. ;-)

> > - We still need the above blanket no-instrument for x86 because of
> > GCC. We could guard it with "ifdef CONFIG_CC_IS_GCC".
>
> Right; so all of GCC is broken vs that function attribute stuff? Any
> plans of getting that fixed? Do we have GCC that care?
>
> Does the GCC plugin approach sound like a viable alternative
> implementation of all this?

I don't think it's realistic to maintain a GCC plugin like that
indefinitely. We can investigate, but it's not a quick fix.

> Anyway, we can make it:
>
> KASAN := SANITIZER_HAS_FUNCTION_ATTRIBUTES
>
> or something, and only make that 'y' when the compiler is sane.

We have all attributes except __no_sanitize_coverage. GCC <= 7 has
problems with __always_inline, so we may just have to bump the
required compiler or emit a warning.

> > Not sure what the best strategy is to minimize patch conflicts. For
> > now I could send just the patches to add missing definitions. If you'd
> > like me to send all patches (including modifying 'noinstr'), let me
> > know.
>
> If you're going to do patches anyway, might as well do that :-)

I was stuck on trying to find ways to emulate __no_sanitize_coverage
(with no success), and then agonizing which patches to send in which
sequence. ;-) You made that decision by sending the KCSAN noinstr
series first, so let me respond to that with what I think we can add
for KASAN and UBSAN at least.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOqSQ38DZxunagMLdBi8gjRN%3D14%2BFFXPhc%2B9SsUk%2BFiXQ%40mail.gmail.com.
