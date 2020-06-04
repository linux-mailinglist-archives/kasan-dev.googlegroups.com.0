Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54H4T3AKGQERCRE2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id EAF5A1EE68A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:23:52 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id y16sf4050842ilm.21
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591280631; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cYEwGFt+NF00+yD5jEtLLa0poMXOTkY9TLj0M1Grllk6XAmhTSb5Hcl8pa/ltDiEZ
         QWQChh521Jn1zDq+3GAjC8WGp9s2h+/vVwxCN44R7BO4SOjdeAYQF4/VWlCvqCIdcXhO
         dG2I6yOxnPkqqocSL97ar3xl34l7XJ69kGhhnGIbDixX6xsyAXFsIJnsy5lP8DmbfF5S
         DW/KtXtX2FIC5FRbxbc/b9aBjNegsZN+wbDoLvmWchbRon6KZiUxHIFnwRSzI14RyM8x
         ApS1VSZZKcIwzCOp5fe0Y8o8N1Rqo49My1K75pKqNhxLasJrzBeIwIZYpoD/ldvY7crJ
         Txmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7jLeQl52rpqs5eDFXjkflQCspfoDjhJo0e1dRo/ZfvQ=;
        b=zqESb8znBYipNn7eNzcXjVKj8sp7ACKkeTzuM9QwNXAL5QwKykVf4qLJR4OPLJe9b+
         2yPHg7fg8ZCr0RUB9MxSM5MemwQlCRSaDUUBYNFYT1oi+XtZC6a4xXNxuy9LjLoOjja9
         Tcjo3Wn4ZcqMp5iZFkO0MWKSlAZKnoSJGvGlbv5lVyB7ZKdpWxCTMcCgVN9Z3RZwT8fz
         EMhgGK15A6cJFInhrlnfB/M+0h58QhxxcuZLan8hUNrXvOfXQm6E7cPC8OGb3jvt5aQE
         dvavVf29X1HClIiLrX0YRm1yl3izJtN2LhC0usjFi6KUKyY1CkRc8NtIIYmBSM7HPvES
         Jw3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HSfqxACh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jLeQl52rpqs5eDFXjkflQCspfoDjhJo0e1dRo/ZfvQ=;
        b=TAaNmFShbA29AB0iN/0xF7vvrg3c9ADX1OOCcJTCLrY35K1kJzrObn/Vg+tZhgM2lX
         NAuIkAl3JB7ZPEUBgMjDgpLl0yGNyQ6cq/SQuYaf7/HdO2DdxLS1xNdwE3hQ0XEeLyYx
         R/Bneo20ynK9UUoCxa1ZyCrsbRNUoP1zY+IiuLcE/hhFVb0X1Czb9mDsDPDypn2Ev/1L
         +F80I9ZTUdt9angpvTX7DPsCwuIT4GmwWAjcBGqalDHQFnlXvk1RhbjFAXhQqXYByGby
         hG1ddEJbbSH3leA2NrUFFOPK6uJQS+mp+YzAnrQXxMYGmltSBQswnTRwSNbg95rkIgvn
         la7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jLeQl52rpqs5eDFXjkflQCspfoDjhJo0e1dRo/ZfvQ=;
        b=Ph4qZ4eQmQ65Hwiv8jCy+hT2mT/Pd/lBIVejTU4IpRk899ek6pfuuOm+fZBuJgRDZ0
         6hvf+mec8rDY4Wov8LyZ5UjfIHLTez1w4KnZV4+DR6DrLVA9xbhS6Kba1dlgUJ6NEA+0
         iH+2ijsRZiPtUGaLuqyrAC9NzTEHHUVlksa7IfX7et2Scp1ypvJ6A2ZIpImXDacobv0m
         CtwZGQM3qu60JKNkZk6LP/0bT8Ie6oKEfdkHvYvvRhxahxNU8Xj5uX38IPENwpG/ZE9F
         U/7Ech/soImHYkAVfTMdVufcQ6KDhAIzX5M20/M02VZ8wtxUpNDVRA9LphMExf+yYP3J
         plqA==
X-Gm-Message-State: AOAM532j4q9jjht9TaNYYcF2hzsJp/pwZtms4xxFJIO5SGBBsLZQ+kDv
	Gl0r0DcSsR4RJ8DrLvzniCI=
X-Google-Smtp-Source: ABdhPJzMNRfIW5kNt/ClOggyY4lmpEILWoCgFYK2QxSidyplkP0MmyuxfqWxjZc1yc7X6c2suIL/eg==
X-Received: by 2002:a92:d185:: with SMTP id z5mr4415702ilz.167.1591280631737;
        Thu, 04 Jun 2020 07:23:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a784:: with SMTP id e4ls767381jaj.1.gmail; Thu, 04 Jun
 2020 07:23:51 -0700 (PDT)
X-Received: by 2002:a02:b782:: with SMTP id f2mr4485416jam.91.1591280631370;
        Thu, 04 Jun 2020 07:23:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591280631; cv=none;
        d=google.com; s=arc-20160816;
        b=wttS0PshZUtZ/JOULLBpIs5hJLTMVJtTMMM9Yrf1NvMn6sE8Qlik1rPA8cyYVWfORa
         j2fTcbkGdRa9tx0Th/mrZpToKWT2yZX+UEToW1UVEfNOnN4f6fSb9Dc/uV/4tClTOKv6
         RHPm0KDOeSU1eddI/Yhw/WKf0jskYdYBcjOP90uxEENhouvEinF+gDpFBwjdxJQTK/2B
         SANqMv/cFvwFUZNkL2kSBcMecHiIUdnDcqsClFHQl0YoX0Z+w29VS+SKZSkD555qeGT2
         lPka3g3y0i91Kkb9ntZ43vKh8On/foeFFDGpT9TRwp7MudmJsxUoUcg+vhEj3YXth+3T
         MijA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0yy5MHljbkaYpaeAQHYcaCMNZgb1qOOCz2cvx6JmiYQ=;
        b=UR+JJVLRS6rzXiBYsbQNXqFH+UxbBDdpdlFAzFTD+HEjj0ZgzNNbmK7Ir0OD7Gl05o
         JIR4oBYhiukEsyE2RF5OvkKX3BYgAwvpj+uffL1l6Sq/RNOQ29J4McFtIHbc1m5sJJp6
         SeaxDtyY0CbrreDWIT6jmuAgmY8gd26wldrY+1EtHQhuHRRvkRgyi/7ZKVJihHoBowoC
         6/s+WjPWj4HHtzT0Kab6VyxP0NtG1Mo8oeFb1krSkPBd1vmsDGiEvG92+v/OkmyiU3rb
         k7K2S7GZ3DJP6AFWwaY2gj3gaz0lTaSk/BXNdrMKvByyX0idcqOzUSTQ4r2XyGctY9Mx
         vzYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HSfqxACh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id x10si71224ila.3.2020.06.04.07.23.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id e5so4856808ote.11
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 07:23:51 -0700 (PDT)
X-Received: by 2002:a9d:6958:: with SMTP id p24mr4127585oto.17.1591280630632;
 Thu, 04 Jun 2020 07:23:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200604095057.259452-1-elver@google.com> <20200604110918.GA2750@hirez.programming.kicks-ass.net>
 <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
In-Reply-To: <CAAeHK+wRDk7LnpKShdUmXo54ij9T0sN9eG4BZXqbVovvbz5LTQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 16:23:38 +0200
Message-ID: <CANpmjNML7hBNpYGL81M1-=rrYn5PAJPTxFc_Jn0DVhUgwJV8Hg@mail.gmail.com>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HSfqxACh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 4 Jun 2020 at 16:03, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Thu, Jun 4, 2020 at 1:09 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Thu, Jun 04, 2020 at 11:50:57AM +0200, Marco Elver wrote:
> > > The KCOV runtime is very minimal, only updating a field in 'current',
> > > and none of __sanitizer_cov-functions generates reports nor calls any
> > > other external functions.
> >
> > Not quite true; it writes to t->kcov_area, and we need to make
> > absolutely sure that doesn't take faults or triggers anything else
> > untowards.
> >
> > > Therefore we can make the KCOV runtime noinstr-compatible by:
> > >
> > >   1. always-inlining internal functions and marking
> > >      __sanitizer_cov-functions noinstr. The function write_comp_data() is
> > >      now guaranteed to be inlined into __sanitize_cov_trace_*cmp()
> > >      functions, which saves a call in the fast-path and reduces stack
> > >      pressure due to the first argument being a constant.
>
> Maybe we could do CFLAGS_REMOVE_kcov.o = $(CC_FLAGS_FTRACE) the same
> way we do it for KASAN? And drop notrace/noinstr from kcov. Would it
> resolve the issue? I'm not sure which solution is better though.

Sadly no. 'noinstr' implies 'notrace', but also places the function in
the .noinstr.text section for the purpose of objtool checking. But: we
should only mark a function 'noinstr' if it (and its callees)
satisfies the requirements that Peter outlined (are the requirements
documented somewhere?). In particular, we need to worry about vmalloc
faults.

[...]
> > > -static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > > +static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > >  {
> > >       struct task_struct *t;
> > >       u64 *area;
> > > @@ -231,59 +231,59 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > >       }
> > >  }
> >
> > This thing; that appears to be the meat of it, right?
> >
> > I can't find where t->kcov_area comes from.. is that always
> > kcov_mmap()'s vmalloc_user() ?
> >
> > That whole kcov_remote stuff confuses me.
> >
> > KCOV_ENABLE() has kcov_fault_in_area(), which supposedly takes the
> > vmalloc faults for the current task, but who does it for the remote?
>
> Hm, no one. This might be an issue, thanks for noticing!
>
> > Now, luckily Joerg went and ripped out the vmalloc faults, let me check
> > where those patches are... w00t, they're upstream in this merge window.
>
> Could you point me to those patches?
>
> Even though it might work fine now, we might get issues if we backport
> remote kcov to older kernels.
>
> >
> > So no #PF from writing to t->kcov_area then, under the assumption that
> > the vmalloc_user() is the only allocation site.
> >
> > But then there's hardware watchpoints, if someone goes and sets a data
> > watchpoint in the kcov_area we're screwed. Nothing actively prevents
> > that from happening. Then again, the same is currently true for much of
> > current :/
> >
> > Also, I think you need __always_inline on kaslr_offset()
> >
> >
> > And, unrelated to this patch in specific, I suppose I'm going to have to
> > extend objtool to look for data that is used from noinstr, to make sure
> > we exclude it from inspection and stuff, like that kaslr offset crud for
> > example.
> >
> > Anyway, yes, it appears you're lucky (for having Joerg remove vmalloc
> > faults) and this mostly should work as is.

Now I am a bit worried that, even though we're lucky today, with what
Andrey said about e.g. kcov_remote faults, it'll be hard to ensure we
won't break in future. The exact set of conditions that mean we're
lucky today may change and we have no way of checking this.

I'll try to roll a v2 based on the "if (_RET_IP_ in noinstr section)
return;" and whitelist in objtool approach. Unless you see something
very wrong with that. And I do hope we'll get compiler attributes
eventually.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNML7hBNpYGL81M1-%3DrrYn5PAJPTxFc_Jn0DVhUgwJV8Hg%40mail.gmail.com.
