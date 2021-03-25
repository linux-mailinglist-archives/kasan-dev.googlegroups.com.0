Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOT6KBAMGQE2E3JO3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 75B0F34952B
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 16:17:54 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id u12sf4227754pgr.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 08:17:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616685473; cv=pass;
        d=google.com; s=arc-20160816;
        b=i/kjFzaqcfqVc7S+cNsodDl0LZHliXGglIHfvYL3OK9PodPliRZ5BFXhWAaNzHHKQ6
         uUuRvq/wYtMmkTKndUfnf7XW70FI4ZphhyKJjasFyhiT6Q4OuiNxTOIYoTR+8TxtymlV
         rH0Ik/ysCqPPuhPMnhejF+0nE0wpolBDRE5+/HQFwqbSWQemHnya43fXMelDN/GC6hsA
         cb8ulXdPfrYQ/zdFaEO255BPn5eF4vOVDEUDOqIUbqNEmvjvjm0pZp4y9Y1DfD49PTTB
         9Hyar7pdr8mof8vd7QDJWRWq4GrV4KqIjfk7Xk8fUDhrfcTXP4msdHV0kbXtP6SIypjS
         Pemg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y0VffVsAdsfBsM4v1uAVJdliV+i+NMAG5kCL4Yj2ByE=;
        b=IqP+CLDqU308jEYX6Lmk7kP79aAOpU02KxFl1DTAh5IcdOTGTueh7fz95hYFOzbvm4
         TE1p5LbytHdxAH/O56X4mGtsQJGpPo47Op08gx5ie/RapLrHpvuZNyAlWai2lRqP1yiT
         Srk6SR4KUEj6x3WW7RjcoiVQjaZlFeiDO1Da0dTbjKutfqLXew1AuxDoNKqXnHCnBl1r
         1VJXUL4Bp+N39jLMiQgPszwg51F3ctxo9Mv4W/I/WA8TnDMaa1v8Q9eaXyXgG07k1bgg
         gBMROWZt0CjesRP0RNbwx/55qy4h67uDEji5YIGxzt5FAEvBAq4KCgBlPZrZij6UuE9A
         jNeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=us6aw6Ol;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y0VffVsAdsfBsM4v1uAVJdliV+i+NMAG5kCL4Yj2ByE=;
        b=LczLQD4/4ku1j8D/E+JZR/c5RXzHe9am+iYI7z6TPZIvoXhEs6IQHTm+/DTem9WwZ6
         yUfyODXDZkB2X5v2WYx1b9hvulOTpdeIW4uFS9fgr+kOxCtwfq+TK7N8yTiN78gDm1Fb
         lEuFSCf9/fs5oaA1+1dcGgmusecet5XHAAoVs1QBxNQyazI2kjlNK9QXJqTx6E7l+QFU
         1DVB1FbgdotTlkOXWjGoeII6S6tr5fVPxG6fax0l/uQ0ewFOUHnEJqYJsNA7jZ3C6KMp
         xl6hLQSZEZIVENe11b7ogyxwI0L00iTiI6vMyPnfvtXNdPsBy6f1j5nBaAj4WJu+0sTs
         U9RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y0VffVsAdsfBsM4v1uAVJdliV+i+NMAG5kCL4Yj2ByE=;
        b=Uxb87NIwjOFXmKpmdyMr8VvYln8+U8eL94fWsHdp2oQa70SKC/czh5CcV8DYMCvdsX
         QidvhtwERNAGoKSlSypTJupqJs4eaI7hFjVqGe/UkHHAjIq0DqfiCGsWucKc73GCqNur
         Qdb45d2ATxr08I2PwYNG3LqMr62EXt4uPoYZWEzPRsPV+ZDJMiov3dT8KGGV4/JNM2Lp
         vmRQ+wN4I7vgybz7YqgEiHJnxxnxwNChuRSe0/os6SE/yD0sYaT3rKrdHMTT7KtJMdW4
         4vT06uAJCUnzGWgNkhmcaTBxrXIoAkRoZaGugO3RFx+KMyTSiWnq/Pt6SZhrt8KH0RLW
         3VsQ==
X-Gm-Message-State: AOAM532SeDk7R7qaSppH+a9SMXJfEgexm9a2GFD1mw6QBIYjBR0wbAwZ
	jjL4+/+G7Ve3362QAOFTP7A=
X-Google-Smtp-Source: ABdhPJwjf/XERqE/XlShNxOyIsr2YQptK9v+idz2XvS79QeKwP/ntkLAePa+mwNdWP5SNv5NYq815Q==
X-Received: by 2002:a17:90a:fd89:: with SMTP id cx9mr9169562pjb.93.1616685473200;
        Thu, 25 Mar 2021 08:17:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb43:: with SMTP id i3ls3411765pli.7.gmail; Thu, 25
 Mar 2021 08:17:52 -0700 (PDT)
X-Received: by 2002:a17:902:c94f:b029:e4:59a3:2915 with SMTP id i15-20020a170902c94fb02900e459a32915mr10070190pla.9.1616685472648;
        Thu, 25 Mar 2021 08:17:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616685472; cv=none;
        d=google.com; s=arc-20160816;
        b=k36aP7zMLynGbqKfjxvs4I2aD2L24vfS0ZljjNe6eoTArbU2CZoDXSatYzebLPnXu1
         M7IitJZB4KmkwNLp6GRuStHgZxxWTWMflaCUjvtkBXIaOgbftMq53FSLDd+AeootU1PY
         muoVcfCvQiHA27ZYvPQR2e/ToDh7RhEZhIk6M2tqjX507tCPnW7vdPTI7IrQvzcS7gSv
         3KbewVYsIvAXOFqremkWYDa/q6Uekkor9ZC3oHxfCjUZ4rmiPkxsWHWjLPmbZXaNahYf
         sFlddpLeuGaET/cFJNu+VVeRqVNwqxUjObqeo11nHrX2frnyyVVA+mnvM49lqC5n4H50
         hz8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EPhq8X0xhYyGxzLncqihu1TYBV4JibjwwPfDPM36hqE=;
        b=0D0l+04l8NTqqsrFtIETjSqni0DEQ8r2rSRa0MsQI0TsXIzRCKFRSuxrjHBXWPhqIH
         mo6MfGylVqXXczDtTaiM5NtPTVI5PfDWXMZ/f8wsz2vjgd3ZNjY1ZSVFuuegXjGXXW7D
         eRjwvAd0N+RHu/0OHzs7cASaNKnA462hT1txDZrraHZepawQKS/Sb4MmHjqOpy5CNSXe
         Op/sEqnHuNhX8kX8sbFaT+oh4Pf2RK+8qdAsYDr3+kdnpAejYmpVx9FQ+3z+T5zWHu26
         31UzXQy1ow84PBxn46SGOdfmZP1G3MUpzkGad/Iwgv6H2ZInTrNGjmXcOf8kRR1xik0W
         4w4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=us6aw6Ol;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id r2si310595pjd.1.2021.03.25.08.17.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 08:17:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id 91-20020a9d08640000b0290237d9c40382so2227112oty.12
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 08:17:52 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr8235464otq.251.1616685471859;
 Thu, 25 Mar 2021 08:17:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net> <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net> <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
 <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com> <20210325141820.GA1456211@gmail.com>
In-Reply-To: <20210325141820.GA1456211@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Mar 2021 16:17:40 +0100
Message-ID: <CANpmjNNcYSGCC7587YzMzX1UpDvTA8ewAJRsKFdzQRdmWEO7Yw@mail.gmail.com>
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on SIGTRAP
To: Ingo Molnar <mingo@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=us6aw6Ol;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Thu, 25 Mar 2021 at 15:18, Ingo Molnar <mingo@kernel.org> wrote:
>
> * Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > On Wed, Mar 24, 2021 at 3:05 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Wed, 24 Mar 2021 at 15:01, Peter Zijlstra <peterz@infradead.org> wrote:
> > > >
> > > > One last try, I'll leave it alone now, I promise :-)
> > >
> > > This looks like it does what you suggested, thanks! :-)
> > >
> > > I'll still need to think about it, because of the potential problem
> > > with modify-signal-races and what the user's synchronization story
> > > would look like then.
> >
> > I agree that this looks inherently racy. The attr can't be allocated
> > on stack, user synchronization may be tricky and expensive. The API
> > may provoke bugs and some users may not even realize the race problem.
>
> Yeah, so why cannot we allocate enough space from the signal handler
> user-space stack and put the attr there, and point to it from
> sig_info?
>
> The idea would be to create a stable, per-signal snapshot of whatever
> the perf_attr state is at the moment the event happens and the signal
> is generated - which is roughly what user-space wants, right?

I certainly couldn't say how feasible this is. Is there infrastructure
in place to do this? Or do we have to introduce support for stashing
things on the signal stack?

From what we can tell, the most flexible option though appears to be
just some user settable opaque data in perf_event_attr, that is copied
to siginfo. It'd allow user space to store a pointer or a hash/key, or
just encode the relevant information it wants; but could also go
further, and add information beyond perf_event_attr, such as things
like a signal receiver filter (e.g. task ID or set of threads which
should process the signal etc.).

So if there's no strong objection to the additional field in
perf_event_attr, I think it'll give us the simplest and most flexible
option.

Thanks,
-- Marco

> Thanks,
>
>         Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNcYSGCC7587YzMzX1UpDvTA8ewAJRsKFdzQRdmWEO7Yw%40mail.gmail.com.
