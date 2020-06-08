Return-Path: <kasan-dev+bncBCMIZB7QWENRBAG7673AKGQECSDIVZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 368511F1409
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jun 2020 09:57:54 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id y12sf12566156pgi.20
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 00:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591603072; cv=pass;
        d=google.com; s=arc-20160816;
        b=T4cS8EwcQwUp8ftpE78VBqRDAqRsqjp3qNws5u7YEecq/4Nktg4J3yMGdVrKPcmWmn
         ZjxhdRYPOPjBdrXX44/rfBDB4gkUeyBB7q/Iz4BB7Dg7CpkctTO6sagBeZr8w+KQCN6e
         wKJpcNMJKRuforsN08/+jfW7DJ5DVTZTwId0Kte/EsS0VU4ApnYRWyZbB2xZpQ/l75jG
         JZ5sHiKgdbaD+MsD9zzbc23Oaf1t707zO16F4nw02fh2X0EczZzMz7eGfzzoSznk4Yez
         7WT/6W7K36OvwTz/t5PCSGz6FWQ6NTmWAjLXxigNcfJxWWUUPhIF+1hYCL5E9S+YrxbO
         444A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+rOD+9pfUXaWD+mJU7jVTzsDzdIu1Aw5LsPE4epaMvs=;
        b=hzwpsrsxZIhwrl/NYuOpDC7dOh3jc7DYVeKw0SEDRG6Haujx01ACsbB0qZOoNkIi40
         hBl3FNu1yCLbwob0y1NnCzLBwO9q6hNlRlWIHc6wY7jqhQBP64J7atPY/agwUuHf1eMv
         cuIDYGzXqTrKyShMmk7e0Jn3wNrC/RYlQQXZIkFaoDoICIjlWnGcK6kC+su7KYdNIHFe
         7KrhIzuNtD8A68Y1XVY1yvvX0LeUvAt18DJICF9aqPQHuprCiIrLdET9//upNPShmSRF
         j1L30AGnaSk4qEMgtvjIRjAXByHHHDzZiE0Ig4tz8wpfdiDgKj0JeoXDGAky13+GNl2V
         1Ibw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dadYrfXc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+rOD+9pfUXaWD+mJU7jVTzsDzdIu1Aw5LsPE4epaMvs=;
        b=bn0JyeeyWShttdHWg8PYHi1Jx8+O8FpUs921OdjcyNeTykpw51euvHlCCVM40u8rTd
         XpF0K55u5MnU3ExtGVy6A6W1E6/EEK2f/GtN6E/qSUHlBoOdl3/TrVtVdHajXEc44PXR
         AzO9jLQfQQkn1iK88b4rJANkdo6L7zh+dDcLe7ziudyCEh8e/bFx44eXw5KUGyfjsTtb
         6tk2NR6XMlKt1VO0q+R3UJMg6+VSj1lGDsCZcVQofUNbFTzAcgU3BW81uHGPe/u6CiVY
         6ffZi4W/Vwz+Yxytdb57btZVRzLvywkwn84QFN2k1SYHlrhkcA4lJOefWGlHUo+kEr1j
         iosA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+rOD+9pfUXaWD+mJU7jVTzsDzdIu1Aw5LsPE4epaMvs=;
        b=GuTDwbe+yf1vDFHiQKM/E8oFNkRA+s+IBJKvtb3asY1IHLezCAvqlTVxl07BUQkZtZ
         ardKArNttcWX9sR+I0hSqJ7CM4LhyDUyc9hEHTp8K9Ua572Og+sBuYCvRmob1ivP/50O
         A1m1OMe5x0QT5O504Ybi3wG1exSfzHa8CIrA5SKGGYj2268doC548q8loRpob2Tvk3y0
         Vjzl3qvFyq6o09znB6OsDYjMGOMbyeSX/HFfrTGDBFrE1ITNWCDiF1GjG7JnO6Yua0SQ
         Q70g8xn+FSIeKV73a43aDx6nB2gRoFKhFGLTiEbvV23BX+eGoKxsQAr3WG/5WaDSKSWP
         YOZg==
X-Gm-Message-State: AOAM532VlBJ9gQ8qy6SIHWFvCKDzFuf3ow1BbUNJFWpbrJbpJGU7X9mY
	kYVt2PTyXoJv+3G8Z77RfMM=
X-Google-Smtp-Source: ABdhPJxY3Fy6/wApYBZhhelT5vUXgb7uMTMrzaZcGdbBxiAAKQ84GNC+jGxmLqIxZ5IxHJkA1fWbZw==
X-Received: by 2002:a62:5f84:: with SMTP id t126mr21544471pfb.124.1591603072477;
        Mon, 08 Jun 2020 00:57:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:718c:: with SMTP id i12ls7596522pjk.1.canary-gmail;
 Mon, 08 Jun 2020 00:57:52 -0700 (PDT)
X-Received: by 2002:a17:902:7297:: with SMTP id d23mr14130647pll.282.1591603072074;
        Mon, 08 Jun 2020 00:57:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591603072; cv=none;
        d=google.com; s=arc-20160816;
        b=ZCChwkwHUFUEJ+2T75U338T4adNTp4hg73BswuL2fAt2TY2I/AdEsz8sIdtHeyxeG6
         KFzaeSS32dL2CeKTGKpNTEg4OL6iiRKJppgPPfdBYl6r/023rSKNFj0fcUCLNjsI4yZj
         TMD1dbqVCXYZQZ3XhgzbgRyPpGck8ileBy4+Wj+Cn0O0LTeSqHT/TiuTdsNB1WeNNJhv
         p8FRrergzk+/7VgMXjCJurmDq1YEvp3EMRPhMhutOz07TkzIRHUIMK9TW4N7FGv2pMca
         0XnfZj9YOpo4Wr/SRG5Sp78efcN83SB+NwzKls9EXGoQRa/q30CDjuuV7xmi8oTyCUyn
         zl6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UXDknJ6zk2gEs3+RNn5uknA1R62+oU40etEr62atLbs=;
        b=q/aGDMSuTvfga/xJ6Oc9iQ/a+gqKNlxXV7At6AQJku8RonMO1GLRMYeLGZdXG+ItnP
         6WgBZGYeOsPb8gNJVeMmeX4caggCvdGxJYQZU1p2EdTw4gzRxotLumawr4HOe686uXrT
         6SDVPokvnH0zBCmDaEyIpXYwdW35WZZ7oddf87WSE7/jrqeso9h/fxtufSN4v8yKTYIg
         f2/RHNuvFRweN03aQr23yLoEHRHqIvo2erDXW7seuDpybuy0d32yDxUkIUdUoumNMEZi
         cy/ZNxmK8wzHGICY+zA/kWHtIdNDJhjet2VW8TEw3hRw4zuMPkl4BXcp0VCnz8N+fs+j
         VG7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dadYrfXc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id r17si344998pgu.4.2020.06.08.00.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Jun 2020 00:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id q8so16350550qkm.12
        for <kasan-dev@googlegroups.com>; Mon, 08 Jun 2020 00:57:52 -0700 (PDT)
X-Received: by 2002:a37:a304:: with SMTP id m4mr21920419qke.8.1591603070800;
 Mon, 08 Jun 2020 00:57:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net> <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com> <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
In-Reply-To: <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Jun 2020 09:57:39 +0200
Message-ID: <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dadYrfXc;       spf=pass
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

On Mon, Jun 8, 2020 at 9:49 AM Marco Elver <elver@google.com> wrote:
> > On Fri, Jun 5, 2020 at 3:25 PM 'Andrey Konovalov' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > > > On Fri, Jun 05, 2020 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> > > > > On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
> > > > > >
> > > > > > While we lack a compiler attribute to add to noinstr that would disable
> > > > > > KCOV, make the KCOV runtime functions return if the caller is in a
> > > > > > noinstr section, and mark them noinstr.
> > > > > >
> > > > > > Declare write_comp_data() as __always_inline to ensure it is inlined,
> > > > > > which also reduces stack usage and removes one extra call from the
> > > > > > fast-path.
> > > > > >
> > > > > > In future, our compilers may provide an attribute to implement
> > > > > > __no_sanitize_coverage, which can then be added to noinstr, and the
> > > > > > checks added in this patch can be guarded by an #ifdef checking if the
> > > > > > compiler has such an attribute or not.
> > > > >
> > > > > Adding noinstr attribute to instrumentation callbacks looks fine to me.
> > > > >
> > > > > But I don't understand the within_noinstr_section part.
> > > > > As the cover letter mentions, kcov callbacks don't do much and we
> > > > > already have it inserted and called. What is the benefit of bailing
> > > > > out a bit earlier rather than letting it run to completion?
> > > > > Is the only reason for potential faults on access to the vmalloc-ed
> > > > > region?
> > > >
> > > > Vmalloc faults (on x86, the only arch that had them IIRC) are gone, per
> > > > this merge window.
> > > >
> > > > The reason I mentioned them is because it is important that they are
> > > > gone, and that this hard relies on them being gone, and the patch didn't
> > > > call that out.
> > > >
> > > > There is one additional issue though; you can set hardware breakpoint on
> > > > vmalloc space, and that would trigger #DB and then we'd be dead when we
> > > > were already in #DB (IST recursion FTW).
> > > >
> > > > And that is not something you can trivially fix, because you can set the
> > > > breakpoint before the allocation (or perhaps on a previous allocation).
> > > >
> > > > That said; we already have this problem with task_struct (and
> > > > task_stack). IIRC Andy wants to fix the task_stack issue by making all
> > > > of noinstr run on the entry stack, but we're not there yet.
> > > >
> > > > There are no good proposals for random allocations like task_struct or
> > > > in your case kcov_area.
> > > >
> > > > > Andrey, Mark, do you know if it's possible to pre-fault these areas?
> > > >
> > > > Under the assumption that vmalloc faults are still a thing:
> > > >
> > > > You cannot pre-fault the remote area thing, kernel threads use the mm of
> > > > the previous user task, and there is no guarantee that mm will have had
> > > > the vmalloc fault.
> > >
> > > To clarify this part AFAIU it, even if we try to prefault the whole
> > > remote area each time kcov_remote_start() is called, then (let alone
> > > the performance impact) the kernel thread can be rescheduled between
> > > kcov_remote_start() and kcov_remote_stop(), and then it might be
> > > running with a different mm than the one that was used when
> > > kcov_remote_start() happened.
> >
> > Ugh, this is nasty. But this has also gone, which I am happy about :)
> >
> > Why I am looking at this is because with coverage instrumentation
> > __sanitizer_cov_trace_pc is the hottest function in the kernel and we
> > are adding additional branches to it.
> >
> > Can we touch at least some per-cpu data within noinstr code?
> > If yes, we could try to affect the existing
> > in_task()/in_serving_softirq() check.
> > If not, it would be useful to have a comment clarifying that
> > within_noinstr_section check must happen before we touch anything
> > else.
>
> I don't think this will get us anywhere. If anything this will require
> introducing code outside KCOV, and I think that makes the whole
> situation even worse. My guess is also we can't even read per-CPU
> data, but Peter would have to comment on this.
>
> > I assume objtool can now also detect all violations. How bad is it now
> > without within_noinstr_section check? I am assuming we marking noinstr
> > functions to not be instrumented, but we are getting some stray
> > instrumentation from inlined functions or something, right? How many
> > are there? Is it fixable/unfixable? Marco, do you know the list, or
> > could you please collect the list of violations?
>
> It's everywhere. We cannot mark noinstr functions to not be
> instrumented by KCOV/-fsanitize-coverage, because no compiler provides
> an attribute to do so. GCC doesn't have
> __attribute__((no_sanitize_coverage)) and Clang doesn't have
> __attribute__((no_sanitize("coverage")), and therefore we can't have
> __no_sanitize_coverage.
>
> My plan would be to now go and implement the attributes, at the very
> least in Clang. Then what we can do is make wihin_noinstr_section a
> noop (just return false) if we have CONFIG_CC_HAS_NOSANITIZE_COVERAGE
> or something.
>
> Unfortunately, without this patch, we won't have a reliable kernel
> with KCOV until we get compiler support.
>
> The thing is that this slowdown is temporary if we add the attributes
> to the compiler.

As a crazy idea: is it possible to employ objtool (linker script?) to
rewrite all coverage calls to nops in the noinstr section? Or relocate
to nop function?
What we are trying to do is very static, it _should_ have been done
during build. We don't have means in existing _compilers_ to do this,
but maybe we could do it elsewhere during build?...


> > Is there any config that disables #DB? We could well disable it on
> > syzbot, I think we already disable some production hardening/debugging
> > confings, which are not too useful for testing setup.
> > E.g. we support RANDOMIZE_BASE, no problem, but if one disables it
> > (which we do), that becomes no-op:
> >
> > #ifdef CONFIG_RANDOMIZE_BASE
> >     ip -= kaslr_offset();
> > #endif
> >     return ip;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2BFFHFGSgEJGkd%2BzCBgUOck_odOf9_%3D5YQLNJQVMGNdw%40mail.gmail.com.
