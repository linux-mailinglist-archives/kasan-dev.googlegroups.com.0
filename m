Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4W2673AKGQEOYAU2AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EDAA1F13DA
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jun 2020 09:49:08 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id x14sf10563824pjt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 00:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591602546; cv=pass;
        d=google.com; s=arc-20160816;
        b=a303QNsEbk4n82kiohnT8OSYw872gu/gyxH2S3Jgy6zDl+9rYTGAuax8N6zB23MXnI
         4TQ3dw1ePj0GNkgF9MfKbjlqIL6Jtsc5h4/ndrYcm/1gj3tQrluTpL0+8yJ0Du6Kw6e2
         Tfb1EoOhShEMiZvXkQJVFY+AhSunjc/yZeler1Gn6uP/jiQnSVMhk5IHviui9WO/iLXR
         UqcigsVRoq0UEIdnD+nIpZSRhQVTHcX9R2KE7xunI6O94d0rQL5BUWNiVzdJg7UNORce
         KxkbnGnrnTQmYXUzUEYjT7yYUSL3o+LYURq6HjY3gMJIQZy4jLRTMbu8WlRjBi9gw4lq
         4bnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A9ClHGmv7mckmHbBgX9x3vD3bxZOaxfQRo31EG663PY=;
        b=nBGACYja4YFy/gd5lUUW7eSwYTurln2pYUI+w5sMoN4kVFz/q1lOUiRw7Bw+aKgJXA
         Y+g5FhA8krxnJaSMfRyWlua+NZhsxLZ32JTzLcF2NjJoIuDmygrXCHBVr09AUR7EMkwz
         sRGzqWcwnwLuYj+14xXNtAe+FyPSU1Yu6fJz2H39bEli6+vsHZ6ZRdFQllKB44xKFvRq
         AsslFoALxdWt+mDYQJPM36gyRNX7FIb2kdThY3yvfxGj+A3nscR6xCQTTJ1V8gAZJDJe
         SLgotnvpT6byZanaF86aobbSc4YrpJ+HVoCVMonfbOi7Wx5T0ZptrFqx0q8uQMamlqr+
         z8hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wkt0uBkw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9ClHGmv7mckmHbBgX9x3vD3bxZOaxfQRo31EG663PY=;
        b=AWmwBflL/muP8czSMGduNw5CjBJnAZ7NmJmTl8s0m0+OOMhRKbeNjru5QYNhq2ZeAO
         vbLHvpKPhxxLc2xYHpwZ5XsaZDJyDx3HL4U16HJBqdIwv8VhOz/lg9mbi8Fac0g/41uo
         mHDyfeo67jp1Bmj/V2mgc266+cv/anSGj2HyyURyHYiGW6hPV2cuYgDPkuatjJtHRqxa
         QEYT94y4G3RCz9kn8ZHa9aOXKDDcKafo0dnEmcDCekzvikdNClPiFEDl3n3uhiJkoBS5
         DbQCxuB9HqDNJE4NhfsxKgkRERx3bhmt/AYlM6wtfYRt4o7SyAkeqECwQEP1Qa+WA9l7
         JllQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9ClHGmv7mckmHbBgX9x3vD3bxZOaxfQRo31EG663PY=;
        b=jQvlXdz6e4QBQ9WMQIyeRwDdbomUqnvsrIpCxpo4H9mp8CgIMQxFOWEnQomBcPcD3m
         iwruNjh6sLyY6Ky8OIiQt/0vhNl+s9Iajplrg3yEa+q+C1u58CVZzPAUU23fQQy8p/iB
         PCVNvIp4Opio2qHnWC1AFwW9Fspd2MqyYCib9wdpMTNMo4tg9k1eV8Fay6ylXcURFSUS
         0Q9+WmxQD8BGQdkTLiOCKXGhwuA0kG68DK0CCVFHJGrMsuIfvsOby2r18QXXhwsNlPjC
         vxR/EBwgk/zKZq+/Pwc2RRIwUkSeAfogRpDI87pnOvd2FniydgB2IYfml2XatlWvcvqV
         oNOg==
X-Gm-Message-State: AOAM532Mhw63cfV9Ia2y46FwGnx/CMTkQXX7T8BHupk4WW6hC1eJwCrk
	eiRZNH9e683bIpcYAX7bpn8=
X-Google-Smtp-Source: ABdhPJwrG2AQAN1YT0lm/2+fc91On5ZOl6wzTWOSmSPutlAKN6HLhzUSSErEm+Dl1gZuDIj5h5DaIg==
X-Received: by 2002:a17:902:b182:: with SMTP id s2mr20136098plr.60.1591602546291;
        Mon, 08 Jun 2020 00:49:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f3a:: with SMTP id y26ls5049094pfr.3.gmail; Mon, 08 Jun
 2020 00:49:05 -0700 (PDT)
X-Received: by 2002:a62:cd4a:: with SMTP id o71mr20518284pfg.115.1591602545754;
        Mon, 08 Jun 2020 00:49:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591602545; cv=none;
        d=google.com; s=arc-20160816;
        b=h8P+CowRCSmWS6VBhB8xmPx4N2wNld1HJMuBzqEED4fkEBebO8bVb3uS9WLAzunStF
         gIl8sWPEUKtgSewyuWnw42BndSUo5ENextcZ+xXajGAfPXxtYYIpxdYIfLgiZxD4GM1k
         9UejStjZw6IDNsk/tW+BSdVeecCAkC/nCRsT1Vc865MA6Lrrx47I7DEQz10wv+tP2r4k
         En/T8o2O9GTSyIgYwcEcRETcfGkEgsXT38vVCnBP318jxYKF/L4pKiwgvTgVux6W69BB
         uc1f9Pjfl5qt5Uy0m7MXKrgGv0hDr2ABGc42f4r6f7oa+X819xz+RV05hM40f59fittu
         KILQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+1dlHdbQCWrUXJ4LO9gAGKWP7TZEvzQ6RBz5kvhjOak=;
        b=JcpTFuaUjwSWx/wpf/abelaY0VSvF5q6u7m02/oHw/XhX4D24bD8RE2N9Y0Qn+jshk
         XBNXhR54vvE17toaZboOe2/5Stf/ZcFGVTQdySR6X9RWWKPRABbybg9Qysf7uZEMVtti
         2ZOrlZB4+0N1rZnRAZvhNsOtLGkLAHFVLOE8SL3HKBObng7xkS26FWL2xsq26CYgxAob
         2957KUaEYJx4MwADpPBavFeDhqmGVq1HrBaTXmbWcz9Uwv6h5S5+2nzr3/EaSdy+zMeN
         HEduJSIrSus5ibfMSGFNShDT266riO0U989B8EP95U6afLPBrTzIEK5//dZYbwAQyrtX
         8Yow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wkt0uBkw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id w15si1038564pjn.0.2020.06.08.00.49.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Jun 2020 00:49:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b8so14484133oic.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Jun 2020 00:49:05 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr9979761oih.70.1591602544808;
 Mon, 08 Jun 2020 00:49:04 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net> <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Jun 2020 09:48:52 +0200
Message-ID: <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wkt0uBkw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Sun, 7 Jun 2020 at 11:37, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Jun 5, 2020 at 3:25 PM 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > > On Fri, Jun 05, 2020 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> > > > On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > While we lack a compiler attribute to add to noinstr that would disable
> > > > > KCOV, make the KCOV runtime functions return if the caller is in a
> > > > > noinstr section, and mark them noinstr.
> > > > >
> > > > > Declare write_comp_data() as __always_inline to ensure it is inlined,
> > > > > which also reduces stack usage and removes one extra call from the
> > > > > fast-path.
> > > > >
> > > > > In future, our compilers may provide an attribute to implement
> > > > > __no_sanitize_coverage, which can then be added to noinstr, and the
> > > > > checks added in this patch can be guarded by an #ifdef checking if the
> > > > > compiler has such an attribute or not.
> > > >
> > > > Adding noinstr attribute to instrumentation callbacks looks fine to me.
> > > >
> > > > But I don't understand the within_noinstr_section part.
> > > > As the cover letter mentions, kcov callbacks don't do much and we
> > > > already have it inserted and called. What is the benefit of bailing
> > > > out a bit earlier rather than letting it run to completion?
> > > > Is the only reason for potential faults on access to the vmalloc-ed
> > > > region?
> > >
> > > Vmalloc faults (on x86, the only arch that had them IIRC) are gone, per
> > > this merge window.
> > >
> > > The reason I mentioned them is because it is important that they are
> > > gone, and that this hard relies on them being gone, and the patch didn't
> > > call that out.
> > >
> > > There is one additional issue though; you can set hardware breakpoint on
> > > vmalloc space, and that would trigger #DB and then we'd be dead when we
> > > were already in #DB (IST recursion FTW).
> > >
> > > And that is not something you can trivially fix, because you can set the
> > > breakpoint before the allocation (or perhaps on a previous allocation).
> > >
> > > That said; we already have this problem with task_struct (and
> > > task_stack). IIRC Andy wants to fix the task_stack issue by making all
> > > of noinstr run on the entry stack, but we're not there yet.
> > >
> > > There are no good proposals for random allocations like task_struct or
> > > in your case kcov_area.
> > >
> > > > Andrey, Mark, do you know if it's possible to pre-fault these areas?
> > >
> > > Under the assumption that vmalloc faults are still a thing:
> > >
> > > You cannot pre-fault the remote area thing, kernel threads use the mm of
> > > the previous user task, and there is no guarantee that mm will have had
> > > the vmalloc fault.
> >
> > To clarify this part AFAIU it, even if we try to prefault the whole
> > remote area each time kcov_remote_start() is called, then (let alone
> > the performance impact) the kernel thread can be rescheduled between
> > kcov_remote_start() and kcov_remote_stop(), and then it might be
> > running with a different mm than the one that was used when
> > kcov_remote_start() happened.
>
> Ugh, this is nasty. But this has also gone, which I am happy about :)
>
> Why I am looking at this is because with coverage instrumentation
> __sanitizer_cov_trace_pc is the hottest function in the kernel and we
> are adding additional branches to it.
>
> Can we touch at least some per-cpu data within noinstr code?
> If yes, we could try to affect the existing
> in_task()/in_serving_softirq() check.
> If not, it would be useful to have a comment clarifying that
> within_noinstr_section check must happen before we touch anything
> else.

I don't think this will get us anywhere. If anything this will require
introducing code outside KCOV, and I think that makes the whole
situation even worse. My guess is also we can't even read per-CPU
data, but Peter would have to comment on this.

> I assume objtool can now also detect all violations. How bad is it now
> without within_noinstr_section check? I am assuming we marking noinstr
> functions to not be instrumented, but we are getting some stray
> instrumentation from inlined functions or something, right? How many
> are there? Is it fixable/unfixable? Marco, do you know the list, or
> could you please collect the list of violations?

It's everywhere. We cannot mark noinstr functions to not be
instrumented by KCOV/-fsanitize-coverage, because no compiler provides
an attribute to do so. GCC doesn't have
__attribute__((no_sanitize_coverage)) and Clang doesn't have
__attribute__((no_sanitize("coverage")), and therefore we can't have
__no_sanitize_coverage.

My plan would be to now go and implement the attributes, at the very
least in Clang. Then what we can do is make wihin_noinstr_section a
noop (just return false) if we have CONFIG_CC_HAS_NOSANITIZE_COVERAGE
or something.

Unfortunately, without this patch, we won't have a reliable kernel
with KCOV until we get compiler support.

The thing is that this slowdown is temporary if we add the attributes
to the compiler.


> Is there any config that disables #DB? We could well disable it on
> syzbot, I think we already disable some production hardening/debugging
> confings, which are not too useful for testing setup.
> E.g. we support RANDOMIZE_BASE, no problem, but if one disables it
> (which we do), that becomes no-op:
>
> #ifdef CONFIG_RANDOMIZE_BASE
>     ip -= kaslr_offset();
> #endif
>     return ip;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPNa2f%3DkAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA%40mail.gmail.com.
