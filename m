Return-Path: <kasan-dev+bncBCMIZB7QWENRBXHK6L3AKGQEM7FC7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B44421F0AB0
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Jun 2020 11:37:33 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id p82sf7200001oia.13
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Jun 2020 02:37:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591522652; cv=pass;
        d=google.com; s=arc-20160816;
        b=QAn2ry92TW4NIZp44rRKOhUMKhbz0JPTJCi71MlcziFTOflEbmxmHcl0kxfRBP59wZ
         5KWh6XULTP5Ev6KhepjvwF4c1tZY6zOAhSxlW9hXzQPbReX4+8bRNp7OVdiEzbYOrPLX
         z0P8iJdcoZpdvFKMS/zJzqoDXm3dEpiYqQhDCM96JCT/q8dXqqBy1oPfDliCO2VzVMPe
         /+Gig8E+xggAh91aKwpeuhHUFkKLbFaxTJVUc/J9Ex5KdaskP5YsHm2KzIMnORcGLH5a
         7oUfdkQx2UQhbxG43TOMF26flfX+gmJX1kC9sRQ68/QDMoI7afMq8bGP8iG0pj/v1NP/
         GoRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0WoSSzwifcUhFW5yNsLJ2zAzfN+4nWhro1VOgYZGTgw=;
        b=Jf5TQPUT7mmAiUXTFz6AXdVBi7AXeQcsYzQfke76aR+I8SCFS1X15F2X53s44uOONB
         jepT28lQrE2+zdBEvlN8qmexZQW5UdqwoM6S8E9BaVoqeG2ZD10nqt72Xb0UQmRXKKua
         2+ih/Fbndo97xZDcceoL4OzdpQ7EPLv8IvPE29wmlc2uMtKylXcjkjorxbKJHRcVPsjx
         koEVoCR0XbicEhO/OQt8aj4OdfiBYeL3ozqzho38I5j5zVxOAwQh77eGSeAhZM3UiqjK
         0HUltHyXM/NgSru56xnWLD8I4xgICyJdl2fuYRzELs/cJWwK5+rOW+yNFXUKK/6zXrTd
         7kXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T2nKWR5j;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0WoSSzwifcUhFW5yNsLJ2zAzfN+4nWhro1VOgYZGTgw=;
        b=s2UTNJEIbKjkNC/QljYUBT2wGyJOI2w1Dm0SseQawJOeR7BkAFcA4hPvZCvV0ICnPp
         mme8DC0/RPz4twAq36g3eKvNXQuDeGqVzFqkPnqe3s+Kg2VMDGIHQhY7Rg4PGuU1ArpS
         Ves46wdiEkXhZvPqVaUjf65ulvsuwPLlhiKjknxF/8a4K+eBCM2+ljyuq28yk/95Rp0e
         I4CDOMMvcDP9vkmw3AWD8RY2XTNI0Rb25Dm4t4dRSR3a3phVBx6z5UUBH1NZmOJV1T0i
         Hez/lvwEaxn7fm3V8u4Vob7/PNxdhljM+9ZGwyfXjrh4uk96YZGVETc6s2kmYgFZMxqP
         EcnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0WoSSzwifcUhFW5yNsLJ2zAzfN+4nWhro1VOgYZGTgw=;
        b=Sd6yEPrh6urAi/9H8tXrMFhHL69NHIBLh4u7oBCu5wEDIhp0utz/Mgv/Hqm83D3vOi
         C+MlC++6uPJzF9AZ7LqPipz6h69aq9qpVrJNIQjR34s4HBlMD8pLWR5XEj4Dl8knvxay
         TJNhH3xt7UmJMwlaejZohRq3dWgZo8tq+MgcHjwPgC6vLvznwlogFgRfPVitvX+yQJ4y
         ICLGPja5mtxwtbFkSHqDCbLGqZXOF/3HS+I3fYAifj3YlrHOqDApnOj93XeYIUXHKRIC
         17ilZ4/V6Nftb/aPH56KQZ+mkcVXe3HfIs0UqkY339mxQ6FCuwsoJ7tgn2JjHBQgoMxw
         HwVg==
X-Gm-Message-State: AOAM533ozALIr9dzYFZviv306bgejlTj1ZoisSNO1PzeHZiVYaxNq3ll
	4G1KnrUh5AjZ8Z5vnlYJhkE=
X-Google-Smtp-Source: ABdhPJxs8YoAaYbwndsh3VxOFWxP4czYFyfWCmN+V9GrrHL53fwYRnpfArUiE5KLAcIY/Ru5OUSWiQ==
X-Received: by 2002:a4a:d1ac:: with SMTP id z12mr152124oor.60.1591522652553;
        Sun, 07 Jun 2020 02:37:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ba8a:: with SMTP id d10ls764808oop.9.gmail; Sun, 07 Jun
 2020 02:37:32 -0700 (PDT)
X-Received: by 2002:a4a:6812:: with SMTP id p18mr13747512ooc.45.1591522652273;
        Sun, 07 Jun 2020 02:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591522652; cv=none;
        d=google.com; s=arc-20160816;
        b=zK2JQg5FdpitSqMvB8Onrjerf5SHxqgp8R6gQpYHspnN7yIbUbj+X3XUEIo0nJB2M9
         xVg/1p5r38cLHCqeKHz8wohmUy+xDraj3EkHPzk3hakZwbIpdScQpV6Q276W8vwY7fZf
         UxL+i3Lu2JO3Ubm0iD17PslDP595bZxNvuMuRGDGlM/tY6cjowGDUXWVVcFxwJvcTmft
         7cTm5ESGTg0Om/TbEnKSSlLs6sSK4Fc+GYx8kHtxUgNgVT28veqnQ+nZFabBLFIxcZjA
         qCWO4CpciOGsWBXXLQg1OeHY8Npiey9kJT4ShNZ1Sh3FiJEwnecdPWAWeDksjUaZT9tl
         93KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e2xlbfV4VPwn4qpyM6wODK/8b6ahF6KoGTstDUIrXuI=;
        b=FABmWp8spOUdlMzPq7apqQjawlDihWXZGhWfXHL3zDX71zL92UXRO3gzEpHhNWb60Q
         baAKbGhLw6zVT+b1+28jgsvN8CGlnIzwbcsh8t6TOVKUIaitiOecSzbUOW/ksM58z6hd
         JNuIuSY0G93ddjARAu+SRu/LBSmXemhhCDrqRXCH0goxtxJYhNj4CAcdjDHByV4XgIuV
         FwX3IEizCVTAnvDzGFO9TnguaKAS1BJ3n+Wn7jtE8AObBgNJep/ZnsCETLNnS4NfLYjh
         g5VUTCSHKBv4etM4enTfop7Q3+l9aUBNpLyJWz9IvIHyS5mzGuPB51nOflrKlIeAwon7
         iBHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T2nKWR5j;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id o199si424783ooo.0.2020.06.07.02.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Jun 2020 02:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id g62so8845305qtd.5
        for <kasan-dev@googlegroups.com>; Sun, 07 Jun 2020 02:37:32 -0700 (PDT)
X-Received: by 2002:ac8:7a87:: with SMTP id x7mr18590826qtr.50.1591522651451;
 Sun, 07 Jun 2020 02:37:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net> <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
In-Reply-To: <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 7 Jun 2020 11:37:20 +0200
Message-ID: <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T2nKWR5j;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Fri, Jun 5, 2020 at 3:25 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> > On Fri, Jun 05, 2020 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> > > On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > While we lack a compiler attribute to add to noinstr that would disable
> > > > KCOV, make the KCOV runtime functions return if the caller is in a
> > > > noinstr section, and mark them noinstr.
> > > >
> > > > Declare write_comp_data() as __always_inline to ensure it is inlined,
> > > > which also reduces stack usage and removes one extra call from the
> > > > fast-path.
> > > >
> > > > In future, our compilers may provide an attribute to implement
> > > > __no_sanitize_coverage, which can then be added to noinstr, and the
> > > > checks added in this patch can be guarded by an #ifdef checking if the
> > > > compiler has such an attribute or not.
> > >
> > > Adding noinstr attribute to instrumentation callbacks looks fine to me.
> > >
> > > But I don't understand the within_noinstr_section part.
> > > As the cover letter mentions, kcov callbacks don't do much and we
> > > already have it inserted and called. What is the benefit of bailing
> > > out a bit earlier rather than letting it run to completion?
> > > Is the only reason for potential faults on access to the vmalloc-ed
> > > region?
> >
> > Vmalloc faults (on x86, the only arch that had them IIRC) are gone, per
> > this merge window.
> >
> > The reason I mentioned them is because it is important that they are
> > gone, and that this hard relies on them being gone, and the patch didn't
> > call that out.
> >
> > There is one additional issue though; you can set hardware breakpoint on
> > vmalloc space, and that would trigger #DB and then we'd be dead when we
> > were already in #DB (IST recursion FTW).
> >
> > And that is not something you can trivially fix, because you can set the
> > breakpoint before the allocation (or perhaps on a previous allocation).
> >
> > That said; we already have this problem with task_struct (and
> > task_stack). IIRC Andy wants to fix the task_stack issue by making all
> > of noinstr run on the entry stack, but we're not there yet.
> >
> > There are no good proposals for random allocations like task_struct or
> > in your case kcov_area.
> >
> > > Andrey, Mark, do you know if it's possible to pre-fault these areas?
> >
> > Under the assumption that vmalloc faults are still a thing:
> >
> > You cannot pre-fault the remote area thing, kernel threads use the mm of
> > the previous user task, and there is no guarantee that mm will have had
> > the vmalloc fault.
>
> To clarify this part AFAIU it, even if we try to prefault the whole
> remote area each time kcov_remote_start() is called, then (let alone
> the performance impact) the kernel thread can be rescheduled between
> kcov_remote_start() and kcov_remote_stop(), and then it might be
> running with a different mm than the one that was used when
> kcov_remote_start() happened.

Ugh, this is nasty. But this has also gone, which I am happy about :)

Why I am looking at this is because with coverage instrumentation
__sanitizer_cov_trace_pc is the hottest function in the kernel and we
are adding additional branches to it.

Can we touch at least some per-cpu data within noinstr code?
If yes, we could try to affect the existing
in_task()/in_serving_softirq() check.
If not, it would be useful to have a comment clarifying that
within_noinstr_section check must happen before we touch anything
else.

I assume objtool can now also detect all violations. How bad is it now
without within_noinstr_section check? I am assuming we marking noinstr
functions to not be instrumented, but we are getting some stray
instrumentation from inlined functions or something, right? How many
are there? Is it fixable/unfixable? Marco, do you know the list, or
could you please collect the list of violations?

Is there any config that disables #DB? We could well disable it on
syzbot, I think we already disable some production hardening/debugging
confings, which are not too useful for testing setup.
E.g. we support RANDOMIZE_BASE, no problem, but if one disables it
(which we do), that becomes no-op:

#ifdef CONFIG_RANDOMIZE_BASE
    ip -= kaslr_offset();
#endif
    return ip;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA%40mail.gmail.com.
