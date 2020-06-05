Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWUP5H3AKGQEVISNOWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EC2661EF8F2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 15:25:47 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id n2sf6379487ilq.4
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 06:25:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591363547; cv=pass;
        d=google.com; s=arc-20160816;
        b=qkE4o2vM70lVCfRmcc+NARFy9skJaSiUkLLCH6KMJ3IbL9grsxHI6I0fbul2lcLh/d
         UImr+O4L179PUNZhFlUKuAGeiUuZJj2wvF+snmw/uOnWPoRRe6TjOHUixM+8er9U2FnV
         nONAKXMMK7hmBaHzeai2N+C6sn9raqXWYRj5ZHJgOWfQ/pFpvtD35pbCuUlNjxCZW4kh
         UkFv5eGdQzzscPKoiJnDDw3VgvwVCA+PoDV8H8KcQMk+7AgX1jIMBwQRAgyYMzN9rBBl
         7fY7nVAV8Lgr2bmvBqcWdUJv0d3/Sgha3BptlruQ1LqY7JziUekCsvNqGrdfv1fGCsVi
         HEIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qzUu2KHWGP8LIvjEHLqBVTZr++yhdzy//UsmHLNX8Ew=;
        b=armhQ38HNpD1CH/j3bH+8Hnrb19u5UjOuqderSXyu6X0vN9hPFRmAKFRA8HznYXIlA
         9TwWFkOvvepLl4WvN4lhoZHFIl10kDCChFA8k3tUBaj0OUAEbTNErNXebSvaMbtDH0xl
         GxXqOwvZui3jpl7jy8ARGCY2xvzt6ZeUOiU9NvL02+BqCugq+55VRswvNdxhM8ifdVY9
         RT6H8UYMO9+j42ILTdlbO6pXEZGYvoXQjbVnEQLraKBpf3GWjCnIN7jsqSiMKqahCten
         nAsXiSt17uPqcklJ1aAG9IBdmUOlP7EmnqyEVWe6KsjMN33CHTSQZ7sXUf99gZw/mL4b
         qMnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WaP9I3El;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzUu2KHWGP8LIvjEHLqBVTZr++yhdzy//UsmHLNX8Ew=;
        b=MWatgrG0dS/OfnIJFup0lSGCVdKDgbdpi8xWJlHnUmkZUOWb3elSlq1YjO+/axzKb6
         73PsFDprDHA+9au46wF6YrQHAPrhrFoWQ8WrdfQzQ+BrbTYGz6fKN3BrwBoJVhzv1+e0
         yQYGYjzC3L5lPNEyRCpO66kzYxPcioVG7lk9Fy8VMfJOaENYllnmHl0RLuU37BEDLenV
         qP9aJ/hyG7VPPw8EkiM9bQRNJNTMsZKOBKgCJ6yK7qYA2Md8BVLc7WlCZmSj5eFkwyFs
         aKYNEy4/lPwDulzMKOQEieWFohBfVEys7J4OMkAFQpfm+QOFgI7lu1dHCDfvFe7EQssH
         llGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzUu2KHWGP8LIvjEHLqBVTZr++yhdzy//UsmHLNX8Ew=;
        b=Kk19UeqGkDRuMGQr+esC5KmwRbff8fYsaCq7Sax+hw4VZWgkirTp5JJunXvu7WkIm9
         FOmlWvGqEpw/UF0fgjvJwx/iUABzo1Jb5uCXObCLdwI1YNNl1djKAsoIJMbEOIN73xod
         Up9lLGtVqY5hCF8ps7TXkCxt3OO1Q9EME4s6bP5aSJMXMbqLCxV7FBM3E8PwTd6AYg7Y
         1rUl4CIm1vhdbETtK/8KSfTviAxH926EUhFLlG1fBLMUHGibvX9/HHqVdjI04frbxmop
         VbvwxUIPZcBsareQIDGplQKIP9H9hzm2t/YZUPnMsdUBYCLwf9/suoIDzQ7CsWxZ2Cwe
         VYeQ==
X-Gm-Message-State: AOAM533LKjxcXfPEc1gsL6u1wo2ue8JqemwB38xp29tuG0lVqfo1WJ/+
	s5MEE/k9hIDK79pQZo5cY+8=
X-Google-Smtp-Source: ABdhPJyhAxschXRJleytCxr21HJLXba5/GZHAZ/7Z/iHJa+M/OMjtQHG9eF02I/VO9KrqD7Fm8hYYg==
X-Received: by 2002:a92:8593:: with SMTP id f141mr8582789ilh.264.1591363546876;
        Fri, 05 Jun 2020 06:25:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:c85:: with SMTP id b5ls2443402ile.8.gmail; Fri, 05
 Jun 2020 06:25:46 -0700 (PDT)
X-Received: by 2002:a92:730b:: with SMTP id o11mr8179030ilc.153.1591363546584;
        Fri, 05 Jun 2020 06:25:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591363546; cv=none;
        d=google.com; s=arc-20160816;
        b=ADPoNNBY1VsTFm79R/a+sxHg3EXXD1BhLzwjBvB4yt+pCJBEL1piuKeVAKTqjkAhiv
         kzyqQiNUS9QKAJE5cj8Mo8bkoy0suQE/opDnmGuCcPg3OwQl4Xa0HQUu9pDktwvfWcmT
         woKkuuD2EZQhejJJ5P8w/WWGCBU7osFrCfCgMrnYWRPYMSGjUSXOwhvMUMay52qtZ+RX
         xd8qHxhHu3rMt+kLHbGVigSPmi7+eLgivywq1aQbyRHzosT4fn18/ev+8M5scxFVmOi+
         AWh3YzNRgxAUteekkNXbot+MMPtTKk3F0KilOOgswTiUYkp50AjKsvECQjbzIRcK8B7c
         EA7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xJJnlLNjBPmVl14e43YLrTf5lqn0jzr6Vaq59xpn/uY=;
        b=fqQFO5+A3NgYtMjcH2rKNBL318Uu7quJq+QyVtl1NfBmURDB0g8V5dXpUbiELJ0ywA
         9FvpKiig4hwZ2h5oL5wojzsxoTdm5dWs86BSdYKQtKIzpkaeL9zKG97BGDBpm5oLQJc7
         6BofXqPwVyUnNYvGNmmIwAFirU/MWNlHY4CPNgdr4fJkHThRPyzABNbHN9kNTNUVFnxb
         eZCL9ndkURUsSQWWVp2hwI6NX7SYHqGPLEZ+gH/n37pGU1w9XF1fJtH/rUie+UqJ106b
         Ih9jY45s95Fujvkpg0+t0e+LPY3ix5ppJ/Lsw1YdWyrjl3yEMNhgoo7/5Xemharci3GZ
         cWbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WaP9I3El;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id v16si317731ilj.1.2020.06.05.06.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 06:25:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 185so5106470pgb.10
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 06:25:46 -0700 (PDT)
X-Received: by 2002:a63:e454:: with SMTP id i20mr9457353pgk.440.1591363545752;
 Fri, 05 Jun 2020 06:25:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com> <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net>
In-Reply-To: <20200605120352.GJ3976@hirez.programming.kicks-ass.net>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jun 2020 15:25:34 +0200
Message-ID: <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Peter Zijlstra <peterz@infradead.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WaP9I3El;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::536
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jun 5, 2020 at 2:04 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Jun 05, 2020 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> > On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
> > >
> > > While we lack a compiler attribute to add to noinstr that would disable
> > > KCOV, make the KCOV runtime functions return if the caller is in a
> > > noinstr section, and mark them noinstr.
> > >
> > > Declare write_comp_data() as __always_inline to ensure it is inlined,
> > > which also reduces stack usage and removes one extra call from the
> > > fast-path.
> > >
> > > In future, our compilers may provide an attribute to implement
> > > __no_sanitize_coverage, which can then be added to noinstr, and the
> > > checks added in this patch can be guarded by an #ifdef checking if the
> > > compiler has such an attribute or not.
> >
> > Adding noinstr attribute to instrumentation callbacks looks fine to me.
> >
> > But I don't understand the within_noinstr_section part.
> > As the cover letter mentions, kcov callbacks don't do much and we
> > already have it inserted and called. What is the benefit of bailing
> > out a bit earlier rather than letting it run to completion?
> > Is the only reason for potential faults on access to the vmalloc-ed
> > region?
>
> Vmalloc faults (on x86, the only arch that had them IIRC) are gone, per
> this merge window.
>
> The reason I mentioned them is because it is important that they are
> gone, and that this hard relies on them being gone, and the patch didn't
> call that out.
>
> There is one additional issue though; you can set hardware breakpoint on
> vmalloc space, and that would trigger #DB and then we'd be dead when we
> were already in #DB (IST recursion FTW).
>
> And that is not something you can trivially fix, because you can set the
> breakpoint before the allocation (or perhaps on a previous allocation).
>
> That said; we already have this problem with task_struct (and
> task_stack). IIRC Andy wants to fix the task_stack issue by making all
> of noinstr run on the entry stack, but we're not there yet.
>
> There are no good proposals for random allocations like task_struct or
> in your case kcov_area.
>
> > Andrey, Mark, do you know if it's possible to pre-fault these areas?
>
> Under the assumption that vmalloc faults are still a thing:
>
> You cannot pre-fault the remote area thing, kernel threads use the mm of
> the previous user task, and there is no guarantee that mm will have had
> the vmalloc fault.

To clarify this part AFAIU it, even if we try to prefault the whole
remote area each time kcov_remote_start() is called, then (let alone
the performance impact) the kernel thread can be rescheduled between
kcov_remote_start() and kcov_remote_stop(), and then it might be
running with a different mm than the one that was used when
kcov_remote_start() happened.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ%40mail.gmail.com.
