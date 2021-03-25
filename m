Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXK6CBAMGQEI3G7HDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 224F63489C2
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 08:02:00 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id d3sf1076455ybk.5
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 00:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616655719; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDvmZ+ma25/EsXt098WJdIKFrgPGgdyqccNAa7YAGlG3/juP6cJmpKL35fCE0X1KdN
         D8HAuO/+L2joIQImz32KiMRWSPn7zcR0ek5CMPoWM5y58Hi5tNSVjMAjNuN+akEaSznN
         aksD2KfeWREsAzdFgwFKBpeC+KmErESC0VlgQiaszGwFmcirjfdCZmy7WHkr3eF4KQjq
         mXwSAkaS0S1BSEgl8ZsKIUWGOCbqJvRYQ2t10cW9nu5PYlGgFWrMyAOFN+OYc8DifYLz
         7XVwRLmaK4vvrulp57CcqF6ubiVJxdt6dXCeGBYsF/AyWTSgt0uaUTuycMQNQyOfqq02
         y06Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=llfb7+yP+kjCWTelBqtvhZ0jSOEQPTF0ccVBCzGPypA=;
        b=lmPFL136m09mpJ6bMD7LYvovi6kVMtW1MapAhyi1ioE0u1Wx8G0DDguNfSQogtKMXK
         OMHsd3ioWbTDqUVrU9XgpNbvmCuDLdlDH7i3rl0DKM4PgwTtQcOb+Hnlnrzm9+nsKZ1i
         BAv5MUv7kmeQt/6xZlzLEpFKVCvwBxlET/6X0+6jm3J1xhMI7lD1J4002L0hZvIgXPbC
         bh8KH3SQU2E29Qxd5aXwEwxK9z4YPPe5+VQcSZszFbeKDQn61TsfgyrF90CYGGvr17jE
         ND/BBLt+6HUp9rdSkcksSZx21L4Ke5p0yj2Is1OdgMa906lfsQKr08XjFs70OeCs95U5
         J44g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hbSQau/S";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=llfb7+yP+kjCWTelBqtvhZ0jSOEQPTF0ccVBCzGPypA=;
        b=C/ou4yKPd8sINOQK+zU7OnQoLK4kUeJGthQMIN6As4HbICoKwj0hXLG5t7EMBFSAX3
         lB9u9YPA8e0b32eZRuGFlBGp2ya+L/8vVe5n+AYtzUSJmg8E7GFrbmGUoxfPbByakg8/
         s0GfDRLzKraVJSoPn46CHeOiFfADtsd9gpDtOW9GmXRLOjgmpsua0033o7UtIADviW23
         Polp8wXVcalQn0bsdJoPOR7/iEoIFigZ3VPVLkLsuFXRw8rLJDkxbUlO3LUViARQKFqp
         6heKFgL5g7uCatWLKW1aQtGBKdclcatPOMGnR36b8azFgTpFYry/hSfB6+pf2kvAHclK
         Yjaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=llfb7+yP+kjCWTelBqtvhZ0jSOEQPTF0ccVBCzGPypA=;
        b=EbPbrl8LT+xAkRcUcib2jSOupKnF3IKTC23dWfmYYvAcQLb+d1fUBNts9pVZiLPitg
         KBGhbfMRFtgbgZRIIrpNH4lQ5VGKLgiMhMl3mRbJkgSk7sZqUubPqe/LWkz4DovprUeO
         RhK9sGiAZzR6SoFpLezaudZ0QW/AnStC+xSVj0TjWPs69+sOG1JMTWJ0ivWYtCw3Vr0S
         JGDtPtSqMAnN0LyrM8YKNFjNrsXPSrKXG6E47taT+RBAtAWVs2tSfsrdeHet26yfqrj6
         7EAsobsXFU1gJSP4KG2XsVh1D2VgvoGEwIXMl5+QQpuaqhrEXQ5De1b4lXty3q+pV2Bk
         iO6A==
X-Gm-Message-State: AOAM530EAdErOLuOdPgOE47xfvP0tdq27uDz/YGkUtcq7rKJlpbXiubs
	9Mw4LsgeFjmRyJrLgkkPb3g=
X-Google-Smtp-Source: ABdhPJxLUuiXX6VDAEcZzwgNvrz/7AToRmF/i5dVHm4KFcoe50f6dPpCzXg9y8TNX2/fyxP7endxxw==
X-Received: by 2002:a25:e4c4:: with SMTP id b187mr10979473ybh.92.1616655718871;
        Thu, 25 Mar 2021 00:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:706:: with SMTP id k6ls2267560ybt.3.gmail; Thu, 25
 Mar 2021 00:01:58 -0700 (PDT)
X-Received: by 2002:a5b:88d:: with SMTP id e13mr10162916ybq.327.1616655718464;
        Thu, 25 Mar 2021 00:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616655718; cv=none;
        d=google.com; s=arc-20160816;
        b=R2NlT7Ae1T4qZLJaEaKWRC5HgFdkoZRMzftSp9FRrN/YK2ei8LVmGbmoGbKLhYZPzo
         Wr52zeDvAX2ngqi3w/WJFgJVuJFmsVKLZuYTSuHiXiIjyPHMgmNVu53ckXjMT/a1ycJJ
         09tuYO6C7oXXe/apcOCETp2501SrvGwSkeahdduA+FAe5KP6hbNFcW7+ZORuTu1ezPlE
         CVIQ+bW4hmnurtyA69XGRyNJVcO33tsswlLrW8w4OF9kyzlYJ5C+h63eZvj9oFpSVixd
         UrBSZEyBegUdSj1u3E/kCr2kMOdx9jDV0d/4OHuQmk+nAof2E6L/OMO8rgDgUS5X4iyg
         45eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Er9VTBwwaI4g9NSWPaQXCrSglwdU7EBlM0d7c0+OO70=;
        b=yKe2doEzX1TSMeOtp9LAGpe2WW1ScI5aPnKlJ1oFeY6l4zx7K3gQ9xmFmkcgMmqhGj
         yPMbNWiJCkbA0BfCxJUI7KXXKKOzzsfo78E4OdVpTTgZ3jgEWlbmcMuKr0LPQh8UJX7u
         ehribnB3NPVlED06bPYeDba6HbELPhhWi+rjMYwr30V8YvUwmRcTqIACZ8A+uouXICkS
         Vhg4b+J0d/XIypbZwm4GQo/Skz13jo9OF2/teb4uTKI9PaAl5pq64BpkOFg7Qf0hfDIm
         08xn7HOXJwN3H/okhDNz8s2WosDZQls+s8AIcgrbNpRSeNH18a9E0iEcGJJOWy7hhKUF
         LXTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hbSQau/S";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id l14si341314ybp.4.2021.03.25.00.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 00:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id s11-20020a056830124bb029021bb3524ebeso1066665otp.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 00:01:58 -0700 (PDT)
X-Received: by 2002:a05:6830:1c6e:: with SMTP id s14mr6341695otg.17.1616655718013;
 Thu, 25 Mar 2021 00:01:58 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-8-elver@google.com>
 <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net> <YFs4RDKfbjw89tf3@hirez.programming.kicks-ass.net>
 <YFs84dx8KcAtSt5/@hirez.programming.kicks-ass.net> <YFtB+Ta9pkMg4C2h@hirez.programming.kicks-ass.net>
 <YFtF8tEPHrXnw7cX@hirez.programming.kicks-ass.net> <CANpmjNPkBQwmNFO_hnUcjYGM=1SXJy+zgwb2dJeuOTAXphfDsw@mail.gmail.com>
 <CACT4Y+aKmdsXhRZi2f3LsX3m=krdY4kPsEUcieSugO2wY=xA-Q@mail.gmail.com> <CACT4Y+aRaNSaeWRA2H_q3k9+OpG0Lc3V7JWU8+whZ9s3gob-Kw@mail.gmail.com>
In-Reply-To: <CACT4Y+aRaNSaeWRA2H_q3k9+OpG0Lc3V7JWU8+whZ9s3gob-Kw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Mar 2021 08:00:00 +0100
Message-ID: <CANpmjNOysjStB6VPDNaBnQe37VWtWq5c-7_p0kFbsbN5ohD0Lg@mail.gmail.com>
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on SIGTRAP
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
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
 header.i=@google.com header.s=20161025 header.b="hbSQau/S";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 24 Mar 2021 at 15:15, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Wed, Mar 24, 2021 at 3:12 PM Dmitry Vyukov <dvyukov@google.com> wrote:
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
> >
> > One potential alternative is use of an opaque u64 context (if we could
> > shove it into the attr). A user can pass a pointer to the attr in
> > there (makes it equivalent to this proposal), or bit-pack size/type
> > (as we want), pass some sequence number or whatever.
>
> Just to clarify what I was thinking about, but did not really state:
> perf_event_attr_t includes u64 ctx, and we return it back to the user
> in siginfo_t. Kernel does not treat it in any way. This is a pretty
> common API pattern in general.

Ok, let's go for a new field in perf_event_attr which is copied to
si_perf. This gives user space full flexibility to decide what to
stick in it, and the kernel does not prescribe some weird encoding or
synchronization that user space would have to live with. I'll probably
call it perf_event_attr::sig_data, because all si_* things are macros.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOysjStB6VPDNaBnQe37VWtWq5c-7_p0kFbsbN5ohD0Lg%40mail.gmail.com.
