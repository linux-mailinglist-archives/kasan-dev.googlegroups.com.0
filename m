Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCH3Y6GQMGQEYTOMGIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id ED5CF46E8B4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 13:58:49 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id bi22-20020a05620a319600b00468606d7e7fsf6687518qkb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 04:58:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639054728; cv=pass;
        d=google.com; s=arc-20160816;
        b=SgiLl/2wg1MYu0EzrOOQs8K/egSAvlKmEkCdX5DNbhekBuQq4QrZwEv0fMwHbZr1jV
         UgRX0bCbGjVqcaqd1WqejNOX0iCIBTdtQZ3TjvOXzVLXG4KPdb/FS9M8D+4ci8CBLj//
         IiE8XdjbZ0qI5m4kwFBBSvcR2wfn+Thvrn6zBZpODmL+l04Udsd1z3rvEAGXfev+DQ5x
         LIRY3a0eMOqKgf9mZRrVYlR8WS0Ur6BsNtSZHgkyWvmE8LDjUSCCd+Mj+JAnOvjnRPgU
         kaADRCnds6CEBLlw7Puo9uZVlm3Aigxy8+LXRNnnY5upWVPN8DeArOciPmtGlsRUnkYB
         /j2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XNSM1kIqiUhgL4WTUZqvd7S5mm6q2CrQbjMW5b52Ngw=;
        b=RVBpxCVSJEqiGSBoz4kcJyW/I82zUBKtV+kZD1Rf9bbsYhD4xTeiUjPjKnDDG1DcSW
         JsJi5GXGeFN7HAe+7giZiSjjjW33CbNIr6Lyoz9QYwhBewkuxCFfJEE9cdvzcV93r+n9
         HElj9mqhPmml0ALUlZer1xeH3r1Pfei8L7rEa6hjmWLj5Axb8rVoXZph+A8kVFs2BSSv
         7v+gOL18nftNA7QfeWbQdLorW3bnuut2Pbex0f9o1S3Rxs+1nZQgVDHVc2cD5YAVMhkD
         HcItzwiHZv5dTKWXLucURQEFKO/ekPEBtPPje8HPV8F9JzjYrmRFqNUmbSmaPJeCx+Pv
         JNvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ODJRjoun;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XNSM1kIqiUhgL4WTUZqvd7S5mm6q2CrQbjMW5b52Ngw=;
        b=D5IgN9vXr3SQzFcVutd6JtmuuZ3Y+Rh3dH/xliST2Myin8+54iaiBGLEWI8FfzajNh
         hBFPRu8Y55cS+WShK3MlbOdirx4Rc0S4UIM2a8jNPXn2D2x13ow7/boRkHYkuO2REfCS
         6DvcSbbAHjhb/yHz43hWs9EH8ARWVtYKJm1Ymb2zDU0yH4TAC6R0ptKkKj+MbdulgDEg
         kKT9TNoGrRJBazKYG+MG49pKwzlq8lFd4wPdSMXzAfiIjwkBuO7dao+toWE5lfdx7dAP
         7ZoMDEkhlykxW8T0agHrWz09KoerMBsZLf6TyXeDLMGHwB8Pju/PoIinMe7OvA6QllE0
         cfgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XNSM1kIqiUhgL4WTUZqvd7S5mm6q2CrQbjMW5b52Ngw=;
        b=UiBrCHXZ3MITmsNqX2QSXtBZ7jJoFSwbtDMwhufUkU9fTANdRz3ly6nFLL+Gl4zSsW
         a3k3OIV+961T2bi6BwwPE5r6esNPkqC+pBkjrpawNr3yAEhZeYVEjWBHmVqzbJmERo4I
         H8KZBddPDnNATx1KJLqcvyTb6dQsTHZnhi80Nv6jl3YTtjpkSjRan6Jud98NYTTAyR+u
         Qd90Mwty49GA4rMVP9LAKamov92raoyePnzlJBhEwTMJ5aG6ALWS6IBoIxpVcD9wn+a7
         x9y2WV7NyUnNvRJ5QE6m0iEmBmDIA+PXLVhB8SGPDyvtIAWizq3D1lwNLw3cyskncK2r
         tOmg==
X-Gm-Message-State: AOAM53339hWeKnsXoH/AT2YcZOOs1HNrVBToBMDfmQi7wNNRoLRB33cg
	6UhNy57xcrhVV83PmY31uGE=
X-Google-Smtp-Source: ABdhPJx435/EM36sakgE4kt+j90fdkfuYD3lfQyj92Qt7T5z8jSjxWe03xf86+kobla7HPXbTKvfLg==
X-Received: by 2002:ac8:57d0:: with SMTP id w16mr17111098qta.398.1639054728807;
        Thu, 09 Dec 2021 04:58:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a81:: with SMTP id s1ls4047979qtc.11.gmail; Thu,
 09 Dec 2021 04:58:48 -0800 (PST)
X-Received: by 2002:ac8:7774:: with SMTP id h20mr16729655qtu.236.1639054728319;
        Thu, 09 Dec 2021 04:58:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639054728; cv=none;
        d=google.com; s=arc-20160816;
        b=sF5KNAnWE7A3tXH83Rx3bs1hxnyYyEliqccK8Tn3cGl2BPI56SKYY3SEUAocANVYPY
         kYu50DjupTnWfI+BExaOSwn4YqtlgAeGYBnyx/Dwq0Eby773NxmmohTSbG5hnsvGOkQ7
         CtO56uuWd3bABwX0UWcDZx3voj+qI1iQ360IvxkiRd2+d1BEmt/FIx5fwEluvVfIFZlX
         LlQrawMWOoShPnbZVRLrE2qeKw2OyEEsMy4ZxEWuVnLc9hoRRzOP7BkCLjfKas251AH9
         OnJGkM458QWmQxaEB3/UttgWFEFEBhGuDEGCVwgeW3pYgGC8w+iiBNc1zdznMHqYJZMP
         8n+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lxsC+6JiZmFDaNw110BSUcqVFCAa+894CcThmcjMkw4=;
        b=vv/yDqwHEo1dmB5Y7vSV3Ucoa9KBDlYG0aeg9IFo008WM8eahiyqfJgAglLvZMEp97
         JR2FZ2G8+SlQr/CVJhHWyzX/X+MBHMOjbOGODTavotqU0TncYhMzhjUR/0/Tjtl4PfKD
         rr+6AIDJvqfilyWiTgCRaxiZSZd8dhPbOBCYOAIsyaYW2MF2ggEZo5JFZhasWmzJgdf/
         F3PajRAjWu67jFvFAvC3VLMtyXLB+hicom94e6jNU1J+nj9wRzbZhTQzSSdQK+9nJUZL
         up9PpaVTMtU0cTcQRlz0UX5tEkWQAcyZB8+qkG4abNXHx/o81FmieqgL0/GVId/Lwtpz
         bM9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ODJRjoun;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc35.google.com (mail-oo1-xc35.google.com. [2607:f8b0:4864:20::c35])
        by gmr-mx.google.com with ESMTPS id bs32si836895qkb.7.2021.12.09.04.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 04:58:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) client-ip=2607:f8b0:4864:20::c35;
Received: by mail-oo1-xc35.google.com with SMTP id d1-20020a4a3c01000000b002c2612c8e1eso1645771ooa.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 04:58:48 -0800 (PST)
X-Received: by 2002:a4a:cf12:: with SMTP id l18mr3585635oos.25.1639054727653;
 Thu, 09 Dec 2021 04:58:47 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <YbHaASWR07kPfabg@hirez.programming.kicks-ass.net>
In-Reply-To: <YbHaASWR07kPfabg@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 13:58:35 +0100
Message-ID: <CANpmjNODi8sLHe8JoU-phddf++vh+1sW90b08j-yM7chsecxyg@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Peter Zijlstra <peterz@infradead.org>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Jann Horn <jannh@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ODJRjoun;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as
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

On Thu, 9 Dec 2021 at 11:27, Peter Zijlstra <peterz@infradead.org> wrote:
> On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
[...]
> > There are several options:
> >
> >       A. Make memset (and probably all other mem-transfer functions)
> >          noinstr compatible, if that is even possible. This only solves
> >          problem #2.
>
> While we can shut up objtool real easy, the bigger problem is that
> noinstr also excludes things like kprobes and breakpoints and other such
> goodness from being placed in the text.
>
> >       B. A workaround could be using a VLA with
> >          __attribute__((uninitialized)), but requires some restructuring
> >          to make sure the VLA remains in scope and other trickery to
> >          convince the compiler to not give up that stack space.
> >
> >       C. Introduce a new __builtin_alloca_uninitialized().
> >
> > I think #C would be the most robust solution, but means this would
> > remain as-is for a while.
> >
> > Preferences?
>
> I'm with you on C.

Seems simple enough, so I've sent https://reviews.llvm.org/D115440 --
either way, there needs to be support to not initialize alloca'd
memory. Let's see where we end up.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNODi8sLHe8JoU-phddf%2B%2Bvh%2B1sW90b08j-yM7chsecxyg%40mail.gmail.com.
