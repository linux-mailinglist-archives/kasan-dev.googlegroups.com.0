Return-Path: <kasan-dev+bncBCMIZB7QWENRBZPEYWDAMGQEYKPRKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 061763AFC8B
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 07:17:27 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id q207-20020a3743d80000b02903ab34f7ef76sf16744094qka.5
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 22:17:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624339045; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjYWOlJ5dkJYzJyX9uqoA66uaOQQ/GCvvIW2HopTYw6Swe/eFdNBO3Tzq29s8Zzbfp
         4yfXVguhyRxPNNEosM8pHSNjpszKcpkseUiL1BlkJ4arLDO4ANIiyHxpXhVqeV64hzI4
         hNKXjuUMroHKStTc9sDErIKAGdGAoQBYL9P5YJEgItZsqC/8U/EytlC6oYRjF+HGpli1
         3ld7IaZSL6JYCPJ/rM3Vng2Qi2frzvBjmNGPabJFWM5wMF9CSDFVDWw07+y/2TnwB8IU
         Mzu68QbAOB1mUbFxnTGhn1jZDXyundLZikA1BmQlVnnxV7fVrpbSkJchpV7508XVr6J0
         ABPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YLqYk1Y6ZsBGAZchoY7aUZjBjozAjvMgyyHc2DP7++o=;
        b=XswdDd4VHID4IVd0QJnZVD4ilJoY4J30DO0RMLsxSgkJyi5ABtouE12HXGuny1Ydfz
         a5NzNfGwPbDWQivCZW/ecQmUTfdh53mq67R6qbcrFS+9mjIru1vJPaX41hY9KRMOV8Ae
         gzreei/Rmmr8VZLqXugMu07jJB6wUbkOUCVuUQy/0Y7Zb2LlRJYTgoWVka5q2T3PCcZj
         z56xN3TMK2yqstMt9SR5AipGINpNqwtzeln8MFeAsTHGQ4eeDHEze0yYhNQL01RrVA/Z
         L/OwSrKTLIdqBfbUqYCBP+9krRFwyRMy6RRmI13smpi1AdhgkJFLUmL+8Z83L82RbeDd
         51Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DHtz42yZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YLqYk1Y6ZsBGAZchoY7aUZjBjozAjvMgyyHc2DP7++o=;
        b=pWOWVPEEjaUSgqkRsXgeV/lT0WXtKE27VUk4K9evGCXD/t1SKdx/ZHWN9LR1suzc9o
         ueqinHKAPijR8p9UCIQaT870/f8q0WnUyfUaBv995Mc0LseHPemCO01cxbgp7MkBSuzI
         ZY3NquZkvKb1+7BECygZQw1rlk2QsoaLHq6zLQezpb7bVUiNQKRIVdvhLx1BVJGuaVDJ
         +egdeaLudSEsEzSt9lS70vVqA1Bsvp8bBgANPN7PZA3QB5zKrI8zZ8ZSEHJLdTNSdoiG
         5e+O7f1Ego9SpTPpy/s4P4MXzvFr5XuhqqXVckpmvWIg/s9GRVcTZrelUVdPToa/RfOw
         AiNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YLqYk1Y6ZsBGAZchoY7aUZjBjozAjvMgyyHc2DP7++o=;
        b=hhHj0Bs63sbqVjC2Z58BHFSKvLpsYmDqR4RcJt7NIfYfXUgy8/vcSvzXQ740OTA90O
         diOMozKx+j7HK0nPo0swQ8vJieGEUDHUhL+iZ5vJHBz0lbJnx1/p+u8hS0QaeSeDSb1f
         41F2INgs/FJnsOY3SSUqXlB/O+LGlgYOjU/M8GVj3JMN/5FMtDQBsl0HkoypP3UA3ixS
         N0f9uKy+ZH/3sffAFfuvl5pmqe02C6UDqRW3ZFPlgr062ph7ith0Y8eVS2ZfLpZ2TVvE
         Pdub5Su/oQE0vCw8NOZl4oTEAvsIjO4kgkJ9NhqTSEcDkauxDbxwJF4SyI1wDD69LMxE
         ao5w==
X-Gm-Message-State: AOAM531RvQ50PyvCgzWLsmyWMdrGlkJuWVXv7N0EG4KeoL2aTa82DGST
	KdM7zC07SsJS9TAfOx7s7G4=
X-Google-Smtp-Source: ABdhPJzezx2b6HcbrHQfRrbbyk8zhrhEnub2IfT1SV5pCydq9ABUgIfQNCnjtB/drLKR1+5bq82uiA==
X-Received: by 2002:a25:c6cb:: with SMTP id k194mr2329420ybf.286.1624339045780;
        Mon, 21 Jun 2021 22:17:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bece:: with SMTP id k14ls10429323ybm.7.gmail; Mon, 21
 Jun 2021 22:17:25 -0700 (PDT)
X-Received: by 2002:a25:28e:: with SMTP id 136mr2379629ybc.74.1624339045325;
        Mon, 21 Jun 2021 22:17:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624339045; cv=none;
        d=google.com; s=arc-20160816;
        b=kbK4eJz5Q93PMfxnIM5SY0n0RHgKs7Sh22zK0wfGRJ6VTF6gLW14ztarHBY/iaX2ai
         DZYfKeZ5ToR+G+n+bk6YY4Y+phHJ1QqcuOnZjXS2o3YBf20yk1Q7hgUQna3Sjj7MgrJo
         weD3YDipQiVmtk1Szb3ulQkIVwwWbPNH1T81gbPlK89sKBIbJ9GhRY6ftGvNrg7R0A6+
         qyD2+LkFXHi/M+RkLIgolcfqHqM6V9mAt/1uTfhYVvC9QjB1cPE53vLugvVjswKlPoPF
         QWxQeixfL8OY4loe4BQMXlqqcT+SZ9S5PhDC+hs1h/ikcTGMiOHGv8K9gviouFJl4JgB
         JPGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NqSlROQ23wCczEkXMjh41SAPP0yfuUJ4MkjfzIZVHcQ=;
        b=aebNY9D/C6wBAuZFGXkpzFC9XypT+Za+NYye0zPTwKH0gFT1eR/2x1fBcg2PPBD49v
         47pdpbhL73/IN/i1g56wtvJs5vOYbWce6msYZ/n9Xlf9XXiPga5t2/S6qRKBgAvy8JgO
         CVIIXy2AdP26uOCaojH0XdiOnaehdH2LnG1nJqYWnUe+jfHKaZMGCFIUOsJM/DvEARmI
         NKb3Pbb2SnZoYaNNiIupj4UjBYUEl+PeAGSkMrj8b01dbUrYmJIOd3zuNlAcbCA6BX+Y
         WxgMSQnND/tbi0qmcRSKfEPTztoDfmpSr6SOC8h1DxwK2ZQFDAW8qmrS/mASgW3qKtVp
         NoRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DHtz42yZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id x199si96798ybe.5.2021.06.21.22.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 22:17:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id f5so8661614qvu.8
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 22:17:25 -0700 (PDT)
X-Received: by 2002:a05:6214:80c:: with SMTP id df12mr23565588qvb.18.1624339044833;
 Mon, 21 Jun 2021 22:17:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1> <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com> <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com> <YNBqTVFpvpXUbG4z@elver.google.com>
In-Reply-To: <YNBqTVFpvpXUbG4z@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 07:17:13 +0200
Message-ID: <CACT4Y+ZJvcYpiCUO6ioaz3ieQKU=X8NBCQLsFpQqEGosJfW9zw@mail.gmail.com>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>
Cc: Daniel Bristot de Oliveira <bristot@redhat.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DHtz42yZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f32
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

On Mon, Jun 21, 2021 at 12:30 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
> [...]
> > > Yes, unlike code/structural coverage (which is what we have today via
> > > KCOV) functional coverage checks if some interesting states were reached
> > > (e.g. was buffer full/empty, did we observe transition a->b etc.).
> >
> > So you want to observe a given a->b transition, not that B was visited?
>
> An a->b transition would imply that a and b were visited.
>
> > I still need to understand what you are aiming to verify, and what is the
> > approach that you would like to use to express the specifications of the systems...
> >
> > Can you give me a simple example?
>
> The older discussion started around a discussion how to get the fuzzer
> into more interesting states in complex concurrent algorithms. But
> otherwise I have no idea ... we were just brainstorming and got to the
> point where it looked like "functional coverage" would improve automated
> test generation in general. And then I found RV which pretty much can
> specify "functional coverage" and almost gets that information to KCOV
> "for free".
>
> > so, you want to have a different function for every transition so KCOV can
> > observe that?
>
> Not a different function, just distinct "basic blocks". KCOV uses
> compiler instrumentation, and a sequence of non-branching instructions
> denote one point of coverage; at the next branch (conditional or otherwise)
> it then records which branch was taken and therefore we know which code
> paths were covered.
>
> > >
> > > From what I can tell this doesn't quite happen today, because
> > > automaton::function is a lookup table as an array.
> >
> > It is a the transition function of the formal automaton definition. Check this:
> >
> > https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
> >
> > page 9.
> >
> > Could this just
> > > become a generated function with a switch statement? Because then I
> > > think we'd pretty much have all the ingredients we need.
> >
> > a switch statement that would.... call a different function for each transition?
>
> No, just a switch statement that returns the same thing as it does
> today. But KCOV wouldn't see different different coverage with the
> current version because it's all in one basic block because it looks up
> the next state given the current state out of the array. If it was a
> switch statement doing the same thing, the compiler will turn the thing
> into conditional branches and KCOV then knows which code path
> (effectively the transition) was covered.

If we do this, we need to watch out for compiler optimizations. In
both clang and gcc KCOV pass runs in the middle of the middle-end
after some optimizations. It's possible that some trivial branches are
merged back into unconditional code already (e.g. table/conditional
moves).


> > > Then:
> > >
> > > 1. Create RV models for states of interests not covered by normal code
> > >    coverage of code under test.
> > >
> > > 2. Enable KCOV for everything.
> > >
> > > 3. KCOV's coverage of the RV model will tell us if we reached the
> > >    desired "functional coverage" (and can be used by e.g. syzbot to
> > >    generate better tests without any additional changes because it
> > >    already talks to KCOV).
> > >
> > > Thoughts?
> > >
> > > Thanks,
> > > -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZJvcYpiCUO6ioaz3ieQKU%3DX8NBCQLsFpQqEGosJfW9zw%40mail.gmail.com.
