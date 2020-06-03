Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7Q333AKGQE5XYXYVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C61FA1ED252
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 16:48:08 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id o12sf1672569ilf.6
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 07:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591195687; cv=pass;
        d=google.com; s=arc-20160816;
        b=PtqPIN5oywTwoN6xT0HXZB9cwPGf5pbGjbCkGPUmk2EvTxxDJ4OoWM+4OLhg4DMlWH
         uU0dpQkr0LhVS5viZfvrOZYZUqQkIsiE7S279BHeL/K0Xq4Ouk2TglBjzczEzJc2rAOG
         p6QOjv5YD83UnLd02NGbNVqVWLf8pk6qqooOBSsze8yJtNnC8mCysaaVANgS6Z2PiX7v
         aqdtHyqhmXVcPvFmUzlE8sy8Sv1WOwdT4KDJuQIPBFRUU4/Pm1JjtUP5WS+qp6ujf0dU
         Am/bH9Mm6xzGACIM5VczVcq1GFl5hbHKxLXx6ZCP7MPs6D4Zc7hZD8wp16179xHZXe+4
         9yAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CChHEDCrQPBhqxbdVlMB6/Vr8gFPwq8nh5Fc+NntVz8=;
        b=BK57m4DGF8cOgNRLJalCncCYxXgLwKwhcKkwkkt4DkIwoDRFQj5WZCAb0iI7zjrMZZ
         q4m6a8/PQsG/vDQRvUmBRMAKaAGe8XtwgJ+Aujb7cmqIs68j/rCEgcnU5QsvwAXGpUs2
         n/iW9VyZpLQ6f6LvK8nYCkklGtwCpAGEb+Ztua/Ba8L25+YAy+GVAbd2gRf9kQirxf8D
         mS9sPHkO+WTfl3+xmVo40vy3qiWmXm474kEhbXU2yCSYKAs723VFC0dwcB1umLbSjyU9
         fn3knT5wjHIOvtCQH0oS387xoFK2IPRvI7oalYlzWsyRFKIhs/BWAuybGv+C0lNw/eBs
         zmEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MIkps4tW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CChHEDCrQPBhqxbdVlMB6/Vr8gFPwq8nh5Fc+NntVz8=;
        b=rW6DOYEUsGq2TTR09ut7XHUdCdq6Y/Xa6HZrliT3oOJg467ODFgjSeD3WWUmledRo4
         wSp5KspZRrGEdlme9TRqpy694KwOuYPi8cOIJnhIN7C56isdNNgv312CCLC666QaHTZT
         e8KSURc6ZPb+MYSkJvZAsjDpGnago+EJN7IhpEUYvGJS5z97NJY4Z5TVrg0wVJ0i1S9s
         Q52N6h4yyXmeSTC2uYs9b84kvxykBPIL2hMQHTORCJVbtfsVXA+ugbZwCe0oEgs+fIxZ
         M8rKC+aJW/U8bSu/eCKeG9Dna2NDbXn6wPwtQJoOArqMMgE6+VFS4/+qqF9XyejAL7Hj
         4RTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CChHEDCrQPBhqxbdVlMB6/Vr8gFPwq8nh5Fc+NntVz8=;
        b=hLROdwxTSLVbtJ3csAWtNONaMs/qVJFCbGim6KS5QsQXlZuQSzTzeHj+AfuG67vBEq
         IME1wPyHzA8hWLJwcNB4JiQrddsRy6RA+7IBsS0Ub7U2D7iAlZhLBhiqvQkKVzOIcfr4
         H0YzZhkhsNBceNYy6sIWJOluAa77YFGWjeDjWNObObvdJLyLqXOY5li9qvsTUv75PKBu
         Rs7Ex5pqbpbBtLGGK339TBlcgqHPXNS/t4+f50DPDcYfsdYySueYGoGtyWFIRksEtFM6
         Z0RYbmhF2wxa5igV90QSVu+sqHnATTJWC9nCvZFpWQtMfZH/jB0TjcnbnW9V1lUdm5+9
         CQag==
X-Gm-Message-State: AOAM532cWOyZNJQMT6Fqjs7XBzLg3u39Y4WAF6LaJ/HU8DzEKAjGu8m/
	1y+CboHZdC524mUnuDYQoMU=
X-Google-Smtp-Source: ABdhPJzNUGFclSo70P+R07xYY2ruZjuZ7Qt19wFAwcGPY8q+fcxN34rguq9Z7Q+PMN8bIWNYXbU5zQ==
X-Received: by 2002:a92:bad0:: with SMTP id t77mr4381052ill.82.1591195687632;
        Wed, 03 Jun 2020 07:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1453:: with SMTP id 80ls377222iou.2.gmail; Wed, 03 Jun
 2020 07:48:07 -0700 (PDT)
X-Received: by 2002:a6b:8b51:: with SMTP id n78mr120856iod.120.1591195687123;
        Wed, 03 Jun 2020 07:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591195687; cv=none;
        d=google.com; s=arc-20160816;
        b=RtUw6sLGtrBc5eAvw/aN7c4XMPi2PjgPOjcm6JgddLFQ4QauBzViW0UzBqnhvBTlje
         TgZx9hbAvXJNU5EyChz4J2yq942AzX3kXaiHR306PF4yq97eUBZB1uuBvUfUswYH2rsa
         7qM4E5NhN/D4tXTukLFjmGp+dqlZisDmadaovxD1LNLhTk8LUYAZOq8f6rH9iP92UXZF
         rA2+hHhkmj8klhsYAIugEMFQTcZFfihaNGM0uyoH7bvpR8yqagnYgnMUPLERJDZQc1uG
         iV434TcPjfRFotLCJuEXYJV4s6mxZ9DzfuskqhGj+falzBnsoq2detxqMNamZ/SrfKkq
         LDcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K4mWQ9BO+ADAedoRkxDsxNn5p6Rl0+bZnTb72ellqDY=;
        b=TRheDYP0RmQ8lYRMHU+1iwbKH2TmberJzE+L5C+OLZkeT2ZwdsIbNpFmZmpy2Ru31L
         n+37qiP4ZpCUZW1UJm3G+Szk+BiBiaU+2tk0nPO4D5knfIbqCo2KtWnCozPXAmOYNHTR
         dyk2nEGRXiCYnB7xQn8Ui6NwuBXsySuChc9Al1NBEf5GuC1w/OEdL+4g6E7uZX9Zce4/
         He/gVdLiky56PVnHGtI0xOgtnu/ZjxxLSQ0yKf5g3eSeOM37woNU4ciAz9WA+bPY5UHw
         /u7i4qRU6CBUV4ewmnYEzXIDOmJs7GT1LSUlX1xj7af4CfDoVPiHK22b6ZUkj6x4CQVX
         IZnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MIkps4tW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id 29si93908ilv.5.2020.06.03.07.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 07:48:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id v17so2094784ote.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 07:48:07 -0700 (PDT)
X-Received: by 2002:a9d:6958:: with SMTP id p24mr256297oto.17.1591195686488;
 Wed, 03 Jun 2020 07:48:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net> <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
In-Reply-To: <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 16:47:54 +0200
Message-ID: <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MIkps4tW;       spf=pass
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

On Wed, 3 Jun 2020 at 15:32, Marco Elver <elver@google.com> wrote:
>
> On Wed, 3 Jun 2020 at 14:18, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, Jun 03, 2020 at 02:08:57PM +0200, Marco Elver wrote:
> >
> > > What is the .config you used? I somehow can't reproduce. I've applied
> > > the patches on top of -tip/master.
> >
> > So tip/master, my patches, your patches, this series.
> >
> > $ make CC=/opt/llvm/bin/clang O=defconfig-build/ -j80 -s bzImage
> >
> > is what I used, with the below config.
> >
>
> Thanks, can reproduce now. So far I haven't found any indication that
> there is a missing check in Clang's instrumentation passes somewhere.
> I'm a bit suspicious because both Clang and GCC have this behaviour.
> I'll continue looking.

This is fun: __always_inline functions inlined into
__no_sanitize_undefined *do* get instrumented because apparently UBSan
passes must run before the optimizer (before inlining), contrary to
what [ATM]SAN instrumentation does. Both GCC and Clang do this.

Some options to fix:

1. Add __no_sanitize_undefined to the problematic __always_inline
functions. I don't know if a macro like '#define
__always_inline_noinstr __always_inline __no_sanitize_undefined' is
useful, but it's not an automatic fix either. This option isn't great,
because it doesn't really scale.

2. If you look at the generated code for functions with
__ubsan_handle_*, all the calls are actually guarded by a branch. So
if we know that there is no UBSan violation in the function, AFAIK
we're fine. What are the exact requirements for 'noinstr'? Is it only
"do not call anything I didn't tell you to call?" If that's the case,
and there is no bug in the function ;-), then for UBSan we're fine.
With that in mind, you could whitelist "__ubsan_handle"-prefixed
functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
case is quite rare, it might be reasonable.

We could try to do better, and make __ubsan_handle_* 'noinstr' by
checking if _RET_IP_ is in .noinstr.text and just return. Would that
work? But that would only be useful if there is a UBSan bug. It might
also slow-down regular UBSan, and if we assume that the
__always_inline functions called from noinstr functions that end up
with UBSan instrumentation don't have bugs (big assumption), then not
much is gained either.

Thoughts?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPzmynV2X%2Be76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ%40mail.gmail.com.
