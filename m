Return-Path: <kasan-dev+bncBCU73AEHRQBBB4636X6QKGQE2UWYPJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A5022C31FB
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 21:32:54 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id 185sf10830705pfw.18
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 12:32:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606249972; cv=pass;
        d=google.com; s=arc-20160816;
        b=QaXnCCKinWcRBswX6RBuCExuWo0ocMAY2iyM4Oof5xG17wi6Gh/NhKwplI8eR8tRjV
         bqy4GXOr3iiPVa4fPyCb2wKP59WG37W46B9sjOWvu+aW8BTrflordw5Xk1gFsbB1MZKr
         kWgT4B36yFeY0J0A0RElged5lkypimsM+j6XT00Ru5gkLC1IzPRSRlwShqURZs1DLR/0
         JxGN+VSsPGZzOPw4z3JbEZ+hoMF0ZhrRaOktAgUNdoDfZprDBbrmirD18pNcXl2mxCmW
         v9o2VMY67SjTJThMuVgaD4NIBMBo/7RrgExj1nVmlEP9g4VXTP6q3dDoUaSOYsNjY/oy
         /Fyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/B+dQS+mU7LVzP6dB7HAJcQU482HlYHhHjYCDEW5cMc=;
        b=QMyLh2OaDw6lRYw3wNk4acszdQrnjZA5QWnWMg6O7UjDqpXH5zirCokDxUxVC5nxuU
         UZdyuRaqbeOCymeUAMx9nTRWTijQIPJwrdVoyhAuSuDMkIvYM3sRkXmzuR4wW5nuKjBW
         Ge2XfhW519PeEAFFJbqZUEuSkFcVfzg5V4DVDMkX20ZeM0Niz4VhBezIIr0k4Ya7XHON
         RtsghVp/GoAlyoc7M2++Fc9HhBLowKb2Pp0ssrCv2xJ0ZhMIr99ISPm8n/Xdbi20cS3F
         mUdMja9nooHZGmdAoKz16R5wHKnZRdubxp/eUqDu1aQ7/wdJmezT3T+0wGflP1mFgGVM
         rodA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=izch=e6=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IZch=E6=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/B+dQS+mU7LVzP6dB7HAJcQU482HlYHhHjYCDEW5cMc=;
        b=jMTmg5cN/8AM5k8yEed5ibKE4l1UjE7FU9rg/18FFINve6iT26DZjAZwl+oPoU7eH2
         sbii+RAfADj2bXqSt4T4+IAu8E4Jd8TT/pAoDGunePv/w/fIznccoIaMYappMBaZFvjo
         JXbuN89qPxlkXSDxXwLSV/f3S4AzK+4E/8B7hRSPqLOs5yDZ6y1jNSrqv6Gm84Zl51Xk
         84Axf0hRkGnJF9uP3aYPXiLcoLxgxQCvHsSnvk+lMtBXp0pkSYyttaghm23GhpcI36Bf
         nJEhkn+sjvj6458OWtxFWbFuUyEmQthy3NMhmXLvySSbsTWTUPmWYH1Fd44a1pIhjU4a
         s7vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/B+dQS+mU7LVzP6dB7HAJcQU482HlYHhHjYCDEW5cMc=;
        b=oU0JnSX2zgl7KLMl93Tvs7TOAUzP7++H9nkkouFx6LihlFrfmvU8QjmSpptuEb6TeU
         BA50hU02+G1NtGuCwMxRWiapLnypZSk4rNKNr2sk5fw5Mh5XKXvBsbfz4dQ3l0V6XkPt
         Y2/b6+ieJamy9XtsvQ9r3++z1HEURwB6MAu1BBdRQ6m+Sr4d8e4hevxpelAH8EXOMrXV
         +KnPGpyWF3G/0eIiAy66zn20wZcDsc4WuSbZIvScmqrOXcilE0ajsN1toy6Uik5REPRL
         mNZm8ZDRhL4EsCW4D6i+J2PqzFcmEvQmC5ND59u+keMcF7eQbyfbxmp5DIKj50laT0YJ
         vmaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hXmaawAt6s7YUV4eyq/PI8MKpEbm8OaaDsZzWnJFejzmEFqdY
	w5wuRIUfzLzFL1vAuvKOIiM=
X-Google-Smtp-Source: ABdhPJzBqM5MI4Pu+lg3KcPaGRdrpEIrdwNS/xRUb6GjfwkkTu4EOSHe8QMWsp0ZYvYEeCLxBmEH9A==
X-Received: by 2002:a17:90a:4814:: with SMTP id a20mr362437pjh.163.1606249972732;
        Tue, 24 Nov 2020 12:32:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a44:: with SMTP id n4ls6516pfa.7.gmail; Tue, 24 Nov
 2020 12:32:51 -0800 (PST)
X-Received: by 2002:a62:2ec4:0:b029:18e:f566:d459 with SMTP id u187-20020a622ec40000b029018ef566d459mr10988pfu.80.1606249971138;
        Tue, 24 Nov 2020 12:32:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606249971; cv=none;
        d=google.com; s=arc-20160816;
        b=NtGbjhDaW/r5pLHhTHyXl4eiaoh2vGLKo22IQRK0PgSw33wULwZcxgWG+1D5+zAFOL
         pmUmN3NHmLNxgxjUBmoDNehhNAQfKDDhLVnwE87RZqo645fSa+wNzFvtD0CXviWrBIMp
         KkNVTkANdIwNguV57gPTzdzNtF1KBepdW5U1GJr045qiv3wiPUq7w4GhjEqGNfcPQmd3
         8DWX+6CzL2BWvVdA8gF0nI+ejbZQigUYdT82d8pHund6CrsXDoe2l/rTT4D2V+OpLyDi
         pSA1rWlSkbCGUGGH/nIFNhVVbJBtTkNvTfalSJchEJ3F0iRSUHJW0fbxkn1OF89lPP/2
         4w1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=oy9GM5J8lLFyHkQD3tKi2715+OHGZVyuFeesB9p4QH0=;
        b=ZBY8qoQQGQF5fGLhfaBnJv1xLWaqkOnzsG7PEOMYXebOqS1hBp9itPz/SZ1HKgl+Zy
         ToV+9H/wBGJf3WprLGCN7hD3Uhb2D6L17k+laavMkcT9PARyAqIvmaeWCA/cdBGFo+5O
         V+IKVQmIFofMopvk1zohSiBfW0RRHLiZEMuaZG+Te2JFfTbe/2zwsJNtMw8lGb6vT40n
         7Fzy+DUCYzr1Kyc+dPJ4M/LfEP/d0Bt8n9MQbclC8Y3U4vwZtd730uk1oKjm4ExpAUHD
         kdWK5BsNMSdVoQUKa+3lLRs6r9LLoqUmtU1a1HS4x+D/OZJ8DKCJEMD48bCM3E8Oid0I
         Q1Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=izch=e6=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IZch=E6=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b26si9593pfd.5.2020.11.24.12.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 12:32:51 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=izch=e6=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from oasis.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C409620678;
	Tue, 24 Nov 2020 20:32:47 +0000 (UTC)
Date: Tue, 24 Nov 2020 15:32:45 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
 Will Deacon <will@kernel.org>, Anders Roxell <anders.roxell@linaro.org>,
 Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn
 <jannh@google.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>, linux-arm-kernel@lists.infradead.org,
 boqun.feng@gmail.com, tglx@linutronix.de
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201124153245.5bda420d@oasis.local.home>
In-Reply-To: <20201124194308.GC8957@C02TD0UTHF1T.local>
References: <20201119170259.GA2134472@elver.google.com>
	<20201119184854.GY1437@paulmck-ThinkPad-P72>
	<20201119193819.GA2601289@elver.google.com>
	<20201119213512.GB1437@paulmck-ThinkPad-P72>
	<20201119225352.GA5251@willie-the-truck>
	<20201120103031.GB2328@C02TD0UTHF1T.local>
	<20201120140332.GA3120165@elver.google.com>
	<20201123193241.GA45639@C02TD0UTHF1T.local>
	<20201124140310.GA811510@elver.google.com>
	<20201124150146.GH1437@paulmck-ThinkPad-P72>
	<20201124194308.GC8957@C02TD0UTHF1T.local>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=izch=e6=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IZch=E6=goodmis.org=rostedt@kernel.org"
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

On Tue, 24 Nov 2020 19:43:08 +0000
Mark Rutland <mark.rutland@arm.com> wrote:

> AFAICT, the issue is that arch_cpu_idle() can be dynamically traced with
> ftrace, and hence the tracing code can unexpectedly run without RCU
> watching. Since that's dynamic tracing, we can avoid it by marking
> arch_cpu_idle() and friends as noinstr.

Technically, ftrace doesn't care if RCU is watching or not, but the
callbacks might, and they need to do the rcu_is_watching() check if
they do.

Although, there's work to keep those areas from being traced, but to do
so, they really need to be minimal, where you don't ever want to trace
them.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124153245.5bda420d%40oasis.local.home.
