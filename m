Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV44TH3AKGQEQDDT7WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 544661DCA6F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 11:48:08 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id h129sf4676046ybc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 02:48:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590054487; cv=pass;
        d=google.com; s=arc-20160816;
        b=pBwrhy4VedghO0iD+2ua3ouITckRZLB6ZXBUgSmXtd5RPlUlmcHi+s8xtH+VnOLpg8
         P2KhYu/IUQ75jEYMO4iEV5eUfTf7x8nF0rVihuU1wIMRx63+sxVLeEoHvwQKuUbwW2aX
         8KgisF9g6Rd84/5VMMTrjaZtm0P/qb3WE5twXbYuqbkK/aWJHQ5U9BmZ2275UBOOYDDi
         JN4ULbTAKA5BmtcwbGHUkHGbhwnvP30GF87K2HKGMvfF9mbscg3STakEau7rWTRXOOzi
         GCMdH4ClzathbJKye/WabtT6fRukqh3/KO15H6FgkmuVrLDk6O5+rGCdv7QtgZGmeGXv
         YXfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YtTgHiK/hvloV+isoTSGh3KTy09xk5xFGhrqhpxPTbo=;
        b=wx8IGZtIeVq8qAhLk8fuW28HJmO7KfDfwlHYSvlwC3nRxE9w31KPgFcznFLb3sAVcu
         fQtx4Ap0iP+Msagz57hMYxy6/gyXGz39kFl7mASieYtx5zVgZ4NL2mM5cMrpOcySCCQz
         B9FBo9+YeduOEmb1AaOBmHSEgklSA4fxA4GlZUc5keGo3OU5mgIWDnHJ2bnhy0SFjGSs
         lxDzhe8DGJ3jAl4m3k/5LkgC+iM/e85L53UjlClgPWiXJK+JEbYqqWhb7/SRFYs5vly9
         tAsPEMkFmcbPJNVMk9piV77bSHMpYE1+Bqj6QP/HiScwZs7EkpIsJnR4fqB2xdnDVsu6
         iBcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNY9dMzQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YtTgHiK/hvloV+isoTSGh3KTy09xk5xFGhrqhpxPTbo=;
        b=kiv6ChkwE3kFyG/V+YKKcnjQDz7vEKwQpBOShgveMTQjDYEAl8zr7z5yiBXhrgiAjt
         wDM+D/CqQArxyyryR52gkij2zvfqJXNY4/352tDPQ9W15Ltqld2PYUaLCeHbOoc5l2IJ
         uWq+VeXm3wJScsrom+Kjm+XLgbd1gjN++RC7l2KLNqopOEJ/X+cMqHm9H24Md28Fntnk
         EKM1Am5KcbX9QkG4TWro7w3InIU9ggUXB7ZyCcJYs7UaWJeYKXru4sw+1K3H4Xn64vvb
         9Yoq/vVVFS14uoEpTvDvrLTTAT4nHZ+l4ZYDLimTiBfZFsQKvvQvqp9ugJ5m+Va2J03W
         HKjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YtTgHiK/hvloV+isoTSGh3KTy09xk5xFGhrqhpxPTbo=;
        b=mvM1Mv66CjrpHqoJGfbDviO5oi6mN+9ixyK3C1kLqZSsg1sGJFIOZ2YNvSULBiBMBz
         SRBKJc9PU5Ow2r2ZvDhRtVeBWuZIZY2gbtZJ+RJyAITwvHOo44Yg94t1E70nfrLQLv4R
         y2CaA9mZaCJZ4veys/HcliiI5CDZZkUZ7OuUQaxLy+5mTBz5CZd4znrZTrBI4P1gzQ8k
         YFQAvrla8wTdqq0NnD4bJRDovV4uhK643Q/3zPvApkph9qlwnE2qnRBbwsqRf4uLzVuP
         YuIfFOpjB7zIjm4nlF1348u7TcKagrV7GdP/n3b0Sm6yBpvvCoxqoR4aUE9IRfkuSk4n
         LP/Q==
X-Gm-Message-State: AOAM531bR16L47H/v0+Ysasb14jg1EGF02xH1xrZsLw3F1+Wk/xZBymM
	AsDbPGqZFUc4MwkA27E5G2s=
X-Google-Smtp-Source: ABdhPJzNzj2/DAh1gwIHHYgmHhuXhKHwbUtYCIWiacmvfQTI6acWlIenhdktswDpU77ve32JkuIuSw==
X-Received: by 2002:a25:b951:: with SMTP id s17mr13832177ybm.205.1590054487200;
        Thu, 21 May 2020 02:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd43:: with SMTP id d64ls578311ybf.6.gmail; Thu, 21 May
 2020 02:48:06 -0700 (PDT)
X-Received: by 2002:a05:6902:508:: with SMTP id x8mr13775473ybs.206.1590054486803;
        Thu, 21 May 2020 02:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590054486; cv=none;
        d=google.com; s=arc-20160816;
        b=WHUAB/AfTTIYFVbiGQBbtCgs1AmS9qE2ZIlNfC9x0wSl4MqZzydcP26mJTXuwuiZ1n
         eA+HDwxfAucP2/SC5/S8krw2GyUihC06y1Tk1rvBZTVX9td2kdgBNXDaZ3SjwyWPnoXB
         PJ8Q4LjXaIfh3dskhu1FgkxjOGi7CG1OuXkJyEcuWhr6gkJ3sqfe/jc2Q5mar8SFubJp
         Q0r8GS192Q0uK0ClmpJYM3ZMf9F6GNYEIpqWoPxE9Ul6YXet5H1IsdphxV69Nh10M1pK
         66ZCpBF8pxI6+uhsUvjIYJl1HDY7ekG8xMUnATB64PQBZtYE2e2hA6XaKVxJ6lGv+UPP
         GUKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZQALpX3tKawurBrPQADjT0//A1CRuxacWFTx+oaYIXo=;
        b=U2lbMCVsUBP0JBOFPdHG4mQESKbYNBKHxBru5PKhllYBSalWOfl0yAnFGTnnNbVfHP
         COd8vnAyQSoufs2BP5AQKjJncVdgzkO1LxEGYYS5VbQbZq4BizRXLGT0309CdvOZf+fD
         UjhrBEjYBMOpOztOxeO2Al4Ws9YQ3ex5Xk22FY4uMsnBqtxVPkUBDY+JwR9ophaRm+ob
         bs2f8f3d8TVh8D+vSUEooOdYcLG2RVNxWHqXw1e69DQGwHhJ9PXXOBbnGKcDKcV/BKBw
         LAJUmE7y31pqgcXNaeDzjLXYe9CcUgvbFDIECS9RxOtF61jlC1NioP73sxUXphzaNMyW
         nXIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNY9dMzQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id u126si62205ybg.0.2020.05.21.02.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 02:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id l6so5690548oic.9
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 02:48:06 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr6229196oih.70.1590054486120;
 Thu, 21 May 2020 02:48:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200515150338.190344-1-elver@google.com> <20200515150338.190344-9-elver@google.com>
In-Reply-To: <20200515150338.190344-9-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 11:47:54 +0200
Message-ID: <CANpmjNNdBrO=dJ1gL+y0w2zBFdB7G1E9g4uk7oDDEt_X9FaRVA@mail.gmail.com>
Subject: Re: [PATCH -tip 08/10] READ_ONCE, WRITE_ONCE: Remove data_race() wrapping
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qNY9dMzQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Fri, 15 May 2020 at 17:04, Marco Elver <elver@google.com> wrote:
>
> The volatile access no longer needs to be wrapped in data_race(),
> because we require compilers that emit instrumentation distinguishing
> volatile accesses.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/compiler.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> index 17c98b215572..fce56402c082 100644
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -229,7 +229,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
>  #define __READ_ONCE_SCALAR(x)                                          \
>  ({                                                                     \
>         typeof(x) *__xp = &(x);                                         \
> -       __unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));  \
> +       __unqual_scalar_typeof(x) __x = __READ_ONCE(*__xp);             \
>         kcsan_check_atomic_read(__xp, sizeof(*__xp));                   \

Some self-review: We don't need kcsan_check_atomic anymore, and this
should be removed.

I'll send v2 to address this (together with fix to data_race()
removing nested statement expressions).

>         smp_read_barrier_depends();                                     \
>         (typeof(x))__x;                                                 \
> @@ -250,7 +250,7 @@ do {                                                                        \
>  do {                                                                   \
>         typeof(x) *__xp = &(x);                                         \
>         kcsan_check_atomic_write(__xp, sizeof(*__xp));                  \

Same.

> -       data_race(({ __WRITE_ONCE(*__xp, val); 0; }));                  \
> +       __WRITE_ONCE(*__xp, val);                                       \
>  } while (0)
>
>  #define WRITE_ONCE(x, val)                                             \
> --
> 2.26.2.761.g0e0b3e54be-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdBrO%3DdJ1gL%2By0w2zBFdB7G1E9g4uk7oDDEt_X9FaRVA%40mail.gmail.com.
