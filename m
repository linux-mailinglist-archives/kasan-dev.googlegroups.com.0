Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5MBZKOQMGQE77SMYZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FFC865AD8F
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Jan 2023 08:00:07 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id s7-20020a05620a0bc700b006e08208eb31sf7018256qki.3
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Jan 2023 23:00:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672642806; cv=pass;
        d=google.com; s=arc-20160816;
        b=mg11AEw4J83v8AMPya3nElLoJeUluC6XXVuQHa9tezBm7rKK+KwAZhFKBp+zvaOJKe
         voji+Xnx+mEiNzD2uZxWMXKbvK1EOr8SiYd0tad9jhA9mICFqYpWOjyQlbK5dK/o2Nks
         YNka9K4lQa7KrauhtpENtyzEX4I30ftnXVIDpUiZ/GdmICvuLBK7cq5xfwR21nSijZGf
         q9K5Ub/wKqzWQKGQ8giXr6EeFzsBdjORFudbYwOMotm3SV1bXGtG5/LMDfbkd+KtmeTV
         V/SkFIdTyWQ+qpdaM6YAhLcYs2iOi9nTSqSiDmlAIML4w0oJ/wHqchZkqhwe/+0RbcJQ
         b07A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q2CDGpxqAV/cHo2CK3QO6dktiiniVW1o9yzI2ITWExI=;
        b=Mb2HDaCNoNJvqv2GHchQBtczwMDJyAPAM4SjWYBSM3w4Ewt4BxAD09iO1mXoS//YuB
         4796xd8trAPFhj4a5orL0ylbbRh3Gmn0Pvwxt621vvChtKyUTWXmdZSGVjB67tz+aJTI
         oqv8DyeZa8zn5EEKQO1h99pffQLy6rbYdQJhXX/2+pPAx4uAVosNh78wtTnx4vhberRF
         RLJxB8vGVf3IdRGtVDSjaRVS5M+8p12sMWVr/WBV7lQPxx4CNm2eiUi7AsrXzVqEaZR0
         YqGLdYXqgacM+tbhW3iKttOfySFvn9mjDms3E7pcBOKsB5cuDBJBuzFPYpl4mSA6ICBy
         cbAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gjtpkUXM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q2CDGpxqAV/cHo2CK3QO6dktiiniVW1o9yzI2ITWExI=;
        b=YRJkpaEYzXG2uoF1/AU8v0KYEmhipP4sSZKTrl0KD08F4waSpsfOr1VuM2OjPLiVId
         Jlxg2O+g8lC42mA2EaVcRJ9FI4RImnmARYUF8uzM4kR4H489kMwadQb97zgCH4jxa+0k
         Z+meZZQqsk9kIJYc2FlT7SZ4bxOM6bz8u5VcNfav7itnWofv2XW2kwhUXmIRv4wyGU8F
         oKP+MCo4bFvqvd73tfSztpoAKpAhqROq9JyBOJwhnkR717AXKv0vHvL8vxRuWq7n5r4a
         agwnjDcYkodc/pR8iLbTMAUTg7uiPqaBKSCTlAJe0UD+VrMzzFJw+4PgpgjQQ+MoDAgS
         KcwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=q2CDGpxqAV/cHo2CK3QO6dktiiniVW1o9yzI2ITWExI=;
        b=Db7NgiiYKL1yqwX2W/4B/Pup7TOdOSdG8LffF78xvp/HUvSFfrDCg9G+oJJZzPbGCw
         2lwb15pC3nAgcmXC94m8P5/N8EsK7X7zggYL11d1wiLMYdmPEFEfu+6NmMFfRtK2R7iB
         sSQWWnSIa3g148cj2gf6JL1rmRPVAE9T1zmIVH63ZOYsrrpbA0Hyl+ZC3coin9b6ya88
         DYO5wX/8HxsY3bofnEQSwNo5ANnjd5kvixt1i6uyP1vUucpCmFZ5Ldcx7TZushpBp0AW
         1001DbVMsVOOS1OH7KT7PgsfG7f/aDlZmdWHRO7d1B2aLAWdyjBBn9M6uYO0Cj33jtgs
         Dxgg==
X-Gm-Message-State: AFqh2kpniG59TAdQKS1b/rLHfDP4tGvbbX4anxWDitH1PRnwiDjz7sN7
	D+xkeLdho5cbOMhDmapzGM0=
X-Google-Smtp-Source: AMrXdXuyTw5/EDCee0e6jv+DhdjJdnfd2pOfjhR7nx1clkgt3fNkfaUqP+itWzrWxB/djaVCpQWN6A==
X-Received: by 2002:a0c:f9c6:0:b0:531:47f7:7bee with SMTP id j6-20020a0cf9c6000000b0053147f77beemr1822921qvo.83.1672642805986;
        Sun, 01 Jan 2023 23:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4089:b0:3a5:45a4:2fd4 with SMTP id
 cg9-20020a05622a408900b003a545a42fd4ls19669562qtb.10.-pod-prod-gmail; Sun, 01
 Jan 2023 23:00:04 -0800 (PST)
X-Received: by 2002:ac8:7082:0:b0:3a8:1593:f15b with SMTP id y2-20020ac87082000000b003a81593f15bmr67217620qto.50.1672642804732;
        Sun, 01 Jan 2023 23:00:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672642804; cv=none;
        d=google.com; s=arc-20160816;
        b=tLD51ICAkSasoVU9sBei52NOB41bxSWjkfP30XBemAtnV3m/CRn5Is0KsBoF3I2mT+
         ezxbWQy3jQLQ+b2K20kSm2U52TOAR1zN7clyq2kfdUQfHsQ2oSpOM2Zrr2an5FGI4meh
         6KYV+OMwfnGYE9JlkDBs9Rqg30+4jhEr7yyBgWDC0GH32kPhZxo3E1D+v9PsF/QsOqmI
         tTIUvkB25wY/oed+qSwe9BTOg8YZNdLQ9WrsAk31YAWIDaeK1VIvjRg0q6KFb+rqHdt4
         3sh6Ptu1OfF2DD6lbVRGSn4wjEM87fEHV1i3MM4OaUDYnHrUeZTsaq5tctChzGS5NxYQ
         G6Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0FTLkrtp1Ew2BFHSG03YNcRgOUsktg1BSIJrviOVnRQ=;
        b=twsrB1Bp18OAd5nBojaVzH71Qo56796R8XTv4FVuI3piZmOxCJecXIYeP7q/7FjsOB
         InqCN/2Mhmj6pHFwn6DAKL+fjgjLlwZ6vfpp1MKxrBdIjfJoyvzZa0oFPhWWfoalmwie
         7QFjJl7PVcIJUZLcdfrzVCGoxmNIJ7E1U54R18rugZ9XkmbAzfwnoYLLEM/VCthl/Vtv
         PxyZgOwjfrtUqL5gm8EfFWQtemdkxFrpQY7ryNeAelgjtehmWzbMkTZ7wlxGWC/gCp+X
         vU8vGIZQ9Zrmu3OeR7FCgkdTmoqOYUtuKUvi+4jgIIudYQ6AX+13UTrBFQUNuHGi3rqX
         a6mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gjtpkUXM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id u22-20020a05620a085600b006fa81f6aaf7si1745258qku.7.2023.01.01.23.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Jan 2023 23:00:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-482363a1232so233146477b3.3
        for <kasan-dev@googlegroups.com>; Sun, 01 Jan 2023 23:00:04 -0800 (PST)
X-Received: by 2002:a05:690c:fd3:b0:4a8:330b:2554 with SMTP id
 dg19-20020a05690c0fd300b004a8330b2554mr212247ywb.238.1672642804252; Sun, 01
 Jan 2023 23:00:04 -0800 (PST)
MIME-Version: 1.0
References: <20221231004514.317809-1-jcmvbkbc@gmail.com>
In-Reply-To: <20221231004514.317809-1-jcmvbkbc@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Jan 2023 08:00:00 +0100
Message-ID: <CANpmjNNPTT+K3CRZN+RnUbHwmtUUzqb0ZDP=M6e8PHP0=qp=Ag@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: test: don't put the expect array on the stack
To: Max Filippov <jcmvbkbc@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-xtensa@linux-xtensa.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gjtpkUXM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Sat, 31 Dec 2022 at 01:45, Max Filippov <jcmvbkbc@gmail.com> wrote:
>
> Size of the 'expect' array in the __report_matches is 1536 bytes, which
> is exactly the default frame size warning limit of the xtensa
> architecture.
> As a result allmodconfig xtensa kernel builds with the gcc that does not
> support the compiler plugins (which otherwise would push the said
> warning limit to 2K) fail with the following message:
>
>   kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
>     is larger than 1536 bytes
>
> Fix it by dynamically alocating the 'expect' array.
>
> Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>

Can you take this through the xtensa tree?

> ---
> Changes v1->v2:
> - add WARN_ON in case of kmalloc failure
>
>  kernel/kcsan/kcsan_test.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index dcec1b743c69..a60c561724be 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -159,7 +159,7 @@ static bool __report_matches(const struct expect_report *r)
>         const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
>         bool ret = false;
>         unsigned long flags;
> -       typeof(observed.lines) expect;
> +       typeof(*observed.lines) *expect;
>         const char *end;
>         char *cur;
>         int i;
> @@ -168,6 +168,10 @@ static bool __report_matches(const struct expect_report *r)
>         if (!report_available())
>                 return false;
>
> +       expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
> +       if (WARN_ON(!expect))
> +               return false;
> +
>         /* Generate expected report contents. */
>
>         /* Title */
> @@ -253,6 +257,7 @@ static bool __report_matches(const struct expect_report *r)
>                 strstr(observed.lines[2], expect[1])));
>  out:
>         spin_unlock_irqrestore(&observed.lock, flags);
> +       kfree(expect);
>         return ret;
>  }
>
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221231004514.317809-1-jcmvbkbc%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNPTT%2BK3CRZN%2BRnUbHwmtUUzqb0ZDP%3DM6e8PHP0%3Dqp%3DAg%40mail.gmail.com.
