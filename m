Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR4GUGIQMGQE77P57RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DA994D28A7
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 07:03:53 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id p8-20020a17090a74c800b001bf257861efsf3150399pjl.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 22:03:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646805832; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GNvI7xLbACfihB0rlCRdGx3OGlTxo/b+QqI1jqgeZ9CAkqFgbQMg+xje/bhPTxZ2D
         6scERsyv4ynUdK9QxYzm5nL4qJ4liXlFKf/YBO47LQVVyX22ym+Nrr5VMOwltxTl6YZ9
         DKmiTVlZohuImYTsXkT2FLxmBTixdjd/tNtJB32mZl2dL3AcJfPQ1OBI/UFMf+qdmKzi
         E7jcHlh0lU5ZdpbzC4RpYD6qcw4nHoFboG6zR0AOUACLISuypJP0vLfulvkjx4BXtScZ
         8hbIT9M/F/WDx7TLOjEMoO5yqGlgVkXA5rLwd46/vyduCWKE2D4keL8vRypDHLAYETU7
         q/7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YXjuLxodzq5LlMUCDRoB+mwBjLqhouZ5BKWsX3zlE9I=;
        b=zM1hPSaw/j6A4JQZGHQEDjeBWfNseidWZo51uNiHb7dCRr8Ne9S2iThQ4gN5+ngg2W
         nMrNTOS4B5S6QsQ7aH6PI7voW2+VNSzzaRPk00KTvsn6U9Qe2d1IwMOciUDcx3noSjGJ
         Vzms5izxrl41WmTEhyTmi2Mp3Ep4HdEgjHiZL5H+Uu2gWxraS+J/QpJ87jPGsNDuTAdH
         ZpgnAZfZz0wd4TjHwEdQFIToWbfNP9PcPB4hiSfJ2gQ9U0FyXbx36iQiUxxescEaDLe2
         PlNpoZraX8q5CbbUnoOssFqiBvHaYqFm60c3e4DHdLCvUuzVXKmOE/fEwigSkv6v+iJZ
         PMhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YX63l3Tu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YXjuLxodzq5LlMUCDRoB+mwBjLqhouZ5BKWsX3zlE9I=;
        b=L0cQc5GRVWvY6IOe+U6vWfiUffwjbUyFAD+hCIgFM63vx81D3eQ36ditUvs4wAIz9C
         fsIrD1iOgT+NeqAhB3UbyRNiq89eu35wctRnHNjDtW9BkWWjJiQBz7lJ8LecBGg2dLXJ
         TtNXSKU3odKAb9hcwG6V2YKrTnOnLauTyDD9TzyrxDak62B3Nsi/UqRyhpq3YnSS2YKT
         7Dg3HSpe3lO0u6ugi10so3wMdU9OmtbUo9gE7nQPUGi4lMiw+Z07xkGd7egw3dVcGjOd
         zPe6//9jamLqvkcdpHwJ4Tz+LjyIaSJ0YitGi9mTWa09vp8TJgzEqgtFehtdob2syREw
         ge5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YXjuLxodzq5LlMUCDRoB+mwBjLqhouZ5BKWsX3zlE9I=;
        b=tOXaJWqrVmOY2ukI/5ZpRCXVOmTOwDJkixpD27qwxsl4hjTwyvK1NbMPtRFZVyJaT3
         7NZ/i/SDBCRELq4/zGlgDEFq8PC425uLetCTqrxzjKfpUAFh+DWWy32mbiysf7Y3WGjy
         jmHWjt5ubhj9STrav4EYgdfj9sTHRKfRX5oxo0xgi+eLoIE27hkpniqK+vq0mobJ2JmF
         AVF2S+rDbeCmkCAoqQ2WfFIlGeQXJQBs6GNCtKn25o4mkEIvAerhQ7TQdLL5WosgpVaZ
         /YhW0Tuv+iLTYBijrA/jm4cdLL/z41IXeyEhNj4vrYYNG8YN2d2aHNU13mQLUI3JPcmV
         mY8A==
X-Gm-Message-State: AOAM533Z/KUeGktNrIctfEjr6OFU5r+R4oy3GF+a4FbuLtXeAOLH4xv7
	U77FGShUyExH63cuQdpMw68=
X-Google-Smtp-Source: ABdhPJyVnhlfpM+QBmbzJ9UprbHuXkFcstalflDYsU7S+iQ/aSQkFg4ff3RuRpQKkG/ZyP2ZJhZ1Jg==
X-Received: by 2002:a63:cc:0:b0:380:afc4:bb07 with SMTP id 195-20020a6300cc000000b00380afc4bb07mr2414787pga.341.1646805831891;
        Tue, 08 Mar 2022 22:03:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b70c:0:b0:380:928b:8818 with SMTP id t12-20020a63b70c000000b00380928b8818ls477255pgf.11.gmail;
 Tue, 08 Mar 2022 22:03:51 -0800 (PST)
X-Received: by 2002:a63:6c01:0:b0:37c:73a0:a175 with SMTP id h1-20020a636c01000000b0037c73a0a175mr16820362pgc.415.1646805831126;
        Tue, 08 Mar 2022 22:03:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646805831; cv=none;
        d=google.com; s=arc-20160816;
        b=wPdNvT5tD6dojHw5AkGXUwVGSSzZOqGNhwMhv2IySxAdZXmXPmsDwuElIyJMd4a5Zx
         s1VTMcUQoZ518bAZ01xjxao3bA84y7s9OcxHRW5kTcWQ9B5fFiW1/T4+7viVhVmcfa07
         ZAWcQ/PE9xhUL8xQY0apvBHcPhIH88g4+2QpCUnvwpYPa70L+BkVlaBC8uvvc59BeYlY
         FmfjsB6+I8YuNa3kJMXR+ieiSQ1TXu9f2EZhEuZVTz+OeBCGoXH05gr0BgEl6m+tw7Qx
         F+aYNdty+jruSQePHbKpAFZHch/b3LulAt9V7+ADjpg5o2UVmdvZPP+pVt6+xdk2vvNF
         ANgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IupeTBPV0CwLiSouyNsLlNej2M8VfozXJBeb1wXs4oQ=;
        b=L2j54qnhRNBwjpmOEFgURcrfJ7I4ZIAATyKnVJY117NQGqBYTKb5AmeDphMzd2f/ML
         XWnvlZ2a72jJvIkMOz59pfi5ZY6AILulFzXYAigGbEGpIuJsYIpLwOdE51YhyCaottsl
         qUtJGp2Oxhgy3EUkRovQD1lYPw5/hV/iPDC564T2am5rSjU+8FUDpd1czf1glKHKzTEi
         u0byneQCCt59Rrx8ZvaC7FpU8u9JzZWdZrrMGgyDfLOTZ0J4wGFCDzC3iid52tFg4uXS
         mgrgq9ZZ1N0kuDBk/gxAiPLr4fsZCX6wDNTElNJfLSHDrXehip8YcwGogMURXTii0GUq
         +Ing==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YX63l3Tu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id n15-20020a62e50f000000b004f6d2226c79si31823pff.0.2022.03.08.22.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 22:03:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id z30so2251877ybi.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 22:03:51 -0800 (PST)
X-Received: by 2002:a05:6902:184:b0:628:233e:31fe with SMTP id
 t4-20020a056902018400b00628233e31femr14583650ybh.609.1646805830152; Tue, 08
 Mar 2022 22:03:50 -0800 (PST)
MIME-Version: 1.0
References: <20220309014705.1265861-1-liupeng256@huawei.com> <20220309014705.1265861-3-liupeng256@huawei.com>
In-Reply-To: <20220309014705.1265861-3-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 07:03:13 +0100
Message-ID: <CANpmjNOU+M1ZaRTMPMCFE7pm8JXLKsWcMpMAsDmJXZUga3N7=A@mail.gmail.com>
Subject: Re: [PATCH 2/3] kunit: make kunit_test_timeout compatible with comment
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YX63l3Tu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as
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

On Wed, 9 Mar 2022 at 02:29, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
> represent 5min. However, it is wrong when dealing with arm64 whose
> default HZ = 250, or some other situations. Use msecs_to_jiffies to
> fix this, and kunit_test_timeout will work as desired.
>
> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Does this need a:

Fixes: 5f3e06208920 ("kunit: test: add support for test abort")

?

> ---
>  lib/kunit/try-catch.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
> index 6b3d4db94077..f7825991d576 100644
> --- a/lib/kunit/try-catch.c
> +++ b/lib/kunit/try-catch.c
> @@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
>          * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
>          * the task will be killed and an oops generated.
>          */
> -       return 300 * MSEC_PER_SEC; /* 5 min */
> +       return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */

Why not just "300 * HZ" ?

>  }
>
>  void kunit_try_catch_run(struct kunit_try_catch *try_catch, void *context)
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-3-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOU%2BM1ZaRTMPMCFE7pm8JXLKsWcMpMAsDmJXZUga3N7%3DA%40mail.gmail.com.
