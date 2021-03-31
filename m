Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBWYSGBQMGQEQCV5OFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 33FA2350066
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 14:33:12 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id ev19sf1086067qvb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 05:33:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617193991; cv=pass;
        d=google.com; s=arc-20160816;
        b=PLkakY6kL2cojARPItQd3gi/438gHLw3Cg69+GArKKl8OFnMvitrmEqb3bmA6Ls0Sz
         diV6yk5d1OIYNfY1LbYbAfmSkJMKAb7IC148CuZtsLzacpMWOFH9V9uA3VjG4O8Ykq/J
         mkEzEbPwx9q7B3002aSD79QP6T4Uu5uvWy/v400QO4x7iujabk9Kbcq8UkCAFwFjPa99
         O5XWj5q3c44d2qjuwktDoc76M+msSktfb68pU+wgMsPJqMU2mtI+sgkVokCcoYkDoB/y
         DM/V1iBDFVxOaP/I2PoTUbpPEdPTUrk5dkbXdmg68QRJeF/AO/fWfL56a+HPCV96PqO9
         ACUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fYc7i98jcuMQfL9ANou617nngxOogdwm9HDkuWoQ5Co=;
        b=JUI1n4PZd6sv4wN4BjRJhSOY71OdaH0fg6qckh7WDh5g+h7aSLVbYJcNF9J7tQbCT6
         LvZx2e97l4R5ry7Fz4f3dgDFH2nD5rMyKxc6TusrYKOL3uX2cg9XyctBoNQ4V/VZksdZ
         y2nrAms4FJdwCaLFRrEOWbPUwB9E/tYSfu+08Af0nhqSmKbCUNOYmVTj54IhiEQ7T5Ng
         QoWzetbna84X7PrzPx/O3F0zn9ic+lHNXAySyfoqlIxUaD7FuSgQo6VjjzAdLpuBmWCM
         Mp6UDHxjyTR1Ec/90ihC0ptFqWwzW1IowjrCdIfwv/CtXfVrZG+ewv1ZcYPQRTcr0XKB
         0m+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dMoq/sx5";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYc7i98jcuMQfL9ANou617nngxOogdwm9HDkuWoQ5Co=;
        b=TRc6W4HMuIbjMMiV1CLfWYPEuazBDVoVc2w025/xpMh+DOaq1Y/2SKk0ZLYrvpwf0u
         UoE89YXkmxaFbxw4Q90NuNky5jNv/rwrw21ov/4Foj/WfIhbgqpW0I8slQPFBpQttZpz
         Yy9mey7+K6EtJrvkTsAph9S9bHyZeuUSrlbZMi7sBTAUzF2T8fng1nTMJviRd3gjwWbW
         OdflbsiQ4rmO/72whpxwQcHBuAGStrE2D7Jdn4rClfJV4wCPCh4oxu6Ka3D3MaWKkFbX
         EYjjbX6euHqbqDneEnIL78KSzoaeh0U6pTrGWf5JnZ/0Cb4ZVcVQ9ji5mKSL/blvq8cM
         leoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYc7i98jcuMQfL9ANou617nngxOogdwm9HDkuWoQ5Co=;
        b=XGaLxg91n+Cve/NGaMPDbsJ8pMwEFu9fYhUkN/sbgwRErc/bGF0AbkJyUo0TmcL+ZY
         kBOGBErLcYIsGeQ+WrXYpkA2vnAeladeCOshRfS5incj+UxHMn82zNY5Zr1DD0sHiipJ
         tQQN183E2tV1j2xFnHgzn8IxjZWBkYLWi5Krr0WwAzproZRNXbANgAynA0417ONzUcr7
         BMG6VF17yHGUtrXMxouBd8njH1BVReVvAGRr/aEW98q8aPfiCUtPlhBfYzH+DGhUDZ7G
         4y3cSavcWDQU3R9oNN63fZaZD2km+2Z8sqL/WiUh3rIaY5DsoSc0zr32dOP0vamc+O91
         RKuw==
X-Gm-Message-State: AOAM531ksuJagL81vrAXEQb3Wl0sqGDe831GBmuUNHm7biBeXQG+0o7u
	8W9zRn9c26X8wIQdcRAJoZI=
X-Google-Smtp-Source: ABdhPJyYwoke9f4UV6XzJLN2ErHx+iV1K4KrpDJ5WQfUlIjbOqr4J1KPY58fv6I37X3b1Yu/tnc2NA==
X-Received: by 2002:ad4:4b2c:: with SMTP id s12mr2490115qvw.19.1617193991009;
        Wed, 31 Mar 2021 05:33:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4f10:: with SMTP id b16ls858219qte.7.gmail; Wed, 31 Mar
 2021 05:33:10 -0700 (PDT)
X-Received: by 2002:ac8:4288:: with SMTP id o8mr2123062qtl.28.1617193990497;
        Wed, 31 Mar 2021 05:33:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617193990; cv=none;
        d=google.com; s=arc-20160816;
        b=fkkfew+N6nVe1czXBWD+7bHGMEZOKlmdz2EfFZ5gAe4TRawKXIaWR7z6s4XORyQ6PO
         FB9ynmbxWiFQv7dynruDHSu34doRY46r8+HRz7I0gxl51S9RsyPqjdmVSmHQNuTYb9kd
         H5WayCTD4Z925JkljhMsYZa/UKccRjFvqKgl9X0/RCsUHJGTFHLQCiz+j4JW2WlQ0u5N
         cm0Ey2kTxwrdrindUnfcruD8rKPJMr/h61rjvvSuMcf+5PvTfm5hHDoUBbFdiXWfFo9H
         QkviBeH2M+3LenXGq799hNL0vje4p1luQqHktgFkVlOksruXnHT+Jy9ySzFhRxT3S1qw
         785w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G2AUmQQuU10DnwHLe3j88zasAy4fwJf13uqVDHeKF6c=;
        b=heYZYV4XilLNnI1Bi83EDYJ4SwnXyp3pDk+0o5FumMgMqnBVYIlrf0rr9S+kMQgOst
         59vNB4QReDtJ8zP3cZmGW5Ak6Ko8v9yQub24EQw1vn2I951h6cYFHvMQrewBUb0d7ZNR
         E0zKz2+oQdyCk+0ad9oU5fykw/gxEJJtYBAe38arMfvy6lNT0jXfhwHOq4WyAkvbtr7b
         GaJPZoe0ebDnzAr/Jnzc2ATQwp42pYRfSPV+OokhEfRehQqsrnDL9QnFCIVAYNR9IM7P
         o6B9878bePbtkSDY8gcz/SlTeabo6Ra6/VWjnM18UYQJUJP9cfLIXLnUiMjbGBG3TBjq
         BWPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dMoq/sx5";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id a15si270477qtn.4.2021.03.31.05.33.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Mar 2021 05:33:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id y19-20020a0568301d93b02901b9f88a238eso18741341oti.11
        for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 05:33:10 -0700 (PDT)
X-Received: by 2002:a9d:5508:: with SMTP id l8mr2553279oth.233.1617193990006;
 Wed, 31 Mar 2021 05:33:10 -0700 (PDT)
MIME-Version: 1.0
References: <20210324112503.623833-1-elver@google.com> <20210324112503.623833-7-elver@google.com>
 <YFxGb+QHEumZB6G8@elver.google.com> <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
In-Reply-To: <YGHC7V3bbCxhRWTK@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Mar 2021 14:32:58 +0200
Message-ID: <CANpmjNOPJNhJ2L7cxrvf__tCZpy=+T1nBotKmzr2xMJypd-oJQ@mail.gmail.com>
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	Jiri Olsa <jolsa@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dMoq/sx5";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Mon, 29 Mar 2021 at 14:07, Peter Zijlstra <peterz@infradead.org> wrote:

> (and we might already have a problem on some architectures where there
> can be significant time between these due to not having
> arch_irq_work_raise(), so ideally we ought to double check current in
> your case)

I missed this bit -- just to verify: here we want to check that
event->ctx->task == current, in case the the irq_work runs when the
current task has already been replaced. Correct?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOPJNhJ2L7cxrvf__tCZpy%3D%2BT1nBotKmzr2xMJypd-oJQ%40mail.gmail.com.
