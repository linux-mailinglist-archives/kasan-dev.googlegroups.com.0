Return-Path: <kasan-dev+bncBCMIZB7QWENRBDODQ6KQMGQEPIQSM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CAC8E544B2F
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:03:26 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id c25-20020ac25f79000000b00478f05f8f49sf11506609lfc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:03:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654776206; cv=pass;
        d=google.com; s=arc-20160816;
        b=o+tuaBk7LrPTPtU9uPfoQw0du5ZngENy763xbxVdACW7BVQ0f0K4zqWQCfwKIusx4Q
         Z/6AFVY8+WVNJ3jI1cXrEV64KIW0vENcw783eXhtdXUS9HbprpFF2HZNd93oB5/QZVju
         wytW0ZOnCWQbR6plEGJraNiBHoaomKNfPI6f96Pg+1b6PVwmc2XvAOwkWsLsFiRsb6Ao
         uLIS0/blJ4kn0WFSe2O4xbzxTdyEhUGUQmxsBzCd9dcmdLCN+lDhP2GaSmwxGoNqCV0r
         9nMBOlx9yLWuAZcVjbJp3o7fqoQ5At9kL6vbwGqiDLBRpmqxmTC+MQ37FaDF8MNWlc8A
         Eg+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RivhutXvvTaN8GC2GCcE/uwBQQuddDlAn4gdOUj9yQ0=;
        b=TCaxq5L2oc4qnSMCJI8tajd2eiGg8yNJp8LxZ5BA9ffYr9XEzIj527ZonizOK/ZwON
         zwnW0QuvxugtnFTdT++7nTqiE5CNdmS8moSE/pODbbmxHWOYoOnL2yruj+XNyx/sO/Yu
         MfhwGef2Hn4iFOq4HS1dEXngPJR22n0g/e06Y9H23AToFZ1ktBDmrivP75EHhUG2Ywpn
         k2GeMZlC+fTcBPjCODu6VmbJm1B5q81D/Qd4FBfP/YaNkJKus1le7o91AJBVoFXjTl2K
         4/pydcgQxJRIbCiM1VdLhEnfYVBBAyMbAHApIUNftwpNiY6T/1z9CBve9mAk6IMgAhZ6
         Uygw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WUkfehuO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RivhutXvvTaN8GC2GCcE/uwBQQuddDlAn4gdOUj9yQ0=;
        b=Sy1IZO8/ItXfww+rUfmVLTdjXmFaN1UrtgEYD9HTCNg2QgJRKF6VG+FpC6v+y8S5+F
         4gSDBhB0dBsGVA82LHGobKAATlxXrhdM5XJHJgjDP+038KGaBpZMG/rAdBjFwccK3w1o
         iOYv08T+2C3/8wUSwO/KrHJPCx27gRU1v/SupDQQzazngzAuXktjv2ZmG6d83v3wFy75
         l68hh0+kHYj0tvWhdI618ithWdA1r01mZ4UCkQXUsx1MGQT/iJUFWBR0YzzuBjTj7qdg
         iI+uhcy1ssib7w3DbQOE6W+ZLNJu6kbYkjVgCJHFRoD51/PcYOzH0aa+1mQv/Q1795/F
         v9Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RivhutXvvTaN8GC2GCcE/uwBQQuddDlAn4gdOUj9yQ0=;
        b=uqV9oYL0z5HlweNNO06DIBfrvYy5qQmPKN+O5JPQgGPpkbW0FmiDeMpHjk6mt7Nn7J
         YaVvVbc94lR3NSaeyhRKV7AEFEnbVvNVznHHs4BAzmpU+KTmp+jQQmAosPc5AqqsUqLP
         HYdXrBQhOLeTdHlffQG2QoCXwh6oEd5S3QEWe+5HtmzH36rlbsGfX0VO6e2cSY48aUXs
         W3sUxm7CiY80ylQtg420E2j2ZTBQW68Y7O3FfbE2O6V8z9D1wfmw1SIu3VrJb1k5reUL
         l2sBZP3ttwMP3ZR7bOXtTMtik0SQkBIE05ftH+sUbsy4dmbp0utZw5hDFl0uxaetBoGY
         DPRQ==
X-Gm-Message-State: AOAM530W7x/OYpxUXfNAmWE1P+xAnjfP9Y7tZhlb7tgoXCia9Kizwu4r
	rxnWTYSc1Q/bSAgCCk5g80A=
X-Google-Smtp-Source: ABdhPJygpowjGs0cHMonde5DMn/VJ+viuja0roj+/ZzdUgSHMmSIC51ZhxQs0sP9ABKmoZI8TNAZ0A==
X-Received: by 2002:a05:6512:c1d:b0:478:f321:a57b with SMTP id z29-20020a0565120c1d00b00478f321a57bmr24897681lfu.125.1654776205541;
        Thu, 09 Jun 2022 05:03:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:80d8:0:b0:255:ad4f:fe4b with SMTP id r24-20020a2e80d8000000b00255ad4ffe4bls813230ljg.4.gmail;
 Thu, 09 Jun 2022 05:03:24 -0700 (PDT)
X-Received: by 2002:a2e:a5ca:0:b0:254:5b8a:8dff with SMTP id n10-20020a2ea5ca000000b002545b8a8dffmr38685256ljp.121.1654776204302;
        Thu, 09 Jun 2022 05:03:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654776204; cv=none;
        d=google.com; s=arc-20160816;
        b=JZT9MzNUyLbtI6agfULZJ+aa86+U9gIRH9kJtX7RD2jRDunP44p3IujHmvsjPm5wHI
         nj+mBWkjHx1GpdTKaR66uZAF3mq6Hoh8sD/9nwMtBUDPD9l/XK78izr0CyVkDed88XhN
         jr9SaQeI16LGVBD9S4gyws+HuToTocJuegVm1eory5PDJzCITKp9+M+ekBenMwAt7X2n
         SJ6v/u1SVZSqs2cjiTKuU5ufETXvVa00zfNgU1B0wnY7EaPp+sCbmziqrTniu6h7trv0
         0cUVgtn8Qg1m7vJ8dhnbNYEDvqvPNMypGZO4O3FDDwkZBUy9DDBPJd+slIki/+A+4yeb
         /OCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F1uvmSUGsFaK9iCgbfPZK7tHgGjdwwOqEzHuFfRRs9g=;
        b=ZA/4tG8OlIa+jSbNvxUYllWopZsdlDmI4G0hu5MNXzl0z9WoE4WRoVPZl4nXb918kI
         qBBFJpknOlM3Gv4/KsBQYw3myttMoZ6VwzIIA0Hh05whBvu1PkMaUr6grduAD0Nvb9wk
         6KXuAn1crF3fUUdVrzJritUlcMbKHdnMIFs7OLAJPyAoO7lQXhIf9kzQmeu5jvUZCxrX
         iaPJSuVsSPDjlV48v7tfCI1iBW3Tr/3T+94Jq8MMvgYTtC4g2i78Ge1vDnWGoOvTsNqB
         atTHrRnVPRnwfB7MSpIbjGcamcLeK6a/KAFDK1Uv9DdSUevQaiHSSPoul9nQ6MboNgg4
         1HOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WUkfehuO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id v9-20020a2ea609000000b0025594e68748si552235ljp.4.2022.06.09.05.03.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:03:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id g25so25863514ljm.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:03:24 -0700 (PDT)
X-Received: by 2002:a2e:b0fc:0:b0:255:6f92:f9d4 with SMTP id
 h28-20020a2eb0fc000000b002556f92f9d4mr21901545ljl.92.1654776203624; Thu, 09
 Jun 2022 05:03:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-5-elver@google.com>
In-Reply-To: <20220609113046.780504-5-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:03:12 +0200
Message-ID: <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com>
Subject: Re: [PATCH 4/8] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WUkfehuO;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::236
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
>
> Due to being a __weak function, hw_breakpoint_weight() will cause the
> compiler to always emit a call to it. This generates unnecessarily bad
> code (register spills etc.) for no good reason; in fact it appears in
> profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:
>
>     ...
>     0.70%  [kernel]       [k] hw_breakpoint_weight
>     ...
>
> While a small percentage, no architecture defines its own
> hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
> which makes the fact it is currently __weak a poor choice.
>
> Change hw_breakpoint_weight()'s definition to follow a similar protocol
> to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
> hw_breakpoint_weight(), we'll use it instead.
>
> The result is that it is inlined and no longer shows up in profiles.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/hw_breakpoint.h | 1 -
>  kernel/events/hw_breakpoint.c | 4 +++-
>  2 files changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> index 78dd7035d1e5..9fa3547acd87 100644
> --- a/include/linux/hw_breakpoint.h
> +++ b/include/linux/hw_breakpoint.h
> @@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
>  extern int dbg_release_bp_slot(struct perf_event *bp);
>  extern int reserve_bp_slot(struct perf_event *bp);
>  extern void release_bp_slot(struct perf_event *bp);
> -int hw_breakpoint_weight(struct perf_event *bp);
>  int arch_reserve_bp_slot(struct perf_event *bp);
>  void arch_release_bp_slot(struct perf_event *bp);
>  void arch_unregister_hw_breakpoint(struct perf_event *bp);
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 8e939723f27d..5f40c8dfa042 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -125,10 +125,12 @@ static __init int init_breakpoint_slots(void)
>  }
>  #endif
>
> -__weak int hw_breakpoint_weight(struct perf_event *bp)

Humm... this was added in 2010 and never actually used to return
anything other than 1 since then (?). Looks like over-design. Maybe we
drop "#ifndef" and add a comment instead?

> +#ifndef hw_breakpoint_weight
> +static inline int hw_breakpoint_weight(struct perf_event *bp)
>  {
>         return 1;
>  }
> +#endif
>
>  static inline enum bp_type_idx find_slot_idx(u64 bp_type)
>  {
> --
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYHp1mxxGNuGke42qcph0ibZb%2B6Ri_7fNJ%2Bjg11NL-z8g%40mail.gmail.com.
