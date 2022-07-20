Return-Path: <kasan-dev+bncBDPPFIEASMFBBKOA4CLAMGQEYM4FQMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 632D057B9C7
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:32:58 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id h189-20020a1c21c6000000b003a2fdf9bd2asf8539891wmh.8
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:32:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331178; cv=pass;
        d=google.com; s=arc-20160816;
        b=SidNBG2PDN9Ozxwz8kjiMmX4Zi0wk/rfme656T3ZjvQO7wz1glZEZunuWraJBzoDi0
         Plr5TfWUxoR6QSZBTATzNWJ5oUcUhUOGi9Inb/b+lyp8E7UjDWnIbPQjQYHVnPq//J0v
         0k9rZcIVgJHDDkde29rtkv4FGoZQhAiZsXGJ0qAkMju2ATH4Ljs9+jWDELocXRMjGyJB
         xeMmcDLh6drWB+0HaHIS7EEDtaxPq6xdv6XzH9xVFcQPi+s2hqk8H8Xr0wY1mYuKPWm/
         mBorkHoaOJWJWZexAvuENDxUm9ebvPMkvUG86uKFHUr/KRhWMq/35/ZUEygYNydHk2yU
         kZbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G+uJW1/q/dR175js1/NsTFOPP5P652FbzU/nuCZa98g=;
        b=0hAT0s14Hf+zNXpUq2GMctUg9tInAe1Mmkhkx752LU8K5D29WuNPDb+CtolU7FBjRj
         cOpPHoGM+5XJCShwlZ6OccKQTY++MIaHDKTayF34NsquNgiDotZubAZq6yaIlXtoCH+s
         /QQH7A+Fb0ECo92irozrHHX3Dpc0KMMuymmjFW9RBWZ4XGlvy5e0qy3xx53MkRmve5R9
         zyq6wGTf7iMuIAIJ0DNoDoCG6CrOW0gz8mNKza6RcRAYHrBbBhkxm0gxJHhT4q21F4Ls
         IamfHgWn6lvo7niqYvnh5DytUII6eoyNGGbqWz9BjFYu0Qb61ZLcDqKPz/IUPhfgMv+4
         zoHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rtE6DDog;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+uJW1/q/dR175js1/NsTFOPP5P652FbzU/nuCZa98g=;
        b=Wmghao1AnLlIBoU2Zh310BXfKOi3iabjtLBdK1Okcl4+oqySnzbHoTpnwld5jZdF5P
         5vOxLNT5YvzDfs52fo3Fkg6dJwbcGHL24M59hhq9/TH2Jt1hE2w1FyYBLGNmwKFv5qda
         mQWzoVb4L3V1ZVdn9uvfyuzq7lBEXwouUvxce8o4Ti19E1v6FaD8I9Nm6vEJLG70fg3Q
         3jFkid/FvB+jCzaxQwBK61ZJWjchPvlP3CaYIIU9F3ROjXudHMdCrfarm825bDCkdMti
         70oQ5Zu3NzNp0UIhzFFydIodj57XSLjpeI3lwlB71Sz26sXLP8kd4gv/rhE8kW+yXUeU
         IqXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+uJW1/q/dR175js1/NsTFOPP5P652FbzU/nuCZa98g=;
        b=4IRHh8e65LxY7l6hHtmXVQ5DnqSgd/wQC8LJnci84W1rRXz707rbeIg+OjSy/sX30z
         riMrbHpjI513ZEQwKBqRSn79UgutMaAK3HOmx1XRTffug2fQ76qNqq+2KUgL9S1NS+F+
         GKCtOeZDSq/M7y9RRjEQxIal5sbm48EKXh85H4l7FGnMKFrtjXXbWFUfq32Zmrbk9qv0
         I3UlD3cHH2GvKTe+dFGjcXmMRltE/KTw3WtcY+lvJM4W2ruvbqynF+Xu5dJGgUA6IRo+
         WJcRI8dU7ocfv8YAO8mRVU+AK4tDLn2gDCJkvFKJZCc1evuAuS38nC8YCTN4LJf5Ck1Y
         275Q==
X-Gm-Message-State: AJIora/Rn2hkVSQc2USwSGOsIm/f525YwjfuFDAmt+aRCePrr56ZQahD
	3wd5SxrKC4qAKyVgzecFBZo=
X-Google-Smtp-Source: AGRyM1u5zK4IWX/BPY0BUcJ0CAhiAHzzBsskEWfElLDhl662WivnV1A8KndKcF4gopUwXTpUBju1lw==
X-Received: by 2002:adf:e98b:0:b0:21d:7337:da3a with SMTP id h11-20020adfe98b000000b0021d7337da3amr31227702wrm.13.1658331178011;
        Wed, 20 Jul 2022 08:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6547:0:b0:21d:668b:3503 with SMTP id z7-20020a5d6547000000b0021d668b3503ls128726wrv.2.-pod-prod-gmail;
 Wed, 20 Jul 2022 08:32:57 -0700 (PDT)
X-Received: by 2002:a05:6000:144f:b0:21d:a3cc:a6fa with SMTP id v15-20020a056000144f00b0021da3cca6famr31006267wrx.191.1658331177080;
        Wed, 20 Jul 2022 08:32:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331177; cv=none;
        d=google.com; s=arc-20160816;
        b=qaAxsm70VepBC5IoSUGkvuKq7nptCog+yzbynXA3X3lCTR9lyC1De+TfaoIQc0UUrA
         qp/niWprcMmYsKzAiVXb+LA+pjS5Cec0MVLrDtSzVFSE5b23rX+pO613bB2c+56NVAXi
         Om1uJhgKVSrFl0osTN6kxfGPz4kpAU1DMIx6llhJdgFJ97bFKNQS8GLMbCddVKN+XCRT
         O+XPY6p9VHK7EhVm5NgDZfnsh1v7bvD8xmnT1WjvW11jLBsWLcCQb+1/tb/FtOX5ptQ5
         D2WQaaRPU58tCyczksbJkA85/vjpZceS/2xg4V61pWfWnuOfM3bOdlD7sHW7kQ1bihoQ
         FjJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MXRVB9OIIhdX/URjZNl0v6pVC+o3sTM2QCDmzX1vQJc=;
        b=eC1KxNdzNzT46+k8x+GMKfIxg1abubG9P8C3QPIZmOXmzJcbbFpr+3kwtM7dvG6rMH
         0QBbzVewDQIvBGWBDAkSDOICkBgmoi9rx4eYgRm//oj/skaNy8dn8cD3W2TK/w/WOlIo
         JJ74ENb3IoR1/HvoAc5lZwi7Szt31v6Afh7X8G7z3370mrqfQblJNriU60ne75ENXvjd
         9Bn2/AIhQO8Y25BAMm8GTR5gMPTcvR8gHGxYkd/fUwjZKs/gKQbXjTQSRbqBt7NTILMU
         coyzYHhNmIFz2iH/gWvscepXPq7DT3ALUFEV2+/WFUH8vvFMgDZtL23btFVTaCqw2GbE
         gNcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rtE6DDog;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id l128-20020a1c2586000000b003a31bb11cdfsi202625wml.2.2022.07.20.08.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:32:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id c187-20020a1c35c4000000b003a30d88fe8eso1594633wma.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:32:57 -0700 (PDT)
X-Received: by 2002:a7b:ce13:0:b0:3a3:102c:23d3 with SMTP id
 m19-20020a7bce13000000b003a3102c23d3mr4328674wmc.67.1658331176588; Wed, 20
 Jul 2022 08:32:56 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-8-elver@google.com>
In-Reply-To: <20220704150514.48816-8-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:32:44 -0700
Message-ID: <CAP-5=fWTZ7f4TvJX_S4vZ3os2DBZGWE4qkyu9ro8ufs10A01Ow@mail.gmail.com>
Subject: Re: [PATCH v3 07/14] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rtE6DDog;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:06 AM Marco Elver <elver@google.com> wrote:
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
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
>  include/linux/hw_breakpoint.h | 1 -
>  kernel/events/hw_breakpoint.c | 4 +++-
>  2 files changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> index a3fb846705eb..f319bd26b030 100644
> --- a/include/linux/hw_breakpoint.h
> +++ b/include/linux/hw_breakpoint.h
> @@ -80,7 +80,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
>  extern int dbg_release_bp_slot(struct perf_event *bp);
>  extern int reserve_bp_slot(struct perf_event *bp);
>  extern void release_bp_slot(struct perf_event *bp);
> -int hw_breakpoint_weight(struct perf_event *bp);
>  int arch_reserve_bp_slot(struct perf_event *bp);
>  void arch_release_bp_slot(struct perf_event *bp);
>  void arch_unregister_hw_breakpoint(struct perf_event *bp);
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 9fb66d358d81..9c9bf17666a5 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -124,10 +124,12 @@ static __init int init_breakpoint_slots(void)
>  }
>  #endif
>
> -__weak int hw_breakpoint_weight(struct perf_event *bp)
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
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfWTZ7f4TvJX_S4vZ3os2DBZGWE4qkyu9ro8ufs10A01Ow%40mail.gmail.com.
