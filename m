Return-Path: <kasan-dev+bncBCMIZB7QWENRB5ODQ6KQMGQEPTAVMWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BF2B544B42
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:05:10 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id e13-20020a19674d000000b0047944c80861sf5540042lfj.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:05:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654776309; cv=pass;
        d=google.com; s=arc-20160816;
        b=pWohcL2ilsapwkGI6DJTzyl4V8oDyXk7bTjp8ujKM0iz9yg/4yxe0EfsJKbGDKqhQt
         rox+Va1Ii5piVXpPGl5ILxfNZxlS849p3NcZKdM9n5ivTmJvlAEme8L1yQTxlx/lf/vm
         T7xIWtoRIjtWPwDAXQ00YKHHgEqIEzFtd/t+CZWdmdtBAstDp8NW7yL0loOxueLEt+NI
         lGkNHLhu57Y0h2wdLzbuzE66678IM9sZp51tmlh4WaC2rvcKsGvcoi3PuDHGts7x6sMf
         Yckcq0yAxRmultCrx/cfysztNq1g/OrRz+sz2vG1eck+J/jz6aj07+CXJuRJQrwMXlvM
         XoBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OWX7jx2ze2BCn3b5J6wIpJ03dRpBFzJ0q0b1Y4OFMUk=;
        b=tgKM5sR+mCBKfj8+yrRYT/UUNPV97BbGq7bO8AOHVUoYt8q8S4kIYLKjB0JHge459j
         sfmaHu7lokm+uGVOCRqbS5VtOW7Gu71D29040UgFKPT48NEV3V36uR8YPh3KlOL4m2hT
         yuTz8aIamMZ4HR3q2w6L45cpaYymHe702ojJgo9cXoVaW+7NuEM4eEXae0Gil75Vq/S/
         zswHYjo1RST22sSrsmhUvkiljSOuSQhMFl1uMBZjab856kBWHuNDy0v9HF2FNH3qtSkT
         Bll091XKrzWU0ocULeFoD7U+Zew72IICSt7wLuQOPuCw7wm3Ym2GwAzwjXjXXZK1Txm8
         kIHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NmOW1JYw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OWX7jx2ze2BCn3b5J6wIpJ03dRpBFzJ0q0b1Y4OFMUk=;
        b=HRKhukriFUzhKEibuockHIX0X75XlRv+xnkFOoGUDmQ3488xAGrN4c+bxeoTmguBch
         5wOTUsYEHXE6f0ZkoeHBPG5Pb5wMJF8ByOOkFyBxbhfzzWpWb1nTxrNZN9L9hjlf/PlH
         UZsB/R5NgvZNWj6HN6xpAvG5RxxNMMV03ES/wCG+msrhOWAE01TCrzlXDrLghaU+sjHa
         bjlWtqN9wNbXt++jjO8BBlpG97+wMN21OaHJeKdqKebXPmsNxnB/kwKuq6qt/Frx5Z17
         iExpTB4JlVSmCNh3EzrYalFDHapyYmfF4u+eTYydvjIxUubTCipCWk8K+1OVz5TtPqWM
         /OrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OWX7jx2ze2BCn3b5J6wIpJ03dRpBFzJ0q0b1Y4OFMUk=;
        b=3xffL0cG3m+3/9ys4o2V/6AjjGs9Rbt1cGkT92UK2cwSyZycEcIKV5Z1KLl739xajN
         f7hEsQpRIBwf5IfQn3raEXMef36OsBi3i5Nuxxh45NWHzQGC3AUxwSmESrFlU+FZaaBR
         xB0H8Q0ZNjyLSUh8DCZoxkmlcVujZ9mYZkN7gjUo69MIcCHLLALkvf9fqFF8NMQ5hOne
         /lQ68lNnfMaaEHmdN5a36/V0jcXC5un0UrAp4nRoJGvIMLlkYW8tBVYkuRGLwXxqor8v
         xaNbeDz1ZEXsJ79zYhQ7CKOJVYv6tRy4BXgWSpujUPVddhGOytnpSvsf2Sh+N4ibYCri
         jqEA==
X-Gm-Message-State: AOAM532aFiKvwzrcZ3uaGwaoh0qgPLXYIaozcICVPQT69DncmcNMQ4lM
	/ifkbWXGlbCm9YPLKjwb1V0=
X-Google-Smtp-Source: ABdhPJxpgMkupY7crmG1D1kGF67SR9VXC9TE4OL7NvoX2fekYD+N0VXOmTgpX7CxNwQmcOAVs0xDeg==
X-Received: by 2002:a2e:a594:0:b0:255:84c3:55b8 with SMTP id m20-20020a2ea594000000b0025584c355b8mr15637660ljp.484.1654776309250;
        Thu, 09 Jun 2022 05:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls22888lfu.0.gmail; Thu, 09 Jun 2022
 05:05:08 -0700 (PDT)
X-Received: by 2002:ac2:490d:0:b0:479:1568:ed46 with SMTP id n13-20020ac2490d000000b004791568ed46mr20917053lfi.569.1654776308015;
        Thu, 09 Jun 2022 05:05:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654776308; cv=none;
        d=google.com; s=arc-20160816;
        b=LydXlMqadJDPYBa7eS37xXJhAk5CXhJp0apxQpEzdh7i4xK0yBSCT9LAQLch6NsBJN
         GxcN+ey8sJmV2HvtotBKv6nAPrgX8M3pf4rMVHo9ViQ+X1ZsgXnZLE8i/8hbLZpeh9Hm
         URK4SuWJAmmH9Bgk5KwCjexv4kZMI326ikof4WP72UpicN89+tmS814/Y173RML2BYRU
         GXlUJyI+oFtv4TpWfkDgLHgPhHx46k8dq6rMAXunbSK6kAC/IVthSDyEm6bwKGaoawm+
         fnwAiWv7NpDIUdEWs8TEHTF8spnaxdBw2lUjZLliZhVa9RIhbYbg+SMGU4P+saI+ksNP
         O21w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FkqNvRH4Nue6fdbta9cxcgqLM1LMKqMxVWrvF9XcLFQ=;
        b=uMZ8wzRIeHKYTNbZLfvlXGIzWi2YaCikqF+aCt/HG6IiiNm3q5QiYiLlfJWs4ITrn1
         dwHJY8bnXVlkWLdU9qt2EIY2TJGL20k8R/0ZSvwXKqDq1nXYsIY0v8v6AreOhXi8RwXo
         FQooDk+sFOi6Bz04Qx2/g9bQ0IdTxFUbfS15wFR8wLzwK5+CPSAziLcPGp/aSJVjuUF7
         7EbbFtAswSv4BEKMzBLTCvmYuNC1PD6E0EvYDCWgGMQP6M0TqENHG5vjOpgB8pI2fKIq
         DlFILAYfqFjE7dsPluOHf3+VhmqvWdTD5ID/KlDZYprXhtNlDGSGnG4EITIKl7/589DO
         l6zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NmOW1JYw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id i37-20020a0565123e2500b00472587043edsi1145542lfv.1.2022.06.09.05.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:05:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id s6so37601834lfo.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:05:08 -0700 (PDT)
X-Received: by 2002:a05:6512:1588:b0:477:a556:4ab2 with SMTP id
 bp8-20020a056512158800b00477a5564ab2mr24570497lfb.376.1654776307498; Thu, 09
 Jun 2022 05:05:07 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-6-elver@google.com>
In-Reply-To: <20220609113046.780504-6-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:04:55 +0200
Message-ID: <CACT4Y+Zd0Zd_66DZ-f2HG4tR6ZdraFe9b4iEBJmG9p72+7RMWQ@mail.gmail.com>
Subject: Re: [PATCH 5/8] perf/hw_breakpoint: Remove useless code related to
 flexible breakpoints
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
 header.i=@google.com header.s=20210112 header.b=NmOW1JYw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133
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
> Flexible breakpoints have never been implemented, with
> bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
> bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
> flexible count in fetch_bp_busy_slots().
>
> This again causes suboptimal code generation, when we always know that
> `!!slots.flexible` will be 0.
>
> Just get rid of the flexible "placeholder" and remove all real code
> related to it. Make a note in the comment related to the constraints
> algorithm but don't remove them from the algorithm, so that if in future
> flexible breakpoints need supporting, it should be trivial to revive
> them (along with reverting this change).
>
> Signed-off-by: Marco Elver <elver@google.com>

Was added in 2009.

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/events/hw_breakpoint.c | 12 +++---------
>  1 file changed, 3 insertions(+), 9 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 5f40c8dfa042..afe0a6007e96 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -46,8 +46,6 @@ struct bp_cpuinfo {
>  #else
>         unsigned int    *tsk_pinned;
>  #endif
> -       /* Number of non-pinned cpu/task breakpoints in a cpu */
> -       unsigned int    flexible; /* XXX: placeholder, see fetch_this_slot() */
>  };
>
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> @@ -71,7 +69,6 @@ static bool constraints_initialized __ro_after_init;
>  /* Gather the number of total pinned and un-pinned bp in a cpuset */
>  struct bp_busy_slots {
>         unsigned int pinned;
> -       unsigned int flexible;
>  };
>
>  /* Serialize accesses to the above constraints */
> @@ -213,10 +210,6 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
>
>                 if (nr > slots->pinned)
>                         slots->pinned = nr;
> -
> -               nr = info->flexible;
> -               if (nr > slots->flexible)
> -                       slots->flexible = nr;
>         }
>  }
>
> @@ -299,7 +292,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
>  }
>
>  /*
> - * Constraints to check before allowing this new breakpoint counter:
> + * Constraints to check before allowing this new breakpoint counter. Note that
> + * flexible breakpoints are currently unsupported -- see fetch_this_slot().
>   *
>   *  == Non-pinned counter == (Considered as pinned for now)
>   *
> @@ -366,7 +360,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
>         fetch_this_slot(&slots, weight);
>
>         /* Flexible counters need to keep at least one slot */
> -       if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
> +       if (slots.pinned > hw_breakpoint_slots_cached(type))
>                 return -ENOSPC;
>
>         ret = arch_reserve_bp_slot(bp);
> --
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZd0Zd_66DZ-f2HG4tR6ZdraFe9b4iEBJmG9p72%2B7RMWQ%40mail.gmail.com.
