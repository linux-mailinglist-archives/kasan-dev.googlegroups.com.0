Return-Path: <kasan-dev+bncBCMIZB7QWENRBFHRQ6KQMGQEDRC3U5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id CFAA2544DE5
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 15:41:41 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id y4-20020aa7ccc4000000b0042df06d83bcsf17149434edt.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 06:41:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654782100; cv=pass;
        d=google.com; s=arc-20160816;
        b=MDTU5mptsMmDbdP4mo2tBxMTevplx3REax9WUILG5IwPsU+GLLIV+ubXmqwg+3GXi8
         uMAcRD9UQgOyQUgdQSMKZq2q6iHf/1vjonXJa/JAqP4PRiZ7U5BXt5y9O0KfjlleEpUx
         8ojAlBH/PWv2AjV/S3qL4A3+38KduuWA8WyH7S8/6DuGFUAsCRwZ+ZEn41r/I6NG7n9l
         mGtaSO2kRgsipBRJHmv7g36AWd861G4TwfAwUjchVATyqQaGQgky+xLZaL971KlbrsIV
         BtTKgGRjmyvmZDHqQX7NwB/tWdJ0Qv5t+PxSwl0vYqTNTRVbUcZ6TY72BnuDs97Lrcx/
         1cLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zh7TrUXAL5fSBKnvKaGIz9W8CaKSSn9KmlRd+8iVc9E=;
        b=NFZqQs5G+ZPTqJrzgHeN3F9qWeFSFLCwu8+P5AzkgxeQGAB41Aug+7gbyPhpKTrqZH
         YtuI8XFr2TtkfT5q8/r0pFM/CfJ0MpIaL4agd38RIYzReSNSZ9aIY8J0QJxDUVxbBREZ
         yx8E+0NQhooKeOLHvEpVjulu7DkGcENA1j/umUodtzrs/1JDQEiDXSm44r4tYcIjc6pS
         vVf7aLSQQj2OdPB7+v1EfKmdFyiVeXthQX7PrX2zVzmOKxbn6RQC1yzjCwDufuQ44fJb
         lo+FyTvXCWNtnvvCzSR4L0/FlXCPamIYB+5VxK8PgVY1H/Kp+GCL7pWKC7roe1+mhIGQ
         eX/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OAxGTJUe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zh7TrUXAL5fSBKnvKaGIz9W8CaKSSn9KmlRd+8iVc9E=;
        b=d5MC+OzACP4isNSqVDpV2y2Egg4RbCUCrnPc3oTp/CtwZSYxxuwnesoQDT2dWuO841
         SdS3mLyjV4yn1m1QFOuX3fbp7NgbxKAviSQw64I4Ck3c4lyJBkGB/MAA8Uc96jEHz2bf
         FHt8aMUYPWdlM+t2dOwK3/dI1es7/no87kQ/2WenCe/5ZPYBANLq97ACtOzu3M2W1xyD
         BUKtswHKifAcr2d+aqwFf2z4+y7uI6oCZ+Xi1Zp4JaMiM0iiYAIMzhYJtg3d+EmhpsWp
         N/cSNLMSm21Gw8UDIFge5u8ta7Y2J2rOUIfmzhHntoNWxC2mJo1ST8zK32hyYG91MUsm
         2ONg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zh7TrUXAL5fSBKnvKaGIz9W8CaKSSn9KmlRd+8iVc9E=;
        b=LzK8cGKmusImrJOtvWjwxPhLGhLrnhdhRD5teV+luhYwPDrNSZIdPhDebLkKAQhU45
         42tpkHthm4VB9+iFe+pQT0aeWf+rxWssc9bzR1gDO+m6SydAhipuZd6/AgUXKKz7TEZc
         +CLNC6RzfT0ABkh9It2b+A2pziEte4U/6inSRRBcHZfqoU/pjh+4F6IZzfhhoazaOR40
         TES0Xcgj5aJOzCWy1TO/FNy7vQ9jnoS/aV0qDGOGmriHX1Q322372M580YrobvmwU3i6
         XNrjk90vw0/4ZeOa2uVTpYcvXjYueUSQgHmhPMCfNDvJXGgUCeb53UopPuFkcIss7owV
         TxBQ==
X-Gm-Message-State: AOAM532o3YIhONfcH0tdnwPfc8eFS5Y4WR9Nj4M4GnF4mEmkafZvz2+X
	yXWJlHJxtNaaxmVbr017Oog=
X-Google-Smtp-Source: ABdhPJwtQv/UYwwmqxF5cxlojwVgc4RlOE3GIt0D3LUbs4LdGArG59Lt8OkKeikgkgCEP0SCtm5YWA==
X-Received: by 2002:a17:907:7d91:b0:6fe:efb8:8f97 with SMTP id oz17-20020a1709077d9100b006feefb88f97mr36172982ejc.717.1654782100504;
        Thu, 09 Jun 2022 06:41:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:c19:b0:704:582e:9858 with SMTP id
 ga25-20020a1709070c1900b00704582e9858ls2832402ejc.1.gmail; Thu, 09 Jun 2022
 06:41:39 -0700 (PDT)
X-Received: by 2002:a17:906:1dcf:b0:711:f0df:b903 with SMTP id v15-20020a1709061dcf00b00711f0dfb903mr9116204ejh.267.1654782098935;
        Thu, 09 Jun 2022 06:41:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654782098; cv=none;
        d=google.com; s=arc-20160816;
        b=krIyNXHDdqf+sjTp3/bz8e7u47rahSdDazValklXm0BcfkaUvgidCerUQJk8FBKrzg
         q8pTq1YXWfpde8HPnh62ocrZzf4HLYytVcGtO3GGrHZK+3HSzqevX2NRakrgkjhigVFi
         j0CPIFMcyMSYwy1asdfDzlsT3ohBk39PKeDmHmV26zDmyRYKFGHVu0C7XNK5iuUGkVC1
         ag6DbqIYdrqo2aAAxT2J4jYFPyustLd6RedjcxANiGBOrCYoaph3W/Y3g+it+izYoIZy
         GPZLyms1PgZqceQOwCKSjR7JtIGaECGY2sewwUCbIEDp305YDonOAo6hvJa7sbLy9wzD
         ndtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PF28ZnQLVsGI2i7ul/dfgqup/8C1a0mc9TiBXmcosYU=;
        b=cJDVKScFF791U7aS/Iv8zOE9EEXLMVM1eqQqOw+hBPqSzm8BExR/YRNvRI/RxnoEY5
         BuhHUJrwnZIrwEw2s8Y1EPzIVJ9R8HB5HEQagczYIvSjQ7SRSk9kvk9IFJilZ18YwHCe
         qYitgFWRXDOs8j5QR3Ou3P/1VaZNIZQNiz6dVhWmSfukd5kfSlGYPlQhhKuDb2bBmV5U
         BnmhBLlKADcsj6o5fmCbaUX1cnxyAOKyp8DhsOILihRNYoOMqjTyT2QpcYSycwZhO5/8
         sZ5WwrzQLUZRyqZZUQMK6+tuCGhPmbBIXsDoJeJYk0/PFFj32bsoLhW5rXoBJZFKenEC
         xh/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OAxGTJUe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id a26-20020a170906245a00b007104df95c8bsi764801ejb.2.2022.06.09.06.41.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 06:41:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id b12so15222670ljq.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 06:41:38 -0700 (PDT)
X-Received: by 2002:a2e:b0fc:0:b0:255:6f92:f9d4 with SMTP id
 h28-20020a2eb0fc000000b002556f92f9d4mr22136645ljl.92.1654782098160; Thu, 09
 Jun 2022 06:41:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-6-elver@google.com>
 <CACT4Y+Zd0Zd_66DZ-f2HG4tR6ZdraFe9b4iEBJmG9p72+7RMWQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Zd0Zd_66DZ-f2HG4tR6ZdraFe9b4iEBJmG9p72+7RMWQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 15:41:26 +0200
Message-ID: <CACT4Y+appPi5YAdKFB-2caO6xkg89FmV1_4532u7Jx_5CAX9xw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=OAxGTJUe;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230
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

On Thu, 9 Jun 2022 at 14:04, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> >
> > Flexible breakpoints have never been implemented, with
> > bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
> > bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
> > flexible count in fetch_bp_busy_slots().
> >
> > This again causes suboptimal code generation, when we always know that
> > `!!slots.flexible` will be 0.
> >
> > Just get rid of the flexible "placeholder" and remove all real code
> > related to it. Make a note in the comment related to the constraints
> > algorithm but don't remove them from the algorithm, so that if in future
> > flexible breakpoints need supporting, it should be trivial to revive
> > them (along with reverting this change).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Was added in 2009.
>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>
> > ---
> >  kernel/events/hw_breakpoint.c | 12 +++---------
> >  1 file changed, 3 insertions(+), 9 deletions(-)
> >
> > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > index 5f40c8dfa042..afe0a6007e96 100644
> > --- a/kernel/events/hw_breakpoint.c
> > +++ b/kernel/events/hw_breakpoint.c
> > @@ -46,8 +46,6 @@ struct bp_cpuinfo {
> >  #else
> >         unsigned int    *tsk_pinned;
> >  #endif
> > -       /* Number of non-pinned cpu/task breakpoints in a cpu */
> > -       unsigned int    flexible; /* XXX: placeholder, see fetch_this_slot() */
> >  };
> >
> >  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
> > @@ -71,7 +69,6 @@ static bool constraints_initialized __ro_after_init;
> >  /* Gather the number of total pinned and un-pinned bp in a cpuset */
> >  struct bp_busy_slots {

Do we also want to remove this struct altogether? Now it becomes just
an int counter.

> >         unsigned int pinned;
> > -       unsigned int flexible;
> >  };
> >
> >  /* Serialize accesses to the above constraints */
> > @@ -213,10 +210,6 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
> >
> >                 if (nr > slots->pinned)
> >                         slots->pinned = nr;
> > -
> > -               nr = info->flexible;
> > -               if (nr > slots->flexible)
> > -                       slots->flexible = nr;
> >         }
> >  }
> >
> > @@ -299,7 +292,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
> >  }
> >
> >  /*
> > - * Constraints to check before allowing this new breakpoint counter:
> > + * Constraints to check before allowing this new breakpoint counter. Note that
> > + * flexible breakpoints are currently unsupported -- see fetch_this_slot().
> >   *
> >   *  == Non-pinned counter == (Considered as pinned for now)
> >   *
> > @@ -366,7 +360,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
> >         fetch_this_slot(&slots, weight);
> >
> >         /* Flexible counters need to keep at least one slot */
> > -       if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
> > +       if (slots.pinned > hw_breakpoint_slots_cached(type))
> >                 return -ENOSPC;
> >
> >         ret = arch_reserve_bp_slot(bp);
> > --
> > 2.36.1.255.ge46751e96f-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BappPi5YAdKFB-2caO6xkg89FmV1_4532u7Jx_5CAX9xw%40mail.gmail.com.
