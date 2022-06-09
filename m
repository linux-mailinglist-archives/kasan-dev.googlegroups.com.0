Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6FQ6KQMGQEQUPFEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AAF6544B4D
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:08:41 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id t11-20020a17090a2f8b00b001ea6a226d21sf346744pjd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:08:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654776519; cv=pass;
        d=google.com; s=arc-20160816;
        b=GxOpN0JsyMwVSZGijUJomJ5FBorWh1iWD9QanqZb7FSU0kegEG2Qlk4nfhTfr/X5ty
         d5P5hCDXjoGkL8Y7UkIAe1BpQOmSfqBPP9Jl1QHszz1sGe10xUZZAIH2BaoZxx7MonTN
         G6N4CDop16SepX4RQUscr/iOVlvoIXG1rbGpMJK7xWp3g+CZLYnXPQVomODyU4tCXHCO
         hvwIrl+V1xaSLlMWqdiugV5DhII7G3VVvC/d0r+flPFb0FP7BpR2s1J5Qkd4n8ODlbKo
         VwJI+ZHjZFIpZKYvv0RaVSANVgXuenSlK8+bzV9+4na0XuHcQAdfoS6EEzp+UJ3C86WX
         YkZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mg2mlCfGNH/CcFFAnQw1nZ+NiP2lx5gpIvqtz7Mh8Dk=;
        b=r+qM5xSIfYn9ZCfCs6XS3unS1v93Q++TqhuLD0YelbudmWsVnLWGZrvpyyuMM7GNPo
         GJwnR6YHZEUUDxAd4kmpUyS7rCXLW92L211IXPdkUQ/fOa3qQsY3etmuB6iAxPfX6e6k
         2Aegr2UL/PXm+HdUa95RaiOJ+7+XMi7arH+bxD6x20IWeHlmmht+2mWk88JdnFWMDNsM
         YO0nIC2TMbpcjD0mpuaXXb34JshCkkJTpvBcxCf+HBe/9HX0b3GVbNPOY6d+sy98ibvW
         AFyy0Exo60w4rUNkXOo+iMfAlQrk5EUGvuG3bVJtdzVRQ9zpETzrufY0SfsXNxdD286v
         VeTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dvX8wSw1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mg2mlCfGNH/CcFFAnQw1nZ+NiP2lx5gpIvqtz7Mh8Dk=;
        b=c1UTOWjq2Nm0Dn8qqWlfi6fNxLMMd39QzrEwbAdSKFt0gj3YjCtQSeYPnd3IN9xuuu
         JDFS/uFZNEMEEoLAQe7m7cS7LOQRbkHHVfUBOmXBR+pfoJwvjfiUG1Gq8P6kgPoAVYx8
         qqpc7tGsFydq+n24wcjedMWwaZ2iS42uHmZrzYN8s+1/jSY3Psoe8izlIo1Wi9g6swwQ
         2LJj/QqrsAKeAljhmIFUkvgJ6BFeuzhaOXDJMlMfuzs5qD1uHrOWmjiEsAouzeguVWK/
         qCp0XE+RgK0E5hyRRNrderzjIK/ZadpraHbeWbXkidU98gYqzxWd0MlGaTFg6/YZnDLP
         6Low==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mg2mlCfGNH/CcFFAnQw1nZ+NiP2lx5gpIvqtz7Mh8Dk=;
        b=tTm55VTHlwx473yuMwolvo3x2Y/6Ttyu9xUMOgJBXAM+6XnljsiyHs2Qb5cUcUGmY/
         flBAz0KPYlezr4M4k5UwIwLNxDBWgfZL9S8qwmvg1e7FewhyeGWEL2+hGHuWHfLj43WT
         gMG/6f4zL+NTL2V8Ds57G6k5YbsNmB7a6tNirI8z0ZWQULg+biESXLzXk1hwn2x3XCDC
         dq9TozXr9Kgw3emUN+4tXns8g8PJkFr32l9doHp7qtSWyYhllb0FOTfpMq4lIFpkcvKY
         79gZ1hjv2n4rwrI1Pb95wLvkBMlrwSkTdS6cGDWRJ54bFvHzhtWaP8OHecabDItLX/mC
         u13A==
X-Gm-Message-State: AOAM531yMY0H+GOAHAQfyM038tKbiFS1ArslHS1XUoPRUvhqdVVTrDMQ
	fYs1+YPTEvtNluPWhCUUmYw=
X-Google-Smtp-Source: ABdhPJzEvH8HcTfK8BGtkkL29FiF4B9UeiJQrU75C7WfEMepcDp/l40UkbNa/ZDVo0l1drIBXF+obQ==
X-Received: by 2002:a17:902:ea85:b0:167:96cd:b97b with SMTP id x5-20020a170902ea8500b0016796cdb97bmr12853567plb.95.1654776519273;
        Thu, 09 Jun 2022 05:08:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22cf:b0:166:4fb9:d7da with SMTP id
 y15-20020a17090322cf00b001664fb9d7dals13195896plg.3.gmail; Thu, 09 Jun 2022
 05:08:38 -0700 (PDT)
X-Received: by 2002:a17:902:e5cb:b0:165:1500:a69b with SMTP id u11-20020a170902e5cb00b001651500a69bmr5578914plf.29.1654776518504;
        Thu, 09 Jun 2022 05:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654776518; cv=none;
        d=google.com; s=arc-20160816;
        b=YyLicgEJebWAhc6NeX0kjpN0XAkekwYsQYZygLjG7OYzQkWUPGcqGFju7jMoJo0GvD
         LLVjCSlwf14tm9TlI0oB0CPVzLDm6iBdQI0n3S96C1GPbmiyjk5J2Rke1eonteJHtgHP
         rCGyH/NpmswtznPLcmYtCJSZMUvDNuXDwc7sKyebFNbxT6OYkv86O0gCt9ZoF9vmulK1
         +fdHXXH9jmongyKjxDwYNmh5mRUNyfMqVh/zbKI4h/0cgbomcNtfvWv+P/MQMdZ9Kzxa
         t46jIEs3jYk5FqwbDAI+dAuoYrplO3t3BX+XFOu2G1RGnyx8UFTK1AwidIlcqv+UaTST
         42Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/fgAdX8O4qm/LW6iACkSWWobNgY9ruhG5Pvbw2aAB7Y=;
        b=qx0sSGXLL0mEFhNQg2RDlcCpFKKWJoLFirx7IsoibnIIzIWpTCzk2aRE9V+QCUHf4d
         NP/lcbBjpSTrmSelTcmUzVwxWPHOr4PhNY+eQa31tCEOPqVzlkSL9EctJZD3kYznKPCe
         pYJoFG3YxPMDtFxd16snpTPED68kqB+LzJbfduerzsV0uOOhgKjSZWBe2/UlBkhdrie+
         UeD2fFlp0zMN/nILoqmSLUEQzkZQ2AmtgzXr5LXiCElncW0qRZc9+wxr9H7t+h/W/ZBw
         8fpd/3lNdGD/s3RFwvU7fomNPtseZ3uChlfwFr5e/Gh7t+PPGjgz5A3wn4SfzK1Ed+AZ
         FWNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dvX8wSw1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id jz19-20020a17090b14d300b001df76e9c039si96490pjb.3.2022.06.09.05.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-2ef5380669cso238576157b3.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:08:38 -0700 (PDT)
X-Received: by 2002:a0d:c0c6:0:b0:2ff:bb2:1065 with SMTP id
 b189-20020a0dc0c6000000b002ff0bb21065mr44133509ywd.512.1654776517756; Thu, 09
 Jun 2022 05:08:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-5-elver@google.com>
 <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com>
In-Reply-To: <CACT4Y+YHp1mxxGNuGke42qcph0ibZb+6Ri_7fNJ+jg11NL-z8g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:08:01 +0200
Message-ID: <CANpmjNMA=UKzpURckHh_Ss14oRoTQ7nZ4yqcb=nV1kBtEcEkdw@mail.gmail.com>
Subject: Re: [PATCH 4/8] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, x86@kernel.org, 
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dvX8wSw1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Thu, 9 Jun 2022 at 14:03, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
> >
> > Due to being a __weak function, hw_breakpoint_weight() will cause the
> > compiler to always emit a call to it. This generates unnecessarily bad
> > code (register spills etc.) for no good reason; in fact it appears in
> > profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:
> >
> >     ...
> >     0.70%  [kernel]       [k] hw_breakpoint_weight
> >     ...
> >
> > While a small percentage, no architecture defines its own
> > hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
> > which makes the fact it is currently __weak a poor choice.
> >
> > Change hw_breakpoint_weight()'s definition to follow a similar protocol
> > to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
> > hw_breakpoint_weight(), we'll use it instead.
> >
> > The result is that it is inlined and no longer shows up in profiles.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/hw_breakpoint.h | 1 -
> >  kernel/events/hw_breakpoint.c | 4 +++-
> >  2 files changed, 3 insertions(+), 2 deletions(-)
> >
> > diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> > index 78dd7035d1e5..9fa3547acd87 100644
> > --- a/include/linux/hw_breakpoint.h
> > +++ b/include/linux/hw_breakpoint.h
> > @@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
> >  extern int dbg_release_bp_slot(struct perf_event *bp);
> >  extern int reserve_bp_slot(struct perf_event *bp);
> >  extern void release_bp_slot(struct perf_event *bp);
> > -int hw_breakpoint_weight(struct perf_event *bp);
> >  int arch_reserve_bp_slot(struct perf_event *bp);
> >  void arch_release_bp_slot(struct perf_event *bp);
> >  void arch_unregister_hw_breakpoint(struct perf_event *bp);
> > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > index 8e939723f27d..5f40c8dfa042 100644
> > --- a/kernel/events/hw_breakpoint.c
> > +++ b/kernel/events/hw_breakpoint.c
> > @@ -125,10 +125,12 @@ static __init int init_breakpoint_slots(void)
> >  }
> >  #endif
> >
> > -__weak int hw_breakpoint_weight(struct perf_event *bp)
>
> Humm... this was added in 2010 and never actually used to return
> anything other than 1 since then (?). Looks like over-design. Maybe we
> drop "#ifndef" and add a comment instead?

Then there's little reason for the function either and we can just
directly increment/decrement 1 everywhere. If we drop the ability for
an arch to override, I feel that'd be cleaner.

Either way, codegen won't change though.

Preferences?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMA%3DUKzpURckHh_Ss14oRoTQ7nZ4yqcb%3DnV1kBtEcEkdw%40mail.gmail.com.
