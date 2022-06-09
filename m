Return-Path: <kasan-dev+bncBCMIZB7QWENRBBOLRCKQMGQEX53LKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A8EB6545274
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 18:53:26 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id mh24-20020a170906eb9800b0070947edf692sf10469020ejb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 09:53:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654793606; cv=pass;
        d=google.com; s=arc-20160816;
        b=ufEujQTdrjJYgiF2CyNhBqaYPh4/RIUPiENox8qN1OqU/y7ttFiRFUr7aCN8toBWem
         3GxvFxayQML3c+h55SWYyXUmOQyjV0OqeigKcc8lWWX2rrEWvqSn0/xn0FITy5K/yy6b
         ZWbWv6kl3drnMQ7oORnzHsHg5xvj3J7ZzfmJnfqdLhF9VeZyz9CP25Mfodm7w6hN3uIv
         N6tzCfwrEbc0Wn3eG18Uf8E60JbpVCW0G51vChVuhFwVGMAtKSB7TSLNTngRr0uFC+pb
         vxI6aPLyjGeF8boBvhxr2WUFk+BXXxVdc5SAn6TAJxLLv/C0xreFsaoIqgMEcaDbdjor
         Hw5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M5Ig7kx8Bj0wkAA4znMN+J8+aONhwDi4VoR8p+jMJFE=;
        b=Hewrc46pxmxBnlxoIN+gpvyoCrU1VW7dxOEqz4Wtm7DAmj7jfsRhKZS6PnINrBXLjT
         XYmJIkPXWg4vK/Z37oYlJpy4Y8VlcDtQp/3kVJIxFdBrtn80zAZAxD0eZDd0srLyKqVD
         AAqyBRvY9Pv7JGNOTvBjy0bSt1DJa69XqJvV/e5zGEeAGa99q9JQW8YivlHxNuKwBWdy
         9wCM3PRHcua5um7pFZ24vNUTv6NZmB+FWIAHjqjzXbHNaHtoryc7KQf0x984TooB5QGw
         VK2Gzb/pwKmVGPxA3qgDgiom2HCIEuO3IhQLIVZoo8tuvPpyYbVeiqBZjelR8csoM/5f
         ME+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rMqG2WJP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M5Ig7kx8Bj0wkAA4znMN+J8+aONhwDi4VoR8p+jMJFE=;
        b=l4jRIF+tv8BBieiCFx4bbJ07NukDhe6uB0TguCvV7YPA1b71BlpPNCgllP+tCq/NnI
         1OplBCjjjXHDMdEElPAlESwUhL31ot7uTd0MpRpcMZ/fBUR3NnKu39zfjorWjnko4TQ6
         NYdGAJOEsavfj3ChuUi9em9JEVsfOLaZ2FuO6mVYCZGxbyLrnw0VPMysy7gcwtTGDsod
         CdniROLbxLWNPfVe8bGHkSg2IInNhBsKan0bqdXnpfEmyEkIjZCQWxgAoEyokWzh9DJg
         BMwEkrN35s2y6cCu42ebakqo352CBvP3xke9RplZAxxCksizseG26SwvhA4oMSzNGYng
         4ogQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M5Ig7kx8Bj0wkAA4znMN+J8+aONhwDi4VoR8p+jMJFE=;
        b=hZjSd7jSk+OXh80ji0T22IUs3tVMwOTlNPhyNxgLfExMB+BY/k0Jb+nBJWjeZoSiYM
         AzqC1NzFWD9NlbWB/hSgntY12Y8HjW5tqh/j2IOwRpW/kWys12f3nFqT4X5IqI2HPrhn
         oo5VZvR0tE7AgprQDslBLvLp+JAxKaqi4q1K5IVi5WHcdvsJIDHABxRdhiVjvSxZZhrI
         FsBuUyNsUjvAwgzRYAK5KLMvl7osJ9yjhX5nIqFoc4eh0zgAdocN9vO8RcRnnqWBOpys
         L8QzQQv++siQLD5SuhpWR5md2vt8tTOIb/38cUzR46VKfLThvIzbfSChxWQYZcNVnZmF
         DU4Q==
X-Gm-Message-State: AOAM530P3gjG8yHeINXC0TmFIcEyHso9CWQn1aFr5r+7uCdtW7eKTKoN
	9ufrTFtMrnTrU/VEN4oRv/w=
X-Google-Smtp-Source: ABdhPJwSNOBZBoO4/qumDMpddbgcY3+mFG0QVrfd5ScgjApF0svcNiJPuznYiT44mZLFhXCR7yys5w==
X-Received: by 2002:a17:907:6d9b:b0:711:d26b:f5ba with SMTP id sb27-20020a1709076d9b00b00711d26bf5bamr18455312ejc.135.1654793606062;
        Thu, 09 Jun 2022 09:53:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:294a:b0:42b:31b9:2087 with SMTP id
 ed10-20020a056402294a00b0042b31b92087ls2681852edb.2.gmail; Thu, 09 Jun 2022
 09:53:25 -0700 (PDT)
X-Received: by 2002:a05:6402:42d4:b0:416:5cac:a9a0 with SMTP id i20-20020a05640242d400b004165caca9a0mr45818239edc.86.1654793605041;
        Thu, 09 Jun 2022 09:53:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654793605; cv=none;
        d=google.com; s=arc-20160816;
        b=WEK/rS2419wTiQJxv+9/vgIhc91nRGdS0rwJrVJtgVBIJM9LPVan72uEd8HIZ512aR
         R9XnpKwW6bGrdhL6yGOi1fPhkX52i/ankzrznzPEPjltIGQWaoKlPF3j7wcqJxWggb/J
         9H7ckPHPYEhaPWSScbYv9mk3jqF5pS7uUj00K1YB7ri9fq8LKdVkNxLbbFsHU7RoxeYW
         Fc3ZCxPH42ErTpDvhI1SytyQhsUJ55S/GaaHWTz4Ji7I5D5xBQl6AFWyNt5SLS0pcDb6
         6/h55mfVxbxFNnsNlghAXsmkAO8DalOQ/Tw57Brx6mY/bd6gop53Ef5mEaCW6lu38PiW
         RHAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RnnI75MEx4lNy+rx7v/bh01lvj2FiAMBVy1u9JepGfo=;
        b=Hf8eu3xSJztfxuiAe0gG+HXi0CeAwx+fS+ZE38x79xFAroV/4kNMhyripjJdVIMzFc
         KlRrMz96ez/nNh3tLz296p8xFjkgpKl+9+DmUBbTQwG6rwP8NQ/RZYe8gUj8psOe+/3x
         8SexBsG6vAnSUj+9py/bUoBJNCVYSVpYDvt3WfjoQvLcCaWUg7cI9lqKzfiy+48O8dbK
         3p4+WddNRwGi2lbqkENnUCROAOSaAQTNfbt1IJEH7jr0S/XunYV0hezRUXJy+TKFlCuN
         IeALD+7JRTziPE/IXkbDHt6N8ZhHI4ov7Zpd5H6JidVIeER63JYzlWykuwo2u0Pjh4qD
         Dl8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rMqG2WJP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id e41-20020a056402332900b0042b8a96e45asi986657eda.1.2022.06.09.09.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 09:53:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id d19so14367551lji.10
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 09:53:25 -0700 (PDT)
X-Received: by 2002:a2e:b0fc:0:b0:255:6f92:f9d4 with SMTP id
 h28-20020a2eb0fc000000b002556f92f9d4mr22608060ljl.92.1654793604135; Thu, 09
 Jun 2022 09:53:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-2-elver@google.com>
 <CACT4Y+bOFmCyqfSgWS0b5xuwnPqP4V9v2ooJRmFCn0YAtOPmhQ@mail.gmail.com> <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com>
In-Reply-To: <CANpmjNNtV_6kgoLv=VX3z_oM6ZEvWJNAOj9z4ADcymqmhc+crw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 18:53:12 +0200
Message-ID: <CACT4Y+Zq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ@mail.gmail.com>
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task breakpoints
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
 header.i=@google.com header.s=20210112 header.b=rMqG2WJP;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a
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

.
/On Thu, 9 Jun 2022 at 16:56, Marco Elver <elver@google.com> wrote:
> > > On a machine with 256 CPUs, running the recently added perf breakpoint
> > > benchmark results in:
> > >
> > >  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
> > >  | # Running 'breakpoint/thread' benchmark:
> > >  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
> > >  |      Total time: 236.418 [sec]
> > >  |
> > >  |   123134.794271 usecs/op
> > >  |  7880626.833333 usecs/op/cpu
> > >
> > > The benchmark tests inherited breakpoint perf events across many
> > > threads.
> > >
> > > Looking at a perf profile, we can see that the majority of the time is
> > > spent in various hw_breakpoint.c functions, which execute within the
> > > 'nr_bp_mutex' critical sections which then results in contention on that
> > > mutex as well:
> > >
> > >     37.27%  [kernel]       [k] osq_lock
> > >     34.92%  [kernel]       [k] mutex_spin_on_owner
> > >     12.15%  [kernel]       [k] toggle_bp_slot
> > >     11.90%  [kernel]       [k] __reserve_bp_slot
> > >
> > > The culprit here is task_bp_pinned(), which has a runtime complexity of
> > > O(#tasks) due to storing all task breakpoints in the same list and
> > > iterating through that list looking for a matching task. Clearly, this
> > > does not scale to thousands of tasks.
> > >
> > > While one option would be to make task_struct a breakpoint list node,
> > > this would only further bloat task_struct for infrequently used data.
> >
> > task_struct already has:
> >
> > #ifdef CONFIG_PERF_EVENTS
> >   struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
> >   struct mutex perf_event_mutex;
> >   struct list_head perf_event_list;
> > #endif
> >
> > Wonder if it's possible to use perf_event_mutex instead of the task_sharded_mtx?
> > And possibly perf_event_list instead of task_bps_ht? It will contain
> > other perf_event types, so we will need to test type as well, but on
> > the positive side, we don't need any management of the separate
> > container.
>
> Hmm, yes, I looked at that but then decided against messing the
> perf/core internals. The main issue I have with using perf_event_mutex
> is that we might interfere with perf/core's locking rules as well as
> interfere with other concurrent perf event additions. Using
> perf_event_list is very likely a no-go because it requires reworking
> perf/core as well.
>
> I can already hear Peter shouting, but maybe I'm wrong. :-)

Let's wait for Peter to shout then :)
A significant part of this change is having per-task data w/o having
per-task data.

The current perf-related data in task_struct is already multiple words
and it's also not used in lots of production cases.
Maybe we could have something like:

  struct perf_task_data* lazily_allocated_perf_data;

that's lazily allocated on first use instead of the current
perf_event_ctxp/perf_event_mutex/perf_event_list.
This way we could both reduce task_size when perf is not used and have
more perf-related data (incl breakpoints) when it's used.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZq-1nczM2JH7Sr4mZo84gsCRd83RAwwnHwmap-wCOLTQ%40mail.gmail.com.
