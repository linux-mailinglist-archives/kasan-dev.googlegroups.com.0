Return-Path: <kasan-dev+bncBDPPFIEASMFBBCOH4CLAMGQEYFORY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D53E57BAC1
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:47:22 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id az39-20020a05600c602700b003a321d33238sf2901319wmb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:47:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658332042; cv=pass;
        d=google.com; s=arc-20160816;
        b=guLbkLN7o1BWJ/RIhLRrrZ7Z8eE/aK0eVwl6H+g40M1hmwt7/tqZgjFpPqqAZ/n9FK
         avUuGcgyVfy0HAUro41+7AsSrHRO9/daHD40P+yUS16cVNTbNUy6zkgindbVC+iK3Zh7
         FmhxzDObzlJd77zhuon1/dKEyL8XfoUZ63dpo2d8J4x6+PAk+0kTAaSsEs5K8VNht5rj
         JvG6HmVUElnRjkDq5ZPoH4wmHIab336a29/NuVQjFAF+5Djzi31BIqY9b5rlR5ncx75o
         d02lPm8i0n5DNC50TM4GPUGWmQOZqmPEat9aSvuyrJotoVP0vafSC9qWToafxCsSjSzb
         d9kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=opFWUsSgGb9XcCIqPoV5gqtGu8+VNfJ10HHgRjvmcGs=;
        b=r7kqR9pk12f2ITI1Uzy+OWWmua3r2GOE2nTOxjblJoX2ltryXWLDMahkKC8cclKq3Z
         3OYDFeMKNeoAUgXPzxCNSloaxH9SqpDh5YbvGP2VU/uIHA0LkNMSTQr6e2CgZV0Stgzl
         LKromg7yn1XfYbV2wo3VlHu5WzcDBO+HdPl4VvEeWBXRtGzEJru3O+ZaaCBQ803ILIjW
         YysDGImv5pNhUuEo2jZFEnSaf6+C+QMMChJaEn1RzOOyvirY3BxuYlvUk9Kpm+z0OtAS
         aOHUYPgD0OcBB7OvbL+zmEgtrpjui5l3HHVWvM3Vm1a+ILJjuEJDl+heatcrsaKCMv4U
         p4xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sIAZtEgu;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=opFWUsSgGb9XcCIqPoV5gqtGu8+VNfJ10HHgRjvmcGs=;
        b=OzG8QHjogSw1MW6uUqD2NbILFWXHUQ2Cc8NJo5DPtbDBHWPi5+01oS2gCnyQnv6C3K
         rajFjCyI7MH9T5WSCc672EIU0JrN9+u3ml2zmd3VFBmtJynVvmJEYLaay/64hJagL9jw
         dnDu6cT6nPxoAN3Swr2qYi5EjkpKU9wlnFQDrDPQXDW+5494S3vqNGiQPXwO5A2CJdfT
         b+bQlOGAExza53iH2OOAEMkOUXfNPlEgvkDULfFXxfAhU66vtOnTf4SWVCm/jm/UWWLQ
         EYpdgN5cNxVfHPcTvy7wREXrYjfRA6vZ9Mbhw4hC4dCgQsWdsmHDsguyC6Mbxv5cRHV0
         nzzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=opFWUsSgGb9XcCIqPoV5gqtGu8+VNfJ10HHgRjvmcGs=;
        b=vd/eIyVvkza8giLgQDUOzSLZp89dzaCwA9GrWUsO/Dnm4DpcivCQ2AZEO2iHl09yys
         oj46pcVX0zFBLMYfPdTjByTd8xtWPmBfeJE8j6BePwDbAQvdpOTmaDS/70BQI3qlIr3n
         px1qwoOi8GyHoitOjXUj0QJCUXO4VPbmeLOpiVZ9sUpYJm6cXDxUe8iUVX/31Dfn2aqH
         4a1RCZvl7psTWYaAuhNi5VbPbjiT/JnUiRzHCD+yt/oNxgpMoUm1eCIp7aakSpOZtK8A
         nfbm6GmJdl2GHKm8fDTVr4o+cNVfT0pzO3dpN0FxFrcbUXdhDFbiRrfCZ6rjhX8VjYsQ
         snFA==
X-Gm-Message-State: AJIora8nL1wIr0dJ+LcHhREl2Ss8HET3rr06CzCm0sSHxk6Ll53y8F2z
	GOVUlaLelcGJ4PLFGbZclk0=
X-Google-Smtp-Source: AGRyM1v2Gk6E48/oXLQVo6pwiK+746REr4Bo4L3ZQBdu1gwbM4pbfS4BLzt1KrkNELGDrO/fdDwrMA==
X-Received: by 2002:adf:d201:0:b0:21e:47a5:5ee4 with SMTP id j1-20020adfd201000000b0021e47a55ee4mr3800536wrh.261.1658332041878;
        Wed, 20 Jul 2022 08:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f415:0:b0:397:d1d5:9b4e with SMTP id z21-20020a1cf415000000b00397d1d59b4els934486wma.3.-pod-control-gmail;
 Wed, 20 Jul 2022 08:47:21 -0700 (PDT)
X-Received: by 2002:a05:600c:1f08:b0:3a3:1b00:c201 with SMTP id bd8-20020a05600c1f0800b003a31b00c201mr4544974wmb.171.1658332041035;
        Wed, 20 Jul 2022 08:47:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658332041; cv=none;
        d=google.com; s=arc-20160816;
        b=WnzP2P5X1uzdW81U3aO15Mlfbp9aNfMbkVC7SEzT6lkywqX1agrJygCRUyAMeKwbvM
         o+W5MR81HmogKeFBr43w9ImD+2ThR9tfvnmaOS+CzmRmaJJJbnt9tIC8rzZYFIf2I0dR
         rToggOOwRg+qtvCRPuoaXN5PWYff815HzFyb20ADmbtzPEQRLMtSiRwydX42GRKwrk8i
         jePzTfcdUzuF3owekqeBQabTtNXI4T0fs6z3L5I2C7Vx+Rcuutvjj6A32d0nxBqGDuji
         0KGJqg5x56pqyEXQsEH4MFAlasIWpIzx/HRJ+LH+Jjr2rovN0Bd+Z1bzkBMM8j9tqQ3k
         fQdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mWnAaZCfU7C7OmxHqnYWgl+iLsNs720nTVq22EtgHY0=;
        b=KUG8Rw3MxBHHuyS9GimPQCp2CchhwmeLHJIX60tQW7AMG2Xcsq/gBoT1Gn7/77b5pX
         0R5wS30FFK1ksGTv1CDIbwsNGK/NGi9M0qHqe4+2Da8OlkxGUT0P0etH8SJdDzlSSfpC
         jrNy3IAKBJCucrdqhf9a1Ax5pRwO1u1EaVoJv1Jr5PxwLMYBGuPewdPlZxOAkOQrCgfD
         J410zkObgTY80WqEsKqheHwWTLx61Yj8V/xcZSpr4q8BIqQ6YCCR5fiVXYulE4Oh6vvI
         N/AMQFZMlBPUrVMJQF7OM7vJ7HSsGYL4TuSVNb7SM6jSNl3PTUA3EUpIPi5josUB/5yP
         k+Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sIAZtEgu;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id bd14-20020a05600c1f0e00b003a03ade6826si113705wmb.0.2022.07.20.08.47.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:47:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id h14-20020a1ccc0e000000b0039eff745c53so1533132wmb.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:47:21 -0700 (PDT)
X-Received: by 2002:a7b:ce13:0:b0:3a3:102c:23d3 with SMTP id
 m19-20020a7bce13000000b003a3102c23d3mr4391193wmc.67.1658332040566; Wed, 20
 Jul 2022 08:47:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <CANpmjNP0hPuhXmZmkX1ytCDh56LOAmxJjf7RyfxOvoaem=2d8Q@mail.gmail.com>
In-Reply-To: <CANpmjNP0hPuhXmZmkX1ytCDh56LOAmxJjf7RyfxOvoaem=2d8Q@mail.gmail.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:47:08 -0700
Message-ID: <CAP-5=fXgYWuHKkfAxxTeAzTuq7PLwMd6UvBu+J+6tnqHwraSCA@mail.gmail.com>
Subject: Re: [PATCH v3 00/14] perf/hw_breakpoint: Optimize for thousands of tasks
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
 header.i=@google.com header.s=20210112 header.b=sIAZtEgu;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::32f
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

On Tue, Jul 12, 2022 at 6:41 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, 4 Jul 2022 at 17:05, Marco Elver <elver@google.com> wrote:
> >
> > The hw_breakpoint subsystem's code has seen little change in over 10
> > years. In that time, systems with >100s of CPUs have become common,
> > along with improvements to the perf subsystem: using breakpoints on
> > thousands of concurrent tasks should be a supported usecase.
> [...]
> > Marco Elver (14):
> >   perf/hw_breakpoint: Add KUnit test for constraints accounting
> >   perf/hw_breakpoint: Provide hw_breakpoint_is_used() and use in test
> >   perf/hw_breakpoint: Clean up headers
> >   perf/hw_breakpoint: Optimize list of per-task breakpoints
> >   perf/hw_breakpoint: Mark data __ro_after_init
> >   perf/hw_breakpoint: Optimize constant number of breakpoint slots
> >   perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
> >   perf/hw_breakpoint: Remove useless code related to flexible
> >     breakpoints
> >   powerpc/hw_breakpoint: Avoid relying on caller synchronization
> >   locking/percpu-rwsem: Add percpu_is_write_locked() and
> >     percpu_is_read_locked()
> >   perf/hw_breakpoint: Reduce contention with large number of tasks
> >   perf/hw_breakpoint: Introduce bp_slots_histogram
> >   perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent
> >     task targets
> >   perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task
> >     targets
> [...]
>
> This is ready from our side, and given the silence, assume it's ready
> to pick up and/or have a maintainer take a look. Since this is mostly
> kernel/events, would -tip/perf/core be appropriate?

These are awesome improvements, I've added my acked-by to every
change. I hope we can pull these changes, as you say, into tip.git
perf/core and get them into 5.20.

Thanks,
Ian

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfXgYWuHKkfAxxTeAzTuq7PLwMd6UvBu%2BJ%2B6tnqHwraSCA%40mail.gmail.com.
