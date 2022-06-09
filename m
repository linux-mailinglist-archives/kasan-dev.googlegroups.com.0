Return-Path: <kasan-dev+bncBCMIZB7QWENRBZOOQ6KQMGQECLUJY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 949BD544BF6
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:28:22 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id e13-20020a19674d000000b0047944c80861sf5561538lfj.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777702; cv=pass;
        d=google.com; s=arc-20160816;
        b=mm0OBvFG1aUQHqg0Ma8LwfoaQK11o/FlQp6rUNcrCbyObEx+vPNXKe28TRKCBSH7Bq
         aZ2KohU+MKwJ5HuNgHzVvEgW0oh8jYiHeWcVsyjoIe4oNOjG7SKTt13AriEDOlJYt64E
         6RmtP30REU9PTu6f72xOVc4tOvqBvdk0ZAkThMTXIkZf/FjPryKvpX9A3xlkvGHchfd0
         hqLJOQH8jxERF71nH4kn01TP/uhcJB/fmdK2mdO6zyu/f4T17NNQ8Bnb/xgdpfhJ6W3d
         eYPXb3a49cb7GfSwztG1Ibf2leEGtyFV5pawkATLpKzvgETbRaH6wC4B3wkTfGMP1TPe
         T9RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sFP+vYowGIzoFuDgspMiZJczldPA1wcWStsTtrPbO5k=;
        b=NnUn9T8aEvApEOzDDy6dGcYcO2k8Wdkat4k/VVd+XvtYbUc9SXKAW0VoXnxLLZsZqp
         zJ64TADlQIhyh7yxNLRRqP9OyEC6qJDm6/p0Tgtr4i6y+TqgsrL+EzlXrnqMlF/eU/WA
         FNt4hrVf2htMwhHOue4UUt7EZAPHyj0W91ZKszWhVZuTtX+/RQj86Hl+KrovY9JtlSOs
         tHKk47rpxU5aibeghW2bus65PPd7wwSo/ioP1A8rh3Ukple4s5LJYsttkBUo62MzDS33
         YsWGdocozjv79o3+2/8KaoufEJsUK9g1KA91+Ik3FMNgZM17IEUpYk3xSChOyTVGRVVt
         Ge7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IMiMlQXz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sFP+vYowGIzoFuDgspMiZJczldPA1wcWStsTtrPbO5k=;
        b=E3oI8uEKl4eNXlXdVH2Zjpkd0PiSL33O1cy5R5E/nDNtplTJWDSsJ1QIAAK1J9IaZc
         xXySZZ+nZVelGQjJNBqvPx/3K4zY5/+A8N1POljoHoB6qz/5jFOoGpnOBeTJZdZsds1X
         h8+QqiBbgNP7GygnxxZUO8rpygymIZmScLonz80HfbSPcF4mGzTd1kzVCUlwVkp3RZVZ
         8UI0v0YnbQcs+2tCGisrfma4KmSGQge31DPNMOElUpfvqHWr9k8a8wU+jtcoXX2gaPWZ
         xj7QfUf+VytyLp9SEMBAFxTrQLv9y6ycq1MVEbcvabWCoX+ajkScqPDJPcYnN+W07yw3
         Bmcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sFP+vYowGIzoFuDgspMiZJczldPA1wcWStsTtrPbO5k=;
        b=OmwmO898OT2vtVZtnERadXJf7ciKYfFgGohuOuKfQcMUL4d+Xd+GftGSiKNgg4t8qH
         tfT3PUSUEFOJLDuCwxW/pnXRoIEEfC8xjLppmcX2o5kq3HTsjej3BlqaorkbmTWdobyU
         g6emt9A5TbPDp1NZwppILI+RvsvAk71B21y1PMn1+NPoMdR7HdDmGQdi8WLms8SD23yv
         uIxz7H5i8kMtqYtG1MVapE4sDjvm2UGDgj1Fms1nvwvmSF2kgJ3SpVWDzugp3Qa9tdc/
         9b3hy6FGpwIhwc3XBS4WUyNU+TiUdcCtHGG+fji1y5BjT1oqwVSbH8DL0sQZMyF6HXLh
         0hng==
X-Gm-Message-State: AOAM533mwUdbxTg870svbKKIJDjbCEvvtPazhh6xa+1DpG2Oc0LSz8FC
	6yaEKSyHLg09ePO6s4vi+64=
X-Google-Smtp-Source: ABdhPJyDFJy3AFlJhJ9A4h/5ottfE84hz3QcGIVXdGzTxqHc6d8bXBLmn0cZ20EEjOvJonjfEDrhoA==
X-Received: by 2002:a2e:2ac1:0:b0:255:6d35:6726 with SMTP id q184-20020a2e2ac1000000b002556d356726mr21903937ljq.41.1654777701917;
        Thu, 09 Jun 2022 05:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cc:0:b0:253:9ae0:be3b with SMTP id u12-20020a2e91cc000000b002539ae0be3bls830972ljg.10.gmail;
 Thu, 09 Jun 2022 05:28:20 -0700 (PDT)
X-Received: by 2002:a2e:7e0f:0:b0:255:5b7c:e173 with SMTP id z15-20020a2e7e0f000000b002555b7ce173mr26893445ljc.446.1654777700522;
        Thu, 09 Jun 2022 05:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777700; cv=none;
        d=google.com; s=arc-20160816;
        b=qGa9cFv2ZkWz4PCakA9jvSL13aURc5aIFFGlCb59BqTEb9gmrGhi/MDzEyE5fntv48
         /agkdiTlihSGedV3PYW5Pxr5AzwrqP3Jf7OKYQM99naTUYtH2tqeKhW5OpWQ0Ew6O+kg
         wI+a12KIeHQ+kNyjEVm7hhlFXqGYPTC20qsf/ahiE5r4i0BDl/c+S9KkhXafzCIjRfBY
         YaQd5OTEme0EtTyCFCELOBbcaUuNxuXpqKlSG/KUQIIltEjdUPefqyl1cd1X3W7Fhq4A
         wgbXoiFp/6LZtJfjRrDloRkMeTDTXJkj8zzeQLnkF3vvoO+HeAwkghlSw/wTdRZ4YVSe
         pDIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7ZkVNogiVa8TD8+T4Yv+cG2dpFAwHLFgC+ukHCJDT4I=;
        b=kB19JNpoFP+VOUXojgSz8NvHVw/hA8PqTaNbMs3dUiQulNScgDiUHkc7vvHHnGpuWm
         X0nF+2zIMrYd1LhdNveEwS8Eb0Oehq7SNfZhElEvRNhBKoxz9SDHiuVi1bNRn6ZKmfwO
         NhfIlQdm5EuRfcC8eCPVjEBa9EHeU4xcJWvnLixNoIbwblRjWtlk1dUyFK5pZUMDo7xC
         q7XPXZ336yHoABDqzaJKbqeqqwI7aDZE8jaoIWXZhivo+UhRFFRJ4eCwggoXvucQIc1s
         BrJQr6eG1N1SyWpVmocH2QFzqz7cDUZjIoqAow+i+NBJMeZVQUevofX3BLTQQosJEQr2
         Rl7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IMiMlQXz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id bp23-20020a056512159700b004789faf5d76si446628lfb.12.2022.06.09.05.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id g25so25936185ljm.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:28:20 -0700 (PDT)
X-Received: by 2002:a2e:8882:0:b0:255:6858:d4c0 with SMTP id
 k2-20020a2e8882000000b002556858d4c0mr24538236lji.268.1654777699961; Thu, 09
 Jun 2022 05:28:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
In-Reply-To: <20220609113046.780504-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:28:08 +0200
Message-ID: <CACT4Y+bA44uBgOZ7Hn74zrnX+agqGQWbkq=bzOX+A726nB2M7Q@mail.gmail.com>
Subject: Re: [PATCH 0/8] perf/hw_breakpoint: Optimize for thousands of tasks
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
 header.i=@google.com header.s=20210112 header.b=IMiMlQXz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231
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

On Thu, 9 Jun 2022 at 13:30, Marco Elver <elver@google.com> wrote:
>
> The hw_breakpoint subsystem's code has seen little change in over 10
> years. In that time, systems with >100s of CPUs have become common,
> along with improvements to the perf subsystem: using breakpoints on
> thousands of concurrent tasks should be a supported usecase.
>
> The breakpoint constraints accounting algorithm is the major bottleneck
> in doing so:
>
>   1. task_bp_pinned() has been O(#tasks), and called twice for each CPU.
>
>   2. Everything is serialized on a global mutex, 'nr_bp_mutex'.
>
> This series first optimizes task_bp_pinned() to only take O(1) on
> average, and then reworks synchronization to allow concurrency when
> checking and updating breakpoint constraints for tasks. Along the way,
> smaller micro-optimizations and cleanups are done as they seemed obvious
> when staring at the code (but likely insignificant).
>
> The result is (on a system with 256 CPUs) that we go from:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>                 [ ^ more aggressive benchmark parameters took too long ]
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 236.418 [sec]
>  |
>  |   123134.794271 usecs/op
>  |  7880626.833333 usecs/op/cpu
>
> ... to -- with all optimizations:
>
>  | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.071 [sec]
>  |
>  |       37.134896 usecs/op
>  |     2376.633333 usecs/op/cpu
>
> On the used test system, that's an effective speedup of ~3315x per op.

Awesome!

> Which is close to the theoretical ideal performance through
> optimizations in hw_breakpoint.c -- for reference, constraints
> accounting disabled:
>
>  | perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
>  | # Running 'breakpoint/thread' benchmark:
>  | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
>  |      Total time: 0.067 [sec]
>  |
>  |       35.286458 usecs/op
>  |     2258.333333 usecs/op/cpu
>
> At this point, the current implementation is only ~5% slower than the
> theoretical ideal. However, given constraints accounting cannot
> realistically be disabled, this is likely as far as we can push it.
>
> Marco Elver (8):
>   perf/hw_breakpoint: Optimize list of per-task breakpoints
>   perf/hw_breakpoint: Mark data __ro_after_init
>   perf/hw_breakpoint: Optimize constant number of breakpoint slots
>   perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
>   perf/hw_breakpoint: Remove useless code related to flexible
>     breakpoints
>   perf/hw_breakpoint: Reduce contention with large number of tasks
>   perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent
>   perf/hw_breakpoint: Clean up headers
>
>  arch/sh/include/asm/hw_breakpoint.h  |   5 +-
>  arch/x86/include/asm/hw_breakpoint.h |   5 +-
>  include/linux/hw_breakpoint.h        |   1 -
>  include/linux/perf_event.h           |   3 +-
>  kernel/events/hw_breakpoint.c        | 374 +++++++++++++++++++--------
>  5 files changed, 276 insertions(+), 112 deletions(-)
>
> --
> 2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbA44uBgOZ7Hn74zrnX%2BagqGQWbkq%3DbzOX%2BA726nB2M7Q%40mail.gmail.com.
