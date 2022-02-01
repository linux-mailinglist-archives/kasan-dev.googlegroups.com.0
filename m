Return-Path: <kasan-dev+bncBCMIZB7QWENRBUGE4OHQMGQEYOBXF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B40734A57C8
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 08:33:38 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id z29-20020a62d11d000000b004c8f0d5dec9sf8728460pfg.4
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 23:33:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643700817; cv=pass;
        d=google.com; s=arc-20160816;
        b=m5X1v1+hXSFGbpckB4qDW8WuEUS7ENLkctnU0YShVVeoYXpTCVxm8Kv4eRa4KAVZZV
         kP8bQbXKZkMpUZkK0i6O+oTZb6I6+/+4BFhvkfz0YQk6XuFatvu39y9+dTSLzq2VH7A4
         3nudo7QqRcqsw09rPljdjNW6qDGHLfnrIVa9GitWaHhYy3WZ+cW3WrGN2jEb2AYKR6PM
         +s7jVYd93SO/ui2bXdZludBW3ZaMIazAWusHvLsSt0OI9pUmmkQc97rwwug0cHGYwWdY
         HyhsbW2r1hvYfWpYWwkec7VnkVQXxzNMv3kNxfK9+2uupisAoVwrzEbE4o7uMJnklYwO
         /1ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2FsuoMYe4KDVjLA/8FGPo1OKSAv5gtoXi8MIglDfGho=;
        b=o44/UAyh3GxCizOJQItrQqCLyK/2eNODReMBVMgdTo4uXDQRJ88yJ+3jVKA3IMjw2s
         AXlIdsp9SBfM7+EeOr9VolDID7TFdqD6aKmS8IsE/+UXICZCWdp5uX2Q3aXTXoEpFzxJ
         CN0YjQjM+2HD/5kcI0knc0kdHdo7JxNIStDNaTurpQ27PZ3r785HBfqgOASoLAAjfPoA
         FT2dfuACon4XpbJD+3aLRGFTMrKabNMiWTz2s9MT3swbMVj9wdrQm4VXWDtNsuGFgV6/
         /heqg5jTF2hN9LGcyyFFilKko9+1GmzljmzQLJLFAXXV2Tonq6bZHUGBTrC1JhgqJQRO
         2W1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=haoGVsVQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2FsuoMYe4KDVjLA/8FGPo1OKSAv5gtoXi8MIglDfGho=;
        b=BubY9aZQJvYfDWXjX0aJSj+zuekcyC+uflJWz3fNSMFA+XPJHWTYQGgkDK56kwKGej
         wEJc0pxqap10pXVZMa7h/NVVPzXMmeJpT/fyQTe7WSbJnqIA2QVUYz+CpIOAylOxPZ8K
         Rx6CxYyE/eLZLidhzAmSEgBL3Rqw163u9jLFkJ2hIykVuNx80k0QhT6GI8HRXCUxzXMq
         AuDC+RZzJpiUNBNjQiI6cTIHrOvSenah1XUWQgAcGjNB446CjqLQdgRbTAx19Ds+m/SP
         Z98mwvT2qKU3JuElU54Wg/LRwhXAX2IzASCjbU/tDHJP68IPMODKPHadDUlTHFmj9uHX
         8krQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2FsuoMYe4KDVjLA/8FGPo1OKSAv5gtoXi8MIglDfGho=;
        b=hC9EG1ur8SfF+bWc/WJ1ilthglvXrz6GENgBxdTYiXu6njfFAvzgEPHYCvNQbFPwsr
         Ww3YuW9aV/WtFZO7KLW5bjGlFdgxUys1gqRZj60yo5QixCzhBkQ0TeRLyzfo6dxOG0XC
         K7Z8c6KUhB0fBmaXNCuCilg2QeO/M716X+wKJ+bVVMuIgrbMhY0a48SRm5x/av70grkQ
         mt8hackX0PrFvTIZaCujs9+o10PNpuMwmC2z1M3swdYvRepa1hCUdd/bzIGvbar1rdzD
         5E1OJSHlachA95zu4dvremD2WVqOcTvZsh9l0ojvEaJYE73eSZop3v8AWRBxF1vNGrwa
         Uu+Q==
X-Gm-Message-State: AOAM531fViUI2YLuRZB8+zd4hSQcqyIXTENV9xWnzAIB57YSvficyTjd
	tXD3F2h822GrN5862DboOrE=
X-Google-Smtp-Source: ABdhPJw8uwnlON/fiEK7Bale1aKgjXG7feb4I0L/QB9MJpk059Ulc+3cbOhfyKpq8GCBwNc0HXXvdQ==
X-Received: by 2002:a05:6a00:8d2:: with SMTP id s18mr23353074pfu.5.1643700817099;
        Mon, 31 Jan 2022 23:33:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6d8d:: with SMTP id bc13ls6428184pgb.6.gmail; Mon, 31
 Jan 2022 23:33:36 -0800 (PST)
X-Received: by 2002:a05:6a00:2402:: with SMTP id z2mr21849940pfh.42.1643700816472;
        Mon, 31 Jan 2022 23:33:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643700816; cv=none;
        d=google.com; s=arc-20160816;
        b=J41lWy8unw62KLFi2Jl/sFYQkEL91BspIhp2ZhIjL8niaCoJdGsfixM01bSRcJey6c
         avgv7kP58m7XODkt9+JJ/jWWe5HdbdO0o/JGMiVibM+ZEzvCIo4X4aa8AkV2BJbvGTIH
         K8qPQQM5vbSXmmRzG/kYS0aZvJc1IaCATi1kmn2/Mbj62I4wY+iCRsIuQV06nr+aNNep
         lyz7kXuStptzMMyomN52ET8ItRY32ejjG1/cAyYdL0Dm2QCBRaIIny9SqiM/+43Hdw1D
         Buvbj/C//DF07VyVESvUgwP/vb9ewHAg3tXrCsEPCMWoK4itAbCYfJBVYTJjWOWugf/7
         Rg1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I8UdammtyVx5EZAt87tg0T0RNHOojMP8yJWvr7M56iQ=;
        b=cWYo5EQYxKS0LvaVS9Atr1+QXwYn32UeNo7tOUo/YE3+Jok0U3bIbpvtdDAuAj0oaR
         HfoWuKCFCwWeND19LUHTGzsAbqrbj9R3FBkImCQATonQvH/yGF/yRWoaxad6d3PHlP4T
         cdNcsFCRdGbna7peLW/Qa42tVhAoxrq9GX60tlucJsLgBORa9c0FgLf80DsCvLtdZGSQ
         Iq8iSXc1op1G/k5cC9pCi4pY98OYbf0CPKs/nvuTCY1dAmWm98oULCeSxGbNrT2+Q5r8
         zzPD38t/a1+hJVoh5XiB+mVaPMjgwOA77qcLfXcJC30X3t37oC43aifS7tP+qGuz48aC
         C97A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=haoGVsVQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id ck20si160982pjb.0.2022.01.31.23.33.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 23:33:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id u13so15454686oie.5
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 23:33:36 -0800 (PST)
X-Received: by 2002:a05:6808:1188:: with SMTP id j8mr395888oil.195.1643700815629;
 Mon, 31 Jan 2022 23:33:35 -0800 (PST)
MIME-Version: 1.0
References: <20220131103407.1971678-1-elver@google.com> <20220131103407.1971678-2-elver@google.com>
In-Reply-To: <20220131103407.1971678-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Feb 2022 08:33:24 +0100
Message-ID: <CACT4Y+b3cpG_L+UO=vvRtPdBh7Np5U4AA5_WuK7s7FUazuBvwQ@mail.gmail.com>
Subject: Re: [PATCH 2/3] selftests/perf_events: Test modification of perf_event_attr::sig_data
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=haoGVsVQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::230
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

On Mon, 31 Jan 2022 at 11:34, Marco Elver <elver@google.com> wrote:
>
> Test that PERF_EVENT_IOC_MODIFY_ATTRIBUTES correctly modifies
> perf_event_attr::sig_data as well.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
>  .../selftests/perf_events/sigtrap_threads.c     | 17 +++++++++--------
>  1 file changed, 9 insertions(+), 8 deletions(-)
>
> diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
> index 8e83cf91513a..6d849dc2bee0 100644
> --- a/tools/testing/selftests/perf_events/sigtrap_threads.c
> +++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
> @@ -44,9 +44,10 @@ static struct {
>  } ctx;
>
>  /* Unique value to check si_perf_data is correctly set from perf_event_attr::sig_data. */
> -#define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
> +#define TEST_SIG_DATA(addr, id) (~(unsigned long)(addr) + id)
>
> -static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
> +static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr,
> +                                             unsigned long id)
>  {
>         struct perf_event_attr attr = {
>                 .type           = PERF_TYPE_BREAKPOINT,
> @@ -60,7 +61,7 @@ static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
>                 .inherit_thread = 1, /* ... but only cloned with CLONE_THREAD. */
>                 .remove_on_exec = 1, /* Required by sigtrap. */
>                 .sigtrap        = 1, /* Request synchronous SIGTRAP on event. */
> -               .sig_data       = TEST_SIG_DATA(addr),
> +               .sig_data       = TEST_SIG_DATA(addr, id),
>         };
>         return attr;
>  }
> @@ -110,7 +111,7 @@ FIXTURE(sigtrap_threads)
>
>  FIXTURE_SETUP(sigtrap_threads)
>  {
> -       struct perf_event_attr attr = make_event_attr(false, &ctx.iterate_on);
> +       struct perf_event_attr attr = make_event_attr(false, &ctx.iterate_on, 0);
>         struct sigaction action = {};
>         int i;
>
> @@ -165,7 +166,7 @@ TEST_F(sigtrap_threads, enable_event)
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
>         EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
>
>         /* Check enabled for parent. */
>         ctx.iterate_on = 0;
> @@ -175,7 +176,7 @@ TEST_F(sigtrap_threads, enable_event)
>  /* Test that modification propagates to all inherited events. */
>  TEST_F(sigtrap_threads, modify_and_enable_event)
>  {
> -       struct perf_event_attr new_attr = make_event_attr(true, &ctx.iterate_on);
> +       struct perf_event_attr new_attr = make_event_attr(true, &ctx.iterate_on, 42);
>
>         EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &new_attr), 0);
>         run_test_threads(_metadata, self);
> @@ -184,7 +185,7 @@ TEST_F(sigtrap_threads, modify_and_enable_event)
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
>         EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 42));
>
>         /* Check enabled for parent. */
>         ctx.iterate_on = 0;
> @@ -204,7 +205,7 @@ TEST_F(sigtrap_threads, signal_stress)
>         EXPECT_EQ(ctx.tids_want_signal, 0);
>         EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
>         EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
> -       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
> +       EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
>  }
>
>  TEST_HARNESS_MAIN
> --
> 2.35.0.rc2.247.g8bbb082509-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb3cpG_L%2BUO%3DvvRtPdBh7Np5U4AA5_WuK7s7FUazuBvwQ%40mail.gmail.com.
