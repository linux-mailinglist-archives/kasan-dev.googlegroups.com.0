Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUXTWWLAMGQEDZDYQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id F0D93571B7D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:40:35 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id m12-20020ab0138c000000b003820c57eda7sf2173112uae.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:40:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657633235; cv=pass;
        d=google.com; s=arc-20160816;
        b=QhpN6oVj1J1SDGXStptoCv8XBlUlVVehY+iX51u3WYWvsF2rkcAtfejYdadotD6TlD
         OPbriDU+mJT6WcZ32zfaJXkBC1cffaWZplvcuUgEdJgsL3l2fSm3QNLdrgJpLqMJ1V7J
         Wm77C+u4gsxgzilz9Bax8FyQ0jTm6ergpRSGoO1j7jqlEiHD/2AE2zD+q2n+p7bNKER0
         JTB133Oq0PoJFwkymm9M07WPqA7UR6OdfMrWDhZI6KTm5qeeeyL5UUe1b9pFffldzX20
         tAeNKHIU4tm4qnRNZlnCVu/avUp6yyoSuuLYiDMIEHa1CogbaiE+VzMnlTP0V/diUf02
         jo0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3NiNvrVT5jtrwaMNv125tjM8K4HWZBFUd9ewKf22cN4=;
        b=scckk7iZ+E/G7BsbZhZrmzLpJaYuGF9CqvibCC5urqXIeiMB2Ab3+rkpxsYSIs0wIY
         h3yhrLvIbnMicPEGHVbn7FL2hjc63TPgECZ8Z6eisBTamQQHaIQMEugf4q2PLbTX3L/7
         00QJyPqJjKeG0a7HNQdeLA5iqWv43GbI2Pan/TFREdmJe2ecASJkUxWPQH/pSXPQdauC
         z067mbKTSQMPssMqgM5e51N2rBfjeb0YK2Z6/fcASUUalgCcHirDc4aByyzl3MtlmIwT
         8hhT18OD0KmgP0n1VYrz68k/jH3hyNo10inAFlxJn4mZzUjqQfCxTi/8G3M/Jf11nZhz
         Yzxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LSt+DLU3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3NiNvrVT5jtrwaMNv125tjM8K4HWZBFUd9ewKf22cN4=;
        b=BHN6BIK0Qz0VJ1l/THqyH5zfjOyoKxeeu4kAfmktUV+3tyDsFaMQDSp6LFtfq0QC39
         MJQsOwyx+gzU/tCmsADfAYK+wEAwDCuYLIRAB5gAJdmIMHhGQDP8fksujf03Moc4Kbzf
         qhEOjPrsrOUuocBbHQY5Rxakuo9R21mFDCxZLmMiMjwD4Zxv7HJLzG4yu7xc0y3xoJzz
         3C47pd10TczgPakgaIq4A3wbrhfYsEsgL7TzahfdZlmtitaybnsj06vcrFhzS/6uZSVq
         /SZO2sst06jZV54u6LrudHlJ3AFeX4VW2XnxGnFhKp8IN3hNsDqJdouCu5cbCifJxIrR
         Ljpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3NiNvrVT5jtrwaMNv125tjM8K4HWZBFUd9ewKf22cN4=;
        b=BfbLaovtCoHcz/ABVImwDWl0LUcXGe2qKuHsHlYVWr5wD3xIW/AZMEdrKF5bbug4Gx
         NJO/AXE4JTiS8R+am9S1wGqJvLeO8Sh3VLKmxp9Yg26ztTwG/icZmr9FrBZSbmU/00Z7
         uUDWf1A0TuYZ2FXwDTuT6T7Jy/YMuE2wpxVhp/h84FHaEmeSnzvXYzZZRt1fyUfi0k/r
         BuIVPIBASecqBzqMgDTkvB/2PduWkyYN1/kAMPr8mEEUbltsjdNlAN7bHYyRxtFYI4VR
         zaR8Hme6+AVhUQq6ywzpCK9RakuAwrSQbWbdNZexv9Bk3OokJKkPGohk7RoKVODQNw0/
         YRmg==
X-Gm-Message-State: AJIora8TerlP1IRtzOhQsp87iYHRaIFP4LrwJ2aMgS3Q2gO5r9uuauXT
	h4GKo2482DeLk0+Tgcbdm48=
X-Google-Smtp-Source: AGRyM1sh1WNFVrnysoTcaWCjqsjWjtlmMhkBG0Ig3m2B9Pe28/q7L0Zhw/zYde8jXE79P8SDciFymA==
X-Received: by 2002:a67:ec82:0:b0:357:52ad:a242 with SMTP id h2-20020a67ec82000000b0035752ada242mr4759972vsp.56.1657633234737;
        Tue, 12 Jul 2022 06:40:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2146:0:b0:378:f70b:cf8b with SMTP id t6-20020ab02146000000b00378f70bcf8bls170203ual.6.gmail;
 Tue, 12 Jul 2022 06:40:34 -0700 (PDT)
X-Received: by 2002:a9f:3245:0:b0:382:ecc2:e174 with SMTP id y5-20020a9f3245000000b00382ecc2e174mr7814429uad.38.1657633234143;
        Tue, 12 Jul 2022 06:40:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657633234; cv=none;
        d=google.com; s=arc-20160816;
        b=VQcPEKTXJjLerGMam8jcvPGXe3yqppM5vlzya86Zv3r4gsJ1nuPWyjzFnTWKtdG9KD
         A6tHQ2NGp4Tp2BghsJJYatLADFetif34EV+q4AjhfFXcy2u1rGceYp5jUW91JWY3ggya
         dkMniCNJh3/6FVh72CHrzrjI4ISLpwiNEwghsC26QOUrMsUGJxLt/+2sxSRRgfelV0Mk
         0Z9TVYmtRYGZBSMtR1gKNXHmlliII3Xy0vzjDhu/IjtoIp7bNWLSjMdfkJICmnOa+dHR
         bztUftSr+fGFpqAhonG01BS7kBjSYmWCkmt5XmIn4p4i6pVw6dgEu7SNlHgLwpWLNyEA
         v4WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ALyPmALyKUZN850RRfbsMebRjTXHId7O0aEtI7++nZc=;
        b=S+76jHfCAHhq3C4cHMRt+tcc0v/eNFbwZYJyYv8Bfj5ny3eL+iaHATsSMKOxK1YnOU
         qVbgW5p5QP/OLj64GwPj+1mjEKDgR//YYBmKRDK5/8AA4EXWsvT3c2u5lhfwlJ1MwGSH
         8U/gKb76u+VNXj7BOlhDU9STQ285N6mHcwoDLOzGHOw+rgZt9dnvoF3AbJs4c7m2Y9re
         aSyBx7NWpXMXMPXPPnFbjqbne6sMVrAEbHJsADjsPKgBRSD7dFIlgqCTpo1dNeBAXSLd
         8ariZMWVs/4upaTyWoSSKhHs2AEKsTHI84iR+fapNJdTPVcy4fV30FnTbkI+ig21IDMI
         OwHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LSt+DLU3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id g62-20020a1f2041000000b0037467483219si340468vkg.0.2022.07.12.06.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:40:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-31d7db3e6e5so50620767b3.11
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 06:40:34 -0700 (PDT)
X-Received: by 2002:a81:98d:0:b0:31c:921c:9783 with SMTP id
 135-20020a81098d000000b0031c921c9783mr25237173ywj.316.1657633233606; Tue, 12
 Jul 2022 06:40:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
In-Reply-To: <20220704150514.48816-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 15:39:57 +0200
Message-ID: <CANpmjNP0hPuhXmZmkX1ytCDh56LOAmxJjf7RyfxOvoaem=2d8Q@mail.gmail.com>
Subject: Re: [PATCH v3 00/14] perf/hw_breakpoint: Optimize for thousands of tasks
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LSt+DLU3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Mon, 4 Jul 2022 at 17:05, Marco Elver <elver@google.com> wrote:
>
> The hw_breakpoint subsystem's code has seen little change in over 10
> years. In that time, systems with >100s of CPUs have become common,
> along with improvements to the perf subsystem: using breakpoints on
> thousands of concurrent tasks should be a supported usecase.
[...]
> Marco Elver (14):
>   perf/hw_breakpoint: Add KUnit test for constraints accounting
>   perf/hw_breakpoint: Provide hw_breakpoint_is_used() and use in test
>   perf/hw_breakpoint: Clean up headers
>   perf/hw_breakpoint: Optimize list of per-task breakpoints
>   perf/hw_breakpoint: Mark data __ro_after_init
>   perf/hw_breakpoint: Optimize constant number of breakpoint slots
>   perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
>   perf/hw_breakpoint: Remove useless code related to flexible
>     breakpoints
>   powerpc/hw_breakpoint: Avoid relying on caller synchronization
>   locking/percpu-rwsem: Add percpu_is_write_locked() and
>     percpu_is_read_locked()
>   perf/hw_breakpoint: Reduce contention with large number of tasks
>   perf/hw_breakpoint: Introduce bp_slots_histogram
>   perf/hw_breakpoint: Optimize max_bp_pinned_slots() for CPU-independent
>     task targets
>   perf/hw_breakpoint: Optimize toggle_bp_slot() for CPU-independent task
>     targets
[...]

This is ready from our side, and given the silence, assume it's ready
to pick up and/or have a maintainer take a look. Since this is mostly
kernel/events, would -tip/perf/core be appropriate?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP0hPuhXmZmkX1ytCDh56LOAmxJjf7RyfxOvoaem%3D2d8Q%40mail.gmail.com.
