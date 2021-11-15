Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC4LZCGAMGQETSJC6UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CED944FEED
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:00:28 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id 17-20020a921911000000b00275824e5c5esf9921274ilz.12
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 23:00:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636959627; cv=pass;
        d=google.com; s=arc-20160816;
        b=a6cd17HRXgKJEnHs5nelOzGbReGETfQoAymoMBO6cl7EOBg88pXDMwh3A9+/2aXDLY
         q80RhV9baT8WtmGjhm3mHoD3DRsxULw4apQA/7YkVg46fmTRxGaZd2FXeLjc3vko6Cxb
         3vrJxb1lj5WWi0IEtiIbm1D34QEXHsbWRTgqP5jTziriMrUuE+yc24zutTbfPdnbqGTO
         Hvf7m9psVo63TctvWWHMdGx6lTLBXnCVrPaceg6D3PEb0P/EYwvRPYf1mj/gM3pzj1Ow
         EMfvbzr03cPGLv7EQhHu41F9NtMITYsrJ72Gygv83NSr6KqYxy4Sb4nLlAViUqTA3Qzq
         GihA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=K/vQq75CiZjoufiaT9qfESE1Fh9HWjrO9fTJ3eBxz0Q=;
        b=qtKTUMYiB+gXyVXL7Ac2Cx0KglaRxnExNLe0an9W1AkygqjG4la9uLaL1OCOJBls00
         OpnG3p0yO6/AlBloIShUvrWRZPVBb2nGHLcvZFpd3D/AfBbcYLZ/myyBaqkqVe4OtQMu
         gQGbHcaEmBCrC/RozcF7Ku9F5cGUzR8s184e3W069t6DxfhWw/nMTvnjQ1wzoXmaKoX2
         xGbvVsYTwNXY+SN9JAz1IAvy4JXBMmGkQ0vy1HgXszU48xo1G/7t/PvwIID14D5rmKmR
         lzkvp0X655BGT1vECR3u0yTcQZs/iYZ42MuksSnKoDfoaxIOx2N0cSjBYtriza0ceSJ8
         YnGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EM7CmmPr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K/vQq75CiZjoufiaT9qfESE1Fh9HWjrO9fTJ3eBxz0Q=;
        b=KN4PZmYd4taoGWFaxoCqKm70s5MSoDi2cG5H7ym/3j+5rHs2QDxf6wLtFlOqyk9xxz
         J2SCaITsFcIG+ikeasVA0GgwSvw3HU0ViJwLh1jTpvPZmRVvIZ6YCwQGBJfDi/GE/H9z
         o14HWC6T74/3f4Q6KbUc7y+ZkAxiOSqGyERy5/129HyGOcsNCoKUV92HEEA7COKxjP9M
         rYYvwcDHCP3bCqGWnFKRew7jk3Vvbvb2T+Chkl5eVuohkJq/3xbjYvFsakDjhR6EiIpi
         bbLr76QfcmRji+46P0Ib9fig70dv2QP7qsUrHHiHAXDbB30ivwSkdNWGa24RifqEnxV2
         79jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K/vQq75CiZjoufiaT9qfESE1Fh9HWjrO9fTJ3eBxz0Q=;
        b=zpAgN8CwJR5wbrvwA2RhdcyKVmanyxFMkwSkR75WLmIqxWJJGLqygXTeZvLQuw8KWn
         FZbAsunu5s/w+uVYVXXlyC/DLjUsTb+7946yjcHOJoM1N+hYX3mbxSileSHPQeiQ+OF2
         AIIsPtsdvzbppUDyjj7jEN/US3CPY/9zzEu018CsMyX5cMN3xIi5aoYtMQcg47kGKaBg
         BADApL1tIGlYs4o8B/jAhJCr5YhvKiuzluFN9ptpLmUbPLmifL0yhH+1dUmgHvVaQ6UE
         tzRN1NsnuUjCzNxRdqgOzAJME7sXhSR5l7ASvvyAOQJ0NlOwobIYenGlAGi3jBh7TTfl
         qJ3Q==
X-Gm-Message-State: AOAM531syUJSJ27wCEq2LhGrfImhT/8K0vNPTDVNAyQjyHO7EZuNO/R3
	SmTem7lZf4LGZ1aWs30l/8s=
X-Google-Smtp-Source: ABdhPJwe9Hjj73JEZYWkF4Qrz2z5x5/W370d0JyBAER2a3p4xuq74lTjiyIqw+xWrCp+k3jTSRDLbw==
X-Received: by 2002:a05:6e02:df1:: with SMTP id m17mr19825547ilj.125.1636959627318;
        Sun, 14 Nov 2021 23:00:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0f:: with SMTP id i15ls2215929ila.8.gmail; Sun,
 14 Nov 2021 23:00:27 -0800 (PST)
X-Received: by 2002:a05:6e02:c68:: with SMTP id f8mr21079188ilj.184.1636959626921;
        Sun, 14 Nov 2021 23:00:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636959626; cv=none;
        d=google.com; s=arc-20160816;
        b=ZMkc0ia1LX7I71kWn9gnPvfyAnpPEFBa7ZGmymKHxwVl1kyLnCKXU2zs6FiHXRPuq0
         weweh2A1k5yJGn7a3K9ygVnJFseZQT8J44Ybx6piSqxnFHvDNHkoS5S30Dc0eQBD3BGO
         Fi3O5JLLSizRW2tsoTPTkSpqMh7SWcOxMWX53eEY8C13zgaFMUnEDEsPX7K2Wc58yh08
         6btrMzFVcGXD4GanzmqQO2f6MlGI52Ea3U1BhZZ92E7VCjfzbL/0n6f0IJCc8f9D88ga
         n2KQzUbYK5ClQuPSctbvCbVCBpFiOqIwzCOO+vu3whZZFZ0ImOzwrVgG7Jgh+93bRHyv
         rb9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=//m9Q4+cuEgELvadHIoGYR2QVZ4qU+OxipLUtFZQsco=;
        b=wJDnYm8rxmPtYAkqG969R4Dw/gL5D6aFijr8ou19oFaCTrUvj8/rX2TuKbxaCpCYwO
         69Z1VJnTXD9OwExBEbVD0a1AjRdk6or3GRIJ7HIlC7RW7vhUUhDPxK2Pq1a7N5wNUdja
         8ZpzjQb+3AOrohvthpzRCRwdL8D+6T4a/915SiOINk8mB6NG0zzsIenRP/2Ail4R5BKA
         Zw1UaGQ90/vfDX8Txcxbwv6/fIBf8ENxEDHjSLr7tQVcpvUteKDuyYmtm5fum9+462Xb
         OZevsRNpFwlk/97soYoOM6lJpjiB3jReEco+F+0z11zuBkeAvc6XaSByyp8WTkKv8hK1
         cGvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EM7CmmPr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id o6si924105ilu.4.2021.11.14.23.00.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 14 Nov 2021 23:00:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id h19-20020a9d3e53000000b0056547b797b2so25003149otg.4
        for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 23:00:26 -0800 (PST)
X-Received: by 2002:a9d:7548:: with SMTP id b8mr28740314otl.92.1636959625057;
 Sun, 14 Nov 2021 23:00:25 -0800 (PST)
MIME-Version: 1.0
References: <20211112185203.280040-1-valentin.schneider@arm.com> <20211112185203.280040-3-valentin.schneider@arm.com>
In-Reply-To: <20211112185203.280040-3-valentin.schneider@arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Nov 2021 08:00:00 +0100
Message-ID: <CANpmjNMh=_oxuViL_WcTZX=UG6=QmFTuNOLYe6eNs84Rb8MTOA@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] preempt/dynamic: Introduce preemption model accessors
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EM7CmmPr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Fri, 12 Nov 2021 at 19:52, Valentin Schneider
<valentin.schneider@arm.com> wrote:
>
> CONFIG_PREEMPT{_NONE, _VOLUNTARY} designate either:
> o The build-time preemption model when !PREEMPT_DYNAMIC
> o The default boot-time preemption model when PREEMPT_DYNAMIC
>
> IOW, using those on PREEMPT_DYNAMIC kernels is meaningless - the actual
> model could have been set to something else by the "preempt=foo" cmdline
> parameter. Same problem applies to CONFIG_PREEMPTION.
>
> Introduce a set of helpers to determine the actual preemption model used by
> the live kernel.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>

Looks sane.

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/sched.h | 41 +++++++++++++++++++++++++++++++++++++++++
>  kernel/sched/core.c   | 12 ++++++++++++
>  2 files changed, 53 insertions(+)
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 5f8db54226af..e8e884ee6e8b 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -2073,6 +2073,47 @@ static inline void cond_resched_rcu(void)
>  #endif
>  }
>
> +#ifdef CONFIG_PREEMPT_DYNAMIC
> +
> +extern bool preempt_model_none(void);
> +extern bool preempt_model_voluntary(void);
> +extern bool preempt_model_full(void);
> +
> +#else
> +
> +static inline bool preempt_model_none(void)
> +{
> +       return IS_ENABLED(CONFIG_PREEMPT_NONE);
> +}
> +static inline bool preempt_model_voluntary(void)
> +{
> +       return IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY);
> +}
> +static inline bool preempt_model_full(void)
> +{
> +       return IS_ENABLED(CONFIG_PREEMPT);
> +}
> +
> +#endif
> +
> +static inline bool preempt_model_rt(void)
> +{
> +       return IS_ENABLED(CONFIG_PREEMPT_RT);
> +}
> +
> +/*
> + * Does the preemption model allow non-cooperative preemption?
> + *
> + * For !CONFIG_PREEMPT_DYNAMIC kernels this is an exact match with
> + * CONFIG_PREEMPTION; for CONFIG_PREEMPT_DYNAMIC this doesn't work as the
> + * kernel is *built* with CONFIG_PREEMPTION=y but may run with e.g. the
> + * PREEMPT_NONE model.
> + */
> +static inline bool preempt_model_preemptible(void)
> +{
> +       return preempt_model_full() || preempt_model_rt();
> +}
> +
>  /*
>   * Does a critical section need to be broken due to another
>   * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 97047aa7b6c2..e2502b8643b4 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -6638,6 +6638,18 @@ static void __init preempt_dynamic_init(void)
>         }
>  }
>
> +#define PREEMPT_MODEL_ACCESSOR(mode) \
> +       bool preempt_model_##mode(void)                                          \
> +       {                                                                        \
> +               WARN_ON_ONCE(preempt_dynamic_mode == preempt_dynamic_undefined); \
> +               return preempt_dynamic_mode == preempt_dynamic_##mode;           \
> +       }                                                                        \
> +       EXPORT_SYMBOL_GPL(preempt_model_##mode)
> +
> +PREEMPT_MODEL_ACCESSOR(none);
> +PREEMPT_MODEL_ACCESSOR(voluntary);
> +PREEMPT_MODEL_ACCESSOR(full);
> +
>  #else /* !CONFIG_PREEMPT_DYNAMIC */
>
>  static inline void preempt_dynamic_init(void) { }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMh%3D_oxuViL_WcTZX%3DUG6%3DQmFTuNOLYe6eNs84Rb8MTOA%40mail.gmail.com.
