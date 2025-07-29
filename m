Return-Path: <kasan-dev+bncBCMIZB7QWENRBDOZULCAMGQE3LXMZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E387B14CC8
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:12:15 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32b500a9a28sf20366061fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:12:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753787534; cv=pass;
        d=google.com; s=arc-20240605;
        b=k/Re9WnHB8omhfEYhsCTXtuwrsGEQp8is1N1QD22mO26z7rDPiILzocH3f8hrvJfBP
         bg+gEH4olGX0VrVg7T2arL123m/jAEqMxeglR68CR3hFqqk+Nl7QhNnrOhfZFNM9zJRS
         mo+tBFQIJG+4ao/KEiQ9saVqUjQOgYqCNQPkQ6+U2Ah1L7QQmeJTakAnHvhdwiJBslF7
         7wuZB9kBoSHVXenw0+Ymlkl00zVe9nLyBLQ/x6gqIi0R7aSoI0n0l3onjbqyhK1MLm3f
         PF2hFt9a395mqXJDzlEDCxifkEOaEjMQozo1IFukWRAjjL+S1Bc2Fzc+3B37ymfs54AK
         tUog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RW9ATq34TXGY2e57AYbGVRPnrnFXAtM5C0B1SuOSiw8=;
        fh=fI8xf+4vYs4XptFo/CbcYDyjTxOPT1Gf4LivP/iLbQc=;
        b=RsMgo5622z3nlXBLo8UJSZjKfZAB0IQ5N+eDsIs97flZVBFrSt4pRME/evVcbF6jjc
         VxzrxXvAKFz8oFFA+/LkrwGh5oMomF8uOBfiuSOxdIfxzYmkEWmLmhHAMPoQ1C3UFu9J
         QbmYcjz45mHP618qInDjwzSPChAQlF72YTNsX14z8F4Njikrs+YhAMfFEARKpmoqmc3e
         mFvjrO4tgd3bLfYpJzb2vHt4AnJnwePcGeg9WrJR/JlH6fETDw2sTC3nfcHPmL0XnlDi
         AfOG1bh6g2F0wgM3sIxIzeYMtU4HfrwNNayczco5LU+2IvDXd7bdnGH+PMVLBvawD5gD
         /TOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ugchyYK1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753787534; x=1754392334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RW9ATq34TXGY2e57AYbGVRPnrnFXAtM5C0B1SuOSiw8=;
        b=T7xDkBCnd3H3Tl+paWJ9U3uVgotcjrdEkO2mRTlu3oI0prmWoAmyosTg3nHSQGbSWG
         SbP9yYftqcVdyvFk/eYLnD1qiD0hP5pCMRh+U+ADCQ8vjIQcVRSk/eRa8x3FTZv2G/+g
         NG7Z3GPjWZJ9HWj5vzVE636PMD+F11M+mgbwp/cg9YHlOhPTD56HMSAfta+IoFy+UxU9
         VajNkzhOOwEPnIU+pxy24otPPHlLG5WncT5FR7K369fP73bs+oB4Gwixl/lOpV+lTlXe
         SRKStueL1PvnBqjcT51e0Lwh9+TFIvMQ9QYf4u60S54ER05t1cJlEbJJYVNi3jXRmtGr
         Lb0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753787534; x=1754392334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RW9ATq34TXGY2e57AYbGVRPnrnFXAtM5C0B1SuOSiw8=;
        b=fgRP0uELU9TyZzVrWCNGtcezRQ5jsv4LYUaQE7VqhR3WfAsphWe2sIvlueRqOzPIOD
         9NalGnBm6lkdi9SI5JYjnuM1cyyb2IgJD+uad2x2c6ATNkgh0Xt/VS6p953cB2dsnj0W
         DUM9cshfkZywxDwRu+85rzXEz2SgO1k7KWHYIcSpur/IEYJhbrG/d6lAmt5WHxzs0JC5
         I9YyKQha6pRNr3Hq8rhCd3fbMPSG03HNAWzawmeU1UtQQeFPlD9zbtFEiAcYhh4yag0Z
         AY2vsezKV5JB0a75dRn+KA7ZHgM+BuLt7rDW0iWOOMy7a7tGWb5Ii3Cj2tM26cCVA09Y
         0cfg==
X-Forwarded-Encrypted: i=2; AJvYcCXvfm8mEJ7kdikAOGvgqA9kcH+Re04zLZiVmGJWN+u4vqRY1QDh2wJN4G5cmVjMdDmqo+bq7g==@lfdr.de
X-Gm-Message-State: AOJu0Yz5z4RXMEp0WXPke/wyBqu/ZmmQb79VrSQyHfPSEX8XcVYziCXo
	CwOH2WoCiplPGRfshpXijfyLAXyvlHN7ST1XImyg6D7c6v42TIEZlyXX
X-Google-Smtp-Source: AGHT+IE8VPsBMxFMew4QJBNkmjN/74Niy9Om8W8/ocGUs/jc4uxJU+nM5fMGpkESR8aSGZ+neFVsgQ==
X-Received: by 2002:a2e:9a04:0:b0:32c:abf4:d486 with SMTP id 38308e7fff4ca-331ee692563mr34792301fa.14.1753787534095;
        Tue, 29 Jul 2025 04:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcOPL14HBLkicp17T8pXzB5vRIE5fdgbHQw+lNQvCGUSw==
Received: by 2002:a05:651c:4118:b0:331:e79f:46a0 with SMTP id
 38308e7fff4ca-331e79f4864ls4925721fa.2.-pod-prod-05-eu; Tue, 29 Jul 2025
 04:12:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYof6iSRTIDMnlUYlAy7rBMWKDuCv/NPyfGoqgRdcO2dErIPM27cojd2kDEDRKaskCkH1IvKCfKd0=@googlegroups.com
X-Received: by 2002:a2e:b890:0:b0:32f:425b:3278 with SMTP id 38308e7fff4ca-331ee74c97fmr45246261fa.25.1753787530823;
        Tue, 29 Jul 2025 04:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753787530; cv=none;
        d=google.com; s=arc-20240605;
        b=U42GyaDarcMA+dzSUAjIDeLkbMGsQeGyc7lKba90FDZgc3qjce24w4Hxw+NkkuL85o
         iEcF1sK4olfX9hsj2XQbEwOAO9Cot39ttMxWMm6FJTMSxji6uPZ5kmxsk3b/DJjoxYTS
         TM9ho9AaXpUw/FzzmsYk0+Ii265NmJbhBZLnezdfJ19Nwr9Kk4w+n1im2nRwySDrFuCF
         sKAfrwwoCo5LKJXdn0h8O8zZghTpALWcOW6MdlvFGKrPgc5iWbFWGJXhj1eK8ZH32O3l
         WS3GfjXKDn3W9wT86hJRS24rr+h/KD0h9qGApFPQyb4zEvctiEWsP4MbmlpJVm1AEooD
         mgag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/5LXLgdNoFY7nm3djrI3De1oD1rZPUM1dBdXIbzK2TE=;
        fh=VQj91ZMqRMGY4/j4kuh4+zst3drrRfp7W3WXcLnAyIM=;
        b=BvNcx3ibVuUywkPq7ho9zjbl+zcWdn/+nOkLFnAGYpl5bUDDe2IhUwHdbQBOF7/J0P
         5pW5CRD1jpeom+HbJ9eRd89MUYfJhVq0Nbw4E/iNePKXPGga52achhoRYnySwy3XgaJf
         wJHmjcw62TzdikGIMIQ2qVE4Q4+Uk9voE9C7Lj2NsedmeCc0pOOQALfgW7VsM01J5PRL
         RVbJroOqlbChk6kusIQ2Vj44phuLCfKSTXA2/dbrTL0liC1rPbBd255C0mbMIV7nzXo2
         YSA9R9yOHUUtsR0Njthjrbc6386hfRQrCDmv1dr3QrBz4ms6i7jHw5SGJcpMiAsaCgNs
         sjIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ugchyYK1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f420ffa7si2253821fa.7.2025.07.29.04.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-32b7123edb9so71435601fa.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:12:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZLZsyyCyWUF8AVNY4udBBu9a1WR3TQspm827G0wrn50/7wkEesysmZNYnsNpqq1wkqUVOzRDGA4c=@googlegroups.com
X-Gm-Gg: ASbGnctAvfVUn+KAHj/2dIwmvk9Sh/LMEqwUFyLN3d/fEH1XqgQdly7zs0TTzPq4ad4
	+PFosPNc5fdVs9YT2+ey68Bej3DuaDbNK6JFi/4JeGybNI5oPh+87tR0h4JxU9QADcNa3HhWxif
	kIsem3GM8gc92V6zRpUziZ+2bLuftAFmPlpihYVejg5in3JaeDut/e/Lr3EdjguHLx5BChnTeSp
	kMhB0xPjJmvYwSV6AUujsAGI4+743UitdWEtQ==
X-Received: by 2002:a05:651c:1107:20b0:32c:a006:29d3 with SMTP id
 38308e7fff4ca-331ee66d357mr27919651fa.10.1753787530153; Tue, 29 Jul 2025
 04:12:10 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-7-glider@google.com>
In-Reply-To: <20250728152548.3969143-7-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:11:58 +0200
X-Gm-Features: Ac12FXywcPyU53mFZ7Bl6gOazcF0D4j2xnZWgO3CWGRVf7fcxWsyg-cMguQJbC4
Message-ID: <CACT4Y+Ymd=7zQ-AYhEx93DpBZ89jVbdUM0pbN+2vPaiwKg-sdA@mail.gmail.com>
Subject: Re: [PATCH v3 06/10] kcov: add trace and trace_size to struct kcov_state
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ugchyYK1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> Keep kcov_state.area as the pointer to the memory buffer used by
> kcov and shared with the userspace. Store the pointer to the trace
> (part of the buffer holding sequential events) separately, as we will
> be splitting that buffer in multiple parts.
> No functional changes so far.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v3:
>  - Fix a warning detected by the kernel test robot <lkp@intel.com>
>  - Address comments by Dmitry Vyukov:
>    - s/kcov/KCOV/
>    - fix struct initialization style
>
> v2:
>  - Address comments by Dmitry Vyukov:
>    - tweak commit description
>  - Address comments by Marco Elver:
>    - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
>  - Update code to match the new description of struct kcov_state
>
> Change-Id: I50b5589ef0e0b6726aa0579334093c648f76790a
> ---
>  include/linux/kcov_types.h |  9 ++++++-
>  kernel/kcov.c              | 48 +++++++++++++++++++++-----------------
>  2 files changed, 35 insertions(+), 22 deletions(-)
>
> diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
> index 53b25b6f0addd..9d38a2020b099 100644
> --- a/include/linux/kcov_types.h
> +++ b/include/linux/kcov_types.h
> @@ -7,9 +7,16 @@
>  struct kcov_state {
>         /* Size of the area (in long's). */
>         unsigned int size;
> +       /*
> +        * Pointer to user-provided memory used by KCOV. This memory may
> +        * contain multiple buffers.
> +        */
> +       void *area;
>
> +       /* Size of the trace (in long's). */
> +       unsigned int trace_size;
>         /* Buffer for coverage collection, shared with the userspace. */
> -       void *area;
> +       unsigned long *trace;
>
>         /*
>          * KCOV sequence number: incremented each time kcov is reenabled, used
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 8154ac1c1622e..2005fc7f578ee 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -194,11 +194,11 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>         return ip;
>  }
>
> -static notrace void kcov_append_to_buffer(unsigned long *area, int size,
> +static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
>                                           unsigned long ip)
>  {
>         /* The first 64-bit word is the number of subsequent PCs. */
> -       unsigned long pos = READ_ONCE(area[0]) + 1;
> +       unsigned long pos = READ_ONCE(trace[0]) + 1;
>
>         if (likely(pos < size)) {
>                 /*
> @@ -208,9 +208,9 @@ static notrace void kcov_append_to_buffer(unsigned long *area, int size,
>                  * overitten by the recursive __sanitizer_cov_trace_pc().
>                  * Update pos before writing pc to avoid such interleaving.
>                  */
> -               WRITE_ONCE(area[0], pos);
> +               WRITE_ONCE(trace[0], pos);
>                 barrier();
> -               area[pos] = ip;
> +               trace[pos] = ip;
>         }
>  }
>
> @@ -224,8 +224,8 @@ void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
>                 return;
>
> -       kcov_append_to_buffer(current->kcov_state.area,
> -                             current->kcov_state.size,
> +       kcov_append_to_buffer(current->kcov_state.trace,
> +                             current->kcov_state.trace_size,
>                               canonicalize_ip(_RET_IP_));
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
> @@ -241,8 +241,8 @@ void notrace __sanitizer_cov_trace_pc(void)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
>                 return;
>
> -       kcov_append_to_buffer(current->kcov_state.area,
> -                             current->kcov_state.size,
> +       kcov_append_to_buffer(current->kcov_state.trace,
> +                             current->kcov_state.trace_size,
>                               canonicalize_ip(_RET_IP_));
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> @@ -251,9 +251,9 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
>  static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>  {
> -       struct task_struct *t;
> -       u64 *area;
>         u64 count, start_index, end_pos, max_pos;
> +       struct task_struct *t;
> +       u64 *trace;
>
>         t = current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> @@ -265,22 +265,22 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>          * We write all comparison arguments and types as u64.
>          * The buffer was allocated for t->kcov_state.size unsigned longs.
>          */
> -       area = (u64 *)t->kcov_state.area;
> +       trace = (u64 *)t->kcov_state.trace;
>         max_pos = t->kcov_state.size * sizeof(unsigned long);
>
> -       count = READ_ONCE(area[0]);
> +       count = READ_ONCE(trace[0]);
>
>         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
>                 /* See comment in kcov_append_to_buffer(). */
> -               WRITE_ONCE(area[0], count + 1);
> +               WRITE_ONCE(trace[0], count + 1);
>                 barrier();
> -               area[start_index] = type;
> -               area[start_index + 1] = arg1;
> -               area[start_index + 2] = arg2;
> -               area[start_index + 3] = ip;
> +               trace[start_index] = type;
> +               trace[start_index + 1] = arg1;
> +               trace[start_index + 2] = arg2;
> +               trace[start_index + 3] = ip;
>         }
>  }
>
> @@ -381,11 +381,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>
>  static void kcov_stop(struct task_struct *t)
>  {
> +       int saved_sequence = t->kcov_state.sequence;
> +
>         WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
>         barrier();
>         t->kcov = NULL;
> -       t->kcov_state.size = 0;
> -       t->kcov_state.area = NULL;
> +       t->kcov_state = (typeof(t->kcov_state)){};
> +       t->kcov_state.sequence = saved_sequence;
>  }
>
>  static void kcov_task_reset(struct task_struct *t)
> @@ -734,6 +736,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                 }
>                 kcov->state.area = area;
>                 kcov->state.size = size;
> +               kcov->state.trace = area;
> +               kcov->state.trace_size = size;
>                 kcov->mode = KCOV_MODE_INIT;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
>                 return 0;
> @@ -925,10 +929,12 @@ void kcov_remote_start(u64 handle)
>                 local_lock_irqsave(&kcov_percpu_data.lock, flags);
>         }
>
> -       /* Reset coverage size. */
> -       *(u64 *)area = 0;
>         state.area = area;
>         state.size = size;
> +       state.trace = area;
> +       state.trace_size = size;
> +       /* Reset coverage size. */
> +       state.trace[0] = 0;
>
>         if (in_serving_softirq()) {
>                 kcov_remote_softirq_start(t);
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYmd%3D7zQ-AYhEx93DpBZ89jVbdUM0pbN%2B2vPaiwKg-sdA%40mail.gmail.com.
