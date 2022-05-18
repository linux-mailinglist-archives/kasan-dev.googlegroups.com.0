Return-Path: <kasan-dev+bncBCMIZB7QWENRBPXJSKKAMGQE5QP57CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C80C52B530
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:56:30 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id bj22-20020a0560001e1600b0020cccc6b25asf375130wrb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 01:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652864190; cv=pass;
        d=google.com; s=arc-20160816;
        b=LwXGR1dQCV/VUTlwhjgfle3+acJU7jWyTcAVduxQwlyUXXorp8g64GcdeU5JxF5n3K
         FLuv3IIcKinNvQwiS/w8+7/9SPk50jhdSTTfELZUlYBVmSvRHyzBUoGuyZ6ItOZPGk2z
         agb6y1AMOvd+ztE328MrqbDLGxZKV1soHJBsf2qL+1yRkd8ttOBV5qTQDIpWOvRFXpy4
         nz5MA/JaPaz8/eT4H9XLTRzOBtlTTwsJNLUB6U5x46AcUTouFGDFr3/ZhYl36Z9AROPS
         JqFtrLVBOIDBs/c8Gc5bv/tOad+BZv3WvhjvXWEymKd0GcrqycWQoMur2EXX8x84LOGJ
         qoxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yQzaHPyquGHrHIehgxoqeLqGmUUttFnEOo4vkex9TOo=;
        b=zSrVO4d1/Blxzo+fNfRW4044liFpUzVRc35RjEQduPhjYYe2MenNBZDgtt751Y5Y16
         87dWNDaSajY5hrp/LGZTZWyJ3CN0SLFC9yQM8IiGfzAA0p1KaT0aSDztPoRgY0kw9jUl
         NXXzBhzoXkEA16yzUhllnIOM3kwP1cmfy9S6uzoYbU+3RD7RxFC883kmIdC/Bk/4nA/r
         S6kMGN9vHL+KUm72OS4A+m3V5TiJZNP0wvgb4WBPxP32GqTxNaiba3AD60rTAwvsk8ym
         vuCWABcx/PEk5L44vHBDCgSBMlXmebOJbVZd8dBxdUsevegQSXE7zvKW7sDgOTm1sOzE
         sEeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nmd6m7vK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yQzaHPyquGHrHIehgxoqeLqGmUUttFnEOo4vkex9TOo=;
        b=JYbpxpBeXo+zlxgL9P8VAZATIW7HL0nQaOJevsMw0wHOCSSv8RYOxnldcG5YG16bM8
         alM7DQjVfzmWZelk1tlmvCYl2psgqRlSxWU5HOXp0sH1zhQklQQurQE5xPWc6KsmmEx5
         0wmUfthPYOBVWv4WrCXDVVDv4fiDu+yB+/v/Ai7aUC8ou876wCYisLizb5BnQ+pU/5mU
         YdbVvF6Enq16Z9Nb2+dv0poQrvvhGnAuqa3/Nt/kX7ZDCgLa3XPVhR+5wLpvfGfGmew/
         iF74x7Kbr0TA68rQ9s4IBe3ijDT9A2VXJUE5lDBksNilHUka2A3X4IpxgmSPjrFCaazs
         d+Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yQzaHPyquGHrHIehgxoqeLqGmUUttFnEOo4vkex9TOo=;
        b=6IwJJ/OBXhWLg4aK+UI96kr4rJbrUtY5nylfb10RfWk35Sn9Vv/bFbOLIxflwkKwHM
         SK63P7RSqkd/r7MCbKd18qrDhNKgPA9+xjx873QRpp5+p6Lo+ZnqHJAJoJufFlLiXAa7
         Z0kWruv1/1w/pGYIuClKgYBuC3jWQocZ0Bqfzq5onliN7AMKuAVmIPg18ZsLm2YYDuSC
         nbiD4/nfjoninEyLPJO+tM+rcDUxvLQTY/x2pmjytSZcHIDgkrkAj9ilFttPC9wBYAzC
         lmJ9J0KZRtWO1pA5nst1hUvx7OTUhBkFanVbSiLvnRVUeBBh9FhHfwYqMDzTGLAiqI9A
         aing==
X-Gm-Message-State: AOAM533RAgymapO7X+0fGshJXLRgMZ+56vYg4fpJ9jO3weWheM4uyLoD
	mvkAxRJXbSMkrVbgGwv+lEA=
X-Google-Smtp-Source: ABdhPJyhCQla6eyI7mOOaVfG44R+SJ+W+C8DpXLzHM48jQ9PG4KBxspgXXkGN8FjE0ZiboP1O8fSew==
X-Received: by 2002:a05:600c:4e05:b0:394:8955:839a with SMTP id b5-20020a05600c4e0500b003948955839amr24784969wmq.28.1652864190298;
        Wed, 18 May 2022 01:56:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1688:b0:20c:67b9:e68b with SMTP id
 y8-20020a056000168800b0020c67b9e68bls6619323wrd.3.gmail; Wed, 18 May 2022
 01:56:29 -0700 (PDT)
X-Received: by 2002:a05:6000:18a4:b0:20c:5603:c0bf with SMTP id b4-20020a05600018a400b0020c5603c0bfmr21589034wri.145.1652864189282;
        Wed, 18 May 2022 01:56:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652864189; cv=none;
        d=google.com; s=arc-20160816;
        b=C0/VHVMMHzNXFmm76gr1/foUZD3K4/9jv03v1jtg5mOJYx5McyHCB7cylTS3FdED7Q
         kRNLti9sUie6owLfco0xIfIy2s16ryXjeOS4p9QwsOpR+t+0KmdCzJUknQL+KZvDZmnl
         qDzkGF4MkDDePG+AIAw6kXBC2qL7usGtOcZHeKQMEQxHB5P5KC6P2RwPk3kSO7CLE2tF
         VEF4Cpz4qEpnvm/UnWN1B5ByBWeTH75pj2mKdYqrGEe6IXRyt3HIzpB9poHH4dqTrzJr
         cHE8xNHCaTdbRAbaHQU81bTn2AzflhTBrVd5Be0M8CkqnlQ9U7oMoojMr6B0OiLUNMOt
         eveA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MUKJ8QRlQSCBTIhaVerC8fhj0gKK+rHwygeAwjxNYCY=;
        b=RCfc4JvRYsF9kae7HJ1BkHaSjUDuTXFOljPvcZVBzVyCHHz3PAU3iNazM0Fl1h7S2r
         t9tytxaACLxgYa7XGLi7QgECk5w5WIXLHOAVRCvj/Mf9tu7HYd/O34+Kn5U1iv9GE+Ho
         EjfJ8jVK5RgZDW9fS6n1fu4OQ9JPo112nK8r3FKVh2Eu9Tozb2ljUOQ4BVVsv8qdfZZx
         0zCZgZKEgmSG4ZgaTKmeXi1pnxYJhpYwebszhAw0wcB3Bz3Xhes0MLuQVeYzZ8rfVZeI
         /xezyvqrqD02MpwEohU8/Qnf3Q6/UlfYyaIaO4QhtmGGLKifBfMKyvxZUXtwLtEhg7yf
         7UIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nmd6m7vK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id v17-20020a05600c215100b0038e70fa4e56si302917wml.3.2022.05.18.01.56.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 01:56:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id f4so2372614lfu.12
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 01:56:29 -0700 (PDT)
X-Received: by 2002:a05:6512:696:b0:473:a6ef:175d with SMTP id
 t22-20020a056512069600b00473a6ef175dmr19713174lfe.540.1652864188483; Wed, 18
 May 2022 01:56:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220517210532.1506591-1-liu3101@purdue.edu>
In-Reply-To: <20220517210532.1506591-1-liu3101@purdue.edu>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 10:56:17 +0200
Message-ID: <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
To: Congyu Liu <liu3101@purdue.edu>
Cc: andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Nmd6m7vK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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

On Tue, 17 May 2022 at 23:05, Congyu Liu <liu3101@purdue.edu> wrote:
>
> Some code runs in interrupts cannot be blocked by `in_task()` check.
> In some unfortunate interleavings, such interrupt is raised during
> serializing trace data and the incoming nested trace functionn could
> lead to loss of previous trace data. For instance, in
> `__sanitizer_cov_trace_pc`, if such interrupt is raised between
> `area[pos] = ip;` and `WRITE_ONCE(area[0], pos);`, then trace data in
> `area[pos]` could be replaced.
>
> The fix is done by adding a flag indicating if the trace buffer is being
> updated. No modification to trace buffer is allowed when the flag is set.

Hi Congyu,

What is that interrupt code? What interrupts PCs do you see in the trace.
I would assume such early interrupt code should be in asm and/or not
instrumented. The presence of instrumented traced interrupt code is
problematic for other reasons (add random stray coverage to the
trace). So if we make it not traced, it would resolve both problems at
once and without the fast path overhead that this change adds.


> Signed-off-by: Congyu Liu <liu3101@purdue.edu>
> ---
>  include/linux/sched.h |  3 +++
>  kernel/kcov.c         | 16 ++++++++++++++++
>  2 files changed, 19 insertions(+)
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index a8911b1f35aa..d06cedd9595f 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1408,6 +1408,9 @@ struct task_struct {
>
>         /* Collect coverage from softirq context: */
>         unsigned int                    kcov_softirq;
> +
> +       /* Flag of if KCOV area is being written: */
> +       bool                            kcov_writing;
>  #endif
>
>  #ifdef CONFIG_MEMCG
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index b3732b210593..a595a8ad5d8a 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
>          */
>         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
>                 return false;
> +       if (READ_ONCE(t->kcov_writing))
> +               return false;
>         mode = READ_ONCE(t->kcov_mode);
>         /*
>          * There is some code that runs in interrupts but for which
> @@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
>                 return;
>
>         area = t->kcov_area;
> +
> +       /* Prevent race from unblocked interrupt. */
> +       WRITE_ONCE(t->kcov_writing, true);
> +       barrier();
> +
>         /* The first 64-bit word is the number of subsequent PCs. */
>         pos = READ_ONCE(area[0]) + 1;
>         if (likely(pos < t->kcov_size)) {
>                 area[pos] = ip;
>                 WRITE_ONCE(area[0], pos);
>         }
> +       barrier();
> +       WRITE_ONCE(t->kcov_writing, false);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>
> @@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         area = (u64 *)t->kcov_area;
>         max_pos = t->kcov_size * sizeof(unsigned long);
>
> +       /* Prevent race from unblocked interrupt. */
> +       WRITE_ONCE(t->kcov_writing, true);
> +       barrier();
> +
>         count = READ_ONCE(area[0]);
>
>         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
> @@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>                 area[start_index + 3] = ip;
>                 WRITE_ONCE(area[0], count + 1);
>         }
> +       barrier();
> +       WRITE_ONCE(t->kcov_writing, false);
>  }
>
>  void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> @@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>         t->kcov_size = size;
>         t->kcov_area = area;
>         t->kcov_sequence = sequence;
> +       t->kcov_writing = false;
>         /* See comment in check_kcov_mode(). */
>         barrier();
>         WRITE_ONCE(t->kcov_mode, mode);
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2BHtUttrd%2BbtEWLj5Nut4Gv%2B%2BgzCOL3aDjvRTNtMDEvg%40mail.gmail.com.
