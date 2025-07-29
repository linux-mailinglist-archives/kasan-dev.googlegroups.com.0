Return-Path: <kasan-dev+bncBCMIZB7QWENRBY63ULCAMGQEU4PJKFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 34CA7B14CE2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:17:57 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3b7891afb31sf1439824f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:17:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753787876; cv=pass;
        d=google.com; s=arc-20240605;
        b=FrbTHWsISXxTKsaEbtCXbNE+cFnIJ9ABgAgnb5JJ8tgwkyap4CxXoJBUAxgA0SYbg+
         7n0iSnC9eshGlixWTh9KVwUaXnNNifbcZx6YCFthae98mdaZFJMI4C3kRfLX31he7/i7
         8xqMdZ+e6XWJ2fBMp5s2T2zgIX/s66mdo5GnY9NVvY0aJuCmf5dppyekV56JOaTBH6iM
         hXWZDAcT0/lyTVW1KFc3qipJ0nlU2f0ZWmDXo2m25ziNfvvEDOdfff3MSYZdCNUY5MMi
         zniqv1B4BDv1c+yofyIDgAoaRLsrvUff2AyhaTaG6I8V53r2UEJn9uspHGpeEoPFcCIX
         OVAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hSbnGeiIDDktVycLk7wEAJG+8vE+0mmkVEMLQFrKedM=;
        fh=nMGPbHLFAO4WbzJyifzva2kPd1eLrfhonVnQVqwq6Mo=;
        b=LHUYAQlzgTZUDk9CgJbIuRcC25kvNw7zQ9aGjOvzfN67EhQF4BfU4cdJsFov7EGvuR
         WtUcN7CkxEqsz2lj63QCOdngRzlqLpWtppmy7KTvmS1vHQClvm4xUUtC5j5Wyog7n1hh
         nRAmGs9sI6j6zodCwldo3v71jGpINunckyJp+ignwbinGRPWPKwsf4zaEBjUKVrdzamj
         R0OR5IYTP5+5rtNpiVx3WmO7JYexVK0KN94WFL5PnBV79DPFTeKoQfKxjNlA83oj1Iq/
         Lc5JS36sfY5SzyiYIaoVQAoOgpP+avVnvbOkoMywYcQi+HJhPQ3/DjEX/lSxJc8nylah
         q2Hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3fGXSgNb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753787876; x=1754392676; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hSbnGeiIDDktVycLk7wEAJG+8vE+0mmkVEMLQFrKedM=;
        b=RNiZ57oJuRyBAu7ZE3LmJmnkrk9IsAny0hs6Vf48yFh/uoIsSpQLutC1uIBUpwFTxC
         UJoTpJNjpALUwPzSe15fVJzemdWmItazjDFmlVel5MsRcYRYXiPrN/WTco0dqSkk9UnH
         2H+6MENOSXQO+F32ohPwFt/Gd4TWmnJmJw2MMTT0tmX4PaRyGDdg4vOYNs7zk2coerSg
         nKHumCQY67VX2E5mHWrS0tOOp+TpcJoZQhAZOi+OZO8Hz4n+46q1n3wp2rSTz/99FLFY
         o4Bmv8YAmvmPXEEIQkWlBbXaE7jKnlTMBl0wOIUBtQCWoM6yCFh35G2RMgSr5Ji3QQ6U
         /0lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753787876; x=1754392676;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hSbnGeiIDDktVycLk7wEAJG+8vE+0mmkVEMLQFrKedM=;
        b=W5SbyQKAcoFRgEDHAA906/EeQWpNwfaKeFHQiSiYV048nyYETctZIatoGcEhjrgrMb
         JF6lN9CYwl/KiJAeWyAl808XP7bkkTO14+kdn0FgeGJ1++WsgMgczxAGGk8X5yjZWIi/
         lwrTpswjmZEZd26Ovyasb1P3VaBQVsJOYxVF4YFmo/pMfrctYJ+7CxK5Um85oyZIhHDh
         iZk2h7sZUakezhmhsJqpsghoNTGxp31flOkNzl/kwu41Vxs/tjBwPkbk0LPw1A4vmMrL
         FjMySSE/Qcpg8przbQpR+YwOR0gBfwIuA2uMd+NQt+MpuV/dgDtxntEo6lO4627WPBQa
         IJmw==
X-Forwarded-Encrypted: i=2; AJvYcCVlu5yS1qjkKNfp0o/OsVucBPh180tJlZGH2EeIopxitP8tMv+Xy/fKHoDQztOjuo0eZcetBw==@lfdr.de
X-Gm-Message-State: AOJu0YwK2IL6WC4E9ph7+ikEOyB/+zXKwnABJyjURvMiRqcj3JwSvf1L
	WB4E87s83Ui4xs4++79EQ+Is5hmKdoOMgWg4CY7prtUdffWBEIOPe4P2
X-Google-Smtp-Source: AGHT+IGxiCHL2LwD/KBEtNQC4C8mbmKY0dFbCNmuwm+PMROe9+a3M3XtxrbLbazKSSQu+gcXyzkYoQ==
X-Received: by 2002:a05:6000:2f83:b0:3b7:901c:92ee with SMTP id ffacd0b85a97d-3b7901c9628mr1311312f8f.58.1753787876463;
        Tue, 29 Jul 2025 04:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbOJm/lY+C7DuCAPHj0KAzDs/ORBV0WgRzh0jAnAxEXA==
Received: by 2002:a05:600c:1c9c:b0:456:7cf:5289 with SMTP id
 5b1f17b1804b1-4586e8a5750ls28537525e9.2.-pod-prod-09-eu; Tue, 29 Jul 2025
 04:17:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgP3CgyWXN6WtP6OXnxAUCCAuBvqbNRh2gFjlP2W1B3kBwh36NlBkLCtV00zj8muuupt0GIgwtbmY=@googlegroups.com
X-Received: by 2002:a05:600c:6306:b0:456:2cd9:fc41 with SMTP id 5b1f17b1804b1-45876547e82mr114307055e9.20.1753787873825;
        Tue, 29 Jul 2025 04:17:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753787873; cv=none;
        d=google.com; s=arc-20240605;
        b=l16nBnpNllV/lqGsh9SCwp35hipiuUGP8j5W8PeRee5SgURVYOypWqs1nrUa5b+09L
         MpysY0gqjAr69dRW3Y3EtGWhJpPyFgkku2cZ1DfrmeCJCngEfNeKyHAbq88XIMa/1x6l
         KXC17mc1lZf2HXgRI1VnRTMFubm89VRJR3cGQFyN9p1k+kQlN2nv2ywkl2xRQE41EkbW
         k8debrVpOzvnUi1UvUTrIYZbhCSCCx43G09RpvvTO/ClObrgVoDNO82v9cl5br+0VCNt
         vG0rkWuLaBW8nyqvQ0kFC+B2jTpIQjGV5IGafnHWHWFGsTLdeESWz0XMpFpKx3iQFlqq
         2xOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ltMJxWBOHtolA4fHUO1dAMcF/j+HeyAumwrml6j94Dk=;
        fh=mIbteqGhhUb2vBuHccj2y25JcIAouHoiRMEb4mNY8N4=;
        b=ARM4LSgb+pBNJFBfFM9K9kdF0Mv3lV/ZIYkHnW6dw7Q1j+oF+Ejy9G80SFfKyrHEks
         KGGqe6eEApDLfbsPOVqkhOsQCjOfgYKh+eWsxS5hQt/du9gjpbJ9OPy4lxNxHsANtXhK
         dOPiaAxsczldgy0EIEK7k3/R6mP6f5WAkNNAa0f5LuOjRF4d96gZy7upOI1bHCjTHBIz
         xEEBXuTUocU3zO2ky7AXY5/Q9SPikk6ogZSiXbEyMtefMpF8QODRaZEAtjHnaTAPSK9m
         hG2kgKAMLgSHTOfoVq9biuGZxHDO6bjmGTxqrjvT1OQhuCrNlI1OU2c0EYfazEM9pg7e
         zYKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3fGXSgNb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588df568ebsi377205e9.0.2025.07.29.04.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:17:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-32b7113ed6bso58739371fa.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:17:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUua3zixYxevSt60oFd4wDCPAnuw1Qmk0kCKZMR+/JiYDDoJafqZ9e5Ag378GrwQ0ZPO1fFx2BGdDM=@googlegroups.com
X-Gm-Gg: ASbGncvRa3MRy9uJAUq40JPJD1AkjxoXHZurVI5+lt8LvevipvwfhvExyvODuN2uaTd
	pM56GqigmlBtMpDKfjegPLeBN8SFrEn7cta+MjxR+BPpZ8L0p9nc17oh1zfR+ngs0RQqY5TjSdi
	E6JFK5JhrnlrMr24lorODgN1+rFBd/dfv2IthY5RF4FR3juV7yj0Su8a1JYoD4BM5eDNDq8XLh8
	wiTopoD2+/e8x1116/v7dbuP5ypTzbajMMoJES7hwWvqwRf
X-Received: by 2002:a05:651c:3254:10b0:331:e6e3:5f9a with SMTP id
 38308e7fff4ca-331ee70ee1bmr36539531fa.3.1753787872852; Tue, 29 Jul 2025
 04:17:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-9-glider@google.com>
In-Reply-To: <20250728152548.3969143-9-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:17:41 +0200
X-Gm-Features: Ac12FXzvXT6ZDgqBgnzLORTrdzHWOr68Bbqui0G02Gy0qCyfBlS9fa_n-K2ksxM
Message-ID: <CACT4Y+aEwxFAuKK4WSU8wuAvG01n3+Ch6qBiMSdGjPqNgwscag@mail.gmail.com>
Subject: Re: [PATCH v3 08/10] kcov: add ioctl(KCOV_RESET_TRACE)
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
 header.i=@google.com header.s=20230601 header.b=3fGXSgNb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::234
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
> Provide a mechanism to reset the coverage for the current task
> without writing directly to the coverage buffer.
> This is slower, but allows the fuzzers to map the coverage buffer
> as read-only, making it harder to corrupt.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


>
> ---
> v2:
>  - Update code to match the new description of struct kcov_state
>
> Change-Id: I8f9e6c179d93ccbfe0296b14764e88fa837cfffe
> ---
>  Documentation/dev-tools/kcov.rst | 26 ++++++++++++++++++++++++++
>  include/uapi/linux/kcov.h        |  1 +
>  kernel/kcov.c                    | 15 +++++++++++++++
>  3 files changed, 42 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6446887cd1c92..e215c0651e16d 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -470,3 +470,29 @@ local tasks spawned by the process and the global task that handles USB bus #1:
>                 perror("close"), exit(1);
>         return 0;
>      }
> +
> +
> +Resetting coverage with an KCOV_RESET_TRACE
> +-------------------------------------------
> +
> +The ``KCOV_RESET_TRACE`` ioctl provides a mechanism to clear collected coverage
> +data for the current task. It resets the program counter (PC) trace and, if
> +``KCOV_UNIQUE_ENABLE`` mode is active, also zeroes the associated bitmap.
> +
> +The primary use case for this ioctl is to enhance safety during fuzzing.
> +Normally, a user could map the kcov buffer with ``PROT_READ | PROT_WRITE`` and
> +reset the trace from the user-space program. However, when fuzzing system calls,
> +the kernel itself might inadvertently write to this shared buffer, corrupting
> +the coverage data.
> +
> +To prevent this, a fuzzer can map the buffer with ``PROT_READ`` and use
> +``ioctl(fd, KCOV_RESET_TRACE, 0)`` to safely clear the buffer from the kernel
> +side before each fuzzing iteration.
> +
> +Note that:
> +
> +* This ioctl is safer but slower than directly writing to the shared memory
> +  buffer due to the overhead of a system call.
> +* ``KCOV_RESET_TRACE`` is itself a system call, and its execution will be traced
> +  by kcov. Consequently, immediately after the ioctl returns, cover[0] will be
> +  greater than 0.
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index e743ee011eeca..8ab77cc3afa76 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -23,6 +23,7 @@ struct kcov_remote_arg {
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote_arg)
>  #define KCOV_UNIQUE_ENABLE             _IOW('c', 103, unsigned long)
> +#define KCOV_RESET_TRACE               _IO('c', 104)
>
>  enum {
>         /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index a92c848d17bce..82ed4c6150c54 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -740,6 +740,21 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 return 0;
>         case KCOV_UNIQUE_ENABLE:
>                 return kcov_handle_unique_enable(kcov, arg);
> +       case KCOV_RESET_TRACE:
> +               unused = arg;
> +               if (unused != 0 || current->kcov != kcov)
> +                       return -EINVAL;
> +               t = current;
> +               if (WARN_ON(kcov->t != t))
> +                       return -EINVAL;
> +               mode = kcov->mode;
> +               if (mode < KCOV_MODE_TRACE_PC)
> +                       return -EINVAL;
> +               if (kcov->state.bitmap)
> +                       bitmap_zero(kcov->state.bitmap,
> +                                   kcov->state.bitmap_size);
> +               WRITE_ONCE(kcov->state.trace[0], 0);
> +               return 0;
>         case KCOV_DISABLE:
>                 /* Disable coverage for the current task. */
>                 unused = arg;
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaEwxFAuKK4WSU8wuAvG01n3%2BCh6qBiMSdGjPqNgwscag%40mail.gmail.com.
