Return-Path: <kasan-dev+bncBCMIZB7QWENRBE6HQ6KQMGQE3WFAJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B983544B64
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:12:04 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id m23-20020a05600c3b1700b0039c6e3c169asf611533wms.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654776723; cv=pass;
        d=google.com; s=arc-20160816;
        b=OI7tcmXhCwHNN2EbhxEFMdthdjd1HGjCOnwXVQq1RY8Jk3639h3EtQ+gRMwOhCuDw+
         kdert/EsRCWtLFKbtt2bjZ0H/3d2+lksqfz50CR/bxjPdL63ulRlk1TiU6aFcVG9MKA7
         +qYKWegIXn6dms7KIt02FnXBzFSpWfJpFc6Ty326jEwk3fUDEzUxk6I4DkVnFZ1AZal9
         RgiQD5vOSs0YsDNODm/kYET1ACEYGfa/5QTSFAkJJd/6bQ/Yyp9okz2qrPZEnabGzIQ2
         3HU/ptxNfwCS2IVR+mUpakHioe2HvSW1RVhWKaZQ2S6pq/LRPO+kz/Hhh8ynn0VVGmAQ
         AqJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LOIFRiIy5nnHAGyhRFo/85ff9YMmM2Lk+1yUmnqfZzo=;
        b=Gbs66NxxcowsJAZkS09Hq4SZGBV5SzQajSoY/JXZuopidfBEaGwAJ3n5gufa05aPok
         IN8hMZxoowQPUH59qZbmXPQiJ/1p7Bnlmx5lFNbwF1kRVILJBejqNWSgOJc1SGZAPt2a
         DBhZcc+XM1JBCRT4oQeBRJsxg3zNVp/1UfN65wZuSWO7UL49l+TEGuBvte2WKz72Tvm0
         3oLrL20itkMcvuNnQEpy3ir6EcxTQ4e4g7yjp2EFDLgGlUpywdOo9jJ3/RzHw+FTuAVH
         iFOTm1DDwrfqM7IWt/MPryCcK3prnMDWLLM0TLuYIiqSDUpQ8lKuW0sf//YNbbicPZf8
         AXMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D1YG4fyB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LOIFRiIy5nnHAGyhRFo/85ff9YMmM2Lk+1yUmnqfZzo=;
        b=Xzn8OFs2KA9ydTdV/KUg3Ax2ZYTPwJYJ377aj3jYjNSfmBBhvZeYJvspOj16WVkgrg
         bw6uMokR9yXT4RkDDwJQavnvyetISLOWDYFu/vZbf/e8MqHgHJxjujgF/wTHgGfzV/Fw
         sKvXIdMCvgrGjA46cn30AvLjSByc8X0F2NzVStypYcfsaky16Yn1SPTfCgIn7YK/4jVG
         H6kLa0i6EA87E3YIDVCQREJBxvOlsvceVTX9HTAJisYuocyANX8tZhahbzJZUsaI7Hv8
         423KJABcP/J72Ago7VGLGca2Tm6LFQTkQDFRu80pZ4lAICkqOrOgFmvFgrcWTt26YYAK
         FRrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LOIFRiIy5nnHAGyhRFo/85ff9YMmM2Lk+1yUmnqfZzo=;
        b=q2EvkItJY3mA8oEwMvghqdfptIAhveVnEpeJpuutexXj6hoEEoRyji+6UzflHGS4w1
         E7ouB3kfSpj7JRnBtcfZK0FrkR66uk8MyKyC2kz1zxr+Aene3Ky1dH5AnkLVxdFgpFj0
         f+Dnk0QHU4+FC+gzreNSippXfxMfWezMnviIg7HlsaGG1Le4Q9NDRXJaw8LeW4sh/q09
         PVc1hXSE2RsCMW/0jYpRSYZ0J1GCf/nXkhLHGaaIHK4MaKJnWh1eDVJZN7T3m0J1Bp15
         v9jowgvBNPJLf6R/aBqQOcr5aGb0Tr4Dx0Mp5+yXwORoLolysI61oFEyTi08wHqK4xNK
         G7qw==
X-Gm-Message-State: AOAM531GGIvvK9g34r2zMVua9Kap1gdEYjczY7P2L1PsJBeJ3gbvhXUR
	aaN8QZsk78cIKG0xPiaTrgw=
X-Google-Smtp-Source: ABdhPJywK3lCeX1sB34sKV30BxSPPa5gAH/nK53u9yBSy5GJmC1MfVgWJO5Wt2mMlnMsFZdYir+Clw==
X-Received: by 2002:a5d:42c6:0:b0:210:28d4:428e with SMTP id t6-20020a5d42c6000000b0021028d4428emr38403891wrr.656.1654776723647;
        Thu, 09 Jun 2022 05:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls1175462wrs.3.gmail;
 Thu, 09 Jun 2022 05:12:02 -0700 (PDT)
X-Received: by 2002:a05:6000:1008:b0:210:3e9a:324c with SMTP id a8-20020a056000100800b002103e9a324cmr37934699wrx.89.1654776722671;
        Thu, 09 Jun 2022 05:12:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654776722; cv=none;
        d=google.com; s=arc-20160816;
        b=qfF4LQUOu5iZ8x89uWaG7eBvpk7CXI2yk+r5wTeOA7dLpI8YWBXTiDCcpfDs+Q3itl
         zgk6/V8kzn82jnzMURq7MF1mc8sd8R/W6FeCp18/rqMG7nJ2D8cUs3LWQWefsEX+JMzE
         NIEkpBVq3sGCgykKYrs7f8xIUUZMgV7cYh/1Muq2gW9zT6OXUMEz42gWNL1R/OTPzlds
         NtRyG/ijITDFQqg5jKolumHuefDJYmDi8Ow6t9KcHkr3aEWhki778x83SAdU7Ep9tAgv
         x9zIqQZJ9QKJUgVLmBf21Uuzwc1Y8dOf2jCehDk2YsTMWWbR0jdkIbNXAgYbm+Q5PfFl
         5gUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XXw13yRcDqKg7DkQzKXd5XjAMX2OrZDRyub1ykACt1g=;
        b=RRHqrQTLuKcTcIaQG4vivVUmD2I3Upod6t41AW3fsJsYiPMJ/Pk0TxJDknzi1ieC3n
         xW2fr7rfxx7qaK/3Xqwd2ViJY0r63MqBP7TNnUpvfvDNGvSjMpT6Dxa0Sjw5b30FTFcP
         WyEvuT4Ps2HgkiKxMPwSQtBhZcOQG5dmvnbcBHffZ+w6di2M74oeVuyWS9HwuVGkRll7
         Le+klL3QzU7NqxIJA0Mwjq6M5HiS/LI4R7unuS25QHv/kQHjwXxz5JL+z0WcPPv1utXj
         noRNLfx7oVwOSf6RmPRWhlc2jkj2yVlAB0ns2VZtYaUxLyq++beZWbbiUGbCi0wr+Ek0
         aT6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D1YG4fyB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id i10-20020adff30a000000b002132c766fd7si840282wro.4.2022.06.09.05.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id j20so2292274ljg.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:12:02 -0700 (PDT)
X-Received: by 2002:a05:651c:1988:b0:255:b2ef:6a5b with SMTP id
 bx8-20020a05651c198800b00255b2ef6a5bmr6789351ljb.465.1654776722133; Thu, 09
 Jun 2022 05:12:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220609113046.780504-1-elver@google.com> <20220609113046.780504-9-elver@google.com>
In-Reply-To: <20220609113046.780504-9-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:11:50 +0200
Message-ID: <CACT4Y+ZFO8F6KzZTuCiDNn4PjSjT3VcFD7dC0Chg9RM9c7bbUg@mail.gmail.com>
Subject: Re: [PATCH 8/8] perf/hw_breakpoint: Clean up headers
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
 header.i=@google.com header.s=20210112 header.b=D1YG4fyB;       spf=pass
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

On Thu, 9 Jun 2022 at 13:31, Marco Elver <elver@google.com> wrote:
>
> Clean up headers:
>
>  - Remove unused <linux/kallsyms.h>
>
>  - Remove unused <linux/kprobes.h>
>
>  - Remove unused <linux/module.h>
>
>  - Remove unused <linux/smp.h>
>
>  - Add <linux/export.h> for EXPORT_SYMBOL_GPL().
>
>  - Sort alphabetically.
>
>  - Move <linux/hw_breakpoint.h> to top to test it compiles on its own.
>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/events/hw_breakpoint.c | 20 +++++++++-----------
>  1 file changed, 9 insertions(+), 11 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 3b33a4075104..e9aa7f2c031a 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -17,26 +17,24 @@
>   * This file contains the arch-independent routines.
>   */
>
> +#include <linux/hw_breakpoint.h>
> +
>  #include <linux/atomic.h>
> +#include <linux/bug.h>
> +#include <linux/cpu.h>
> +#include <linux/export.h>
> +#include <linux/init.h>
>  #include <linux/irqflags.h>
> -#include <linux/kallsyms.h>
> -#include <linux/notifier.h>
> -#include <linux/kprobes.h>
>  #include <linux/kdebug.h>
>  #include <linux/kernel.h>
> -#include <linux/module.h>
>  #include <linux/mutex.h>
> +#include <linux/notifier.h>
>  #include <linux/percpu.h>
> +#include <linux/rhashtable.h>
>  #include <linux/sched.h>
> -#include <linux/spinlock.h>
> -#include <linux/init.h>
>  #include <linux/slab.h>
> -#include <linux/rhashtable.h>
> -#include <linux/cpu.h>
> -#include <linux/smp.h>
> -#include <linux/bug.h>
> +#include <linux/spinlock.h>
>
> -#include <linux/hw_breakpoint.h>
>  /*
>   * Constraints data
>   */
> --
> 2.36.1.255.ge46751e96f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZFO8F6KzZTuCiDNn4PjSjT3VcFD7dC0Chg9RM9c7bbUg%40mail.gmail.com.
