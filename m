Return-Path: <kasan-dev+bncBCMIZB7QWENRBNMF7O2AMGQEGMPKO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 451C69394C6
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 22:36:07 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-427d9e61ba8sf23084915e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 13:36:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721680567; cv=pass;
        d=google.com; s=arc-20160816;
        b=ao9GpfIoGrcUxMZKkyrBo2eMT65kUAU+brzV+mlHTvdfzDQpCdRb02BbvlrTW+sLvk
         QZ0X5KWeKP+0by5674mdMIgpkJIf/Hd9+DGGl9ooCMAh93qBHBjtZDhN8T47cIR5k8Jl
         ooZ44K0RpG3lnbUEZF7aCzVtfkhvuXQ4lFEdptxqjMGNN5mh0x3sv6tL2reHIcatrJGz
         OXmOpzjNo2SoPhkQxVlrMJ3+6291EWGsN0BAKCv/gRDUdQ1pA569kiDK1Y2nZMLjuu8p
         B6hS3TixRviW/oyJPwrKoAA5B/1TW0/Ro3Xa7aNuU4e6plzWq4Y+VwdYLZt5KOXISjyO
         BjLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Y6kKY1jZpuIGgSIG+hZigEZMmQGygjLaKCileq5vm/I=;
        fh=B1+ciZOPCxhi9/jPMsIf8L3QsnV2qRwYfGto9LWS34M=;
        b=ZMeobn7T6CQXw0zCPVF0N6SsFE1u+nzZAGhwAS73Ja+onQsiTohuah8OuZKZfXn88Y
         Ab48ihqWMjT4l3CD7XpPydIwRtYbtxYmDm84QvPedCShfieU6IKv3GfR78pu2E4Bntfw
         DjygDOeiGAk0ljjYSC+xiKzhc3vBqluZDq/3tSGkwmXxd5jf24BIzDjEr18kMiOmQmKj
         hgmW+sCYNJxFz4ghAJb/Kb5mBqtAuRcBgsESqHhhQLoZ7KzyjwPaRVI0WSq/6dh4mbkf
         FcVfMNLmDUODWHN8cGrTScdhAWBrB97rGZQY1pAc5uNJQMx2m/kZo8eWL460ItVE483k
         hLeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J75SNElr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721680567; x=1722285367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y6kKY1jZpuIGgSIG+hZigEZMmQGygjLaKCileq5vm/I=;
        b=qqA5dNNElXD/kT/RKR14KleDr4BvC5I1zHXml7fKoC9zqZgiwTfPC3V6a572M+UINK
         noDG9KytOVhlQ/MszLdbiscWxwweGw8/RkIGO4HtkGyl5ynh2+bvRLYc4xzIwN2BswCz
         dzyg2Q0vjzeFKIKUZLA3HeA33gIhCcB7XPWJDMuy4ZaGWB2okJa51YAE5IH3tJ/tfs1e
         qb7K0c4ezli8hngvNRQsokpFeW2ATps2nqa+wQJzpFW5MRvz9KtUtoR1A11T/Th2fY/+
         OOXIIgsnjVOCiYG4+mV68O/77mp5fdnj9h9LbbP8kh3YdvFZAcqER9+R4lth8a//mHtT
         XVKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721680567; x=1722285367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y6kKY1jZpuIGgSIG+hZigEZMmQGygjLaKCileq5vm/I=;
        b=jUT+BOSV1ebfMS79j+yOIzOT7hMXRLlWJhJ6b4m3KxAGEPGRkcymcN4n4OYDQmiBW4
         81a3nDKnNjx2fQYnXvJ8ibjB+IbVTo9IEsnAFtEB7KSBIXC6MmYKnqlel+4zLVW8cAcx
         8pTQKc4cjiOdPYCfQ+gJoalye7iywbzgFvby04BvTFtW4vafm69W3SqWQpzPa8Baonqc
         DtKsWE+BGB8Xl0i+F3RjgNVc1+XnWnhTAKOCd31fFHkJlwpB6cDvA3yYY++P+znhI8A8
         dgbjLKWkQWx3E5LR0rUZfj9cEZ35fwbT3HauJGiZhhcqMAPxPkJnjL8rycqVLTr8RwTb
         zXjg==
X-Forwarded-Encrypted: i=2; AJvYcCWGAiExlLzEyTdKCOz16bx2DWdI+QuRPkRQVo6xXGq2UCjmlfH8MT+tELW9obH4U2vDqzuizLuMW6yp/nyaLqNs/RkRCIeg1w==
X-Gm-Message-State: AOJu0YzWfc7uaWkBQfjkUQ8PRrdlCSerV6FdkyZsCqi5gyV9B7y0zfIh
	xSFkH+p8NRWOXjAJ9FCVH4QHRXWMqgy3mI/dk+9muaqrIypBhGpd
X-Google-Smtp-Source: AGHT+IF5snEXSwwkZZLN+OVOcSuVr9Zue8QJu1aCIP8clZQMFmDodPONgU+EJZ7fkUqElGH4cnvcNQ==
X-Received: by 2002:a05:600c:1c1c:b0:426:597c:7d4d with SMTP id 5b1f17b1804b1-427ed001c2emr8258795e9.18.1721680566176;
        Mon, 22 Jul 2024 13:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c13:b0:426:6f58:8e6d with SMTP id
 5b1f17b1804b1-427c83ab20als23884605e9.2.-pod-prod-03-eu; Mon, 22 Jul 2024
 13:36:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViyXCEGvxqMvoVcndUjDm/JVfZXWNddWbiPmC3oI/abBuUgwP225p6EaRy3DlkNOll9jqwHiAFw/ay8Dz8MCh40oRdMMursl0Dbg==
X-Received: by 2002:a05:600c:198f:b0:426:54c9:dfed with SMTP id 5b1f17b1804b1-427ed059c10mr6341835e9.28.1721680564551;
        Mon, 22 Jul 2024 13:36:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721680564; cv=none;
        d=google.com; s=arc-20160816;
        b=R5b1iA5sZlP5gWhvTdjx3wDNzBu3Ehk5HwGOJm6iFlg8zuFR1JttOpkGlvFozBvizp
         URBMVLQ4vWqkDs2lrYVa1wQWslOxrHUTDs54hxSI/9tXcFL9gmY3xDsy4b++P4L/RvX5
         jTfqs80WIN5yETvLyOAIiz1G0TEw0gxovTtkG3IzKdl/tly/ShtzTDlfkUtt0Gy9ebPf
         ojrXAUqe0+MpRX40+By7bQteDoyOzkJ1t9Ju9DxFV+8DX4khOkCZ1FFFPpBMNbaKh8AR
         curIMHWv+BL1KWJxxjRAUvdWhXveFAhg0yoj3KtRN0LXr892z6eT++LXFPeIa374VKoM
         9aeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wA86CUyO9g/UBTDzj6a6yBQ8gAzp68p6n3zkRO96JMs=;
        fh=y01rB8iV7S0hRYPxNOLmwDmwmDucRjP/YlBm/uJWNMA=;
        b=kYD6bLLh1FyZjQO8mKyOM4bmPB8W7rvjET/VV8mq5b1x7WFrzBUyEurwbpZFR/8DDL
         vSCnrgnJa2lbFQgcZpGcRAqmn6LtyUSd8zy9OC6d/vegfZ6MWjO//eu0/1ToHyNqZRqd
         ih4OLBWHEJlJgu1FKKpNAklA+y1leXW1ser7VtaCyErJ95+MytZQ7j+PABcEskFHmVbw
         ULvj9iRrj9h3vxsX19Mei0osRpfq977glg8mqqntf9g1lpU4Q9WPw09YvSFVc9UeiK2h
         QFZ9IrJ3vpkd4r3gbOgw7vYXoQ5sIjqtguNqHDuRIr7tgWnWzpvJuyxhqwTMj6M6su5V
         2lsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J75SNElr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ef50e02csi4795e9.1.2024.07.22.13.36.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jul 2024 13:36:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso5513a12.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Jul 2024 13:36:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWDaikcGM1nhAQlTGrPjyytBLPXi/Fdd+xL3resin4LFQvrZ1g4D8bSvd/HO8kXcI8iaa0shUvWY1LlhcYSlI0AvlLL1Zi76arGCg==
X-Received: by 2002:a05:6402:40c1:b0:58b:93:b624 with SMTP id
 4fb4d7f45d1cf-5a4a8333773mr317602a12.1.1721680563688; Mon, 22 Jul 2024
 13:36:03 -0700 (PDT)
MIME-Version: 1.0
References: <20240722202502.70301-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240722202502.70301-1-andrey.konovalov@linux.dev>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Jul 2024 22:35:52 +0200
Message-ID: <CACT4Y+Zb5ffw0MiYMNqT6YUSdJ7X6xDxJND0ZZPQ7SZmoGybXA@mail.gmail.com>
Subject: Re: [PATCH] x86, kcov: ignore stack trace coverage
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=J75SNElr;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::532
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

On Mon, 22 Jul 2024 at 22:25, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> When a multitude of kernel debugging options are enabled, they often
> collect and save the current stack trace. The coverage produced by the
> related routines is not relevant for the KCOV's intended use case
> (guiding the fuzzing process).
>
> Thus, disable instrumentation of the x86 stack trace collection code.
>
> KCOV instrumentaion of the generic kernel/stacktrace.c was already
> disabled in commit 43e76af85fa7 ("kcov: ignore fault-inject and
> stacktrace"). This patch is an x86-specific addition.
>
> In addition to freeing up the KCOV buffer capacity for holding more
> relevant coverage, this patch also speeds up the kernel boot time with
> the config from the syzbot USB fuzzing instance by ~25%.
>
> Fixes: 43e76af85fa7 ("kcov: ignore fault-inject and stacktrace")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> ---
>
> I'm not sure whether it makes sense to backport this patch to stable
> kernels, but I do think that it makes sense to take it into mainline
> as a fix: currently, the USB fuzzing instance is choking on the amount
> of coverage produced by KCOV and thus doesn't perform well.
>
> For reference, without this patch, for the following program:
>
> r0 = syz_usb_connect_ath9k(0x3, 0x5a, &(0x7f0000000080)={{0x12, 0x1,
> 0x200, 0xff, 0xff, 0xff, 0x40, 0xcf3, 0x9271, 0x108, 0x1, 0x2, 0x3, 0x1,
> [{{0x9, 0x2, 0x48, 0x1, 0x1, 0x0, 0x80, 0xfa, {{0x9, 0x4, 0x0, 0x0, 0x6,
> 0xff, 0x0, 0x0, 0x0, "", {{0x9, 0x5, 0x1, 0x2, 0x200, 0x0, 0x0, 0x0, ""},
> {0x9, 0x5, 0x82, 0x2, 0x200, 0x0, 0x0, 0x0, ""}, {0x9, 0x5, 0x83, 0x3,
> 0x40, 0x1, 0x0, 0x0, ""}, {0x9, 0x5, 0x4, 0x3, 0x40, 0x1, 0x0, 0x0, ""},
> {0x9, 0x5, 0x5, 0x2, 0x200, 0x0, 0x0, 0x0, ""}, {0x9, 0x5, 0x6, 0x2,
> 0x200, 0x0, 0x0, 0x0, ""}}}}}}]}}, 0x0)
>
> KCOV produces ~500k coverage entries.
>
> Here are the top ones sorted by the number of occurrences:
>
>   23027 /home/user/src/arch/x86/kernel/unwind_orc.c:99
>   17335 /home/user/src/arch/x86/kernel/unwind_orc.c:100
>   16460 /home/user/src/arch/x86/include/asm/stacktrace.h:60 (discriminator 3)
>   16460 /home/user/src/arch/x86/include/asm/stacktrace.h:60
>   16191 /home/user/src/security/tomoyo/domain.c:183 (discriminator 1)
>   16128 /home/user/src/security/tomoyo/domain.c:184 (discriminator 8)
>   11384 /home/user/src/arch/x86/kernel/unwind_orc.c:109
>   11155 /home/user/src/arch/x86/include/asm/stacktrace.h:59
>   10997 /home/user/src/arch/x86/kernel/unwind_orc.c:665
>   10768 /home/user/src/include/asm-generic/rwonce.h:67
>    9994 /home/user/src/arch/x86/kernel/unwind_orc.c:390
>    9994 /home/user/src/arch/x86/kernel/unwind_orc.c:389
>   ...
>
> With this patch, the number of entries drops to ~140k.
>
> (For reference, here are the top entries with this patch applied:
>
>   16191 /home/user/src/security/tomoyo/domain.c:183 (discriminator 1)
>   16128 /home/user/src/security/tomoyo/domain.c:184 (discriminator 8)
>    3528 /home/user/src/security/tomoyo/domain.c:173 (discriminator 2)
>    3528 /home/user/src/security/tomoyo/domain.c:173
>    3528 /home/user/src/security/tomoyo/domain.c:171 (discriminator 5)
>    2877 /home/user/src/lib/vsprintf.c:646
>    2672 /home/user/src/lib/vsprintf.c:651
>    2672 /home/user/src/lib/vsprintf.c:649
>    2230 /home/user/src/lib/vsprintf.c:2559
>    ...
>
> I'm not sure why tomoyo produces such a large number of entries, but
> that will require a separate fix anyway if it's unintended.)
> ---
>  arch/x86/kernel/Makefile | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
> index 20a0dd51700a..241e21723fa5 100644
> --- a/arch/x86/kernel/Makefile
> +++ b/arch/x86/kernel/Makefile
> @@ -40,6 +40,14 @@ KMSAN_SANITIZE_sev.o                                 := n
>  KCOV_INSTRUMENT_head$(BITS).o                          := n
>  KCOV_INSTRUMENT_sev.o                                  := n
>
> +# These produce large amounts of uninteresting coverage.
> +KCOV_INSTRUMENT_dumpstack.o                            := n
> +KCOV_INSTRUMENT_dumpstack_$(BITS).o                    := n
> +KCOV_INSTRUMENT_stacktrace.o                           := n
> +KCOV_INSTRUMENT_unwind_orc.o                           := n
> +KCOV_INSTRUMENT_unwind_frame.o                         := n
> +KCOV_INSTRUMENT_unwind_guess.o                         := n

I've sent something similar recently, I think it should be in tip/x86 queue now:
https://lore.kernel.org/all/eaf54b8634970b73552dcd38bf9be6ef55238c10.1718092070.git.dvyukov@google.com/



>  CFLAGS_irq.o := -I $(src)/../include/asm/trace
>
>  obj-y                  += head_$(BITS).o
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZb5ffw0MiYMNqT6YUSdJ7X6xDxJND0ZZPQ7SZmoGybXA%40mail.gmail.com.
