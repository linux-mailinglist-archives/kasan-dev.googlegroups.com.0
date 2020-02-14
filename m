Return-Path: <kasan-dev+bncBAABBV67TTZAKGQECTL2WNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 86F1B15FABA
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Feb 2020 00:40:08 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id c1sf6737292qvw.17
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 15:40:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581723607; cv=pass;
        d=google.com; s=arc-20160816;
        b=r+qSyuqKBt9ieYQUMnQLsVH2TNt2K3ECyP++yyHDbGNmEPXJhQtzZA6vNhykN3kdhb
         Bsluj9qzmsuyX69uMi2R6VBNqaOhHaBymsM3ple8xnjOsGvQe694C/QkVL+eLv+FdULu
         AagWgJCu2GyLTEtWaTwMeUu2d0NVS4td7pYjLvHmxycRyMKpjfDBtfBL1xBFYfCf7p9k
         gpUzBzGvfSVCVllc8ZQ1m6MTQv6Ym6lbMiSEVtLsS3bx+U2/7ufvWe1g8N+ZJeR3EsDJ
         lzgt6yUiX2SqpOa757L5IpWQh7PjkeAdidYI03dsgwz8/Iv64UPEOPzrrqKJl/TdYx5l
         N3bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=2uFbmqT346nvgpGH71Wtf8NCWuR59lkj6+DLqkRzEOw=;
        b=jjfpWJnRds2gGPbGR+OiH7SuhKEm/4xTKUdd+fVvCNGwecxvdlAi58YGC1eEzEOJSI
         gaxJwtyqpvFOYZKlz5OO5GY+JRBh2T/1Kj8T/T8Mt4fHC7vTWvb5JbzykKJATf0JakR/
         4R5qkmvG/dE0tHKkGARRHVK/1/xr3u/Vqz24wn3odpABsl4+2o3xZG8WMc4Ym+TcF3FF
         rL+UQ7N2jmhcuVduPFM1EaQ4iBUZVuC3y7886VLTHrnIPB+Zp6RUju/FzPDoZd87dgJs
         SWc8Dh7kekvXlPf+68UT99Njm+RhbXHbfwGBQlOCd+qcs01OBymsRIxz+CfYbJKyZCBV
         38hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZoJanWRX;
       spf=pass (google.com: domain of srs0=u5xr=4c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U5XR=4C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2uFbmqT346nvgpGH71Wtf8NCWuR59lkj6+DLqkRzEOw=;
        b=qH24eswdsmrd+MUZyorDyMDMN80IFu62q0M0WWrSIToicdHdc7YqQqa3gFIlEILF+T
         IFjhIy5RGD6gOclVBCLY4Et5v7/cHUYzzZ0Cu78TyZ/8kZ1l0hb76KRURe4sP0v5pURq
         8GepwO5SsIVDF5cdi/VdeB6OzbocyZmORrH0qESJRRn01fIzbZIkXmRapGLxdIr8EZDt
         r8uXj1mFFsvRqY6zhZqVvYmu9rr9Q4rWEoQqt2PUESzdVQMHcW3KVXarWMkwKIRTgLqR
         rHU+BXgr/u4N8LYIV4f1/In4XJoy5wE6Cjt1ppoY5FRR5YXnRcS1gr4O02TaPT56DWUF
         x+xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2uFbmqT346nvgpGH71Wtf8NCWuR59lkj6+DLqkRzEOw=;
        b=FASsD59QuM41EkBjkerrgqS1J0yGF2hT/EgeAdhNkI0X4ZqvbxFOQCmCW1IDH8jp2Y
         sdbrcNCtFn6EXVzOdc5vePkv8wn+FAJli2aZxT5dU2CnHKbIayAbi4SpUqN9oiwgLJ/3
         fmJUL+4nIFzW6+JAXGiLiVp3V1FJmiHSKl6ptRdvCmO/+M8C+T9BWGwZjrN4UA6JhBA/
         eSf9Cf9lPGFqHAJ8uiNnwOr+vxsR3vnlaz/1t48WE0jOXmvGd3i9rvyo3FqgfV9CBB7W
         vABEmQb7eD2lfV/cV54l+ENTP4CkuGlLyc7goVJXOGMaPUyXjAGhf0reiq2nkGLfjT1P
         i+GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9UjDcylB+KkVnvMKzbQGncHvwYEAnoRQ3e0HDovEidMC6cwza
	WftOVqbmxpicM6Y33TfvJx8=
X-Google-Smtp-Source: APXvYqwXooDAdpqV6863cM987hpyjI51dkiXh7qlqqMUlqdwveX35VtY5YVsWp2wwpY3vNL/B/Psyw==
X-Received: by 2002:a05:620a:16d5:: with SMTP id a21mr1220671qkn.107.1581723607302;
        Fri, 14 Feb 2020 15:40:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2ba4:: with SMTP id e33ls1384159qtd.2.gmail; Fri, 14 Feb
 2020 15:40:07 -0800 (PST)
X-Received: by 2002:ac8:60d5:: with SMTP id i21mr4607128qtm.341.1581723606981;
        Fri, 14 Feb 2020 15:40:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581723606; cv=none;
        d=google.com; s=arc-20160816;
        b=W2LvEYsbvlxLc1t4c+nqCOuOh3D1VgwWCkVlhiY2DpYtop1Z/8zbUPnF72s8SxRLXN
         1JFz3h5Bk/RtfGjWWsxV9iFpDX9I04Dk2sXUNEFgQ8UdsgUV76NgB34g5X+Id494FsYk
         IpzaBQlNyNGkpkVZ/3SRyzeS/dv9Jd5XWAylU2t54El95oTJ7Fbta/KhAId3xZAcCibC
         rUyWtPskydO/0nUT3GESuAv7TBPDtUbabKRa6thB6vz7WwO+svE+W6gDajRQIf80Eu/T
         GCEtEV/C9012Ebt50r8BlhWVsY0J8eSeeV3+9N7QLf0TrzIeccKq0VUpan2pkF0hyhJu
         XXyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Csl0Q/n25jgDsbIRH/0To6RgkCFUF7ukOO4ByE0vlA4=;
        b=vW6aXIYR9txbj7DY4zmZaUo1sIMIoGdeXjjHWQdCAow6GeQoV43kkJv6c2FFFjZTEe
         yylbJo6lUbVbHmwAt7LTE+hBnU0XC+6LHszbIonYoqVhr17gn1TWjoc+I3Bu2er+9Ylx
         7zyf7GRYONO8Ji4whKbSsFmeT8SwCH4N6QW4/lmgyXjdeJ5x01M0sSCMSTF8C67CK8m+
         V6nZUIdWw3UpUneJDuB4Y0Lvs0dnEU0Wy6L6/zkaXc4V/hbveRM4208Y+VS0fZOsoZa5
         hFt3H0JRTBfq3UN1zZ5FKFpPhMvY4X96g5bvO20ptEgnijLLVw7NktnMZzqviKwBVMto
         3nnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZoJanWRX;
       spf=pass (google.com: domain of srs0=u5xr=4c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U5XR=4C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 14si327057qke.3.2020.02.14.15.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Feb 2020 15:40:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=u5xr=4c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [62.84.152.189])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B078E2187F;
	Fri, 14 Feb 2020 23:40:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 4A98E3520D46; Fri, 14 Feb 2020 15:40:04 -0800 (PST)
Date: Fri, 14 Feb 2020 15:40:04 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	rostedt@goodmis.org, mingo@redhat.com, x86@kernel.org,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH v2] kcsan, trace: Make KCSAN compatible with tracing
Message-ID: <20200214234004.GT2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200214211035.209972-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200214211035.209972-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ZoJanWRX;       spf=pass
 (google.com: domain of srs0=u5xr=4c=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=U5XR=4C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Feb 14, 2020 at 10:10:35PM +0100, Marco Elver wrote:
> Previously the system would lock up if ftrace was enabled together with
> KCSAN. This is due to recursion on reporting if the tracer code is
> instrumented with KCSAN.
> 
> To avoid this for all types of tracing, disable KCSAN instrumentation
> for all of kernel/trace.
> 
> Furthermore, since KCSAN relies on udelay() to introduce delay, we have
> to disable ftrace for udelay() (currently done for x86) in case KCSAN is
> used together with lockdep and ftrace. The reason is that it may corrupt
> lockdep IRQ flags tracing state due to a peculiar case of recursion
> (details in Makefile comment).
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reported-by: Qian Cai <cai@lca.pw>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Steven Rostedt <rostedt@goodmis.org>

Queued for review and further testing, thank you!

Qian, does this also fix things for you?

							Thanx, Paul

> ---
> v2:
> *  Fix KCSAN+lockdep+ftrace compatibility.
> ---
>  arch/x86/lib/Makefile | 5 +++++
>  kernel/kcsan/Makefile | 2 ++
>  kernel/trace/Makefile | 3 +++
>  3 files changed, 10 insertions(+)
> 
> diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
> index 432a077056775..6110bce7237bd 100644
> --- a/arch/x86/lib/Makefile
> +++ b/arch/x86/lib/Makefile
> @@ -8,6 +8,11 @@ KCOV_INSTRUMENT_delay.o	:= n
>  
>  # KCSAN uses udelay for introducing watchpoint delay; avoid recursion.
>  KCSAN_SANITIZE_delay.o := n
> +ifdef CONFIG_KCSAN
> +# In case KCSAN+lockdep+ftrace are enabled, disable ftrace for delay.o to avoid
> +# lockdep -> [other libs] -> KCSAN -> udelay -> ftrace -> lockdep recursion.
> +CFLAGS_REMOVE_delay.o = $(CC_FLAGS_FTRACE)
> +endif
>  
>  # Early boot use of cmdline; don't instrument it
>  ifdef CONFIG_AMD_MEM_ENCRYPT
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index df6b7799e4927..d4999b38d1be5 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
>  UBSAN_SANITIZE := n
>  
>  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
>  
>  CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
>  	$(call cc-option,-fno-stack-protector,)
> diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> index f9dcd19165fa2..6b601d88bf71e 100644
> --- a/kernel/trace/Makefile
> +++ b/kernel/trace/Makefile
> @@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
>  ORIG_CFLAGS := $(KBUILD_CFLAGS)
>  KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
>  
> +# Avoid recursion due to instrumentation.
> +KCSAN_SANITIZE := n
> +
>  ifdef CONFIG_FTRACE_SELFTEST
>  # selftest needs instrumentation
>  CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200214234004.GT2935%40paulmck-ThinkPad-P72.
