Return-Path: <kasan-dev+bncBAABBTFE6H2QKGQEPGQIHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id ADCFA1D1FCA
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 22:02:21 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id m191sf75848vsd.10
        for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 13:02:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589400140; cv=pass;
        d=google.com; s=arc-20160816;
        b=FAZ5dQEYed1LLM+0UqEZGGL1J83eV6w9WjPrXV2BTk9hJ3ZpzNhRslcQJrL/wI8AyP
         mpU6rXu/qWsfUEH3sPwsxAhXzZTTreMvUrOZenIQZ0OKwEuNVvWTu4YV9mynE44VKR8o
         5fCj0kv+eIF+ZLwjoD/rWa0PVGLlfRQLhSLrRN8e50ijBH12RS06DYJFb57OKuVHpt5M
         4wklR/YCsgpow3Ond2+DE/MwPQlcgi1qMQYJEF/AcAzUYKMGUCUyKGdv401SngpIZzQE
         wGwn6F+8BN0g/eDSrgIoxfR1He2YkfmxGcWUj7kyjv9ifuSZzM4JAEe8VJ9jlddZTsfP
         KpDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=HI4bMGt5KAHBwOAjwVQHDh/Oz7OWXSm3wvuo1GjCGlk=;
        b=rjHSIkGeoOQT4ewFLCVcYsLhU0w2wl+Qbw2l63+iA1CN2obnIersoFqHy3+3CYyhHa
         a0FM761Cz6/Yi6wnzYwvQDfUx4VqJYwOvvx+8SbhkKuRsQzsRk6Lg69lDomZKSWFQd5J
         jaNoNDimsruJqhMt8AlDGaorSkwC0R8FPbJ0eHFj2aRmAHl2rSDy9ZdC2KnQHFy4n0JJ
         eB854rvaa6DQl0lMzwm3P5xqhYwI55lbrByayYvU3Nbrkwj3pEK1PcZa314fVxWQuZCh
         bpbqualuys+zkGeB7h2IG967SsnHOsMW2FBvwYMGRm9QfjSU9j6ELBjE1BfeDgk0W2rq
         Pwhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oZX6W3Z4;
       spf=pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HI4bMGt5KAHBwOAjwVQHDh/Oz7OWXSm3wvuo1GjCGlk=;
        b=qjsy0zdjAbYFmDLiKpmW0eWPnN5M21vSwHYUomGN6DoZpTX1ozCZutjbS5EJEMIWGq
         td+CqJ7Eel/a212K+D2oU/RVRGAd4E4cJE8p8KnV5B7pv/t0Sdi+GyDtG6UVXnNrkgRu
         FXT8mG/wOcU3ruda3gCXSpJmjKyK0tZHkILxWvlTd5WZ4V1jG72QsRydRnHMXbTmdon9
         IGeFtDjz9PLbx4VZn4yRfS2BOkoThqnbaFF9SghfVVG5hfNzXrt3cuDQQv86IYpSEdxH
         ADAwxL33DPJosXQgGnt47Mn9Xcxlf9cEkRuKLPkwx8toLuyTIyPuzzRwChSxd/sRN0ak
         WfOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HI4bMGt5KAHBwOAjwVQHDh/Oz7OWXSm3wvuo1GjCGlk=;
        b=e+jOMIJGeGWDd8EIdeG/pwHSVYVxcc/izIBsbYpKc36TwtTWI5pRAiRCuOGaDsiGuC
         kuo0phGB8HOK0bq4mqcbqkp2T2sBB3lJXlJnWzY9/+/kUsT/EFMK4MBy/O/GQW/tyBLT
         JrY7Oa1v2OaIrI1mvs/+bkpQniZYkp0j1KJ0dERMPU9gb39Y30iu4swnaEzRoJxcmbcl
         WDVsTbCf+hd7ZsnVGHGH1WnrZovO20Lp9k3Eo8v3IHqeErCdQdeO7Av7QfdI/ynD10hx
         8nLtYFXbRxM8N2j8vAjnRFeJaJtbzvgfiKUviysZBep/0VA5AezI79R4jQQGnPRe5mzs
         GZBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZpZkzYHfHz9sNEWBgwnSaYUoM+0x3ebMUZBI8wI0Np229m1O7
	hNQJiQyi3v3rUSNFElOxsv4=
X-Google-Smtp-Source: ABdhPJwC0/nutmcTjrTQScOI6Ugdwe+pW4jh1/5l9TrPlZdRoi9hOCvGwzQSTSzvXdl6pbwQus3PgA==
X-Received: by 2002:a67:1903:: with SMTP id 3mr730487vsz.22.1589400140508;
        Wed, 13 May 2020 13:02:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7f86:: with SMTP id a128ls98279vsd.8.gmail; Wed, 13 May
 2020 13:02:20 -0700 (PDT)
X-Received: by 2002:a67:8743:: with SMTP id j64mr757342vsd.149.1589400140237;
        Wed, 13 May 2020 13:02:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589400140; cv=none;
        d=google.com; s=arc-20160816;
        b=F4pS1Vq5j2iPBGg4Lhk9iykUYfc7NuvoXnRtgsGIAxKEubAV3Xkewhz0WjNozxnoo6
         e1fRA9WjvtEvXCJDCN9S4+KuYTSS7UJ3WHEMLlTpOgyxw/6Y7buoTNJrXHjb3yVsVSPB
         DOigch44yJCWpzw41YmL9bNNrpam1IyivWuLRlGt7rQhgB+xnOk6oXL47zuAgAxZiaNb
         QfLGR+8mnAqq0aOXu+ph16Z0WF0IInW6vXorx3DgOUQTdpdgd9ZaVAeF35E70OdoD3gA
         uGM24R49v8tgcDvyci+Jkdb+0prXBKeXmLznE7OLqUBcvpxKExxFmdLOwyDxcHFey2pm
         CkeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=q8bx4k6HGy5lI9oMQDUvpfRKQB8DBhk2AZO6NIPgo1s=;
        b=YPrvDH0GHZgDduf/LxzKzkKcW15JyRsL8/82y/g3cNAlVd369nrcA33jHSXBZYkKTF
         DY2S1GvI3VMyhWkvW8pxQCgzISre1kSoKgmu3nf1K01C6AL16ZmPaNxEMDXb4jkLG2Wk
         DPXQzNxpPG9Oun+mTIYkAlMsJO9aYt7WkSoEozNN0ioUWw24pq86YuCqdGoh6MDK1EyN
         7AC4KsgFxxSUHqcrkKMnjMzuxxVPFin/m7zZn3zDmklf9wmr8z2Ku7nHjgwX9ISNSJOz
         5GSjrg2RquOOUT98Hi6njePWcUztYAWYxFDdj6+hI8j6OXw5XxFZTfvrLksh+aZMLdFi
         Ukcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oZX6W3Z4;
       spf=pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i26si30626vsk.0.2020.05.13.13.02.20
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 May 2020 13:02:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D9A59205ED;
	Wed, 13 May 2020 20:02:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 005D5352352C; Wed, 13 May 2020 13:02:18 -0700 (PDT)
Date: Wed, 13 May 2020 13:02:18 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, clang-built-linux@googlegroups.com
Subject: Re: [PATCH] [v2] ubsan, kcsan: don't combine sanitizer with kcov on
 clang
Message-ID: <20200513200218.GA25892@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CANpmjNPCZ2r9V7t50_yy+F_-roBWJdiQWgmvvcqTFxzdzOwKhg@mail.gmail.com>
 <20200507162617.2472578-1-arnd@arndb.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200507162617.2472578-1-arnd@arndb.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=oZX6W3Z4;       spf=pass
 (google.com: domain of srs0=h0+r=63=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=h0+r=63=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, May 07, 2020 at 06:25:31PM +0200, Arnd Bergmann wrote:
> Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> with -fsanitize=bounds or with ubsan:
> 
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
> 
> To avoid the warning, check whether clang can handle this correctly
> or disallow ubsan and kcsan when kcov is enabled.
> 
> Link: https://bugs.llvm.org/show_bug.cgi?id=45831
> Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Applied for v5.9 and pushed, thank you!

							Thanx, Paul

> ---
> v2: this implements Marco's suggestion to check what the compiler
> actually supports, and references the bug report I now opened.
> 
> Let's wait for replies on that bug report before this gets applied,
> in case the feedback there changes the conclusion.
> ---
>  lib/Kconfig.kcsan | 11 +++++++++++
>  lib/Kconfig.ubsan | 11 +++++++++++
>  2 files changed, 22 insertions(+)
> 
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index ea28245c6c1d..a7276035ca0d 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -3,9 +3,20 @@
>  config HAVE_ARCH_KCSAN
>  	bool
>  
> +config KCSAN_KCOV_BROKEN
> +	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
> +	depends on CC_IS_CLANG
> +	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
> +	help
> +	  Some versions of clang support either KCSAN and KCOV but not the
> +	  combination of the two.
> +	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
> +	  in newer releases.
> +
>  menuconfig KCSAN
>  	bool "KCSAN: dynamic data race detector"
>  	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> +	depends on !KCSAN_KCOV_BROKEN
>  	select STACKTRACE
>  	help
>  	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 929211039bac..a5ba2fd51823 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -26,9 +26,20 @@ config UBSAN_TRAP
>  	  the system. For some system builders this is an acceptable
>  	  trade-off.
>  
> +config UBSAN_KCOV_BROKEN
> +	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
> +	depends on CC_IS_CLANG
> +	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
> +	help
> +	  Some versions of clang support either UBSAN or KCOV but not the
> +	  combination of the two.
> +	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
> +	  in newer releases.
> +
>  config UBSAN_BOUNDS
>  	bool "Perform array index bounds checking"
>  	default UBSAN
> +	depends on !UBSAN_KCOV_BROKEN
>  	help
>  	  This option enables detection of directly indexed out of bounds
>  	  array accesses, where the array size is known at compile time.
> -- 
> 2.26.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200513200218.GA25892%40paulmck-ThinkPad-P72.
