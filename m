Return-Path: <kasan-dev+bncBCS4VDMYRUNBBT525GYQMGQEKSLXMUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D3F8BE9E2
	for <lists+kasan-dev@lfdr.de>; Tue,  7 May 2024 18:56:48 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6f02bc1e0f1sf3867648a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 07 May 2024 09:56:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715101007; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ig2IR2qErjyS4CrO9nSPji0OgOVh/K0RksVmiSOfVJkxjoIROSmgeKgMdTVkrjEN1c
         JJuEZAR42H9nhCrtVvh0F+w843jh0/3E4EkHtBvuFq+FQV6J86tmO/Z4zMDMl7egb6kR
         v+H0FE5HiKv0aMF+fo5BuvALb/UflylxLRBQTJuwD4LZY3anYo7dEJ82/IggtyfWzY+n
         3y7m6+CNLpntxBkIXdyxwS2Abtj0V0s+upVGls8AF98u88q3fTG6ZIsf42fNE1p0kYvK
         ATeL/CQ125oxOKGNCqlwZmF1Vo3CkVIApQTOIDxayFVKrW0fpz0TaYBdcU9dFZbBfcux
         qSQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=EusuaLF8noCMxjuHxm3kx7e/afZj9mnhyZBjDCbYnkQ=;
        fh=T9P+h/lKJd1DMubrN92vuItw97N7xIpFxDQsVJmViT4=;
        b=zKKw3yNSRb++8zzJUe3eIKUDv7S3uVivOIhUAs2IYtHi6ZfTvjQLBEPbUXgRHs29JT
         SQWMADtVX/NZCHGVtZMrPhl8uOulMwPVvfghGmt0+j+GmEp+ZIQQeGmLiyCJmyNcP4Pe
         JxlLtnbs/0dpsFyM1qIiH2GPICYgSXBOrvYAVTIl6ruXoA2fWgw6fQF9m9MBUMD2BVs1
         WhsTunT1dRuHluzHICLtWk2xtqNsFEsiuYmgs1y/JUEpUVN7Ir73ih5T4PeoXKzPk1Z5
         hYtuArMTIw5muz/pG6jOygvhtr4rDLbmh4P5/kPhq/+Zknk42HEMLkronq01nmxosPT1
         uKUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/G+nh7M";
       spf=pass (google.com: domain of srs0=kuxv=mk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=KUXV=MK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715101007; x=1715705807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EusuaLF8noCMxjuHxm3kx7e/afZj9mnhyZBjDCbYnkQ=;
        b=w3Bjr2Tr+qHWKacE0s91ap/OKnqGXMxNA1c07L1kDCcZx/QGA3Srr1RIBu6AZoet3g
         4IpnrfDVR5tQ07yTKSERDX3iA9A1o9ZlFriZFD/zBTZyWWSL8HEvEeyyNEimuJdyKMbD
         vJ69rxxQbI5D/u7JgF1ObuyCnV3uRGAi1pNMkKUw+6SDlwYHS+z075PrQC8mCCc5vqni
         F4EQwCrvwA/1Ujbhu21IZjWNs3M+pxlXmYjFQkByXEL8q4bKKP5G9mQu/GHXtdIQVLOR
         yOOMH/RxVou4QR2HTZBnIPYCHmBzOqpA9yGd2dIkVRJ9nU9+vQ7Ne7y7/buyg06bSKIU
         +ZQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715101007; x=1715705807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EusuaLF8noCMxjuHxm3kx7e/afZj9mnhyZBjDCbYnkQ=;
        b=ttvSNYGILX6CpwzVeDfZ2YBrO0SR8DoXnE/cJSfEKQgh6F4l/kElExYRlb2my2Yz2j
         dRjDcRxM5n4KEXEqMLtvs7tJHlCXi6fTNxIQp4LHd2PW9KD0FjuEgHduZMNPtO9NIs7V
         VUlwgbwcJhIRSuSwnwKafWj9ZuJ1h7yIMxirw3m/8Wt/YDbDPWcW7vIB02F/W3VJUfpH
         ZM32Pzr3zGP1idqGbO19Ni+GnFcp0AzwCfkZGRxmmpzoQD0CdZoWxT1teKn1bNlde/mu
         MvkUm+CEx+DbgakadOPpY/PME1IkZ1jc/2iXVjGsU5LsDuPgKlWsr9Q5IlVKL4Mi8rDr
         J7HQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWacWUwik5/pLapleltaZmtG7CGOFD6gCEvZmfaHkNzQ4rPnb6QfF56apKQKvCARssIT5u47V9KMrXWvatu7U5myWrQdcL1Vw==
X-Gm-Message-State: AOJu0YwssjWFl8vBMdtav+6eogeMgC2VHuNcslSzT9nE5DZ/eeYVVZhw
	ZiQu+Y9tGdexd5UarprFmtvyh/yb4TBt1D+f22qu8NGvqJ3WLy3Z
X-Google-Smtp-Source: AGHT+IFzG+1oJ+NQaJYqUZ0wJ5ucOPyRysjrpo5TUtKW1PGcRpBcMGY6ZeXzDOJN4d2SQgVTeUqMhA==
X-Received: by 2002:a05:6870:a68d:b0:23e:5c0c:92dd with SMTP id 586e51a60fabf-240979c063amr195815fac.9.1715101007215;
        Tue, 07 May 2024 09:56:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d38a:b0:240:1fca:6433 with SMTP id
 586e51a60fabf-2401fca80ecls1012768fac.1.-pod-prod-02-us; Tue, 07 May 2024
 09:56:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdexOQp11ewVHrf/rvdlY1RZtN8iToc9dCOyjk6CPNvfxVOVWDr9ipBNQd9sm2AHar0WoL/RTm4M/S7AiwFEHJfG2aUHIf0pXHSg==
X-Received: by 2002:a05:6870:414f:b0:239:876a:8fd8 with SMTP id 586e51a60fabf-24096cf6e91mr241811fac.0.1715101006320;
        Tue, 07 May 2024 09:56:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715101006; cv=none;
        d=google.com; s=arc-20160816;
        b=jUESrwe7CnyCQRfra8m18BjUn7tTvVxYggX1QJyqltILmf3+vKzCeet20ughP0wwFN
         kWmGtQGCyg7Lz5gA8vsseegfsoTYSXLzBRWtC0gn6QkSbLMa2dHoutLQ1qEm0Ur++Wid
         omG/Q8J+VDvEdzQTGSCAMwBnsF0KQFzQGTISuQuAlna6ZVRG3piFhrFiWcEO/6hjLex3
         6vlILa1CZ8LKIsXJSyKRJYTnNbt914MkOp5XqPvwFoWY4nU+uXcsUPx3uoEGrkxuZm7f
         peeEcaewYXmGrTWHmAqOddn9r6+DQV+KioJWpdz2Hik/0vCu2oLlz7A7DAq7Frfvlq0B
         AY0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+EMAYasugQJlF/eIJC9doRqtMdUsWD58uq5OF+PT44M=;
        fh=da2oyvUOV2BW9gyf5zGIr+iw3AXc8Nd7+4aoYUaZj+s=;
        b=0uDHw1jySD9TmPFbmmlCA3BcN1v43GFbsUoq+R1yIXFvAUzq64gmg9uDmD9JRAhIjM
         xrvkAFEzMzvIDMiWzQUTpZ25qPih44WKRUokE4UQ0bq8PpNQSppyYuxieMlGbBfAtris
         eQ5FHu9/v4Da2EzscFcOA/ghbCPYBgxJ5pF+ThOUF4BQiYfxARLJRNlyvzX7PBwihxwJ
         VlgKSKhtrdNQOS6Gd6tqgC0JeDizV1RoAqnxJC7D8MwPl/shMGaPyPS9iLq/X2AEDg0E
         VLxHI6j7MXvihgOTVb9aQsTA+IRHlvkUbpuBb4ucOOouHKOzactYgDeNSK6saO4ZAEJs
         LVZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/G+nh7M";
       spf=pass (google.com: domain of srs0=kuxv=mk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=KUXV=MK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id hi9-20020a056870c98900b0023c15c423c7si976185oab.0.2024.05.07.09.56.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 May 2024 09:56:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kuxv=mk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1538A618D6;
	Tue,  7 May 2024 16:56:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DAF1CC4DDE1;
	Tue,  7 May 2024 16:56:45 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 839E3CE14CC; Tue,  7 May 2024 09:56:45 -0700 (PDT)
Date: Tue, 7 May 2024 09:56:45 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Subject: Re: [PATCH] kcsan, compiler_types: Introduce __data_racy type
 qualifier
Message-ID: <f140eb01-fc94-478b-8931-3e1d281949ce@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20240502141242.2765090-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240502141242.2765090-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="E/G+nh7M";       spf=pass
 (google.com: domain of srs0=kuxv=mk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=KUXV=MK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, May 02, 2024 at 04:12:17PM +0200, Marco Elver wrote:
> Based on the discussion at [1], it would be helpful to mark certain
> variables as explicitly "data racy", which would result in KCSAN not
> reporting data races involving any accesses on such variables. To do
> that, introduce the __data_racy type qualifier:
> 
> 	struct foo {
> 		...
> 		int __data_racy bar;
> 		...
> 	};
> 
> In KCSAN-kernels, __data_racy turns into volatile, which KCSAN already
> treats specially by considering them "marked". In non-KCSAN kernels the
> type qualifier turns into no-op.
> 
> The generated code between KCSAN-instrumented kernels and non-KCSAN
> kernels is already huge (inserted calls into runtime for every memory
> access), so the extra generated code (if any) due to volatile for few
> such __data_racy variables are unlikely to have measurable impact on
> performance.
> 
> Link: https://lore.kernel.org/all/CAHk-=wi3iondeh_9V2g3Qz5oHTRjLsOpoy83hb58MVh=nRZe0A@mail.gmail.com/ [1]
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>

I have queued and pushed this, thank you!

I have started testing, and if all goes well I will rebase this on top
of v6.9-rc2 (same base as the rest of my commits for next merge window),
merge it in and push it out.  With a little luck, this will get it into
tomorrow's -next.  With more luck than anyone deserves, today's.

							Thanx, Paul

> ---
>  Documentation/dev-tools/kcsan.rst | 10 ++++++++++
>  include/linux/compiler_types.h    |  7 +++++++
>  kernel/kcsan/kcsan_test.c         | 17 +++++++++++++++++
>  3 files changed, 34 insertions(+)
> 
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index 94b6802ab0ab..02143f060b22 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -91,6 +91,16 @@ the below options are available:
>    behaviour when encountering a data race is deemed safe.  Please see
>    `"Marking Shared-Memory Accesses" in the LKMM`_ for more information.
>  
> +* Similar to ``data_race(...)``, the type qualifier ``__data_racy`` can be used
> +  to document that all data races due to accesses to a variable are intended
> +  and should be ignored by KCSAN::
> +
> +    struct foo {
> +        ...
> +        int __data_racy stats_counter;
> +        ...
> +    };
> +
>  * Disabling data race detection for entire functions can be accomplished by
>    using the function attribute ``__no_kcsan``::
>  
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 2abaa3a825a9..a38162a8590d 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -273,9 +273,16 @@ struct ftrace_likely_data {
>   * disable all instrumentation. See Kconfig.kcsan where this is mandatory.
>   */
>  # define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
> +/*
> + * Type qualifier to mark variables where all data-racy accesses should be
> + * ignored by KCSAN. Note, the implementation simply marks these variables as
> + * volatile, since KCSAN will treat such accesses as "marked".
> + */
> +# define __data_racy volatile
>  # define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
>  #else
>  # define __no_kcsan
> +# define __data_racy
>  #endif
>  
>  #ifndef __no_sanitize_or_inline
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 015586217875..0c17b4c83e1c 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -304,6 +304,7 @@ static long test_array[3 * PAGE_SIZE / sizeof(long)];
>  static struct {
>  	long val[8];
>  } test_struct;
> +static long __data_racy test_data_racy;
>  static DEFINE_SEQLOCK(test_seqlock);
>  static DEFINE_SPINLOCK(test_spinlock);
>  static DEFINE_MUTEX(test_mutex);
> @@ -358,6 +359,8 @@ static noinline void test_kernel_write_uninstrumented(void) { test_var++; }
>  
>  static noinline void test_kernel_data_race(void) { data_race(test_var++); }
>  
> +static noinline void test_kernel_data_racy_qualifier(void) { test_data_racy++; }
> +
>  static noinline void test_kernel_assert_writer(void)
>  {
>  	ASSERT_EXCLUSIVE_WRITER(test_var);
> @@ -1009,6 +1012,19 @@ static void test_data_race(struct kunit *test)
>  	KUNIT_EXPECT_FALSE(test, match_never);
>  }
>  
> +/* Test the __data_racy type qualifier. */
> +__no_kcsan
> +static void test_data_racy_qualifier(struct kunit *test)
> +{
> +	bool match_never = false;
> +
> +	begin_test_checks(test_kernel_data_racy_qualifier, test_kernel_data_racy_qualifier);
> +	do {
> +		match_never = report_available();
> +	} while (!end_test_checks(match_never));
> +	KUNIT_EXPECT_FALSE(test, match_never);
> +}
> +
>  __no_kcsan
>  static void test_assert_exclusive_writer(struct kunit *test)
>  {
> @@ -1424,6 +1440,7 @@ static struct kunit_case kcsan_test_cases[] = {
>  	KCSAN_KUNIT_CASE(test_read_plain_atomic_rmw),
>  	KCSAN_KUNIT_CASE(test_zero_size_access),
>  	KCSAN_KUNIT_CASE(test_data_race),
> +	KCSAN_KUNIT_CASE(test_data_racy_qualifier),
>  	KCSAN_KUNIT_CASE(test_assert_exclusive_writer),
>  	KCSAN_KUNIT_CASE(test_assert_exclusive_access),
>  	KCSAN_KUNIT_CASE(test_assert_exclusive_access_writer),
> -- 
> 2.45.0.rc1.225.g2a3ae87e7f-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f140eb01-fc94-478b-8931-3e1d281949ce%40paulmck-laptop.
