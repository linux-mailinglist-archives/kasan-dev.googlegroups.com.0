Return-Path: <kasan-dev+bncBDV37XP3XYDRB4PI3CGAMGQE4GI3UVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1208A4559B1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 12:09:38 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id r6-20020a1c4406000000b0033119c22fdbsf2453003wma.4
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 03:09:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637233777; cv=pass;
        d=google.com; s=arc-20160816;
        b=hlpCEtVAOCsN5fsQEzlhB9R6rta+PJhY2P1qjC5crfcCcC5P1Hq/E4qcrzu0RPwm4w
         6maSE3z3Iakjjr5A6Xbn4xsCW5lvQK7v+5yBQxTYMzARFzz60GoTYxEVVCd3ScBDCwwE
         EtJMhsKKwXB9oyJb7lJhUYsSNddmNaCU8JVD9zw2p9CZQrxJMyxrd/ZkC8U2bwff1imD
         9s9VqF1PkWSD+OMgbMwBuZhmpZug7DhmoDNAlz0JKITu1pWIke878mWaEGIf0Bo4fLlF
         FZaUhzI23D5tmVYF/aquVTHn8Cz0T2M94im/3kkNlN60KCG5LMhQh9U1XpMJo4aZYfa3
         bAjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=g/U1pxZAThCOSWO42pJTkHsTnkYDViBZ3MvW4ree840=;
        b=SYtNw48ZnsG8bCkiwKI1Pckp+LbYPGaRAD7jbtTG8q5nchnV6G0y2ZnowZ7VGzx/LU
         qoYQjlVYN1Kzi7N130DNLb9dTN/exVgXGIWdkdOTHA5gIMeQmhzytxumUqPlJ1xKt77D
         yv9kAXgT999AxpBQVPJloaWgMsMEB0bIPa9dz9DdDOlu/BVwHU+6D0F+bqOMGxeRzKsI
         8B/DoHJbgSVGHwqNKHiYBvM3IMaQkS5VEFnXI+HkCuz+n9ZHGC7zGRof1qw7VO1zB0t9
         Uv42dLNbqMz0byHQ3MOFaftyR3cz7HtIrgPsVxOw1fdIbdhDlm6lkHQzohQtdACgFCGi
         JCyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g/U1pxZAThCOSWO42pJTkHsTnkYDViBZ3MvW4ree840=;
        b=m6ZNhryGPYuJH0NEIzFkHZmrYWpyHwepCr1Wbks3uahhC3LHGqSZRD7AcZ8fcDMswm
         DfW4pmWML2NftsNZns9wz27Fqx4BPz+fHhUEXAbrXE1S3696QM+aJ39RKqFHY+q8N8MS
         OkZ0VxjmAaiaTATRDNhFD8FKihEGsCRCvu1qtBBEjg3+vb9pQwkZNN+jDKe/9BcRARuV
         Upvw08Fq9ITT6LY+eb5H0QO5lIAH5TQwPaMklYIRfQtgIE3Fq2fzFT6Y1bVHARneYB5d
         eegMHd1ju70fDY/VjbBI9LYYjJZb284lwYsVFk8dvRQ/NY1VCWti46rdpNaAJOATa2hK
         0vXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g/U1pxZAThCOSWO42pJTkHsTnkYDViBZ3MvW4ree840=;
        b=rFr1bfgzgKrigxzzAQWL0n8A31dS6Vbm8vt8xG3VxXU2uu9FzEBBZeiPq+GiRQ9rtn
         av/soQeiASjiW5RY73zfsU/bWC96eY/I8yx+ooxqTJMQsWKtM2gUCycU9La3nWS16f9V
         KGY1YDLPmzRWD8NJLJe81+BRq2XUjpOExaB4dL1a+oc0pkGGdHMhy7RLSPEuTen/oLAn
         adoFgGaGF5Ej1YL9Tda3haN6hwYjShNg4LvS3coRnNHkmV1tsgqoL6cCGsK0mtT+yqjg
         z9p4spI/JH6NjGG3WDT8KUbCq+bq6eI0fgmY/nFadnU92v9bHkmqrR7uIWBFJgtrAmtP
         l7ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/wnK1JtWrBIChEKqsdFZoWTW3sLLP3Y5O/bCr+YuAXu8EgDhW
	66Kc9tK9tDHIlQ7rN7TUJjg=
X-Google-Smtp-Source: ABdhPJwkpvjCsGZoV8kJMXYZgzfuiGLYXpfbaljzfFiAc80uFRuNRmCMeWnlhAk4O3Zj6SH6OlT1FA==
X-Received: by 2002:a5d:6152:: with SMTP id y18mr30181252wrt.271.1637233777814;
        Thu, 18 Nov 2021 03:09:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls3049312wrr.0.gmail; Thu, 18 Nov
 2021 03:09:36 -0800 (PST)
X-Received: by 2002:adf:d1c2:: with SMTP id b2mr30344943wrd.369.1637233776751;
        Thu, 18 Nov 2021 03:09:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637233776; cv=none;
        d=google.com; s=arc-20160816;
        b=Se9YwIccSLC1yjfQqknJ5pEAkkUWoGlEWqiXUTjaslk5FHyE/L1TiwijI3z9FzPZXj
         CCI7gWpDSOsAuzPXVzXQzNT1GXmlxbG39G6w9f8mTKL8scxqySwMC/uQNiRvfMNVo1xx
         h3kAmLIA1Oh1AEBO87mhJOEi8dJx1bnnE+csfm9ZxU+ruBjcYCr+EEd3Z5aU+xPH6k09
         F50416+Ijvo7KsehE9ijf0jQhfBSNO6XwY3DyFRD4mR7NOVUQsOMQ/p4Nmj3f0UoijOQ
         i8DEqtoM8ppmJRTEpiFxqf2v3Om0hwXkqe7ng0p5b4zk2u+iMhlBDPnwV2mY/OxIo9tS
         BOIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=WjRKTFUMYfLD2lR7e9VkwRwtbg3YIQKufVeatWZNt3I=;
        b=E+3FL2aP/a2IWlLbXZT+MJXF86TVEg2GDPGxAeHIs1L/a5KXkKvUyvUKaab2JN9lDc
         Dwy3fDIAZo+vjF4r9gmNh/tn3FVLz2gCwXJnqLZVnKmeS+MdG05WWeptgrb4IzWlulfl
         CVmsmNQ5jltH0MrrPMCUhdNOo2vGXMijCIdXxZ0mMVoTiDJKUOwTn7vgx/3X2kV/4h+D
         xM/QAq6OpjM++11sOUEEay+SP956sM+rD6OExGG9aTpkzWk5wAWcIwN6pD3Fh8CK5aPK
         YwkqAIo7H3afQdGx2JgqHSvzU2BHzMpHp7YENQPqf/IqmECnR2HUBFAk7HMVRY8mlVsL
         5QKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s138si612600wme.1.2021.11.18.03.09.36
        for <kasan-dev@googlegroups.com>;
        Thu, 18 Nov 2021 03:09:36 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EAB671FB;
	Thu, 18 Nov 2021 03:09:35 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9C2123F5A1;
	Thu, 18 Nov 2021 03:09:33 -0800 (PST)
Date: Thu, 18 Nov 2021 11:09:31 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 02/23] kcsan: Remove redundant zero-initialization of
 globals
Message-ID: <20211118110931.GB5233@lakrids.cambridge.arm.com>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211118081027.3175699-3-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 18, 2021 at 09:10:06AM +0100, Marco Elver wrote:
> They are implicitly zero-initialized, remove explicit initialization.
> It keeps the upcoming additions to kcsan_ctx consistent with the rest.
> 
> No functional change intended.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  init/init_task.c    | 9 +--------
>  kernel/kcsan/core.c | 5 -----
>  2 files changed, 1 insertion(+), 13 deletions(-)
> 
> diff --git a/init/init_task.c b/init/init_task.c
> index 2d024066e27b..61700365ce58 100644
> --- a/init/init_task.c
> +++ b/init/init_task.c
> @@ -181,14 +181,7 @@ struct task_struct init_task
>  	.kasan_depth	= 1,
>  #endif
>  #ifdef CONFIG_KCSAN
> -	.kcsan_ctx = {
> -		.disable_count		= 0,
> -		.atomic_next		= 0,
> -		.atomic_nest_count	= 0,
> -		.in_flat_atomic		= false,
> -		.access_mask		= 0,
> -		.scoped_accesses	= {LIST_POISON1, NULL},
> -	},
> +	.kcsan_ctx = { .scoped_accesses = {LIST_POISON1, NULL} },

I'd recommend leaving this as:

	.kcsan_ctx = {
		.scoped_accesses = {LIST_POISON1, NULL},
	},

... which'd be consistent with the DEFINE_PER_CPU() usage below, and
makes it easier to add fields to in future without needing structural
changes.

Either way:

Acked-by: Mark Rutland <mark.rutland@arm.com>

>  #endif
>  #ifdef CONFIG_TRACE_IRQFLAGS
>  	.softirqs_enabled = 1,
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 6bfd3040f46b..e34a1710b7bc 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -44,11 +44,6 @@ bool kcsan_enabled;
>  
>  /* Per-CPU kcsan_ctx for interrupts */
>  static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
> -	.disable_count		= 0,
> -	.atomic_next		= 0,
> -	.atomic_nest_count	= 0,
> -	.in_flat_atomic		= false,
> -	.access_mask		= 0,
>  	.scoped_accesses	= {LIST_POISON1, NULL},
>  };
>  
> -- 
> 2.34.0.rc2.393.gf8c9666880-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118110931.GB5233%40lakrids.cambridge.arm.com.
