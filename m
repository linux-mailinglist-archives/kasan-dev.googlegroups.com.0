Return-Path: <kasan-dev+bncBDAZZCVNSYPBBEX7TH3AKGQEVKGEZII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2285E1DCDD0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:18:12 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id q1sf3388580oos.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590067091; cv=pass;
        d=google.com; s=arc-20160816;
        b=T/TMZEgVAd0b+nB4AGOszerFydEgVnFqY/CWZSAeIt2mhcJYdUnkHwS5UnWY86gGuF
         /9HHaDuHpnkGqBfGDsQf1+xdz1RSUZv9LI/2Y+RP1gtJeiQoN7KEERFtmmHkHZnKe+ni
         vFJwYwMo4K/uuUNZ5EnR12HMEY0CkBlhCWTd+PGCt6zb9DPmZAi7HCqKOxR/sf7V2gw+
         /lLtXOaHonEQknD8BDsBOi8BoUty+RfU2OFw+Xv3G2OocUPMRp+RyjGTCh45fJBD7hXI
         ZRr5JDAWf5CyZ21ExPzFiH5e8j3U2a5tTstYh/i9+YRRptPLEF1h8cuVfgoKEwlFFp8F
         fNTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=MHfXpUOb87C54qqTDCZqHPIo0lxmBmIYyb0jsFDAxn0=;
        b=hY0+jDKwSVZ/+k5QEBrq3uP22eJBf0JpAfwhei0eVkwYog9+xT2csJeeEhRhHFMc6V
         0LzPOJc0qony5jTmodxT8l8HfFqMtI2ykyvAyrSZ/R9XXV3s08hGfw/FhQ62M/Jz8gvE
         0OltjeEuYTe3kYMrS/vxo7Xqnceftm8vg3nV6nXxyo+dSk3mfzmKg4CEl41ae0L6jHaH
         HuVXlH/W2IgGYKu2RPJZjgPZXP9wm+3Txz3dtdmOfqZz3pXcb8lCtGgbe/2g/DAeALhk
         mZi0OFzjxtZXwmY0eJclnm2f2PDxtF287V8omHYvHa8Zp6gs6//LK5Es2TCtKCzMZBh2
         S6fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MM5SHFs0;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MHfXpUOb87C54qqTDCZqHPIo0lxmBmIYyb0jsFDAxn0=;
        b=EpjWMfHxhywRVQnrIoQTJuy8h8XKkzusFkCwiIbfpv1achDQLNzRJcYKw8m6ljgz45
         urrVVQmLvfoHtipM3ilTLuibiBMUwiDUxyl1YkPPvfAqSF/pXZ+z+iunlqe++woHZHzz
         3HL0A71eSDzlkka/ej2Bn5wiW3nd8IPuR3atyKsdaTbHQ3An/Hx1naOmQScuWUj7cTse
         Z3YZrbPlZlDTUKNYmq/KyBJoQkN/VLI3P3L4pH7T1J6rLOskGInSwYJE11ROduC4lEZm
         p1Lx1s3x6SCjv1zvsIhrE7OT+FOMnsyHHq6tmxgXOkFRmP1sRBa5eRom7lNW0SMgtumC
         aQZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MHfXpUOb87C54qqTDCZqHPIo0lxmBmIYyb0jsFDAxn0=;
        b=gAD+CNv94J3R2KCtAXC+36ps8O+4xw2dD0c+eQkw79RlSMwK2o/iW4She81CkXWgTH
         FlkD/A4emxD+WTDN2IbIbRdlCcTEStTlc5gUAHpbzkdoqb3OTGMauo15YYYyq/JFtUeH
         PIPXSgYpK9kjjCNKle/k6nPM7c6Bb/kYwCRLDJBWXx95Px097PpTJu3Ng8sp0pr4DNrd
         e9qvSELxjxZeXEDl65ly3pLJ0v4R6Dr7HOpw/Nz4Tf+LyEJ8tywCWWzk2YNAW7A3Rhpi
         s9oCSuCkhwPFQjgOxzun0HDecRSRUzFxwAnIt7GAs0H/0LvUE25kwleFMqx7yZXykzH2
         oqNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FZ7vGSr1SU8khKMSp61I0iYV/M+1y/H5F06JbqAy2lDnJ8aLP
	cfBWaG/5fSOgdgUlbIcx/NA=
X-Google-Smtp-Source: ABdhPJwCRg5urHEruKNbAVWplfwOlNY3kTU6PKi7UyhCTucQ4Crw1+0AQBSJGX89ZqDmZnuK4osWlw==
X-Received: by 2002:a05:6830:210e:: with SMTP id i14mr7014829otc.284.1590067091002;
        Thu, 21 May 2020 06:18:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3147:: with SMTP id c7ls447567ots.7.gmail; Thu, 21
 May 2020 06:18:10 -0700 (PDT)
X-Received: by 2002:a9d:4689:: with SMTP id z9mr2554070ote.266.1590067090570;
        Thu, 21 May 2020 06:18:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590067090; cv=none;
        d=google.com; s=arc-20160816;
        b=SEbXdETnFOGCwA0mwsSz6+j6n8ii2NXzZFXhj3ykrNBI6Rc4Obfq6RfoAFncISSetL
         ZmdxkB7eN4tE2gyEKNqLk+kNnW+3c/PQ252w1XvzwH+ZnN/AqxBO9TmZ8HCI/e3cAbJe
         PvGe7NNFKqO8/CpAe9e4iqF6AIT7vT3we2EyZyrpIKZ8UKzpdiwprZxHkLstGoi68ip6
         7cJkCqgL4Uufw+LaVTWgEKMfOV6ZZRTA+h5+O7zkoZxIaj95r9ac7BHfRgD5j0ZGxIYS
         2ZQczCO/k+1MOczimw4Wcl2QJehgaxeHFyuR2o/c5w+A2StgpzCdUsZam3Awu/grrhGb
         3p0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SkkhyRh2GOF9j3JhBd/woc8MU/INH88dpxNU85NcE7E=;
        b=taiOKvRsvvVlWi20OLZW1GYmcn12Jh1E1nZ3Vv09iLgvGfwNidhpxRpXKh61oKxgFI
         L4AUpatpA1xJyHgMl+lA8YYJZA8jBl7H8gBzvNkvr9edhB3VwobA4F/Xml21e/G+6JsH
         hqG0JLzaBcTRVRLbAzjcZXS9PiR56B26K8/ypQtHV3h0CUN66feIiB1K0uuOh0lnbdEF
         LoQTCtWdq26EutVtgvR531PZarLslyUluZL7uDypZbLaBxN+nfP9fim9cT+YrfO221np
         TD5vRNbArRcE4ZZjgxtOzuRxno+mO7S2vq8owUSQ9f6L5DNtZlbM57HK8LDBRq5/ipRL
         bJMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MM5SHFs0;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f197si433346oob.1.2020.05.21.06.18.10
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 06:18:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B8A6B206B6;
	Thu, 21 May 2020 13:18:07 +0000 (UTC)
Date: Thu, 21 May 2020 14:18:04 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org,
	peterz@infradead.org, clang-built-linux@googlegroups.com,
	bp@alien8.de
Subject: Re: [PATCH -tip v2 03/11] kcsan: Support distinguishing volatile
 accesses
Message-ID: <20200521131803.GA6608@willie-the-truck>
References: <20200521110854.114437-1-elver@google.com>
 <20200521110854.114437-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200521110854.114437-4-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=MM5SHFs0;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 01:08:46PM +0200, Marco Elver wrote:
> In the kernel, volatile is used in various concurrent context, whether
> in low-level synchronization primitives or for legacy reasons. If
> supported by the compiler, we will assume that aligned volatile accesses
> up to sizeof(long long) (matching compiletime_assert_rwonce_type()) are
> atomic.
> 
> Recent versions Clang [1] (GCC tentative [2]) can instrument volatile
> accesses differently. Add the option (required) to enable the
> instrumentation, and provide the necessary runtime functions. None of
> the updated compilers are widely available yet (Clang 11 will be the
> first release to support the feature).
> 
> [1] https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> [2] https://gcc.gnu.org/pipermail/gcc-patches/2020-April/544452.html
> 
> This patch allows removing any explicit checks in primitives such as
> READ_ONCE() and WRITE_ONCE().
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Reword Makefile comment.
> ---
>  kernel/kcsan/core.c    | 43 ++++++++++++++++++++++++++++++++++++++++++
>  scripts/Makefile.kcsan |  5 ++++-
>  2 files changed, 47 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index a73a66cf79df..15f67949d11e 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -789,6 +789,49 @@ void __tsan_write_range(void *ptr, size_t size)
>  }
>  EXPORT_SYMBOL(__tsan_write_range);
>  
> +/*
> + * Use of explicit volatile is generally disallowed [1], however, volatile is
> + * still used in various concurrent context, whether in low-level
> + * synchronization primitives or for legacy reasons.
> + * [1] https://lwn.net/Articles/233479/
> + *
> + * We only consider volatile accesses atomic if they are aligned and would pass
> + * the size-check of compiletime_assert_rwonce_type().
> + */
> +#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
> +	void __tsan_volatile_read##size(void *ptr)                             \
> +	{                                                                      \
> +		const bool is_atomic = size <= sizeof(long long) &&            \
> +				       IS_ALIGNED((unsigned long)ptr, size);   \
> +		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
> +			return;                                                \
> +		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
> +	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
> +		__alias(__tsan_volatile_read##size);                           \
> +	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
> +	void __tsan_volatile_write##size(void *ptr)                            \
> +	{                                                                      \
> +		const bool is_atomic = size <= sizeof(long long) &&            \
> +				       IS_ALIGNED((unsigned long)ptr, size);   \
> +		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
> +			return;                                                \
> +		check_access(ptr, size,                                        \
> +			     KCSAN_ACCESS_WRITE |                              \
> +				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
> +	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
> +		__alias(__tsan_volatile_write##size);                          \
> +	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
> +
> +DEFINE_TSAN_VOLATILE_READ_WRITE(1);
> +DEFINE_TSAN_VOLATILE_READ_WRITE(2);
> +DEFINE_TSAN_VOLATILE_READ_WRITE(4);
> +DEFINE_TSAN_VOLATILE_READ_WRITE(8);
> +DEFINE_TSAN_VOLATILE_READ_WRITE(16);

Having a 16-byte case seems a bit weird to me, but I guess clang needs this
for some reason?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521131803.GA6608%40willie-the-truck.
