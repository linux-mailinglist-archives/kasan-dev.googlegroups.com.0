Return-Path: <kasan-dev+bncBCV5TUXXRUIBBD6KTXWQKGQEAHMEXSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B604DD9963
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 20:44:32 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id a130sf10038894vke.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 11:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571251471; cv=pass;
        d=google.com; s=arc-20160816;
        b=l4BKKivyZ4j1ZdhOWZw9aOsFpu7HkPvRVJ8GihLhzYcumAEMvYkM85rpFk0Lno5yG6
         Rbly39TRRDGnDrHa7F1mt40Z8YgVW3mWFV3fmnb+kh52wNJk4ryuyIvjY7XqqXaYsDqe
         8sehyGpahiGcmNUY4Zea+KJVavq+Lxs7xQWkp+SEwQNp/troV2jJD4LXm8/QKkh0C++L
         wv7eCsLv2co64mcobutlK3H3EGGoI51q814xOHnnrxR24izxbB2gKeMCv/lwDG9vKTsK
         IYV6qmXAFA/a2fZPUafsht6uvVI43uxbIPlTF6JvLRRSG0t3dHLw/KfLRbUDxv9OpViu
         Sf9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DoiKbosMEiCvS53aaqtrG0Cr1FqKQ63+QeVsAIIjwPU=;
        b=d/OgMBUrm1ohf8A0Cr08cU3Xx5IfBJ5smDloAsr9kmPAnaXCXb2FGKStK4Q7oj26Tu
         yckmzPIodPN+1ib6QTMISJWRGPy4Q5oTdTEVPcVbNqHLSwl42232S6qz5MnWc8zuAjvw
         6UijmWRsh3F+KjxbtUNsElsJgwEoosf7rjRnmoUybYpfyu405BaCSNFJ5k4R6H7algZY
         51NOjCg0xdo+o2A8kKrZmUzxBhEgi/9psUsXCBHqxm8d2TcJNzpw48XSLmCPYDX9wphU
         k/hgd71eHA/4pZHqpx/3RcsBwaQYlxYnCH7s2fnzSDP/wLTblNItwAcDMmsJa5sCnjro
         fXEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=RUtfEOh4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DoiKbosMEiCvS53aaqtrG0Cr1FqKQ63+QeVsAIIjwPU=;
        b=GQHN9WAUIUHnOUGvLY5ms65Q3aouSuiUPyVlK1e5Qy0xj6kH7BJdIHSrPBm/9BIhrO
         DtX9BwOtRm4RAaVKUUjcWEesgHqJlt/z/lr9LBnFuMzlBooBFzsiPt132PMYKhgxrAYa
         To13QskZDvwqOKIAPG2twzVTCZZuxDWSLdsMFvpCFg9uIH4v2DFYQnTzc8D1IecfdYEc
         n5qhifXuCHOCfXBqmW0RD+vIJPTErBrsVQTqMMh9PdCFfWEoNCRyOV+ypkJZmNRF1dTK
         1B7E2kXQFKKRjoXoYPHwjRdMKz0u86AcqzRfj0qJeJi9JB+or2rzKwuiintaNYzQJyGW
         AXQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DoiKbosMEiCvS53aaqtrG0Cr1FqKQ63+QeVsAIIjwPU=;
        b=TtUzY6lMsD3NNqxq0AcYXsTDVgXh7u6UyBNqUkoUdb0FZ7s2qkE0mBiZDYxgJ19ZOD
         XAkNP29izgDd36kjubu+vjI0nNFlnQdAYIDUhBm6/qcp8JOs7MKUgKDMhRXn8KjtW0pF
         m41woo9s56OxtJk67uHgupwxybLpDHkeq8h61r2jDOc9VnFAqlErDfhGheopxtFniIee
         nMxJeg2ASzem1yOQVuEfDXOvyK1md6vhB7ddJFGkmzsh+2oth6hrpce/a+7Z+ab45erc
         nYvcHWeuzNAlMJxYB84orU0rPSgSwMt9FEwZjkzTiwVz6+8D8ao+/gTOY70N/dOwNHkE
         nXdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU1qorrXcMrwUsG8rX7GMDyCSa85p/Wd3p8CtdVhnXK1h32Duhh
	6bCYz0aad7Sa3oLzXKMUtWs=
X-Google-Smtp-Source: APXvYqy9K/Wewi6olwBZBlb8iZ7HMTvpd/OEJIreO08AxfmLmwmPXJaM46Qijgc8ZxWHX2Zl+NJgcg==
X-Received: by 2002:a1f:1881:: with SMTP id 123mr22700724vky.37.1571251471508;
        Wed, 16 Oct 2019 11:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c883:: with SMTP id v3ls2238612vsk.2.gmail; Wed, 16 Oct
 2019 11:44:31 -0700 (PDT)
X-Received: by 2002:a67:6911:: with SMTP id e17mr25035436vsc.44.1571251471049;
        Wed, 16 Oct 2019 11:44:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571251471; cv=none;
        d=google.com; s=arc-20160816;
        b=PE1W4fFK7QlrtAk5Mm3A11Gxi9+lxlMQTYkXVkj6x3so78FGb/i1sXDmwzDtY4+14N
         3YGOYTFTpuuzNujFu6OCUfZdj2pnCnIorNrzIevizIlT4e58saLAWDgOVyPSGf+6OM8S
         7drwkc13Bwiu3mcltSkGOzBRv/c86/zZLL1dyEmZsePa7aTf3wX2k4v/VpGTuSZCoNqE
         ZzxF7hFQVc9A/IAxvSfsESmdCLKwUzCnaIwuHLLZeYYN2cFW/w0HaEEsybRE2UDv/Wr+
         dp3XU7qkeW1M7+pp2oueOhSQRCE6DHGkdGa0uQ/vKN1/wKWCUVWecOZ8UKONlxhKuNRd
         sv1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Xkj+IPEJ6D9FNAsOyKv+xxTO5cnYq7m4+bjOEldOn7U=;
        b=SEBEOZt9N4ey0ukNKAJcayzdW/X7dRE7HYImUcWNGdNws34I/OzxsXwAd8P7LKTPFv
         UEDo7BEklwle5byBFzAXLhbRnVfJJCIsfMVnrZkicrOwFS1GObx2KDUJdhYu+vCTiNv8
         Y2VaonSrll140dTKq3Hq9LhowFc83reQgow8IPQUqrJ5FVuA3t/IsFLh+cYeiEPE3n3v
         X8cb1eNf4oY+N18hDwq7Q9hvC/AdEixpVglOpxST4CZDST5MTtLjBGcVjXhkwcmfUWC6
         XyKYFGxvnqW4KMWDKUm6Vr7stMULoml2fKeJEg6G9ZRiB440lSt4rNVgXqyyNgy7sBPD
         LoTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=RUtfEOh4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id u196si801351vkb.1.2019.10.16.11.44.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 11:44:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iKoH4-0007gT-0F; Wed, 16 Oct 2019 18:43:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E1E46303807;
	Wed, 16 Oct 2019 20:42:51 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C50B629E86612; Wed, 16 Oct 2019 20:43:46 +0200 (CEST)
Date: Wed, 16 Oct 2019 20:43:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, paulmck@linux.ibm.com, tglx@linutronix.de,
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191016184346.GT2328@hirez.programming.kicks-ass.net>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191016083959.186860-2-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=RUtfEOh4;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:

> +bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
> +			      bool is_write)
> +{
> +	atomic_long_t *watchpoint;
> +	long encoded_watchpoint;
> +	unsigned long flags;
> +	enum kcsan_report_type report_type;
> +
> +	if (unlikely(!is_enabled()))
> +		return false;
> +
> +	watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
> +				     &encoded_watchpoint);
> +	if (watchpoint == NULL)
> +		return true;
> +
> +	flags = user_access_save();

Could use a comment on why find_watchpoint() is save to call without
user_access_save() on.

> +	if (!try_consume_watchpoint(watchpoint, encoded_watchpoint)) {
> +		/*
> +		 * The other thread may not print any diagnostics, as it has
> +		 * already removed the watchpoint, or another thread consumed
> +		 * the watchpoint before this thread.
> +		 */
> +		kcsan_counter_inc(kcsan_counter_report_races);
> +		report_type = kcsan_report_race_check_race;
> +	} else {
> +		report_type = kcsan_report_race_check;
> +	}
> +
> +	/* Encountered a data-race. */
> +	kcsan_counter_inc(kcsan_counter_data_races);
> +	kcsan_report(ptr, size, is_write, raw_smp_processor_id(), report_type);
> +
> +	user_access_restore(flags);
> +	return false;
> +}
> +EXPORT_SYMBOL(__kcsan_check_watchpoint);
> +
> +void __kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
> +			      bool is_write)
> +{
> +	atomic_long_t *watchpoint;
> +	union {
> +		u8 _1;
> +		u16 _2;
> +		u32 _4;
> +		u64 _8;
> +	} expect_value;
> +	bool is_expected = true;
> +	unsigned long ua_flags = user_access_save();
> +	unsigned long irq_flags;
> +
> +	if (!should_watch(ptr))
> +		goto out;
> +
> +	if (!check_encodable((unsigned long)ptr, size)) {
> +		kcsan_counter_inc(kcsan_counter_unencodable_accesses);
> +		goto out;
> +	}
> +
> +	/*
> +	 * Disable interrupts & preemptions, to ignore races due to accesses in
> +	 * threads running on the same CPU.
> +	 */
> +	local_irq_save(irq_flags);
> +	preempt_disable();

Is there a point to that preempt_disable() here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016184346.GT2328%40hirez.programming.kicks-ass.net.
