Return-Path: <kasan-dev+bncBDBK55H2UQKRBLVA7HBAMGQEO4ZQAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3495BAEB0DF
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 10:02:56 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-6077af4c313sf1597714a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 01:02:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751011375; cv=pass;
        d=google.com; s=arc-20240605;
        b=KYZnwRTGZmtw9GLrraoiFgLn9W6UGdRPFLkVjQvp3o634+Pjse5Ou4R3ZOnsSIhbz/
         cdxKG9WsmZjbr79WnAov5L8/kbD97hyi2SloE+jE2W0LBMDroFqCh/5Z8uE0kXhGU/uQ
         dGERtqJ0aB7a5lMmTrz4FD1Deu4RmIZmt6AXHs3YOr0i7d2TfkB3vby5q74d+v1vfw7O
         45rWWFZzWYaV9i16WT8SHmYlYjyWbwa5TXr9JIwWLdO9eA/1KE150zvl5DWqvbcMTG5S
         frDCE1ZQE9AoqhLJiehqyLN0CAeAI/CX4r6BclolcChGVuPTUi5M2Ud34L/3Y/MaxDTG
         3KFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ukq+eZM2H3/V7i0d6eo/R4YGEBTseYJKQCZHLBNSpXY=;
        fh=2EsxqvF/BRi4Kax5LhVmvswHd1fPARX0Gky+//7wJGk=;
        b=DijjOwnwGJI3jDhb9UAhuAnQazAE/JlbUACzoWULoLj1OfYcX3VjEXhiSqQX+tCUXc
         hIkdZd1SWkZv4wWWD621FAlRRkrvMnygN0GaknIabu8adc6HleqO9Os7GzoyA3quQmXW
         CXP1BzLX02r3oRK8XIolu/lW1FLH46kbRacZkbDZ4Q5lrQYvm8IZQarPmRBZFFNn2UA+
         Ckotum8fDfgcEV9pVt43nJuEzN/SlS0r9NUonEmpvDvWSKXwkE/YPT0Ihajgg3RdiP/y
         4DNHHMa6qA6FwXh5SSCNtj/8harv078QEBKruCKyiLtqBVf71oLg9fgerljg621paVPT
         /SHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Str6SwuN;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751011375; x=1751616175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ukq+eZM2H3/V7i0d6eo/R4YGEBTseYJKQCZHLBNSpXY=;
        b=SRl+hqiIYrWNS1x925e0DPC+rQVYFPCum2SEdhRlMpMwDid8V6xcVvkhzuOT6+Yc6N
         PaieSpvNfuRv+5PSXODQAePwrV3UIq4DL5mnqlMYVGeqYXZcIGruqbDWnFQ5pQcmzVPQ
         6Y0+85ZQ7qQzYrp37gRpULfmgz4fuDk7YBUjyVxavc52UILGxkvyGjSgu7CbRAbkQYV8
         wgYZsdHZ9wnFkHfE19UTtLs72K7pCpNzRTSN4fSr+zuUABZ5lddUE/M77egq6X4v3I4P
         bQIhgFtyl4bzsQu+S3E26SsTre+svX2Ijuvpxeqik6eljE38hgtq1UFXOPR7qUsZxTQB
         sKkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751011375; x=1751616175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ukq+eZM2H3/V7i0d6eo/R4YGEBTseYJKQCZHLBNSpXY=;
        b=b0mmJE6otuUE3AwQJTmuSkPPWc+PF2ep329l1wI8MBzdkPpYANva/JmMZnM5otqJGY
         9tdaAW1kbWN+TX47KTL0H/j+LM/gnjgO++beiDhX539hNgD5Jr+kEV3IXKfXaVjpMWvz
         ZEJBbt4mjok+jhd44fl5SeKUjWUfejvQCN58c3xuAqe25k3S3AnP9b/Jnz5fhrU+uhxk
         G7D40Rsgmzj8JNLsO55AnBBSba1C5xS2JwnoC5qYf/v9Hil4CRvDPzTzutcPXQvHz+d9
         j9srXi/I7SyM99aGR3f8tTKtX0twX5z7j8ZoITGp4mo3i/MOmIy8WzgwRIihaVQ8XTmd
         EBHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCViefg9jQZn+hu0B05M1zHeg/LrYZ4hzanl8pKeGZndRyQGjiJK7Gt0awqH41/w3+qtXROgAg==@lfdr.de
X-Gm-Message-State: AOJu0YwMTMLBk6PiSX3rLAUrHBXtXlr0yxqttMsUNwvHmVRPqAZFSr6t
	zmysVL12Jhgc6dlQKj1briLcqDZt20bs2kwqe/7k2ld12nLxXcQMHCke
X-Google-Smtp-Source: AGHT+IEK9ZJbi4MFSY6aRZ9SycH13fpJCQ0YSGKuMgKiaJwG949ENUMtESNxlAflTJrf5xI519bjWA==
X-Received: by 2002:a05:6402:5386:b0:605:c570:57de with SMTP id 4fb4d7f45d1cf-60c66f27d79mr5278957a12.8.1751011374782;
        Fri, 27 Jun 2025 01:02:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNkPk9xNiI7SpKqY1Ih2P1gBX5DnYUofaOtUPjNJghmg==
Received: by 2002:a05:6402:34ca:b0:609:aa85:8d81 with SMTP id
 4fb4d7f45d1cf-60c65f82400ls1531905a12.2.-pod-prod-00-eu; Fri, 27 Jun 2025
 01:02:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1z4gHtNmjoo1LUFr/jtVITwiQYLY6IuuOEdkgxvFO8LkTGVeRPAa5x59fvBOQxwNcTXMWCIoQ2IM=@googlegroups.com
X-Received: by 2002:a05:6402:321c:b0:605:390d:6445 with SMTP id 4fb4d7f45d1cf-60c66e000f9mr6713850a12.6.1751011370930;
        Fri, 27 Jun 2025 01:02:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751011370; cv=none;
        d=google.com; s=arc-20240605;
        b=BX/VI0jpeeARVeXYZXDxWgKJdebeJw0cH8dF3s/AgJJuHVeJpDIaKyI+NaYEj0quAi
         okzpGZQmqygH5AJEnK7brttFBG0ggATSSo9gPRsnOId5hN9BeiFnp2B4OxCGog//CPBf
         5f+vUJn2Q2ofU9hvHRBhMUWztfLjz9DsOzsiqlXHMPA5SpXPxLoLweYS8cq0aR14cR0P
         2MMBOsoD2Q58caYhtpgKxboC1i4ccPiZkKOuxjGbcOkKZ3LVJPfKmFyMZghuV1qE5Fph
         cCczlCi9S0VjOhuKbxZTLQcWMWWtn2ekqZBp/bqCjFgSP8N2U4VXjbqbqGdXRKmeDeiL
         G46A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GQJ6cEtAWkqqCEmraKtILCYkz5+4I5qUBIAFj/BaO74=;
        fh=Ek1jAUi3GNl8SEwqAncxOvAsWJOejJFeI61Czi5lJC4=;
        b=Wiht0AL6OLKCn1zh/aiQqz8nl1t4Ohz4gVAItN0AAgxm0OIeacnH58819OJd5hWctm
         6VA4eCR96pVGBcTCHPPIHufEsreU6MIoCMtRL1fPNxAz7E7a40pLCbvz0lhg+X8v+1Vl
         EX7o13ymLHpb8r4rJXF4peut8i3QZmrMDTyk8YR/iivXYm30S9sYFYxDNAOP4sqfiCD+
         0cYSsO94QtFs3cSiLFbnhNetXF1Dp4/HG5a7+nQZdY0yHsLR3+j67uUCfzjqiJIWl/Ty
         BjWQBHGh+TpgOFItczmo0WDWOnG9mi8u7vVeVIR2rnh0koiP4igrY3hHFDUhU7Rmx6k5
         sMIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Str6SwuN;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60c828ae04asi91322a12.2.2025.06.27.01.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 01:02:50 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uV42r-0000000DYu7-1a3d;
	Fri, 27 Jun 2025 08:02:49 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D32DB300222; Fri, 27 Jun 2025 10:02:48 +0200 (CEST)
Date: Fri, 27 Jun 2025 10:02:48 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
Message-ID: <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-3-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626134158.3385080-3-glider@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Str6SwuN;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 26, 2025 at 03:41:49PM +0200, Alexander Potapenko wrote:
> kcov used to obey clang-format style, but somehow diverged over time.
> This patch applies clang-format to kernel/kcov.c and
> include/linux/kcov.h, no functional change.

I'm not sure I agree this is in fact a good thing. Very questionable
style choices made.

I had to kill clang-format hard in my nvim-lsp-clangd setup, because
clang-format is such a piece of shit.


> -static inline void kcov_task_init(struct task_struct *t) {}
> -static inline void kcov_task_exit(struct task_struct *t) {}
> -static inline void kcov_prepare_switch(struct task_struct *t) {}
> -static inline void kcov_finish_switch(struct task_struct *t) {}
> -static inline void kcov_remote_start(u64 handle) {}
> -static inline void kcov_remote_stop(void) {}
> +static inline void kcov_task_init(struct task_struct *t)
> +{
> +}
> +static inline void kcov_task_exit(struct task_struct *t)
> +{
> +}
> +static inline void kcov_prepare_switch(struct task_struct *t)
> +{
> +}
> +static inline void kcov_finish_switch(struct task_struct *t)
> +{
> +}
> +static inline void kcov_remote_start(u64 handle)
> +{
> +}
> +static inline void kcov_remote_stop(void)
> +{
> +}

This is not an improvement.

> @@ -52,36 +53,36 @@ struct kcov {
>  	 *  - task with enabled coverage (we can't unwire it from another task)
>  	 *  - each code section for remote coverage collection
>  	 */
> -	refcount_t		refcount;
> +	refcount_t refcount;
>  	/* The lock protects mode, size, area and t. */
> -	spinlock_t		lock;
> -	enum kcov_mode		mode;
> +	spinlock_t lock;
> +	enum kcov_mode mode;
>  	/* Size of arena (in long's). */
> -	unsigned int		size;
> +	unsigned int size;
>  	/* Coverage buffer shared with user space. */
> -	void			*area;
> +	void *area;
>  	/* Task for which we collect coverage, or NULL. */
> -	struct task_struct	*t;
> +	struct task_struct *t;
>  	/* Collecting coverage from remote (background) threads. */
> -	bool			remote;
> +	bool remote;
>  	/* Size of remote area (in long's). */
> -	unsigned int		remote_size;
> +	unsigned int remote_size;
>  	/*
>  	 * Sequence is incremented each time kcov is reenabled, used by
>  	 * kcov_remote_stop(), see the comment there.
>  	 */
> -	int			sequence;
> +	int sequence;
>  };
>  
>  struct kcov_remote_area {
> -	struct list_head	list;
> -	unsigned int		size;
> +	struct list_head list;
> +	unsigned int size;
>  };
>  
>  struct kcov_remote {
> -	u64			handle;
> -	struct kcov		*kcov;
> -	struct hlist_node	hnode;
> +	u64 handle;
> +	struct kcov *kcov;
> +	struct hlist_node hnode;
>  };
>  
>  static DEFINE_SPINLOCK(kcov_remote_lock);
> @@ -89,14 +90,14 @@ static DEFINE_HASHTABLE(kcov_remote_map, 4);
>  static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>  
>  struct kcov_percpu_data {
> -	void			*irq_area;
> -	local_lock_t		lock;
> -
> -	unsigned int		saved_mode;
> -	unsigned int		saved_size;
> -	void			*saved_area;
> -	struct kcov		*saved_kcov;
> -	int			saved_sequence;
> +	void *irq_area;
> +	local_lock_t lock;
> +
> +	unsigned int saved_mode;
> +	unsigned int saved_size;
> +	void *saved_area;
> +	struct kcov *saved_kcov;
> +	int saved_sequence;
>  };
>  
>  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {

This is just plain wrong. Making something that was readable into a
trainwreck.


Please either teach clang-format sensible style choices, or refrain from
using it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250627080248.GQ1613200%40noisy.programming.kicks-ass.net.
