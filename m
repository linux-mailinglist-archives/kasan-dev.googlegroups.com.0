Return-Path: <kasan-dev+bncBAABB2M6Z3ZQKGQELJBAMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9435618BB16
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 16:27:38 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id h12sf2274162ils.12
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 08:27:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584631657; cv=pass;
        d=google.com; s=arc-20160816;
        b=Or0F4Q885RlzGXK7vsrx222jMIa4OiT3Tg5agX7ynl895ePCCzI/zGDi7Wenvz1VHB
         ZidTsBl3JmATQOl94u05veepRGWYw16eqndUZvwGQO7g8HEvLISHISCpi6F3nF1qIo73
         raZZAsesZFhYPbFLCTNBJ/efW4oZ4tS+tEGKcumQfDgFRKYbeId97wYquXhyetnGE+cG
         8Hs9wWCi2lcVBGRrXm+MRyvFZhKFUICMWxetEjDUXsmajC4Dx7GBp2CEQ+QnbPSZQ159
         vjt/g8zIjMzzaRDv8c6PVjKb0V2oOY0ZBrdCLBWTYFZZRzUOsEfJUWhNjaTGLdZciExL
         0cKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=C6i8vNSb96fZgd/M/UUMRoa5GxlwyXS5Vvxv34pRyq4=;
        b=cMUknjA8GaB26MiFYY0ImUsOE7Qdd+4ZuG+u+gdgjh9djf59VntI3Nr+dp8PbfgL59
         All5hvk87Bb5Rpgnv8rqJE9Mjz1cUMScmiCg2ORkapR8l4hNOAEHzRjIkhZKF4/TUfzK
         olWYh2LnAKq+LPsw90ySK4PfzkaBxPbgRR++gH9tMh9vLQYNHStC2CYrRAkIhFoMEZ+e
         z+ks8JagNi9wyjpfkfeAvFuTfHGndij7MK6CFOtZaS1zcPQwWrAvimDido4YA6MVCbVo
         oSzsA7ADRqClaUIeNXKp3YFwQPIZegxnwtaNAwYhT00PtrQM7YC1brt8aoXcnwdekqtb
         rJLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PNYPzcil;
       spf=pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C6i8vNSb96fZgd/M/UUMRoa5GxlwyXS5Vvxv34pRyq4=;
        b=GcIF8rax1o/81pON8a8LB0BV9LJzdNti0MQ2rAbMDNGt7qfvytXE94vKqaux7HgNqS
         rl1+UZURobZf47xk86AFznyWxpMfRONaMVeMusL3KMOjZMWr+bt+InzDy/SM3bjdB70x
         Vz+XF0XhGSqyk3XrEY4eTTEMbiPP9PgPR8iOuvuN59QLf+wXC61FMMJoHalvQHt+0gYJ
         zSU+KZTCsw9cCpN0nFlKitZpCcDZatj5HueWIz5GalIu13Xfjk1kKE2xHI4/uvMMUfgf
         xSXNrFINv6WtGOQtZuEiGX/FOey//0uqGAY4xigH8QRI/vfVz4r0Jf111hltE+JCy4Bp
         b+lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C6i8vNSb96fZgd/M/UUMRoa5GxlwyXS5Vvxv34pRyq4=;
        b=du9wIt4rNF9DlYUHC0cZQxHpvi4RX1gE4nD6pInI/UwbEY0eZ4LNSdXHi7pnWj9Mf5
         rHL7ewl48Enmq+Niw8GoLHmmzXtigco20/utAAx4PLLfySeMfkk/fO4KhPwlgKX6+u5W
         GDY1aNj1tvo52W8QNMznhAFefnUFEMOiquIftoeXy7c2nfi7yBTIX4AF//fOZzxNNn9X
         xoTnRb+b2gciRGSeB0bIJFUviUmifn012qpv9r2mpP1zwqgPp9bfr1+kcP8O6QBGsO4l
         SKuJPHQVMyICC6dUqAwYLKm7ay6QC+Tb/piLfnkTkrKjSmV5saQu/51oCM54WQJmpJTh
         mLUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3Ib/pE8jCjWd8QnG4iFsGI6hoZAf8r39xhUISH4RWOzxijC8LV
	bOArLZdq+f2KQgvtLInW+hM=
X-Google-Smtp-Source: ADFU+vsQHulI7pfehpbqdWC6IdB+LaYVqqCzysolTRUuswdzMcAwD/n2O2DI84cfjShp13K4x+/55g==
X-Received: by 2002:a92:d84e:: with SMTP id h14mr3287083ilq.160.1584631657513;
        Thu, 19 Mar 2020 08:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1557:: with SMTP id v84ls673912ilk.11.gmail; Thu, 19 Mar
 2020 08:27:37 -0700 (PDT)
X-Received: by 2002:a92:ad0b:: with SMTP id w11mr3826178ilh.241.1584631657105;
        Thu, 19 Mar 2020 08:27:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584631657; cv=none;
        d=google.com; s=arc-20160816;
        b=FGrqJ7He9yxsCsG19k+gCvdFMTLEhw1W/lokpbOKmRmFVzNplGUZ+zew1Kja6lFcLm
         TqfIh3gv/P1nBPQEYdOfYO89nsFN3kMU4XaiU8qmxvVgP1djiY7lvXjdCg8gKSci2A4I
         H8QxUySu/roBzN+TzR8gXyZlFsV9gZqs7w44h4F5vzFN/h3KZSawT9rdqIdzSAm8zw2V
         t79jZSVbJ+deLFTLnLfHPrHt3qoASSEUmqm5al9LQ9/tTVLfRmPd8dDRcFIQpuclRL9k
         mwceThLQzDciARKV/dV2F128W6UHMBbbm5WJDikcGXi4tKF/uobsZk9T8V0XXZDJ70ET
         07Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zdkg17j9jOQAF04hhyi9/DAa0dB5JknI3X6P7xK/Hsg=;
        b=oTiCzSslJjb4GKF29QM+goU+3+VUrfZw2LkZp3GsV6u4vuMgPoU8r5HcvD7vhlBFGZ
         h9/bJ3ISqCnp/VOvBueJeiwDn3JuXuCjO9/eiy/itYZkWDZWKm6Qx706oe8zRj7NRGcf
         Hq1WQroQAJlCya35IMCGu4uyT/Q3UKyFTTd/dR0hHTzeOiDFE5O3aCAAtXF3P/lds7x6
         a9UXEiQmB5vNO/XAjHXOtf/vspGHx34B732nIFTH58GMZI2A5BmfjW2rlHTCv6SfHA++
         vVzwP9qYAU3k/44CAHXUPeiIh9MEAD0g1OvuRx0MreIWKmRPZqEUM+noCa5cRoL90ldV
         yZIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PNYPzcil;
       spf=pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v13si144260ilg.4.2020.03.19.08.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Mar 2020 08:27:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6A7B22072D;
	Thu, 19 Mar 2020 15:27:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3C9F03520F2A; Thu, 19 Mar 2020 08:27:36 -0700 (PDT)
Date: Thu, 19 Mar 2020 08:27:36 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Introduce report access_info and other_info
Message-ID: <20200319152736.GF3199@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200318173845.220793-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200318173845.220793-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PNYPzcil;       spf=pass
 (google.com: domain of srs0=ip8j=5e=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ip8j=5E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Mar 18, 2020 at 06:38:44PM +0100, Marco Elver wrote:
> Improve readability by introducing access_info and other_info structs,
> and in preparation of the following commit in this series replaces the
> single instance of other_info with an array of size 1.
> 
> No functional change intended.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued both for review and testing, and I am trying it out on one of
the scenarios that proved problematic earlier on.  Thank you!!!

							Thanx, Paul

> ---
>  kernel/kcsan/core.c   |   6 +-
>  kernel/kcsan/kcsan.h  |   2 +-
>  kernel/kcsan/report.c | 147 +++++++++++++++++++++---------------------
>  3 files changed, 77 insertions(+), 78 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index ee8200835b60..f1c38620e3cf 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -321,7 +321,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
>  	flags = user_access_save();
>  
>  	if (consumed) {
> -		kcsan_report(ptr, size, type, true, raw_smp_processor_id(),
> +		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
>  			     KCSAN_REPORT_CONSUMED_WATCHPOINT);
>  	} else {
>  		/*
> @@ -500,8 +500,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
>  			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
>  
> -		kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
> -			     KCSAN_REPORT_RACE_SIGNAL);
> +		kcsan_report(ptr, size, type, value_change, KCSAN_REPORT_RACE_SIGNAL);
>  	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
>  		/* Inferring a race, since the value should not have changed. */
>  
> @@ -511,7 +510,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  
>  		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
>  			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
> -				     raw_smp_processor_id(),
>  				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
>  	}
>  
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index e282f8b5749e..6630dfe32f31 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -135,7 +135,7 @@ enum kcsan_report_type {
>   * Print a race report from thread that encountered the race.
>   */
>  extern void kcsan_report(const volatile void *ptr, size_t size, int access_type,
> -			 enum kcsan_value_change value_change, int cpu_id,
> +			 enum kcsan_value_change value_change,
>  			 enum kcsan_report_type type);
>  
>  #endif /* _KERNEL_KCSAN_KCSAN_H */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 18f9d3bc93a5..de234d1c1b3d 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -19,18 +19,23 @@
>   */
>  #define NUM_STACK_ENTRIES 64
>  
> +/* Common access info. */
> +struct access_info {
> +	const volatile void	*ptr;
> +	size_t			size;
> +	int			access_type;
> +	int			task_pid;
> +	int			cpu_id;
> +};
> +
>  /*
>   * Other thread info: communicated from other racing thread to thread that set
>   * up the watchpoint, which then prints the complete report atomically. Only
>   * need one struct, as all threads should to be serialized regardless to print
>   * the reports, with reporting being in the slow-path.
>   */
> -static struct {
> -	const volatile void	*ptr;
> -	size_t			size;
> -	int			access_type;
> -	int			task_pid;
> -	int			cpu_id;
> +struct other_info {
> +	struct access_info	ai;
>  	unsigned long		stack_entries[NUM_STACK_ENTRIES];
>  	int			num_stack_entries;
>  
> @@ -52,7 +57,9 @@ static struct {
>  	 * that populated @other_info until it has been consumed.
>  	 */
>  	struct task_struct	*task;
> -} other_info;
> +};
> +
> +static struct other_info other_infos[1];
>  
>  /*
>   * Information about reported races; used to rate limit reporting.
> @@ -238,7 +245,7 @@ static const char *get_thread_desc(int task_id)
>  }
>  
>  /* Helper to skip KCSAN-related functions in stack-trace. */
> -static int get_stack_skipnr(unsigned long stack_entries[], int num_entries)
> +static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
>  {
>  	char buf[64];
>  	int skip = 0;
> @@ -279,9 +286,10 @@ static void print_verbose_info(struct task_struct *task)
>  /*
>   * Returns true if a report was generated, false otherwise.
>   */
> -static bool print_report(const volatile void *ptr, size_t size, int access_type,
> -			 enum kcsan_value_change value_change, int cpu_id,
> -			 enum kcsan_report_type type)
> +static bool print_report(enum kcsan_value_change value_change,
> +			 enum kcsan_report_type type,
> +			 const struct access_info *ai,
> +			 const struct other_info *other_info)
>  {
>  	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
>  	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
> @@ -297,9 +305,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  		return false;
>  
>  	if (type == KCSAN_REPORT_RACE_SIGNAL) {
> -		other_skipnr = get_stack_skipnr(other_info.stack_entries,
> -						other_info.num_stack_entries);
> -		other_frame = other_info.stack_entries[other_skipnr];
> +		other_skipnr = get_stack_skipnr(other_info->stack_entries,
> +						other_info->num_stack_entries);
> +		other_frame = other_info->stack_entries[other_skipnr];
>  
>  		/* @value_change is only known for the other thread */
>  		if (skip_report(value_change, other_frame))
> @@ -321,13 +329,13 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  		 */
>  		cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
>  		pr_err("BUG: KCSAN: %s in %ps / %ps\n",
> -		       get_bug_type(access_type | other_info.access_type),
> +		       get_bug_type(ai->access_type | other_info->ai.access_type),
>  		       (void *)(cmp < 0 ? other_frame : this_frame),
>  		       (void *)(cmp < 0 ? this_frame : other_frame));
>  	} break;
>  
>  	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
> -		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(access_type),
> +		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(ai->access_type),
>  		       (void *)this_frame);
>  		break;
>  
> @@ -341,30 +349,28 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  	switch (type) {
>  	case KCSAN_REPORT_RACE_SIGNAL:
>  		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> -		       get_access_type(other_info.access_type), other_info.ptr,
> -		       other_info.size, get_thread_desc(other_info.task_pid),
> -		       other_info.cpu_id);
> +		       get_access_type(other_info->ai.access_type), other_info->ai.ptr,
> +		       other_info->ai.size, get_thread_desc(other_info->ai.task_pid),
> +		       other_info->ai.cpu_id);
>  
>  		/* Print the other thread's stack trace. */
> -		stack_trace_print(other_info.stack_entries + other_skipnr,
> -				  other_info.num_stack_entries - other_skipnr,
> +		stack_trace_print(other_info->stack_entries + other_skipnr,
> +				  other_info->num_stack_entries - other_skipnr,
>  				  0);
>  
>  		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> -			print_verbose_info(other_info.task);
> +			print_verbose_info(other_info->task);
>  
>  		pr_err("\n");
>  		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> -		       get_access_type(access_type), ptr, size,
> -		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
> -		       cpu_id);
> +		       get_access_type(ai->access_type), ai->ptr, ai->size,
> +		       get_thread_desc(ai->task_pid), ai->cpu_id);
>  		break;
>  
>  	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
>  		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
> -		       get_access_type(access_type), ptr, size,
> -		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
> -		       cpu_id);
> +		       get_access_type(ai->access_type), ai->ptr, ai->size,
> +		       get_thread_desc(ai->task_pid), ai->cpu_id);
>  		break;
>  
>  	default:
> @@ -386,22 +392,23 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  	return true;
>  }
>  
> -static void release_report(unsigned long *flags, enum kcsan_report_type type)
> +static void release_report(unsigned long *flags, struct other_info *other_info)
>  {
> -	if (type == KCSAN_REPORT_RACE_SIGNAL)
> -		other_info.ptr = NULL; /* mark for reuse */
> +	if (other_info)
> +		other_info->ai.ptr = NULL; /* Mark for reuse. */
>  
>  	spin_unlock_irqrestore(&report_lock, *flags);
>  }
>  
>  /*
> - * Sets @other_info.task and awaits consumption of @other_info.
> + * Sets @other_info->task and awaits consumption of @other_info.
>   *
>   * Precondition: report_lock is held.
>   * Postcondition: report_lock is held.
>   */
> -static void
> -set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
> +static void set_other_info_task_blocking(unsigned long *flags,
> +					 const struct access_info *ai,
> +					 struct other_info *other_info)
>  {
>  	/*
>  	 * We may be instrumenting a code-path where current->state is already
> @@ -418,7 +425,7 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
>  	 */
>  	int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
>  
> -	other_info.task = current;
> +	other_info->task = current;
>  	do {
>  		if (is_running) {
>  			/*
> @@ -438,19 +445,19 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
>  		spin_lock_irqsave(&report_lock, *flags);
>  		if (timeout-- < 0) {
>  			/*
> -			 * Abort. Reset other_info.task to NULL, since it
> +			 * Abort. Reset @other_info->task to NULL, since it
>  			 * appears the other thread is still going to consume
>  			 * it. It will result in no verbose info printed for
>  			 * this task.
>  			 */
> -			other_info.task = NULL;
> +			other_info->task = NULL;
>  			break;
>  		}
>  		/*
>  		 * If @ptr nor @current matches, then our information has been
>  		 * consumed and we may continue. If not, retry.
>  		 */
> -	} while (other_info.ptr == ptr && other_info.task == current);
> +	} while (other_info->ai.ptr == ai->ptr && other_info->task == current);
>  	if (is_running)
>  		set_current_state(TASK_RUNNING);
>  }
> @@ -460,9 +467,8 @@ set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
>   * acquires the matching other_info and returns true. If other_info is not
>   * required for the report type, simply acquires report_lock and returns true.
>   */
> -static bool prepare_report(unsigned long *flags, const volatile void *ptr,
> -			   size_t size, int access_type, int cpu_id,
> -			   enum kcsan_report_type type)
> +static bool prepare_report(unsigned long *flags, enum kcsan_report_type type,
> +			   const struct access_info *ai, struct other_info *other_info)
>  {
>  	if (type != KCSAN_REPORT_CONSUMED_WATCHPOINT &&
>  	    type != KCSAN_REPORT_RACE_SIGNAL) {
> @@ -476,18 +482,14 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  
>  	switch (type) {
>  	case KCSAN_REPORT_CONSUMED_WATCHPOINT:
> -		if (other_info.ptr != NULL)
> +		if (other_info->ai.ptr)
>  			break; /* still in use, retry */
>  
> -		other_info.ptr			= ptr;
> -		other_info.size			= size;
> -		other_info.access_type		= access_type;
> -		other_info.task_pid		= in_task() ? task_pid_nr(current) : -1;
> -		other_info.cpu_id		= cpu_id;
> -		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
> +		other_info->ai = *ai;
> +		other_info->num_stack_entries = stack_trace_save(other_info->stack_entries, NUM_STACK_ENTRIES, 1);
>  
>  		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> -			set_other_info_task_blocking(flags, ptr);
> +			set_other_info_task_blocking(flags, ai, other_info);
>  
>  		spin_unlock_irqrestore(&report_lock, *flags);
>  
> @@ -498,37 +500,31 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  		return false;
>  
>  	case KCSAN_REPORT_RACE_SIGNAL:
> -		if (other_info.ptr == NULL)
> +		if (!other_info->ai.ptr)
>  			break; /* no data available yet, retry */
>  
>  		/*
>  		 * First check if this is the other_info we are expecting, i.e.
>  		 * matches based on how watchpoint was encoded.
>  		 */
> -		if (!matching_access((unsigned long)other_info.ptr &
> -					     WATCHPOINT_ADDR_MASK,
> -				     other_info.size,
> -				     (unsigned long)ptr & WATCHPOINT_ADDR_MASK,
> -				     size))
> +		if (!matching_access((unsigned long)other_info->ai.ptr & WATCHPOINT_ADDR_MASK, other_info->ai.size,
> +				     (unsigned long)ai->ptr & WATCHPOINT_ADDR_MASK, ai->size))
>  			break; /* mismatching watchpoint, retry */
>  
> -		if (!matching_access((unsigned long)other_info.ptr,
> -				     other_info.size, (unsigned long)ptr,
> -				     size)) {
> +		if (!matching_access((unsigned long)other_info->ai.ptr, other_info->ai.size,
> +				     (unsigned long)ai->ptr, ai->size)) {
>  			/*
>  			 * If the actual accesses to not match, this was a false
>  			 * positive due to watchpoint encoding.
>  			 */
> -			kcsan_counter_inc(
> -				KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
> +			kcsan_counter_inc(KCSAN_COUNTER_ENCODING_FALSE_POSITIVES);
>  
>  			/* discard this other_info */
> -			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
> +			release_report(flags, other_info);
>  			return false;
>  		}
>  
> -		access_type |= other_info.access_type;
> -		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
> +		if (!((ai->access_type | other_info->ai.access_type) & KCSAN_ACCESS_WRITE)) {
>  			/*
>  			 * While the address matches, this is not the other_info
>  			 * from the thread that consumed our watchpoint, since
> @@ -561,15 +557,11 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  			 * data, and at this point the likelihood that we
>  			 * re-report the same race again is high.
>  			 */
> -			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
> +			release_report(flags, other_info);
>  			return false;
>  		}
>  
> -		/*
> -		 * Matching & usable access in other_info: keep other_info_lock
> -		 * locked, as this thread consumes it to print the full report;
> -		 * unlocked in release_report.
> -		 */
> +		/* Matching access in other_info. */
>  		return true;
>  
>  	default:
> @@ -582,10 +574,19 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  }
>  
>  void kcsan_report(const volatile void *ptr, size_t size, int access_type,
> -		  enum kcsan_value_change value_change, int cpu_id,
> +		  enum kcsan_value_change value_change,
>  		  enum kcsan_report_type type)
>  {
>  	unsigned long flags = 0;
> +	const struct access_info ai = {
> +		.ptr		= ptr,
> +		.size		= size,
> +		.access_type	= access_type,
> +		.task_pid	= in_task() ? task_pid_nr(current) : -1,
> +		.cpu_id		= raw_smp_processor_id()
> +	};
> +	struct other_info *other_info = type == KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> +					? NULL : &other_infos[0];
>  
>  	/*
>  	 * With TRACE_IRQFLAGS, lockdep's IRQ trace state becomes corrupted if
> @@ -596,19 +597,19 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
>  	lockdep_off();
>  
>  	kcsan_disable_current();
> -	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
> +	if (prepare_report(&flags, type, &ai, other_info)) {
>  		/*
>  		 * Never report if value_change is FALSE, only if we it is
>  		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
>  		 * be done once we know the full stack trace in print_report().
>  		 */
>  		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
> -				print_report(ptr, size, access_type, value_change, cpu_id, type);
> +				print_report(value_change, type, &ai, other_info);
>  
>  		if (reported && panic_on_warn)
>  			panic("panic_on_warn set ...\n");
>  
> -		release_report(&flags, type);
> +		release_report(&flags, other_info);
>  	}
>  	kcsan_enable_current();
>  
> -- 
> 2.25.1.481.gfbce0eb801-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319152736.GF3199%40paulmck-ThinkPad-P72.
