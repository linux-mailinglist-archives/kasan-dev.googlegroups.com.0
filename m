Return-Path: <kasan-dev+bncBDC4FFVJQ4BRBPMRTPDAMGQEORU275Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A5CFB56976
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 15:53:04 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32e0b001505sf1055730a91.0
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 06:53:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757857982; cv=pass;
        d=google.com; s=arc-20240605;
        b=JUKJsEX6L+aHxhTRSBDmXwhgQ4VnxFyWGsPR0iqY7Fgw9qeQFH1DDR3iZpJrMfmlZn
         3QClUlRiQoGCWqClCCvdcrMYJ7q8xDdLsY4ox/qv56obvTGUhlFghrGJdQfIOgCBqzr6
         pZOEF19c4VvxFoWdKsLXM4Evl/fz+2N3hnlBDRoC/IOPfJTQ80N3UWx7sanxFtyFmtKp
         n1JgP6+YDVeZVvRqadY/Y6Gpb3Pj1s8KY8VC55gg0VZNli0aExChyORVZKM50idR+sLe
         g2U44y2EJSIvNGeVE+97R9UWn7HSPEnTVdgbKKfmJxIqjHCj4ZYT5afhQ6TFFxYgc4Oi
         adwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=7kxnuZKJBJEDKT5xdmsn99ac/9Vv9yvkvWBaD0Fv//E=;
        fh=PAeJzke7eFI74zRt4NG/dbT/6MuyFRp81/U4He/8jcM=;
        b=bOtTD2ENn8u5hepepmNEsZWPNvBX5Nq4PKPpIdgm2Jd0V90QhU6LaLmbzwUHfQMUMA
         1EPQ4qgLaydIXleRINnXC20RY0jPktaHM5lp5WTii9CYb8cY0RYo5Cb+7l/9lQF1vmQr
         UmQrPGJL8COaNhPiV+BXJXXRjTxZ1Sb/1k+yCwvbxmLKQ/kQ4/zexxoidxhsYxQHOR4x
         Lf2LdyPEhMGEmgFHgAP/8vmS+ISr65zEaifWDQycbNRhtVdqT6vXvPAPCVJSioxN9cI1
         2lL4OGZbLQVEtVk+Y/b12g41Qa60KycDsFGFwGcBZTB/8OPVxxMIOuer9OmpSLmATwmX
         HQ2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bECoVG1z;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757857982; x=1758462782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7kxnuZKJBJEDKT5xdmsn99ac/9Vv9yvkvWBaD0Fv//E=;
        b=J4FRxLB9U0e//SIeAA7Gchvb675MVDL9SXd74jVHGmsRAzwAj9dUoKLHaUExod5EXZ
         xSHOdRypvBnGzKHYMxuZRAVXrRy1IpOzUSvAV3ZCf0OMqYqvD6lHTw+DOepgY/IU9nWS
         SJeQx7XTXIlChqW+98091FfFo0Esr4vtlOXJdfrh13+mUUJNBv/fp6Vu4T0K1/VLWLYW
         W67u5eeiJ3+ZV7k67SC52bkqKqHpA51gFhoAmFEnEvsWXvpcb3zHmabW5wYPD3J1lbCt
         7THXOvfUmIZ1t8Pveb7C56ktNvfOQTqtpgHVGnouddIgyrcPjUd9OkrlqnTgjB/uWHx+
         IsCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757857982; x=1758462782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7kxnuZKJBJEDKT5xdmsn99ac/9Vv9yvkvWBaD0Fv//E=;
        b=HqqM4gaG7i++oD8nMIoGdfWteUYznqY2dMtVoq9MJxB9zpoe8VxNUkCOBgzsVRhn3/
         AXgiAKlHorcj4u3T/uklIF3SunGn3om/oJipl8pzz/Q263ztCkUPqkAIzCAKkMU+wH4V
         27FuyTvWVMuQANm9EFik2FEDH+iRcILREI8B078XxZDUZhlDYBPwZC0/8kyoEXjcj9+r
         mTyb3E1cULcqUWBzJaBQogL0I69XD7B9GciL0XXQdsRiKdWOnPWrvlJjO/cQNthFsaCJ
         fZFO7r2CzOWnp8P/pvU3TBUL9xNpJoxPtcWyPNnNzG2ixZ6E9kJV588sUccSxzeIfobV
         bbyQ==
X-Forwarded-Encrypted: i=2; AJvYcCVpNS204JGJu6fgfsWcFlESaBiFEZaubN91nJqZrpnYkClxcuDiPvL+4CxXJh5X6+4+TUP7tA==@lfdr.de
X-Gm-Message-State: AOJu0Yz/C49ddgVk+1857qMCRCqm0Tl0sExHlWSV8Xx4wvHz+6kgipXW
	/G6Etlov2L8eABBu87STLNHRXvxCVBNf6D65saMDOLpK7ZopXB2Z9D/U
X-Google-Smtp-Source: AGHT+IEwWr1anXzTYb1/pKqToziG4Cct4bIJ9yM1OR1VioU8rNiqjPedT7PNOXU9IOfGdNgpH7Iw/A==
X-Received: by 2002:a17:90b:1649:b0:32e:1b1c:f8b8 with SMTP id 98e67ed59e1d1-32e1b1cfc95mr4816743a91.26.1757857982127;
        Sun, 14 Sep 2025 06:53:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4xz6KwowNMwvKIbzAAGElC9Ubm6jZZsveiSzXmPAa5Ww==
Received: by 2002:a17:90a:648:b0:327:6f3a:16ba with SMTP id
 98e67ed59e1d1-32dd4edb16cls2673263a91.2.-pod-prod-04-us; Sun, 14 Sep 2025
 06:53:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7pRdNQIvhOQF7IhvhxhEyx1o1p90oV/CAFvKblt4nnLRcRRa+C07vmlzD0IML710UIxLjR9zyPz4=@googlegroups.com
X-Received: by 2002:a05:6a20:432b:b0:245:fb85:ef58 with SMTP id adf61e73a8af0-2602c90cbe2mr12975468637.40.1757857980141;
        Sun, 14 Sep 2025 06:53:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757857980; cv=none;
        d=google.com; s=arc-20240605;
        b=eCxiBLR+OPnRGLHiNkSiKNqk+EdhF1zjfqqOZ5M2Nqn1QYDI175RIq4EE00z3UUm/U
         Ux0kyQOlKpFgm7G5emPPr/TL6OKBGCQSxVKpInFZIdCsd5RRFot07ZDVBcvYIoqCKuaJ
         Psk5sHnctsCgsPgazVdGgsm39Ajkp5eAPJBcBuR277+uuKgR2VJc8sX0oi+wQJFsQF6R
         eB51Wdzgdr9/Mo7emWZeY5Q7xAldDmmGUWAt368/9qhX2JQNCwi9UA3xaXKkFliXiUyO
         f/fR52sZPfgwDvjndjn7FhkQj05uGc4dRVFT/UIoyc8yeHH3efZshyZNqGu9N1ElrVGc
         ayRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OLpgwUf4fony2ahEU7jyRp8ERtRjVojzKUczuwKwKWM=;
        fh=NQeqbZfMKjMy8NaCHM8JPlpyfQbM5NGco4RXkoRnpTY=;
        b=TWk5C2e/vJM8Xl2DAxozqx3gF6rG2seRsSPHleaJofCa2IHt9mFNqCld3M4Zd4RKbO
         V7rJEIpePpmRNTShLOLWHsJuBw/iA0c8UZod+gGX/c/of99NZK+cScnUjZM+FaT7UG/+
         EkDWS4p3iLU2fcnzAXs/54DUnRWSNmZQzxWAysTljrmlyeVjKlW7K/1K4x8lmUYZmrln
         0W6+LiLj69EbLIBtyvF8tKfTtTaoxG6EIGjhNbR8SqK5LWk/iryT/OTyzU/au2fe7IbT
         puvIgrVI3zHcNmqhM4RkrUQsZKxPqMyPyqnPGlQUoGYl2QUe0wrvHiE9bgRiU1mrGFMr
         +mhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bECoVG1z;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32e6140f723si2516a91.0.2025.09.14.06.53.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 06:53:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7384B4058B;
	Sun, 14 Sep 2025 13:52:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BBA19C4CEF0;
	Sun, 14 Sep 2025 13:52:44 +0000 (UTC)
Date: Sun, 14 Sep 2025 22:52:42 +0900
From: "'Masami Hiramatsu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, Alexander
 Potapenko <glider@google.com>, Jonathan Corbet <corbet@lwn.net>, Thomas
 Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav
 Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Juri Lelli
 <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>,
 Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt
 <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman
 <mgorman@suse.de>, Valentin Schneider <vschneid@redhat.com>, Arnaldo
 Carvalho de Melo <acme@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Alexander Shishkin
 <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, Ian
 Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>, David Hildenbrand
 <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers
 <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin
 Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, Alice Ryhl
 <aliceryhl@google.com>, Sami Tolvanen <samitolvanen@google.com>, Miguel
 Ojeda <ojeda@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Rong Xu
 <xur@google.com>, Naveen N Rao <naveen@kernel.org>, David Kaplan
 <david.kaplan@amd.com>, Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan
 <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-mm@kvack.org, llvm@lists.linux.dev, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v4 01/21] x86/hw_breakpoint: Unify breakpoint
 install/uninstall
Message-Id: <20250914225242.b289de4a30557fec718b8cc8@kernel.org>
In-Reply-To: <20250912101145.465708-2-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
	<20250912101145.465708-2-wangjinchao600@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mhiramat@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bECoVG1z;       spf=pass
 (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=mhiramat@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Reply-To: Masami Hiramatsu (Google) <mhiramat@kernel.org>
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

On Fri, 12 Sep 2025 18:11:11 +0800
Jinchao Wang <wangjinchao600@gmail.com> wrote:

> Consolidate breakpoint management to reduce code duplication.
> The diffstat was misleading, so the stripped code size is compared instead.
> After refactoring, it is reduced from 11976 bytes to 11448 bytes on my
> x86_64 system built with clang.
> 
> This also makes it easier to introduce arch_reinstall_hw_breakpoint().
> 
> In addition, including linux/types.h to fix a missing build dependency.
> 

Looks good to me.

Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>

Thanks,

> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  arch/x86/include/asm/hw_breakpoint.h |   6 ++
>  arch/x86/kernel/hw_breakpoint.c      | 141 +++++++++++++++------------
>  2 files changed, 84 insertions(+), 63 deletions(-)
> 
> diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
> index 0bc931cd0698..aa6adac6c3a2 100644
> --- a/arch/x86/include/asm/hw_breakpoint.h
> +++ b/arch/x86/include/asm/hw_breakpoint.h
> @@ -5,6 +5,7 @@
>  #include <uapi/asm/hw_breakpoint.h>
>  
>  #define	__ARCH_HW_BREAKPOINT_H
> +#include <linux/types.h>
>  
>  /*
>   * The name should probably be something dealt in
> @@ -18,6 +19,11 @@ struct arch_hw_breakpoint {
>  	u8		type;
>  };
>  
> +enum bp_slot_action {
> +	BP_SLOT_ACTION_INSTALL,
> +	BP_SLOT_ACTION_UNINSTALL,
> +};
> +
>  #include <linux/kdebug.h>
>  #include <linux/percpu.h>
>  #include <linux/list.h>
> diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
> index b01644c949b2..3658ace4bd8d 100644
> --- a/arch/x86/kernel/hw_breakpoint.c
> +++ b/arch/x86/kernel/hw_breakpoint.c
> @@ -48,7 +48,6 @@ static DEFINE_PER_CPU(unsigned long, cpu_debugreg[HBP_NUM]);
>   */
>  static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM]);
>  
> -
>  static inline unsigned long
>  __encode_dr7(int drnum, unsigned int len, unsigned int type)
>  {
> @@ -85,96 +84,112 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
>  }
>  
>  /*
> - * Install a perf counter breakpoint.
> - *
> - * We seek a free debug address register and use it for this
> - * breakpoint. Eventually we enable it in the debug control register.
> - *
> - * Atomic: we hold the counter->ctx->lock and we only handle variables
> - * and registers local to this cpu.
> + * We seek a slot and change it or keep it based on the action.
> + * Returns slot number on success, negative error on failure.
> + * Must be called with IRQs disabled.
>   */
> -int arch_install_hw_breakpoint(struct perf_event *bp)
> +static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
>  {
> -	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> -	unsigned long *dr7;
> -	int i;
> -
> -	lockdep_assert_irqs_disabled();
> +	struct perf_event *old_bp;
> +	struct perf_event *new_bp;
> +	int slot;
> +
> +	switch (action) {
> +	case BP_SLOT_ACTION_INSTALL:
> +		old_bp = NULL;
> +		new_bp = bp;
> +		break;
> +	case BP_SLOT_ACTION_UNINSTALL:
> +		old_bp = bp;
> +		new_bp = NULL;
> +		break;
> +	default:
> +		return -EINVAL;
> +	}
>  
> -	for (i = 0; i < HBP_NUM; i++) {
> -		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
> +	for (slot = 0; slot < HBP_NUM; slot++) {
> +		struct perf_event **curr = this_cpu_ptr(&bp_per_reg[slot]);
>  
> -		if (!*slot) {
> -			*slot = bp;
> -			break;
> +		if (*curr == old_bp) {
> +			*curr = new_bp;
> +			return slot;
>  		}
>  	}
>  
> -	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
> -		return -EBUSY;
> +	if (old_bp) {
> +		WARN_ONCE(1, "Can't find matching breakpoint slot");
> +		return -EINVAL;
> +	}
> +
> +	WARN_ONCE(1, "No free breakpoint slots");
> +	return -EBUSY;
> +}
> +
> +static void setup_hwbp(struct arch_hw_breakpoint *info, int slot, bool enable)
> +{
> +	unsigned long dr7;
>  
> -	set_debugreg(info->address, i);
> -	__this_cpu_write(cpu_debugreg[i], info->address);
> +	set_debugreg(info->address, slot);
> +	__this_cpu_write(cpu_debugreg[slot], info->address);
>  
> -	dr7 = this_cpu_ptr(&cpu_dr7);
> -	*dr7 |= encode_dr7(i, info->len, info->type);
> +	dr7 = this_cpu_read(cpu_dr7);
> +	if (enable)
> +		dr7 |= encode_dr7(slot, info->len, info->type);
> +	else
> +		dr7 &= ~__encode_dr7(slot, info->len, info->type);
>  
>  	/*
> -	 * Ensure we first write cpu_dr7 before we set the DR7 register.
> -	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> +	 * Enabling:
> +	 *   Ensure we first write cpu_dr7 before we set the DR7 register.
> +	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
>  	 */
> +	if (enable)
> +		this_cpu_write(cpu_dr7, dr7);
> +
>  	barrier();
>  
> -	set_debugreg(*dr7, 7);
> +	set_debugreg(dr7, 7);
> +
>  	if (info->mask)
> -		amd_set_dr_addr_mask(info->mask, i);
> +		amd_set_dr_addr_mask(enable ? info->mask : 0, slot);
>  
> -	return 0;
> +	/*
> +	 * Disabling:
> +	 *   Ensure the write to cpu_dr7 is after we've set the DR7 register.
> +	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> +	 */
> +	if (!enable)
> +		this_cpu_write(cpu_dr7, dr7);
>  }
>  
>  /*
> - * Uninstall the breakpoint contained in the given counter.
> - *
> - * First we search the debug address register it uses and then we disable
> - * it.
> - *
> - * Atomic: we hold the counter->ctx->lock and we only handle variables
> - * and registers local to this cpu.
> + * find suitable breakpoint slot and set it up based on the action
>   */
> -void arch_uninstall_hw_breakpoint(struct perf_event *bp)
> +static int arch_manage_bp(struct perf_event *bp, enum bp_slot_action action)
>  {
> -	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> -	unsigned long dr7;
> -	int i;
> +	struct arch_hw_breakpoint *info;
> +	int slot;
>  
>  	lockdep_assert_irqs_disabled();
>  
> -	for (i = 0; i < HBP_NUM; i++) {
> -		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
> -
> -		if (*slot == bp) {
> -			*slot = NULL;
> -			break;
> -		}
> -	}
> -
> -	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
> -		return;
> +	slot = manage_bp_slot(bp, action);
> +	if (slot < 0)
> +		return slot;
>  
> -	dr7 = this_cpu_read(cpu_dr7);
> -	dr7 &= ~__encode_dr7(i, info->len, info->type);
> +	info = counter_arch_bp(bp);
> +	setup_hwbp(info, slot, action != BP_SLOT_ACTION_UNINSTALL);
>  
> -	set_debugreg(dr7, 7);
> -	if (info->mask)
> -		amd_set_dr_addr_mask(0, i);
> +	return 0;
> +}
>  
> -	/*
> -	 * Ensure the write to cpu_dr7 is after we've set the DR7 register.
> -	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> -	 */
> -	barrier();
> +int arch_install_hw_breakpoint(struct perf_event *bp)
> +{
> +	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
> +}
>  
> -	this_cpu_write(cpu_dr7, dr7);
> +void arch_uninstall_hw_breakpoint(struct perf_event *bp)
> +{
> +	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
>  }
>  
>  static int arch_bp_generic_len(int x86_len)
> -- 
> 2.43.0
> 
> 


-- 
Masami Hiramatsu (Google) <mhiramat@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250914225242.b289de4a30557fec718b8cc8%40kernel.org.
