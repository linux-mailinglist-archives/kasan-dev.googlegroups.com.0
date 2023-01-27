Return-Path: <kasan-dev+bncBDV37XP3XYDRBF5J2CPAMGQEAVWKUEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A280D67ED39
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 19:14:48 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id n6-20020a0565120ac600b004d5a68b0f94sf2400231lfu.14
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 10:14:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674843288; cv=pass;
        d=google.com; s=arc-20160816;
        b=snk8D24RxWV4u/t5sWt/OgOyuFe4PjRjqof2GbeZBUYjJz3Ngov73k3dYPRwDuRjfH
         CkSp/2Wj3qai3AhO2Kavy0Gk1bIfjfCbmFV5DtuVFLUj8m1S9yZsTaZbRYxtgoZT3FRp
         Wwja/vGKxeh5rhPgSMTbkstfITXecNEEq4XoACFJCzgJCmw0+lg7PQKZiUNCtkxmHHRJ
         hyrTURZEWppQdjaH52KKmr1jxyYO8PxwztQrAfe7WIXTB5ZxM6HA8V0bhDjfbU7os7N7
         JESMnXV+h2iUWp1gXu5DkldEMy7UII/LLsEhM5eHXB8c7xOcU1EKkgKYJGbOeB4CJ45J
         V+sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=14ZMaS1BJnX2zJ+QhiRXvQEkmVhCnNOMRsALBPtF2lc=;
        b=XnaZWKGss4k2Bl2qRyu4d/zooHFaYSas4DkEA5INbFOgzH8KHUFq4WAPkvN+WB6EXM
         lDVxaSfhpICeTON8AyQLj9GGWGQOcPsMo6oxj1jg124WTHlfPLf7z8nG68rgQFkG5vAy
         KRgChMPPs7aVc7Zs2LlquMkCC+uweJQ/Zn4C8nvxTwpNZ+P/KJ20WSiBXo+Mq+4w4Z1e
         H+cdMzJTa0cJFKHHL484odIi4RFLrJMgyghPIAUEiLvw8K6svqfU2qGeLM0JaxzGSAeO
         ukNFgc8rSHXVkeDppQRWaWH8Vf03NWFiZh3nEUZCEx+8iye38tlZgP6x5YWEz2GTYwW4
         a6Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=14ZMaS1BJnX2zJ+QhiRXvQEkmVhCnNOMRsALBPtF2lc=;
        b=se2x2BYH0IpEDoTto8Z/l19ghct75Q8HhzJffz47ZN23YuHy9VNDFcKckenuNJEFJT
         ISpugZk4c3lTH2irlpQTjnRCZUrqmA8F6s4kmPhxEVr7BK8P5mmHlsmBi2q/MhWx4B16
         KJlWSHyDO0V/YzpbCyWge9CfX1qYI+6dEUY+sZQVx0e8KjjNtd1ghwR3Z6NTIUldNs95
         GH3faAlZ8fMJvKAMQ2iXZhn9oUPua+0eeqMVKwaRByfBdVVp6+wwDjPOv9RWGs10lsNB
         SQe5c8hm+Oa4riGCGW9r+rrJ+S9iQXQQlkqg18a4MJO6XYoklYw5G/mQImPcG75pOMDJ
         Jt/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=14ZMaS1BJnX2zJ+QhiRXvQEkmVhCnNOMRsALBPtF2lc=;
        b=epnQ5yjn8SmeeRtujOgOvK+dlht3zy1Ga7zE6l2pdnWtKLOSai+O/ZFuoCrTXthT2t
         y8Irrq/FWkJkGEZy2bCdc4eRXI2fdOTlHruaVabkoTZKhKmw/rwUSrgaO3e7i3G4TeFQ
         7OD7Wg0b4fLmbbLixJoGG5cohIM22FIoQAlFAJetRAvvAJf2AMpFuxuoFt0JsGN4Qi7y
         rKp6/oVsxn08R00PfFTqZdLTZOChGQyE78Qoliruv68HKSL0PobI7qSfoYscBFlk7zRa
         GjlvCEK4exOPD8Yk8E0Jc7m8DKyA4ksLN5pO/ysxQn4l2XbN2BMYlIi79YvJQ1huozen
         aCVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kopRP4KKeh0jRikfLirLHvFegAx6hONfHsggOZXyxs7HOm089a7
	cCMWm3PHhinfvvRU06/om9A=
X-Google-Smtp-Source: AMrXdXvijysFydOuZj0qhQt43tcl3m8dfW1xe/jGuDz7/Q56YX7O+KLjzIkjKjquLXn7MmAYjdh/2A==
X-Received: by 2002:a05:651c:1a07:b0:28b:bf1c:e11 with SMTP id by7-20020a05651c1a0700b0028bbf1c0e11mr2391921ljb.164.1674843287969;
        Fri, 27 Jan 2023 10:14:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:87c4:0:b0:27f:bedd:57d with SMTP id v4-20020a2e87c4000000b0027fbedd057dls920313ljj.10.-pod-prod-gmail;
 Fri, 27 Jan 2023 10:14:46 -0800 (PST)
X-Received: by 2002:a2e:b895:0:b0:28e:71dd:69e7 with SMTP id r21-20020a2eb895000000b0028e71dd69e7mr3127401ljp.10.1674843286140;
        Fri, 27 Jan 2023 10:14:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674843286; cv=none;
        d=google.com; s=arc-20160816;
        b=MQU+fPPUyo3O+40Nlrv1LUvjyzB72fpRHU/ZbyEsfFZXvWGUZyvbwLpbGtwY5drKo/
         WUKAWabeKL7SEuZADsb8FGF3wT2bSkEB7QTvqCoztrM5VvnDVllla0CguMTuPMLasGqD
         fkYRDo1Rrkntph6niy5MjW2npnSBLaWYkIChqrJaege+Efb6AFRvyE6VvfG5NKPQRwBa
         khIN00SD6H9JhF7Wp3D8wTuhx6xsYo2hagGEFcCcKyGmlYyjFueJm+ZPzHqizRQimLBr
         hwLehuY0LIcRKU7NyFf/EcsfJVIvq8Pqq99qIuVRqqMIdUG24ACCxqF3qBo0HcFwwpzK
         wKCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=d0ukVVDSmmVv772jTC+qYZY43ilFNFv0pxbLU5Cn1S8=;
        b=grdBvkoaDxaitxWHfGQbVJvdfsOfArxDN6yKRFgJA5kiqs5Yg34velPtZ1SlsJ9x/k
         KA3X1pm7zVA4eKTbhgqkOW/S8zXfgiJShekFt6BgOU+MrbgJkPDJe27VSC1e5rBlT3wP
         Q3kUt4NopgliCRJFs0gDce0J5I6bvyoPIsaPTb8trf39S4HZmB3i8t2OvXYuZqAu9yqX
         Kt0KM0X1MsZ6YSHRMmYvIuDb19JXy6Zhg+/RFu81BezZwTOFV4wScGTTpe/UI1f/J95P
         SfVnyxIPfDYY78jqj7XC9PNaFERF1rkJI9rYVJOheJpOxaiCll/35YhRditGmy0Rv2ZW
         3kaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p6-20020a2e8046000000b002865233e8b5si320017ljg.5.2023.01.27.10.14.45
        for <kasan-dev@googlegroups.com>;
        Fri, 27 Jan 2023 10:14:45 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 962632F;
	Fri, 27 Jan 2023 10:15:26 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.11.183])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7C2E63FA58;
	Fri, 27 Jan 2023 10:14:42 -0800 (PST)
Date: Fri, 27 Jan 2023 18:14:35 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Andrey Konovalov <andreyknvl@gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user
 addresses
Message-ID: <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
References: <20230127162409.2505312-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230127162409.2505312-1-elver@google.com>
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

Hi Marco,

Apologies for having not replies on v1...

On Fri, Jan 27, 2023 at 05:24:09PM +0100, Marco Elver wrote:
> Allow the creation of restricted breakpoint perf events that also fire
> in the kernel (perf_event_attr::exclude_kernel=0), if:
> 
>   1. No sample information is requested; samples may contain IPs,
>      registers, or other information that may disclose kernel addresses.
> 
>   2. The breakpoint (viz. data watchpoint) is on a user address.

I think there's a potential problem here w.r.t. what constitutes a "user
address". Below, the patch assumes that any address which access_ok() is happy
with is a user address, but that's not always the case, and it's not
necessarily always safe to allow watchpoints on such addresses.

For example, UEFI runtime services may live in low adddresses below
TASK_SIZE_MAX, and there are times when we run code in an idmap (or other
low-half mapping) when we cannot safely take an exception for things like idle,
suspend, kexec, pagetable rewriting on arm64, etc.

So I think this may introduce functional issues (e.g. a mechanism to crash the
kernel) in addition to any potential information disclosure, and I would not
want this to be generally available to unprivileged users.

Most of those happen in kernel threads, but they can also happen in the context
of user threads (e.g. if triggering suspend/idle via sysfs), so special care
will be needed, as above.

> The rules constrain the allowable perf events such that no sensitive
> kernel information can be disclosed.
> 
> Despite no explicit kernel information disclosure, the following
> questions may need answers:
> 
>  1. Q: Is obtaining information that the kernel accessed a particular
>     user's known memory location revealing new information?
> 
>     A: Given the kernel's user space ABI, there should be no "surprise
>     accesses" to user space memory in the first place.

I think that may be true for userspace, but not true for other transient
mappings in the low half of the address space. Ignoring the functional concern
above, for idmap'd code this would at least provide a mechanism to probe for
the phyiscal address of that code (and by extension, reveal the phyiscal
location of the entire kernel).

>  2. Q: Does causing breakpoints on user memory accesses by the kernel
>     potentially impact timing in a sensitive way?
> 
>     A: Since hardware breakpoints trigger regardless of the state of
>     perf_event_attr::exclude_kernel, but are filtered in the perf
>     subsystem, this possibility already exists independent of the
>     proposed change.

Hmm... arm64's HW breakpoints and watchpoints have HW privilege filters, so I'm
not sure the above statement is generally/necessarily true.

> Motivation:  Data breakpoints on user addresses that also fire in the
> kernel provide complete coverage to track and debug accesses, not just
> in user space but also through the kernel. For example, tracking where
> user space invokes syscalls with pointers to specific memory.
> 
> Breakpoints can be used for more complex dynamic analysis, such as race
> detection, memory-safety error detection, or data-flow analysis. Larger
> deployment by linking such dynamic analysis into binaries in production
> only becomes possible when no additional capabilities are required by
> unprivileged users. To improve coverage, it should then also be possible
> to enable breakpoints on user addresses that fire in the kernel with no
> additional capabilities.

I can understand the argument for watchpoints (modulo my concerns above), but
there's no need to support instruction breakpoints, right? i.e. there's no
legitimate reason for a user to want to monitor a given user address
system-wide, regardless of what's running?

IIUC this only makes sense for watchpoints, and only in the context of a given
task.

Thanks,
Mark.

> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> 
> Changelog
> ~~~~~~~~~
> 
> v2:
> * Commit message (motivation, more explanation).
> * Apply ack.
> 
> v1: https://lkml.kernel.org/r/20220902100057.404817-1-elver@google.com
> * Rebase.
> 
> RFC: https://lkml.kernel.org/r/20220601093502.364142-1-elver@google.com
> ---
>  include/linux/perf_event.h |  8 +-------
>  kernel/events/core.c       | 38 ++++++++++++++++++++++++++++++++++++++
>  2 files changed, 39 insertions(+), 7 deletions(-)
> 
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index c6a3bac76966..a95a6b889b00 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -1463,13 +1463,7 @@ static inline int perf_is_paranoid(void)
>  	return sysctl_perf_event_paranoid > -1;
>  }
>  
> -static inline int perf_allow_kernel(struct perf_event_attr *attr)
> -{
> -	if (sysctl_perf_event_paranoid > 1 && !perfmon_capable())
> -		return -EACCES;
> -
> -	return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
> -}
> +extern int perf_allow_kernel(struct perf_event_attr *attr);
>  
>  static inline int perf_allow_cpu(struct perf_event_attr *attr)
>  {
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index d56328e5080e..0f1fc9aef294 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -3174,6 +3174,12 @@ static int perf_event_modify_attr(struct perf_event *event,
>  		return -EOPNOTSUPP;
>  	}
>  
> +	if (!event->attr.exclude_kernel) {
> +		err = perf_allow_kernel(attr);
> +		if (err)
> +			return err;
> +	}
> +
>  	WARN_ON_ONCE(event->ctx->parent_ctx);
>  
>  	mutex_lock(&event->child_mutex);
> @@ -12289,6 +12295,38 @@ perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
>  	return is_capable || ptrace_may_access(task, ptrace_mode);
>  }
>  
> +/*
> + * Check if unprivileged users are allowed to set up breakpoints on user
> + * addresses that also count when the kernel accesses them.
> + */
> +static bool perf_allow_kernel_breakpoint(struct perf_event_attr *attr)
> +{
> +	if (attr->type != PERF_TYPE_BREAKPOINT)
> +		return false;
> +
> +	/*
> +	 * The sample may contain IPs, registers, or other information that may
> +	 * disclose kernel addresses or timing information. Disallow any kind of
> +	 * additional sample information.
> +	 */
> +	if (attr->sample_type)
> +		return false;
> +
> +	/*
> +	 * Only allow kernel breakpoints on user addresses.
> +	 */
> +	return access_ok((void __user *)(unsigned long)attr->bp_addr, attr->bp_len);
> +}
> +
> +int perf_allow_kernel(struct perf_event_attr *attr)
> +{
> +	if (sysctl_perf_event_paranoid > 1 && !perfmon_capable() &&
> +	    !perf_allow_kernel_breakpoint(attr))
> +		return -EACCES;
> +
> +	return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
> +}
> +
>  /**
>   * sys_perf_event_open - open a performance event, associate it to a task/cpu
>   *
> -- 
> 2.39.1.456.gfc5497dd1b-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9QUi7oU3nbdIV1J%40FVFF77S0Q05N.
