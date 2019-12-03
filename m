Return-Path: <kasan-dev+bncBDN5FEVB5YIRBDMZTPXQKGQE7RLHAAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id A891E110632
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 21:58:54 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id b3sf476478vsl.12
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 12:58:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575406733; cv=pass;
        d=google.com; s=arc-20160816;
        b=u2jxRweNVX09z993Xl1PE7f30x4SHEf1dL2DinylYSTBFmSpmzFJuYJBRNRyWtMkxU
         MNEWPCMpb0A5ApTPEqMuwU0WIRtape4DBrG1Pze+cQ0ghYhyumNL2s8pgaXonzPELKew
         Y/AbJHRmR2SdUdf8DRL7N1ZSxdSXEuLvPOfyzihkuF4GLjGe8T5TV9CSN5MDG1oQRyrs
         7XuOk70115RVtsFtS6/dd85fGuIgbGAUMqhD0BUFykuACMXB9uSn8j8xmUIPfjlOk1wj
         58mCApU8nXjZuouK11UJ5qreAZCZli8dajs/xv61qGcqUnKLj3q4RCTKl4KKt/rqEVIY
         5MQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pf+IDUNx3T3zZVYu3ccDY8M4k/7vnIUcIZkPBQLpJgI=;
        b=ezKo4QOJmCYLLz/CGCj1GeUqFHK+EbWvJfy6CK61tLx9aNKXVCI11KtLVcxOJIB2iv
         zmZYFkzM4QYcPjWoijwfzKDs1pulpLogus7mnT94gXuzJw/5Diper8l8wk3UXGD2WFXg
         xNlDlNJNknOpHmfTLT12we5Mj/2gd10MA7WGdCx7T1tqTLqXHJVlvdDyjLH+l71+IrSU
         ySOoXzWrrKt5SJZNaqaJP4jaZyOLfpjVZvhwkhRJiiAbs4gUbB72EfgXSTBwZOPAJKVk
         X1FY33NV+9Mwvu0lcFzYIN0wpwaWg18JFeKtRcnNkamyAjfztyQ51xgvqBHWvL8028kP
         KpOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pf+IDUNx3T3zZVYu3ccDY8M4k/7vnIUcIZkPBQLpJgI=;
        b=WTJflxiCPuuLdGLjeB18Kj3VYZ3fLoK74jlX8OquCJIT8UeJkBGy0QR1pweWRh0JcT
         UZ0WMju+cdAdg3juiD4zxGALa9r68PPpsGnTbkTcti0duI2FZ7eNHPSS4N+AsKCmBKHr
         POw0fdE0DtCWWu48YoxkX6edCvhaFlBEYsTm0suM/hL6bkd6sNwaZQNa8v7Yxm/o3qkv
         qcv6Y5ozrmYFTX3FtwZ27x6GjAuyZnF7L5PAeTNSUzAW/xM9l5EgoT6WmJfitxOOKqhl
         2dN3qbWodh1DQwW8VQwhwlbdACFufbOwIy/vqEVf1RqzernROuMOBSwgP6G4b70rigi8
         YogQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pf+IDUNx3T3zZVYu3ccDY8M4k/7vnIUcIZkPBQLpJgI=;
        b=oCy44kbyW3woxE9Uxy0XQnsG5UzBkKnyZ2ta0QT0eNrreWZyx+B3BrLOjoi9fyddEg
         4uLZMLSou5itYxcwGmw8L1y4wHEwJ55IdSbSUDU35mSIGoGqjq5OKzlE98Pm2wI1ajqe
         tgFQSCcDkvr32Ump96QNxp6T8ZoD55LdTISRKiBe4wVKZHRHnQ3cxqiJo8QkDvOtMedI
         hI8SwCBSlsmKb0/GhdLCqiMw9ulCQqnnfI3Gae58RomhTFiemjfFiGN2Win8wWtZ71DF
         DXMhKdiagG0OTIxiERxBs9yKG3O1dfZnPZ/GrE0M8vR4on9ALUvlyNjnrpSyguK6/WR8
         dy/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW/XYyBQ5Jjk3NUp2r7ryhmVjYsrag3uuN5TurlpXz1QS165IEQ
	ninDA9mKXCyhBqzrAX6NQaI=
X-Google-Smtp-Source: APXvYqyi41cUsn++rZKdxo5H9SUoAA8h7kEtiCO+LEO/fq0rn0iI+gt2UvB2v0Y/hIQlmPy7ZfQLXA==
X-Received: by 2002:ab0:21cc:: with SMTP id u12mr69808uan.55.1575406733178;
        Tue, 03 Dec 2019 12:58:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc8b:: with SMTP id x11ls400295vsp.7.gmail; Tue, 03 Dec
 2019 12:58:52 -0800 (PST)
X-Received: by 2002:a67:e8c4:: with SMTP id y4mr4540100vsn.0.1575406732864;
        Tue, 03 Dec 2019 12:58:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575406732; cv=none;
        d=google.com; s=arc-20160816;
        b=L00Zi0ZOygdzc4IomV6AOCIf3C5gDQgZdegTm+jDrrtAEGjjXA8H+E9ToAHv6gORgC
         zWlCy4q+z5+knuoMH1MWcFGfu6CoezytMdYVISeQyfpxE8cJPBwrFki+3aKAtyVsR9Vi
         Q97VEuzaob2FYhUMBgKoD9HvzBJ5seC4xmYiNPhToa3UElkebH4Bi7XjU5TweyP+e6fi
         WYBi98IzC8ndFmryJlc6aWgnH33iNRIHXuVL58I6efo8hqxQycX5iMaYWwdd0jjvma03
         2QvZLxFbOZaX6bDi7oVKt7uHA/S61I6X8jf9I8Vo2KeM4RLbMdAw3b4yAg8WGd65EPNR
         bE7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pjZjdGP2w3iW5zooa+QIeX85GyFtFMHVHLLxEckFmz0=;
        b=xSRXEi8wZuaeSWdMiua/N8Bj64tfhSWZeS/JiqkfdFcfFdVhayKhTwJASZAHmL2GOB
         GoGtnOnAGxhNKGUST7Q5PW+cGpSvUl0FkBinMp5MuCHLUWZ/TSY2oDuh7gpxdF/YSBNt
         47SLtUEUVRCLgdJTFNBRjFxHEoMTCFpsRatH48ItNFyAfwuC9NGwqkDJ6wrbPFto4r0C
         8B7qZMl+U+s0zv0YP22hbKAzkgQVkrvrwlXfQsltTdd6aESj64HAjilkt5BZEa9mKuM6
         QSz2U3hB6dhNEwkuJyZJaF1Q+nO9A3HarpmR/AIr8xb8NOzLcfhlrmv+fhLyZgidnKUD
         iWCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id n13si191514vsm.0.2019.12.03.12.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Dec 2019 12:58:52 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga106.fm.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 03 Dec 2019 12:58:52 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.69,274,1571727600"; 
   d="scan'208";a="205128882"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by orsmga008.jf.intel.com with ESMTP; 03 Dec 2019 12:58:51 -0800
Date: Tue, 3 Dec 2019 12:58:51 -0800
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH v5 2/4] x86/traps: Print address on #GP
Message-ID: <20191203205850.GF19877@linux.intel.com>
References: <20191127234916.31175-1-jannh@google.com>
 <20191127234916.31175-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191127234916.31175-2-jannh@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Nov 28, 2019 at 12:49:14AM +0100, Jann Horn wrote:

With a few nits below,

Reviewed-and-tested-by: Sean Christopherson <sean.j.christopherson@intel.com>

> +#define GPFSTR "general protection fault"
> +
>  dotraplinkage void
>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> -	const char *desc = "general protection fault";
>  	struct task_struct *tsk;
> +	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;

Nit, x86 maintainers prefer inverse fir tree for variable declarations.

>  
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
>  	cond_local_irq_enable(regs);
> @@ -540,6 +587,9 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  
>  	tsk = current;
>  	if (!user_mode(regs)) {
> +		enum kernel_gp_hint hint = GP_NO_HINT;
> +		unsigned long gp_addr;
> +
>  		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
>  			return;
>  
> @@ -556,8 +606,22 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  			return;
>  
>  		if (notify_die(DIE_GPF, desc, regs, error_code,
> -			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> -			die(desc, regs, error_code);
> +			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> +			return;
> +
> +		if (error_code)
> +			snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
> +		else
> +			hint = get_kernel_gp_address(regs, &gp_addr);
> +
> +		if (hint != GP_NO_HINT)
> +			snprintf(desc, sizeof(desc), GPFSTR " %s 0x%lx",

Nit, probably should have a comma before the hint, i.e. GPFSTR ", %s...".

    general protection fault maybe for address 0xffffc9000017cf58: 0000 [#1] SMP
    general protection fault probably for non-canonical address 0xdead000000000000: 0000 [#1] SMP

  vs. 

    general protection fault, maybe for address 0xffffc9000017cf58: 0000 [#1] SMP
    general protection fault, probably for non-canonical address 0xdead000000000000: 0000 [#1] SMP

> +				 (hint == GP_NON_CANONICAL) ?
> +				 "probably for non-canonical address" :
> +				 "maybe for address",
> +				 gp_addr);
> +
> +		die(desc, regs, error_code);
>  		return;
>  	}
>  
> -- 
> 2.24.0.432.g9d3f5f5b63-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191203205850.GF19877%40linux.intel.com.
