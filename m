Return-Path: <kasan-dev+bncBCXK7HEV3YBRB24SQ2AQMGQEHMCMOIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C3F3313E31
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 19:56:44 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id v1sf7213773oto.16
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 10:56:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612810603; cv=pass;
        d=google.com; s=arc-20160816;
        b=nm9FpuAxpET8JYUV3ykCrgJb+vhfGdICwXEbjHVFl9xn2E7MQ7IxrnKD5erwgp7ACX
         ab8K745noyd+lD09CNs9a48DMOsmqDIPW6Uc1m39Rw6BZ5aCs3thvIF77x8DhHZI0Ewg
         /57ctSXjhx2E8rWo0rckW7g8pxFyHKMUPwjo3IxPtQLF3furucKvDEqSemoTwQ9CX84o
         eiqTDLsnR4vzJTA5f0B1O23sVPDPlwPFl5Iq5jCOLC2QHys5u+e7J8JFv3Mu33unA0Ew
         LezFZz3YR36k2KDKAuiLckhTZZAbba5UOqtIXQ2HbdKm4glvwWTuacnz84+hLWMGohKO
         gMJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=C5IHD5fGQX66lj5HKqRFXGq8eT899yJxsG4XIncl0pU=;
        b=aFtLTkLi/mWgAJxGMlJ/g+JtyhuzV/ZE+BtyfVNISd3oQvN33bolWVxFhNaPYbV1C5
         jIkigU8s5+8tOcSYsswgVxN4AuyqieHBteoJsDWi9qr4OrGWXBcWbzWMDpYNcR4PeQbk
         ARmH4DI42p7jC4glvKIhlxrNX389HMbeBidrDcHePmCKzZV8nQR83UeYBJ0S28gltK7Y
         I0aGgWsDSk9nARJ7UHW9wmvwNn73RVPGnyA8yo3Sztl1yrWtSnFE4ttlWXW587TYsWDH
         270m2iDqZqrIaHnCW98IfX2vxTCqb1/54/VqdQecyvkWobKWu9TT5mND8z5vY37M3Tlv
         Hb+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C5IHD5fGQX66lj5HKqRFXGq8eT899yJxsG4XIncl0pU=;
        b=YNRSfMkUS1MP5Lqmh84dlBHS/s3Xh5Drwj0A7X8BqyDAcMnK7z7dXONMGpPbTu8LOW
         LIeZ6mY786w6wO+XMZL2ny2TprsN8CS7No2k/3vtWmRcqA8bk+PYxUYHzdIT+S1hjYw9
         Wcw20Zzz9LOdzeG2uFreHELQ/yP1GmarTuxv+707ji8qNe1FdTQ6Fur6XEDoNcSVQAEA
         B8w1QL5TM9GfQO8Nl3fC4I/2Xq6pdq9uQ0XFH/qdd+3mEuJBarTFH73ozu8vIeZPTSnE
         5nih6qsf1CMKd6AcY4J81TMrMr+aqlQa+0A73p3vT3U70Jh2bLlartNrvuM56q0VGF2h
         /cAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C5IHD5fGQX66lj5HKqRFXGq8eT899yJxsG4XIncl0pU=;
        b=AtYm22MiyB4qgUCoVxnThvYYEJM8PE3wfSddPI0lUujdOsvsyNHElG+oo9mro8+ee2
         ihFr6OLmtbJD0nJxdv+jKhZkFA+se1SAzGVarL/hiXUEnztjq50mutl8NmCuFoV+w8+q
         yxZxpwJQxdYMplF0eyqwPqSXFj1i8YpI4LMQ8eCODx3ePADb6hXvZk1ceniQbUROUwcv
         hm9lin44hgmd23NWHw/8+AyQRKzhi9cBuUlxjhfRrsh+bgez0MSK62WH8VurkoqBfsyR
         g3EXB2dzPQc/Msic+hWElvEW06RcaK4rNQxvO3ezVQIGAS6GnnwsMnoETIR+doQQkVBt
         SFNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hHXg7cxVbxYi4FX8kRVtIowe255/E0EXA4DZ6C3XkSo4Q6FZT
	NAcyY9v8efSv5E6gCXo8eeA=
X-Google-Smtp-Source: ABdhPJx/OWcSfJKRkYTT/dihVcBAAvtUjEMTC1MefNPl2iRb8dRj7UfAHn8iOtenARSLsabCBTBnFQ==
X-Received: by 2002:a9d:1717:: with SMTP id i23mr13842909ota.179.1612810603611;
        Mon, 08 Feb 2021 10:56:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5c15:: with SMTP id o21ls2169687otk.10.gmail; Mon, 08
 Feb 2021 10:56:43 -0800 (PST)
X-Received: by 2002:a9d:6852:: with SMTP id c18mr13969172oto.166.1612810603215;
        Mon, 08 Feb 2021 10:56:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612810603; cv=none;
        d=google.com; s=arc-20160816;
        b=Oxzunji8JLqv+2DRE2gvqGzSFtEW4cOwt5xFKZ09IfwijV1FzYqRdCTXK22nUeYb7R
         WloSMnJFgTk8GIBaFUGoC+DWHdRs5CwfEZSxDTHfxoXzpcqBZYcQuWJ+ZGixVwGuyD1x
         4jNd+wXz88M1VUYkQeAChJtCbovDphr/lRC7cX3+e9zYTeQfIZjPybRl6wP4C4AGSxbM
         uL90tHvivF0xHE3OgddrqdEk+P1tXD/QP043LdWcG0brP18TUFFLA6KACODRps9lmVqf
         TveKZct10TtEecnxjIYEMtf/Wow8NIOr9LPjIVyOGqDzKI4IXRxkfw8LbsW9C+Z/byX/
         kZ9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=fuQZWQZnFShJJbZZvXm6YS5p4bxCxSotGow3yUb4zr0=;
        b=LKyf7iRgsJqORDSkkBaS39EVmKjo8KG2CG+fnunYWzKRWNw5TDe3tdLj6WyLngAh8x
         7VDuNUUyzUKII/l1aqJWKwrK2PIbL4Jjtn9LhGbudanKG5im4l64bwskkSSbLxKRdvcS
         QqK/CYaVSAb5Xc+peD+VmoAfeUmRE8/cYv5fzokIwp4ofTHC6CX8NADNBkcKU56nfCbc
         QbLDiCrCAzv+AkJgPvAGQ8j0ov3Qc9YypyY794GllA/K4os6dl9x8C7m3k/yhtIoK4Jn
         v+zFg49YxZtooICznmGbODa2Mk3E02M5kN+EfQOuT9PogVy+cKRoolb65UDrQAB31mgv
         DYwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m26si1148957otk.1.2021.02.08.10.56.43
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 10:56:43 -0800 (PST)
Received-SPF: pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A471D1042;
	Mon,  8 Feb 2021 10:56:42 -0800 (PST)
Received: from e121166-lin.cambridge.arm.com (e121166-lin.cambridge.arm.com [10.1.196.255])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DCE713F73D;
	Mon,  8 Feb 2021 10:56:40 -0800 (PST)
Date: Mon, 8 Feb 2021 18:56:35 +0000
From: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
Message-ID: <20210208185635.GA13187@e121166-lin.cambridge.arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210208165617.9977-7-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: lorenzo.pieralisi@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Feb 08, 2021 at 04:56:16PM +0000, Vincenzo Frascino wrote:
> When MTE async mode is enabled TFSR_EL1 contains the accumulative
> asynchronous tag check faults for EL1 and EL0.
> 
> During the suspend/resume operations the firmware might perform some
> operations that could change the state of the register resulting in
> a spurious tag check fault report.
> 
> Save/restore the state of the TFSR_EL1 register during the
> suspend/resume operations to prevent this to happen.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h |  4 ++++
>  arch/arm64/kernel/mte.c      | 22 ++++++++++++++++++++++
>  arch/arm64/kernel/suspend.c  |  3 +++
>  3 files changed, 29 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 237bb2f7309d..2d79bcaaeb30 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -43,6 +43,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
>  void flush_mte_state(void);
>  void mte_thread_switch(struct task_struct *next);
> +void mte_suspend_enter(void);
>  void mte_suspend_exit(void);
>  long set_mte_ctrl(struct task_struct *task, unsigned long arg);
>  long get_mte_ctrl(struct task_struct *task);
> @@ -68,6 +69,9 @@ static inline void flush_mte_state(void)
>  static inline void mte_thread_switch(struct task_struct *next)
>  {
>  }
> +static inline void mte_suspend_enter(void)
> +{
> +}
>  static inline void mte_suspend_exit(void)
>  {
>  }
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 3332aabda466..5c440967721b 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -25,6 +25,7 @@
>  
>  u64 gcr_kernel_excl __ro_after_init;
>  
> +static u64 mte_suspend_tfsr_el1;

IIUC you need this per-CPU (core loses context on suspend-to-RAM but also
CPUidle, S2R is single threaded but CPUidle runs on every core idle
thread).

Unless you sync/report it on enter/exit (please note: I am not familiar
with MTE so it is just a, perhaps silly, suggestion to avoid
saving/restoring it).

Lorenzo

>  static bool report_fault_once = true;
>  
>  /* Whether the MTE asynchronous mode is enabled. */
> @@ -295,12 +296,33 @@ void mte_thread_switch(struct task_struct *next)
>  	mte_check_tfsr_el1();
>  }
>  
> +void mte_suspend_enter(void)
> +{
> +	if (!system_supports_mte())
> +		return;
> +
> +	/*
> +	 * The barriers are required to guarantee that the indirect writes
> +	 * to TFSR_EL1 are synchronized before we save the state.
> +	 */
> +	dsb(nsh);
> +	isb();
> +
> +	/* Save SYS_TFSR_EL1 before suspend entry */
> +	mte_suspend_tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +}
> +
>  void mte_suspend_exit(void)
>  {
>  	if (!system_supports_mte())
>  		return;
>  
>  	update_gcr_el1_excl(gcr_kernel_excl);
> +
> +	/* Resume SYS_TFSR_EL1 after suspend exit */
> +	write_sysreg_s(mte_suspend_tfsr_el1, SYS_TFSR_EL1);
> +
> +	mte_check_tfsr_el1();
>  }
>  
>  long set_mte_ctrl(struct task_struct *task, unsigned long arg)
> diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
> index a67b37a7a47e..16caa9b32dae 100644
> --- a/arch/arm64/kernel/suspend.c
> +++ b/arch/arm64/kernel/suspend.c
> @@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
>  	unsigned long flags;
>  	struct sleep_stack_data state;
>  
> +	/* Report any MTE async fault before going to suspend. */
> +	mte_suspend_enter();
> +
>  	/*
>  	 * From this point debug exceptions are disabled to prevent
>  	 * updates to mdscr register (saved and restored along with
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208185635.GA13187%40e121166-lin.cambridge.arm.com.
