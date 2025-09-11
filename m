Return-Path: <kasan-dev+bncBDC4FFVJQ4BRBXFXRDDAMGQEBFITREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BD0BB5251D
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 02:46:22 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-723954c62e0sf3730147b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 17:46:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757551581; cv=pass;
        d=google.com; s=arc-20240605;
        b=G6xgmYCkUCScGqfqEdxcwsUF3F3+Fjr3KgbMnZtZdOUZ3sk9WbFuX8/9QVUikQVqR2
         TF6+YG1dyFb8/UVafCfvx1PYLh9BA4+4VHFwPKutkoLZZ64EWD49UOu80heACAu6gjX2
         3QoVuWd4ERCTC+W4yNWZMM7o0wF6qckOmj8PhiTUh+xdjVfFcSMigYVadECH5ZOtu062
         NEep1LxrOuszC217pUK+auhWqwsWGnFoKqYO2AuPX3o7xN/dRoAf0zRf4ymUztv4A0Jj
         YtuML11iGH9AEDPH3TKLmlpPQQ7uh7kiVmdrWhexmlm4KCOLMSnW7vXapUmU8Z2Hw1ir
         DuGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=q0SxtWtNqQHFO3cY6BwQ1OcezptMt4qz+AXK4xtGOGQ=;
        fh=DXufvsy2E/4B0Y3umUSLT1gCMIXfUWfc1qV6aZm8uZI=;
        b=PJE3yeLvJZCOPxBB7QbRKHrPBCxaYrx0l7VG7HTuv+jXIQyfnHGZ6GokpErfPLq+Zq
         huaPzc7H3rIQXcXZRB4MoDm0gykBsmfEtZSzjjJ308E9FJRczB63OFOnIVvzh2BnRpnd
         LKzQ4WY/0AIA3hqMAupgbpPW0E3Xuk4tNKN93RX9U2bMlJ0nQUuZ9s0Nrr3r589KRjwY
         1njtlU2lKwGZMoP2NzK4mmmJhMUl3H9pwiyVk3YzWTIom09/U7ws8X9T3xF1feNPpMwO
         /DFxW84nclDiYCxSdMxeclIN/KN9EG17wELjpA3J1UVREsMwtF8ySxlF2ksmMrYoJwD5
         xIVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QB8At8RC;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757551581; x=1758156381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q0SxtWtNqQHFO3cY6BwQ1OcezptMt4qz+AXK4xtGOGQ=;
        b=arDD5IiFF+sDu31M1krBgBLW8mA+Nh0kXofHKxmnPWwCAvBzsIWD0Ogd5vlkXZGXCb
         +3CjlTN589Ugja+/2hsjimJky2eUr9B4pKSKmpEQLKlNno/D+v5AXBvmrbJV27JQIIu/
         O6wOSTF5Dv4uUMCulWHOQWslK9RZWAZYJNiJSQwL1oJPHSOmZGZBGUdxKjTBArT3rk6t
         4XvA8uae0hIdWHH4WVxQXtdE3qiCXr5WLgjkeKpckgaoKRvLp7Prvrib+RFTAPjT+hHl
         nUXTsGbuBGFownidRGTcknncNVHUPp4nfHQtYBjpxPRL4PekCuA0Iyr+PGv2sPP50eIL
         +7PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757551581; x=1758156381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q0SxtWtNqQHFO3cY6BwQ1OcezptMt4qz+AXK4xtGOGQ=;
        b=oLowf0UgPRzWYnVq6kiMemsW7h7fq8bVPDFCmvV1gg6Gz8DW89IH0mml6vlf8fdJb9
         uVnDOifhm9C9JLaLQMb/NEEwPLZ8z62jHfwQB5KX+hXqjNWywGJvq52J2vxSoq3LxxHX
         Lgu9avdVvtcz1MUUtOaTEqfYi2qGNabP7AESyBlAJqgCPLyt1KxD1gmeisfqf4LkzNuC
         qGfe8nL2pbHp4aO9Iuc/mPMp3zVJH1nvj5YZyGhhM+y0cGuIasSWoLEPufjK/epO4Tn4
         Qju7YHIMjfGBZIQOk8TfssfxSooTvvGzjGPjFDaT278ocKms06698XPnbbskzF8bzUyO
         ux4g==
X-Forwarded-Encrypted: i=2; AJvYcCXiGRfqub+qAHFRnhTp7N2wiYQQvE2XV5qRnKogKlQopcXN6uZb+kiv2m2PCWeRyLnuim4ziQ==@lfdr.de
X-Gm-Message-State: AOJu0YzruotBkAGRwBCubrq3Kpjyr5v5FjR+DBjw7BKDtMwXVfX1c83G
	oRe4uwJ4pdFc6aWLbRwTewggpsJ6ur5tkx3xLYRhj/3aGWVIgp2wrb57
X-Google-Smtp-Source: AGHT+IFJHZ4amm/pxYj5WgNo6F4jZSDVXqsEc47LaC33cnzL05wk5j+00bD3rqzrQvNoSW26mb7c2g==
X-Received: by 2002:a05:690c:380f:b0:71f:f359:6ca2 with SMTP id 00721157ae682-727f593e146mr162750377b3.52.1757551580720;
        Wed, 10 Sep 2025 17:46:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7gAMqDbzCgQ0NH9HCvsaLqLrA6yEZvJi9r0fwGSG3G4A==
Received: by 2002:a05:690e:2549:b0:5f3:b853:a8e3 with SMTP id
 956f58d0204a3-623f31883b3ls70827d50.0.-pod-prod-04-us; Wed, 10 Sep 2025
 17:46:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNEsnnPC7u1RqHAonyTrqhezEhx4r7f21vEWH2PkRB8ENpnpxkBa8ASdzrGA4ORSH24g5iX4Nasi0=@googlegroups.com
X-Received: by 2002:a05:690e:23c2:b0:601:9c7d:e49e with SMTP id 956f58d0204a3-61026ee524dmr8831506d50.5.1757551579576;
        Wed, 10 Sep 2025 17:46:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757551579; cv=none;
        d=google.com; s=arc-20240605;
        b=krdux0ac3qzMy4fn1Xk+2J5KTQp0/Vg4yTukHONA6c6EFNk075UBM78RGTaU/SuJ9Y
         DQrf4pmjigbeAOgdEeOfVK0egq94X7LEiUoivTyOzzJrbTAhAsxTerKr4mHPsvXaJNLa
         uxIFlWZUB5VUCassSuUl3TXE2tw+Zd8uezNYxVDxl6zW6dl4IxUE4NZNmYa6EVJ95TQC
         pfW8osEj4LGmoWWa4+0n5sAfvBW+iDxBnNpAi21C+cWm4XNqeaCp0TSpid3TiXaYPNBQ
         rFvu9oDB+Hb6Bt72wbFIDb+EES2WvJk2zzYFigqpnA+mdVHY8CrJ24XnyqVDua+UNGWx
         lIAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bhmCRE1xvUkDdFSmNKcdyJjIq+1gf0S/XmVmi+FDygA=;
        fh=1/QbizLL+du2g9C6ehvJt0jZCXKiWTgT/c+ay0+ZNSQ=;
        b=eVRO+Ln9+qRb6j98uYSjelySzLHHa1EgA39Sj+zdXZqMyCENukEmo1rLoFKzlWZH4e
         6nzUwAu9ixGz4g7ywzXuW5h9t5mI7EgPlyFC2+U9N1ZH/2E1UbTsorTcoM7O6MSPtb4y
         bFbPJCdeEjkXp6aDTs/OuDS2shKvW4nClcpjXiRl2Yt8E879mGNM6iIrwMYJ4DDt/+WQ
         HGkthjR5zdKMDE9ZANftiu9FXdrcCH6VBfBC+ioSg8oucnyW9ipiTgMxNXV/GvkeYzuf
         gQ9YvtuAPJ3BmpLGWRsxq4tYEgEctVw930Dc9Yik5iSRInEHcmmpsRoSgVVDTXTaG24r
         ffzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QB8At8RC;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6247dc39033si7387d50.1.2025.09.10.17.46.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Sep 2025 17:46:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhiramat@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A8EBD405E4;
	Thu, 11 Sep 2025 00:46:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1598C4CEEB;
	Thu, 11 Sep 2025 00:46:11 +0000 (UTC)
Date: Thu, 11 Sep 2025 09:46:09 +0900
From: "'Masami Hiramatsu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, "Naveen N . Rao"
 <naveen@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, "David S. Miller"
 <davem@davemloft.net>, Steven Rostedt <rostedt@goodmis.org>, Mathieu
 Desnoyers <mathieu.desnoyers@efficios.com>, Ingo Molnar <mingo@redhat.com>,
 Arnaldo Carvalho de Melo <acme@kernel.org>, Namhyung Kim
 <namhyung@kernel.org>, Mark Rutland <mark.rutland@arm.com>, Alexander
 Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa
 <jolsa@kernel.org>, Ian Rogers <irogers@google.com>, Adrian Hunter
 <adrian.hunter@intel.com>, "Liang, Kan" <kan.liang@linux.intel.com>, Thomas
 Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, linux-mm@kvack.org, linux-trace-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 01/19] x86/hw_breakpoint: introduce
 arch_reinstall_hw_breakpoint() for atomic context
Message-Id: <20250911094609.5f30e9767ffc3040068ed052@kernel.org>
In-Reply-To: <20250910052335.1151048-2-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
	<20250910052335.1151048-2-wangjinchao600@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mhiramat@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QB8At8RC;       spf=pass
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

Hi Jinchao,

On Wed, 10 Sep 2025 13:23:10 +0800
Jinchao Wang <wangjinchao600@gmail.com> wrote:

> Introduce arch_reinstall_hw_breakpoint() to update hardware breakpoint
> parameters (address, length, type) without freeing and reallocating the
> debug register slot.
> 
> This allows atomic updates in contexts where memory allocation is not
> permitted, such as kprobe handlers.
> 
> Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> ---
>  arch/x86/include/asm/hw_breakpoint.h |  1 +
>  arch/x86/kernel/hw_breakpoint.c      | 50 ++++++++++++++++++++++++++++
>  2 files changed, 51 insertions(+)
> 
> diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
> index 0bc931cd0698..bb7c70ad22fe 100644
> --- a/arch/x86/include/asm/hw_breakpoint.h
> +++ b/arch/x86/include/asm/hw_breakpoint.h
> @@ -59,6 +59,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
>  
>  
>  int arch_install_hw_breakpoint(struct perf_event *bp);
> +int arch_reinstall_hw_breakpoint(struct perf_event *bp);
>  void arch_uninstall_hw_breakpoint(struct perf_event *bp);
>  void hw_breakpoint_pmu_read(struct perf_event *bp);
>  void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
> diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
> index b01644c949b2..89135229ed21 100644
> --- a/arch/x86/kernel/hw_breakpoint.c
> +++ b/arch/x86/kernel/hw_breakpoint.c
> @@ -132,6 +132,56 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
>  	return 0;
>  }
>  
> +/*
> + * Reinstall a hardware breakpoint on the current CPU.
> + *
> + * This function is used to re-establish a perf counter hardware breakpoint.
> + * It finds the debug address register slot previously allocated for the
> + * breakpoint and re-enables it by writing the address to the debug register
> + * and setting the corresponding bits in the debug control register (DR7).
> + *
> + * It is expected that the breakpoint's event context lock is already held
> + * and interrupts are disabled, ensuring atomicity and safety from other
> + * event handlers.
> + */
> +int arch_reinstall_hw_breakpoint(struct perf_event *bp)
> +{
> +	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
> +	unsigned long *dr7;
> +	int i;
> +
> +	lockdep_assert_irqs_disabled();
> +
> +	for (i = 0; i < HBP_NUM; i++) {
> +		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
> +
> +		if (*slot == bp)
> +			break;
> +	}
> +
> +	if (WARN_ONCE(i == HBP_NUM, "Can't find a matching breakpoint slot"))
> +		return -EINVAL;
> +
> +	set_debugreg(info->address, i);
> +	__this_cpu_write(cpu_debugreg[i], info->address);
> +
> +	dr7 = this_cpu_ptr(&cpu_dr7);
> +	*dr7 |= encode_dr7(i, info->len, info->type);
> +
> +	/*
> +	 * Ensure we first write cpu_dr7 before we set the DR7 register.
> +	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
> +	 */
> +	barrier();
> +
> +	set_debugreg(*dr7, 7);
> +	if (info->mask)
> +		amd_set_dr_addr_mask(info->mask, i);
> +
> +	return 0;
> +}
> +EXPORT_SYMBOL_GPL(arch_reinstall_hw_breakpoint);

Please do not expose the arch dependent symbol. Instead, you should
expose an arch independent wrapper.

Anyway, you also need to share the same code with arch_install_hw_breakpoint()
like below;

Thanks,


diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index 89135229ed21..2f3c5406999e 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -84,6 +84,28 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
 	return (dr7 >> (bpnum * DR_ENABLE_SIZE)) & 0x3;
 }
 
+static void __arch_install_hw_breakpoint(struct perf_event *bp, int regno)
+{
+	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
+	unsigned long *dr7;
+
+	set_debugreg(info->address, regno);
+	__this_cpu_write(cpu_debugreg[i], info->address);
+
+	dr7 = this_cpu_ptr(&cpu_dr7);
+	*dr7 |= encode_dr7(i, info->len, info->type);
+
+	/*
+	 * Ensure we first write cpu_dr7 before we set the DR7 register.
+	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	barrier();
+
+	set_debugreg(*dr7, 7);
+	if (info->mask)
+		amd_set_dr_addr_mask(info->mask, i);
+}
+
 /*
  * Install a perf counter breakpoint.
  *
@@ -95,8 +117,6 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
  */
 int arch_install_hw_breakpoint(struct perf_event *bp)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
 	int i;
 
 	lockdep_assert_irqs_disabled();
@@ -113,22 +133,7 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
 		return -EBUSY;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
-
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
-
-	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
-
-	set_debugreg(*dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
-
+	__arch_install_hw_breakpoint(bp, i);
 	return 0;
 }
 
@@ -146,8 +151,6 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
  */
 int arch_reinstall_hw_breakpoint(struct perf_event *bp)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
 	int i;
 
 	lockdep_assert_irqs_disabled();
@@ -162,22 +165,7 @@ int arch_reinstall_hw_breakpoint(struct perf_event *bp)
 	if (WARN_ONCE(i == HBP_NUM, "Can't find a matching breakpoint slot"))
 		return -EINVAL;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
-
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
-
-	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
-
-	set_debugreg(*dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
-
+	__arch_install_hw_breakpoint(bp, i);
 	return 0;
 }
 EXPORT_SYMBOL_GPL(arch_reinstall_hw_breakpoint);

-- 
Masami Hiramatsu (Google) <mhiramat@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250911094609.5f30e9767ffc3040068ed052%40kernel.org.
