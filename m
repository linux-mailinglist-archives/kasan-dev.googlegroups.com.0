Return-Path: <kasan-dev+bncBDDL3KWR4EBRB27CTLBQMGQEOF3PYIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id BCB28AF7DFC
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 18:35:57 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-236725af87fsf1283375ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 09:35:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751560556; cv=pass;
        d=google.com; s=arc-20240605;
        b=bDfDPi0G7r2/C0V4fVdYVbWI7JvZV+ULx3Dwejwk0L0QkUeZt7jIgSil48Hea1rFne
         uSBeSWjBAgas/fqNyp8aHxBoW9VGCmMMlMqGvxizjNMicDPr07m9U8ZT4xsN5oQmbFBV
         MeOUF9DQBIlJs3chucLC5uO5/+M8xhUHjn+s4iN85U5SD2eYcshn8yfXWbrLx3rnOJFU
         ywfeAGNsbzi5O2eoeCb7XMgBk4cq0o9d1VgbxXn0gAwh2bfSOb9F2K97030yqq8nlHTK
         Oy8cdfs/62/V6Qy0wUbAe9D0si7ExKWSIVYomgHoCQkcAZGjOt8udHOaDfgGL5Eoc/k1
         2jVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JbB5Tn4kKzlATwyixaJvmgcxKW0T5VMVSObBgmdf1UY=;
        fh=ITVrSzOb5jnKp35gWeka+tYm67Rav/CR88qOJav5OSA=;
        b=K4JpcmqF8I0Zdru4kiBBJRLScOj4UV3at9DLs+d2Cw4vh2wpmeIVP20pcAh+Mp+1Wa
         g4MlRFJLuY1bgFphngyuKGjc2QwKKBqTrIbPUU0uWI9a3rkFWIYRPVlkq32zL5A4PiYx
         wFSmEMsXXToOo7Dd8y2LH8j3uG6oVA2DLCGF/miH2oS6HR6QucspFnMMcpdrrL9C6Vt5
         wxvaEHqHKJll2s5Xuang+YkNrlVWUp6jJW5ZKpHt4pF3kSzuJbiGBzG86/6nmJlQOWE4
         VNcE7fztED3bNP7p0TMwkAWXnXEI/EPfn9E+RdaXcY4bBAtTavEMwkipvbYnHIL81ihf
         PQdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751560556; x=1752165356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JbB5Tn4kKzlATwyixaJvmgcxKW0T5VMVSObBgmdf1UY=;
        b=dSqLbNJMOlCpmOkhzZlKtrRIEk1hkGbAGvfjxzr6/zxh2v4bSYnp2QRAwcQaeuFgOj
         uX0K3a+mmicy2/B4Zh4lOPOIW4ljaQjv56drdcp0kXg1f2X56gsaGQcquGeli+ReB/Ol
         iORLdphAdnAXrfwxhyeG5XkEuAv8vyKSVTPEJFRtdYOODpUkZsiIePjKnBv1IHiO7NMl
         LgiMK3T7HSzxbfL8KSgWEK2EAOW+not/OkyvgYXUYcbfgdE/G3R3MOQSC0jSyW9P3vMV
         RudCrRtgFbcAYsKz7EBoHTJDYSdpttgUgGpkKc4mEqSNZ0h0K4/jg+Qd43sECHOnCWqR
         9YWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751560556; x=1752165356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JbB5Tn4kKzlATwyixaJvmgcxKW0T5VMVSObBgmdf1UY=;
        b=YmzT8CR1we7aJYTq98q2CZ38SC96t/YZ1GwNl3sXPbcob5HMm3mKD3hSDTIFDYxOrn
         E0n/GVbmsCJ7DgolPvx1xu2MfKrDf9td/SQMv9waRwVRqHOIGYNww4l3B26gdWVdm+4B
         DR7ByMkUwz3qZ7LEZt1Lk3DSzRQbWLeYbIwiCXhhx3MebiTNo+J7a/+ihNPrfY5gO5/B
         6qM9LLnIx03USFliyvzIIOIrOIh7c8bcshL8P0pT4ZEGqQmQ7tt68JxyS0vIYAl8IE7g
         /OmlsEy3wUkbbo7ajY5hT1/mBRI6dcCsindMZArg3roiyUwUZfDuW4Wm4EzEcrJnDfZT
         e5fg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyTSjxdsrFhqJMwo+kezXM2yY9GzP7S0oTn5yD+0KB1t0kOd9wfbGua9rRxcj83JT2AwG2/g==@lfdr.de
X-Gm-Message-State: AOJu0YzN6N1AelmIv+in0Nu92Znky1fAaiPHPP53UyyW1DyYuBPxUbgU
	DeE08vNvyF/BO+11vj+ew5BsIayPXmhN1fi3fBmzO6JreQkXXbKBBGJP
X-Google-Smtp-Source: AGHT+IEeFm887J4bNI/cjGQF/NkTiXuRjZ14bTVbYTfL6vez+IwJgcw6VJQQdUihEd4KcT/g+4lr2A==
X-Received: by 2002:a17:902:cf51:b0:23c:7b9e:1638 with SMTP id d9443c01a7336-23c7b9e1708mr27239585ad.35.1751560555898;
        Thu, 03 Jul 2025 09:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe7TJ7bDidZBPuy+SkaPJn/AIyyDjlD4LVnyeAUI8JZiQ==
Received: by 2002:a17:903:2cb:b0:234:d1d3:ca2 with SMTP id d9443c01a7336-23c837c936bls823155ad.1.-pod-prod-03-us;
 Thu, 03 Jul 2025 09:35:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyYeKWl3Uo77HZLt430OCEXwIf8wv3ApteX4NduelpQUk/Czh5WDnXtjzc4ekO0sZTkh1WsnhOOuQ=@googlegroups.com
X-Received: by 2002:a17:902:cccb:b0:238:120:134a with SMTP id d9443c01a7336-23c6e539ce7mr116539335ad.22.1751560554115;
        Thu, 03 Jul 2025 09:35:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751560554; cv=none;
        d=google.com; s=arc-20240605;
        b=Gu46cIvJvf7S6TADSq8fMR6/96+iTT/dKVuFvrSNbZfwajkf9NPi6pYMXBePCTLCHZ
         51FZrrRbUNqpCrjQE26bO2cvzm1WkytyrVKw+oL8b6WwMhna/ZCMgICbi5X4BShsl3v8
         eqm5B2OBS3gJeflsGhRV+LOX/3khgE82gIjjuxIP9BAvqpMsC1dHA2IByaO5Fbbe7w2v
         RjWVRIpjZVx0T61NblCa+N7dWz28x3cDEOBUyKys9khSB0xK4IJv3zPYxZr8UZwqkVFs
         b68Pyybjl6x26XhLkMfuuiuC7hJdqnZSeVzFoSLBMaXxXkX9XTts6g6upxRtHBQR2LI9
         pQPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=rF2qYrvErubAyGK8fOu3JYouiv0z9Oj4BLs/e8Dkg7g=;
        fh=FvL1ULwV5Gvjv24gkv97gwuJpEPP1pin4/VP6hZ6B/0=;
        b=QlCHZpDK4Cigy9oaRixv686e2RqDf2YNdsb+wEXM9EID2CIxKns+oapwHIeSMhl2/L
         kR5AbUBbQn0P9Vv9S+v76G+wBhQDpRgDXRcjkAsQJMyn4IAP1OYA6k4haGLs63W4B4GE
         J90PpQ5x0DloZYJ9Xc5SSLVAqvVjXbSuVd3iQo6kwoXNhc25Kj1BlnoEvtE1yguPzakT
         oN1P4p1ZcHJG32zzU3WgGkvcPyFNbHdS5v3pKeDQGx4vuVtvmajnmRYpi71JNaV6bEEt
         koP3zY5OrAG91bBVDT7c0q+uwpeRsk23zk/sDvEMCswNFlTSIMPLATdOf5xXxiVmnj30
         n6QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b38ee43e930si2330a12.2.2025.07.03.09.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Jul 2025 09:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id EBAF461446;
	Thu,  3 Jul 2025 16:35:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4BADC4CEE3;
	Thu,  3 Jul 2025 16:35:50 +0000 (UTC)
Date: Thu, 3 Jul 2025 17:35:48 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Breno Leitao <leitao@debian.org>
Cc: Will Deacon <will@kernel.org>, usamaarif642@gmail.com,
	Ard Biesheuvel <ardb@kernel.org>, rmikey@meta.com,
	andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGaxZHLnDQc_kSur@arm.com>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
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

On Tue, Jun 24, 2025 at 05:55:53AM -0700, Breno Leitao wrote:
> KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
> services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
> with KASAN tags reset to avoid false positives.
> 
> This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
> EFI stack allocation, which internally calls kasan_reset_tag()
> 
> The changes ensure EFI runtime stacks are properly sanitized for KASAN
> while maintaining functional consistency.
> 
> Link: https://lore.kernel.org/all/aFVVEgD0236LdrL6@gmail.com/ [1]
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Breno Leitao <leitao@debian.org>
> ---
>  arch/arm64/kernel/efi.c | 9 ++++++---
>  1 file changed, 6 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/kernel/efi.c b/arch/arm64/kernel/efi.c
> index 3857fd7ee8d46..d2af881a48290 100644
> --- a/arch/arm64/kernel/efi.c
> +++ b/arch/arm64/kernel/efi.c
> @@ -15,6 +15,7 @@
>  
>  #include <asm/efi.h>
>  #include <asm/stacktrace.h>
> +#include <asm/vmap_stack.h>
>  
>  static bool region_is_misaligned(const efi_memory_desc_t *md)
>  {
> @@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
>  	if (!efi_enabled(EFI_RUNTIME_SERVICES))
>  		return 0;
>  
> -	p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> -			   NUMA_NO_NODE, &&l);
> -l:	if (!p) {
> +	if (!IS_ENABLED(CONFIG_VMAP_STACK))
> +		return -ENOMEM;

Mark Rutland pointed out in a private chat that this should probably
clear the EFI_RUNTIME_SERVICES flag as well.

> +
> +	p = arch_alloc_vmap_stack(THREAD_SIZE, NUMA_NO_NODE);
> +	if (!p) {
>  		pr_warn("Failed to allocate EFI runtime stack\n");
>  		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
>  		return -ENOMEM;
> 

With that:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

(but let's see if Ard has a different opinion on the approach)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGaxZHLnDQc_kSur%40arm.com.
