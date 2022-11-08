Return-Path: <kasan-dev+bncBCSL7B6LWYHBBHXIVKNQMGQEF5XL43Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B582621D51
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Nov 2022 20:55:11 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id i14-20020adfa50e000000b0023652707418sf4385315wrb.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Nov 2022 11:55:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667937311; cv=pass;
        d=google.com; s=arc-20160816;
        b=qRA+1Mq8330giwrAo0JKykTGBjWedTFGb3StT3sAVnOnlfrzrFJnxtB/T0KCTfkW3w
         g+XIETVrqYeEkOFR4WPInJJqu2mEbuSrZwzOgKDp/S0Pg+WEumHNgT4VwMSs3N0P6qsH
         w005gzQ/M1/5R6kedJ3Y2y58IseA0zDdfosUl14YHyJ/NOr1NTJa5iojogHwtZq9fKrc
         qT1wx58AtcdL1gwaQx0XzYInAoprXxvW8zIO/+YP2IreeZZQkoD5/f8d1O+JmPMIZUyT
         YF5RD2mpVkUxyHMu7g8pq1gStB00FS4r2DumsMjAVyY0iauF8dOzb/omypwHYpwYOTw/
         YaPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=trIbwh1Zw8sTGxwsD4Lca76wNbY6YRmBFLyHCrOJ8q4=;
        b=YjKlelkIqXmGGcHhbEaiwMSUEYpr0F4PmqYmy7ePjg0F8nS2ZwkZ/0zDDBXzvTz8Lk
         JIWqMoSy4RA4H0hNjxFH/P66tsxKER0mTdakxV4tdG+7XokLb9GernXFjGyxy2P11HPU
         aVRjiEA3WOwioomcdvTKTmGhA+/fryXStr/bDa47GFismejUdnn77RNp2IGYeUrU6c9D
         EahQ0mSV9f9wHkmW5wL6DiXd1Q+2ckVwZ1IR+11HMkxlvhp/0pXyoeRKlmNnVlrUDeuN
         IZOe99FtPeB69h7oi+Q7WSOM61Yqm2lt1m9IJPLQOdm01P7lQDXzNkj6zPXcllIqdcxW
         Gadg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Bkc+KKqS;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=trIbwh1Zw8sTGxwsD4Lca76wNbY6YRmBFLyHCrOJ8q4=;
        b=sQOiv4iusJ2xjk5cMZdxczezeH4/T+oSF+FMsiFCUNoiu7U+A4HHuzvHscvAhy/39+
         eXuAnPIHh5zuVUOW08+Ybx1U1hu2EVOD4H+0cVqEc7t5mAN1oAQUWVJCjzgh+9xeifrK
         kp+a+i4kxTQcaC7c7ygMVwI/YazngfWxyhNY2pdF9kHDgJ/7umWzTd9ZyeOl9zTC1gX/
         zXA7wTUy05NGHJXCMNaQbJeQFGmyAyzR0gVQwjLtklmhYUr/HSR5mBrb/iyO9yNF58iH
         JvsAeHRFSxVL9kpCBR9QISWI1uQLlZovmPSCsTQaua+YpRCUawdsVgv33xgSJzKG535A
         ELgg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=trIbwh1Zw8sTGxwsD4Lca76wNbY6YRmBFLyHCrOJ8q4=;
        b=En3vPa7URhodD55OQRVORBjbEnEKU8Yf7mGqJ0DjuWU1CCPoYnV2A2Mcdp6+CPLwvR
         AwErmGJ7cfpZSsWp6Tq/t4G8ZXSC+C5kJjJO72VJQPsbcSJlLfycmOmVEPMzRQ0quAI0
         SEeU47YVlZ4t7KfKC0jroUBlEJWovM8IOb6Le8agbsBNDwJphP2Pihx4X7DsHk9MGWRP
         usfdqRFN7wnNfiXb/i1/boSGN2guKh70v7SqmXsBpmslaXCbiL2opLaI7JlVSNmzxMkT
         yxYJK9NDO3YoC9BXup0UzWHDjp1NSixmJm91iawTfa7YWbYmcYkoilhtNT5nRxk7jUIt
         Nceg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=trIbwh1Zw8sTGxwsD4Lca76wNbY6YRmBFLyHCrOJ8q4=;
        b=x6e5fTzMkK5hxMc2+p4zaPWlRzuZxq87qOXyBGsGTMn5YvB2g/DnLYSfn4+VxinzIt
         ZBBH52BAsE4vvhosBt8Aye0B+9nBt8jSvQJvWNgvRqKdo/gOtXLihuINdRM8HiB0Ql1+
         q9tgZe34oZA1mMBSVrEiM8HInwh5PRNm5DKil6vwU9Zzj6H6LwS1YZ+TXGhMGtSDFrSb
         vCbGzUndrpSpczL8EXATPlqnAgmHq7zp+PpzpvuEmsCnEb385ETo9uyqt6Y8jGJ60LaN
         L6tEV7YtrzeCV/lqDohBwj26rRUSnUrJzzjZJCHHFtraaSvT3Fzo7EQl/C8wT+JUqQtw
         /2Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Jyop4kd0VNTEoGwA4QSmU9eE0Bx3uMcxw3JHo5SJ2jSESFgwU
	YOXKRjJo9Bx3vE9d9CON3aE=
X-Google-Smtp-Source: AMsMyM4b76GRyeW031BPT5zxAbOM5cEieToIohpDM8jhRVhiXzx6bSeTL/MzFnEdITixA4n005Sbcw==
X-Received: by 2002:a5d:424a:0:b0:23a:4ac:397e with SMTP id s10-20020a5d424a000000b0023a04ac397emr17951662wrr.716.1667937310686;
        Tue, 08 Nov 2022 11:55:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6014:b0:3cf:9be3:73dd with SMTP id
 az20-20020a05600c601400b003cf9be373ddls5856572wmb.3.-pod-canary-gmail; Tue,
 08 Nov 2022 11:55:09 -0800 (PST)
X-Received: by 2002:a05:600c:19d2:b0:3cf:adec:1d20 with SMTP id u18-20020a05600c19d200b003cfadec1d20mr7547732wmq.87.1667937309348;
        Tue, 08 Nov 2022 11:55:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667937309; cv=none;
        d=google.com; s=arc-20160816;
        b=dJkq8XfMyPtNQzBnhzl9ENgBkwmezuiDTWrfjkJL0ZfEoh4RTUtzPbT9fMH5kHj/BQ
         umHeAxUTrPKosxD3xzwJnLGKPfNLHESb6IH7anWd6lsuEktNpxmDc9Vz4yVzmtOcgwgJ
         VRfLjkh8v6+gxsOfrp0ct5o+GrezznGdbA5lsXlv7+63R4MI2H7acTwj+LSxBhwzwI+m
         ZikL27/pBMdlVYsH6O+oxN3BsEVHoEHqz7eCToK7h9h9Phm1vbsqdqq64AglIRwi0p9o
         QmupAUzfjoXttP7RXtulHDnWvcKwhQ+xCDPd5pAhwSRcKct7TyORUagtxUzS/LNEirzi
         958w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=sX3Ra3mwa6x/tHIBVR3+s7O4i1MGo+YxctILWccf32I=;
        b=qhaffZblKJqC/XSWYEVXFpQQJvBoE4k/wphT5+lxY3AlWUmcfNQ5uQrkNH+nVlYsNc
         qGPQQxqFCqoN4GE+QKfAz+Ls6lKUFK52FBA1CDvEH+ipabenK67EjB/JQs4ott1QGKwM
         OVQSHEgh/z0hDYDwhB7tJKLkAcmaIUKosPEQL4+6A0qxnv8cVCPU9E6VCBjhsgdzgmOo
         OfAR4jY4RCvcUp2YcAEy2e7Xk1ISZaI/qZ3NwJjHjRf/5M3WH/PzLPA8t4YTUC/nGP06
         FijHbHWC6R+mZl3BSxDCWJwbbxM2KWKvSnVWX7FpgIZauHqnZ/DSXchwdP2ahucs1rPc
         JpwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Bkc+KKqS;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003cf1536d24dsi391113wmk.0.2022.11.08.11.55.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 11:55:09 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id b9so22698274ljr.5
        for <kasan-dev@googlegroups.com>; Tue, 08 Nov 2022 11:55:09 -0800 (PST)
X-Received: by 2002:a2e:b88a:0:b0:277:7364:cbcf with SMTP id r10-20020a2eb88a000000b002777364cbcfmr12306536ljp.50.1667937308549;
        Tue, 08 Nov 2022 11:55:08 -0800 (PST)
Received: from [192.168.31.203] ([5.19.98.133])
        by smtp.gmail.com with ESMTPSA id x23-20020ac24897000000b0048aee825e2esm1902708lfc.282.2022.11.08.11.55.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 11:55:08 -0800 (PST)
Message-ID: <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
Date: Tue, 8 Nov 2022 22:55:08 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH 3/3] x86/kasan: Populate shadow for shared chunk of the
 CPU entry area
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, "H. Peter Anvin"
 <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221104183247.834988-1-seanjc@google.com>
 <20221104183247.834988-4-seanjc@google.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221104183247.834988-4-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Bkc+KKqS;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 11/4/22 21:32, Sean Christopherson wrote:
> Popuplate the shadow for the shared portion of the CPU entry area, i.e.
> the read-only IDT mapping, during KASAN initialization.  A recent change
> modified KASAN to map the per-CPU areas on-demand, but forgot to keep a
> shadow for the common area that is shared amongst all CPUs.
> 
> Map the common area in KASAN init instead of letting idt_map_in_cea() do
> the dirty work so that it Just Works in the unlikely event more shared
> data is shoved into the CPU entry area.
> 
> The bug manifests as a not-present #PF when software attempts to lookup
> an IDT entry, e.g. when KVM is handling IRQs on Intel CPUs (KVM performs
> direct CALL to the IRQ handler to avoid the overhead of INTn):
> 
>  BUG: unable to handle page fault for address: fffffbc0000001d8
>  #PF: supervisor read access in kernel mode
>  #PF: error_code(0x0000) - not-present page
>  PGD 16c03a067 P4D 16c03a067 PUD 0
>  Oops: 0000 [#1] PREEMPT SMP KASAN
>  CPU: 5 PID: 901 Comm: repro Tainted: G        W          6.1.0-rc3+ #410
>  Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
>  RIP: 0010:kasan_check_range+0xdf/0x190
>   vmx_handle_exit_irqoff+0x152/0x290 [kvm_intel]
>   vcpu_run+0x1d89/0x2bd0 [kvm]
>   kvm_arch_vcpu_ioctl_run+0x3ce/0xa70 [kvm]
>   kvm_vcpu_ioctl+0x349/0x900 [kvm]
>   __x64_sys_ioctl+0xb8/0xf0
>   do_syscall_64+0x2b/0x50
>   entry_SYSCALL_64_after_hwframe+0x46/0xb0
> 
> Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
> Reported-by: syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Signed-off-by: Sean Christopherson <seanjc@google.com>
> ---
>  arch/x86/mm/kasan_init_64.c | 12 +++++++++++-
>  1 file changed, 11 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index afc5e129ca7b..0302491d799d 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -341,7 +341,7 @@ void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
>  
>  void __init kasan_init(void)
>  {
> -	unsigned long shadow_cea_begin, shadow_cea_end;
> +	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
>  	int i;
>  
>  	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
> @@ -384,6 +384,7 @@ void __init kasan_init(void)
>  	}
>  
>  	shadow_cea_begin = kasan_mem_to_shadow_align_down(CPU_ENTRY_AREA_BASE);
> +	shadow_cea_per_cpu_begin = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_PER_CPU);
>  	shadow_cea_end = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_BASE +
>  						      CPU_ENTRY_AREA_MAP_SIZE);
>  
> @@ -409,6 +410,15 @@ void __init kasan_init(void)
>  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
>  		(void *)shadow_cea_begin);
>  
> +	/*
> +	 * Populate the shadow for the shared portion of the CPU entry area.
> +	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
> +	 * area is randomly placed somewhere in the 512GiB range and mapping
> +	 * the entire 512GiB range is prohibitively expensive.
> +	 */
> +	kasan_populate_shadow(shadow_cea_begin,
> +			      shadow_cea_per_cpu_begin, 0);
> +

I think we can extend the kasan_populate_early_shadow() call above up to
shadow_cea_per_cpu_begin point, instead of this.
populate_early_shadow() maps single RO zeroed page. No one should write to the shadow for IDT.
KASAN only needs writable shadow for linear mapping/stacks/vmalloc/global variables.

>  	kasan_populate_early_shadow((void *)shadow_cea_end,
>  			kasan_mem_to_shadow((void *)__START_KERNEL_map));
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/06debc96-ea5d-df61-3d2e-0d1d723e55b7%40gmail.com.
