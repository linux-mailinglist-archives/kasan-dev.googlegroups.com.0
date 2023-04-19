Return-Path: <kasan-dev+bncBC2NLZHUVQHRB2FO7WQQMGQETJCIZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EB4D6E7159
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 04:52:25 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-760ebd1bc25sf190251339f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 19:52:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681872744; cv=pass;
        d=google.com; s=arc-20160816;
        b=DYciLIG2dASmE/zdOqEvxOwlUEhMrEqgAdzJQSTspMC7UmvWtfGMGL5c8AzIOKy564
         TpYzwLT28QYkxMcrLgB0TW8atOfBvI0SWFxG6nDtVXWeQfjGxn6GoRDvM24utV6MM1kr
         Mh9iKEJXv2dVjiatr8cK9v5PWH7aQLpJjBaOVVwqY3l3n3XruYYRU1OCLIHzPwCjRF2h
         3rkLl0PV8vdN5k2TUDMrirR1T8vwh1RnLnqliy9po+cLfq1OupW1D9SSXCrYVeRKZa2z
         5TlohH780q7jPEJqMDVEXpfL5ZAt4sdjOcsr/uDaq73hOXvehlrQbSWwvHgnJ9/AP4dv
         w2sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=VLtQiX28PCg1S5+GY0OIUCaoXHQH5OBrMVk/8IZbNqY=;
        b=hn+VXGBbznpETplbdX2IQinOtmm+4gry+JwJJspAB7B/GNtIr+uh0g9vivyFBfPJXM
         PXg4N54gnqhrTQvM1UNGLHsD5YEoSW+zGjz7y5glaRaXw9Vrk2l6X5Bdj3VPFXL73Eyb
         aO8Ys86KU1aOHzq21NcBmVs9P4lks375RxoIGvC6s6J+BgNa6FvlMes0E1dYpV5L5T2g
         jRJlWo9ZXq6l9iKzp1S8/Fh2OEOEZlSl9fwy77g5m7ysoBi7pL4G4xUHaU29/XLVDxME
         sRI/ijx4/MHFNP9zuc3za5gLdE5dHX9/KIss9yBoQ1boTNR3A4Qw9S8BTev9PrwTtDpP
         w0gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=UBXsagd+;
       spf=pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681872744; x=1684464744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VLtQiX28PCg1S5+GY0OIUCaoXHQH5OBrMVk/8IZbNqY=;
        b=nmmNXc+vbYmS+No7LSWodXl7CWbTP4NLOxaBCT1+6dl5Z0bkgYboXRkMtLycFp9YtS
         WbKF9ADe/qkQRnYhPDACLHOeFO+g4Fsi5ktu3K+cx9ed/HH3UpqirXGitPm+FF1Patyc
         o/mCm5CR7Ns9dEpgMV8JEbR0xDuINlAxaxz6NUgJTjXbU78IHJFyiYYJIof41mmZF96n
         f8uZPWeqK78+MouZBozXq1BrZmF2qP2sl+fHqejjbIE3Qc/7bz6iU2VT0zQP0gpeujyt
         N3BnnP2kF4PNaVGLDGVLVwrJrnuIrw6OSjDB1Dx4LZLnAa5bIXo/136pzPc5TVzKbquk
         JDGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681872744; x=1684464744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VLtQiX28PCg1S5+GY0OIUCaoXHQH5OBrMVk/8IZbNqY=;
        b=GOEZvCSu4TgILGfl/i9XcQcM4zx8/UgNyhSftCX4t8s98lKrVfqUXaFiHR0ye6sMws
         iTvtipVSwOEwiacm7irsaYoSVu3cyWxOmRzHTf1aWer6CBiDC8s/NNrei+/WplsuXQgn
         cMH0kGlI2veflPj/2JDarOmV3T72EALf/bv1JPwikKUq1YyWmS0l3SCafc0Wqtb68Pmo
         sTb3sExeVvLTyz4fHJD3H29rvUWJbE1CZDCL1rCD712TSLb+cswqh9Pyk3J9BN81Tbvp
         hPg+lA4Yac6/epWMp0gXVJSz6KpI1lFD2Ps9yl7sORah9SjyUJ9YLc3SmwOjb3Czt1ev
         VTQA==
X-Gm-Message-State: AAQBX9e9n9FkWD3ovAzzPW6pHiBE23K06XdCkObxEpju2V4QyuiweR4q
	71AxZa4mKSlMmNQKVts6YuE=
X-Google-Smtp-Source: AKy350ZPQF8W2GaG2DE7zenCZNiogobzqVTeFC9S1yzwzsQtmTqTp72DW8KnE2YCXQY1LHedKFHrHw==
X-Received: by 2002:a05:6602:3146:b0:760:e9b6:e6de with SMTP id m6-20020a056602314600b00760e9b6e6demr2998260ioy.0.1681872744123;
        Tue, 18 Apr 2023 19:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1aaa:b0:325:cefc:db5b with SMTP id
 l10-20020a056e021aaa00b00325cefcdb5bls4164125ilv.7.-pod-prod-gmail; Tue, 18
 Apr 2023 19:52:23 -0700 (PDT)
X-Received: by 2002:a92:da4f:0:b0:32a:314:a68c with SMTP id p15-20020a92da4f000000b0032a0314a68cmr17561178ilq.16.1681872743469;
        Tue, 18 Apr 2023 19:52:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681872743; cv=none;
        d=google.com; s=arc-20160816;
        b=YGzzV5yRzlBYzusDCRbiDPez5nxQItCrt0D8kV1io8QihfQJ368j+RBY6RFc0KZKhd
         NjIHrFzVLAt3XuOARHUvtsjG6Hek/CoK2I1vbJCvTu1u1t9Rh4lN0JjSUEniw15Akeds
         O1NBa+LcKBmxh+dNUN+nvUn9JFuNMJlxXZM8Aqk89EqMdla5knBU75YVsDYnt2qOEHPS
         Eex9kT8ArTgnVyvDfmKSWj3aOjfPrplCHtaWSRAdFKo3sPkZF8nou6byUSei6PAITZ01
         H2pmV91aFLT00OFQm4UZs3oNBb/DeUxVyflLPIopQ/jjhHuiGVGK9xTbNhv98kOoY+iZ
         p5wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9zzMcMOPEpfr5THwWMh35gYibbv6uY1wVkSMdB4TPrg=;
        b=r3eb8//I/Kg5FuksbQcjcYr2V9fmhFE8m1e+xhLEU23EfKM4YsPt6TbPM2M28B96og
         slf9TPP3vmTpvXwyJkhuLq+j1KmkVil6oZIk8r0ac/FbxC/g8Hni5lAUg622jye/HLUS
         agW8BHRVuLmNhoN8UUtzWULsAeHaujI1O4xvCSjehmaeILTShKdgvyY2h8EanI8qVzdl
         DEfBAwHgZ/3j/red+KJnDO/zkcc+3Iy2k35LecxwmdsJfi3dpdWFBb86jFulyEbMIbqb
         C14RcSIgqX/4PO64qe3dfGUKRNrKpT4vj+mBnpIKx9H5tHb3PpcLX7z9bx10wIpalzK5
         m8Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=UBXsagd+;
       spf=pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id cs9-20020a056638470900b0040f8a20c639si796238jab.5.2023.04.18.19.52.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 19:52:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-63b7b18a336so839289b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 19:52:23 -0700 (PDT)
X-Received: by 2002:a17:903:11c9:b0:1a6:6bdb:b548 with SMTP id q9-20020a17090311c900b001a66bdbb548mr19768853plh.1.1681872742749;
        Tue, 18 Apr 2023 19:52:22 -0700 (PDT)
Received: from [10.70.252.135] ([139.177.225.245])
        by smtp.gmail.com with ESMTPSA id jf1-20020a170903268100b001a245b49731sm10255632plb.128.2023.04.18.19.52.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 19:52:22 -0700 (PDT)
Message-ID: <f16db6f6-2699-bb8f-d34c-2ce3d37a6498@bytedance.com>
Date: Wed, 19 Apr 2023 10:52:15 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.10.0
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
To: Zqiang <qiang1.zhang@intel.com>, elver@google.com,
 ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, akpm@linux-foundation.org,
 Vlastimil Babka <vbabka@suse.cz>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
Content-Language: en-US
From: "'Qi Zheng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230327120019.1027640-1-qiang1.zhang@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: zhengqi.arch@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=UBXsagd+;       spf=pass
 (google.com: domain of zhengqi.arch@bytedance.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Qi Zheng <zhengqi.arch@bytedance.com>
Reply-To: Qi Zheng <zhengqi.arch@bytedance.com>
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



On 2023/3/27 20:00, Zqiang wrote:
> For kernels built with the following options and booting
> 
> CONFIG_SLUB=y
> CONFIG_DEBUG_LOCKDEP=y
> CONFIG_PROVE_LOCKING=y
> CONFIG_PROVE_RAW_LOCK_NESTING=y
> 
> [    0.523115] [ BUG: Invalid wait context ]
> [    0.523315] 6.3.0-rc1-yocto-standard+ #739 Not tainted
> [    0.523649] -----------------------------
> [    0.523663] swapper/0/0 is trying to lock:
> [    0.523663] ffff888035611360 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x2e/0x1e0
> [    0.523663] other info that might help us debug this:
> [    0.523663] context-{2:2}
> [    0.523663] no locks held by swapper/0/0.
> [    0.523663] stack backtrace:
> [    0.523663] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc1-yocto-standard+ #739
> [    0.523663] Call Trace:
> [    0.523663]  <IRQ>
> [    0.523663]  dump_stack_lvl+0x64/0xb0
> [    0.523663]  dump_stack+0x10/0x20
> [    0.523663]  __lock_acquire+0x6c4/0x3c10
> [    0.523663]  lock_acquire+0x188/0x460
> [    0.523663]  put_cpu_partial+0x5a/0x1e0
> [    0.523663]  __slab_free+0x39a/0x520
> [    0.523663]  ___cache_free+0xa9/0xc0
> [    0.523663]  qlist_free_all+0x7a/0x160
> [    0.523663]  per_cpu_remove_cache+0x5c/0x70
> [    0.523663]  __flush_smp_call_function_queue+0xfc/0x330
> [    0.523663]  generic_smp_call_function_single_interrupt+0x13/0x20
> [    0.523663]  __sysvec_call_function+0x86/0x2e0
> [    0.523663]  sysvec_call_function+0x73/0x90
> [    0.523663]  </IRQ>
> [    0.523663]  <TASK>
> [    0.523663]  asm_sysvec_call_function+0x1b/0x20
> [    0.523663] RIP: 0010:default_idle+0x13/0x20
> [    0.523663] RSP: 0000:ffffffff83e07dc0 EFLAGS: 00000246
> [    0.523663] RAX: 0000000000000000 RBX: ffffffff83e1e200 RCX: ffffffff82a83293
> [    0.523663] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8119a6b1
> [    0.523663] RBP: ffffffff83e07dc8 R08: 0000000000000001 R09: ffffed1006ac0d66
> [    0.523663] R10: ffff888035606b2b R11: ffffed1006ac0d65 R12: 0000000000000000
> [    0.523663] R13: ffffffff83e1e200 R14: ffffffff84a7d980 R15: 0000000000000000
> [    0.523663]  default_idle_call+0x6c/0xa0
> [    0.523663]  do_idle+0x2e1/0x330
> [    0.523663]  cpu_startup_entry+0x20/0x30
> [    0.523663]  rest_init+0x152/0x240
> [    0.523663]  arch_call_rest_init+0x13/0x40
> [    0.523663]  start_kernel+0x331/0x470
> [    0.523663]  x86_64_start_reservations+0x18/0x40
> [    0.523663]  x86_64_start_kernel+0xbb/0x120
> [    0.523663]  secondary_startup_64_no_verify+0xe0/0xeb
> [    0.523663]  </TASK>
> 
> The local_lock_irqsave() is invoked in put_cpu_partial() and happens
> in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y (the
> LD_WAIT_CONFIG not equal to LD_WAIT_SPIN), so acquire local_lock in
> IPI context will trigger above calltrace.

Just to add another similar case:

Call Trace:
  <IRQ>
  dump_stack_lvl+0x69/0x97
  __lock_acquire+0x4a0/0x1b50
  lock_acquire+0x261/0x2c0
  ? restore_bytes+0x40/0x40
  local_lock_acquire+0x21/0x70
  ? restore_bytes+0x40/0x40
  put_cpu_partial+0x41/0x130
  ? flush_smp_call_function_queue+0x125/0x4d0
  kfree+0x250/0x2c0
  flush_smp_call_function_queue+0x125/0x4d0
  __sysvec_call_function_single+0x3a/0x100
  sysvec_call_function_single+0x4b/0x90
  </IRQ>
  <TASK>
  asm_sysvec_call_function_single+0x16/0x20

So we can't call kfree() and its friends in interrupt context?

Also +Vlastimil Babka.

Thanks,
Qi

> 
> This commit therefore move qlist_free_all() from hard-irq context to
> task context.
> 
> Signed-off-by: Zqiang <qiang1.zhang@intel.com>
> ---
>   v1->v2:
>   Modify the commit information and add Cc.
> 
>   mm/kasan/quarantine.c | 34 ++++++++--------------------------
>   1 file changed, 8 insertions(+), 26 deletions(-)
> 
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 75585077eb6d..152dca73f398 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -99,7 +99,6 @@ static unsigned long quarantine_size;
>   static DEFINE_RAW_SPINLOCK(quarantine_lock);
>   DEFINE_STATIC_SRCU(remove_cache_srcu);
>   
> -#ifdef CONFIG_PREEMPT_RT
>   struct cpu_shrink_qlist {
>   	raw_spinlock_t lock;
>   	struct qlist_head qlist;
> @@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
>   static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
>   	.lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
>   };
> -#endif
>   
>   /* Maximum size of the global queue. */
>   static unsigned long quarantine_max_size;
> @@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
>   	}
>   }
>   
> -#ifndef CONFIG_PREEMPT_RT
> -static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
> -{
> -	struct kmem_cache *cache = arg;
> -	struct qlist_head to_free = QLIST_INIT;
> -
> -	qlist_move_cache(q, &to_free, cache);
> -	qlist_free_all(&to_free, cache);
> -}
> -#else
>   static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>   {
>   	struct kmem_cache *cache = arg;
> @@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>   	qlist_move_cache(q, &sq->qlist, cache);
>   	raw_spin_unlock_irqrestore(&sq->lock, flags);
>   }
> -#endif
>   
>   static void per_cpu_remove_cache(void *arg)
>   {
> @@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>   {
>   	unsigned long flags, i;
>   	struct qlist_head to_free = QLIST_INIT;
> +	int cpu;
> +	struct cpu_shrink_qlist *sq;
>   
>   	/*
>   	 * Must be careful to not miss any objects that are being moved from
> @@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>   	 */
>   	on_each_cpu(per_cpu_remove_cache, cache, 1);
>   
> -#ifdef CONFIG_PREEMPT_RT
> -	{
> -		int cpu;
> -		struct cpu_shrink_qlist *sq;
> -
> -		for_each_online_cpu(cpu) {
> -			sq = per_cpu_ptr(&shrink_qlist, cpu);
> -			raw_spin_lock_irqsave(&sq->lock, flags);
> -			qlist_move_cache(&sq->qlist, &to_free, cache);
> -			raw_spin_unlock_irqrestore(&sq->lock, flags);
> -		}
> -		qlist_free_all(&to_free, cache);
> +	for_each_online_cpu(cpu) {
> +		sq = per_cpu_ptr(&shrink_qlist, cpu);
> +		raw_spin_lock_irqsave(&sq->lock, flags);
> +		qlist_move_cache(&sq->qlist, &to_free, cache);
> +		raw_spin_unlock_irqrestore(&sq->lock, flags);
>   	}
> -#endif
> +	qlist_free_all(&to_free, cache);
>   
>   	raw_spin_lock_irqsave(&quarantine_lock, flags);
>   	for (i = 0; i < QUARANTINE_BATCHES; i++) {

-- 
Thanks,
Qi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f16db6f6-2699-bb8f-d34c-2ce3d37a6498%40bytedance.com.
