Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBSOA72QQMGQEMT44CLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EF18B6E7494
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 10:03:22 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id q11-20020a19f20b000000b004ec86f8b0b0sf8685072lfh.23
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 01:03:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681891402; cv=pass;
        d=google.com; s=arc-20160816;
        b=CmXX83yjzTqLUnATYfY9X40UBzIv6EoN6rZTKNnTt1LETOL398mmH1+9ikpjG0JRXI
         LACBpQpju43b6G9a4+MOzh27ILyu0zy48t2323/L25sSyha4P7XLHWhfp63V4xFkClcP
         18BzhyBaD9dYhWG9RY4cIVU1C+WYaxmWRlQTWFDl5uefQ1+3mz2ETptFms1qWba5qeRw
         TfsvoeWO34zGmiijqcpQjcQLtycGHuN9F+Hbq9E+lxezND9agZIWS7C8Z37+rAQ51cTT
         8iIa/IoRzN4xm1FtzQB+tpfUa2dCUj0bhaOOkL3NJoDwol6XUmfOk5N4e4p1K6t9ydMG
         Z40g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=syer9t3SbMf6vK+zSa4R5+nBoaSMXxHP9IE9hzzmL3o=;
        b=pBvpm9QwA0N3hAyg4i/TQZtyn4w1kipRL86YmVy02O+y7Q0jgLHA8kYk7ZkOdNk6Z1
         Mo1+Uz3vJa0r31cWA/iRaa1C2Gz6ruRQ689ZSp2rj7bdsy3+cBJtBpIat+sa+VpUZZSR
         20mRsc9FdTvg7gmuSIbX3+iUODwNbsp87hkqIluBfa2z6F6GYN2TlCwGEAPodbUXgUOK
         qasH5DSDFtE6/hPJ9uICu88r1BP1JGkLPovSISTWRxhIqp7l+tVbjPBG/DiHyOqoCKzL
         zNecRmsjNTt1Bc5O8LZGiqcMUxhHN5GoSII1h8hk0oKjXnfKZ3egnMNjL8h/2RXJbRge
         YIiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hf2iFPF5;
       dkim=neutral (no key) header.i=@suse.cz header.b=9bZuRAex;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681891402; x=1684483402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=syer9t3SbMf6vK+zSa4R5+nBoaSMXxHP9IE9hzzmL3o=;
        b=Vm30YHIzlhEqobBclF6Qm86P4GxZlqeO8t4ZjxgaGPQHvO4AP3fPB8qe8X82NSpgpE
         9OqwIrJ49Bpo74m4UTJPry6LGeoBayUcJW/6J/5iIbpSQyce+9lYpGxqbbT/TcdzjXRf
         DdzOPH41zlcY3USDKqaaAsfClN3MSEnHxywhkxsVkJ92lDjwVjJdFsNKEwZZZhn61SMs
         oBPWyZdR62vJkgglQlL+aYsp4KsduwdY0h8EMkK1VVO5wAfHSB9cqS9E5c7MomEtgqcS
         Jacw5RFtD3qf4Obo6PW75yzmN6/l4+jISoM1Tiun2ceX0FVisvqJ4hL2g/E+kCqDO29M
         E/1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681891402; x=1684483402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=syer9t3SbMf6vK+zSa4R5+nBoaSMXxHP9IE9hzzmL3o=;
        b=T/Olo5DXxVMzs45q3NCLEfvYbe72/VviV4+T4z+zA3jNyAeipAY8Q6fm+39Sm+YtK9
         6J++w93/n6cT3Z3y7w8gIbmDr62fXmp0I7SkQxH3tZxzs6L2zwdmqrEGgLjc+Fv8psoi
         ovalEyxC0ymYH4jwgzNXNUnHTK95KQPcgQY4GTC6KCf/7VleG76Uk74/+27px/LMbDv0
         jirS1mAC5M3Nn4OPCso+rptzTDWIoEG0LI4vZo4KxpwneZ80IPD48/wCTQMQZJRbkewX
         m2IzMQ6W4uBTNxkhWX1BaEXAzrRZEbM74wf5IBZI9fLHfFZMA8/7sbwqJWIrF45Ma8AD
         SHUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dtKccGrLQS/+CxciMe2fj84K9UF8f8KtAQ0vfTg09Jxz9FQQ59
	EYxNMNjwhRJZJ2H6f76ezzg=
X-Google-Smtp-Source: AKy350ZaqQDZEBvJwLqsu9ShvTA/KMiQdMMlv7TxoaHOCtZChHWUjcAHJ/knNFmr8ynf7glUDaLtCw==
X-Received: by 2002:a2e:800c:0:b0:2a7:6bb4:a701 with SMTP id j12-20020a2e800c000000b002a76bb4a701mr1687984ljg.5.1681891402135;
        Wed, 19 Apr 2023 01:03:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea9:b0:4e8:c8b4:347a with SMTP id
 bi41-20020a0565120ea900b004e8c8b4347als3780332lfb.1.-pod-prod-gmail; Wed, 19
 Apr 2023 01:03:18 -0700 (PDT)
X-Received: by 2002:a05:6512:376d:b0:4db:4fe8:fd0f with SMTP id z13-20020a056512376d00b004db4fe8fd0fmr3681672lft.25.1681891398623;
        Wed, 19 Apr 2023 01:03:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681891398; cv=none;
        d=google.com; s=arc-20160816;
        b=yuHWKg9IZpwN0MwJMQVMxxXdev7fle6rqwfc9ThxsfYNsrJILlo96xMVrXHZPeQD6I
         m5G/lEOLzzGuU9k/rlywmRgkfr+Nl+vC41TJEzA6p/c+a3hfPCtkKyeEhOj3AYS4T46z
         wFkNWZJL7MqZRFLIaXnqhGi9rTaUhaF4GtASxCMrdaQ0X7CB+zL9NQ2JwyCtOD2EwDRp
         RJ539APsM/RDEXsOAoeafi9Mr0wtBe5KTOSyjqdlxPM9QcPjXWRbrnLp8FCPYE/HDoS/
         sXyty7bUCto6ffxo0FA6F6g+8lHLkAl3Jw2BapXy0BnqmdlKYwmB7SzSPBBMi/DzTVBC
         faog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=JlSYbYryU4jjk+BGdngS93om7BXz5+VfainCEWdrZZY=;
        b=MEUmgfoELtjc0dq04+iDGbmkfvr8G7ckT6Ep7M4SSrnXB53oQONHt0kKE2kmBxpMoq
         z/QIjCN1xT62gyBUH3fwZHngV7xJJAxrcG/iEj2nzkxs5KsSvhzU/AKFt6sQ1voXd4J8
         DV6VE7fQARJz/RYRMa9T2TfqLoTCJ/dH9GsS7Rmgo5JzGPqBv4d8yH0CjADNfMfs4XU0
         JX3FErUHZJqOQuGdSPIGL+Pfqut7iRzxUh6VY2l8FnASeGGW+cplcQkTdKExCv9/uSbv
         sZIhCKnbyr4M7b/WHp1zUPevfcZM53Cy8vzElnnb3fDfv51a3mfJtbgyHjiPd6bRJdXZ
         6/Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=hf2iFPF5;
       dkim=neutral (no key) header.i=@suse.cz header.b=9bZuRAex;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bp25-20020a056512159900b004dc4c1e0df8si895288lfb.11.2023.04.19.01.03.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Apr 2023 01:03:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C9E8D1FD87;
	Wed, 19 Apr 2023 08:03:17 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 97D7B1390E;
	Wed, 19 Apr 2023 08:03:17 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id PWcDJEWgP2SEVwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 19 Apr 2023 08:03:17 +0000
Message-ID: <6f183ff4-f23e-b82a-3524-2d1f5d833a2d@suse.cz>
Date: Wed, 19 Apr 2023 10:03:17 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
Content-Language: en-US
To: Qi Zheng <zhengqi.arch@bytedance.com>, Zqiang <qiang1.zhang@intel.com>,
 elver@google.com, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
 <f16db6f6-2699-bb8f-d34c-2ce3d37a6498@bytedance.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <f16db6f6-2699-bb8f-d34c-2ce3d37a6498@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=hf2iFPF5;       dkim=neutral
 (no key) header.i=@suse.cz header.b=9bZuRAex;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 4/19/23 04:52, Qi Zheng wrote:
> 
> 
> On 2023/3/27 20:00, Zqiang wrote:
>> For kernels built with the following options and booting
>> 
>> CONFIG_SLUB=y
>> CONFIG_DEBUG_LOCKDEP=y
>> CONFIG_PROVE_LOCKING=y
>> CONFIG_PROVE_RAW_LOCK_NESTING=y
>> 
>> [    0.523115] [ BUG: Invalid wait context ]
>> [    0.523315] 6.3.0-rc1-yocto-standard+ #739 Not tainted
>> [    0.523649] -----------------------------
>> [    0.523663] swapper/0/0 is trying to lock:
>> [    0.523663] ffff888035611360 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x2e/0x1e0
>> [    0.523663] other info that might help us debug this:
>> [    0.523663] context-{2:2}
>> [    0.523663] no locks held by swapper/0/0.
>> [    0.523663] stack backtrace:
>> [    0.523663] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc1-yocto-standard+ #739
>> [    0.523663] Call Trace:
>> [    0.523663]  <IRQ>
>> [    0.523663]  dump_stack_lvl+0x64/0xb0
>> [    0.523663]  dump_stack+0x10/0x20
>> [    0.523663]  __lock_acquire+0x6c4/0x3c10
>> [    0.523663]  lock_acquire+0x188/0x460
>> [    0.523663]  put_cpu_partial+0x5a/0x1e0
>> [    0.523663]  __slab_free+0x39a/0x520
>> [    0.523663]  ___cache_free+0xa9/0xc0
>> [    0.523663]  qlist_free_all+0x7a/0x160
>> [    0.523663]  per_cpu_remove_cache+0x5c/0x70
>> [    0.523663]  __flush_smp_call_function_queue+0xfc/0x330
>> [    0.523663]  generic_smp_call_function_single_interrupt+0x13/0x20
>> [    0.523663]  __sysvec_call_function+0x86/0x2e0
>> [    0.523663]  sysvec_call_function+0x73/0x90
>> [    0.523663]  </IRQ>
>> [    0.523663]  <TASK>
>> [    0.523663]  asm_sysvec_call_function+0x1b/0x20
>> [    0.523663] RIP: 0010:default_idle+0x13/0x20
>> [    0.523663] RSP: 0000:ffffffff83e07dc0 EFLAGS: 00000246
>> [    0.523663] RAX: 0000000000000000 RBX: ffffffff83e1e200 RCX: ffffffff82a83293
>> [    0.523663] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8119a6b1
>> [    0.523663] RBP: ffffffff83e07dc8 R08: 0000000000000001 R09: ffffed1006ac0d66
>> [    0.523663] R10: ffff888035606b2b R11: ffffed1006ac0d65 R12: 0000000000000000
>> [    0.523663] R13: ffffffff83e1e200 R14: ffffffff84a7d980 R15: 0000000000000000
>> [    0.523663]  default_idle_call+0x6c/0xa0
>> [    0.523663]  do_idle+0x2e1/0x330
>> [    0.523663]  cpu_startup_entry+0x20/0x30
>> [    0.523663]  rest_init+0x152/0x240
>> [    0.523663]  arch_call_rest_init+0x13/0x40
>> [    0.523663]  start_kernel+0x331/0x470
>> [    0.523663]  x86_64_start_reservations+0x18/0x40
>> [    0.523663]  x86_64_start_kernel+0xbb/0x120
>> [    0.523663]  secondary_startup_64_no_verify+0xe0/0xeb
>> [    0.523663]  </TASK>
>> 
>> The local_lock_irqsave() is invoked in put_cpu_partial() and happens
>> in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y (the
>> LD_WAIT_CONFIG not equal to LD_WAIT_SPIN), so acquire local_lock in
>> IPI context will trigger above calltrace.
> 
> Just to add another similar case:
> 
> Call Trace:
>   <IRQ>
>   dump_stack_lvl+0x69/0x97
>   __lock_acquire+0x4a0/0x1b50
>   lock_acquire+0x261/0x2c0
>   ? restore_bytes+0x40/0x40
>   local_lock_acquire+0x21/0x70
>   ? restore_bytes+0x40/0x40
>   put_cpu_partial+0x41/0x130
>   ? flush_smp_call_function_queue+0x125/0x4d0
>   kfree+0x250/0x2c0
>   flush_smp_call_function_queue+0x125/0x4d0
>   __sysvec_call_function_single+0x3a/0x100
>   sysvec_call_function_single+0x4b/0x90
>   </IRQ>
>   <TASK>
>   asm_sysvec_call_function_single+0x16/0x20
> 
> So we can't call kfree() and its friends in interrupt context?

We can (well not RT "hard IRQ" context AFAIK, but that shouldn't be the case
here), although I don't see from the part that you posted if it's again
CONFIG_PROVE_RAW_LOCK_NESTING clashing with something else (no KASAN in the
trace or I'm missing it?)

> Also +Vlastimil Babka.
> 
> Thanks,
> Qi
> 
>> 
>> This commit therefore move qlist_free_all() from hard-irq context to
>> task context.
>> 
>> Signed-off-by: Zqiang <qiang1.zhang@intel.com>
>> ---
>>   v1->v2:
>>   Modify the commit information and add Cc.
>> 
>>   mm/kasan/quarantine.c | 34 ++++++++--------------------------
>>   1 file changed, 8 insertions(+), 26 deletions(-)
>> 
>> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
>> index 75585077eb6d..152dca73f398 100644
>> --- a/mm/kasan/quarantine.c
>> +++ b/mm/kasan/quarantine.c
>> @@ -99,7 +99,6 @@ static unsigned long quarantine_size;
>>   static DEFINE_RAW_SPINLOCK(quarantine_lock);
>>   DEFINE_STATIC_SRCU(remove_cache_srcu);
>>   
>> -#ifdef CONFIG_PREEMPT_RT
>>   struct cpu_shrink_qlist {
>>   	raw_spinlock_t lock;
>>   	struct qlist_head qlist;
>> @@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
>>   static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
>>   	.lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
>>   };
>> -#endif
>>   
>>   /* Maximum size of the global queue. */
>>   static unsigned long quarantine_max_size;
>> @@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
>>   	}
>>   }
>>   
>> -#ifndef CONFIG_PREEMPT_RT
>> -static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>> -{
>> -	struct kmem_cache *cache = arg;
>> -	struct qlist_head to_free = QLIST_INIT;
>> -
>> -	qlist_move_cache(q, &to_free, cache);
>> -	qlist_free_all(&to_free, cache);
>> -}
>> -#else
>>   static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>   {
>>   	struct kmem_cache *cache = arg;
>> @@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>   	qlist_move_cache(q, &sq->qlist, cache);
>>   	raw_spin_unlock_irqrestore(&sq->lock, flags);
>>   }
>> -#endif
>>   
>>   static void per_cpu_remove_cache(void *arg)
>>   {
>> @@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>   {
>>   	unsigned long flags, i;
>>   	struct qlist_head to_free = QLIST_INIT;
>> +	int cpu;
>> +	struct cpu_shrink_qlist *sq;
>>   
>>   	/*
>>   	 * Must be careful to not miss any objects that are being moved from
>> @@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>   	 */
>>   	on_each_cpu(per_cpu_remove_cache, cache, 1);
>>   
>> -#ifdef CONFIG_PREEMPT_RT
>> -	{
>> -		int cpu;
>> -		struct cpu_shrink_qlist *sq;
>> -
>> -		for_each_online_cpu(cpu) {
>> -			sq = per_cpu_ptr(&shrink_qlist, cpu);
>> -			raw_spin_lock_irqsave(&sq->lock, flags);
>> -			qlist_move_cache(&sq->qlist, &to_free, cache);
>> -			raw_spin_unlock_irqrestore(&sq->lock, flags);
>> -		}
>> -		qlist_free_all(&to_free, cache);
>> +	for_each_online_cpu(cpu) {
>> +		sq = per_cpu_ptr(&shrink_qlist, cpu);
>> +		raw_spin_lock_irqsave(&sq->lock, flags);
>> +		qlist_move_cache(&sq->qlist, &to_free, cache);
>> +		raw_spin_unlock_irqrestore(&sq->lock, flags);
>>   	}
>> -#endif
>> +	qlist_free_all(&to_free, cache);
>>   
>>   	raw_spin_lock_irqsave(&quarantine_lock, flags);
>>   	for (i = 0; i < QUARANTINE_BATCHES; i++) {
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f183ff4-f23e-b82a-3524-2d1f5d833a2d%40suse.cz.
