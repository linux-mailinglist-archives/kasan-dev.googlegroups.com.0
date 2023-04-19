Return-Path: <kasan-dev+bncBC2NLZHUVQHRB47E72QQMGQEYQVC2LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id B1A2D6E7621
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 11:20:52 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-552cb2211bdsf69140627b3.6
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 02:20:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681896051; cv=pass;
        d=google.com; s=arc-20160816;
        b=BAwa/kXlcXMnxQPl1INgCvUEQA8AKQZF/lwSsfSA7yu0J0G4Mr7SZITYadGQjidF4Z
         /s0/+yHegxdSHnbj5J72RRxPJ7OvPm7p8tUwyjP2k4WaM68J41JdJhD0I1d1aFJhXusG
         vLA74URZmtaYlk7Awsc0UOI3PBHcckNU36PtBGYmvyKpc7MfeCrlafWQb9s/9FLJBm5b
         0HN85L2ffCBg8BgWNFzHhJSTtqg9JR949qdDXUElPyjTX8CAcWOnOfp/6j42SY5CI21H
         xHlX+CMXKfV7drTNYZ7cJHseBSIIMNWbUPqC2Aumw5YO0DojB+dhjHJ2ap1j4Gu6Ydcr
         2k7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=UQ6VD6CGpwci2BW0iwQ2NQRIHXNTxoygMEGLUu8OJdI=;
        b=dpHPTLdAP8W7RXvAOTpgtAuNsfjSKpDO7sljE3AID4VINm+gZFzp0Gi38EFCnzLz35
         hS8OF0ojmEnjdmnIucskjmbJElkJ0OSyCgp0DWGdiD7dEcV/plVkxzTd+4SB4isiRh5H
         qU29sBSWSaPkDjl5ycuNeCbdMu/m1cp7y9xKozDiyG1JVJEh85y3NDTQhgp1WwiF8jLt
         Rpn8Ar7W50it9WNrAMAscnKp7XW7OAIrH6jt8MCZjgylaaUzwx4QoOfaJSBdYtMLqk20
         QQH/5YMeVSHgu0ZRunrjyG4KafmBb8JCDD9grvJbybw7D5XYz2pjd+Ghk2z++hTiQwX/
         capg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=W3ChJVWc;
       spf=pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681896051; x=1684488051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UQ6VD6CGpwci2BW0iwQ2NQRIHXNTxoygMEGLUu8OJdI=;
        b=nCPVIuktfL8hJFz3AZYgZwlJJGNnKqiEABRUW3goSU9RXlvQ34ALkwE4ZuXoX1Tn9l
         Al9x98+4L5W0OihDm8PePCI+uC3/dgprl/1uXpSW651d6mMBvr+zwVXMTC6zcYV/qqLx
         HaDuGYuWaVOqO/4Db3Is8NX7TBK3Oh9WBbm/RFAzpwFFGpaKjBqZuZ2mLQcijnD2FTRy
         rzDpcglu1M5EyFOZuMTZkHbnTP/TGkHv8LKrcRjJRut3BA1w5EHpo0o3mzDT9o+7XqAU
         DI61rW1znZ1Q7egXE/GRBmocsvHy5nH32sJHhXU0oJPcYahFnfILAyn/8/whCK5z9Uad
         dCAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681896051; x=1684488051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UQ6VD6CGpwci2BW0iwQ2NQRIHXNTxoygMEGLUu8OJdI=;
        b=a6dQrcY5+4e4nDmBv0jo8CD5AQXilxlYcuguxeHjfvg1pl3NelSbr4NxrBwQ/jtBgy
         Hs2/PwKzp9OIXZrOyO1b99+dDxzv/EKoQUYyx19QiPUvlHlxAMJP3XbDm07Nl5bW02iO
         l8cPjJU5qo8czNplrIj2pzcCiKYg6GFGaYd0zz8w8XbKQvuDA1uXTBVM5qHinNVpE5eV
         hFH8yA/3YUKf7wqJt1pkxXTYexsBPwh2UIKYWkkfVAytm9l/pb9ZB2hmg1OdInCiuwOj
         98sdAVwIq42xanM88iEKpHNLni6b6ybt5UM9wC8S3Q8W+uWUy0ZTg7rJFaUr0zVD3fY9
         0LqQ==
X-Gm-Message-State: AAQBX9coKdwi6xCu7om3foiT1ljCt/6FPLpNXJjz7SM0zkFX3jzsoAvW
	F7lq+vFbqytmet4XxGU0Pms=
X-Google-Smtp-Source: AKy350a/Tryls2e0sSw6p+Cb+ADS0mRgfAx4/5dhh+CR1qOS9SOYg/QgLPpktS1XHCoem1Th3Eq+nw==
X-Received: by 2002:a25:7385:0:b0:b92:3b14:b0f6 with SMTP id o127-20020a257385000000b00b923b14b0f6mr8440106ybc.7.1681896051387;
        Wed, 19 Apr 2023 02:20:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:188a:b0:b92:4a72:d990 with SMTP id
 cj10-20020a056902188a00b00b924a72d990ls5643308ybb.6.-pod-prod-gmail; Wed, 19
 Apr 2023 02:20:50 -0700 (PDT)
X-Received: by 2002:a25:1f84:0:b0:b77:678b:ca53 with SMTP id f126-20020a251f84000000b00b77678bca53mr17228641ybf.64.1681896050601;
        Wed, 19 Apr 2023 02:20:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681896050; cv=none;
        d=google.com; s=arc-20160816;
        b=0VEXJwAAYnwSR0LGRhhYyLa8i3B4OC2t81PgbQBJkY3m6ovEBH5im5XxWFFI7TQzNk
         XF7x8xXmVOR8641F30TmCTNO3sZGkOD91qkF4pEvSI6g9iDheYbGRwkHlVb2EoVozpUR
         Af6uZExLSDIxOCjXs+v3kr8IbYOjHDr8hIu9TPo4WqnyPCiNRiNaWKswg8iciU/jIkFW
         A9VWQMIDbTrZVR0TDqNVm6zNTQcGzy+aoiQtuXmXWwDb6AGOGudI+PZxin/KRw1262Nq
         uNVkkll59LbGAT25LqGLKsc6ClZMoRU+L+GhUCmKUHLTXL/IAktQCWhRhT0dlDrwdcxY
         YPMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=XTqHFht0rFwyDOCXCg3uc4JwZj9L0SsxUyVwxywupyM=;
        b=nQT9PO7H6brH631b1JPKLutV+nAK2e8WeTBNyDGvLY2zyl0+gvjEhCZcIz1R5PwKrd
         TvymIBUXJr3Bt/feSwUrDW7yDI25Dg/iTnX8dJ94+b3TwS/hdgOqwkUZHVyCPNAW8kHE
         SQB0vrcMAuc1RjZMbrSAW+ty+EzIM0J1JiwevfhCCCFPnTbKbRn/mZSMyri6zXPLHPrk
         b2PnAeAIv+U2B3hoeaMZCI5B/8kYRfmSLs9hjnNQyUeb/hK4laA6NVAhYU7vLIORiPxj
         Y/T3Cxl2buqHFbwlOuEcHyFQx/htAEAl/lvcttGZSbdRqfw1aNYL+WYzao0M7KKpEEqe
         NxlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=W3ChJVWc;
       spf=pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id c17-20020a5b0991000000b00b95bf79bf9dsi175250ybq.2.2023.04.19.02.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Apr 2023 02:20:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhengqi.arch@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-2465835cf6fso1001786a91.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Apr 2023 02:20:50 -0700 (PDT)
X-Received: by 2002:a17:90a:1d5:b0:246:fa2b:91be with SMTP id 21-20020a17090a01d500b00246fa2b91bemr15215000pjd.3.1681896049729;
        Wed, 19 Apr 2023 02:20:49 -0700 (PDT)
Received: from [10.70.252.135] ([139.177.225.245])
        by smtp.gmail.com with ESMTPSA id lx3-20020a17090b4b0300b00246cc751c6bsm964575pjb.46.2023.04.19.02.20.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Apr 2023 02:20:49 -0700 (PDT)
Message-ID: <a005e1ce-8c58-7d9a-0c55-09f3f5afc788@bytedance.com>
Date: Wed, 19 Apr 2023 17:20:38 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.10.0
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Zqiang <qiang1.zhang@intel.com>,
 elver@google.com, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
 <f16db6f6-2699-bb8f-d34c-2ce3d37a6498@bytedance.com>
 <6f183ff4-f23e-b82a-3524-2d1f5d833a2d@suse.cz>
From: "'Qi Zheng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <6f183ff4-f23e-b82a-3524-2d1f5d833a2d@suse.cz>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: zhengqi.arch@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=W3ChJVWc;       spf=pass
 (google.com: domain of zhengqi.arch@bytedance.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=zhengqi.arch@bytedance.com;
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



On 2023/4/19 16:03, Vlastimil Babka wrote:
> On 4/19/23 04:52, Qi Zheng wrote:
>>
>>
>> On 2023/3/27 20:00, Zqiang wrote:
>>> For kernels built with the following options and booting
>>>
>>> CONFIG_SLUB=y
>>> CONFIG_DEBUG_LOCKDEP=y
>>> CONFIG_PROVE_LOCKING=y
>>> CONFIG_PROVE_RAW_LOCK_NESTING=y
>>>
>>> [    0.523115] [ BUG: Invalid wait context ]
>>> [    0.523315] 6.3.0-rc1-yocto-standard+ #739 Not tainted
>>> [    0.523649] -----------------------------
>>> [    0.523663] swapper/0/0 is trying to lock:
>>> [    0.523663] ffff888035611360 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x2e/0x1e0
>>> [    0.523663] other info that might help us debug this:
>>> [    0.523663] context-{2:2}
>>> [    0.523663] no locks held by swapper/0/0.
>>> [    0.523663] stack backtrace:
>>> [    0.523663] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc1-yocto-standard+ #739
>>> [    0.523663] Call Trace:
>>> [    0.523663]  <IRQ>
>>> [    0.523663]  dump_stack_lvl+0x64/0xb0
>>> [    0.523663]  dump_stack+0x10/0x20
>>> [    0.523663]  __lock_acquire+0x6c4/0x3c10
>>> [    0.523663]  lock_acquire+0x188/0x460
>>> [    0.523663]  put_cpu_partial+0x5a/0x1e0
>>> [    0.523663]  __slab_free+0x39a/0x520
>>> [    0.523663]  ___cache_free+0xa9/0xc0
>>> [    0.523663]  qlist_free_all+0x7a/0x160
>>> [    0.523663]  per_cpu_remove_cache+0x5c/0x70
>>> [    0.523663]  __flush_smp_call_function_queue+0xfc/0x330
>>> [    0.523663]  generic_smp_call_function_single_interrupt+0x13/0x20
>>> [    0.523663]  __sysvec_call_function+0x86/0x2e0
>>> [    0.523663]  sysvec_call_function+0x73/0x90
>>> [    0.523663]  </IRQ>
>>> [    0.523663]  <TASK>
>>> [    0.523663]  asm_sysvec_call_function+0x1b/0x20
>>> [    0.523663] RIP: 0010:default_idle+0x13/0x20
>>> [    0.523663] RSP: 0000:ffffffff83e07dc0 EFLAGS: 00000246
>>> [    0.523663] RAX: 0000000000000000 RBX: ffffffff83e1e200 RCX: ffffffff82a83293
>>> [    0.523663] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8119a6b1
>>> [    0.523663] RBP: ffffffff83e07dc8 R08: 0000000000000001 R09: ffffed1006ac0d66
>>> [    0.523663] R10: ffff888035606b2b R11: ffffed1006ac0d65 R12: 0000000000000000
>>> [    0.523663] R13: ffffffff83e1e200 R14: ffffffff84a7d980 R15: 0000000000000000
>>> [    0.523663]  default_idle_call+0x6c/0xa0
>>> [    0.523663]  do_idle+0x2e1/0x330
>>> [    0.523663]  cpu_startup_entry+0x20/0x30
>>> [    0.523663]  rest_init+0x152/0x240
>>> [    0.523663]  arch_call_rest_init+0x13/0x40
>>> [    0.523663]  start_kernel+0x331/0x470
>>> [    0.523663]  x86_64_start_reservations+0x18/0x40
>>> [    0.523663]  x86_64_start_kernel+0xbb/0x120
>>> [    0.523663]  secondary_startup_64_no_verify+0xe0/0xeb
>>> [    0.523663]  </TASK>
>>>
>>> The local_lock_irqsave() is invoked in put_cpu_partial() and happens
>>> in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y (the
>>> LD_WAIT_CONFIG not equal to LD_WAIT_SPIN), so acquire local_lock in
>>> IPI context will trigger above calltrace.
>>
>> Just to add another similar case:
>>
>> Call Trace:
>>    <IRQ>
>>    dump_stack_lvl+0x69/0x97
>>    __lock_acquire+0x4a0/0x1b50
>>    lock_acquire+0x261/0x2c0
>>    ? restore_bytes+0x40/0x40
>>    local_lock_acquire+0x21/0x70
>>    ? restore_bytes+0x40/0x40
>>    put_cpu_partial+0x41/0x130
>>    ? flush_smp_call_function_queue+0x125/0x4d0
>>    kfree+0x250/0x2c0
>>    flush_smp_call_function_queue+0x125/0x4d0
>>    __sysvec_call_function_single+0x3a/0x100
>>    sysvec_call_function_single+0x4b/0x90
>>    </IRQ>
>>    <TASK>
>>    asm_sysvec_call_function_single+0x16/0x20
>>
>> So we can't call kfree() and its friends in interrupt context?
> 
> We can (well not RT "hard IRQ" context AFAIK, but that shouldn't be the case
> here), although I don't see from the part that you posted if it's again
> CONFIG_PROVE_RAW_LOCK_NESTING clashing with something else (no KASAN in the
> trace or I'm missing it?)

I lost the corresponding vmlinux, but this should be a similar issue, we
should continue to make lockdep recognize the !RT path.

> 
>> Also +Vlastimil Babka.
>>
>> Thanks,
>> Qi
>>
>>>
>>> This commit therefore move qlist_free_all() from hard-irq context to
>>> task context.
>>>
>>> Signed-off-by: Zqiang <qiang1.zhang@intel.com>
>>> ---
>>>    v1->v2:
>>>    Modify the commit information and add Cc.
>>>
>>>    mm/kasan/quarantine.c | 34 ++++++++--------------------------
>>>    1 file changed, 8 insertions(+), 26 deletions(-)
>>>
>>> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
>>> index 75585077eb6d..152dca73f398 100644
>>> --- a/mm/kasan/quarantine.c
>>> +++ b/mm/kasan/quarantine.c
>>> @@ -99,7 +99,6 @@ static unsigned long quarantine_size;
>>>    static DEFINE_RAW_SPINLOCK(quarantine_lock);
>>>    DEFINE_STATIC_SRCU(remove_cache_srcu);
>>>    
>>> -#ifdef CONFIG_PREEMPT_RT
>>>    struct cpu_shrink_qlist {
>>>    	raw_spinlock_t lock;
>>>    	struct qlist_head qlist;
>>> @@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
>>>    static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
>>>    	.lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
>>>    };
>>> -#endif
>>>    
>>>    /* Maximum size of the global queue. */
>>>    static unsigned long quarantine_max_size;
>>> @@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
>>>    	}
>>>    }
>>>    
>>> -#ifndef CONFIG_PREEMPT_RT
>>> -static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>> -{
>>> -	struct kmem_cache *cache = arg;
>>> -	struct qlist_head to_free = QLIST_INIT;
>>> -
>>> -	qlist_move_cache(q, &to_free, cache);
>>> -	qlist_free_all(&to_free, cache);
>>> -}
>>> -#else
>>>    static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>>    {
>>>    	struct kmem_cache *cache = arg;
>>> @@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>>    	qlist_move_cache(q, &sq->qlist, cache);
>>>    	raw_spin_unlock_irqrestore(&sq->lock, flags);
>>>    }
>>> -#endif
>>>    
>>>    static void per_cpu_remove_cache(void *arg)
>>>    {
>>> @@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>>    {
>>>    	unsigned long flags, i;
>>>    	struct qlist_head to_free = QLIST_INIT;
>>> +	int cpu;
>>> +	struct cpu_shrink_qlist *sq;
>>>    
>>>    	/*
>>>    	 * Must be careful to not miss any objects that are being moved from
>>> @@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>>    	 */
>>>    	on_each_cpu(per_cpu_remove_cache, cache, 1);
>>>    
>>> -#ifdef CONFIG_PREEMPT_RT
>>> -	{
>>> -		int cpu;
>>> -		struct cpu_shrink_qlist *sq;
>>> -
>>> -		for_each_online_cpu(cpu) {
>>> -			sq = per_cpu_ptr(&shrink_qlist, cpu);
>>> -			raw_spin_lock_irqsave(&sq->lock, flags);
>>> -			qlist_move_cache(&sq->qlist, &to_free, cache);
>>> -			raw_spin_unlock_irqrestore(&sq->lock, flags);
>>> -		}
>>> -		qlist_free_all(&to_free, cache);
>>> +	for_each_online_cpu(cpu) {
>>> +		sq = per_cpu_ptr(&shrink_qlist, cpu);
>>> +		raw_spin_lock_irqsave(&sq->lock, flags);
>>> +		qlist_move_cache(&sq->qlist, &to_free, cache);
>>> +		raw_spin_unlock_irqrestore(&sq->lock, flags);
>>>    	}
>>> -#endif
>>> +	qlist_free_all(&to_free, cache);
>>>    
>>>    	raw_spin_lock_irqsave(&quarantine_lock, flags);
>>>    	for (i = 0; i < QUARANTINE_BATCHES; i++) {
>>
> 
> 

-- 
Thanks,
Qi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a005e1ce-8c58-7d9a-0c55-09f3f5afc788%40bytedance.com.
