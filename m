Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBQV272QQMGQEUAYSDEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8058D6E7455
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 09:50:27 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-2fb7ba12a33sf624102f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 00:50:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681890627; cv=pass;
        d=google.com; s=arc-20160816;
        b=EqO/3KcHQHbHIX3wY0ll/mAtb5PILUJ06/F1xhXKNtcmIFFFGkGFj7xuvtRz3hvyoy
         wIbRBA9/dAxjP9XBzLdE3wt/CVBVY7AxmIPTvEidGoztwcj/42cH4rZKUlfv7vORCjt5
         S9MUHhYs3CZXsDJmlM/yDJ/LpHyVG4O14XVzGwEtRWKuivz8t+/tvxy8dwcHXG98hY2N
         Vj0Rajt27rhpD6v/mH+evo52MdTViz3LtXUyUSScF3fKqY7r45SZAMgfIGSM0jVcyLSe
         VMDH+p7+kH5wE/vUtn06UrxAOUVxH8u4VH7/mG8c4cYFqKgnbiZ8P1r/0RBwgr6bTYp1
         Y9sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=l4iQdTk+2Bd7IK3wintOUOSAQLH3ojapFH/wvsGXwOE=;
        b=TnfLsIwCPlv5PA5rQikkUTzGF32eDuxMnV/3UZ/FK1DUE6m5bPFaCLiHLSwcVTt4ZF
         VNfgNQ1uyqmv+TgbnkyTncO5J1BL/BSRHswMi4uBlkV5//z+fVk8y+/rftsdBSs1Dr3G
         LzSp0jcKWEh7U92IDeOE/h5Aq1U13/tDG9yEn87v1mtG3ofH0Cxelac2Aq9TbvWRrk1q
         7O7hFh9N2iK98jHenh3L2oOH1CeRdEhHXWy28iWXsna0YU1vLsCMj96oN6iMucl+Zjyf
         LNJRyFI9u6mo5mcMcV2euN8rkPv0GQFQidauX5zCBCBDk1phUSi9ebY76QRzOdr9eH9B
         t2DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EtYA3ibD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4BHkKvdA;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681890627; x=1684482627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l4iQdTk+2Bd7IK3wintOUOSAQLH3ojapFH/wvsGXwOE=;
        b=g3JutZDGCfMPBDjxiyD9TKgNLEzLHp32GCbJgMcfowGxFLB2UMro40oiCqIOmSzjak
         qC7xD7lZdsZFXyCOyaq5g3oFPbTQf8LvvNfnDPPb1p8bfnS+2jZe0NWqDpeKIKR8tqDe
         z2fK1C5NamTEFzSWQrHdZoV4Lbf2B+HekITl9gKOWgk1k3oCqzDI9hokBOc4N7Br8Pss
         nOicfbUhJFU8V0DG1MPW1+1huJMg71Z6MKDBPqrRhT1lV+S83R/YCRMeGJyZO4xk5PoQ
         KTnr7MkmYV7VjZpmk1iv0cN0Rc/FxCorpVzEjvrNyWUFw4SCoZGsq8ptiLkN0zcz36wu
         uZ8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681890627; x=1684482627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=l4iQdTk+2Bd7IK3wintOUOSAQLH3ojapFH/wvsGXwOE=;
        b=j+dKhuCxNUb+1+bBXRQLefWxzGu1c1eDiuBK3YJXy9tfrJpFxdFJz3J5uYhGhbnzwh
         LozLsg5gTNTAPIU2KMo7AUkjtLdkQl1VVkoK0d0l2TQYmfx2IFAPGIciTPM5SRiwiFnB
         dxheiWLWHxbEPS/VhKW/AcotC5xPKr2F77Bq8r7SgReQBr5GRVpNp3KlYjXHzTZt76j8
         /ggR8o4rUiNp7cwHNseKdBv6IiW8uHNX9MV3MbBoZUN9rNzBJ+YJhoHVOBNSQmrIZMJU
         s/CCR68G33FMCpxsjdbnZhRx0PDdqm4QN1N4ilZpUIR794d7YEeiGJ+hm/dviARInnxV
         zeqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9f3p0109EJ1ew4f12hRXHko7D58VMqfy/qpkFjhDSRnD5/SHkGL
	pdYNR0v6+aD8TApf0rRbOiE=
X-Google-Smtp-Source: AKy350ZDymlbRQF3bGQC+t73rC7iAmZd0wYhOsklY9GLaw5fic3KBK/3BFHK9+rkTKuSX8FH9B5p4Q==
X-Received: by 2002:a5d:644a:0:b0:2f5:4a6f:d880 with SMTP id d10-20020a5d644a000000b002f54a6fd880mr750159wrw.0.1681890626910;
        Wed, 19 Apr 2023 00:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1593:b0:3f1:7596:66be with SMTP id
 r19-20020a05600c159300b003f1759666bels586239wmf.3.-pod-control-gmail; Wed, 19
 Apr 2023 00:50:25 -0700 (PDT)
X-Received: by 2002:a7b:cd93:0:b0:3f1:6434:43bf with SMTP id y19-20020a7bcd93000000b003f1643443bfmr10775023wmj.17.1681890624975;
        Wed, 19 Apr 2023 00:50:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681890624; cv=none;
        d=google.com; s=arc-20160816;
        b=Woq05JvWd51BxOcH7metZDUVMdSGAiynvUXeAUKZcsgSC/yQjpbkw0DytFa51kUyAf
         /n//uZnlD+sH6LKVnW+KUaM7pOooplVvPOZveAiZw+kD7IijZTU55VpvoGwWCUbodbe0
         /KEA7G1/Dahw/ywlHuTTzgGqXPk2eq2g0XnNyL2dHpTZgtwjuDqlF93HWkhO6U3O/B1N
         xzI0BmHKZxfPAGysCV0zKZsECuuFb9dAoJA14i4WiHVnOyk0MR0toB7hSUWQgaIoAm7k
         rWm0pxNpb0kvas1n/6sj8VXCGpKoSUj/K87qCrPJHQhjiwGok0V2r/c243byS34fPU8n
         TCsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=/gOIoJ50usRPRIgQvqFAXblPT8i35cMDLGeltpbNIHk=;
        b=eDYCXijVmMUpRgOMjzVYewSTqHcwn90Nam4e3U2mSgBD39p0poVhFfr8NedUGxrkuO
         M808H3hc/OvjpqDg/zopdWHOpG/seNsb3BQt8495fz21JtzKA7VUH2veLm2S7w2wDerd
         2lZ+g8sYnu6CtdioZ3qkAaPgQVFrjy5YqRELZIA55RFMRUNyqN+z1mBg5BJipp7j96Rg
         qEG9WoFvxGOMmqKVBbw42CiyaGmRFd9RXtUSIy+6WFXLMHgiZ/wh0cCdZe8bF/6b7TNH
         ntj5pYnL3YqbYn6LAYis8lW8/tMDS3AoQ6sL5I8eL1uQVkGGtEzEuKymt9foo0jCltHm
         BGKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EtYA3ibD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4BHkKvdA;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bh9-20020a05600005c900b002ff7131fb70si2086wrb.4.2023.04.19.00.50.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Apr 2023 00:50:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 97E281FD87;
	Wed, 19 Apr 2023 07:50:24 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 43A0A1390E;
	Wed, 19 Apr 2023 07:50:24 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id X2qgD0CdP2QxUAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 19 Apr 2023 07:50:24 +0000
Message-ID: <be865fb8-b3f8-4c80-d076-3bbd15f3c0e8@suse.cz>
Date: Wed, 19 Apr 2023 09:50:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
To: Marco Elver <elver@google.com>, Zqiang <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 Thomas Gleixner <tglx@linutronix.de>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Qi Zheng <zhengqi.arch@bytedance.com>, Peter Zijlstra <peterz@infradead.org>
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
 <CANpmjNOjPZm0hdxZmtp4HgqGpkevUvpj-9XGUe24rRTBRroiqg@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNOjPZm0hdxZmtp4HgqGpkevUvpj-9XGUe24rRTBRroiqg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EtYA3ibD;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=4BHkKvdA;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 4/19/23 09:26, Marco Elver wrote:
> On Mon, 27 Mar 2023 at 13:48, Zqiang <qiang1.zhang@intel.com> wrote:
>>
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
>>
>> This commit therefore move qlist_free_all() from hard-irq context to
>> task context.
>>
>> Signed-off-by: Zqiang <qiang1.zhang@intel.com>
> 
> PROVE_RAW_LOCK_NESTING is for the benefit of RT kernels. So it's
> unclear if this is fixing anything on non-RT kernels, besides the
> lockdep warning.

Yes, the problem seems to be that if there's different paths tor RT and !RT
kernels, PROVE_RAW_LOCK_NESTING doesn't know that and will trigger on the
!RT path in the !RT kernel. There's was an annotation proposed for these
cases in the thread linked below, but AFAIK it's not yet finished.

https://lore.kernel.org/all/20230412124735.GE628377@hirez.programming.kicks-ass.net/

> I'd be inclined to say that having unified code for RT and non-RT
> kernels is better.

Agreed it should be better, as long as it's viable.

> Acked-by: Marco Elver <elver@google.com>
> 
> +Cc RT folks
> 
>> ---
>>  v1->v2:
>>  Modify the commit information and add Cc.
>>
>>  mm/kasan/quarantine.c | 34 ++++++++--------------------------
>>  1 file changed, 8 insertions(+), 26 deletions(-)
>>
>> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
>> index 75585077eb6d..152dca73f398 100644
>> --- a/mm/kasan/quarantine.c
>> +++ b/mm/kasan/quarantine.c
>> @@ -99,7 +99,6 @@ static unsigned long quarantine_size;
>>  static DEFINE_RAW_SPINLOCK(quarantine_lock);
>>  DEFINE_STATIC_SRCU(remove_cache_srcu);
>>
>> -#ifdef CONFIG_PREEMPT_RT
>>  struct cpu_shrink_qlist {
>>         raw_spinlock_t lock;
>>         struct qlist_head qlist;
>> @@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
>>  static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
>>         .lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
>>  };
>> -#endif
>>
>>  /* Maximum size of the global queue. */
>>  static unsigned long quarantine_max_size;
>> @@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
>>         }
>>  }
>>
>> -#ifndef CONFIG_PREEMPT_RT
>> -static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>> -{
>> -       struct kmem_cache *cache = arg;
>> -       struct qlist_head to_free = QLIST_INIT;
>> -
>> -       qlist_move_cache(q, &to_free, cache);
>> -       qlist_free_all(&to_free, cache);
>> -}
>> -#else
>>  static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>  {
>>         struct kmem_cache *cache = arg;
>> @@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>>         qlist_move_cache(q, &sq->qlist, cache);
>>         raw_spin_unlock_irqrestore(&sq->lock, flags);
>>  }
>> -#endif
>>
>>  static void per_cpu_remove_cache(void *arg)
>>  {
>> @@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>  {
>>         unsigned long flags, i;
>>         struct qlist_head to_free = QLIST_INIT;
>> +       int cpu;
>> +       struct cpu_shrink_qlist *sq;
>>
>>         /*
>>          * Must be careful to not miss any objects that are being moved from
>> @@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>>          */
>>         on_each_cpu(per_cpu_remove_cache, cache, 1);
>>
>> -#ifdef CONFIG_PREEMPT_RT
>> -       {
>> -               int cpu;
>> -               struct cpu_shrink_qlist *sq;
>> -
>> -               for_each_online_cpu(cpu) {
>> -                       sq = per_cpu_ptr(&shrink_qlist, cpu);
>> -                       raw_spin_lock_irqsave(&sq->lock, flags);
>> -                       qlist_move_cache(&sq->qlist, &to_free, cache);
>> -                       raw_spin_unlock_irqrestore(&sq->lock, flags);
>> -               }
>> -               qlist_free_all(&to_free, cache);
>> +       for_each_online_cpu(cpu) {
>> +               sq = per_cpu_ptr(&shrink_qlist, cpu);
>> +               raw_spin_lock_irqsave(&sq->lock, flags);
>> +               qlist_move_cache(&sq->qlist, &to_free, cache);
>> +               raw_spin_unlock_irqrestore(&sq->lock, flags);
>>         }
>> -#endif
>> +       qlist_free_all(&to_free, cache);
>>
>>         raw_spin_lock_irqsave(&quarantine_lock, flags);
>>         for (i = 0; i < QUARANTINE_BATCHES; i++) {
>> --
>> 2.25.1
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230327120019.1027640-1-qiang1.zhang%40intel.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be865fb8-b3f8-4c80-d076-3bbd15f3c0e8%40suse.cz.
