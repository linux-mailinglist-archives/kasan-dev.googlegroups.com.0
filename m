Return-Path: <kasan-dev+bncBC5L5P75YUERBT4GQTXQKGQE3VDA5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 68BC510D4FF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 12:38:55 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id g11sf12272815edu.10
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 03:38:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575027535; cv=pass;
        d=google.com; s=arc-20160816;
        b=gY2LE2fsoOIa9Oapfg4r8HPdfelUwIh6JST/YfueOl1dl1HuZGvt9XpYZv6tyRN/ll
         uYsOA+T9TbW5QdKr4F8HS07w2V5v6ICqG074NwmhMuYFM0VGGplu8K9Qfb12dbfgRk5h
         KUe0SiuDz6ReDWpPlFZYiSTUjc1cR1foWIqq31Dn0cYTheb9J4hTU2kGwb+TnGSDzcB3
         ciB0JaOnuA6o0OFcO96ci18VofFBUOtaakh57sRJuNgF8Ah5MiKLevLvF0SdBRXlbYa+
         vj9v2C7U0S0hMq7QahryBZ4z6jxzX7KV+JibSckzkPTSMFRcEmhDTNZ6RI7nKJMe7j8E
         YqTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=lLnI3/0vDxbJ4f11Fc7f+HEOocs7MZXBxrrzC0xk8Tg=;
        b=FOxcS0GVAN04+iAwC7p57c6HqfbDdq8NcIfxSydok6sFxBs2ZFtE88DaiCzlS5lEld
         vW4T6V7WN413+pP3YmDjzO/mDRPaXHwnPduwx3waKgi8fSPraoTheWvtju8zYSe8ELMY
         rgvml1AvFDOdbcJ3q8w2Wn2k7FTa2REnTJIJfuc0bA2P6sd1CnVyo7Twvp4UsglUH/cY
         sLcVZxpLu9DyhzYQHKumkvvsQM+3xytZ7IjJs34EXWqRXMtsHfM/ZzJf3pkjKUn+6WIZ
         8RvAP46/5e63sMfK2fljS2HISZoUrwiRSM1ZAwkxyL8cUVFkmAfhK7coTx5By8q5gkNS
         xTQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lLnI3/0vDxbJ4f11Fc7f+HEOocs7MZXBxrrzC0xk8Tg=;
        b=D0Rlx9PAlLFe1lLTqsvYYiTbd00Qcxd5yAgB+Qyg0H/f+cyYu+hs5JEKhB3Cibwgwb
         5lXRr3OKq3ezjVOqEboh5WedK/UmKlF4ReBOuJAJD+apS1pfX6/TSeh2b3PtcJg+pTws
         UXgVm45NrylrECndQqVAZVOBTX5IHlgQE4xZVnsQzUSoXnhowKY5bbmOUM4q/3xSy50K
         2vjJ2xCpjp9XtGwWk+2lqKceTOF2JveRq9HgeYunEK6J9jCAvUSL94v/0xKphn0BTT+3
         4A/hswSsrw6jfqVEVWiSz22mdrbSJhfyl08rK9QKfvUOffcOCJY8KP9Iphd9aN+Q0JIe
         ycTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lLnI3/0vDxbJ4f11Fc7f+HEOocs7MZXBxrrzC0xk8Tg=;
        b=Fmm2OscOqXP4QbFDM045DeBedltG/d46n6PiuQvJI8x1kN0On/aKZkGfTX8ou1aGKm
         nYTuuDpjJiqc5p9hJR31MUOGNSeRRLbue1JbQQqZsnIF5tbmFVxWCZVhYPgSk4JLXD2J
         9sBysEhqSrrURetsm+w9XHYMokioDT3m1jR5k5UNeBR5nZJ+1O7QpGOkt4Rs49QZgXHA
         T7GOeYezZXk35LNPvcm1X4YsoD0dCCscm5MzU2tlJvYLrg5jraRmjRAkTrTKkRaAVnJx
         77jVtTGTWp2omwBblm2sfa87ko2VhokW1B+lj+EF0OlteUN8yodT+Eej5BrHFH3MpCUW
         dAeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVhM3YrZmkyoMsgi5authuk5tFYYX0kzplCcK5WfBfn8X9Qfg0/
	ZjKYsFGUlrEeIaoRoUlDZmA=
X-Google-Smtp-Source: APXvYqxE64ZkqQBidobKFsElHPVV/RisEESyrOn3ZlfDwm8LL6RO2ijWJD1ULhr4aZviTX5oUWzHdA==
X-Received: by 2002:aa7:c74f:: with SMTP id c15mr8018226eds.304.1575027535106;
        Fri, 29 Nov 2019 03:38:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95d0:: with SMTP id n16ls8867406ejy.5.gmail; Fri, 29
 Nov 2019 03:38:54 -0800 (PST)
X-Received: by 2002:a17:906:3793:: with SMTP id n19mr13080834ejc.85.1575027534398;
        Fri, 29 Nov 2019 03:38:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575027534; cv=none;
        d=google.com; s=arc-20160816;
        b=M7NhAl9Y0WeBD6Us0rqd576mnuSDJET2kW5rKIUGOCy6IEZMdTtmesPljr7nIP3Wob
         80xruoSqLLiiPBdtvMTFlK2TuU/rKnZIHp0xj3jGbeulRk4XEpCjbxzZRyVLJOe/0N1Y
         ETFnGpY0riONWp4orI7tFB9G0BIPu0gK2oOnpuYH2U7kUJaXPMwzkT3OylNpAVLaMTdo
         934OHWw5CtaX0LMl34LzshtINUEeWzpSEA5aF4HBnUNHxgsfAg6Z+rQ5akTn5AeaDSt9
         GESvhR0quI6mhIIpCOuEGm0hR/zR2uSa8Bk46iO+vMK9tY/SAROV4IsaBfT9wNIi85J+
         mBgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YxvDxbuca6QEurx8I23suPpp9ZzZJEd8WIRSaSgu+fA=;
        b=uyyHdek7YeuGu8NIE/bbuNSpMqCVBicUfxXbQZmcUtpttBDPwACuTjVRaSbBiZaPBW
         VfVtuTiaQnZ6DQ3yDvoA6F6lcx4zdPdTx2RB5k9XyNypDBQxuHLyxNWNrD70aKKA/goJ
         Uedc9f6Mq1NZGS2yke45FQAhaYV/5ibq20hVJs3bXX2P8ia+hMNDHajAb6TFBZeYe64O
         YYHfqUbgpLppAF3bf7u3TwettF+S1eUyB/aka/SQ7cYv6rmhSBkxHTu8OqXgHVqLhZw7
         4lecw6Q+Jpp0PLTl4fVjoGUdoy5eshrRD18qjOrrN3Xd9TriCM3zfe8JSOyfyE553Zgz
         YwEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id x16si1012797eds.5.2019.11.29.03.38.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Nov 2019 03:38:54 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iaebJ-0001SW-HX; Fri, 29 Nov 2019 14:38:17 +0300
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 the arch/x86 maintainers <x86@kernel.org>,
 Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Christophe Leroy <christophe.leroy@c-s.fr>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 Vasily Gorbik <gor@linux.ibm.com>
References: <20191031093909.9228-1-dja@axtens.net>
 <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw>
 <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
 <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
 <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com>
Date: Fri, 29 Nov 2019 14:38:03 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/29/19 2:02 PM, Dmitry Vyukov wrote:
> On Fri, Nov 29, 2019 at 11:58 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Fri, Nov 29, 2019 at 11:43 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>>
>>> On Tue, Nov 19, 2019 at 10:54 AM Andrey Ryabinin
>>> <aryabinin@virtuozzo.com> wrote:
>>>> On 11/18/19 6:29 AM, Daniel Axtens wrote:
>>>>> Qian Cai <cai@lca.pw> writes:
>>>>>
>>>>>> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
>>>>>>>     /*
>>>>>>>      * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>>>>>>>      * flag. It means that vm_struct is not fully initialized.
>>>>>>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>>>>>>>
>>>>>>>             setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>>>>>>>                              pcpu_get_vm_areas);
>>>>>>> +
>>>>>>> +           /* assume success here */
>>>>>>> +           kasan_populate_vmalloc(sizes[area], vms[area]);
>>>>>>>     }
>>>>>>>     spin_unlock(&vmap_area_lock);
>>>>>>
>>>>>> Here it is all wrong. GFP_KERNEL with in_atomic().
>>>>>
>>>>> I think this fix will work, I will do a v12 with it included.
>>>>
>>>> You can send just the fix. Andrew will fold it into the original patch before sending it to Linus.
>>>>
>>>>
>>>>
>>>>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>>>>> index a4b950a02d0b..bf030516258c 100644
>>>>> --- a/mm/vmalloc.c
>>>>> +++ b/mm/vmalloc.c
>>>>> @@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>>>>>
>>>>>                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>>>>>                                  pcpu_get_vm_areas);
>>>>> +       }
>>>>> +       spin_unlock(&vmap_area_lock);
>>>>>
>>>>> +       /* populate the shadow space outside of the lock */
>>>>> +       for (area = 0; area < nr_vms; area++) {
>>>>>                 /* assume success here */
>>>>>                 kasan_populate_vmalloc(sizes[area], vms[area]);
>>>>>         }
>>>>> -       spin_unlock(&vmap_area_lock);
>>>>>
>>>>>         kfree(vas);
>>>>>         return vms;
>>>
>>> Hi,
>>>
>>> I am testing this support on next-20191129 and seeing the following warnings:
>>>
>>> BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
>>> in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
>>> 4 locks held by kworker/1:1/44:
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>>> __write_once_size include/linux/compiler.h:247 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>>> arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
>>> include/asm-generic/atomic-instrumented.h:868 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>>> atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
>>> kernel/workqueue.c:615 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>>> set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
>>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>>> process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
>>>  #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
>>> process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
>>>  #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
>>> pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
>>>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
>>> include/linux/spinlock.h:338 [inline]
>>>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
>>> pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
>>> Preemption disabled at:
>>> [<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
>>> [<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
>>> CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
>>> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
>>> Workqueue: events pcpu_balance_workfn
>>> Call Trace:
>>>  __dump_stack lib/dump_stack.c:77 [inline]
>>>  dump_stack+0x199/0x216 lib/dump_stack.c:118
>>>  ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
>>>  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>>>  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>>>  __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
>>>  alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
>>>  alloc_pages include/linux/gfp.h:532 [inline]
>>>  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>>>  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
>>>  kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
>>>  apply_to_pte_range mm/memory.c:2041 [inline]
>>>  apply_to_pmd_range mm/memory.c:2068 [inline]
>>>  apply_to_pud_range mm/memory.c:2088 [inline]
>>>  apply_to_p4d_range mm/memory.c:2108 [inline]
>>>  apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
>>>  kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
>>>  pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
>>>  pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
>>>  pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
>>>  process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
>>>  worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
>>>  kthread+0x365/0x450 kernel/kthread.c:255
>>>  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>>>
>>>
>>> Not sure if it's the same or not. Is it addressed by something in flight?
>>>
>>> My config:
>>> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
>>
>>
>> I've tried this fix for pcpu_get_vm_areas:
>> https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
>> and it helps. But this will break syzbot on linux-next soon.
> 
> 
> Can this be related as well?
> Crashes on accesses to shadow on the ion memory...

Nope, it's vm_map_ram() not being handled

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2297c356-0863-69ce-85b6-8608081295ed%40virtuozzo.com.
