Return-Path: <kasan-dev+bncBC5L5P75YUERB577VHXQKGQEPF6RMOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AC74A115507
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 17:21:11 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id p2sf2282912wma.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 08:21:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575649271; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uq197gB3+LoSCWJvF/5mFif324aPUKdslDWV4z7Rzy+bKffGYx8y0wggUX587baxtH
         qtdaasle8IAH5Db04UXpETOLJCZGcV1uKfU7pp3I5LMwKfOMzVLzIF8C0oYFyEB8Ygs0
         FJh5g/+mq12UedPrXdk7dBsdTDRmbQugcgqHawQ3AHoklW1NB9cln1DxjEF6CULK7gMz
         oi2zVbG7U2B2BdtzPRx+QqmsiSUO39erNOZ5Rk15B6e/iFIvqV2tzkgHkjyUtcfOuult
         OeR8cOGPcKytB1XRxScag6sKrek1n3gobEat6vpKcJTL/hb2kPSkz++41whLI61c/2+w
         c2uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:subject
         :from:sender:dkim-signature;
        bh=R6zJCcGjhd20eMQ/9eOO4NKswSGkkAmvjUHBa+DqVs4=;
        b=t0X+1BZllMO3lrQAMcsUSRL6PBYhaDgAeCOa+Dv0nnGL6YDQ79+r2/JPG0m1FrYjsH
         8EZkZif2vAOemAsp5YXg9qkn8Q0hAaat0JqyfmHDP4MHAQmEtqx2pVcdcxZwPbnwfkW5
         s+tz72g7AAQPLPNq9DiGVRdwXoKfJKnfoslGR3qaicLgg2yPOJPYXigWIAos2n57/s1l
         9YMoYHwQrJFMwG/TSETES4NYtw1QHEtSJg4/rK0++ZkF2IHSXkWWtGcuhVwPvenGp1ta
         kLF/ppMR7EYMxOnIaKaZf9+CLC2PKxDWzMbun9KbmwkHfHZbtf1Thq/BpqQFnKlW9W5z
         Iw4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R6zJCcGjhd20eMQ/9eOO4NKswSGkkAmvjUHBa+DqVs4=;
        b=j1XMxYKVJZ9Weoj8EI37SaIWNvcfZyuTo/hQHuhxB7lJRHhMXGaL0kmG5KMWw6dUHB
         Gt1IsWtwRmpVGJMEjniDR5jdjte7VDzIY7fIG1GJbnHa88qI2kokrJFUc4G3ErkPKTGf
         +AyqtAoSMoh60G/82i0jWgfo9YuXDXEgymrrI4DsJOi8rKmBYVPiXo4peJ31RM0fqr/c
         v2LTrt6ChYJIFG0AJCAiAq7BVW2ZL9efmd3jW6JuQLNy9kkKZ23vMH9csgzbfYYMNDxg
         rM7h0uNIrmD7bcSfbjc7l1ATABfNNJqedgZJAbJ7vX6t7b05tNIsx9TzgTBpCGMnWuL1
         +isQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R6zJCcGjhd20eMQ/9eOO4NKswSGkkAmvjUHBa+DqVs4=;
        b=KcGkQpjUzjfpLug5PhmV7uPWWO6Uz38tebH+vMzJR5JMvKtg7xd+ubxbkSi16FwoQZ
         QoMcR9THjKhKu0U6cN/789D2jm+nzbUZsAHPxa19+YcqBPXMPYB+AdYUmyjgpq7qrWo9
         04BH3P6yVyAWLLXeccShHOf/i7An16WRMViqX5T/RDQQ5NC9NODaWCMFK0I142fWrtN+
         B8IN6FvROSjxRrYmn6k5wQalaFysyobvPL3HFyZzCAwKAHU+mZtRvQkfeEX8OypA1i+l
         JpB8XQacOwKGDOpHxKJPIGSkE7UF5/sZUHyjDYgIvkKyR5ZlfUQ+aeJn1CBZVYAT1Wyg
         xgnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUs6Z7WUIG7Ldg29MG5MSg6I8Db2KkhwJcH3/FWkuFIDBYa5JyK
	x/u/xdZ60YEIQiNJQP4jxDo=
X-Google-Smtp-Source: APXvYqzr3Tn92G0yTnarLxxv3fG1IF6G5hJTB0oufziGxe6ezm5xw//jgPPNuK8ocsZOb6Cinschnw==
X-Received: by 2002:adf:9064:: with SMTP id h91mr16810475wrh.289.1575649271400;
        Fri, 06 Dec 2019 08:21:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:55cd:: with SMTP id i13ls2687672wrw.0.gmail; Fri, 06 Dec
 2019 08:21:10 -0800 (PST)
X-Received: by 2002:adf:e40f:: with SMTP id g15mr17558303wrm.223.1575649270852;
        Fri, 06 Dec 2019 08:21:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575649270; cv=none;
        d=google.com; s=arc-20160816;
        b=yQ0XJJ6tTvMYSvPo5OcrmQi6CyJwQi+ospj75CKnMdJDQ4GLdD8FQcj8Ab1lm+hicu
         8zGEugzwsnhkUNL1BGExojSQyw+JOCyoseq9edn8us23TThpRR3g3WeMDZTRE7rn2GFv
         whgonOFmCfV/KLReOO0AaN+rmdl5ue2XBw6p8e8AWUoCuAyLyFUcNPYoUUMSIrKNenmd
         qVmd73/f8gtJGyp3mCpJdvl4W30pfkkzShKnZfkR1pnmXmJ0dWD97R0VMoe9nHMci8MK
         WJKn1/N+SofJV6P8PH+GlK8ABHhvBMAqZLcRJpwhuVbJ0U5QBlBa4kUWYWpn5udt7W4u
         uUfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:subject:from;
        bh=F2xYd0Fz2Gt7Osnsx58g6Gu8VXVUpKTitvLuUXDe2MQ=;
        b=zcEjdu5j8VINROEoYO22gNKK995JiBPLjrkEJL4wim8ih6rYCekx4/5C33wL3lEIdn
         Tsh9rtkfUo6clAuip56iK40TEsT6XpDOxhO5TCuH+GIwvOUnPqAJ5LJGD3v82hL4MgEf
         qHnDZdylUxT6GjztJO3iyyebruKiW2gd7x5b/69P7K/aOmo8yHRbGCxKrIpC5g/QP2ux
         l9iJGROlcgISuvHes9h6pQcmblm4adlmBW3GhX2MpRmFR5YPnieUE3TH0+tp5Xb9B/XJ
         zfo89EWB7Di1YMAaHLfUAx6y4cPqvuWRwCiZ8eRV8ALn7Cyo0edhVMHaK6K69i3WRopO
         nVXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id n24si146286wmk.1.2019.12.06.08.21.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 08:21:10 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1idGLe-00008F-Rf; Fri, 06 Dec 2019 19:20:55 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH 2/2] kasan: Don't allocate page tables in
 kasan_release_vmalloc()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20191204204534.32202-1-aryabinin@virtuozzo.com>
 <20191204204534.32202-2-aryabinin@virtuozzo.com>
 <20191204142256.567b143cfde572acd804544a@linux-foundation.org>
Message-ID: <1d53f0a3-a37e-72ca-fc69-c34e4f5023b7@virtuozzo.com>
Date: Fri, 6 Dec 2019 19:20:39 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20191204142256.567b143cfde572acd804544a@linux-foundation.org>
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



On 12/5/19 1:22 AM, Andrew Morton wrote:
> On Wed,  4 Dec 2019 23:45:34 +0300 Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> 
>> The purpose of kasan_release_vmalloc() is to unmap and deallocate shadow
>> memory. The usage of apply_to_page_range() isn't suitable in that scenario
>> because it allocates pages to fill missing page tables entries.
>> This also cause sleep in atomic bug:
>>
>> 	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
>> 	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:
>>
>> 	Call Trace:
>> 	 __dump_stack lib/dump_stack.c:77 [inline]
>> 	 dump_stack+0x199/0x216 lib/dump_stack.c:118
>> 	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
>> 	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>> 	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>> 	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
>> 	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
>> 	 alloc_pages include/linux/gfp.h:532 [inline]
>> 	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>> 	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
>> 	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
>> 	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
>> 	 apply_to_pte_range mm/memory.c:2031 [inline]
>> 	 apply_to_pmd_range mm/memory.c:2068 [inline]
>> 	 apply_to_pud_range mm/memory.c:2088 [inline]
>> 	 apply_to_p4d_range mm/memory.c:2108 [inline]
>> 	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
>> 	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
>> 	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
>> 	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
>> 	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
>> 	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
>> 	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
>> 	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
>> 	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
>> 	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
>> 	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
>> 	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
>> 	 __vmalloc_node mm/vmalloc.c:2607 [inline]
>> 	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
>> 	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
>> 	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
>> 	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
>> 	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
>> 	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
>> 	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
>> 	 __do_sys_setsockopt net/socket.c:2133 [inline]
>> 	 __se_sys_setsockopt net/socket.c:2130 [inline]
>> 	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
>> 	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
>> 	 entry_SYSCALL_64_after_hwframe+0x49/0xbe
> 
> Why is this warning happening?  Some lock held?  If so, which one?

spin_lock(&free_vmap_area_lock);

> 
>> Add kasan_unmap_page_range() which skips empty page table entries instead
>> of allocating them.
> 
> Adding an open-coded range walker is unfortunate.  Did you consider
> generalizing apply_to_page_range() for this purpose?  I did - it looks
> messy.
> 
> Somewhat.  I guess adding another arg to
> apply_to_p4d_range...apply_to_pte_range wouldn't kill us.  I wonder if
> there would be other sites which could utilize the additional control.
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d53f0a3-a37e-72ca-fc69-c34e4f5023b7%40virtuozzo.com.
