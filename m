Return-Path: <kasan-dev+bncBCGKXGVR4MKBBHGEWWDQMGQEJDN436I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 41B493C6DC2
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 11:51:26 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id f5-20020a92b5050000b02901ff388acf98sf14073580ile.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jul 2021 02:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626169885; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCY7PBoAthhDPMIvobyUsmEH/V0Ty2W0dzBTaIdv3ukfRgVQM/iY3ZM8C0dTRqx3KV
         L/otzdpzCsxl+JL4icvJdCBP+UNXumbbqHGS54CzXj46Gi1vkiujlgULdmuYHTp0+8Nu
         UCuPXd9PTE/o14Xb9u3uGsWYtbhSGWsGxXRahC5XmhI5e9gC/lkUyBUrTo4IJv8HdgxN
         oDM7jP1WDfevUIuc57SUMf1jywjZWNApUFjaI5zMAJ55FZD30Py17jUiKDrU3+WIAGQm
         Ko3AVF4YCFha/9bQYBfjTaY9vpQotAwzJlzSuHp4UatXhOOVSMlOpVWxLfoGUF2lvWcR
         Nu/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=NdwSWSarg7D/uFoDinXAhqKGCeQknYqh/Gv95g+blDw=;
        b=o1BFD0+uJk797eEeCsQlnYc1mVOGgtOzuFYS/hoBL6AYUA9Ulew/aiu16DwqtL11qX
         hP7f2d8M1XBNxsTDEdT2ZhOEE4jaPlVg8MeTnODMO/hXUJ3AdtuigIYZZDFMqePWWmDB
         WZF3Bn03Hnd9avsu8XMjSEsJTV5Fu3MnZw4t/xSoxXcak3UMg9Ym44Dt+lfefyyEnIdt
         a608dFEWPRwP1aG1R+ugdusGnzRJZ5ZJcBbpqt2cuh4HHljWwZCi1JSLT+ezyl6NXT/z
         WF+2yHO6z33N+WGdpgZwMq/PwYRJ7tCefGkGD7/pV+3nwqPiES4P5Wiyfx7zE9XMsrW/
         NJqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lojnmhW3;
       spf=pass (google.com: domain of desmondcheongzx@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=desmondcheongzx@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NdwSWSarg7D/uFoDinXAhqKGCeQknYqh/Gv95g+blDw=;
        b=ABL9p08rz7vYz4wv0UBk3xfkYAgKrw6vsKdCRA1m20LE0/T9mRjq+rtF046hAlUWr2
         owNTfnahxHpGLHSBLOnorwXHY/QcBeZJRWPBAnhDkaKH0zXRz5h/SzB4yweU2B56SQ7u
         PxH46FjDATIa6njadph8y26+RGvPZTLRRMHlwAexmosZ18rCY5TOe9tY9/oXKD1xaqbg
         KoTZ4nbL+8Kxr56x9onDstL9rs8j5WhCyJ0n4VNEIceGgQpLWVkBjB2NjGstgFW8LlCK
         l0V69TxkdCPLTMzj1c+CIOCq/NtkT4xvKACPCtFsyfV4UT7OdSXmJCSxp8wcFWB69K7I
         JpkA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NdwSWSarg7D/uFoDinXAhqKGCeQknYqh/Gv95g+blDw=;
        b=SF2FPe7iuFS+eRaTaV6kIuncP/IfSI1pH8c7SZM6ZdGx0eJgJFXy4HwSc/6W8LMhQQ
         CBXJq+OzeR1ZZZEATCCC4j2YtZY/sZ/v5gIQUoAJn36bY8q0lCD7zW5OE3sR7ick7rnm
         hfUfFVC0dRYMuDDoLJt4qNW/M8zhdXN6YK6SpWNdpDGGdh2WPqDbZ5/HKQnvRioTA4d3
         gHEqdk3JUAXFMtYGAr8eA7Wo+9tl7jBR9ospqqAYZ4sTLkkAqVL7c9Lcv14WD0utILAc
         lil9YdjAJYWTmX+dJFAZHI7Ew8osSc1Tq62U5T1hEknFVUcELuLkbaFoRVYWMo7AfwYI
         Bp1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NdwSWSarg7D/uFoDinXAhqKGCeQknYqh/Gv95g+blDw=;
        b=AE6SlxWFNkTam5dSaN5+sPeWMzRBRMS2gTf1wzKuv9PUuUJrYt39YdcuptVGu0/L1s
         SKkb5TqZl/HPkpmmMHR2id2o/4ouiDsWlpDZNMsIZDJiXqIWqEnRJOLNy/nGrPZDT2ic
         EtVSq1cxVLnIi/dbh+7li96fF4hOE2rElhZY8k3nucBbQ98qq+QJ9vM9zo+alo7+k3wv
         vWQpoSQ+2AxgPIwb1JUu+8CVhwTtLg5qf40D/4ex8ZeSTy0O0K8NtABuU+kqWSrkzm+P
         noIPfpQ2GjuhXARB6K//wmnnx75Vi7X2eNNmc039wS3+2Y3rEA37hi3XcDYpw96hskWy
         +PJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BfmGfjpl/k7/eQY+V4l9KcAGgmkv0SL0bsh4lw2gOGktuaAgA
	25CIjYdJqKCBcPbN4RaX0to=
X-Google-Smtp-Source: ABdhPJxUuwNsR9Zjb8yPKXjiVjXEyZNN1ix0u3o49onY5CatDbt8dIiOxxEB0Xr5Yw3xa/4UD5FYHA==
X-Received: by 2002:a6b:4905:: with SMTP id u5mr2483725iob.55.1626169884970;
        Tue, 13 Jul 2021 02:51:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2a01:: with SMTP id r1ls3796491ile.7.gmail; Tue, 13 Jul
 2021 02:51:24 -0700 (PDT)
X-Received: by 2002:a05:6e02:194f:: with SMTP id x15mr2200862ilu.145.1626169884603;
        Tue, 13 Jul 2021 02:51:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626169884; cv=none;
        d=google.com; s=arc-20160816;
        b=EWIvBQrSR3YFWAhItT8HesSxC9e9IaZbx6lKV/0hmca2Rq2VTWZoWSiJj63UH8lYy1
         hZa53zUQEuSoOFyx8m9Su/JMQsYYWqBH+fKyIVv4y5GZAnD0FsQYKtenwa6KtMJ4vemZ
         wQd4MaXMYhH4BNIplpCmXTeIqbg5q3YkH4rXBqntQ9xUwtFvDrAMHi0OQ7Y/TVuPTFn5
         Gjsr6rrRNNHs8Hh3ZB74QyG96yDMQVaNSuWIAYpWSqmUgeW9aEr26TfW0aN7RLHhsYXn
         2cPoLMBAR/aGKohHEAu0spyBsB3Eql/uJP1uUzR+VUN+cYKCRsJVRl8ClfXh/qZyxTOj
         1H0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=G05ynKIPKi1oJN3yPy5AvoQWFgL26tqGNRs3jXqC8rc=;
        b=kcYNaK5bwBJ3wS+tHJ6PH3lqqWUg8i++I/Ex4KjtPQb3K18pYRsFEGWWwy6gVTjN95
         ZRt3jFGU2K6XvtuGAkEgHWy2ZTE8MItlcaYEdyMabNC19wqiTE9oSBpgbQ/AR94CoSqf
         J9fN9UExCmqBx3s+zzkES2TMA772Q/fJBvhjj+UhBrZaV43uaB9qtTxXXznppSnh2LuN
         FXvXNxIvaW85yxzGYCsefF7+FJ00rklyXqjxfwzm+2nybg2fqikBPbP+Zv+AN08V90zr
         SKGiqH6ockkttW3no1HrFc8P6B+2ZvcWcPijbZGDmJHM1XFLGHl0hQCRYzGZOiig0wTZ
         VO6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lojnmhW3;
       spf=pass (google.com: domain of desmondcheongzx@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=desmondcheongzx@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id h1si1836834iow.1.2021.07.13.02.51.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jul 2021 02:51:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of desmondcheongzx@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id o3-20020a17090a6783b0290173ce472b8aso1083647pjj.2;
        Tue, 13 Jul 2021 02:51:24 -0700 (PDT)
X-Received: by 2002:a17:90b:4a4b:: with SMTP id lb11mr3570433pjb.99.1626169883669;
        Tue, 13 Jul 2021 02:51:23 -0700 (PDT)
Received: from [192.168.1.237] ([118.200.190.93])
        by smtp.gmail.com with ESMTPSA id f5sm18761261pfn.134.2021.07.13.02.51.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jul 2021 02:51:23 -0700 (PDT)
Subject: Re: [syzbot] upstream test error: BUG: sleeping function called from
 invalid context in stack_depot_save
To: Hillf Danton <hdanton@sina.com>, Dmitry Vyukov <dvyukov@google.com>,
 Mel Gorman <mgorman@techsingularity.net>
Cc: syzbot <syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, akpm@linux-foundation.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 syzkaller-bugs@googlegroups.com
References: <0000000000009e7f6405c60dbe3b@google.com>
 <20210703041256.212-1-hdanton@sina.com>
From: Desmond Cheong Zhi Xi <desmondcheongzx@gmail.com>
Message-ID: <49b84cde-647d-c4ef-4eac-d99376bb600a@gmail.com>
Date: Tue, 13 Jul 2021 17:51:19 +0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210703041256.212-1-hdanton@sina.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: desmondcheongzx@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lojnmhW3;       spf=pass
 (google.com: domain of desmondcheongzx@gmail.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=desmondcheongzx@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 3/7/21 12:12 pm, Hillf Danton wrote:
> On Thu, 1 Jul 2021 13:10:37 +0200 Dmitry Vyukov wrote:
>> On Thu, Jul 1, 2021 at 1:00 PM syzbot wrote:
>>>
>>> Hello,
>>>
>>> syzbot found the following issue on:
>>>
>>> HEAD commit:    dbe69e43 Merge tag 'net-next-5.14' of git://git.kernel.org..
>>> git tree:       upstream
>>> console output: https://syzkaller.appspot.com/x/log.txt?x=1216d478300000
>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=47e4697be2f5b985
>>> dashboard link: https://syzkaller.appspot.com/bug?extid=e45919db2eab5e837646
>>>
>>> IMPORTANT: if you fix the issue, please add the following tag to the commit:
>>> Reported-by: syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com
>>
>> +kasan-dev@ for for stack_depot_save warning
>>
>>> BUG: sleeping function called from invalid context at mm/page_alloc.c:5179
>>> in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 8436, name: syz-fuzzer
>>> INFO: lockdep is turned off.
>>> irq event stamp: 0
>>> hardirqs last  enabled at (0): [<0000000000000000>] 0x0
>>> hardirqs last disabled at (0): [<ffffffff814406db>] copy_process+0x1e1b/0x74c0 kernel/fork.c:2061
>>> softirqs last  enabled at (0): [<ffffffff8144071c>] copy_process+0x1e5c/0x74c0 kernel/fork.c:2065
>>> softirqs last disabled at (0): [<0000000000000000>] 0x0
>>> CPU: 1 PID: 8436 Comm: syz-fuzzer Tainted: G        W         5.13.0-syzkaller #0
>>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
>>> Call Trace:
>>>   __dump_stack lib/dump_stack.c:79 [inline]
>>>   dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:96
>>>   ___might_sleep.cold+0x1f1/0x237 kernel/sched/core.c:9153
>>>   prepare_alloc_pages+0x3da/0x580 mm/page_alloc.c:5179
>>>   __alloc_pages+0x12f/0x500 mm/page_alloc.c:5375
>>>   alloc_pages+0x18c/0x2a0 mm/mempolicy.c:2272
>>>   stack_depot_save+0x39d/0x4e0 lib/stackdepot.c:303
>>>   save_stack+0x15e/0x1e0 mm/page_owner.c:120
>>>   __set_page_owner+0x50/0x290 mm/page_owner.c:181
>>>   prep_new_page mm/page_alloc.c:2445 [inline]
>>>   __alloc_pages_bulk+0x8b9/0x1870 mm/page_alloc.c:5313
>>>   alloc_pages_bulk_array_node include/linux/gfp.h:557 [inline]
>>>   vm_area_alloc_pages mm/vmalloc.c:2775 [inline]
>>>   __vmalloc_area_node mm/vmalloc.c:2845 [inline]
>>>   __vmalloc_node_range+0x39d/0x960 mm/vmalloc.c:2947
>>>   __vmalloc_node mm/vmalloc.c:2996 [inline]
>>>   vzalloc+0x67/0x80 mm/vmalloc.c:3066
>>>   n_tty_open+0x16/0x170 drivers/tty/n_tty.c:1914
>>>   tty_ldisc_open+0x9b/0x110 drivers/tty/tty_ldisc.c:464
>>>   tty_ldisc_setup+0x43/0x100 drivers/tty/tty_ldisc.c:781
>>>   tty_init_dev.part.0+0x1f4/0x610 drivers/tty/tty_io.c:1461
>>>   tty_init_dev include/linux/err.h:36 [inline]
>>>   tty_open_by_driver drivers/tty/tty_io.c:2102 [inline]
>>>   tty_open+0xb16/0x1000 drivers/tty/tty_io.c:2150
>>>   chrdev_open+0x266/0x770 fs/char_dev.c:414
>>>   do_dentry_open+0x4c8/0x11c0 fs/open.c:826
>>>   do_open fs/namei.c:3361 [inline]
>>>   path_openat+0x1c0e/0x27e0 fs/namei.c:3494
>>>   do_filp_open+0x190/0x3d0 fs/namei.c:3521
>>>   do_sys_openat2+0x16d/0x420 fs/open.c:1195
>>>   do_sys_open fs/open.c:1211 [inline]
>>>   __do_sys_openat fs/open.c:1227 [inline]
>>>   __se_sys_openat fs/open.c:1222 [inline]
>>>   __x64_sys_openat+0x13f/0x1f0 fs/open.c:1222
>>>   do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>>   do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80
>>>   entry_SYSCALL_64_after_hwframe+0x44/0xae
> 
> One of the quick fixes is move preparing new page out of the local lock (with
> irq disabled) if it is difficult to add changes in saving stack.
> 
> +++ x/mm/page_alloc.c
> @@ -5231,6 +5231,7 @@ unsigned long __alloc_pages_bulk(gfp_t g
>   	gfp_t alloc_gfp;
>   	unsigned int alloc_flags = ALLOC_WMARK_LOW;
>   	int nr_populated = 0, nr_account = 0;
> +	LIST_HEAD(head);
>   
>   	if (unlikely(nr_pages <= 0))
>   		return 0;
> @@ -5308,17 +5309,29 @@ unsigned long __alloc_pages_bulk(gfp_t g
>   			break;
>   		}
>   		nr_account++;
> -
> -		prep_new_page(page, 0, gfp, 0);
> -		if (page_list)
> -			list_add(&page->lru, page_list);
> -		else
> -			page_array[nr_populated] = page;
> +		list_add(&page->lru, &head);
>   		nr_populated++;
>   	}
>   
>   	local_unlock_irqrestore(&pagesets.lock, flags);
>   
> +	list_for_each_entry(page, &head, lru)
> +		prep_new_page(page, 0, gfp, 0);
> +
> +	if (page_list)
> +		list_splice(&head, page_list);
> +	else {
> +		int i;
> +
> +		for (i = 0; i < nr_pages && !list_empty(&head); i++) {
> +			/* Skip existing pages */
> +			if (page_array[i])
> +				continue;
> +			page = list_first_entry(&head, struct page, lru);
> +			list_del_init(&page->lru);
> +			page_array[i] = page;
> +		}
> +	}
>   	__count_zid_vm_events(PGALLOC, zone_idx(zone), nr_account);
>   	zone_statistics(ac.preferred_zoneref->zone, zone, nr_account);
>   
> 

I believe this particular bug should be fixed by Mel Gorman's patch that 
was added into Andrew Morton's -mm tree (mm/page_alloc: Avoid page 
allocator recursion with pagesets.lock held):
https://lore.kernel.org/lkml/20210708081434.GV3840@techsingularity.net/

With the patch, we avoid recursing into stack_depot_save while holding 
onto the local lock.

Best wishes,
Desmond

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/49b84cde-647d-c4ef-4eac-d99376bb600a%40gmail.com.
