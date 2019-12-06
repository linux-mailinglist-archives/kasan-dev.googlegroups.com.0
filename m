Return-Path: <kasan-dev+bncBC5L5P75YUERBVUBVLXQKGQEYJBL3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 239F9115522
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2019 17:24:55 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id j13sf2057272ljc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2019 08:24:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575649494; cv=pass;
        d=google.com; s=arc-20160816;
        b=nqY776hpS2neh8CmNGO8ToQai6sm9FC6gs27KhkwC+XjXd2g2Q79hs+N9FNpFnRtUf
         L7ZaFjNc9Kmj1hE+/jeGT50kNEC5GZKAwASE4cBjziK3tihssXCUkssYhvDmiRt9UH3u
         4ktGy7fldO8ZHJi4Zpyg2lAYk6+B89y8j5ID2lSX/2JfyrCPzMdAhDd7rWhuFNIknJuu
         e36r4sX6Bd93z6AnP4u6gnSwFgyffCVfedj1ZcgXlsMEv9xWRlo8Y9WiFpzAG/QuEFac
         EDKIC4hux7idfdI1/nt4YsSzWgbqitjoPO2RP0Lkmk0+bT9Grx1zunfRwnlNsS/CQxKG
         REDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=S29dZwuEB1jNKZRgF55gZZ/u2bYand47S7brBSjxe/4=;
        b=k6k1MNp9tA1cwHcgTsdpv1ibrsIoYxmXE3q+p4cpxUW4CCBAJcljbdQL6nAdwVQEYy
         T7rhh6SY8S6rTS4mFN7LXq6j07RRWHiFBO6h382w83mpcVSxw5OyucqxOE64yguYYaUP
         r+XcfJJQZb0a0uHv4rxi5ixeZM/XFgUxgNm1obV/XT7FvYcdk71grgae8KcGkDZ5jlU5
         8rYTLfX7fWW3dQaBVASyV6AzLelKrpQ3XYI79sS/dnltp257vr2ciNUb6vHxvJy5plqu
         tQ1fICjz+OBymtHVNaZc5pKE6PttOw4Zgq9nWuidg2Bp/JXaIQB/iWemSJfBQNPzKCs1
         FWzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S29dZwuEB1jNKZRgF55gZZ/u2bYand47S7brBSjxe/4=;
        b=npwVagYJ3/+z0Psx0tiqoQ9Kaa2YNr1aWF9CPVzg6NbYhm/fSzzyaRtZ5P9Gp7nIfP
         jv59S5OWVt/Tk8CcNttwuebIpN1EOXG+gPti2maCLQQImwSwcp9nC0cebNRPi3Nu5Hdg
         PO2KGAFlEDv1HShsHUqd+0xNy50FzQt0mvYtLwCaXno5qgvnxb8lAyxdtKuRVFCLRFCP
         xlRn0KH1a6vP5hesLJUaXtvFNUEzT8oDh9H5Dm2fsJ5fJXWEkb+3HXuQ9wgkwcgO1l/h
         6XjArdA6P35di3uq0s+TL9JHgPF0mLfoxNEX7Tso7FY98Crn7p/K5G9OcUkicMTjfsCb
         WByA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S29dZwuEB1jNKZRgF55gZZ/u2bYand47S7brBSjxe/4=;
        b=TNXhQaDREdOCKLmLIni281ry/UNAJs3E1jUF24AKmjtk3QqpqDfk2FkqNrz/xRY6Vc
         /KO027gxd2EQwfrTcbCkofgOi/Wk2e/QtT005Gp3It4abdTyRmvqMc6vYQbIy/rScGL/
         3JqqnmuWnw/hiKA4aBPmyDTXhbplUReM6ZSdTYfMWx4WbrlwtGTkwt5ukEVA8tbiLy/a
         ZNefPU40fUOlsF8CujngtHxIZstdgitkMqiQFNadn4zQ0bxoyGP9/cxGckm8LjVhrYru
         iFTh10W+YZKa40NuA1AP8MGjUficnq0vPxfECQ0v89qlk0yy5jr2Javak2Spcn7EXxus
         JyRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUW5fABwzdBTJRkeL4g3k7lYx1WpTVIG1jC1EqWYcDU9JzVgenx
	0ZGPzL+2UcOf0ufn14JP114=
X-Google-Smtp-Source: APXvYqzHjLIVtHUXmkC1+HYj+gbNHNAnyJDRiiLw2llBNU5VzY1mjIMBC/uBrjMLK4axpnLpJ88Cmw==
X-Received: by 2002:ac2:59dc:: with SMTP id x28mr8665135lfn.38.1575649494708;
        Fri, 06 Dec 2019 08:24:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:95c7:: with SMTP id y7ls1080509ljh.16.gmail; Fri, 06 Dec
 2019 08:24:54 -0800 (PST)
X-Received: by 2002:a05:651c:1a2:: with SMTP id c2mr9171500ljn.121.1575649494299;
        Fri, 06 Dec 2019 08:24:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575649494; cv=none;
        d=google.com; s=arc-20160816;
        b=zrSJVINEcQLQPeHjiBD12pDRUJg4HJgftL5j+uWifN36nWFYTD4N2uw/K2kXM0sMLc
         CXcheAFKmdwG3PuQ2jQ+fY6IBncH6U2eYceYKzNiSazL2nEBixE93zg3kEVlTpkhY/0I
         E1MUn+YLMlmamDtm3tR4sdWg4n+l/Dyd2pYIO+oHm+27ZlzYwqPU38fk7+NycPWQO2sr
         P7Z2mYEzlR3C+5sFJwErhTh/jw3q8tE7iKPbTXcgjBUYX1cg8wd+Bx5xTgyRYE+1t+uJ
         Sr74airYTTmPO1CfHSd23KHHnM/AV959kMfCS7pDlT/1yBisMRIErHy+FTWCWrZ7o6Ma
         Gndw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=AWw4Xjt8a29u0rO0vt8kjAsINuRJNvUqCfjRV3dOqIw=;
        b=FdudkuZVBVR8agKIay/BHRPvNF+jrkECDlgQRGJJSOcQxfCjFavAzYsqYa4HeVwa72
         dSO/CCPOP/SrNfhFugPprx2/3gVE1Xi8NkPUPQ+XvARUx/eIVfr38+mY0NHmiJwa94sb
         Pp94m4Cdc4sNSilDbls11U8XhcPcL3wTSrKi+rJobyF5MII1k6IQbhF5PvxuTsMpU2+h
         3rvf40pXGX+K5qQy25E83RVwkdfIHx7Maivh9mVpF6eYT5nMA79LmOWkkRmqMOQjD75w
         9IwsAhrUZD8LJw8o+KLoS/hm6405CS+ib77nZtb4dn0pn9ipMUVrJgF0zD9vriKK/BtA
         94aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id o24si1134499lji.4.2019.12.06.08.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Dec 2019 08:24:54 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1idGPM-00009W-8m; Fri, 06 Dec 2019 19:24:44 +0300
Subject: Re: [PATCH 2/3] kasan: use apply_to_existing_pages for releasing
 vmalloc shadow
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, glider@google.com, linux-kernel@vger.kernel.org,
 dvyukov@google.com
Cc: daniel@iogearbox.net, cai@lca.pw,
 Andrew Morton <akpm@linux-foundation.org>
References: <20191205140407.1874-1-dja@axtens.net>
 <20191205140407.1874-2-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <d3c4ae49-79d3-3641-947f-52926ffe877c@virtuozzo.com>
Date: Fri, 6 Dec 2019 19:24:28 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20191205140407.1874-2-dja@axtens.net>
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



On 12/5/19 5:04 PM, Daniel Axtens wrote:
> kasan_release_vmalloc uses apply_to_page_range to release vmalloc
> shadow. Unfortunately, apply_to_page_range can allocate memory to
> fill in page table entries, which is not what we want.
> 
> Also, kasan_release_vmalloc is called under free_vmap_area_lock,
> so if apply_to_page_range does allocate memory, we get a sleep in
> atomic bug:
> 
> 	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> 	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:
> 
> 	Call Trace:
> 	 __dump_stack lib/dump_stack.c:77 [inline]
> 	 dump_stack+0x199/0x216 lib/dump_stack.c:118
> 	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
> 	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
> 	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
> 	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
> 	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
> 	 alloc_pages include/linux/gfp.h:532 [inline]
> 	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
> 	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
> 	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
> 	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
> 	 apply_to_pte_range mm/memory.c:2031 [inline]
> 	 apply_to_pmd_range mm/memory.c:2068 [inline]
> 	 apply_to_pud_range mm/memory.c:2088 [inline]
> 	 apply_to_p4d_range mm/memory.c:2108 [inline]
> 	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
> 	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
> 	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
> 	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
> 	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
> 	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
> 	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
> 	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
> 	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
> 	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
> 	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
> 	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
> 	 __vmalloc_node mm/vmalloc.c:2607 [inline]
> 	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
> 	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
> 	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
> 	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
> 	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
> 	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
> 	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
> 	 __do_sys_setsockopt net/socket.c:2133 [inline]
> 	 __se_sys_setsockopt net/socket.c:2130 [inline]
> 	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
> 	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
> 	 entry_SYSCALL_64_after_hwframe+0x49/0xbe
> 
> Switch to using the apply_to_existing_pages helper instead, which
> won't allocate memory.
> 
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> 
> ---
> 
> Andrew, if you want to take this, it replaces
> "kasan: Don't allocate page tables in kasan_release_vmalloc()"
> ---
>  mm/kasan/common.c | 8 +++++---
>  1 file changed, 5 insertions(+), 3 deletions(-)
> 


Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d3c4ae49-79d3-3641-947f-52926ffe877c%40virtuozzo.com.
