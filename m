Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBUPST6FQMGQESFLE3UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 1283342D61D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 11:33:06 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id d11-20020a50cd4b000000b003da63711a8asf4615680edj.20
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 02:33:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634203985; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojdXl1yTIbxJ0MbDcAV1sWNF5wKNWh9gQLByorRB8TXXWvM7E6TCnNDxc857mz9Lxk
         AyIs1eLweDCWGAqVVy6BvDenQXwWTk8zmEOm+YeHAugGdpZeNP30Sz5C82BgVpJsf68u
         +lQMKie0Iupods3jthUDPcOTEJpRD5sq+V/wh0NDsxyjup7JrsmyTFZOCXL43sBPNrVw
         e0LAulE7WA/Hdxq19dVbQCbEvdLmb5AA55tO+qy8bLGxXXYDvEL/O7bgtaBuf4RCaFqg
         Mi6I1j9EAXmSxGmV0aGK2yp18n1YjTA7MzBtS6pOWSu1fz/tyK5K1ARowHZ1SMXHG5C5
         m1Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=x0XoE++bClCHJLtdc1/qHATjAMP70xyxuD+8BjT94v4=;
        b=zDE3HFF+5lFm+kpX6uW9BXsKp3/mqOIQ3FmNt9166fai4bcxFAEGoiivdnV0yn1wyr
         TM4MUYl3MBjzq5MeQDrdttor3Bh9daDSHufQozWI/YU12KtVZF9QdF/Kewfwy0xpFGcl
         e3R75yGG9606RjknXCQlf1ueBufa5Sm35sGnY9l4GiWa5e6qDl3MaR6W07nZwPOWUTA7
         11GpBbOC0BnVdaTthLviXdKHgfddE1yqUl32OoctBefxup26ehP0ljdpi75VVyoEHEAr
         3TdUo7FwdjALmnPFs1Nv3me1s5tFPn2XMOpcF/PCT3nglqZqIxuEewmbdxXryFsAB/0/
         3ZJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s1ut4apr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=X3pC7ItK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x0XoE++bClCHJLtdc1/qHATjAMP70xyxuD+8BjT94v4=;
        b=QSENrhLGyvATSI5jxAHVUG8D3JrkFJtX5yWj2DX9H4Z7VOBNNYobHGtMsIBekqGX+T
         6kz9sXAK2Y8YqMcGuMUc6EQzAthu2N6YBeO4hmnLZ/liqiAFIn/Z0tpGsPFjlYez7dvP
         de+XH2dVJ/5LjOPaPYUUOtCBhkiSyoeuw/Ishvz7g4uAgkXiORelofYG+WQt12Yh0tgh
         x5AAwcBGcAzDyvqzo+fAVWMOF6S4Pa3DXbqnkZf2NCUcl0CU6RBgZqBUUcCWKspoLsyZ
         42GP7j8coi35LQHSDt9A+Ei1yHsTuHq+rubKN3ewW4PP088LEbYFfc0Q9ENtRSTjsMv6
         //CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x0XoE++bClCHJLtdc1/qHATjAMP70xyxuD+8BjT94v4=;
        b=XvQAy/BZTrDCObV1I3urV/EWjV/7JDsEuG7eh9BF/Gg8WGUmdRTHbC0HH7Yl7/vs30
         Yjc96Mds2GUy8LYdjm7YHt4z34y5YRkCEacwZHHe+JnaObZwKOrw7XXq/v2uvNzHiQms
         IdSbDr7dv+EgPQ9nDhDPqccitC8mOntCT9NoZYztUqW9TRMhTknCxNXWFtXcWJcLIzVz
         ck6fYSMmpPM/zLynY7AG1r9UAkB7+r/XCwmsJGvXTvL7vy8IIv+MWmPxuqmKa3LTwN4G
         51643nKrr3VAL9iQ7Go4tkHjLTJQ/8pXCmnCAws+L4238JaQEekkADtIVaCY+YA6Goaf
         EBJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LGj4z4Lm6QUwilLxfTSxIDDKvzHbimn+sczducPhrPOxBKoYD
	u6UZC+xzVY8q9OBxmJyL9X0=
X-Google-Smtp-Source: ABdhPJyWZ50wdGaJsWv8HPddYFIVRKjK4cxFyBQADYvVRFGAfRBslqzCPgw06l4y8JLFR0kS5CNuBQ==
X-Received: by 2002:a17:906:919:: with SMTP id i25mr2482670ejd.171.1634203985754;
        Thu, 14 Oct 2021 02:33:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1484:: with SMTP id x4ls1727520ejc.1.gmail; Thu, 14
 Oct 2021 02:33:04 -0700 (PDT)
X-Received: by 2002:a17:906:8242:: with SMTP id f2mr2450885ejx.510.1634203984726;
        Thu, 14 Oct 2021 02:33:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634203984; cv=none;
        d=google.com; s=arc-20160816;
        b=bvR9C877P11nWzAKDlvIehVzLOfzB2IUkdauMDPvs2KV0A0tln+zd5Bgelu/7jYk4M
         9mYQpuIM2H+D5f9vThmX6qwuGxv+s9OphWQJrnJO7+5Yd6EjnYL2lVkz0sQGoS0cH7sU
         d04jAH/5y2ZDMIsoEVnrOG5G/Jw/EhY0kMJZPg341OkdcBS0SOLNtpADGtJC5bYOR0vj
         oOSvpdBlbc6+R9EHErWs36ytj2q3v6wDmuuMz9XMRDpqTZp03o7xFarmsxoZMj6ADVbB
         DaFdnbm51M9McoCvOIX/4O+28T5kEFOTV0MGj8WMrV522kk6KB+okTB4qiUwjgso4byQ
         ecWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=2760sGFl5oJpeELLEsVmFeL7VhzN7ZXzcDPL7h4xml4=;
        b=Kwgqe67j8WkJ4MSKJKOm6VWdV5ep3tRTJpqZddIK75A7EizBAVeXdTDuSTLEkQlaTF
         RGTnObRa8TmCzGIXILjAfkqPGUwNEW6cZGJgq/KpQCSRK9aUMDLxYEzTd4ZCu24LkT3b
         MdqFBqht8bOu2b3rf7Mi3LZ/cg7ml9qW2yALGhsUKOjaYfZJxCGxLlmQRiJivxo5msSI
         4kZMKeoUR5jV4Z7s0ahk1zjo5DXwDK1bVwuLWM9LdCVPqgah4NYMwxm3g+9n4U8UPZIA
         c5udU73TndBYkuOEEXfAUI5xtzBhQyOfW2pnZ/bZTrNSrKSqwriJL04ajwoArWl44A8E
         T+Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=s1ut4apr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=X3pC7ItK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id o25si143060eju.1.2021.10.14.02.33.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Oct 2021 02:33:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4C2F01F782;
	Thu, 14 Oct 2021 09:33:04 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id EA76113D7C;
	Thu, 14 Oct 2021 09:33:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id gCdsOE/5Z2HaXgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 14 Oct 2021 09:33:03 +0000
Message-ID: <4d99add1-5cf7-c608-a131-18959b85e5dc@suse.cz>
Date: Thu, 14 Oct 2021 11:33:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>
Cc: 0day robot <lkp@intel.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta
 <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>,
 LKML <linux-kernel@vger.kernel.org>, lkp@lists.01.org,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 kasan-dev@googlegroups.com, Mike Rapoport <rppt@kernel.org>
References: <20211014085450.GC18719@xsang-OptiPlex-9020>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [lib/stackdepot] 1cd8ce52c5:
 BUG:unable_to_handle_page_fault_for_address
In-Reply-To: <20211014085450.GC18719@xsang-OptiPlex-9020>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=s1ut4apr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=X3pC7ItK;
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

On 10/14/21 10:54, kernel test robot wrote:
> 
> 
> Greeting,
> 
> FYI, we noticed the following commit (built with gcc-9):
> 
> commit: 1cd8ce52c520c26c513899fb5aee42b8e5f60d0d ("[PATCH v2] lib/stackdepot: allow optional init and stack_table allocation by kvmalloc()")
> url: https://github.com/0day-ci/linux/commits/Vlastimil-Babka/lib-stackdepot-allow-optional-init-and-stack_table-allocation-by-kvmalloc/20211012-170816
> base: git://anongit.freedesktop.org/drm-intel for-linux-next
> 
> in testcase: rcutorture
> version: 
> with following parameters:
> 
> 	runtime: 300s
> 	test: cpuhotplug
> 	torture_type: srcud
> 
> test-description: rcutorture is rcutorture kernel module load/unload test.
> test-url: https://www.kernel.org/doc/Documentation/RCU/torture.txt
> 
> 
> on test machine: qemu-system-i386 -enable-kvm -cpu SandyBridge -smp 2 -m 4G
> 
> caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> 
> 
> +---------------------------------------------+------------+------------+
> |                                             | a94a6d76c9 | 1cd8ce52c5 |
> +---------------------------------------------+------------+------------+
> | boot_successes                              | 30         | 0          |
> | boot_failures                               | 0          | 7          |
> | BUG:kernel_NULL_pointer_dereference,address | 0          | 2          |
> | Oops:#[##]                                  | 0          | 7          |
> | EIP:stack_depot_save                        | 0          | 7          |
> | Kernel_panic-not_syncing:Fatal_exception    | 0          | 7          |
> | BUG:unable_to_handle_page_fault_for_address | 0          | 5          |
> +---------------------------------------------+------------+------------+
> 
> 
> If you fix the issue, kindly add following tag
> Reported-by: kernel test robot <oliver.sang@intel.com>
> 
> 
> 
> [  319.147926][  T259] BUG: unable to handle page fault for address: 0ec74110
> [  319.149309][  T259] #PF: supervisor read access in kernel mode
> [  319.150362][  T259] #PF: error_code(0x0000) - not-present page
> [  319.151372][  T259] *pde = 00000000
> [  319.151964][  T259] Oops: 0000 [#1] SMP
> [  319.152617][  T259] CPU: 0 PID: 259 Comm: systemd-rc-loca Not tainted 5.15.0-rc1-00270-g1cd8ce52c520 #1
> [  319.154514][  T259] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> [  319.156200][  T259] EIP: stack_depot_save+0x12a/0x4d0


Cc Mike Rapoport, looks like:
- memblock_alloc() should have failed (I think, because page allocator
  already took over?), but didn't. So apparently we got some area that wasn't
  fully mapped.
- using slab_is_available() is not accurate enough to detect when to use
memblock or page allocator (kvmalloc in case of my patch). I have used it
because memblock_alloc_internal() checks the same condition to issue a warning.

Relevant part of dmesg.xz that was attached:
[    1.589075][    T0] Dentry cache hash table entries: 524288 (order: 9, 2097152 bytes, linear)
[    1.592396][    T0] Inode-cache hash table entries: 262144 (order: 8, 1048576 bytes, linear)
[    2.916844][    T0] allocated 31496920 bytes of page_ext

- this means we were allocating from page allocator by alloc_pages_exact_nid() already

[    2.918197][    T0] mem auto-init: stack:off, heap alloc:off, heap free:on
[    2.919683][    T0] mem auto-init: clearing system memory may take some time...
[    2.921239][    T0] Initializing HighMem for node 0 (000b67fe:000bffe0)
[   23.023619][    T0] Initializing Movable for node 0 (00000000:00000000)
[  245.194520][    T0] Checking if this processor honours the WP bit even in supervisor mode...Ok.
[  245.196847][    T0] Memory: 2914460K/3145208K available (20645K kernel code, 5953K rwdata, 12624K rodata, 760K init, 8112K bss, 230748K reserved, 0K cma-reserved, 155528K highmem)
[  245.200521][    T0] Stack Depot allocating hash table with memblock_alloc

- initializing stack depot as part of initializing page_owner, uses memblock_alloc()
  because slab_is_available() is still false

[  245.212005][    T0] Node 0, zone   Normal: page owner found early allocated 0 pages
[  245.213867][    T0] Node 0, zone  HighMem: page owner found early allocated 0 pages
[  245.216126][    T0] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=2, Nodes=1

- printed by slub's kmem_cache_init() after create_kmalloc_caches() setting slab_state
  to UP, making slab_is_available() true, but too late

In my local testing of the patch, when stackdepot was initialized through
page owner init, it was using kvmalloc() so slab_is_available() was true.
Looks like the exact order of slab vs page_owner alloc is non-deterministic,
could be arch-dependent or just random ordering of init calls. A wrong order
will exploit the apparent fact that slab_is_available() is not a good
indicator of using memblock vs page allocator, and we would need a better one.
Thoughts?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d99add1-5cf7-c608-a131-18959b85e5dc%40suse.cz.
