Return-Path: <kasan-dev+bncBDOY5FWKT4KRBHUHUCFQMGQE77SRO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id A78BF42D6DA
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 12:17:03 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id 104-20020ab00471000000b002c9e0baf2e2sf2726900uav.9
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 03:17:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634206622; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDS1hJ/8VmiZKvZwjarqBjdaDvik6bA0czg4jx5YSk4XhxK0Pu0zT9vUxYtHxAEyeS
         UH3ooTM8OYcUIFuR2JvYvNSMpsuHe4QC0gAu5x7TCrDPycMm+gdyJ/6d90haqGalRi2A
         uBFCpTq0WAFgje6XnLTcFzjdXbA6gszG6VDYfKo5kqRDkS/lBLXanoNnwc1xPhK74rM2
         Dz6ZmtoDIyGauEYEMSlNPxzu4ZahS8IzE6Roaqi9gMj52hN5rD0yOmCKaxeR5g3zM4Tq
         WO7LmOwRjWFhYXCdIvEqyUrVoOeneSGRpVpRNktNywQNCNfD4EQgYU/Qtgyq1lGTnDG5
         9aww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vdJf4GROqLpHDuOQ2MrMz8q+OOkMY2noy8EVUyVv8GQ=;
        b=ifB++gf5RecEjOpXypNb5tSFLlMb2n7BIVugPYebRWcRz3x64oCvd5CCCx9qrZVC1q
         WBdYTDOuXcHKjMijHfB/+9DZfADkJ0JliaLVTWKYoBCxshfMD6zjfAG0q88JKKCONDan
         PhdZ+iGw7QQV0eIQ30OEgjG/Jrc7Fdsjr9Blv/3DYaH0dl+BIggysWUG4dRR8p8zAifH
         cE/l34GLhhvMBVoFWchLidyMnKfirSkAWb4KNkoEVZB6osq80eJB0MzFeAJNSgSwZXma
         DBaEh5WoVy/sguapNodCNM9OkLROA9jwUnFPRwweHCkf3W6hTS7lmrMEJgSmvAMUmKK+
         L32Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NhOD9vih;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vdJf4GROqLpHDuOQ2MrMz8q+OOkMY2noy8EVUyVv8GQ=;
        b=eMcfHE6S9n2mqW0X9of3cCtq1sUvIWzR1O1Dtp/loOUE0XvzyqBl9Hm3yp/BBob0rA
         CGlYb4Atf5LHN4VKaYkhwF3rK8rxa67aH+gtpkJwKw6X5MJtpDg5qx+9Y+JRWTjdKcVg
         4Ni5Z+HaXSrqB521htdLsr7LzyaMwnVtnjv6yOFcEm2HvS/wt9t4E+TGzBDiqeSOSh10
         Cxp8ycciQ0sEbmbbShQ3ldfY29gKQZ68edBpXYmZdWbAOWrhea+qjJ9deAeHRoIg8laV
         Vye8jMDHb+lkZdK361caG5TlGvHGDWQ6beKXGNh+YPPy4x3FujJqsw9xkhGoWdmYFH4R
         NLlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vdJf4GROqLpHDuOQ2MrMz8q+OOkMY2noy8EVUyVv8GQ=;
        b=yorsWVZ2My2p+ngRBU9QdTR+RAzZpIrRnxPuLhF9hTIQc2CIXbLanwz/heK2/KXhfX
         voVl8JYy3h/Sbo48nGtfue6mivIBAlzt2Wa48SG7Pnz6xDftSgOyncA9UBSdh/MDcVLU
         3mwIdfQGdQgOYuPOa8T68QRCDRax2SkiVQzFblCaBJAlBKnoR5PXjO56mW6pMN5Rp3G2
         PTzGiojoYggwS8QjtW+ffrg/Bf4ua2cQBZYkqjMYNVNmjJCq53qeWDfdL2Sl2KUOzymM
         VQEFMCBAKWUjE0Ygvud8LToOyLRPpE5rLx1Vvcri9ezswIegk9cmvRlD5b3o4AJXWg3+
         d3WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QK9Djy6Z16a/sg8jcicpF1PEDglaUxyD9A6t54LFlwxqYUs88
	Wv4TquCG5s8t+Soo6yBwB1s=
X-Google-Smtp-Source: ABdhPJwvrxau8XwosbQivKcEcKGW8g+U2OMhT7BE1XxLEqj7yCRfLmOOI6gx6o9I2S6F7eVI9Rm6gg==
X-Received: by 2002:ac5:cbcf:: with SMTP id h15mr4785142vkn.0.1634206622405;
        Thu, 14 Oct 2021 03:17:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d81a:: with SMTP id e26ls1779566vsj.3.gmail; Thu, 14 Oct
 2021 03:17:01 -0700 (PDT)
X-Received: by 2002:a05:6102:e87:: with SMTP id l7mr5744556vst.56.1634206621865;
        Thu, 14 Oct 2021 03:17:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634206621; cv=none;
        d=google.com; s=arc-20160816;
        b=wZxNIz0oQFLZ8IGJdspEFQiBKv0XYB2jxNSxYf5oHdYOGbeGn6yZ0HRv64um4ETd+3
         f+6jCkBoVOj6QaLIJ5VE2TtBj5mkJdgSTAaP+3kvmrprnrjI35nuNGjKA3W3Iv0fTJdX
         hPLWxrLkStiwukwjPd3gSvZTeWAomedaQ8zO6W42dHZQRJVYPCsIsakGlaq6JctPinu3
         r5IN4C9+BDlaSamcGFW8EXHB33cAJGeGMd4kuRwmut0dX6yujgCJVwsr+ntEZ5cfKyRv
         d0SU2BU0shWEYS4f7Iir6h+cgGLH5QTBP+tLEfq60EpmU7MxxihUszrSzmB8lWyIoVVW
         yPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FdLsF8li5auFUEtFrNkFV6k7aRz5asF7CPC7ov8J9WQ=;
        b=eNmBD6VvgDowDVD9hSyaaqOZSMFejdzAq9cIWOnKYeFOKuFeIgGBPv3a4eBAXBIM8f
         q1JOd/Q7EA0DJL5Lsm9E4a39NbyndyWfAVFHulF2C/lc3fcqsAszbG3K6WowySxRJV4j
         WHXo4F7wgEuLeNrxiT8AMi3auxtm+xPC8UgbcLCEorEDdUI1X9nYnHWm13R42tPheJ7p
         X68tHanhWApqWjKznBVh81m3V+6Pf+BMvtDM96q0d4oMNAc3p40n8ThWQ7r6LeGLwmcd
         76fQBS8TAGWnXILOOFImyMAXAidLrhqVqL7MtY/ff9vDsAZEHLGG3XlTfQn+AeebA1o2
         CL4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NhOD9vih;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h82si159222vke.1.2021.10.14.03.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Oct 2021 03:17:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F1CC1610E8;
	Thu, 14 Oct 2021 10:16:54 +0000 (UTC)
Date: Thu, 14 Oct 2021 13:16:50 +0300
From: Mike Rapoport <rppt@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <oliver.sang@intel.com>, 0day robot <lkp@intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Oliver Glitta <glittao@gmail.com>,
	Imran Khan <imran.f.khan@oracle.com>,
	LKML <linux-kernel@vger.kernel.org>, lkp@lists.01.org,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
	kasan-dev@googlegroups.com
Subject: Re: [lib/stackdepot] 1cd8ce52c5:
 BUG:unable_to_handle_page_fault_for_address
Message-ID: <YWgDkjqtJO4e3DM6@kernel.org>
References: <20211014085450.GC18719@xsang-OptiPlex-9020>
 <4d99add1-5cf7-c608-a131-18959b85e5dc@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4d99add1-5cf7-c608-a131-18959b85e5dc@suse.cz>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NhOD9vih;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Oct 14, 2021 at 11:33:03AM +0200, Vlastimil Babka wrote:
> On 10/14/21 10:54, kernel test robot wrote:
> > 
> > 
> > Greeting,
> > 
> > FYI, we noticed the following commit (built with gcc-9):
> > 
> > commit: 1cd8ce52c520c26c513899fb5aee42b8e5f60d0d ("[PATCH v2] lib/stackdepot: allow optional init and stack_table allocation by kvmalloc()")
> > url: https://github.com/0day-ci/linux/commits/Vlastimil-Babka/lib-stackdepot-allow-optional-init-and-stack_table-allocation-by-kvmalloc/20211012-170816
> > base: git://anongit.freedesktop.org/drm-intel for-linux-next
> > 
> > in testcase: rcutorture
> > version: 
> > with following parameters:
> > 
> > 	runtime: 300s
> > 	test: cpuhotplug
> > 	torture_type: srcud
> > 
> > test-description: rcutorture is rcutorture kernel module load/unload test.
> > test-url: https://www.kernel.org/doc/Documentation/RCU/torture.txt
> > 
> > 
> > on test machine: qemu-system-i386 -enable-kvm -cpu SandyBridge -smp 2 -m 4G
> > 
> > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > 
> > 
> > +---------------------------------------------+------------+------------+
> > |                                             | a94a6d76c9 | 1cd8ce52c5 |
> > +---------------------------------------------+------------+------------+
> > | boot_successes                              | 30         | 0          |
> > | boot_failures                               | 0          | 7          |
> > | BUG:kernel_NULL_pointer_dereference,address | 0          | 2          |
> > | Oops:#[##]                                  | 0          | 7          |
> > | EIP:stack_depot_save                        | 0          | 7          |
> > | Kernel_panic-not_syncing:Fatal_exception    | 0          | 7          |
> > | BUG:unable_to_handle_page_fault_for_address | 0          | 5          |
> > +---------------------------------------------+------------+------------+
> > 
> > 
> > If you fix the issue, kindly add following tag
> > Reported-by: kernel test robot <oliver.sang@intel.com>
> > 
> > 
> > 
> > [  319.147926][  T259] BUG: unable to handle page fault for address: 0ec74110
> > [  319.149309][  T259] #PF: supervisor read access in kernel mode
> > [  319.150362][  T259] #PF: error_code(0x0000) - not-present page
> > [  319.151372][  T259] *pde = 00000000
> > [  319.151964][  T259] Oops: 0000 [#1] SMP
> > [  319.152617][  T259] CPU: 0 PID: 259 Comm: systemd-rc-loca Not tainted 5.15.0-rc1-00270-g1cd8ce52c520 #1
> > [  319.154514][  T259] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> > [  319.156200][  T259] EIP: stack_depot_save+0x12a/0x4d0
> 
> 
> Cc Mike Rapoport, looks like:
> - memblock_alloc() should have failed (I think, because page allocator
>   already took over?), but didn't. So apparently we got some area that wasn't
>   fully mapped.
> - using slab_is_available() is not accurate enough to detect when to use
> memblock or page allocator (kvmalloc in case of my patch). I have used it
> because memblock_alloc_internal() checks the same condition to issue a warning.
> 
> Relevant part of dmesg.xz that was attached:
> [    1.589075][    T0] Dentry cache hash table entries: 524288 (order: 9, 2097152 bytes, linear)
> [    1.592396][    T0] Inode-cache hash table entries: 262144 (order: 8, 1048576 bytes, linear)
> [    2.916844][    T0] allocated 31496920 bytes of page_ext
> 
> - this means we were allocating from page allocator by alloc_pages_exact_nid() already
> 
> [    2.918197][    T0] mem auto-init: stack:off, heap alloc:off, heap free:on
> [    2.919683][    T0] mem auto-init: clearing system memory may take some time...
> [    2.921239][    T0] Initializing HighMem for node 0 (000b67fe:000bffe0)
> [   23.023619][    T0] Initializing Movable for node 0 (00000000:00000000)
> [  245.194520][    T0] Checking if this processor honours the WP bit even in supervisor mode...Ok.
> [  245.196847][    T0] Memory: 2914460K/3145208K available (20645K kernel code, 5953K rwdata, 12624K rodata, 760K init, 8112K bss, 230748K reserved, 0K cma-reserved, 155528K highmem)
> [  245.200521][    T0] Stack Depot allocating hash table with memblock_alloc
> 
> - initializing stack depot as part of initializing page_owner, uses memblock_alloc()
>   because slab_is_available() is still false
> 
> [  245.212005][    T0] Node 0, zone   Normal: page owner found early allocated 0 pages
> [  245.213867][    T0] Node 0, zone  HighMem: page owner found early allocated 0 pages
> [  245.216126][    T0] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=2, Nodes=1
> 
> - printed by slub's kmem_cache_init() after create_kmalloc_caches() setting slab_state
>   to UP, making slab_is_available() true, but too late
> 
> In my local testing of the patch, when stackdepot was initialized through
> page owner init, it was using kvmalloc() so slab_is_available() was true.
> Looks like the exact order of slab vs page_owner alloc is non-deterministic,
> could be arch-dependent or just random ordering of init calls. A wrong order
> will exploit the apparent fact that slab_is_available() is not a good
> indicator of using memblock vs page allocator, and we would need a better one.
> Thoughts?

The order of slab vs page_owner is deterministic, but it is different for
FLATMEM and SPARSEMEM. And page_ext_init_flatmem_late() that initializes
page_ext for FLATMEM is called exactly between buddy and slab setup:

static void __init mm_init(void)
{
	...

	mem_init();
	mem_init_print_info();
	/* page_owner must be initialized after buddy is ready */
	page_ext_init_flatmem_late();
	kmem_cache_init();

	...
}

I've stared for a while at page_ext init and it seems that the
page_ext_init_flatmem_late() can be simply dropped because there is anyway
a call to invoke_init_callbacks() in page_ext_init() that is called much
later in the boot process.

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWgDkjqtJO4e3DM6%40kernel.org.
