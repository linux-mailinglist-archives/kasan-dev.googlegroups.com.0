Return-Path: <kasan-dev+bncBCRKFI7J2AJRBN5WQ2UAMGQEXKA2RLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 59D2379E67E
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 13:21:29 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1bde8160fbdsf86479965ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 04:21:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694604087; cv=pass;
        d=google.com; s=arc-20160816;
        b=MYLrcZk4K6p60VSViLm5qaW0OhdWPUEFtnvAtXjOa/daYXGXUL9szR1YsWg4dqPste
         lbZT4SBnt9ODx38Z++KhoOXtk43JIX5E+GpO0HYj6uNEWQn4c1c40h1PGcmg5SH9aOxc
         QovLn52tq8xHImB4vpDeJ9p3ToKe+1dkcwbC7O1xhAP+p2O9REkummqc5VGRkLTRM+Yn
         RrBhZ9ohl0Mp79vTYXjZFKhbA4Bs33zwyqMYpa0dgs1fsJnNyGZFEHHOvXnEzGHcctZ/
         yYR1xJpzhXyHaQf9zYHWkpD4JojwyrVXFdv+iKV8yUhy1R5UBXiU5xT24xR9aEXw1zSc
         wazQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=YdREAM3DzyUKuSIwtHHM/RYmIFAlH6z8gXcxm351T+o=;
        fh=Qok9FOh5GlsptsRIGj0dxcIldnGIzJkwUNWDBdW72Bc=;
        b=iZcC6o1gR7iPVCG6Cl9kQelTjDsEpvcCTHLkkHS0GJQaY2bGbUZxZ/D2Ff8i18TA4b
         jssAfxvcTncwiI8EGScDK3Bw41K3U+bqIhbpnr2v/IDfdHk4BBMOOpbrqm2Fzy1PYUPW
         eT1se4J38vOVU9ewkB7MoXX4l6uF0BzH294R+iDitmYeMEvcClehlJ7JdBVpaGjR4jwK
         Rfk9ai5EDX3ztN3YsOjgKvH31fUlwH3+2H5Se7uJ479ns8ldpwW/+zIHY8D/9ukTc43n
         wsuNTbeBCILSXTs3+etR6MQmMESAmvbizOpLAo//t5k2ZgHGHyFRdmFAooojVcxdS1JV
         W9ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694604087; x=1695208887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YdREAM3DzyUKuSIwtHHM/RYmIFAlH6z8gXcxm351T+o=;
        b=HPMLVSdS8XBwYSMTBi3kARg+odf383I11hmT8dLwWq5wjzuIay/TZaRMz2TdkCzTlI
         PSpyj+Ub2KufZGUGIu4+lMph4hnPAPc22Xmo8wJ/u+6xe7d6lFt3szCASNqz+Mj5BcNh
         CxLso1sz/WzvYMOr3z4gZHDPy+/Z9WLIic3SUP1R1SYHouQK7bZQSSCm+dI1UgVRr7ye
         7GvAJx84d95x7YncoaSqU2YPVWszZ3KGcUJseHeXtX7AYSUCYzqaCa8rUVfL8RrV0rvA
         CDvnRJwxwAxjB4zb/37u46aKs4dAbowLouT/RdqTdqcvuY2g3Eyr9y74L9fT29hnyVLF
         YtIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694604087; x=1695208887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YdREAM3DzyUKuSIwtHHM/RYmIFAlH6z8gXcxm351T+o=;
        b=eSl6sXlF4uURLDaxSkUsxgGGjBWUhKtWKutA5uUH6+fMRrOu2NnJuyTbXXZISM9J/w
         EwmgDak6sGaN9ga9QR6qjrORGgx8+ptl/mR2zBz6+xd9dqNs9smLB/6xRPkGO7+UNfZO
         FK82xKnkTdj4Pzd2CaC7J8WgkGVqRqbPOd2Ftq+c/1Y6qwTN4WBKAZXZJluSx3X8J2Kx
         /qddP+GoY7nOI558visTRhXUTj8Zf5MihRQvT82nPdmqimRuFFXBGVlTtGckkhrmWDNB
         SQmp9l5MHdUFfs2jI9y/c3OjWLF1OP4TF+CMOy/J0w3TIvZZz8VvfgTEzz0T7ljWRdWt
         qk5Q==
X-Gm-Message-State: AOJu0YxJyBo046bZDQ4IbLvITXCjRj2hW75bRTG0Sw9RvBIqS0W9Dr+n
	zAMscXyEzPryDIuizFaVBjw=
X-Google-Smtp-Source: AGHT+IEZ9cSjG6+mAsvfoxGK3BMrl3o8JdzFMM/wPpVcPTGOlXHfgFICY7Cnil3Z0osrZOjaceraYA==
X-Received: by 2002:a17:902:6b05:b0:1c3:8031:1dce with SMTP id o5-20020a1709026b0500b001c380311dcemr2158221plk.45.1694604087256;
        Wed, 13 Sep 2023 04:21:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:64c8:b0:1b6:8c9d:5961 with SMTP id
 y8-20020a17090264c800b001b68c9d5961ls3696607pli.2.-pod-prod-09-us; Wed, 13
 Sep 2023 04:21:26 -0700 (PDT)
X-Received: by 2002:a17:903:230e:b0:1b7:f64b:378a with SMTP id d14-20020a170903230e00b001b7f64b378amr2996313plh.16.1694604086179;
        Wed, 13 Sep 2023 04:21:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694604086; cv=none;
        d=google.com; s=arc-20160816;
        b=mHXJeR3x5IMAgO5+1b/+PUT4RY9NGdEHNhO6+BddGJo4wfk7LcIoMjzsjasRIGesgA
         qKPU8APhSVEN1Hfe91NwfQuLaYaQTAqeJHqzGu029Tg9IhxU7pnBKzHRXdkEj1kZUpq9
         sVkt2CatzGgJIn7+fVdaLLCpJKOb0OIspnU//Vc+OAv9jXc0fPJaySmgPSoF5tUnQQWF
         mCRwCUqUBsp6146ALfJiDU+qf0YRM+OZE046XeFv7mGd6GleMqQT4IOXaHHv99Shmnuo
         A1AbQgmSgTwwPaVO1tbsNKARRtoUEA0BZhQuiI66YDYdua05IUF/NvPIeDk6+FFHRh8g
         a0dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=9Tr3NRraVeXovf2garJ3t7x/7iJe0XQiP06vh8X4SBM=;
        fh=Qok9FOh5GlsptsRIGj0dxcIldnGIzJkwUNWDBdW72Bc=;
        b=ScbGu2jGgMUpCZoXSvazH8vRmLy8bgHXyH2fjGzjLnqIB7byo1z9xA2sGJnnGOuq8d
         d29QHC2hhJ2BJLO6Oszqc5kaIm34DQ9NRzFaK0ILRXY27SDv+G4V45OSDg+0rMdKmLF4
         x7jUe1SwmPrPH8tVycY1KS7nqm89oT0dhg3RW4xXFizR0Y3M5w78gIT2zqFnQdsbR8pp
         xiOzzwzKc1GL+tC5+s9AxGp0LDg+5OtwUqLiYzLvkQNl8jnrHVxHUHODGmBmCtK+q+Du
         Jzr2ntYksz69LlC34Q2ttT28GlDduZXOxz/mkcW4i53KL2qbH9JLSuXCMxnkrYObtyBd
         m2BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id t3-20020a170902e84300b001bba679925csi863422plg.1.2023.09.13.04.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Sep 2023 04:21:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4Rlydn45mJzrSWf;
	Wed, 13 Sep 2023 19:19:25 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Wed, 13 Sep 2023 19:21:22 +0800
Message-ID: <8181f70f-4e28-4bdf-83f6-3da36fb224e8@huawei.com>
Date: Wed, 13 Sep 2023 19:21:21 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock()
 in kasan_depopulate_vmalloc_pte()
Content-Language: en-US
To: kernel test robot <oliver.sang@intel.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>,
	Lorenzo Stoakes <lstoakes@gmail.com>
References: <202309131652.3e9c0f06-oliver.sang@intel.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <202309131652.3e9c0f06-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm100001.china.huawei.com (7.185.36.93)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

Hi, thanks for you test, but as the commit log of this patch,
it is a hack, I don't think this patch is correct, hope kasan maintainer
to give some advise about the softlock issue about populate/depopulate pte.

On 2023/9/13 16:48, kernel test robot wrote:
> 
> hi, Kefeng Wang,
> 
> we don't have enough knowledge to connect below random issues with your change,
> however, by running up to 300 times, we observed the parent keeps clean.
> so make out this report FYI.
> if you need more tests, please let us know. Thanks.
> 
> cb588b24f0fcf515 eaf065b089545219e27e529e3d6
> ---------------- ---------------------------
>         fail:runs  %reproduction    fail:runs
>             |             |             |
>             :300          6%          17:300   dmesg.BUG:#DF_stack_guard_page_was_hit_at#(stack_is#..#)
>             :300          0%           1:300   dmesg.BUG:#DF_stack_guard_page_was_hit_at(____ptrval____)(stack_is(____ptrval____)..(____ptrval____))
>             :300          6%          18:300   dmesg.BUG:KASAN:stack-out-of-bounds_in_vsnprintf
>             :300          6%          17:300   dmesg.BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)
>             :300          0%           1:300   dmesg.BUG:TASK_stack_guard_page_was_hit_at(____ptrval____)(stack_is(____ptrval____)..(____ptrval____))
>             :300          9%          28:300   dmesg.BUG:unable_to_handle_page_fault_for_address
>             :300          3%           8:300   dmesg.Kernel_panic-not_syncing:Fatal_exception
>             :300          7%          20:300   dmesg.Kernel_panic-not_syncing:Fatal_exception_in_interrupt
>             :300          3%          10:300   dmesg.Oops:#[##]
>             :300          6%          19:300   dmesg.RIP:__sanitizer_cov_trace_pc
>             :300          5%          14:300   dmesg.RIP:exc_page_fault
>             :300          6%          18:300   dmesg.WARNING:kernel_stack
>             :300          6%          18:300   dmesg.WARNING:stack_recursion
>             :300          6%          18:300   dmesg.stack_guard_page:#[##]
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)" on:
> 
> commit: eaf065b089545219e27e529e3d6deac4c0bad525 ("[PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock() in kasan_depopulate_vmalloc_pte()")
> url: https://github.com/intel-lab-lkp/linux/commits/Kefeng-Wang/mm-kasan-shadow-add-cond_resched-in-kasan_populate_vmalloc_pte/20230906-205407
> base: https://git.kernel.org/cgit/linux/kernel/git/akpm/mm.git mm-everything
> patch link: https://lore.kernel.org/all/20230906124234.134200-4-wangkefeng.wang@huawei.com/
> patch subject: [PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock() in kasan_depopulate_vmalloc_pte()
> 
> in testcase: rcuscale
> version:
> with following parameters:
> 
> 	runtime: 300s
> 	scale_type: srcud
> 
> 
> 
> compiler: gcc-9
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202309131652.3e9c0f06-oliver.sang@intel.com
> 
> 
> [  114.366291][    C1] BUG: TASK stack guard page was hit at 00000000d230e938 (stack is 000000004315c7ed..00000000e1c06e40)
> [  114.366312][    C1] stack guard page: 0000 [#1] SMP KASAN
> [  114.366324][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
> [  114.366338][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [ 114.366345][ C1] RIP: 0010:exc_page_fault (arch/x86/mm/fault.c:1518)
> [ 114.366365][ C1] Code: 89 ee e8 74 ca 7c fe 0f 1f 44 00 00 90 44 89 f6 4c 89 e7 e8 7d 0b 00 00 41 5c 41 5d 41 5e 5d c3 66 0f 1f 00 55 48 89 e5 41 57 <41> 56 41 55 49 89 f5 41 54 49 89 fc 0f 1f 44 00 00 41 0f 20 d6 65
> All code
> ========
>     0:	89 ee                	mov    %ebp,%esi
>     2:	e8 74 ca 7c fe       	callq  0xfffffffffe7cca7b
>     7:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
>     c:	90                   	nop
>     d:	44 89 f6             	mov    %r14d,%esi
>    10:	4c 89 e7             	mov    %r12,%rdi
>    13:	e8 7d 0b 00 00       	callq  0xb95
>    18:	41 5c                	pop    %r12
>    1a:	41 5d                	pop    %r13
>    1c:	41 5e                	pop    %r14
>    1e:	5d                   	pop    %rbp
>    1f:	c3                   	retq
>    20:	66 0f 1f 00          	nopw   (%rax)
>    24:	55                   	push   %rbp
>    25:	48 89 e5             	mov    %rsp,%rbp
>    28:	41 57                	push   %r15
>    2a:*	41 56                	push   %r14		<-- trapping instruction
>    2c:	41 55                	push   %r13
>    2e:	49 89 f5             	mov    %rsi,%r13
>    31:	41 54                	push   %r12
>    33:	49 89 fc             	mov    %rdi,%r12
>    36:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
>    3b:	41 0f 20 d6          	mov    %cr2,%r14
>    3f:	65                   	gs
> 
> Code starting with the faulting instruction
> ===========================================
>     0:	41 56                	push   %r14
>     2:	41 55                	push   %r13
>     4:	49 89 f5             	mov    %rsi,%r13
>     7:	41 54                	push   %r12
>     9:	49 89 fc             	mov    %rdi,%r12
>     c:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
>    11:	41 0f 20 d6          	mov    %cr2,%r14
>    15:	65                   	gs
> [  114.366375][    C1] RSP: 0000:ffffc90001388000 EFLAGS: 00210087
> [  114.366386][    C1] RAX: ffffc90001388018 RBX: 0000000000000000 RCX: ffffffff84801717
> [  114.366394][    C1] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffc90001388018
> [  114.366401][    C1] RBP: ffffc90001388008 R08: 0000000000000000 R09: 0000000000000000
> [  114.366409][    C1] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> [  114.366416][    C1] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> [  114.366423][    C1] FS:  0000000000000000(0000) GS:ffff8883af500000(0063) knlGS:00000000f516bb40
> [  114.366433][    C1] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
> [  114.366441][    C1] CR2: ffffc90001387ff8 CR3: 00000001bcfc9000 CR4: 00000000000406a0
> [  114.366451][    C1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> [  114.366459][    C1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> [  114.366466][    C1] Call Trace:
> [  114.366473][    C1] BUG: unable to handle page fault for address: fffff52000271002
> [  114.366479][    C1] #PF: supervisor read access in kernel mode
> [  114.366485][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366491][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366513][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366518][    C1] #PF: supervisor read access in kernel mode
> [  114.366524][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366529][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366549][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366554][    C1] #PF: supervisor read access in kernel mode
> [  114.366559][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366565][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366584][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366589][    C1] #PF: supervisor read access in kernel mode
> [  114.366595][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366600][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366620][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366625][    C1] #PF: supervisor read access in kernel mode
> [  114.366630][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366635][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366655][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366660][    C1] #PF: supervisor read access in kernel mode
> [  114.366666][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366671][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366691][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366695][    C1] #PF: supervisor read access in kernel mode
> [  114.366701][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366706][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366726][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366731][    C1] #PF: supervisor read access in kernel mode
> [  114.366736][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366741][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366761][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366766][    C1] #PF: supervisor read access in kernel mode
> [  114.366771][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366776][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366796][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366801][    C1] #PF: supervisor read access in kernel mode
> [  114.366807][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366811][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366831][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366836][    C1] #PF: supervisor read access in kernel mode
> [  114.366842][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366847][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366866][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366871][    C1] #PF: supervisor read access in kernel mode
> [  114.366877][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366882][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366902][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366907][    C1] #PF: supervisor read access in kernel mode
> [  114.366912][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366917][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366932][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366937][    C1] #PF: supervisor read access in kernel mode
> [  114.366942][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366947][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.366966][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.366971][    C1] #PF: supervisor read access in kernel mode
> [  114.366976][    C1] #PF: error_code(0x0000) - not-present page
> [  114.366981][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.367001][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.367006][    C1] #PF: supervisor read access in kernel mode
> [  114.367012][    C1] #PF: error_code(0x0000) - not-present page
> [  114.367016][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.367036][    C1] BUG: unable to handle page fault for address: fffff52000271000
> [  114.367042][    C1] #PF: supervisor read access in kernel mode
> [  114.367047][    C1] #PF: error_code(0x0000) - not-present page
> [  114.367052][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
> [  114.367075][    C1] BUG: #DF stack guard page was hit at 0000000071957a17 (stack is 00000000d15a2314..00000000d7ec09e2)
> [  114.367086][    C1] stack guard page: 0000 [#2] SMP KASAN
> [  114.367095][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
> [  114.367107][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [  114.367121][    C1] ==================================================================
> [ 114.367125][ C1] BUG: KASAN: stack-out-of-bounds in vsnprintf (lib/vsprintf.c:2851)
> [  114.367141][    C1] Read of size 8 at addr fffffe39ea66b3c0 by task systemd-journal/400
> [  114.367150][    C1]
> [  114.367153][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
> [  114.367165][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [  114.367172][    C1] Call Trace:
> [  114.367176][    C1]  <#DF>
> [ 114.367181][ C1] dump_stack_lvl (lib/dump_stack.c:107 (discriminator 4))
> [ 114.367197][ C1] print_address_description+0x7d/0x2ee
> [ 114.367219][ C1] print_report (mm/kasan/report.c:476)
> [ 114.367234][ C1] ? vsnprintf (lib/vsprintf.c:2851)
> [ 114.367248][ C1] ? kasan_addr_to_slab (mm/kasan/common.c:35)
> [ 114.367265][ C1] ? vsnprintf (lib/vsprintf.c:2851)
> [ 114.367278][ C1] kasan_report (mm/kasan/report.c:590)
> [ 114.367293][ C1] ? format_decode (lib/vsprintf.c:2526)
> [ 114.367308][ C1] ? vsnprintf (lib/vsprintf.c:2851)
> [ 114.367327][ C1] __asan_report_load8_noabort (mm/kasan/report_generic.c:381)
> [ 114.367346][ C1] vsnprintf (lib/vsprintf.c:2851)
> [ 114.367365][ C1] ? pointer (lib/vsprintf.c:2749)
> [ 114.367384][ C1] sprintf (lib/vsprintf.c:3017)
> [ 114.367399][ C1] ? snprintf (lib/vsprintf.c:3017)
> [ 114.367411][ C1] ? kallsyms_sym_address (kernel/kallsyms.c:164)
> [ 114.367426][ C1] ? kallsyms_expand_symbol+0x1f1/0x231
> [ 114.367443][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.367460][ C1] ? kallsyms_lookup_buildid (kernel/kallsyms.c:437)
> [ 114.367476][ C1] __sprint_symbol+0x15b/0x1ec
> [ 114.367491][ C1] ? kallsyms_lookup_buildid (kernel/kallsyms.c:482)
> [ 114.367504][ C1] ? page_fault_oops (arch/x86/mm/fault.c:699)
> [ 114.367516][ C1] ? fixup_exception (arch/x86/mm/extable.c:305)
> [ 114.367550][ C1] ? kernelmode_fixup_or_oops (arch/x86/mm/fault.c:761)
> [ 114.367566][ C1] ? __bad_area_nosemaphore (arch/x86/mm/fault.c:819)
> [ 114.367579][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.367597][ C1] sprint_symbol (kernel/kallsyms.c:536)
> [ 114.367609][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.367625][ C1] symbol_string (lib/vsprintf.c:1001)
> [ 114.367639][ C1] ? ip4_addr_string (lib/vsprintf.c:983)
> [ 114.367656][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:570)
> [ 114.367677][ C1] ? page_fault_oops (include/linux/sched/task_stack.h:31 arch/x86/mm/fault.c:699)
> [ 114.367689][ C1] ? page_fault_oops (arch/x86/mm/fault.c:699)
> [ 114.367706][ C1] ? dump_pagetable (arch/x86/mm/fault.c:635)
> [ 114.367718][ C1] ? search_extable (lib/extable.c:115)
> [ 114.367731][ C1] ? is_prefetch+0x36f/0x3b4
> [ 114.367745][ C1] ? spurious_kernel_fault_check (arch/x86/mm/fault.c:122)
> [ 114.367758][ C1] ? search_module_extables (arch/x86/include/asm/preempt.h:85 kernel/module/main.c:3236)
> [ 114.367775][ C1] ? widen_string (lib/vsprintf.c:618)
> [ 114.367792][ C1] ? widen_string (lib/vsprintf.c:618)
> [ 114.367805][ C1] ? set_precision (lib/vsprintf.c:618)
> [ 114.367824][ C1] ? string_nocheck (lib/vsprintf.c:640)
> [ 114.367838][ C1] ? number (lib/vsprintf.c:573)
> [ 114.367854][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.367872][ C1] pointer (lib/vsprintf.c:2416)
> [ 114.367887][ C1] ? va_format+0x1a1/0x1a1
> [ 114.367900][ C1] ? hex_string (lib/vsprintf.c:723)
> [ 114.367919][ C1] vsnprintf (lib/vsprintf.c:2822)
> [ 114.367937][ C1] ? pointer (lib/vsprintf.c:2749)
> [ 114.367952][ C1] ? kvm_sched_clock_read (arch/x86/kernel/kvmclock.c:91)
> [ 114.367966][ C1] ? sched_clock_noinstr (arch/x86/kernel/tsc.c:267)
> [ 114.367982][ C1] vprintk_store (kernel/printk/printk.c:2193)
> [ 114.367996][ C1] ? __kasan_check_write (mm/kasan/shadow.c:38)
> [ 114.368011][ C1] ? printk_sprint (kernel/printk/printk.c:2158)
> [ 114.368028][ C1] ? printk_sprint (kernel/printk/printk.c:2158)
> [ 114.368057][ C1] vprintk_emit (kernel/printk/printk.c:2290)
> [ 114.368074][ C1] vprintk_deferred (kernel/printk/printk.c:3911)
> [ 114.368089][ C1] vprintk (kernel/printk/printk_safe.c:42)
> [ 114.368104][ C1] _printk (kernel/printk/printk.c:2329)
> [ 114.368116][ C1] ? syslog_print (kernel/printk/printk.c:2329)
> [ 114.368127][ C1] ? vprintk (kernel/printk/printk_safe.c:46)
> [ 114.368143][ C1] ? syslog_print (kernel/printk/printk.c:2329)
> [ 114.368157][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.368175][ C1] show_ip (arch/x86/kernel/dumpstack.c:144)
> [ 114.368188][ C1] show_iret_regs (arch/x86/kernel/dumpstack.c:150)
> [ 114.368200][ C1] __show_regs (arch/x86/kernel/process_64.c:77)
> [ 114.368214][ C1] ? dump_stack_print_info (lib/dump_stack.c:71)
> [ 114.368231][ C1] show_regs (arch/x86/kernel/dumpstack.c:477)
> [ 114.368243][ C1] __die_body (arch/x86/kernel/dumpstack.c:421)
> [ 114.368256][ C1] __die (arch/x86/kernel/dumpstack.c:435)
> [ 114.368268][ C1] die (arch/x86/kernel/dumpstack.c:448)
> [ 114.368280][ C1] handle_stack_overflow (arch/x86/kernel/traps.c:327)
> [ 114.368298][ C1] exc_double_fault (arch/x86/kernel/traps.c:464)
> [ 114.368315][ C1] asm_exc_double_fault (arch/x86/include/asm/idtentry.h:611)
> [ 114.368329][ C1] RIP: 0010:__sanitizer_cov_trace_pc (kernel/kcov.c:200)
> [ 114.368347][ C1] Code: 00 00 48 c1 e6 38 48 21 fe 74 12 b8 01 00 00 00 48 c1 e0 38 48 39 c6 b0 00 0f 44 c2 c3 85 ff 0f 44 c1 c3 31 c0 c3 f3 0f 1e fa <55> 65 8b 05 6e 52 f0 7c 89 c1 48 89 e5 81 e1 00 01 00 00 48 8b 75
> All code
> ========
>     0:	00 00                	add    %al,(%rax)
>     2:	48 c1 e6 38          	shl    $0x38,%rsi
>     6:	48 21 fe             	and    %rdi,%rsi
>     9:	74 12                	je     0x1d
>     b:	b8 01 00 00 00       	mov    $0x1,%eax
>    10:	48 c1 e0 38          	shl    $0x38,%rax
>    14:	48 39 c6             	cmp    %rax,%rsi
>    17:	b0 00                	mov    $0x0,%al
>    19:	0f 44 c2             	cmove  %edx,%eax
>    1c:	c3                   	retq
>    1d:	85 ff                	test   %edi,%edi
>    1f:	0f 44 c1             	cmove  %ecx,%eax
>    22:	c3                   	retq
>    23:	31 c0                	xor    %eax,%eax
>    25:	c3                   	retq
>    26:	f3 0f 1e fa          	endbr64
>    2a:*	55                   	push   %rbp		<-- trapping instruction
>    2b:	65 8b 05 6e 52 f0 7c 	mov    %gs:0x7cf0526e(%rip),%eax        # 0x7cf052a0
>    32:	89 c1                	mov    %eax,%ecx
>    34:	48 89 e5             	mov    %rsp,%rbp
>    37:	81 e1 00 01 00 00    	and    $0x100,%ecx
>    3d:	48                   	rex.W
>    3e:	8b                   	.byte 0x8b
>    3f:	75                   	.byte 0x75
> 
> Code starting with the faulting instruction
> ===========================================
>     0:	55                   	push   %rbp
>     1:	65 8b 05 6e 52 f0 7c 	mov    %gs:0x7cf0526e(%rip),%eax        # 0x7cf05276
>     8:	89 c1                	mov    %eax,%ecx
>     a:	48 89 e5             	mov    %rsp,%rbp
>     d:	81 e1 00 01 00 00    	and    $0x100,%ecx
>    13:	48                   	rex.W
>    14:	8b                   	.byte 0x8b
>    15:	75                   	.byte 0x75
> 
> 
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20230913/202309131652.3e9c0f06-oliver.sang@intel.com
> 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8181f70f-4e28-4bdf-83f6-3da36fb224e8%40huawei.com.
