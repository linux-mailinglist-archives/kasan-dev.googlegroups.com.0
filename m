Return-Path: <kasan-dev+bncBCXLBLOA7IGBBHGY5DXQKGQE2O2AIFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 34452124887
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 14:39:41 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id l10sf715011ljb.15
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 05:39:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576676380; cv=pass;
        d=google.com; s=arc-20160816;
        b=DqLLBCaBac1GUqCxJFrqg54hN6HEAKOkrU33VvOg+ijZvuKA5CzLvZLUc1J09JuTtm
         dXVcKnodVHKH9jU/M/C2ZNOOY6YufEjgUtClhVvpeg3rE6PUpPq1jET6VgNsi2T0ccE7
         CVxEX7uOGYf2IFIezo9Qn2417sywHRwPjAW/7aYHSFkLFbof0wNIR7x33bdsRy8s00ez
         iwaDRfsUC5Ou2nEs+deAm/GDQpXG66rc8vqN2fLSYsDth/dqfcP2zwSZ1Jdh8V8WBmep
         WByzZvaW+uYWcjGMogmNMRj3blFDIKv9VRS8nH9Z8bdJjOyCIRibLzrcJtBGO5d5LoP/
         hcdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=11nBEER5L9KBbdgiEQKrRirX87ba3yD7H3oI949opv8=;
        b=D2xpomQdEN400fYt8f+IPemzlDxsSOFxyS2Su7DBOC3X/hCGa2TzEsDt+8Eb3akc6N
         piA+KJX4zROOL+Uk+3BxyiMZl0uKJ+ONc+IqIM46PW/x+z292Pjm8iFhWANKrGUpoYNd
         KIFC+8rfOQVoVTDctvM7FtWjNE2Vl2BByxXlezd1Ihl8YygIMvL8f3ueeRPpCNgYojsQ
         Xt3OrmeoM/Wy0IHrxIv1042qbsP+k9qn4QDG57b6pW5WaacBOFVP9OLtsixduaIIQGsY
         dQtNoNM9ASwWRy6oKZABA9smmLRCvg3mHV3RD8Ro0dUVLpiQEXige1qmCTwIJk8WOY2F
         Hk+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="d+4E/PC8";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=11nBEER5L9KBbdgiEQKrRirX87ba3yD7H3oI949opv8=;
        b=G40XLspHEZUkF6DzHSUip9/iXQX76LoJhMH+w4NbvUJ9Gv+VAL50a7h4yD5MJNML/T
         b+vEvyLh11Otd2WN5o+ScS5KTnctLjesBJaILHHlYZUGDh/fc81mplzI/U7+J8icQhbZ
         CfCYC3wwxKbOm5LlUKsu1uBPPsv8DddaRVkttY6eXB5WNPKbEAMrZzcWj6wqM6mF6LdO
         zf4x9KEms3I5synff3UPwsNWIWcbM31XuuYSk3IuzuzFfXdEIXdd0GI5nqd09bLQrf+O
         VeGiWwZ7jsri2GBSSgYphb/3rkTABSWZ4KwnJMsdUNuwHZGzrSmCHdtg9EZhz0Cni0xt
         lZfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=11nBEER5L9KBbdgiEQKrRirX87ba3yD7H3oI949opv8=;
        b=ANr1diWW8GAVIxoEjK0lkdSyB5UqrmNab0L36lYt6Fqsmk2WX4F0Fmw0BhcueaifR/
         RxwZ6U9Hm5fjGmDeDNLvJeiMrcjPE+r8YdsnpkVGZ7J9k5CPrzOf4HbohIgYP/eAHjMK
         nRR3Klr2PQDPp/VqbdrviBGqROoh08UERCaVlfkid52czjsJJLEgFL2LNewF8PSe/sCG
         +oeM1dJtiVqph1lrZ6c8xzkX3dIn3UdNTbOYYSopcTDN3Y5yUdlFWWSIpYO4FjBIYtS/
         hZEVDNvg9VjB7y4ZzEAHgTj3IqxcSTqnEB8ebb56WfoGYg6BcYsirLkkPiOEiKvXA3QW
         7Kww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVt7dlM5npbzFMogMVaZVeypBE9h1NBvsRxn2ceXaD5IPGfMyZo
	0IFhWrPTDOzgX8XpvdmONqE=
X-Google-Smtp-Source: APXvYqyUkZwTPVzz5WYYsC3zwV83Hgs0N21DZ6y+mWRtXAEjAOP4jnXTRvf05HdXF0cRN4Em2QmmrQ==
X-Received: by 2002:a2e:9a01:: with SMTP id o1mr1695917lji.247.1576676380712;
        Wed, 18 Dec 2019 05:39:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc3:: with SMTP id w3ls316328ljj.6.gmail; Wed, 18 Dec
 2019 05:39:40 -0800 (PST)
X-Received: by 2002:a2e:b056:: with SMTP id d22mr1813037ljl.73.1576676380098;
        Wed, 18 Dec 2019 05:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576676380; cv=none;
        d=google.com; s=arc-20160816;
        b=ilXPQ7na9ZOQ0GCPmb4owzg1OGrrUZihJkO08H4zGB5Pqi7MEMAZYRtIrdM2V0jf5B
         EGMoerS5R0HkIC5bc6hWaOXvywlO+yUF/q3OsNLhILGuOBclGK5gFPHYENT2XgeR4Lqb
         jwbUr0T8fzfFaptOg+YfYmiFIxsU6tlusxe3KNGIxF5qO8L0GY9jwSUCTjiMVj/LPx1T
         AJIopaY5oM6F0YlhXmFN9EGv3nqdWGOsZ3pE+youYQBkcqRsGqCpMv0ENcZ2qZJ6gpeA
         pJ2MNEbAMdfKRgx3/yA1ZNjr/Cl2o7e6cN/VAhaaZ/aeQEpjLPmJSwvV3KJ4uZE+uBh9
         vDIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=iwJBEI3a+JpTKzVvfuusiKvs7KtPefB+gwCF1RkDs4U=;
        b=l9Ik2613/nVtR20Ez8p09BVWAuO5gHbWE/yKsp5Co+ElTP00YzE/F4apgb/QgLcUgj
         fS4WAIsboY5V7GtWjzkSk8A1OnpprB6tHHvBhR38KZexPuNTFQ0p5XNCj5mSS6q9ytrY
         K0amHxfNWK8maIXSqao4DqezAKVdnpx0Xb7edh85Fm7wTIV4XnQS2jole0q920qBpiPx
         0J0IXPtU2FCjvHMNySj2TNUOEFAzUAvE2GbCr+6kX05bAWKNjN0bVwL/Mq0Fu6x4G/XU
         OSsyolQWOV2SxmwxDvqTS9gh26vruoB00zvIzKdZzVgQYHMxflIGlDbmYD+BTXNOuP42
         ABwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="d+4E/PC8";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id h8si77041ljj.3.2019.12.18.05.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Dec 2019 05:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47dGMY707cz9vBJl;
	Wed, 18 Dec 2019 14:39:37 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 67KJgiDWooek; Wed, 18 Dec 2019 14:39:37 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47dGMY5vL7z9v9F5;
	Wed, 18 Dec 2019 14:39:37 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 10CBD8B83E;
	Wed, 18 Dec 2019 14:39:39 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 2Iu8vxJAWjO5; Wed, 18 Dec 2019 14:39:38 +0100 (CET)
Received: from po16098vm.idsi0.si.c-s.fr (po15451.idsi0.si.c-s.fr [172.25.230.106])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A783E8B837;
	Wed, 18 Dec 2019 14:39:38 +0100 (CET)
Subject: Re: [PATCH v3 3/3] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20191212151656.26151-1-dja@axtens.net>
 <20191212151656.26151-4-dja@axtens.net>
 <ec89e1c4-32d7-b96e-eb7e-dcb16cab89c0@c-s.fr>
 <87k16vaxky.fsf@dja-thinkpad.axtens.net>
 <871rt2uud7.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <cfb1429b-23e1-6a6c-0d85-b0b7c755bcf1@c-s.fr>
Date: Wed, 18 Dec 2019 13:39:01 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.7.0
MIME-Version: 1.0
In-Reply-To: <871rt2uud7.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b="d+4E/PC8";       spf=pass
 (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



On 12/18/2019 04:32 AM, Daniel Axtens wrote:
> Daniel Axtens <dja@axtens.net> writes:
> 
>> Hi Christophe,
>>
>> I'm working through your feedback, thank you. Regarding this one:
>>
>>>> --- a/arch/powerpc/kernel/process.c
>>>> +++ b/arch/powerpc/kernel/process.c
>>>> @@ -2081,7 +2081,14 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>>>>    		/*
>>>>    		 * See if this is an exception frame.
>>>>    		 * We look for the "regshere" marker in the current frame.
>>>> +		 *
>>>> +		 * KASAN may complain about this. If it is an exception frame,
>>>> +		 * we won't have unpoisoned the stack in asm when we set the
>>>> +		 * exception marker. If it's not an exception frame, who knows
>>>> +		 * how things are laid out - the shadow could be in any state
>>>> +		 * at all. Just disable KASAN reporting for now.
>>>>    		 */
>>>> +		kasan_disable_current();
>>>>    		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>>>>    		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
>>>>    			struct pt_regs *regs = (struct pt_regs *)
>>>> @@ -2091,6 +2098,7 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>>>>    			       regs->trap, (void *)regs->nip, (void *)lr);
>>>>    			firstframe = 1;
>>>>    		}
>>>> +		kasan_enable_current();
>>>
>>> If this is really a concern for all targets including PPC32, should it
>>> be a separate patch with a Fixes: tag to be applied back in stable as well ?
>>
>> I've managed to repro this by commening out the kasan_disable/enable
>> lines, and just booting in qemu without a disk attached:
>>
>> sudo qemu-system-ppc64 -accel kvm -m 2G -M pseries -cpu power9  -kernel ./vmlinux  -nographic -chardev stdio,id=charserial0,mux=on -device spapr-vty,chardev=charserial0,reg=0x30000000  -mon chardev=charserial0,mode=readline -nodefaults -smp 2
>>
>> ...
>>
>> [    0.210740] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
>> [    0.210789] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1-next-20191213-16824-g469a24fbdb34 #12
>> [    0.210844] Call Trace:
>> [    0.210866] [c00000006a4839b0] [c000000001f74f48] dump_stack+0xfc/0x154 (unreliable)
>> [    0.210915] [c00000006a483a00] [c00000000025411c] panic+0x258/0x59c
>> [    0.210958] [c00000006a483aa0] [c0000000024870b0] mount_block_root+0x648/0x7ac
>> [    0.211005] ==================================================================
>> [    0.211054] BUG: KASAN: stack-out-of-bounds in show_stack+0x438/0x580
>> [    0.211095] Read of size 8 at addr c00000006a483b00 by task swapper/0/1
>> [    0.211134]
>> [    0.211152] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1-next-20191213-16824-g469a24fbdb34 #12
>> [    0.211207] Call Trace:
>> [    0.211225] [c00000006a483680] [c000000001f74f48] dump_stack+0xfc/0x154 (unreliable)
>> [    0.211274] [c00000006a4836d0] [c0000000008f877c] print_address_description.isra.10+0x7c/0x470
>> [    0.211330] [c00000006a483760] [c0000000008f8e7c] __kasan_report+0x1bc/0x244
>> [    0.211380] [c00000006a483830] [c0000000008f6eb8] kasan_report+0x18/0x30
>> [    0.211422] [c00000006a483850] [c0000000008fa5d4] __asan_report_load8_noabort+0x24/0x40
>> [    0.211471] [c00000006a483870] [c00000000003d448] show_stack+0x438/0x580
>> [    0.211512] [c00000006a4839b0] [c000000001f74f48] dump_stack+0xfc/0x154
>> [    0.211553] [c00000006a483a00] [c00000000025411c] panic+0x258/0x59c
>> [    0.211595] [c00000006a483aa0] [c0000000024870b0] mount_block_root+0x648/0x7ac
>> [    0.211644] [c00000006a483be0] [c000000002487784] prepare_namespace+0x1ec/0x240
>> [    0.211694] [c00000006a483c60] [c00000000248669c] kernel_init_freeable+0x7f4/0x870
>> [    0.211745] [c00000006a483da0] [c000000000011f30] kernel_init+0x3c/0x15c
>> [    0.211787] [c00000006a483e20] [c00000000000bebc] ret_from_kernel_thread+0x5c/0x80
>> [    0.211834]
>> [    0.211851] Allocated by task 0:
>> [    0.211878]  save_stack+0x2c/0xe0
>> [    0.211904]  __kasan_kmalloc.isra.16+0x11c/0x150
>> [    0.211937]  kmem_cache_alloc_node+0x114/0x3b0
>> [    0.211971]  copy_process+0x5b8/0x6410
>> [    0.211996]  _do_fork+0x130/0xbf0
>> [    0.212022]  kernel_thread+0xdc/0x130
>> [    0.212047]  rest_init+0x44/0x184
>> [    0.212072]  start_kernel+0x77c/0x7dc
>> [    0.212098]  start_here_common+0x1c/0x20
>> [    0.212122]
>> [    0.212139] Freed by task 0:
>> [    0.212163] (stack is not available)
>> [    0.212187]
>> [    0.212205] The buggy address belongs to the object at c00000006a480000
>> [    0.212205]  which belongs to the cache thread_stack of size 16384
>> [    0.212285] The buggy address is located 15104 bytes inside of
>> [    0.212285]  16384-byte region [c00000006a480000, c00000006a484000)
>> [    0.212356] The buggy address belongs to the page:
>> [    0.212391] page:c00c0000001a9200 refcount:1 mapcount:0 mapping:c00000006a019e00 index:0x0 compound_mapcount: 0
>> [    0.212455] raw: 007ffff000010200 5deadbeef0000100 5deadbeef0000122 c00000006a019e00
>> [    0.212504] raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000
>> [    0.212551] page dumped because: kasan: bad access detected
>> [    0.212583]
>> [    0.212600] addr c00000006a483b00 is located in stack of task swapper/0/1 at offset 0 in frame:
>> [    0.212656]  mount_block_root+0x0/0x7ac
>> [    0.212681]
>> [    0.212698] this frame has 1 object:
>> [    0.212722]  [32, 64) 'b'
>> [    0.212723]
>> [    0.212755] Memory state around the buggy address:
>> [    0.212788]  c00000006a483a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> [    0.212836]  c00000006a483a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> [    0.212884] >c00000006a483b00: f1 f1 f1 f1 00 00 00 00 f3 f3 f3 f3 00 00 00 00
>> [    0.212931]                    ^
>> [    0.212957]  c00000006a483b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> [    0.213005]  c00000006a483c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>> [    0.213052] ==================================================================
>> [    0.213100] Disabling lock debugging due to kernel taint
>> [    0.213134] [c00000006a483be0] [c000000002487784] prepare_namespace+0x1ec/0x240
>> [    0.213182] [c00000006a483c60] [c00000000248669c] kernel_init_freeable+0x7f4/0x870
>> [    0.213231] [c00000006a483da0] [c000000000011f30] kernel_init+0x3c/0x15c
>> [    0.213272] [c00000006a483e20] [c00000000000bebc] ret_from_kernel_thread+0x5c/0x80
>>
>> Is that something that reproduces on ppc32?
>>
>> I don't see it running the test_kasan tests, so I guess that matches up
>> with your experience.
> 
> I've debugged this a bit further. If I put a dump_stack() in
> kernel_init() right before I call kernel_init_freeable(), I don't see
> the splat. But if I put a dump_stack() immediately inside
> kernel_init_freeable() I do see the splat. I wonder if some early init
> code isn't setting up the stack quite right?
> 
> I don't see this in walking stacks that contain an interrupt frame, so I
> think the correct thing is to tear out this code and debug the weird
> stack frame stuff around kernel_init_freeable in parallel.
> 
> Thanks for your attention to detail.
> 

I added a dump_stack() at the start of kernel_init_freeable() and I get 
nothing more than what follows:

[    0.000000] Activating Kernel Userspace Execution Prevention
[    0.000000] Activating Kernel Userspace Access Protection
[    0.000000] Linux version 5.5.0-rc2-s3k-dev-00932-gf5a548a2b0bc-dirty 
(root@po16098vm.idsi0.si.c-s.fr) (gcc version 5.5.0 (GCC)) #2596 PREEMPT 
Wed Dec 18 09:05:02 UTC 2019
[    0.000000] KASAN init done
[    0.000000] Using CMPC885 machine description
[    0.000000] -----------------------------------------------------
[    0.000000] phys_mem_size     = 0x8000000
[    0.000000] dcache_bsize      = 0x10
[    0.000000] icache_bsize      = 0x10
[    0.000000] cpu_features      = 0x0000000000000100
[    0.000000]   possible        = 0x0000000000000120
[    0.000000]   always          = 0x0000000000000000
[    0.000000] cpu_user_features = 0x84000000 0x00000000
[    0.000000] mmu_features      = 0x00000002
[    0.000000] -----------------------------------------------------
[    0.000000] SMC microcode patch installed
[    0.000000] Top of RAM: 0x8000000, Total RAM: 0x8000000
[    0.000000] Memory hole size: 0MB
[    0.000000] Zone ranges:
[    0.000000]   Normal   [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000000000000-0x0000000007ffffff]
[    0.000000] Initmem setup node 0 [mem 
0x0000000000000000-0x0000000007ffffff]
[    0.000000] On node 0 totalpages: 8192
[    0.000000]   Normal zone: 16 pages used for memmap
[    0.000000]   Normal zone: 0 pages reserved
[    0.000000]   Normal zone: 8192 pages, LIFO batch:0
[    0.000000] MMU: Allocated 76 bytes of context maps for 16 contexts
[    0.000000] pcpu-alloc: s0 r0 d32768 u32768 alloc=1*32768
[    0.000000] pcpu-alloc: [0] 0
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 8176
[    0.000000] Kernel command line: console=ttyCPM0,115200N8 
ip=192.168.0.3:192.168.0.1::255.0.0.0:vgoip:eth0:off
[    0.000000] Dentry cache hash table entries: 16384 (order: 2, 65536 
bytes, linear)
[    0.000000] Inode-cache hash table entries: 8192 (order: 1, 32768 
bytes, linear)
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 95520K/131072K available (8640K kernel code, 
1840K rwdata, 2720K rodata, 656K init, 4679K bss, 35552K reserved, 0K 
cma-reserved)
[    0.000000] Kernel virtual memory layout:
[    0.000000]   * 0xf8000000..0x00000000  : kasan shadow mem
[    0.000000]   * 0xf7afc000..0xf7ffc000  : fixmap
[    0.000000]   * 0xc9000000..0xf7afc000  : vmalloc & ioremap
[    0.000000] SLUB: HWalign=16, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
[    0.000000] rcu: Preemptible hierarchical RCU implementation.
[    0.000000] 	Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay 
is 10 jiffies.
[    0.000000] NR_IRQS: 512, nr_irqs: 512, preallocated irqs: 16
[    0.000000] Decrementer Frequency = 0x7de290
[    0.000000] time_init: decrementer frequency = 8.250000 MHz
[    0.000000] time_init: processor frequency   = 132.000000 MHz
[    0.000153] clocksource: timebase: mask: 0xffffffffffffffff 
max_cycles: 0x1e717863c, max_idle_ns: 440795202213 ns
[    0.000336] clocksource: timebase mult[79364d93] shift[24] registered
[    0.000569] clockevent: decrementer mult[21cac08] shift[32] cpu[0]
[    0.246805] printk: console [ttyCPM0] enabled
[    0.251462] pid_max: default: 32768 minimum: 301
[    0.259445] Mount-cache hash table entries: 4096 (order: 0, 16384 
bytes, linear)
[    0.267030] Mountpoint-cache hash table entries: 4096 (order: 0, 
16384 bytes, linear)
[    0.295520] CPU: 0 PID: 1 Comm: swapper Not tainted 
5.5.0-rc2-s3k-dev-00932-gf5a548a2b0bc-dirty #2596
[    0.304710] Call Trace:
[    0.307115] [c5121ed8] [c0b19290] kernel_init_freeable+0x20/0x240 
(unreliable)
[    0.314283] [c5121f18] [c0003ddc] kernel_init+0x18/0x10c
[    0.319728] [c5121f38] [c00121cc] ret_from_kernel_thread+0x14/0x1c
[    0.337686] rcu: Hierarchical SRCU implementation.
[    0.350228] devtmpfs: initialized
[    0.533520] device: 'platform': device_add
[    0.535188] bus: 'platform': registered
...


Christophe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfb1429b-23e1-6a6c-0d85-b0b7c755bcf1%40c-s.fr.
