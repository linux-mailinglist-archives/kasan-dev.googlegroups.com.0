Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBFR4PXQKGQEN3PPAHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id BBD1D122CE3
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 14:30:45 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id y131sf638947oia.7
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 05:30:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576589444; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ld5KrW5e7KOkKDZk1AaAKw+/FZ8cbT8up791DS+xwK08nUhr9WAbBpawHhgK9FJrHu
         KuWizE9qQID0SBlVS/iNZodF0aEQ4ZwM0eKia9ZZfwUnBqjW+IeEpnR4oa9fVe6a7w8w
         oUldoFWzAuO3vfxWp9wyRZ8Fh+a+453Zjdekgkl6/xOSsIa8GAvFwG3wHJ1DDTzHlF0c
         DOEGuvrzmrmlrnwxeWmduZJ+tfQC5F5e7f3lCb8LoHP12qNWNzosZVHew3sHHnG4cooh
         Gz6U5jSAFj/yffsd9l+GHiSysfNbAhOSCVG40k642Z403TkQUMDQoLwyf13a5JGlJfhz
         1ExQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=nmUYyILfagGqDF1HdNpkE22jaP3Pt1pIO9vzU8MKY2c=;
        b=XV+SJGocwjjM/vkkhI7RVywzEoj0azDqulH4nQysTznhfBETuWwCJjeIkARgyMldIZ
         LCY3lYgWo+QKNtKUA1M8TkvYcPON8qE4JDaQDgUYSM0KpSYJLMkH/YtearJ9F2L/fA43
         UreAAMLwI+R/a5KwRZo5AEqdtuKhbFOscvo7I5qafg2GaQ5nO/h5GtC6Z8+UyKU23wQX
         kjc1CirecaZGaYi/UenJHfTIMMj4OiPu2by9rnrVdh5GBd+IKhzssKL37eDZsCht2EPG
         zxmlrRXhPjoPs6yBxfKvo2TpcDF2lTjh/ynrE/JvaIl2SHWJe6yqYXQPaq6aiwCmdEwS
         T7FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jbZRCt7x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nmUYyILfagGqDF1HdNpkE22jaP3Pt1pIO9vzU8MKY2c=;
        b=ltaXHdo8XEI4IR3LOzuU+tBIf1pghrizZ/9x+VTGodwojrX/ne59vjZAWCNG9z6NH/
         Y/HRw0684Bkx2wdFsTFnfGn2BIC3fL7PjxA/XjxKDuxRHJqG1EYg7fKecVvcBMA7c6Lm
         DEhhjzJiQvUZsJV4C8PufG9ZjTrw/RPT1qD/VfQv+nlDWKiO8AVvLeWIFP9tYl+sBf3r
         sfyY/ECjmXm+/rD7/DGF9a8NHbPyfsMLpel9DO59VFS0oC+ZnnorDnUYSraZW89eyOx3
         0k0LbW/QvNrwsRxs1jcBl3btZkAZTr4PdyIA/Cbkk/03zxNzjNv4cvBP7Gf7zq0go/n7
         16yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nmUYyILfagGqDF1HdNpkE22jaP3Pt1pIO9vzU8MKY2c=;
        b=RQjT4qP09k+bdzQs/9kf0kcYfo5d4h/rBRR+TMeeXDEcZT0utnrkZdP/wVMbY87FB4
         xJfXWvQBsEn/4tWWarJUi/Qs/An2VPnUUvosdo2KoXY8KIoro7V/OdGA276Ani1O0yA7
         CVtYxtsPHXy4TL8QU484dbXUlowkr+hKaOd2SwRGUodaoZMyd28EU/4kFUpJhSA7Jg+M
         Rg8mOHb1gbvtEYrJLhC5jbZ37MG1mtteyGW5+L65XUv1uafQL1DLDzAnmOFfFS898bu4
         KJWx/tjaG3CZRvW3tO7TBQkDtEVaC/DsqI4j09yhSO09lPipcSedrDeSoX9uCOY3KXpa
         DJ0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU+x2MJ2Kc+MasLHXSSDukULgL3SuDo5JA0gqXVAzQHn8wVmU3c
	vsHq6Iujqhupmn5rGnCim+E=
X-Google-Smtp-Source: APXvYqxp9qMfEx0YqkmmLfqK5nFhPYdeD0J1+FFNzSXFEIwKFf7DXvRpFfM5/7U0jUuRPcIiTXHYDg==
X-Received: by 2002:a05:6830:1d7a:: with SMTP id l26mr35991347oti.138.1576589444131;
        Tue, 17 Dec 2019 05:30:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1a0d:: with SMTP id a13ls1524632oia.14.gmail; Tue, 17
 Dec 2019 05:30:43 -0800 (PST)
X-Received: by 2002:aca:728c:: with SMTP id p134mr1546639oic.176.1576589443613;
        Tue, 17 Dec 2019 05:30:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576589443; cv=none;
        d=google.com; s=arc-20160816;
        b=eYAkM2mOkVTPfEKlnU9eTi/SZag3pnixG37ZAuEPbBcJgnFSgTpoml1gAdljl175fD
         2LSzdiW+5Dli7Oky8NCIyMwMe6GT+9zhZ0TO7XrE8VSznwi1UERY6AO28y7QzumJkgxQ
         0ujXdzBFc7HRBqgdWMW931POCBhzgapyWq5gb4Fbzj46VguSxwSCbnM63Erog+oyvBVh
         X3Es20Nb1TwoMfnhCf60Kkr03hiMkMdsV9HDnhg1b2PwyPSBrx00tGKlUxPcPOEPmEv7
         ixnfY/PibJAyaDLDpzaHR2HCjVALGaTvtIYOMBNGxn4gvBGA5Nfy4UUh0A2n5uC1OdNa
         s2ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=Reh3wVNwDhfuM5Xh7lpmH6YixduOnw90SzrqZCSKyHk=;
        b=YkucbL1lJ9Q72LK1jYFu7nM4EGoYGFGukyeoB7MYDSKSvrOLQd2gXUpMWpdDauBAPe
         vftxkheiiVdMmqCoQddBNzVFyvquCsrMZd7M+JAFKm6gHp6dcxh1xPaPIupcX9qTH2zY
         fEEFFALEK60LmoOCvjOe8gTfqwu64YiaDgEd8Jih8Du9cumzvHCKfEJWapLMMSinCAAh
         z7G51I7ULj7T/O2QxU6M2kJUbLfbW/b1RkXPeqPXsJ3Bb55zqIFZNE//CvG6I2StmvDV
         FTEU6zGiQ7ycL9HHLS8T1MU5lcC5cjMqsgSjGxiqZ4q2y1AgX/feTB8vHOoZZcdvy/MX
         ldGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jbZRCt7x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id c24si887866oto.3.2019.12.17.05.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Dec 2019 05:30:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id bd4so6112115plb.8
        for <kasan-dev@googlegroups.com>; Tue, 17 Dec 2019 05:30:43 -0800 (PST)
X-Received: by 2002:a17:902:8501:: with SMTP id bj1mr23059452plb.84.1576589442740;
        Tue, 17 Dec 2019 05:30:42 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e4cb-43b3-6b6e-ca31.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e4cb:43b3:6b6e:ca31])
        by smtp.gmail.com with ESMTPSA id e23sm3430548pjt.23.2019.12.17.05.30.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2019 05:30:41 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v3 3/3] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <ec89e1c4-32d7-b96e-eb7e-dcb16cab89c0@c-s.fr>
References: <20191212151656.26151-1-dja@axtens.net> <20191212151656.26151-4-dja@axtens.net> <ec89e1c4-32d7-b96e-eb7e-dcb16cab89c0@c-s.fr>
Date: Wed, 18 Dec 2019 00:30:37 +1100
Message-ID: <87k16vaxky.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=jbZRCt7x;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Christophe,

I'm working through your feedback, thank you. Regarding this one:

>> --- a/arch/powerpc/kernel/process.c
>> +++ b/arch/powerpc/kernel/process.c
>> @@ -2081,7 +2081,14 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>>   		/*
>>   		 * See if this is an exception frame.
>>   		 * We look for the "regshere" marker in the current frame.
>> +		 *
>> +		 * KASAN may complain about this. If it is an exception frame,
>> +		 * we won't have unpoisoned the stack in asm when we set the
>> +		 * exception marker. If it's not an exception frame, who knows
>> +		 * how things are laid out - the shadow could be in any state
>> +		 * at all. Just disable KASAN reporting for now.
>>   		 */
>> +		kasan_disable_current();
>>   		if (validate_sp(sp, tsk, STACK_INT_FRAME_SIZE)
>>   		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
>>   			struct pt_regs *regs = (struct pt_regs *)
>> @@ -2091,6 +2098,7 @@ void show_stack(struct task_struct *tsk, unsigned long *stack)
>>   			       regs->trap, (void *)regs->nip, (void *)lr);
>>   			firstframe = 1;
>>   		}
>> +		kasan_enable_current();
>
> If this is really a concern for all targets including PPC32, should it 
> be a separate patch with a Fixes: tag to be applied back in stable as well ?

I've managed to repro this by commening out the kasan_disable/enable
lines, and just booting in qemu without a disk attached:

sudo qemu-system-ppc64 -accel kvm -m 2G -M pseries -cpu power9  -kernel ./vmlinux  -nographic -chardev stdio,id=charserial0,mux=on -device spapr-vty,chardev=charserial0,reg=0x30000000  -mon chardev=charserial0,mode=readline -nodefaults -smp 2 

...

[    0.210740] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    0.210789] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1-next-20191213-16824-g469a24fbdb34 #12
[    0.210844] Call Trace:
[    0.210866] [c00000006a4839b0] [c000000001f74f48] dump_stack+0xfc/0x154 (unreliable)
[    0.210915] [c00000006a483a00] [c00000000025411c] panic+0x258/0x59c
[    0.210958] [c00000006a483aa0] [c0000000024870b0] mount_block_root+0x648/0x7ac
[    0.211005] ==================================================================
[    0.211054] BUG: KASAN: stack-out-of-bounds in show_stack+0x438/0x580
[    0.211095] Read of size 8 at addr c00000006a483b00 by task swapper/0/1
[    0.211134] 
[    0.211152] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1-next-20191213-16824-g469a24fbdb34 #12
[    0.211207] Call Trace:
[    0.211225] [c00000006a483680] [c000000001f74f48] dump_stack+0xfc/0x154 (unreliable)
[    0.211274] [c00000006a4836d0] [c0000000008f877c] print_address_description.isra.10+0x7c/0x470
[    0.211330] [c00000006a483760] [c0000000008f8e7c] __kasan_report+0x1bc/0x244
[    0.211380] [c00000006a483830] [c0000000008f6eb8] kasan_report+0x18/0x30
[    0.211422] [c00000006a483850] [c0000000008fa5d4] __asan_report_load8_noabort+0x24/0x40
[    0.211471] [c00000006a483870] [c00000000003d448] show_stack+0x438/0x580
[    0.211512] [c00000006a4839b0] [c000000001f74f48] dump_stack+0xfc/0x154
[    0.211553] [c00000006a483a00] [c00000000025411c] panic+0x258/0x59c
[    0.211595] [c00000006a483aa0] [c0000000024870b0] mount_block_root+0x648/0x7ac
[    0.211644] [c00000006a483be0] [c000000002487784] prepare_namespace+0x1ec/0x240
[    0.211694] [c00000006a483c60] [c00000000248669c] kernel_init_freeable+0x7f4/0x870
[    0.211745] [c00000006a483da0] [c000000000011f30] kernel_init+0x3c/0x15c
[    0.211787] [c00000006a483e20] [c00000000000bebc] ret_from_kernel_thread+0x5c/0x80
[    0.211834] 
[    0.211851] Allocated by task 0:
[    0.211878]  save_stack+0x2c/0xe0
[    0.211904]  __kasan_kmalloc.isra.16+0x11c/0x150
[    0.211937]  kmem_cache_alloc_node+0x114/0x3b0
[    0.211971]  copy_process+0x5b8/0x6410
[    0.211996]  _do_fork+0x130/0xbf0
[    0.212022]  kernel_thread+0xdc/0x130
[    0.212047]  rest_init+0x44/0x184
[    0.212072]  start_kernel+0x77c/0x7dc
[    0.212098]  start_here_common+0x1c/0x20
[    0.212122] 
[    0.212139] Freed by task 0:
[    0.212163] (stack is not available)
[    0.212187] 
[    0.212205] The buggy address belongs to the object at c00000006a480000
[    0.212205]  which belongs to the cache thread_stack of size 16384
[    0.212285] The buggy address is located 15104 bytes inside of
[    0.212285]  16384-byte region [c00000006a480000, c00000006a484000)
[    0.212356] The buggy address belongs to the page:
[    0.212391] page:c00c0000001a9200 refcount:1 mapcount:0 mapping:c00000006a019e00 index:0x0 compound_mapcount: 0
[    0.212455] raw: 007ffff000010200 5deadbeef0000100 5deadbeef0000122 c00000006a019e00
[    0.212504] raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000
[    0.212551] page dumped because: kasan: bad access detected
[    0.212583] 
[    0.212600] addr c00000006a483b00 is located in stack of task swapper/0/1 at offset 0 in frame:
[    0.212656]  mount_block_root+0x0/0x7ac
[    0.212681] 
[    0.212698] this frame has 1 object:
[    0.212722]  [32, 64) 'b'
[    0.212723] 
[    0.212755] Memory state around the buggy address:
[    0.212788]  c00000006a483a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    0.212836]  c00000006a483a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    0.212884] >c00000006a483b00: f1 f1 f1 f1 00 00 00 00 f3 f3 f3 f3 00 00 00 00
[    0.212931]                    ^
[    0.212957]  c00000006a483b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    0.213005]  c00000006a483c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[    0.213052] ==================================================================
[    0.213100] Disabling lock debugging due to kernel taint
[    0.213134] [c00000006a483be0] [c000000002487784] prepare_namespace+0x1ec/0x240
[    0.213182] [c00000006a483c60] [c00000000248669c] kernel_init_freeable+0x7f4/0x870
[    0.213231] [c00000006a483da0] [c000000000011f30] kernel_init+0x3c/0x15c
[    0.213272] [c00000006a483e20] [c00000000000bebc] ret_from_kernel_thread+0x5c/0x80

Is that something that reproduces on ppc32?

I don't see it running the test_kasan tests, so I guess that matches up
with your experience.

Regards,
Daniel



>
>>   
>>   		sp = newsp;
>>   	} while (count++ < kstack_depth_to_print);
>> diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
>> index 6620f37abe73..d994c7c39c8d 100644
>> --- a/arch/powerpc/kernel/prom.c
>> +++ b/arch/powerpc/kernel/prom.c
>> @@ -72,6 +72,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
>>   u64 ppc64_rma_size;
>>   #endif
>>   static phys_addr_t first_memblock_size;
>> +static phys_addr_t top_phys_addr;
>>   static int __initdata boot_cpu_count;
>>   
>>   static int __init early_parse_mem(char *p)
>> @@ -449,6 +450,26 @@ static bool validate_mem_limit(u64 base, u64 *size)
>>   {
>>   	u64 max_mem = 1UL << (MAX_PHYSMEM_BITS);
>>   
>> +	/*
>> +	 * To handle the NUMA/discontiguous memory case, don't allow a block
>> +	 * to be added if it falls completely beyond the configured physical
>> +	 * memory. Print an informational message.
>> +	 *
>> +	 * Frustratingly we also see this with qemu - it seems to split the
>> +	 * specified memory into a number of smaller blocks. If this happens
>> +	 * under qemu, it probably represents misconfiguration. So we want
>> +	 * the message to be noticeable, but not shouty.
>> +	 *
>> +	 * See Documentation/powerpc/kasan.txt
>> +	 */
>> +	if (IS_ENABLED(CONFIG_KASAN) &&
>> +	    (base >= ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20))) {
>> +		pr_warn("KASAN: not adding memory block at %llx (size %llx)\n"
>> +			"This could be due to discontiguous memory or kernel misconfiguration.",
>> +			base, *size);
>> +		return false;
>> +	}
>> +
>>   	if (base >= max_mem)
>>   		return false;
>>   	if ((base + *size) > max_mem)
>> @@ -572,8 +593,11 @@ void __init early_init_dt_add_memory_arch(u64 base, u64 size)
>>   
>>   	/* Add the chunk to the MEMBLOCK list */
>>   	if (add_mem_to_memblock) {
>> -		if (validate_mem_limit(base, &size))
>> +		if (validate_mem_limit(base, &size)) {
>>   			memblock_add(base, size);
>> +			if (base + size > top_phys_addr)
>> +				top_phys_addr = base + size;
>> +		}
>
> Can we use max() here ? Something like
>
> top_phys_addr = max(base + size, top_phys_addr);
>
>>   	}
>>   }
>>   
>> @@ -613,6 +637,8 @@ static void __init early_reserve_mem_dt(void)
>>   static void __init early_reserve_mem(void)
>>   {
>>   	__be64 *reserve_map;
>> +	phys_addr_t kasan_shadow_start;
>> +	phys_addr_t kasan_memory_size;
>>   
>>   	reserve_map = (__be64 *)(((unsigned long)initial_boot_params) +
>>   			fdt_off_mem_rsvmap(initial_boot_params));
>> @@ -651,6 +677,42 @@ static void __init early_reserve_mem(void)
>>   		return;
>>   	}
>>   #endif
>> +
>> +	if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_PPC_BOOK3S_64)) {
>> +		kasan_memory_size =
>> +			((phys_addr_t)CONFIG_PHYS_MEM_SIZE_FOR_KASAN << 20);
>> +
>> +		if (top_phys_addr < kasan_memory_size) {
>> +			/*
>> +			 * We are doomed. We shouldn't even be able to get this
>> +			 * far, but we do in qemu. If we continue and turn
>> +			 * relocations on, we'll take fatal page faults for
>> +			 * memory that's not physically present. Instead,
>> +			 * panic() here: it will be saved to __log_buf even if
>> +			 * it doesn't get printed to the console.
>> +			 */
>> +			panic("Tried to book a KASAN kernel configured for %u MB with only %llu MB! Aborting.",
>
> book ==> boot ?
>
>> +			      CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
>> +			      (u64)(top_phys_addr >> 20));
>> +		} else if (top_phys_addr > kasan_memory_size) {
>> +			/* print a biiiig warning in hopes people notice */
>> +			pr_err("===========================================\n"
>> +				"Physical memory exceeds compiled-in maximum!\n"
>> +				"This kernel was compiled for KASAN with %u MB physical memory.\n"
>> +				"The physical memory detected is at least %llu MB.\n"
>> +				"Memory above the compiled limit will not be used!\n"
>> +				"===========================================\n",
>> +				CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
>> +				(u64)(top_phys_addr >> 20));
>> +		}
>> +
>> +		kasan_shadow_start = _ALIGN_DOWN(kasan_memory_size * 7 / 8,
>> +						 PAGE_SIZE);
>
> Can't this fit on a single line ? powerpc allows 90 chars.
>
>> +		DBG("reserving %llx -> %llx for KASAN",
>> +		    kasan_shadow_start, top_phys_addr);
>> +		memblock_reserve(kasan_shadow_start,
>> +				 top_phys_addr - kasan_shadow_start);
>
> Same ?
>
>> +	}
>>   }
>>   
>>   #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
>> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
>> index 6577897673dd..f02b15c78e4d 100644
>> --- a/arch/powerpc/mm/kasan/Makefile
>> +++ b/arch/powerpc/mm/kasan/Makefile
>> @@ -2,4 +2,5 @@
>>   
>>   KASAN_SANITIZE := n
>>   
>> -obj-$(CONFIG_PPC32)           += kasan_init_32.o
>> +obj-$(CONFIG_PPC32)           += init_32.o
>
> Shouldn't we do ppc32 name change in another patch ?
>
>> +obj-$(CONFIG_PPC_BOOK3S_64)   += init_book3s_64.o
>> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
>> similarity index 100%
>> rename from arch/powerpc/mm/kasan/kasan_init_32.c
>> rename to arch/powerpc/mm/kasan/init_32.c
>> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
>> new file mode 100644
>> index 000000000000..f961e96be136
>> --- /dev/null
>> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
>> @@ -0,0 +1,72 @@
>> +// SPDX-License-Identifier: GPL-2.0
>> +/*
>> + * KASAN for 64-bit Book3S powerpc
>> + *
>> + * Copyright (C) 2019 IBM Corporation
>> + * Author: Daniel Axtens <dja@axtens.net>
>> + */
>> +
>> +#define DISABLE_BRANCH_PROFILING
>> +
>> +#include <linux/kasan.h>
>> +#include <linux/printk.h>
>> +#include <linux/sched/task.h>
>> +#include <asm/pgalloc.h>
>> +
>> +void __init kasan_init(void)
>> +{
>> +	int i;
>> +	void *k_start = kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
>> +	void *k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
>> +
>> +	pte_t pte = __pte(__pa(kasan_early_shadow_page) |
>> +			  pgprot_val(PAGE_KERNEL) | _PAGE_PTE);
>
> Can't we do something with existing helpers ? Something like:
>
> pte = pte_mkpte(pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
>
>> +
>> +	if (!early_radix_enabled())
>> +		panic("KASAN requires radix!");
>> +
>> +	for (i = 0; i < PTRS_PER_PTE; i++)
>> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
>> +			     &kasan_early_shadow_pte[i], pte, 0);
>> +
>> +	for (i = 0; i < PTRS_PER_PMD; i++)
>> +		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
>> +				    kasan_early_shadow_pte);
>> +
>> +	for (i = 0; i < PTRS_PER_PUD; i++)
>> +		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
>> +			     kasan_early_shadow_pmd);
>> +
>> +	memset(kasan_mem_to_shadow((void *)PAGE_OFFSET), KASAN_SHADOW_INIT,
>> +	       KASAN_SHADOW_SIZE);
>> +
>> +	kasan_populate_early_shadow(
>> +		kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START),
>> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_START));
>> +
>> +	/* leave a hole here for vmalloc */
>> +
>> +	kasan_populate_early_shadow(
>> +		kasan_mem_to_shadow((void *)RADIX_VMALLOC_END),
>> +		kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END));
>> +
>> +	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
>> +
>> +	/* mark early shadow region as RO and wipe */
>> +	pte = __pte(__pa(kasan_early_shadow_page) |
>> +		    pgprot_val(PAGE_KERNEL_RO) | _PAGE_PTE);
>
> Same comment as above, use helpers ?
>
>> +	for (i = 0; i < PTRS_PER_PTE; i++)
>> +		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
>> +			     &kasan_early_shadow_pte[i], pte, 0);
>> +
>> +	/*
>> +	 * clear_page relies on some cache info that hasn't been set up yet.
>> +	 * It ends up looping ~forever and blows up other data.
>> +	 * Use memset instead.
>> +	 */
>> +	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>> +
>> +	/* Enable error messages */
>> +	init_task.kasan_depth = 0;
>> +	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
>> +}
>> 
>
> Christophe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k16vaxky.fsf%40dja-thinkpad.axtens.net.
