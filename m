Return-Path: <kasan-dev+bncBDLKPY4HVQKBBO6F72AQMGQEO6SPE4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id DA6EF32B8BC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 15:52:43 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id b62sf3091621wmc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 06:52:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614783163; cv=pass;
        d=google.com; s=arc-20160816;
        b=yU78UWd6uS3QZzX42rSJfMUXVPB5vZTbQo0hu55Q4WvN8euNfBOf1mz2as4zQ2fwt1
         hoGcwyd0mJHWniSz6EyK/rXY7WRvLO/PTqvGlJTvfZ3zzvo7r393ZfwWwaD7CXU1xppl
         886znwi60KTn5ozjzHZNtiwIcbwzWFFNaEhGG3KAAe1KLdydyd74w9viS0+UtqId2XFH
         j2Jv3veCWYP8vPHe6RVnrYrmW8dUP/u3a2ZzW5knZy5tX2De+QZ7HmzDKaD0HTVxHFIZ
         sMFhwxL4LgnuxzZbl61q3T4NqXy8OZA/PYQTLHwHvEZI4Vasxkqe18hrjesGy3rRvAhv
         bcxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=AL+rMiDUuRLsqRvfIVnb3TpUrclwDJop9eZiZDegod4=;
        b=FqQ2QidsP4eveaIRobBiEPUGoURWrcxuYbxeu80Go0XqMeS2fFwi8PvJlBV0JTJX99
         /RneWMjs2oUenZZp6rrBrmpf7751CuYLBizP6nUUYq/FMzyo/CmCZeLDGdjMB5ha6dh4
         oS9OmKhAowwQ4zHmKTMYaBZltOoDJ2InGWLTEnGo1t887c/3MslErLA7NlqQ4KjfXDm4
         1Q7MSHvkN7slKVQa7d0HubT51IVAPEBQwfkY5BcCsCI5TMXIF2Bu5ixZOOcFTIR60y1m
         bnrSTj0VryuVtS2PBcokCRLmRsEePx0mWMCVChWoy1ScQb+xRNpjNJWVJZno5aVMwFUJ
         WmOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AL+rMiDUuRLsqRvfIVnb3TpUrclwDJop9eZiZDegod4=;
        b=k2qLO2LxGbLHknwkdHUUUMOmxlMcGMxyYjDSX9GtSOJAsmwcZCllc2NtyO8iQ3i1f6
         m4I/0eZ2y+eD29DdJVj39B2fNfQquKe8mfUCs6hLHSKr0Xna10nkyNeolZwHieWuX2JP
         8V2CTiG+oZvNf7epbIUuR91YcwfCJnGz+NwZ71rklIDr/RPA4yh30yWyGhevwwq2GTi/
         AruZMUea29IO7vC370racTJpPHjv9jdpt24Ooff1MWU99b4XMHnVl8/v7ilKFOgdo6T6
         20jH7Qs+gVBwua240Ncs2WFHkqatDMvuQaFi/iEQRBlIDz+MK/L30kcDMQcNsVBIxHd0
         2V5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AL+rMiDUuRLsqRvfIVnb3TpUrclwDJop9eZiZDegod4=;
        b=etl2B9dsRSYFjZu8EVPGoqJHjLmVymKUkSwf+IFKsz5vVHoYEmQ2ny9aEl/HAU8tWM
         5OQR4Ss998DXeL9stJGLa7SVAcN7QoPTF/h5IeMlQgQseOlPq7qawNJtobL98qh8Iiq4
         f0rwb83tcaw1Pe1ZenYELSQbLNK2E4DzdtqeN3l5sc/QMo++CJW26ATLxTmjT8HfijmW
         UuVxExVuhttrSU6YY96IiQGbF0XvcxKxYAGKO+M5nJUqZXYLft94dA7a/IoWBl6pnvaz
         /jVKp5SUXec5UOsIkG+/CnF/v0CrJHexCCpSkdbn/1OH4rMZ5zTV/9sLMHymxu1iBrae
         hHEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531s0vDmRmcjyL8xQKAVLLeSUVOxeSI9DiAiS5X6cIre0st3Kf6r
	FAXK3+qTJwqN4xpVaft6s8M=
X-Google-Smtp-Source: ABdhPJwQvas4nw2IW6eeB/h3KY5xjlAeuMVg1IlfChFXws3AxShU8a0K4dI7+koDZyQyM15EjBSSSg==
X-Received: by 2002:a7b:c7ca:: with SMTP id z10mr3346445wmk.117.1614783163699;
        Wed, 03 Mar 2021 06:52:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls1323537wmb.2.gmail; Wed, 03
 Mar 2021 06:52:42 -0800 (PST)
X-Received: by 2002:a1c:acc2:: with SMTP id v185mr9510724wme.150.1614783162850;
        Wed, 03 Mar 2021 06:52:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614783162; cv=none;
        d=google.com; s=arc-20160816;
        b=02XNrYLVxUMEvPEUIL1WZuTfzJHiQZJIfs2GIOtDBWucGkseHTj3aFAE3dbAg3Ns7t
         1TRKdJMXpiXaQBy1P/7rpTKXW61ZpH+CiWv6dbmtNv8myVLWmaYa4XMrWGUV3PB0Yfb5
         EkPCFltS7QXGmTNkQF7EmWZgX4ieU8TZ4Ixlec6B01pxmqvJqcbAuTSNg+Ic8xA0f71M
         ygd5+nbvd7Uu+YwyppT3CC7OdKvWzSuIoSs+ng5uh1CP+l258EcDTHbOjECyv/Zf5V45
         AjyXWkQkkrLc3Nm6WvynFSmCtt5f1EktX2utd/oyT1n0oaghtYc/GbFvOzNUBRBwQHIX
         /nGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=uf1NKCoTwqwRqIaXstrOyFZRogtvVJhHM+c/HlcARak=;
        b=JcqlcG/97H8KtD+DmJP6hj3+K/z5YK66jKgwBvAMw6UIo6jEPlt0Gjgo+A+QWbdxOh
         vXsbHK0ShikGJ4XW9wdaWCfqAW0RlYpXyCQHaxtmZgkK9VBuRWPOgF8KsTeWsRCa/0+J
         I1IdedMZGUTMPOHWdY5g+InaTILai3jRenhUPiGKrck+cnQh/s6Mpx5jiiHKZhtMYQDt
         Cz8hdnvTqYdi9enJJ8rNR6znRF3YRss+fAFT03OaF/kgGwdCgkL8uzdG15I3TaNDbrMi
         wUMAqwwHgKrVzHVhSRiYYllz5tLH8sILrc47eOpqH+I/Y7Rx8nB+Qxq0xVjuHx3JZREu
         kd1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id k83si310464wma.0.2021.03.03.06.52.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 06:52:42 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DrH6K5yVWz9tyY7;
	Wed,  3 Mar 2021 15:52:41 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id rUeZkj7gGtB7; Wed,  3 Mar 2021 15:52:41 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DrH6K50QRz9tyY3;
	Wed,  3 Mar 2021 15:52:41 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 85C278B7E6;
	Wed,  3 Mar 2021 15:52:41 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id SVrpgpT8WrDo; Wed,  3 Mar 2021 15:52:41 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E37758B7DB;
	Wed,  3 Mar 2021 15:52:40 +0100 (CET)
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Marco Elver <elver@google.com>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
Date: Wed, 3 Mar 2021 15:52:25 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 03/03/2021 =C3=A0 15:38, Marco Elver a =C3=A9crit=C2=A0:
> On Wed, 3 Mar 2021 at 15:09, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>> It seems like all other sane architectures, namely x86 and arm64
>> at least, include the running function as top entry when saving
>> stack trace.
>>
>> Functionnalities like KFENCE expect it.
>>
>> Do the same on powerpc, it allows KFENCE to properly identify the faulti=
ng
>> function as depicted below. Before the patch KFENCE was identifying
>> finish_task_switch.isra as the faulting function.
>>
>> [   14.937370] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0x54/0x1=
08
>> [   14.948692]
>> [   14.956814] Invalid read at 0xdf98800a:
>> [   14.960664]  test_invalid_access+0x54/0x108
>> [   14.964876]  finish_task_switch.isra.0+0x54/0x23c
>> [   14.969606]  kunit_try_run_case+0x5c/0xd0
>> [   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
>> [   14.979079]  kthread+0x15c/0x174
>> [   14.982342]  ret_from_kernel_thread+0x14/0x1c
>> [   14.986731]
>> [   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B    =
         5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
>> [   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
>> [   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B              =
(5.12.0-rc1-01537-g95f6e2088d7e-dirty)
>> [   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000=
000
>> [   15.022043] DAR: df98800a DSISR: 20000000
>> [   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13c 00000=
008 c084b32b c016ebd8
>> [   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
>> [   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
>> [   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
>> [   15.051181] Call Trace:
>> [   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x54/0x23=
c (unreliable)
>> [   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
>> [   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_adapter+=
0x24/0x30
>> [   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
>> [   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
>> [   15.085798] Instruction dump:
>> [   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f0024 907=
f0028 90ff001c
>> [   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 8=
12a4b98 3d40c02f
>> [   15.104612] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
>=20
> Acked-by: Marco Elver <elver@google.com>
>=20
> Thank you, I think this looks like the right solution. Just a question be=
low:
>=20
...

>> @@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *trace)
>>
>>          sp =3D current_stack_frame();
>>
>> -       save_context_stack(trace, sp, current, 1);
>> +       save_context_stack(trace, sp, (unsigned long)save_stack_trace, c=
urrent, 1);
>=20
> This causes ip =3D=3D save_stack_trace and also below for
> save_stack_trace_tsk. Does this mean save_stack_trace() is included in
> the trace? Looking at kernel/stacktrace.c, I think the library wants
> to exclude itself from the trace, as it does '.skip =3D skipnr + 1' (and
> '.skip   =3D skipnr + (current =3D=3D tsk)' for the _tsk variant).
>=20
> If the arch-helper here is included, should this use _RET_IP_ instead?
>=20

Don't really know, I was inspired by arm64 which has:

void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
		     struct task_struct *task, struct pt_regs *regs)
{
	struct stackframe frame;

	if (regs)
		start_backtrace(&frame, regs->regs[29], regs->pc);
	else if (task =3D=3D current)
		start_backtrace(&frame,
				(unsigned long)__builtin_frame_address(0),
				(unsigned long)arch_stack_walk);
	else
		start_backtrace(&frame, thread_saved_fp(task),
				thread_saved_pc(task));

	walk_stackframe(task, &frame, consume_entry, cookie);
}


But looking at x86 you may be right, so what should be done really ?

Thanks
Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1802be3e-dc1a-52e0-1754-a40f0ea39658%40csgroup.eu.
