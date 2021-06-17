Return-Path: <kasan-dev+bncBC447XVYUEMRBPUGVSDAMGQESQJ5G7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC363AAE77
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:09:35 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 1-20020a2e0d010000b029015d8fce4f1bsf2345460ljn.17
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 01:09:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623917375; cv=pass;
        d=google.com; s=arc-20160816;
        b=ayYVu4dFjAgiwfb73OnuoKjn6gDzr1MypBz8M7BWp62V/iCfZRI8/lgUF7LkAXlLEL
         KWHLn7lWl6ErSrpaHIHsjS8nvd0yDbxXwamfSn2QPTzbpPMbYwh2hX/A1jkUhAJPmp8q
         Rbis5jJWqCopw+Y5XjuTAGu0/430i0dMV7uhGeEbffE5sCDExx8jZi3UvbB4lw/K3/yl
         h9eLnDB7oONnQaeGi6OuihrVPR8M1XAToDpcnkSleZ+0b8CKafQg2oTAUOhjMl5ZluMd
         lxCnIy4z+gk/YQ7mkRID2xUJRsArB2d7W8f+IL1a7O8ApGFl2MokSr1fXpA7o1A3Bg2p
         rcCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=C3qciequmK3o5MHcOZYGmKD35DQcWucyePMg+wEC7Lw=;
        b=p/MTKFccTMQuhfdJq9w5NK+SNFWTvBRMx+sraNLAnBnX+zYvcti1HPKLUdnCIh62di
         E6rk9CaAKPGnMnSwMT6awKefwF4/U40f4GLkTjTumPIH5HwwcDs0S+Q1JVkLPXPaY/Ox
         eqUFTRfSPS1yYqzqR0PpHtvXbM2kd/sovS1lW+fkwajsE+Z43tnEdURG8Fxwd/QlpBLP
         EAhXJVLMHMmMWBhqya9O+pE+NFlvxVs4ALi208iZC705l3+P/goPSj0jWhpksqct6oS2
         WQfdcvpfUuZxUN895Hsp8AjX3D0U18nN83MJNfkouMBoKKrxnSGZCjo9i83je269k4ou
         CU/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3qciequmK3o5MHcOZYGmKD35DQcWucyePMg+wEC7Lw=;
        b=Xvdy6VKRArECvWeeF2Z8Nw/GHk8kmoMZPAEZyCWJjWYOnksS6ib+O7tqGkZPUBWIuU
         CGWeBwk7kqsYtnFPgUUjXrM0GU4f9MB1mtsGjXrLhlYX/dUyziR0FaiwYZOcJSyMjGxe
         ZYtYMY46pMOQy1emeAHMCGuZ5mjqShEAUafqvK2ZvI0TF5SEj5ZCet83nkK1A8tYdBsq
         nMV6tMNvXManff6Sqq2gfh7PuQPVn0Fomo3iKFrKdI/CWGcV3omcPHYaNt0p2pxS6LiF
         2knm5AV5uaXP9GITbSMS2gCeRbZLuwS8bISxa6Hb50DQqBS6I0eefdlx/+oCq3X5+oe0
         ypTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C3qciequmK3o5MHcOZYGmKD35DQcWucyePMg+wEC7Lw=;
        b=jvbemRreG/7X90m7kuP9jKEYVm1g3leuEqhzIovjv0UWEhrYJ/fNNCIDUgP0W4tndl
         OW7KhGCGNfARfTHgmv4et6Kz2msbFGwbiZ0jbqjQ7Y/lBK0AKPneTl2Ks7XsAJhydlbV
         mMJHDLUHAo1cwEKzMs/Ro05xdDSHtBwTbyKIe0bJyrWNiN99KWRvkd4U+rLa8LGpT8PQ
         HmA6NfSMBzWFQb3T3GUQA4E8R7f0ogQRBxVHYqhGFjmNrVujBJK77X8spnS9c/lVVLPE
         NT9icIqjmHIiUwilL17FGR6hYoc1zZW3is9UfOzyS2ZQHInAuKHEG6Yi1MHuPFjtr0TZ
         EUTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MKQe68Sy9WzDMU2cWSEwt0+UzU4yJT19fCAsMyHmCdF7CmGdB
	HD/RiijwJz5TaCQhfZ+pIaY=
X-Google-Smtp-Source: ABdhPJzcsBXrC/dJNCRDYpOCYg28iY9ty1XFQ6zt7vR6IC9r3kaC69yDa8Qnop6XsKEX+ynEmSK3Hw==
X-Received: by 2002:a05:6512:318d:: with SMTP id i13mr3164183lfe.407.1623917375169;
        Thu, 17 Jun 2021 01:09:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f515:: with SMTP id j21ls730769lfb.1.gmail; Thu, 17 Jun
 2021 01:09:34 -0700 (PDT)
X-Received: by 2002:a19:384f:: with SMTP id d15mr3104762lfj.410.1623917374115;
        Thu, 17 Jun 2021 01:09:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623917374; cv=none;
        d=google.com; s=arc-20160816;
        b=1Ddjh94HJm9SNT7K45iZ4Fds84nKWcofH6ZSrV1AnIFRNcKAEY+6pAAtsfbr1+W6DA
         gk6GSINKOgQccaW7QzKzq83EUvSrtKHpZzYVxuBcOV22bALddo89iDpGggJDt7pkOLcp
         iaOOBQqFc5bxuoQdVEN9rDOvbGS++ze9tj6aWgfs1xtQPNJAjrwMqEBnhJ1hYK9V1m0G
         vnKH8+EDikF0GCg6SQVwjAmFa1ZQSV/tLenlwRHQ/O49N3WcxVjgOAJpw9H9zb/5hZk5
         4oe5aJkcfyFu3w9yjUARu+7FpCrHitHnSsHj4rbNL/1Iuv4kjgrKOxifRDCDQh0ecIet
         +iuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=r/Ie6FRKOKp89jn6KTmD2VT1ADq3AETGG5IMzkkGEpw=;
        b=XvI5sBSQS/LGNxPQh5/ahOifMBHdp87Mgkg6rq2EFVXzFeCf2Kh1ZSVYiK/dSeQRt1
         Wj3g7Dmo7tdW6z7CaRPH8832eZHts0cL+By6yTir3jXc5KK0i0E+pdLqYTWywebT2uHh
         gTuD1+98PZdnNb08vvOEZBk3rX41mqcf1Shvr/PTdMGDq4pfwfHEpZmre9zKcWzuEeIQ
         xN3U3G6lv4gT2dGSqz8/Ox7pckzIUgGnWXujZCSqOqqJZD/DhLqQxH0ZHEf4OdD9iyWx
         d7O+Dra7Iypx/79ZyM7F7hgazttSqDMgDfwo1ZXoqwC+LUwWs8/2Bp51HdJV3G9Buvev
         aqIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id d18si134300lfv.3.2021.06.17.01.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 17 Jun 2021 01:09:33 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 4B98A20017;
	Thu, 17 Jun 2021 08:09:23 +0000 (UTC)
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
To: Palmer Dabbelt <palmer@dabbelt.com>, jszhang3@mail.ustc.edu.cn
Cc: schwab@linux-m68k.org, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, bjorn@kernel.org, ast@kernel.org,
 daniel@iogearbox.net, andrii@kernel.org, kafai@fb.com,
 songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com,
 kpsingh@kernel.org, luke.r.nels@gmail.com, xi.wang@gmail.com,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
References: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
Date: Thu, 17 Jun 2021 10:09:22 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Le 17/06/2021 =C3=A0 09:30, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Tue, 15 Jun 2021 17:03:28 PDT (-0700), jszhang3@mail.ustc.edu.cn wrote=
:
>> On Tue, 15 Jun 2021 20:54:19 +0200
>> Alex Ghiti <alex@ghiti.fr> wrote:
>>
>>> Hi Jisheng,
>>
>> Hi Alex,
>>
>>>
>>> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:
>>> > From: Jisheng Zhang <jszhang@kernel.org>
>>> > > Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking=
=20
>>> W^X")
>>> > breaks booting with one kind of config file, I reproduced a kernel=20
>>> panic
>>> > with the config:
>>> > > [=C2=A0=C2=A0=C2=A0 0.138553] Unable to handle kernel paging reques=
t at virtual=20
>>> address ffffffff81201220
>>> > [=C2=A0=C2=A0=C2=A0 0.139159] Oops [#1]
>>> > [=C2=A0=C2=A0=C2=A0 0.139303] Modules linked in:
>>> > [=C2=A0=C2=A0=C2=A0 0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not taint=
ed=20
>>> 5.13.0-rc5-default+ #1
>>> > [=C2=A0=C2=A0=C2=A0 0.139934] Hardware name: riscv-virtio,qemu (DT)
>>> > [=C2=A0=C2=A0=C2=A0 0.140193] epc : __memset+0xc4/0xfc
>>> > [=C2=A0=C2=A0=C2=A0 0.140416]=C2=A0 ra : skb_flow_dissector_init+0x1e=
/0x82
>>> > [=C2=A0=C2=A0=C2=A0 0.140609] epc : ffffffff8029806c ra : ffffffff803=
3be78 sp :=20
>>> ffffffe001647da0
>>> > [=C2=A0=C2=A0=C2=A0 0.140878]=C2=A0 gp : ffffffff81134b08 tp : ffffff=
e001654380 t0 :=20
>>> ffffffff81201158
>>> > [=C2=A0=C2=A0=C2=A0 0.141156]=C2=A0 t1 : 0000000000000002 t2 : 000000=
0000000154 s0 :=20
>>> ffffffe001647dd0
>>> > [=C2=A0=C2=A0=C2=A0 0.141424]=C2=A0 s1 : ffffffff80a43250 a0 : ffffff=
ff81201220 a1 :=20
>>> 0000000000000000
>>> > [=C2=A0=C2=A0=C2=A0 0.141654]=C2=A0 a2 : 000000000000003c a3 : ffffff=
ff81201258 a4 :=20
>>> 0000000000000064
>>> > [=C2=A0=C2=A0=C2=A0 0.141893]=C2=A0 a5 : ffffffff8029806c a6 : 000000=
0000000040 a7 :=20
>>> ffffffffffffffff
>>> > [=C2=A0=C2=A0=C2=A0 0.142126]=C2=A0 s2 : ffffffff81201220 s3 : 000000=
0000000009 s4 :=20
>>> ffffffff81135088
>>> > [=C2=A0=C2=A0=C2=A0 0.142353]=C2=A0 s5 : ffffffff81135038 s6 : ffffff=
ff8080ce80 s7 :=20
>>> ffffffff80800438
>>> > [=C2=A0=C2=A0=C2=A0 0.142584]=C2=A0 s8 : ffffffff80bc6578 s9 : 000000=
0000000008 s10:=20
>>> ffffffff806000ac
>>> > [=C2=A0=C2=A0=C2=A0 0.142810]=C2=A0 s11: 0000000000000000 t3 : ffffff=
fffffffffc t4 :=20
>>> 0000000000000000
>>> > [=C2=A0=C2=A0=C2=A0 0.143042]=C2=A0 t5 : 0000000000000155 t6 : 000000=
00000003ff
>>> > [=C2=A0=C2=A0=C2=A0 0.143220] status: 0000000000000120 badaddr: fffff=
fff81201220=20
>>> cause: 000000000000000f
>>> > [=C2=A0=C2=A0=C2=A0 0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
>>> > [=C2=A0=C2=A0=C2=A0 0.143859] [<ffffffff8061e984>]=20
>>> init_default_flow_dissectors+0x22/0x60
>>> > [=C2=A0=C2=A0=C2=A0 0.144092] [<ffffffff800010fc>] do_one_initcall+0x=
3e/0x168
>>> > [=C2=A0=C2=A0=C2=A0 0.144278] [<ffffffff80600df0>] kernel_init_freeab=
le+0x1c8/0x224
>>> > [=C2=A0=C2=A0=C2=A0 0.144479] [<ffffffff804868a8>] kernel_init+0x12/0=
x110
>>> > [=C2=A0=C2=A0=C2=A0 0.144658] [<ffffffff800022de>] ret_from_exception=
+0x0/0xc
>>> > [=C2=A0=C2=A0=C2=A0 0.145124] ---[ end trace f1e9643daa46d591 ]---
>>> > > After some investigation, I think I found the root cause: commit
>>> > 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
>>> > BPF JIT region after the kernel:
>>> > > The &_end is unlikely aligned with PMD size, so the front bpf jit
>>> > region sits with part of kernel .data section in one PMD size mapping=
.
>>> > But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
>>> > called to make the first bpf jit prog ROX, we will make part of kerne=
l
>>> > .data section RO too, so when we write to, for example memset the
>>> > .data section, MMU will trigger a store page fault.
>>> Good catch, we make sure no physical allocation happens between _end=20
>>> and the next PMD aligned address, but I missed this one.
>>>
>>> > > To fix the issue, we need to ensure the BPF JIT region is PMD size
>>> > aligned. This patch acchieve this goal by restoring the BPF JIT regio=
n
>>> > to original position, I.E the 128MB before kernel .text section.
>>> But I disagree with your solution: I made sure modules and BPF=20
>>> programs get their own virtual regions to avoid worst case scenario=20
>>> where one could allocate all the space and leave nothing to the other=
=20
>>> (we are limited to +- 2GB offset). Why don't just align=20
>>> BPF_JIT_REGION_START to the next PMD aligned address?
>>
>> Originally, I planed to fix the issue by aligning=20
>> BPF_JIT_REGION_START, but
>> IIRC, BPF experts are adding (or have added) "Calling kernel functions=
=20
>> from BPF"
>> feature, there's a risk that BPF JIT region is beyond the 2GB of=20
>> module region:
>>
>> ------
>> module
>> ------
>> kernel
>> ------
>> BPF_JIT
>>
>> So I made this patch finally. In this patch, we let BPF JIT region sit
>> between module and kernel.
>>
>> To address "make sure modules and BPF programs get their own virtual=20
>> regions",
>> what about something as below (applied against this patch)?
>>
>> diff --git a/arch/riscv/include/asm/pgtable.h=20
>> b/arch/riscv/include/asm/pgtable.h
>> index 380cd3a7e548..da1158f10b09 100644
>> --- a/arch/riscv/include/asm/pgtable.h
>> +++ b/arch/riscv/include/asm/pgtable.h
>> @@ -31,7 +31,7 @@
>> =C2=A0#define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>> =C2=A0#ifdef CONFIG_64BIT
>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END=
 -=20
>> BPF_JIT_REGION_SIZE)
>> -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)=
&_start))
>> =C2=A0#else
>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - BPF_=
JIT_REGION_SIZE)
>> =C2=A0#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>> @@ -40,7 +40,7 @@
>> =C2=A0/* Modules always live before the kernel */
>> =C2=A0#ifdef CONFIG_64BIT
>> =C2=A0#define MODULES_VADDR=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)=
&_end) - SZ_2G)
>> -#define MODULES_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_start=
))
>> +#define MODULES_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END)
>> =C2=A0#endif
>>
>>
>>
>>>
>>> Again, good catch, thanks,
>>>
>>> Alex
>>>
>>> > > Reported-by: Andreas Schwab <schwab@linux-m68k.org>
>>> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
>>> > ---
>>> >=C2=A0=C2=A0 arch/riscv/include/asm/pgtable.h | 5 ++---
>>> >=C2=A0=C2=A0 1 file changed, 2 insertions(+), 3 deletions(-)
>>> > > diff --git a/arch/riscv/include/asm/pgtable.h=20
>>> b/arch/riscv/include/asm/pgtable.h
>>> > index 9469f464e71a..380cd3a7e548 100644
>>> > --- a/arch/riscv/include/asm/pgtable.h
>>> > +++ b/arch/riscv/include/asm/pgtable.h
>>> > @@ -30,9 +30,8 @@
>>> > >=C2=A0=C2=A0 #define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>>> >=C2=A0=C2=A0 #ifdef CONFIG_64BIT
>>> > -/* KASLR should leave at least 128MB for BPF after the kernel */
>>> > -#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 PFN_ALIGN((unsigned l=
ong)&_end)
>>> > -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_START +=
=20
>>> BPF_JIT_REGION_SIZE)
>>> > +#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END -=
=20
>>> BPF_JIT_REGION_SIZE)
>>> > +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
>>> >=C2=A0=C2=A0 #else
>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFS=
ET - BPF_JIT_REGION_SIZE)
>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END=
)
>>> >=20
>=20
> This, when applied onto fixes, is breaking early boot on KASAN=20
> configurations for me.

Not surprising, I took a shortcut when initializing KASAN for modules,=20
kernel and BPF:

         kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
                        kasan_mem_to_shadow((const void=20
*)BPF_JIT_REGION_END));

The kernel is then not covered, I'm taking a look at how to fix that=20
properly.

>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ae256a5d-70ac-3a5f-ca55-5e4210a0624c%40ghiti.fr.
