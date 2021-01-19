Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYGVTSAAMGQEXJUOZIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 985E32FBF81
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:54:25 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id l3sf16224945ybl.17
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:54:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082464; cv=pass;
        d=google.com; s=arc-20160816;
        b=mwMIuX25kxmyL8+Q7qyeY3qxLEYbp1EfI8BzBrCJyjCJaeZmFT94Vl5tAcuLjulDS2
         N8z8ATDr91BP+P3biNeHSNEHToztSYa2CJeC8344e3sKOcUXobyZGNtIlDGoBWfOZOQy
         8Uz1lfKZ7w/IThMDSgDV7fvKB5eHQ37RH50CAas0MHg91lL1n0cXHN0bx8kKvgLgd7Y5
         0z637hcoXAc0KKBHakDQV/Zu91YNM0GT+RQ1oncGwYPfSAUGOjcaZUHuHgaG4r96klY8
         tVHljqRj8AD0iDVMBpEqKYFNjJuYhEICf/s/O1QwcfvhYozxYtioLNKZ3gbUjXVtdkya
         Pq3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qHH/kmZ6TF4pJEpvARMRCdpaEXvJh7zht2IO3qDoXuI=;
        b=xzl2c82tLC/HBpGqI3czVxmn5FkFrR5/CwAo185lcMNhWAk79SU+SuBUrgbac2VUHQ
         ou1ss821PV1ATS22p3oHdp28y4EknZaRIRdI+ZKAu/Lr2+wI9Ar7q1Gr2oZ5g9YHglVF
         Ko9xVcuHMbI8lxp1qVWYqwNfvB0YRtdDxoqNRjpXzSdXv+32t9sWfrAGAIUKMXWEy87s
         SNcCHkkjJUSyA+dT/oNHl7k06A2EdgVpkR376Jiqhodkfn6icu8hwxMxFBi4gfQ34ZCI
         w5Vxi7o9Kl6mfyB0er6YYpnNTHtJhtjufnwtghPNF4WtVjEZSO7HNom4CPayx/8hnNi7
         bL0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qHH/kmZ6TF4pJEpvARMRCdpaEXvJh7zht2IO3qDoXuI=;
        b=qMZUt3lxp292TKTUIMCx6W9pVxR4Gg47WVmzldPhTbK/S0cNI0ilbEbKaCLkTYOLPf
         621usO8c4a9wwaTKRbOtQLd+sVRCmErEPaWDnlZHW40XN1+SxPBYm2uHp/uX4wWRkL3Z
         vcRslxYXmAAVmLAhwhM+oaFRA5b3d5WyP5OsuR1v6MG4Yozl7Kr7laXN3eFKRLfTPYHm
         rhsMR1SQ9NeeFcouKH1n/e1sWunZxE7Fzc19XqdYplp349ij686cCUFVcNhKc0Y1Q/Uj
         qwCXi99DwcHMZ6osCE35bOdR23TPdW7SN5FGzPQA4MnkkoN2un3wpfZ9Gr9b8vSIlIVj
         aoww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qHH/kmZ6TF4pJEpvARMRCdpaEXvJh7zht2IO3qDoXuI=;
        b=UE+rdMhb+WFX9iygScHvmMXIh6X+0KNX9H5atuittH5aWg0CS7OYUWa28us+YOmNHi
         gNrKlTPSG1Fh4zy0lW2kTToLpg1q4fjyAEgE0IaStGnallx4cVjiYK4QTFqV5PonZZh6
         KqCwv0GR6+LAuMis+lSXCfp2PTbZP1wn9qzube86B0KhUEReT2AO0aqaWCrxBDxXo743
         FCxylAp1+9ZfVZhz6Mi3Gz9aIsl78hNJ6dyCg5rsVwIZdIXIyoOd02bTIlmtofTveWWL
         b3hHfaBAP3jsFMPKrEQLWC16dUUBidbAB+90zTKHB/rSupNlo5UgKG9A5dS+eOLRgc+z
         qNsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532S0w6ofkKJeUIrwFjetoO9Qr6CNM5pG5kX8AsKIHkw8o3Gl6sD
	uKw7qvdv8/2JtfAUcxB5j8c=
X-Google-Smtp-Source: ABdhPJxYvbqfoKDAFNPwuGXk24I5rlFui6jFvF2SCCrDQSYMDXZzDi5QsDkvCzCmNIu9z3SIRNuO/g==
X-Received: by 2002:a25:1541:: with SMTP id 62mr8432470ybv.484.1611082464709;
        Tue, 19 Jan 2021 10:54:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8188:: with SMTP id p8ls4766990ybk.6.gmail; Tue, 19 Jan
 2021 10:54:24 -0800 (PST)
X-Received: by 2002:a25:aa10:: with SMTP id s16mr7767342ybi.393.1611082464277;
        Tue, 19 Jan 2021 10:54:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082464; cv=none;
        d=google.com; s=arc-20160816;
        b=QpB8l820e7JR9OewFwjLEwHrMh5tZbWaI7X8UOoXwi8linQrvjBFELptv8QXfJsF4W
         OnxfMJcpGcd+Wup64nvcI0kyw6Jhb9VNWt7wXVLcTSVw1807DR0f04sXUm3o3OfFaUBt
         mM+mi3xFdlvMyubvrDWOjjPnSBSBRskukn3F3m11EzNBgD+k5H9VROM1b7emQ1t8Z2G4
         v5Q7e4PAkhK7xRJweIJtWqEKntoHV3+inyhifaVyp6HTThXVG9jjDE0UoDnoJ+bq8Cmr
         J72OGlKIeafT4LoxLI7xq46aoWdhpTS/lqJhm3C+uIGE54DiV9j4VdlVsgvZHSW0C10t
         V0GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=H54t4LyZwtMDie9gEEcPtE/uTiKhZ1S8YkhVcJ2itAk=;
        b=fce/MtbZmuj+IHSXvDHAAFD8C/ed1TrQvrBBEzcXQ1B5Ioja57AbLcqVW0Ld77iYf4
         8LCwLQm2E1xKOPeSqMfSUFGu1u/lvSrHmFTP8Ywk0Kmcf7+PS/55C32HuEz3dM63wy78
         SDq5qPK9EnWLh9K7SuSGqwQfef7klzScLUufDe3C8DJmRCrOx6DibFaXoR1Kk4OcZg24
         aaJ5YLIFKBHxJ3TF1PPxijxcBsXVVdOJfHXUJW5FSrYrjLWavVKCOhXQc6b/51SktRxn
         bQX0m+Rst33FgEqxqpQD/AyfYRjkQy1eKQFAMFwp4bRLlaG2EOfGsmW2tuadm/aq68Ns
         Jt7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x13si369552ybk.3.2021.01.19.10.54.24
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 10:54:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A5A9611B3;
	Tue, 19 Jan 2021 10:54:23 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4ECF33F719;
	Tue, 19 Jan 2021 10:54:22 -0800 (PST)
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <cc3a5a99-5c99-e526-a5e1-a566f8c412fb@arm.com>
Date: Tue, 19 Jan 2021 18:58:11 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 1/19/21 6:27 PM, Andrey Konovalov wrote:
> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
>> the address passed as a parameter.
>>
>> Add a comment to make sure that the preconditions to the function are
>> explicitly clarified.
>>
>> Note: An invalid address (e.g. NULL pointer address) passed to the
>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
>>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Leon Romanovsky <leonro@mellanox.com>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  mm/kasan/report.c | 11 +++++++++++
>>  1 file changed, 11 insertions(+)
>>
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index c0fb21797550..2485b585004d 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>         end_report(&flags);
>>  }
>>
>> +/**
>> + * kasan_report - report kasan fault details
>> + * @addr: valid address of the allocation where the tag fault was detected
>> + * @size: size of the allocation where the tag fault was detected
>> + * @is_write: the instruction that caused the fault was a read or write?
>> + * @ip: pointer to the instruction that cause the fault
>> + *
>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
>> + * the address to access the tags, hence it must be valid at this point in
>> + * order to not cause a kernel panic.
>> + */
> 
> It doesn't dereference the address, it just checks the tags, right?
> 

This is correct, just realized that the use of "dereference" here is misleading.

> Ideally, kasan_report() should survive that with HW_TAGS like with the
> other modes. The reason it doesn't is probably because of a blank
> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> guess we should somehow check that the memory comes from page_alloc or
> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> instruction to check whether the memory has tags?
> 

I agree, looking a second time at the code the problem comes from
addr_has_metadata():

...

[   18.127273] BUG: KASAN: invalid-access in 0x0
[   18.128604] Read at addr 0000000000000000 by task swapper/0/1
[   18.130311] Unable to handle kernel NULL pointer dereference at virtual
address 0000000000000000
[   18.131291] Mem abort info:
[   18.131696]   ESR = 0x96000004
[   18.132169]   EC = 0x25: DABT (current EL), IL = 32 bits
[   18.132953]   SET = 0, FnV = 0
[   18.133433]   EA = 0, S1PTW = 0
[   18.133907] Data abort info:
[   18.134308]   ISV = 0, ISS = 0x00000004
[   18.134883]   CM = 0, WnR = 0
[   18.135436] [0000000000000000] user address but active_mm is swapper
[   18.136372] Internal error: Oops: 96000004 [#1] PREEMPT SMP
[   18.137280] Modules linked in:
[   18.138182] CPU: 2 PID: 1 Comm: swapper/0 Not tainted
5.11.0-rc4-00007-g86cba71f117-dirty #2
[   18.139275] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2015
[   18.140342] pstate: 60400085 (nZCv daIf +PAN -UAO -TCO BTYPE=--)
[   18.141324] pc : mte_get_mem_tag+0x24/0x40
[   18.142487] lr : print_tags+0x1c/0x40
[   18.143095] sp : ffff80001004bcf0
[   18.143570] x29: ffff80001004bcf0 x28: 0000000000000000
[   18.144526] x27: ffffd042f0bf04e0 x26: ffffd042f0ca1068
[   18.145369] x25: ffffd042f0bdde58 x24: ffffd042f1458000
[   18.146209] x23: 0000000000000000 x22: 0000000000000000
[   18.147047] x21: 0000000000000000 x20: 0000000000000000
[   18.147928] x19: 0000000000000000 x18: ffffffffffffffff
[   18.148928] x17: 000000000000000e x16: 0000000000000001
[   18.149837] x15: ffff80009004ba17 x14: 0000000000000006
[   18.150774] x13: ffffd042f11b27e0 x12: 0000000000000399
[   18.151653] x11: 0000000000000133 x10: ffffd042f11b27e0
[   18.152544] x9 : ffffd042f11b27e0 x8 : 00000000ffffefff
[   18.153443] x7 : ffffd042f120a7e0 x6 : ffffd042f120a7e0
[   18.154272] x5 : 000000000000bff4 x4 : 0000000000000000
[   18.155096] x3 : 0000000000000000 x2 : 0000000000000000
[   18.155958] x1 : 0000000000000000 x0 : 0000000000000000
[   18.157145] Call trace:
[   18.157615]  mte_get_mem_tag+0x24/0x40
[   18.158258]  kasan_report+0xec/0x1b0

...

I noticed it differently but you can easily reproduce it calling
kasan_report(0,0,0,0); from somewhere.

I will send a patch tomorrow that checks if the memory comes from page_alloc or
kmalloc. Not sure what you mean for "instruction to check whether the memory has
tags".

Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cc3a5a99-5c99-e526-a5e1-a566f8c412fb%40arm.com.
