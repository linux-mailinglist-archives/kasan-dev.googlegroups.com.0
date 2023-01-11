Return-Path: <kasan-dev+bncBCV7JPVCWIDRB3GC7SOQMGQEETME36Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F5C966650E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 21:51:57 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id v23-20020a05600c215700b003d9e9974a05sf5959348wml.8
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 12:51:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673470317; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+r73lXYWo9uxuP/okxIQIqs9wqZ/N0xrZDAh9f3wZApiGXNtUVX3HRUdu0+6dWejq
         Fhv/zOHaBWmkeAj9tv6rk2FE+z+nnJJg97jmQfvYWzAx8aOQ6rK5j3rPfMt4LYrZxGd6
         Vl/LoJ7/zTZpx72Vi/P9wSnpFmCSCIQIDYNPd1oH/5GWZbmb6VcR76y4ddLsClOXYNS8
         s9dhrvhVmOfaem0lAifECLCUoioQ1McYLGhlEHC1lja4pk8HdSngHGSQCxKWp98hMYwe
         orfKA9ltyKrtJEG49wl+xiTqSfRc84phKCl1Qn/dJRlqmBBwHjtsZFFh8NS4oGllMA8E
         xtsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=1PS4Fur4L8XKhdaNHeOWJs9Z+3ZkXNRpet8gpOCmrkQ=;
        b=zLeWDnsqVh6OTsOJWP3LEFXbd5SHODq0BTgfGRdalT3aLe+hZS01oG6eWzZnyj80Uj
         uqOPiJ5UEW/Y8G4MUWdOczlnwUzOUmbSYdz9QKlRfdbOE7lEFt+iLDXkmtRk126N3feH
         bcCeL/vhJdGK+vQUAhCVLzJJQk0znHWkA+LdlBF5heYmjt7hukcdeqYw8dUKQLi/XKrJ
         fb9suvThWIKwGDmba3xkMuY0eMgtCoMTgxx5Tdvn84bALE1UxdP18Bn1tyaDJ4Mdm1qi
         4kNehZaCFlHGOMzjBtuW4iiqdR2ejSQvU+LaPuIE3RE2tJRiyhfQTcLueTjO+pDy+Zz+
         bdDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=XS3UABdq;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1PS4Fur4L8XKhdaNHeOWJs9Z+3ZkXNRpet8gpOCmrkQ=;
        b=V8erbq1x9lG7FWd9Mr94ImzNBP0m1yXcoM0+xZw/WlXDJRVwlkLjSvddVHLe+i/f6F
         CSGUsX4U9taEInHN2Jj28kVdwxDbDam5122QsB2/Bmi29enHKH1hJY7G61ofCE8ds7Ym
         Q+d7bxgT96bleFQLQ56VrYxuQNjva7qYhCIuHUr1I2bZINFNr2rWGckFeyEVu2Nx8Ty6
         s2M4tLrHtqS4WdVrQvNqZOVT7eqYPZs2Z9XH0SbZRlOytaCeNRlqvQcs2dLV87nk2V78
         3V25GYVwZtyfOATC3S4FoI5akpZ8FqolJ9nKNDdDh4ODYjFhLHFW7+YaPgO3s2aK5Dp4
         jCsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1PS4Fur4L8XKhdaNHeOWJs9Z+3ZkXNRpet8gpOCmrkQ=;
        b=WB1nI85A5/aFIbRDgSoPnaLgi7Ubuimt5udkrz8ehxs235g3Xkp66X6r3iBfntC/WH
         jSBaKcsKDVknQlCokUDq3nJVHQrNK0KZWUdIdAKGimblU4RdHkAFna23MH7vhvoEA0cG
         X9qORY7EMZh5nLD9Pof1zgHvknLUkINXtyvyR+zfdSsZp3bPYs1cdg1pQWqrU67fm4vh
         AGW5vTsRpInd6hLLLIw2BzWFm/yqLRARXtD31R4aFLVFy0licSM3ksYXa+19E5tsbzmg
         iBUr8F7FbeV1OabLqT6TF3ubLV88wzTGofiqJ8gNfDGDvZjIqlWODorzfLkez/wXRI5U
         OFRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kofnLjZrr3Iz0WTkUbJVY+zdIR/1dt76URFZZZfH/XsAMy4fIJ3
	ey6P18qo0dOYY5M7mcW/kwM=
X-Google-Smtp-Source: AMrXdXt1l6nIq8AsMJ3Rplfsuk24t46+ENxq8Jkpud7LAgOVe/gxgy4mudTDX0BqIOOy+HP/Z6vH6w==
X-Received: by 2002:adf:ffc6:0:b0:2bb:ec9b:6f23 with SMTP id x6-20020adfffc6000000b002bbec9b6f23mr637229wrs.66.1673470316973;
        Wed, 11 Jan 2023 12:51:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:541e:0:b0:3d9:de91:ba54 with SMTP id i30-20020a1c541e000000b003d9de91ba54ls415470wmb.0.-pod-preprod-gmail;
 Wed, 11 Jan 2023 12:51:56 -0800 (PST)
X-Received: by 2002:a05:600c:34d0:b0:3d6:b691:b80d with SMTP id d16-20020a05600c34d000b003d6b691b80dmr52740430wmq.21.1673470316066;
        Wed, 11 Jan 2023 12:51:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673470316; cv=none;
        d=google.com; s=arc-20160816;
        b=rwBaUphzys+8/lfVQixx8AXm/YJKDtlVJl73/2/If3ytARUDVTQCeOWlOy6CLUgmyE
         0kTQ2qq1cpB0OdXfqw5ccMreP5rWoWKTGM9vjyCYGqCDhLmHvEWmyisIppu3OHEbmiwa
         vbJ3JkTj4lchec+wyGKdmzGdjrl3Nu6/Z//1GL0WmKIssYYY06/tDJk28WaBFM2qQzO5
         98bIfyrtDQY70Z9DneBZ6NCbuG11I+MrccpI1PL/hz7QmyKSbhcyxWVt+Gxnyl9tI21s
         qOoB6zJCTCz8OC0KzI3d2Brjsglf9heSqHK18HYvObEVmMu1ipb9X0VACjw0AW8MV3WR
         yBqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=zuw6px+NzHkBNfjG6tvmZnr4uMKhAycqN8SZaVocX44=;
        b=eBYTE47yYoNEQqfqRTfKWi5/8A5/i+bVkiarifsOYFly1DYd1X1LLlsJJeogYGv9I/
         wpI+KP1DUttLtLuNDjSxPgpFgkJ7kYspbJhXtAje6zqB58tVnPRWuDIwOwdHZX2TaVX0
         zngh/HmaK57zWsNvGz5FObmunO9TpnGmDpDfweVjyM17YHnv0dsgVXerpb3/0PsVv5RI
         mHDGoZrmcbrKxpET7clQ0c3BDLG2apj3EObfHHM/JVmt/FosaojPbPhXvABuA7DtXJgp
         KU2opMjaQ8aD+E0YVhyuG1In9eurgOVKSjDoF9kiZKjxZf+Cdq7NMIpiL1kl2u7GLIaY
         7/3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=XS3UABdq;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id i17-20020a05600c355100b003d9c716fa3csi268937wmq.1.2023.01.11.12.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Jan 2023 12:51:56 -0800 (PST)
Received-SPF: pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id h16so16252357wrz.12
        for <kasan-dev@googlegroups.com>; Wed, 11 Jan 2023 12:51:55 -0800 (PST)
X-Received: by 2002:a05:6000:85:b0:2bc:7fdd:9245 with SMTP id m5-20020a056000008500b002bc7fdd9245mr6925493wrx.5.1673470315585;
        Wed, 11 Jan 2023 12:51:55 -0800 (PST)
Received: from smtpclient.apple (global-5-143.n-2.net.cam.ac.uk. [131.111.5.143])
        by smtp.gmail.com with ESMTPSA id u5-20020adfdb85000000b002ba2646fd30sm17254823wri.36.2023.01.11.12.51.54
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Jan 2023 12:51:54 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3696.120.41.1.1\))
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
From: Jessica Clarke <jrtc27@jrtc27.com>
In-Reply-To: <20230111190029.ltynngqnqs42gatd@orel>
Date: Wed, 11 Jan 2023 20:51:54 +0000
Cc: Jisheng Zhang <jszhang@kernel.org>,
 Palmer Dabbelt <palmer@dabbelt.com>,
 Paul Walmsley <paul.walmsley@sifive.com>,
 Albert Ou <aou@eecs.berkeley.edu>,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Alexandre Ghiti <alexandre.ghiti@canonical.com>,
 linux-riscv <linux-riscv@lists.infradead.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com
Message-Id: <391AFCB9-D314-4243-9E35-6D95B81C9400@jrtc27.com>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
 <Yz6T4EYKKns7OIVE@xhacker> <Y0GJDqLXFU81UdfW@xhacker>
 <Y5W0bv8Y/zCc+Fco@xhacker> <Y77xyNPNqnFQUqAx@xhacker>
 <20230111190029.ltynngqnqs42gatd@orel>
To: Andrew Jones <ajones@ventanamicro.com>
X-Mailer: Apple Mail (2.3696.120.41.1.1)
X-Original-Sender: jrtc27@jrtc27.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=XS3UABdq;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates
 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com
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

On 11 Jan 2023, at 19:00, Andrew Jones <ajones@ventanamicro.com> wrote:
> On Thu, Jan 12, 2023 at 01:28:40AM +0800, Jisheng Zhang wrote:
>> On Sun, Dec 11, 2022 at 06:44:04PM +0800, Jisheng Zhang wrote:
>>> On Sat, Oct 08, 2022 at 10:28:35PM +0800, Jisheng Zhang wrote:
>>>> On Thu, Oct 06, 2022 at 04:37:57PM +0800, Jisheng Zhang wrote:
>>>>> On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
>>>>>> On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
>>>>>>> The pgtable_l4|[l5]_enabled check sits at hot code path, performance
>>>>>>> is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
>>>>>>> boot, so static key can be used to solve the performance issue[1].
>>>>>>> 
>>>>>>> An unified way static key was introduced in [2], but it only targets
>>>>>>> riscv isa extension. We dunno whether SV48 and SV57 will be considered
>>>>>>> as isa extension, so the unified solution isn't used for
>>>>>>> pgtable_l4[l5]_enabled now.
>>>>>>> 
>>>>>>> patch1 fixes a NULL pointer deference if static key is used a bit earlier.
>>>>>>> patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
>>>>>>> 
>>>>>>> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
>>>>>>> [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
>>>>>>> 
>>>>>>> Since v5:
>>>>>>> - Use DECLARE_STATIC_KEY_FALSE
>>>>>>> 
>>>>>>> Since v4:
>>>>>>> - rebased on v5.19-rcN
>>>>>>> - collect Reviewed-by tags
>>>>>>> - Fix kernel panic issue if SPARSEMEM is enabled by moving the
>>>>>>>   riscv_finalise_pgtable_lx() after sparse_init()
>>>>>>> 
>>>>>>> Since v3:
>>>>>>> - fix W=1 call to undeclared function 'static_branch_likely' error
>>>>>>> 
>>>>>>> Since v2:
>>>>>>> - move the W=1 warning fix to a separate patch
>>>>>>> - move the unified way to use static key to a new patch series.
>>>>>>> 
>>>>>>> Since v1:
>>>>>>> - Add a W=1 warning fix
>>>>>>> - Fix W=1 error
>>>>>>> - Based on v5.18-rcN, since SV57 support is added, so convert
>>>>>>>   pgtable_l5_enabled as well.
>>>>>>> 
>>>>>>> 
>>>>>>> Jisheng Zhang (2):
>>>>>>>  riscv: move sbi_init() earlier before jump_label_init()
>>>>>>>  riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
>>>>>>> 
>>>>>>> arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>>>>>>> arch/riscv/include/asm/pgtable-32.h |  3 ++
>>>>>>> arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>>>>>>> arch/riscv/include/asm/pgtable.h    |  5 +--
>>>>>>> arch/riscv/kernel/cpu.c             |  4 +-
>>>>>>> arch/riscv/kernel/setup.c           |  2 +-
>>>>>>> arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>>>>>>> arch/riscv/mm/kasan_init.c          | 16 ++++----
>>>>>>> 8 files changed, 104 insertions(+), 66 deletions(-)
>>>>>> 
>>>>>> Sorry for being slow here, but it looks like this still causes some early
>>>>>> boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
>>>>>> see from the latency I'm still a bit buried right now so I'm not sure when
>>>>>> I'll have a chance to take more of a look.
>>>>> 
>>>>> Hi Palmer,
>>>>> 
>>>>> Before V4, there is a bug which can cause kernel panic when SPARSEMEM
>>>>> is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
>>>>> after sparse_init(). And I just tested the riscv-pgtable_static_key
>>>>> branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
>>>>> I'm not sure what happened. Could you please send me your kernel
>>>>> config file? I want to fix any issue which can block this series being
>>>>> merged in 6.1-rc1.
>>>> 
>>>> Hi Palmer,
>>>> 
>>>> I know you are busy ;) Do you have time to send me your test kernel
>>>> config file so that I can reproduce the "early boot hang"?
>>>> 
>>>> Thanks
>>> 
>>> Hi Palmer,
>>> 
>>> I think the early boot hangs maybe the same as the one which has been
>>> fixed by commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in
>>> kasan_init"). Will you give this series another try for v6.2-rc1? If
>>> the boot hang can still be reproduced, could you please send me your
>>> .config file?
>>> 
>>> Thanks in advance
>> Hi all,
>> 
>> Just request to comment what to do with this patch, I think there
>> are two independent points to consult:
>> 
>> 1. IIRC, Palmer gave this patch two chances to merge in early versions
>> but he found boot hangs if enable KASAN and SPARSEMEM, while I can't
>> reproduce the boot hang. And I also expect the hang should be fixed by
>> commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in kasan_init")
>> 
>> 2. Now we know alternative is preferred than static branch for ISA
>> extensions dynamic code patching. So we also need to switch static
>> branch usage here to alternative mechanism, but the problem is
>> SV48 and SV57 are not ISA extensions, so we can't directly make use
>> of the recently introduced riscv_has_extension_likely|unlikely()[1] 
>> which is based on alternative mechanism.
> 
> We could rename the "has_extension" framework to "has_cpufeature" and
> then lump extensions and features such as sv48 and sv57 together. Or,
> if it's best to keep extensions separate, then duplicate the framework
> to create a "has_non_extension_feature" version where features like
> sv48 and sv57 live.

Sv39, Sv48 and Sv57 are extensions these days (see the draft profiles
spec[1] and [2]).

Jess

[1] https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#522-rva20s64-mandatory-extensions
[2] https://wiki.riscv.org/display/HOME/Recently+Ratified+Extensions

> Thanks,
> drew
> 
>> 
>> Any comments are appreciated.
>> 
>> Thanks in advance
>> 
>> [1] https://lore.kernel.org/linux-riscv/20230111171027.2392-1-jszhang@kernel.org/T/#t
>> 
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/391AFCB9-D314-4243-9E35-6D95B81C9400%40jrtc27.com.
