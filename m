Return-Path: <kasan-dev+bncBCOJLJOJ7AARBUEO7SOQMGQE3IV3K5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FE5F666334
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 20:00:33 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id c66-20020a1c3545000000b003d355c13229sf11147838wma.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 11:00:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673463633; cv=pass;
        d=google.com; s=arc-20160816;
        b=v7M0KroS7uBnLcYLWfKyBlqcm2Rula46G0CFxSCAw6kJOSK3bo4ornYusW1TLoR364
         OymgLGiHGRXvM4WhfUknWTGMbiCRcEJ/yyyxomP9gMTzDbZlu/cQexNaiFfz/txmilel
         BR/jP9D4fPuRqQZDXu9+wTioOC3+9Xix9UUlkC2Sos+ytm6QNxbVhr7RxYDN4Rmg7Rme
         oHuxiz1bmAJp3V1WFUSCPiubH1qtCW+if/U1XuIAATC0cytWijiDWQO8f6ds3/wGJDl1
         zCK4Cei/Hldvt6icJVMM5ZhvIoOX/PLX9QEVuGkOLPS2j+q4NkhMle0wBlnjhycstbJ+
         jFsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hWEhXWi+32aoS0bHVpPp4aj8qQTDeDL3kg8b8bM344Y=;
        b=g57BrreFjZe8m1e7Y1mIpoLNzm5SO0JZ/Iu5RAja84upgp+pRV2o1c3UER2V2qXM77
         4RcnJsSXf0Hzc2Uq6Lfws8VrmzD07uDVk1vJJZhkc0BvA0vKHgSpuA377rRzYFPN/jiT
         1D7EdOaZq2lYEsMOoteppQIkrWp3gPDXmNTWJkT0+jdH/nttGM1kjy8PBUwiXWDe9IlE
         B4JmKrVhdUeJNribX7VNPZO+zKeN9DPjHt4uIC/JFyDzPR/9nUhLJjzP5Jqc2z29QKmZ
         5HYaXgPKuvFPZgpomQiX4m62FrO2OTU9Snb1ijosQv0/x1XGQYV0vH2PGxyP0sTND2Xs
         em7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=Xy8x8icI;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hWEhXWi+32aoS0bHVpPp4aj8qQTDeDL3kg8b8bM344Y=;
        b=ShIkIqX0yUVOzi20jyD2pTIgiGygKnPsysgFIKgRUs5eJuNQWfP/4mhTQJkvMVTOEi
         BtK2lq7wJFP1jM1mBAyLnoa16piTS+AE2rqFIah4jjMIhC9Dm1Ea2rfz4U10CqfucRFV
         4upL1NiAbGxaz9FpOXeqTRhRzTib8x/gyQhCo1d9ogLmCwfKQbyAfVc7AvXcnYCC11zu
         It7kBekRr6MV12aCUaXcoKwIcDmPSq+z6I8IKU+uLECAxA1NZBAsxyq81eD73L99LzGS
         oiyeIIrhJXbzeR9Ew9eyX5JwrxlVMa69CdF24VwPkUVh8/6HyKanXcOrbzhbjR9Obh2u
         yXOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hWEhXWi+32aoS0bHVpPp4aj8qQTDeDL3kg8b8bM344Y=;
        b=A9cPfUYY5Z7Ru8Q5tQXPtNtIHkne2lMIzbdQck8XLkNvw3HfrcIALR98j2EH6qMlvl
         3zqvU4bUfvRgatv4dYYEvzu1zH+Kb+o+5Z6fEnJVYGAUvJ3QjVbcSSzTDoDiumoPq61d
         4BoR+8ytBIL31HZkGo9JogfjqHfI8E5XmiXQ+iFK6O3IGYYoI5GHe475GZY5vieAPkWf
         xrEXumfGtwfr/QpVZ3rwcN2Eq6X2P/krcOY/a9RnnzCfy0+VT1fdPTMZLip2QalMGhds
         db0p32B+nYwomjoTABxLN0lNtnFWHDVqQkBFUCthikJljjZZBnf9Mz/A0oyOjvkL2lQV
         EMig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqQh3Q7wtAvU0y/Q0z1h0odBIiiH41b1V6754Pibq9OvC9UaNSu
	RRW3JT76IhdtJBvSj0E53tc=
X-Google-Smtp-Source: AMrXdXtyUFIRDljZsC85Na37z6sYi8I43XiYWClIkVfIiD+t1bJJyWRegj8sVIaO/PClEgb/6efaBw==
X-Received: by 2002:a05:600c:1613:b0:3c6:c2ae:278b with SMTP id m19-20020a05600c161300b003c6c2ae278bmr4339488wmn.127.1673463632807;
        Wed, 11 Jan 2023 11:00:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:59c9:0:b0:298:bd4a:4dd9 with SMTP id v9-20020a5d59c9000000b00298bd4a4dd9ls888157wry.1.-pod-prod-gmail;
 Wed, 11 Jan 2023 11:00:31 -0800 (PST)
X-Received: by 2002:a5d:5405:0:b0:284:8a24:59e6 with SMTP id g5-20020a5d5405000000b002848a2459e6mr33724258wrv.3.1673463631720;
        Wed, 11 Jan 2023 11:00:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673463631; cv=none;
        d=google.com; s=arc-20160816;
        b=I6kRN1nT82qxCwD16J33TW212p8kFo6hFcA6ibISBWZIbnKwAYQOSg7KPlmvjJ0Bl5
         BT6q53YAWweQapHN//WtbiTEhVvOr86urG5UaZ5Q8j9EcygidO+q53PhaBkiUDF2kPFR
         6KKTLmeSNvmg8KgipIXdMZ9kBVDbPFkHm1go/wdMaEzVf+cAIa17SEI80Lxf1PfHIotb
         A8W/3TEzzT82TVYr3urZC6lqVEbMUR4XDYYIFqugR01/NTRHFywRj1/ziQO31/40PMbK
         kHsP3YshwQcjHCXVXLnwsYW7NfhN6Yuu5OqanbP6lPLZ92MHu/iAuzVJE5B5WFobQ9Iy
         17eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AxzGT4R96/nRowldYLVDQHHEyiV31tMmTSZl+oggOxc=;
        b=eQ9e/f8WXFzHmgW63LGrnFvl0uB6dVRPD8nsoYgi+zS2mMW7d9i5/6qM5iMkR/uqnv
         Xlj0U/hY9pE0D0aa1snLsqngqhDdbF9S1JuqRyJ8LElSiPPww4I4OTfg34X78awy1eox
         Q2PaHhlIauh6VKOOh9J3FGR9fd/4xZSbW4QLmIiJm9xDJKP6yZfy3X3JND4XYTVHMZG/
         ebltYYrnCnAkHFgyx65IirP5+bf1p3duZrYuoSnKqclSTHODTtV61lPzQRPQpnG+DBuF
         z3bjfZ9wx6xJ8Kv4QRHaupUzjWWPoZmnJ4l0fU3H5zA95t4aCLniuAHH0uQLS+lEyOjq
         weGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=Xy8x8icI;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id ay5-20020a5d6f05000000b002b57bae7176si663764wrb.1.2023.01.11.11.00.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Jan 2023 11:00:31 -0800 (PST)
Received-SPF: pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id bg13-20020a05600c3c8d00b003d9712b29d2so15093543wmb.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Jan 2023 11:00:31 -0800 (PST)
X-Received: by 2002:a1c:6a16:0:b0:3c6:f732:bf6f with SMTP id f22-20020a1c6a16000000b003c6f732bf6fmr52927572wmc.13.1673463631368;
        Wed, 11 Jan 2023 11:00:31 -0800 (PST)
Received: from localhost (cst2-173-16.cust.vodafone.cz. [31.30.173.16])
        by smtp.gmail.com with ESMTPSA id 2-20020a05600c020200b003d9ef8ad6b2sm11136454wmi.13.2023.01.11.11.00.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Jan 2023 11:00:31 -0800 (PST)
Date: Wed, 11 Jan 2023 20:00:29 +0100
From: Andrew Jones <ajones@ventanamicro.com>
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Palmer Dabbelt <palmer@dabbelt.com>,
	Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
Message-ID: <20230111190029.ltynngqnqs42gatd@orel>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
 <Yz6T4EYKKns7OIVE@xhacker>
 <Y0GJDqLXFU81UdfW@xhacker>
 <Y5W0bv8Y/zCc+Fco@xhacker>
 <Y77xyNPNqnFQUqAx@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y77xyNPNqnFQUqAx@xhacker>
X-Original-Sender: ajones@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=Xy8x8icI;       spf=pass
 (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
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

On Thu, Jan 12, 2023 at 01:28:40AM +0800, Jisheng Zhang wrote:
> On Sun, Dec 11, 2022 at 06:44:04PM +0800, Jisheng Zhang wrote:
> > On Sat, Oct 08, 2022 at 10:28:35PM +0800, Jisheng Zhang wrote:
> > > On Thu, Oct 06, 2022 at 04:37:57PM +0800, Jisheng Zhang wrote:
> > > > On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
> > > > > On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
> > > > > > The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> > > > > > is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> > > > > > boot, so static key can be used to solve the performance issue[1].
> > > > > > 
> > > > > > An unified way static key was introduced in [2], but it only targets
> > > > > > riscv isa extension. We dunno whether SV48 and SV57 will be considered
> > > > > > as isa extension, so the unified solution isn't used for
> > > > > > pgtable_l4[l5]_enabled now.
> > > > > > 
> > > > > > patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> > > > > > patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> > > > > > 
> > > > > > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > > > > > [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
> > > > > > 
> > > > > > Since v5:
> > > > > >  - Use DECLARE_STATIC_KEY_FALSE
> > > > > > 
> > > > > > Since v4:
> > > > > >  - rebased on v5.19-rcN
> > > > > >  - collect Reviewed-by tags
> > > > > >  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
> > > > > >    riscv_finalise_pgtable_lx() after sparse_init()
> > > > > > 
> > > > > > Since v3:
> > > > > >  - fix W=1 call to undeclared function 'static_branch_likely' error
> > > > > > 
> > > > > > Since v2:
> > > > > >  - move the W=1 warning fix to a separate patch
> > > > > >  - move the unified way to use static key to a new patch series.
> > > > > > 
> > > > > > Since v1:
> > > > > >  - Add a W=1 warning fix
> > > > > >  - Fix W=1 error
> > > > > >  - Based on v5.18-rcN, since SV57 support is added, so convert
> > > > > >    pgtable_l5_enabled as well.
> > > > > > 
> > > > > > 
> > > > > > Jisheng Zhang (2):
> > > > > >   riscv: move sbi_init() earlier before jump_label_init()
> > > > > >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> > > > > > 
> > > > > >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> > > > > >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> > > > > >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> > > > > >  arch/riscv/include/asm/pgtable.h    |  5 +--
> > > > > >  arch/riscv/kernel/cpu.c             |  4 +-
> > > > > >  arch/riscv/kernel/setup.c           |  2 +-
> > > > > >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> > > > > >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> > > > > >  8 files changed, 104 insertions(+), 66 deletions(-)
> > > > > 
> > > > > Sorry for being slow here, but it looks like this still causes some early
> > > > > boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
> > > > > see from the latency I'm still a bit buried right now so I'm not sure when
> > > > > I'll have a chance to take more of a look.
> > > > 
> > > > Hi Palmer,
> > > > 
> > > > Before V4, there is a bug which can cause kernel panic when SPARSEMEM
> > > > is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
> > > > after sparse_init(). And I just tested the riscv-pgtable_static_key
> > > > branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
> > > > I'm not sure what happened. Could you please send me your kernel
> > > > config file? I want to fix any issue which can block this series being
> > > > merged in 6.1-rc1.
> > > 
> > > Hi Palmer,
> > > 
> > > I know you are busy ;) Do you have time to send me your test kernel
> > > config file so that I can reproduce the "early boot hang"?
> > > 
> > > Thanks
> > 
> > Hi Palmer,
> > 
> > I think the early boot hangs maybe the same as the one which has been
> > fixed by commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in
> > kasan_init"). Will you give this series another try for v6.2-rc1? If
> > the boot hang can still be reproduced, could you please send me your
> > .config file?
> > 
> > Thanks in advance
> Hi all,
> 
> Just request to comment what to do with this patch, I think there
> are two independent points to consult:
> 
> 1. IIRC, Palmer gave this patch two chances to merge in early versions
> but he found boot hangs if enable KASAN and SPARSEMEM, while I can't
> reproduce the boot hang. And I also expect the hang should be fixed by
> commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in kasan_init")
> 
> 2. Now we know alternative is preferred than static branch for ISA
> extensions dynamic code patching. So we also need to switch static
> branch usage here to alternative mechanism, but the problem is
> SV48 and SV57 are not ISA extensions, so we can't directly make use
> of the recently introduced riscv_has_extension_likely|unlikely()[1] 
> which is based on alternative mechanism.

We could rename the "has_extension" framework to "has_cpufeature" and
then lump extensions and features such as sv48 and sv57 together. Or,
if it's best to keep extensions separate, then duplicate the framework
to create a "has_non_extension_feature" version where features like
sv48 and sv57 live.

Thanks,
drew

> 
> Any comments are appreciated.
> 
> Thanks in advance
> 
> [1] https://lore.kernel.org/linux-riscv/20230111171027.2392-1-jszhang@kernel.org/T/#t
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230111190029.ltynngqnqs42gatd%40orel.
