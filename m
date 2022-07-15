Return-Path: <kasan-dev+bncBAABBTG6YWLAMGQEVWEVPNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 686E7576302
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 15:44:45 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id x17-20020ab04891000000b00383c268f078sf1570582uac.13
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 06:44:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657892684; cv=pass;
        d=google.com; s=arc-20160816;
        b=mdumDNUbrtt0HLQd69++hXmx8QYMfufxJVAVhXpccSEEEnD3L+FW2RMlMWjKgI4a6i
         wjROgc/UrcBn0p2KWNwa74hWPfdLKpUpkvwtwjvreFUGkA1DFjYuFuGCt0G5TG68Kmsk
         9+odU4euXVHm/TgoHQO8qzqQi4mejTOo5y5O+KIs84aCBoG3BooUVRRQDgv+4wJDNpnk
         B8/v1GV/RX8GFFi9oWNnj9E16VzRTZKZPOXOyNZ5t5RBdnTjLf5HlshB3HDQpfPmp6A9
         hvb7a87bUjFHr3dpYLPXe4Ypq8hA4f9yKX5aLXPc4tY/XSCSa0uyu8fmgJQek/XqbQRX
         5DPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UP5btQIe4swVd+hC6y2mhYFM3u/iaiNzf3LYxp9Zp+c=;
        b=CZG/tgJbYAnyhr0KTmEacdIcwHETdm2UYAfZxHl9NonLm/rzo5gWwUO7Hq2QnZkgPp
         vyRpp50iKnoc4WEr1L0d16Wp6cTJR3skvr514OpNgSw0lrSXay/mBkgmu49n30RYtsWu
         +9CZeJOk6jpf7RI84qqJPv7QYawL6sJFtO+ub5/83dyrnTM3pTz+KNg5kP90gR554vmT
         2UshyZFQLAcfBWIKAH1Eifj5/qRwLZnASMdGxff+8yiu0m3tzJuAZnfIQdYugIgTxyIC
         Qj0bVpDkwZBHag6XHsuD9/FA2ySDACrVLyPNZFnHCNWMmG6KIH4b9zjIfYHwx0YrFRqU
         u+Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="U/7omktu";
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UP5btQIe4swVd+hC6y2mhYFM3u/iaiNzf3LYxp9Zp+c=;
        b=FsjkK7RI1bUzILVslb9+VcFRnhVC1kUkDzHbIOlRvloVH9v3UMEyQKHUwExsnFupJx
         sPeDdHuUrFRrqp5X5qPVF2DgL4+QzJ4WXAT+PUySOOo5dsrGPVlU8Gdzqrm/VFaDL/v2
         xJ6rmf5UaHz0H8rIZvBg8rZGOKdb/rEn6YpdNIzcUGVd5riQ0mFUbAE+8xhbSBosBlxb
         UUMUpRty3l1ephcQkTHJMzD3VHiEoL+v/HtgR11D8YOp4xTClaIj9kq5GsJ8d0WGBw8y
         k/Utv0rP3vf3l52q94kqngaQNTQvD7QAvUI6xzDkV7nlc0YrPbrUz3cR8XTMa1vaxF9a
         GhZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UP5btQIe4swVd+hC6y2mhYFM3u/iaiNzf3LYxp9Zp+c=;
        b=FVTnQS398EnkiZCY9X2ZQ6yfZpnVXr0hDLQJoHFz6OGBiuwVc82XOtUIxj4QSqPNxW
         1U/J+vlIf/EbMDWMLnQFbh636RxV+e/KjYfe5vS8G9r1y40EmDZRIIaD3L0yu2v67W9c
         THDWSjBe7RUT6fI0XByewtKjso/+HEIDrqvEDFcr/fZCgQ9AGVmhv4RZGKriYw1bD+5F
         lpiCc8IcRzl7pzgKouD5wMWNug4VIkf3vAC2myhxli6VNDhfw6Qu0YScVp00o7RybFZz
         xoW6Eh6pnjfSX3n0k83rSpaQwXegtN3STFQkF+Arq5XP4vkzc3ZThDILAGifXqLxyPpT
         wTmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+aF+3hpW8uTomno1vjYtbxhDwhVsTIefnO5ZXRS8DCsEsh0vgb
	gSI3/2CmXzE2a6cORaPGOOc=
X-Google-Smtp-Source: AGRyM1vXTwMQT9f9q1ssvV7C8lQUxr6a/6tF84vtUHcmBmPispBjsb5sYGXw2v1bxLc9re+VJPQKkw==
X-Received: by 2002:a67:f6d3:0:b0:357:35:3d12 with SMTP id v19-20020a67f6d3000000b0035700353d12mr5747335vso.26.1657892684167;
        Fri, 15 Jul 2022 06:44:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd02:0:b0:357:655:94fd with SMTP id y2-20020a67dd02000000b00357065594fdls79879vsj.9.-pod-prod-gmail;
 Fri, 15 Jul 2022 06:44:43 -0700 (PDT)
X-Received: by 2002:a05:6102:2907:b0:357:4c8b:6a43 with SMTP id cz7-20020a056102290700b003574c8b6a43mr5890751vsb.27.1657892683711;
        Fri, 15 Jul 2022 06:44:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657892683; cv=none;
        d=google.com; s=arc-20160816;
        b=K6DyS4mlU17tbM2Y1XlkugJb4y/gjpSWYa5+/CyJvLv6wDYDC/Rysxb8LuPM8ee/SG
         9AYcfPCuqODgNTlH9AruH5NJoZwkSpJA/mlTyd+N5JIJ/YKBnyf94RKbqnMrRv84eOns
         unXO/k00iYaa3bA5ECFtnAFZ3sOll/Ml0aFagux6R0cDM2dsFY+Lkst7G121THzknPPh
         /lcJ9asWnHBqzIgfnwQ5ZiIuBUEfK4L/ubWxFEbxryhliYlwE4BkBLR5JoAVD/aPwf14
         EBzTutZ7PMxc6Z19aseOSwc7uJj8Sl5f6TNXOjnClsx7ivlio58PssTz34adRFseehqS
         wbVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vrmbhdzoWQ1WlWmw7mbxX1kl2FS4dZKsnR9YLzhzlcY=;
        b=eGc9IAXLWtmUSgPM/HSmBF/BLfbq96o4nkJP+Uu4bENzG4rLNZMH3yngKqhub6hjj1
         HbnDtDT1f/HvZFMSGUdJ8/bQPyf5GhrpLM7YS65cu51lT4xgnvS6sdS2jsvh984AqNe2
         4CBdsj/y0CQkEI9UsTHcw3tbBBmlpofaSDRxu4Kf9+j9JOybR3nFmwKfDtw/nUlfJLe/
         d+yLl6Sb6GP6LrrLl6Z4ggZ9vmytraGaYLfA8yjcqtknIrIL4CjFcVWt7de5Yx4dZJQX
         hdwHY8QYfPUxNRecr2Tanl0Hm5y6nH2Hu2Sekh06kekz1u+YYEYJX4qxAZ9X464deF4E
         mDdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="U/7omktu";
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id q18-20020ab06c52000000b003831e93c249si162344uas.2.2022.07.15.06.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 06:44:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 31FC7623E4;
	Fri, 15 Jul 2022 13:44:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CA350C34115;
	Fri, 15 Jul 2022 13:44:38 +0000 (UTC)
Date: Fri, 15 Jul 2022 21:35:43 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: anup@brainfault.org, Paul Walmsley <paul.walmsley@sifive.com>,
	aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, Atish Patra <atishp@rivosinc.com>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 0/2] use static key to optimize pgtable_l4_enabled
Message-ID: <YtFtL3+/3FNkalZ5@xhacker>
References: <CAAhSdy0mkwacNMVa_jFZmZ+NRPBa1TpKUQGpzr6Z9_wfoq1R4g@mail.gmail.com>
 <mhng-17913c13-57bd-42f9-9136-b4eb9632253c@palmer-mbp2014>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <mhng-17913c13-57bd-42f9-9136-b4eb9632253c@palmer-mbp2014>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="U/7omktu";       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 01, 2022 at 08:48:25PM -0700, Palmer Dabbelt wrote:
> On Sat, 25 Jun 2022 21:33:07 PDT (-0700), anup@brainfault.org wrote:
> > On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > 
> > > The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> > > is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> > > boot, so static key can be used to solve the performance issue[1].
> > > 
> > > An unified way static key was introduced in [2], but it only targets
> > > riscv isa extension. We dunno whether SV48 and SV57 will be considered
> > > as isa extension, so the unified solution isn't used for
> > > pgtable_l4[l5]_enabled now.
> > > 
> > > patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> > > patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> > > 
> > > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > > [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
> > > 
> > > Since v3:
> > >  - fix W=1 call to undeclared function 'static_branch_likely' error
> > > 
> > > Since v2:
> > >  - move the W=1 warning fix to a separate patch
> > >  - move the unified way to use static key to a new patch series.
> > > 
> > > Since v1:
> > >  - Add a W=1 warning fix
> > >  - Fix W=1 error
> > >  - Based on v5.18-rcN, since SV57 support is added, so convert
> > >    pgtable_l5_enabled as well.
> > > 
> > > 
> > > 
> > > Jisheng Zhang (2):
> > >   riscv: move sbi_init() earlier before jump_label_init()
> > >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> > 
> > I have tested both these patches on QEMU RV64 and RV32.
> > 
> > Tested-by: Anup Patel <anup@brainfault.org>
> > 
> > Thanks,
> > Anup
> 
> Thanks for testing these.  Unfortunatly they're failing for me under my
> kasan+sparsemem-vmemmap config, which looks like a defconfig with
> 
>    CONFIG_KASAN=y
>    # CONFIG_FLATMEM_MANUAL is not set
>    CONFIG_SPARSEMEM_MANUAL=y
>    CONFIG_SPARSEMEM=y
>    # CONFIG_SPARSEMEM_VMEMMAP is not set

Hi Palmer,

Thank you for the hint, I find the reason: SPARSEMEM is the key, KASAN
doesn't matter. To fix this issue, we need to move
riscv_finalise_pgtable_lx() after sparse_init(). I will send out a
newer version soon.

> 
> Nothing's really jumping out and I'm not sure that's a super compelling
> configuration, but IIRC it's found a handful of issues before so I'm not
> sure it's sane to just toss it.
> 
> I've put this all on the riscv-pgtable_static_key branch of
> kernel.org/palmer/linux .  If nobody has the time to look then I'll try and
> give it another shot, but I'm pretty buried right now so happy to have the
> help.

Let me know if you want a seperate patch against
riscv-pgtable_static_key branch.

Thanks

> 
> > 
> > > 
> > >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> > >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> > >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> > >  arch/riscv/include/asm/pgtable.h    |  5 +--
> > >  arch/riscv/kernel/cpu.c             |  4 +-
> > >  arch/riscv/kernel/setup.c           |  2 +-
> > >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> > >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> > >  8 files changed, 104 insertions(+), 66 deletions(-)
> > > 
> > > --
> > > 2.34.1
> > > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YtFtL3%2B/3FNkalZ5%40xhacker.
