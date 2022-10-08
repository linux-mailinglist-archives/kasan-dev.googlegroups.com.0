Return-Path: <kasan-dev+bncBAABBTUWQ2NAMGQELHEUKCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6876E5F859E
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 16:38:08 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id e8-20020a5b0cc8000000b006bca0fa3ab6sf7214755ybr.0
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 07:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665239887; cv=pass;
        d=google.com; s=arc-20160816;
        b=QWujXPBAUACKBaiQMcosXhv19gDrOhhnlAMMRxwgN4mNin546gHEBsFeqNEfA2gE1l
         xUmIH2b6Q4EEM9SU9+7yMX3ROxf/9ecWosQDVtk0TlAOLLfoKB5cQbZAJXej9LadZHNa
         dDCytudYMZTOsLcMYtlLzhbNJ9+6vexiSvDSwaE0cpncv7BiuEIfwal/Ai9RIZcErODX
         XXLHnFl0M77MxdIQqWcDppyHF/d9VZHVp05HAa6mT4/Qja+FsTXyExLKVPSfJlnqmcEd
         3e+XRgvpFwKa8wS1nMcDuIko3zvJdV6IMn4VslmoVM9eefRSUnQwGqAZvsTcCBLXIEJm
         +n5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZfbbSGClLO6NR0XjB3q/UhhFdhQf39Vs8aaTvD7lbfc=;
        b=ZEpG4HPOsgHbiwL8wOv81axoB/d6Ihu+eM7CW+dReQUAOxOvasc20BxqV37ffpEidW
         PNW2la3ud2sHjn9r4Yg3maAJuzKqQxEpL9UbmYzHKqc57D9xC3cF/c6eQPxTsK4Rr7cb
         J29mGw9SOyY0Y3jvbFLZtM4q3nuk4QueeRboP7R+rIUHNeI+M7tYjKUUNeGaqptl8mUy
         U+grBm8x2Vad+xEtcOulMNuJXobBNchX9gDpjK4jKL/MnQxwcVe9Ium/Mqxa0W1A9FOX
         BmcIgv8qVys5wBrzgsfBly1DxyCFGdGiXZf4fNAQ8x1ni0vm9kHujPm8wcova8DJ+ZXj
         GeGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ge2t8CQA;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZfbbSGClLO6NR0XjB3q/UhhFdhQf39Vs8aaTvD7lbfc=;
        b=enJIpO++KwV/Cj+CHWDFpVAQVOlhgETl2tyuD59XHbaCOYQGnoED82bYrj7MWxCDp7
         MSjoUegE9d+ytTBQH8foSVb8b68/j/8xa99wK12gOSk4qWBj9TqVifcIJ6RjoYdFMf1E
         ADAGy8f0jiIinEe2AiQXjoCSVkWYXjLsuRtxGIyndBXsIvOxWbI71GtdBl89XK4WRp8M
         U1k9UJy5wl+nKrwLcvxeLkqr4LqLa/ficD6Mvp4wRIk0c76gpC9WGRgi8tQNQnR0WsgE
         a5sthlCqyEEUtAedYFgU36bIPHI3AopnW8Qjc9U8fktewk/eEI0rMNO2CPflF9zBz011
         H7Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZfbbSGClLO6NR0XjB3q/UhhFdhQf39Vs8aaTvD7lbfc=;
        b=5GqB0xnAovovu6Z1scoDl2vCn4WTYV+wC4Xa8P5E2dKRLoriLWBtOkkQIsRFOUPrRM
         Ktlc7hPHhJQzJdWOkhBpTEp+bdN/0dpBVEOW7cg6xn+m1Z+yBRsifKgHBfUIki08r0in
         KSgkW+014rJebfJ+DO2GbQTWgD4ErKGzZW5M4b4cUcGrmu7RIhBY/4F3rhBfKmG//dEH
         0rxT17bt/vk7Tj1A540gfEw5UE1nMcq2S2w59RK0hgyzECAjElfdDuwVusBh0lBSewE2
         kSyii/E5lbrAACU0x023TiVJ1K/1veyUw7I8Klf0iIQEAgl2DKhhGvZ6X++fyWuj9uIx
         c7KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2gHJF6bulB52lQ+sS8rZ2s2iUes9LZaCxh/9dMLQilvW7z4ZHW
	wgWIogQW4+zzIgpZYfOc1Jw=
X-Google-Smtp-Source: AMsMyM54RdARgjdfm7kAZ7mhf/ZHjcy6imQ1u37dQWCJDat14DBeFuPCzVAISsxrgTzVSBgHzU3HCA==
X-Received: by 2002:a25:dd0:0:b0:6be:45f2:f77a with SMTP id 199-20020a250dd0000000b006be45f2f77amr9818560ybn.490.1665239887154;
        Sat, 08 Oct 2022 07:38:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3616:0:b0:6c0:208d:19f8 with SMTP id d22-20020a253616000000b006c0208d19f8ls447132yba.2.-pod-prod-gmail;
 Sat, 08 Oct 2022 07:38:06 -0700 (PDT)
X-Received: by 2002:a25:8e8f:0:b0:691:9579:d3c5 with SMTP id q15-20020a258e8f000000b006919579d3c5mr9651526ybl.249.1665239886578;
        Sat, 08 Oct 2022 07:38:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665239886; cv=none;
        d=google.com; s=arc-20160816;
        b=DZYT3k48MJf0P58Uwf4O2kYnj3Vc084EczewGm6BGbLlGGPDQa/Jf2ObBF/WREdWQO
         nEoEfC8/MoWSu2uLXMFSU9cXhpDUrfxLZb9NTHbZ0eXopyATeR+YmD1uhEMGktofd2aG
         wZ1jeSM0kqXktcaE/5xmeiOYV+3dnOhJIvSJu9DLvl2BaJKqcEDGRw0G2AFHJOn6hWR7
         NGeFfrTW30qmFHDIvuNs94VUT4HSrUAXe/tYbRxzgmFyqZ1lvwvztof2xpRB8kzHF2gh
         HEoSvArHaBDWWz0vL86ja0nZP9/L44nBLRdFs0vCnR2N9yhaiqZX9fxydzQaw7Bk9rOj
         g0pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fqN5KvViXfXxGFd5AV9VqrAlLAg+jnRftlUd4TRHyXQ=;
        b=vXbavY5B96AyJJiCGSuyDt3GXUk4EUC6qjj1FHWElmif6WmubQGZdqLcvO25aAaJ6S
         9kO/oPzbikT1mBo4yyma7n65hbRdwMeMnDohd2DDfsrRCI91C8E011EwqAI7Ufja+aNf
         6Ys857d13HpGVVt9jTtCNA8xW5oCy8dM0YBfSIV9E8AtQV2ffALsJZLYYOOcFJVbmj9W
         2Ten0rLJx/8qav/s/mnxFCr0CYoeEUZi2N0iKMYd4KhXNDu9/7N7bN21ZAz2Agt8z/vv
         CbG7vLDQWCkkzPOPxqEKO6zlf6lcnPUucqakxa8062fzdWcfvIub60vv27XbhQJWE3S8
         Iixw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ge2t8CQA;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bp1-20020a05690c068100b00330253b8e8asi297752ywb.0.2022.10.08.07.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Oct 2022 07:38:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1021A600A0;
	Sat,  8 Oct 2022 14:38:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0AE06C433C1;
	Sat,  8 Oct 2022 14:38:02 +0000 (UTC)
Date: Sat, 8 Oct 2022 22:28:30 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
Message-ID: <Y0GJDqLXFU81UdfW@xhacker>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
 <Yz6T4EYKKns7OIVE@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz6T4EYKKns7OIVE@xhacker>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ge2t8CQA;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Oct 06, 2022 at 04:37:57PM +0800, Jisheng Zhang wrote:
> On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
> > On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
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
> > > Since v5:
> > >  - Use DECLARE_STATIC_KEY_FALSE
> > > 
> > > Since v4:
> > >  - rebased on v5.19-rcN
> > >  - collect Reviewed-by tags
> > >  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
> > >    riscv_finalise_pgtable_lx() after sparse_init()
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
> > > Jisheng Zhang (2):
> > >   riscv: move sbi_init() earlier before jump_label_init()
> > >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
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
> > 
> > Sorry for being slow here, but it looks like this still causes some early
> > boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
> > see from the latency I'm still a bit buried right now so I'm not sure when
> > I'll have a chance to take more of a look.
> 
> Hi Palmer,
> 
> Before V4, there is a bug which can cause kernel panic when SPARSEMEM
> is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
> after sparse_init(). And I just tested the riscv-pgtable_static_key
> branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
> I'm not sure what happened. Could you please send me your kernel
> config file? I want to fix any issue which can block this series being
> merged in 6.1-rc1.

Hi Palmer,

I know you are busy ;) Do you have time to send me your test kernel
config file so that I can reproduce the "early boot hang"?

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0GJDqLXFU81UdfW%40xhacker.
