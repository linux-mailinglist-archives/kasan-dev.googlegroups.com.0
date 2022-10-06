Return-Path: <kasan-dev+bncBAABBIFM7KMQMGQE4G2MCVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 51CCA5F6307
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 10:47:29 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 133-20020a1c028b000000b003bd776ce0f3sf2279821wmc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 01:47:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665046049; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jj7qGNxLL4TaqfwFk+h4mw/9aGCicfkDVxTz1LzNNnW3/hQKRLblfgxIELDa8lDbJL
         JGG08eivGdDTahAFENTa5+LYUtVnjPnfRGMmH7yi50mgjiCCk3+jYNTl3ZMpn2ft4UXo
         i+GsKLA2vysRMWCFCKrlfqCONlk47oU2MMprfcv2Nu+RIqUMZu9EZlXbkgM1xJAiEmH5
         EnYmW8XbVQyqH/wiRFw4EPJAKB5OrQ9OERu7MD66hSA1CH3/bV6YYzpZF8kfIUIltakx
         m6t1e2bGYa4RYYbGOeaZ7U+S2zwWFUTXZ7c0cHVlpnXmm2VZxmjwOMQSN02MyxOGFwAX
         IE4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Xv8u6C4uB6L+kjdNx2k4ZfjyPwCUTnhXEeqFFZ65kT4=;
        b=ENFl0lgRVb1PjHx1bCuCeckSm5kesF5yUMnul/sP+1L9IDoSS9lqosHyECVqW7GVhp
         p9Dc3vVXFOrtrtJ0Hmv2Gh+d1ZbArwRMGhtz+zfdqSiSYOwrwDfip1V/QNViIBAZv/YD
         Q6y2KVnAtdayrTMf99PwqeXIGD8yi+7kvi25omhUXNynBRakEdMrg2M6IjhDlAJXlQ0C
         SIr4M/9MQlWqX+KCL58CO/F3vSTXvAuQeilqpiO83Yd5bb9OtGlfKV3o2NUWut3sVdqs
         HVCJIfSjjsh/bxrJhcNm/GBRlemnre0tz7+4V4CVyZ9FWv5jOsvH8KsDHhk+N7l/Hobs
         vzcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fXmeRcBv;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=Xv8u6C4uB6L+kjdNx2k4ZfjyPwCUTnhXEeqFFZ65kT4=;
        b=oJcfsse/GrXVFAJ8wDymxEfpGrCq5E518DPmH9oBR0HGVmLl/kEOnxpmRnlOIkmSSz
         YIecZ++7iwuqVyMbE62ak9iE5gn9AdLV8B9dRsZTTo7RZwZ9izu5eXqqDAGvNn/CULUH
         MGtuYMBRUfbRtywMJmVBy5Va1srglidf8Q8GDIkcj+UEYN1pZDe3vhBwX7NAt1bDdZe3
         czwKkQ5yEOnVNoPRypg4Fi5AjKB/JgAEop8gpvqfI4cXwZmRLsHt+/TpJepmXXE4JBVf
         Bk2EuwGT0e95S/EpfB2QnKpBQgmAOGCeW8CETqwHxdTt+OKngDTliC450Nsk+lMxubZp
         +ZUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Xv8u6C4uB6L+kjdNx2k4ZfjyPwCUTnhXEeqFFZ65kT4=;
        b=SdEXeDy8ODHnReQk4pqImph2gN8LkTPgHEYUHdeazOjx/Wo0vU8HNziZnCqce4rtOB
         Gzi+/v66/NpTwowcpMkDuOznFlIafpk5LrrZn7tYUmsPk1ARKavHdwYIkg+YJ8Byvz9f
         E4NGAOoBOpwm2byYZ5Wa/lb7l4uoxDPwcDcqlCE3W8N/7WtL8+GUVzdx4/ly4HGoyxlp
         vCQKDNkduFo042YRhKCDXqcHxwZz8OwzsigIcyqirftVBEuDiyk820XyFFF8pKvPj/qS
         R2vdVOndtg+XM1OYFxch7Mlop/kSgII6oTEMbD68CngLsUFUpKVyoRqfC8ykjBIi9vYZ
         OUeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2cwWZ7dD+NLEnhy1g1xRu71IEl0aY0wzEN0ggvSmAIs/d3tGJt
	6q8rtalVRKKRORBaehfYa4Q=
X-Google-Smtp-Source: AMsMyM7e/Oov3aQOr5NKTZOLnUKoNCXOFmU0p6R4vb4VGDjIBJ3zvZEsIPLMMvUcFZbPW8Z1aLwXAg==
X-Received: by 2002:a1c:f214:0:b0:3be:4e7c:1717 with SMTP id s20-20020a1cf214000000b003be4e7c1717mr2383249wmc.171.1665046048836;
        Thu, 06 Oct 2022 01:47:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c857:0:b0:3b4:62fa:43a7 with SMTP id c23-20020a7bc857000000b003b462fa43a7ls643491wml.3.-pod-control-gmail;
 Thu, 06 Oct 2022 01:47:28 -0700 (PDT)
X-Received: by 2002:a05:600c:4f45:b0:3b4:9c9a:7077 with SMTP id m5-20020a05600c4f4500b003b49c9a7077mr2378319wmq.109.1665046048076;
        Thu, 06 Oct 2022 01:47:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665046048; cv=none;
        d=google.com; s=arc-20160816;
        b=eHh9D2obD2Px8GlP3O0CM8PlqovIRrtkqqamjRgTK1M/1BNgqi/5Lld8thEd+2Q1K9
         IGIaKbVbpuAjRBCprW+5RltxKvnALIor4M91cmkDGni6lYoAWgrCr3Kuigv/bvpCmrGd
         VqXN3X3oxNY1JXwh50jqQMR2EogQFmHba6vcMRlwALxerlMzNDqz6i2Js+PNYoRJ5PUz
         D1AbejsK9DzoWtkuYauveAb2Q6xQibozfBH9RWKqK3P4CLDCPqJT5FomV9aLsXlPHCzw
         TMZYNL7/JVcQ7VbCfU7LAXC7rwTa+3RRBkWBpPr3tIHJgNZWk7+DBphNnKslgHTtX/u8
         5y9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cf/uPJP80mxfamNhBTklwjcNynTCodg8EWIy5SowFRc=;
        b=bti7JQVnAAzklzddpQpvcjmxJ2upYs+gbEoZlfYxMRbl4MMkzFhr3GEBcbFAhW0JJI
         iHywqHbQMGN/2JECtFRZEBeod2jlqJEdsjsZAtLtJUYo4wCtD8fiGhGaYk9OMZt2bZAJ
         G5gS7SaRiT08jBn5Y/NZvTrgCXhww0xtYQ8LnUKQ7/3tmK2+MC3YiGO81bESX/XIKFKm
         kCDl1+IupDg/Cq81MzaaEDOckk5IyaGu1riERdL0HSlZ1KMiYiQs42k0TMsCyt8Swg+a
         1fDPu75JrTd5gAs7+0ohd9296guPUHmWr140VSxLRjmPaGho0AUc26TbRgVBJASrh9G/
         XuNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fXmeRcBv;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id 125-20020a1c1983000000b003a66dd18895si338230wmz.4.2022.10.06.01.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 01:47:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B8AE0B81DED;
	Thu,  6 Oct 2022 08:47:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2567C433C1;
	Thu,  6 Oct 2022 08:47:23 +0000 (UTC)
Date: Thu, 6 Oct 2022 16:37:52 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
Message-ID: <Yz6T4EYKKns7OIVE@xhacker>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fXmeRcBv;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
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

On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
> On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
> > The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> > is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> > boot, so static key can be used to solve the performance issue[1].
> > 
> > An unified way static key was introduced in [2], but it only targets
> > riscv isa extension. We dunno whether SV48 and SV57 will be considered
> > as isa extension, so the unified solution isn't used for
> > pgtable_l4[l5]_enabled now.
> > 
> > patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> > patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> > 
> > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
> > 
> > Since v5:
> >  - Use DECLARE_STATIC_KEY_FALSE
> > 
> > Since v4:
> >  - rebased on v5.19-rcN
> >  - collect Reviewed-by tags
> >  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
> >    riscv_finalise_pgtable_lx() after sparse_init()
> > 
> > Since v3:
> >  - fix W=1 call to undeclared function 'static_branch_likely' error
> > 
> > Since v2:
> >  - move the W=1 warning fix to a separate patch
> >  - move the unified way to use static key to a new patch series.
> > 
> > Since v1:
> >  - Add a W=1 warning fix
> >  - Fix W=1 error
> >  - Based on v5.18-rcN, since SV57 support is added, so convert
> >    pgtable_l5_enabled as well.
> > 
> > 
> > Jisheng Zhang (2):
> >   riscv: move sbi_init() earlier before jump_label_init()
> >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> > 
> >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> >  arch/riscv/include/asm/pgtable.h    |  5 +--
> >  arch/riscv/kernel/cpu.c             |  4 +-
> >  arch/riscv/kernel/setup.c           |  2 +-
> >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> >  8 files changed, 104 insertions(+), 66 deletions(-)
> 
> Sorry for being slow here, but it looks like this still causes some early
> boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
> see from the latency I'm still a bit buried right now so I'm not sure when
> I'll have a chance to take more of a look.

Hi Palmer,

Before V4, there is a bug which can cause kernel panic when SPARSEMEM
is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
after sparse_init(). And I just tested the riscv-pgtable_static_key
branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
I'm not sure what happened. Could you please send me your kernel
config file? I want to fix any issue which can block this series being
merged in 6.1-rc1.

Thanks in advance

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz6T4EYKKns7OIVE%40xhacker.
