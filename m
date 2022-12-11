Return-Path: <kasan-dev+bncBAABBSPN22OAMGQE3XTTEWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C94E26493C7
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 11:54:02 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf3145693lfb.22
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Dec 2022 02:54:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670756042; cv=pass;
        d=google.com; s=arc-20160816;
        b=p11RcQS+vF1TDHr4XE43+cJAHlwOzXI1r0uUP6P3Xv8Gqt+LRPJyTl6lH1F+SIDUUG
         z6Cz6K7NNUdYiZzJQNkiKKe3x7evoyx7djEV0m5kPqNnlp5jZO5LNTQs/zU6VAbR1bT8
         6Ka4JGsWcOIp/semJnxUsEtOigf83ZoOZTsm4pyH0MzwGUv0r8LbTsxDRLvS+H7bayP1
         wmbPZytLya5lUVCTI5uq8Vo/BIxwVmyjzxX77lTDUi62/gRA/K43w6oYWX53DjOSy+Z/
         kkMqaRqznxXOiL5UaZF8nskSJe75s6AZwv1qyxINyzdSmiX84o2zZmIhlcmOP5BBQTux
         GFEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wujzqR2gSBvjTO1ECAhmVPmfXFC3LAcz22ZBdA5m+D4=;
        b=uHczwpVR49eeBm5zpxIpTdtXJfZkdXAeq21gDYfGusPKd6IzSmJ4TQw2FlYjw3tkFn
         VnsG8jClEqEn4pdOTD9DZc3zn6zmf08M/5tfEn0N3xIZi8jwo0LrZycwbIowqi+1h32z
         A6qVbZEQpfmgAllGG/x8ECbhrPNge09M/qAM9+feIeyY/OGrsVfVgOS8lBNbX6xyKlSG
         OSgKtF1/gRi5ar4LUUcT0w9guzmajkTrQm1C6tZ67D/kp3VJvYqDW2JUQf/P+vg9yktd
         bX+p5YpL1WQ5Fr6KKof4hmh3OvkL3bP9M6cYxmmRgxN7MJ+D8rhyiIdnI7S/SLzsxUas
         O5tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z1WVdgDq;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wujzqR2gSBvjTO1ECAhmVPmfXFC3LAcz22ZBdA5m+D4=;
        b=QQLCBvJZaFi/VAZaFT+6Gq2dkedWkL1KPbwNzpPuiiq6n+D9H52EiE7ul4xmAOcYQO
         QkGeHeaeUNvwXpVRP87zefv6OzaIQYMRwBtsOKz592nBKQD2wR+joqMvFNfLK6rnHij5
         MQxBDex9Y/pyDQafTEBH2OZ1VEBgCYnVwfX1/kNXaFua9/zCPXaELxTcnMGyn0SFhL9f
         7mSNGKcg3oypaKtiSHw+ypsWbmMCDGnNctvM0OAdOP7zPFgXJRuvIrolsC3TeJWSrj+E
         b1r67bpZpULVLbBTFASwIjC/cfuE18lws1L74KOWpIaq55YlXrvwWYp30Z5ZrlvVpacH
         8/Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wujzqR2gSBvjTO1ECAhmVPmfXFC3LAcz22ZBdA5m+D4=;
        b=7xLpz0d876ID1LmK2V6ZcjndL0YJzzFtSvQ5Yxr3WSH8FNvpd25jCwHNe6qZNNKchC
         ylhEIQr2RNfdjqpXqOrYQTHIfGF/jTmkpQnjxzSYrJGCDo2qyELBuDtcMaA+fFJq1nNM
         fEnBXJzwIG5ZIdRYi/nz3z3KmXO0U1rArHhGNwtjUleI6VHbd3DdmOpdn6YYZkaszb8B
         LJJl0WApu1TfUtFrS0EhGpvSnwN9Ai3WAvS1yGXOWiIrcuWx6jR2qj8gFi7kcahpBLlV
         t7WD2F+l2MvdnhSP7erHzLDBLXdjJ3xS9MRFAOojfMBwQUAAhrbVW4jNDo9YZhOHJZNT
         rdRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnVRo+/zuBC8ALinAgY6gjTQ2QxksfS/yFANuegeMJ5nfPu7M4G
	BJ3OfR57ycwgU1v24pkDmS4=
X-Google-Smtp-Source: AA0mqf5C5TBdK945pkntkwsLKcXfY4WaueyNmNtSuIMbfqrCKOF1VeNmbG/31YtMAfbzlXx7R4lxig==
X-Received: by 2002:a05:6512:34ce:b0:4b5:8f03:a2b6 with SMTP id w14-20020a05651234ce00b004b58f03a2b6mr4303421lfr.643.1670756041860;
        Sun, 11 Dec 2022 02:54:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3456:b0:4b5:3cdf:5a65 with SMTP id
 j22-20020a056512345600b004b53cdf5a65ls5088347lfr.2.-pod-prod-gmail; Sun, 11
 Dec 2022 02:54:00 -0800 (PST)
X-Received: by 2002:a05:6512:1296:b0:4b4:8bc3:21f9 with SMTP id u22-20020a056512129600b004b48bc321f9mr4763584lfs.36.1670756040805;
        Sun, 11 Dec 2022 02:54:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670756040; cv=none;
        d=google.com; s=arc-20160816;
        b=Kg6dr/PGl0SMkGiMMm4+UmsGsC+oJpmAMBboPans8dvAZOMo7+/TwdWo34//p/1eYG
         UaL0A/9xmrLteWlVNBkbfO8kjjYItTmuLMhmHpHCNia19dtrEPlnznFq6uavBMWWev9I
         zV2G9sRke2mkgx4XwAnrIxorzngRgXv0lgHB1WVxeg3TcCDk4TfU1SpiyIbFUs6iI0nV
         b/xkUaxF/vnEldbc3EXXQQuwmWjWW2usYBDN8OXsHoqU8si6uCWG15k7oNS65k08vInX
         PQet4Ecq2x/M8Ce7dhr5IRsDI7qEJbQs5UUai28JuV2DQ8LK6NexJ+/swoD/g7OjMDtw
         IISQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9UcHbMnDTxKjrW2cb26tW8/WUG7BNqPeISntSmmUYgw=;
        b=MYl7AImFaqjBEn24+jRHx5eBa/vdFdGvA4zkclTzU2O+oPndQdYwruvF8YrkGTE5bk
         camVqw238jJCo2CVItQc0U54rG+NRzeU87clqTj9a4AQV1SIxSAV8TCpY0JOIBqHr30i
         uUrnjdomI0PbMpMBetjEgk47Jov56SZVqve4+HAoGKXeS2Fjh87e4wFPUvuWuto445d5
         IHGKhmemYK/Y3bdQQ84VOtavqfrJwcO7DxQZti5vrGU0agdNTWfILJJ5iEFaeOn/TkpK
         00z6ITKN9iflNZAr/fvWXQeAwLoCYqU4cSYlBHHuAaOF5cPPKqGZaQJKm9Rm/kNJPLq2
         QvTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z1WVdgDq;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id s7-20020a056512314700b00492ce810d43si330903lfi.10.2022.12.11.02.54.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Dec 2022 02:54:00 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1C094B80975;
	Sun, 11 Dec 2022 10:54:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1FA19C433EF;
	Sun, 11 Dec 2022 10:53:55 +0000 (UTC)
Date: Sun, 11 Dec 2022 18:43:58 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
Message-ID: <Y5W0bv8Y/zCc+Fco@xhacker>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
 <Yz6T4EYKKns7OIVE@xhacker>
 <Y0GJDqLXFU81UdfW@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0GJDqLXFU81UdfW@xhacker>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z1WVdgDq;       spf=pass
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

On Sat, Oct 08, 2022 at 10:28:35PM +0800, Jisheng Zhang wrote:
> On Thu, Oct 06, 2022 at 04:37:57PM +0800, Jisheng Zhang wrote:
> > On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
> > > On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
> > > > The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> > > > is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> > > > boot, so static key can be used to solve the performance issue[1].
> > > > 
> > > > An unified way static key was introduced in [2], but it only targets
> > > > riscv isa extension. We dunno whether SV48 and SV57 will be considered
> > > > as isa extension, so the unified solution isn't used for
> > > > pgtable_l4[l5]_enabled now.
> > > > 
> > > > patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> > > > patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> > > > 
> > > > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > > > [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
> > > > 
> > > > Since v5:
> > > >  - Use DECLARE_STATIC_KEY_FALSE
> > > > 
> > > > Since v4:
> > > >  - rebased on v5.19-rcN
> > > >  - collect Reviewed-by tags
> > > >  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
> > > >    riscv_finalise_pgtable_lx() after sparse_init()
> > > > 
> > > > Since v3:
> > > >  - fix W=1 call to undeclared function 'static_branch_likely' error
> > > > 
> > > > Since v2:
> > > >  - move the W=1 warning fix to a separate patch
> > > >  - move the unified way to use static key to a new patch series.
> > > > 
> > > > Since v1:
> > > >  - Add a W=1 warning fix
> > > >  - Fix W=1 error
> > > >  - Based on v5.18-rcN, since SV57 support is added, so convert
> > > >    pgtable_l5_enabled as well.
> > > > 
> > > > 
> > > > Jisheng Zhang (2):
> > > >   riscv: move sbi_init() earlier before jump_label_init()
> > > >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> > > > 
> > > >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> > > >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> > > >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> > > >  arch/riscv/include/asm/pgtable.h    |  5 +--
> > > >  arch/riscv/kernel/cpu.c             |  4 +-
> > > >  arch/riscv/kernel/setup.c           |  2 +-
> > > >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> > > >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> > > >  8 files changed, 104 insertions(+), 66 deletions(-)
> > > 
> > > Sorry for being slow here, but it looks like this still causes some early
> > > boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
> > > see from the latency I'm still a bit buried right now so I'm not sure when
> > > I'll have a chance to take more of a look.
> > 
> > Hi Palmer,
> > 
> > Before V4, there is a bug which can cause kernel panic when SPARSEMEM
> > is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
> > after sparse_init(). And I just tested the riscv-pgtable_static_key
> > branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
> > I'm not sure what happened. Could you please send me your kernel
> > config file? I want to fix any issue which can block this series being
> > merged in 6.1-rc1.
> 
> Hi Palmer,
> 
> I know you are busy ;) Do you have time to send me your test kernel
> config file so that I can reproduce the "early boot hang"?
> 
> Thanks

Hi Palmer,

I think the early boot hangs maybe the same as the one which has been
fixed by commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in
kasan_init"). Will you give this series another try for v6.2-rc1? If
the boot hang can still be reproduced, could you please send me your
.config file?

Thanks in advance

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y5W0bv8Y/zCc%2BFco%40xhacker.
