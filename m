Return-Path: <kasan-dev+bncBAABBNPI7OOQMGQEBJBSB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 95A8266620E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 18:39:02 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id z11-20020a0565120c0b00b004b6f41c58bfsf5872058lfu.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 09:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673458742; cv=pass;
        d=google.com; s=arc-20160816;
        b=JL4xrjzmNxnEPxeIxb2yhEtjtWG8cSwgjg2rTNjm/ydLv3pr09xRoNM482s+u7URFS
         P9wTg4u2AagcwB/5o/q5ijaGe31E40dfjvC271z0jgm1wf54eGDHcRK8K11NO8iks5KI
         zhLpK7teY50my9MBBjjY5sEeiVQ+oc9WOr/rrZGlbRr2CpGfFHbUwXybPd//IRJQXoaT
         Hb7HRd+OiD+lp9k8YiM9W7RClvLYyPLW9HeK58qV+4BvzPpVLQXzo94I7fr8EXF3ghyG
         bjenNULOAPX7L2kzSAcQ7q2qxDSqnbeTOpVpxe56z85mWl1Lxd/gkq477nWS4Kn2boVT
         lwcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Go2Li4pp9sO/cuP9oz0WFdZFfuKuJKErz5O0X3Y8Uyc=;
        b=04K7heuPiD4CbNJozQikcwFFL44/9aFSLq43+X1j20p39e0OBtKS2mZIUcos27vcxe
         9BNHjSMpfHltr4eJTtcE7kbKCxJbpMA56SB0kC1RGmTTSTzLqP8cPHIbx9veT459IR1U
         4ETp80aX/mxCOybxaUDX8IJAFepJNLdXMUxLaOW4Cn9einaYrXmGBlCrDNHCG6BjCt7+
         jzwMWVBJGeFfPYBAAwGCyuWTm11nLhmxg8/uldJJuuSTPAWv1Uf2DeZWBs764aFKWNWt
         o/jZWlnG7GIvZh80fI2EgaGpVm3L6nVIQQfaqk++kQWQLMci4FiJeVGmq1aSbe8iF3qP
         bC8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=czU7dXOS;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Go2Li4pp9sO/cuP9oz0WFdZFfuKuJKErz5O0X3Y8Uyc=;
        b=rqEuFebpoGAJqJ3TnGaIY6bVz2sYfFygq5rxJcmhBXk9wJDo+6bwR9fQIvWeZZLfrs
         o9JSvbfNMe0v7ngBKnPiKLK3pteXp4ixriMYihchFFTkZ01W7QHhkmep2x2Toing8O2Q
         +agg/rO0RZImGXkN9WUIFoNvIuCGHoF6WDF7tj05Dp9sqIfX6SD/sQt54shXp4pL2tK4
         ckfUQdC7nTRRTqu+5nuqdSzTiYUbm+3qR+WFsnItQ1ZmfHYdDLVrTBl/l++joPVecN8s
         rCtp4uBlnHZaeqnX+pp0G1QgKGqHXClWNFbybZ8SbiPK3bGaVFBILKxP0gmAe9qmG6vO
         brdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Go2Li4pp9sO/cuP9oz0WFdZFfuKuJKErz5O0X3Y8Uyc=;
        b=3CS7ZQpXpZRwXUGvY2N8W0rRZE95DD3DpGJigtl6zoGK2gaVLuZp/XqHTtdKdeStQN
         G9lHnd6K+XYoBi+DBcGhZKnpe6P1cRUD8m5EXIEnLqGtwB0sJiIlB/O2Twu8L1KE4jG2
         z5Odi2pZ12WJogNhKn0BrNL02NBscLGu8Sq1/HkHxDKmo7ccIAIG9WrQ7bzSTycpMm8q
         zv9Nf4PNqM0qR0c4U1x/T9Hw7cZP9p4SlNAd0xljeNzQwnCNuJpdP1DfRyXRovfiPian
         wkd6s0NqV4T3GAEAaRtNaVkjx1YS5KkPbxyBxosliyLnVoEAnMd0h0xeVkfDlLnfTLHG
         PxzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpkzyZ/uxoarRsUUCfk8QsPqTtDlx6jbrZkEa8ie5GjT+DcGH3Q
	p58iT/+x61akjb8Vuudc/WQ=
X-Google-Smtp-Source: AMrXdXu+vxdZK5Y+6+N1uPGUokAKnW5hhOrq1dcpSxdb/IpneT9StW2lApkFcwsY0YMLOxSBJp6LXA==
X-Received: by 2002:ac2:4c52:0:b0:4cc:87bf:d585 with SMTP id o18-20020ac24c52000000b004cc87bfd585mr496003lfk.91.1673458741914;
        Wed, 11 Jan 2023 09:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2124:b0:27f:af13:20e2 with SMTP id
 a36-20020a05651c212400b0027faf1320e2ls2324343ljq.11.-pod-prod-gmail; Wed, 11
 Jan 2023 09:39:01 -0800 (PST)
X-Received: by 2002:a05:651c:2391:b0:281:1773:7680 with SMTP id bk17-20020a05651c239100b0028117737680mr6538313ljb.44.1673458741025;
        Wed, 11 Jan 2023 09:39:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673458741; cv=none;
        d=google.com; s=arc-20160816;
        b=O3bfK73JzkM4QIy968dZm+wDsgK1dFuOGOeN83IE8tgilIw8grDFzshiUBv9b/0wxU
         Q0oZwpMyWC69mPCLfhH+JV03D/K0QKAdnlGxxsdCBIclhfUY0RE6gjEfMdGkY1/Czp2u
         lnSmJ1rp61mIhm07E49wq90qXx4Iy7NYu7jsLXUo6lkFO/vt2TBz0ZlTg4Eg4ADBiwyG
         nx4bmBD9NN1+7nFl6qxI2vIOFjOx9eoHgqkGieEEJ4ng1k5Wv+5c7hWCaVMtNGaa9h/y
         GFx1hY+IaJlqIR8UgYtrEpHNZnP33NnhzgGGbKEjP6GnzIrjq4Nuvviv5PWuXfyix3xG
         YB4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=w4Mq7pXpA1c3/QjzRQ8Oyqn8tP8k/8p0/fFIqKxxYIQ=;
        b=RYrV9YlNE/p0Rfkavc+soK7bvDMqUx+Z9OxdCv7SM6R50PUXJV/fG21imHTkD/olFh
         sE+T1b+WzM/uxvwysehcEzxSU+Y4QGZckmbQS/GNGnygW3xxXHZuVPN3mqDb3bhFltPc
         jff5KV0tbfe5PN4OBjlc9M5V6LMQrK+PFKcKr2+S9UvIth2CNqEf3z19VkBVIKjsZJGn
         5YNOgRXcS5UTVfz5uS5sz1Xd2TF372WGTIYMwvtlv5QLmo0euccCTr9yGwAOzVt+eDDV
         u14NFDU+ZjmoW3Tf45OTdsVs5jChPfbdx4K+ZJTmLk2jS1mk8hLrasnkdLqsxdXIFB3o
         0w6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=czU7dXOS;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k9-20020a2ea269000000b0028002e5a082si667729ljm.4.2023.01.11.09.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Jan 2023 09:39:00 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 61793B81BB4;
	Wed, 11 Jan 2023 17:39:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B39FFC433F0;
	Wed, 11 Jan 2023 17:38:55 +0000 (UTC)
Date: Thu, 12 Jan 2023 01:28:40 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	alexandre.ghiti@canonical.com, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 RESEND 0/2] use static key to optimize
 pgtable_l4_enabled
Message-ID: <Y77xyNPNqnFQUqAx@xhacker>
References: <20220821140918.3613-1-jszhang@kernel.org>
 <mhng-30c89107-c103-4363-b4af-7778d9512622@palmer-ri-x1c9>
 <Yz6T4EYKKns7OIVE@xhacker>
 <Y0GJDqLXFU81UdfW@xhacker>
 <Y5W0bv8Y/zCc+Fco@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y5W0bv8Y/zCc+Fco@xhacker>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=czU7dXOS;       spf=pass
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

On Sun, Dec 11, 2022 at 06:44:04PM +0800, Jisheng Zhang wrote:
> On Sat, Oct 08, 2022 at 10:28:35PM +0800, Jisheng Zhang wrote:
> > On Thu, Oct 06, 2022 at 04:37:57PM +0800, Jisheng Zhang wrote:
> > > On Wed, Oct 05, 2022 at 06:05:28PM -0700, Palmer Dabbelt wrote:
> > > > On Sun, 21 Aug 2022 07:09:16 PDT (-0700), jszhang@kernel.org wrote:
> > > > > The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> > > > > is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> > > > > boot, so static key can be used to solve the performance issue[1].
> > > > > 
> > > > > An unified way static key was introduced in [2], but it only targets
> > > > > riscv isa extension. We dunno whether SV48 and SV57 will be considered
> > > > > as isa extension, so the unified solution isn't used for
> > > > > pgtable_l4[l5]_enabled now.
> > > > > 
> > > > > patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> > > > > patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> > > > > 
> > > > > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> > > > > [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
> > > > > 
> > > > > Since v5:
> > > > >  - Use DECLARE_STATIC_KEY_FALSE
> > > > > 
> > > > > Since v4:
> > > > >  - rebased on v5.19-rcN
> > > > >  - collect Reviewed-by tags
> > > > >  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
> > > > >    riscv_finalise_pgtable_lx() after sparse_init()
> > > > > 
> > > > > Since v3:
> > > > >  - fix W=1 call to undeclared function 'static_branch_likely' error
> > > > > 
> > > > > Since v2:
> > > > >  - move the W=1 warning fix to a separate patch
> > > > >  - move the unified way to use static key to a new patch series.
> > > > > 
> > > > > Since v1:
> > > > >  - Add a W=1 warning fix
> > > > >  - Fix W=1 error
> > > > >  - Based on v5.18-rcN, since SV57 support is added, so convert
> > > > >    pgtable_l5_enabled as well.
> > > > > 
> > > > > 
> > > > > Jisheng Zhang (2):
> > > > >   riscv: move sbi_init() earlier before jump_label_init()
> > > > >   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> > > > > 
> > > > >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> > > > >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> > > > >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> > > > >  arch/riscv/include/asm/pgtable.h    |  5 +--
> > > > >  arch/riscv/kernel/cpu.c             |  4 +-
> > > > >  arch/riscv/kernel/setup.c           |  2 +-
> > > > >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> > > > >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> > > > >  8 files changed, 104 insertions(+), 66 deletions(-)
> > > > 
> > > > Sorry for being slow here, but it looks like this still causes some early
> > > > boot hangs.  Specifically kasan+sparsemem is failing.  As you can probably
> > > > see from the latency I'm still a bit buried right now so I'm not sure when
> > > > I'll have a chance to take more of a look.
> > > 
> > > Hi Palmer,
> > > 
> > > Before V4, there is a bug which can cause kernel panic when SPARSEMEM
> > > is enabled, V4 have fixed it by moving the riscv_finalise_pgtable_lx()
> > > after sparse_init(). And I just tested the riscv-pgtable_static_key
> > > branch in your tree, enabling KASAN and SPARSEMEM, system booted fine.
> > > I'm not sure what happened. Could you please send me your kernel
> > > config file? I want to fix any issue which can block this series being
> > > merged in 6.1-rc1.
> > 
> > Hi Palmer,
> > 
> > I know you are busy ;) Do you have time to send me your test kernel
> > config file so that I can reproduce the "early boot hang"?
> > 
> > Thanks
> 
> Hi Palmer,
> 
> I think the early boot hangs maybe the same as the one which has been
> fixed by commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in
> kasan_init"). Will you give this series another try for v6.2-rc1? If
> the boot hang can still be reproduced, could you please send me your
> .config file?
> 
> Thanks in advance
Hi all,

Just request to comment what to do with this patch, I think there
are two independent points to consult:

1. IIRC, Palmer gave this patch two chances to merge in early versions
but he found boot hangs if enable KASAN and SPARSEMEM, while I can't
reproduce the boot hang. And I also expect the hang should be fixed by
commit 9f2ac64d6ca6 ("riscv: mm: add missing memcpy in kasan_init")

2. Now we know alternative is preferred than static branch for ISA
extensions dynamic code patching. So we also need to switch static
branch usage here to alternative mechanism, but the problem is
SV48 and SV57 are not ISA extensions, so we can't directly make use
of the recently introduced riscv_has_extension_likely|unlikely()[1] 
which is based on alternative mechanism.

Any comments are appreciated.

Thanks in advance

[1] https://lore.kernel.org/linux-riscv/20230111171027.2392-1-jszhang@kernel.org/T/#t

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y77xyNPNqnFQUqAx%40xhacker.
