Return-Path: <kasan-dev+bncBCS4VDMYRUNBB24OVKGQMGQEMNMLRPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B291467F1F
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 22:09:00 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id k8-20020a5d5248000000b001763e7c9ce5sf915123wrc.22
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 13:09:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638565740; cv=pass;
        d=google.com; s=arc-20160816;
        b=bzuaD2upN1tDxM45tVe9iszvVDWBZwMtSmeWqZRkpzRW2f9/+bGS5Ouz9eXXH5Xj5d
         NkwZUiw/NskEwhLtGR7kNJN4i81hfJ9PLs2QoIkyEHVKBU1ZFLEbN12RwZCghbMx/H9w
         5MOHHVmb5epINs0rldiCPBcnlVIHCtjZ9Yq3Judn0iFdrB2cIPOcSbrP7FMS0mm8Ajjf
         6YVcJFlOCX+iIhHaR1CgPxpXaoGZ3cp2gG+UThcY+9JCJBjbchLyYZBjQ75ze4E9tisi
         F9dagbakqi4Gt4/801nBPiRzQ+B7BLq7iI/yvQhsaygrVbKPkZgACgAWkZ4QWXxEbR4D
         e3Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=Y0vuutaOzI4ELJZEHFA53abQJckTM68qmQDxVfMSA+Y=;
        b=JnULY8z/7lWxey5bH0F6SyIbXBW9R+HNRGvddkcUWvODeO6yJ2hQWMyZcxPIfU+uwJ
         YHMKVW2j1TG8eZW1UXyku11ai0evyPuJIXwms0vT7oRNErZBDwwzC9qiYTOVpFe+i5hV
         qAaoygdU+4d5nGqrBEtF8VQDqkaWKxi7ukvmj8JKyC6CTBtdn5xFG6iHbSgg9eu17z+m
         y/xFVT19cRyWJYuo9cxikCFg2St5+HarC8ji0k+hfJ1AT46uLWw5ek+QSvJkejMlfKwA
         VuWgZanc7qzsjE1vuFyfdWg65CaMn1hM5RM3zHgwBlqVHzATsIx05nahh1PFcnw7Nmfw
         g/rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ur99wvPA;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y0vuutaOzI4ELJZEHFA53abQJckTM68qmQDxVfMSA+Y=;
        b=Xh5N6YXNdMPF0zOP3vcN0SvcVcKlSMgqZ90fWyQDJdmpxGwT7Hwq6attVqUu7Aa11S
         8E8da0dIbkA69STDpvQdNRVsGqqJY7YbNxTmpq7rGsAH1Nh917y6atJePZY1uS0NgztM
         hOf6upTOKa4Ayu+S18kekDdNvpJODciJeVeL/q0Mkq/06t+/KbHJHEHqcbCJQY4J01i6
         rvxckkCDtPXnr6ZjI9eNUZbasuqRLOcaCl+Qe3wn3yJyn2ilfWXEMTBC3F3TYl6ML3Zy
         xUeNGytVNbHkyWyNqXayYoIJGE166kNXFGN2SRfuezp2ENlb0iczgG1YTeDzHmfSeGWd
         Txrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y0vuutaOzI4ELJZEHFA53abQJckTM68qmQDxVfMSA+Y=;
        b=XaIh/Q2EouD18+RgysWuuOreikBJImODu+fsRMsxYCL7OLA/QuLKxGzUS3/9TqNncY
         SOcI0ka5cIjNkDyP005k74QvnUaSVvbRw25pxZWqQtGapY8Dkgioep+Ntr0ml7ue6tTy
         AOk7+JNBkqurkaOsBmlCm9+yEWU4bifalVMMlYv4l3kCCzUWGTdiboHl6jQYH82/GpHQ
         uAE+kw3BcaWv0zts1N5L4/UtRvzjrf8HFYXa65d5Sdv1Spor4gVDFqU2qk7Law7zA4cC
         BwIkf4tP4mepaVF8nuNeWrW3jeSjEzwx3RCm1I7lIVEKRXmHPBbr+s8MoB+0l8m/2cmN
         Vh/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530a3NQQvKwrC5NBS16iw06Sd3J9yrhR8t9piq5Qnz63AD2MSZRk
	sNrKbX8hco+I753BElge38s=
X-Google-Smtp-Source: ABdhPJzLWAjmglPuN97FSiqP2Ch9f/B7YVMhufAyuap6Yko2uommHwOeJMeVv0kxuh+zCIeSl5ezqg==
X-Received: by 2002:a5d:5008:: with SMTP id e8mr23882939wrt.83.1638565740060;
        Fri, 03 Dec 2021 13:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls5310044wmd.2.gmail; Fri, 03
 Dec 2021 13:08:59 -0800 (PST)
X-Received: by 2002:a7b:c007:: with SMTP id c7mr18000229wmb.82.1638565738996;
        Fri, 03 Dec 2021 13:08:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638565738; cv=none;
        d=google.com; s=arc-20160816;
        b=dfCImaBB5QHm0oXquQc5s0SXjoGUHyhYb6ZRFrw+cr1rj6iEBscK2PDJtY9+JmFUE5
         yTxWIMsL6OGfkWKwuhtl2oozLEyNpK1WTvlYDq5Bb2pSqbMC9JTm4jhoeTTvsvnPKpGO
         mYfwdhjLwKBdtiK/CUq6qs+HVGUtxCzVinQX20euGUM2JyqH/q+BwV+lzuYW/HVet58G
         vL80UoGDVu0l360YWZbXDf53xLKwnIHkvfV+6k4SdmOU3JcoHoPVzOuTQ6vSf7ndmoiR
         6t4JQWrzJPZogkq4jIN/5Ddf3BwKYEy1GInnlqqMGbr8uhTkVpnjeFLp64D17p04/C+K
         y3YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KuZTROtbXLzmE/hTTh0jzCTIbCvYvpN9SbGKwDB3/es=;
        b=LL200k2R5KtmEIi8BH5lLLKjZJMHfJMumcv86r5KoEhic2AwUgQFndxmJx3e8EFcAu
         ozBA9CKIo2jU2RoRdgbI0gV2jDfEhAQp79G+pD9wj7H0AFQb0Ag3RR+UYnURst7nqQzd
         H+hWqn5VplnZf4MRnfniTgBVa93PtFxAfhHzERaXCuLNAIzkPLZ6S6aOorHkEuse6eS/
         6haeVTQBj/xNvPD0SVXgeCGghcKdsbwYEy0jKCnKIps/+KTXl3b90WvjDCVXHnjAtRM7
         IpCsZ7bNzkZdT0LIyn7cRwqVul31moZujiBTqeQfoHD1Sk8kPb/IRm7buHnzXRl+Iz2N
         BYBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ur99wvPA;
       spf=pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id z64si742946wmc.0.2021.12.03.13.08.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Dec 2021 13:08:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 725E4B82958;
	Fri,  3 Dec 2021 21:08:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D79AC53FCB;
	Fri,  3 Dec 2021 21:08:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id DB1665C1108; Fri,  3 Dec 2021 13:08:56 -0800 (PST)
Date: Fri, 3 Dec 2021 13:08:56 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
Message-ID: <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com>
 <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ur99wvPA;       spf=pass
 (google.com: domain of srs0=jahq=qu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=JAHq=QU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Dec 03, 2021 at 08:50:20AM -0800, Paul E. McKenney wrote:
> On Fri, Dec 03, 2021 at 09:56:45AM +0100, Marco Elver wrote:
> > On Tue, Nov 30, 2021 at 12:44PM +0100, Marco Elver wrote:
> > [...]
> > > v3:
> > > * Remove kcsan_noinstr hackery, since we now try to avoid adding any
> > >   instrumentation to .noinstr.text in the first place.
> > [...]
> > 
> > I missed some cleanups after changes from v2 to v3 -- the below cleanup
> > is missing.
> > 
> > Full replacement patch attached.
> 
> I pulled this into -rcu with the other patches from your v3 post, thank
> you all!

A few quick tests located the following:

[    0.635383] INFO: trying to register non-static key.
[    0.635804] The code is fine but needs lockdep annotation, or maybe
[    0.636194] you didn't initialize this object before use?
[    0.636194] turning off the locking correctness validator.
[    0.636194] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.16.0-rc1+ #3208
[    0.636194] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[    0.636194] Call Trace:
[    0.636194]  <TASK>
[    0.636194]  dump_stack_lvl+0x88/0xd8
[    0.636194]  dump_stack+0x15/0x1b
[    0.636194]  register_lock_class+0x6b3/0x840
[    0.636194]  ? __this_cpu_preempt_check+0x1d/0x30
[    0.636194]  __lock_acquire+0x81/0xee0
[    0.636194]  ? lock_is_held_type+0xf1/0x160
[    0.636194]  lock_acquire+0xce/0x230
[    0.636194]  ? test_barrier+0x490/0x14c7
[    0.636194]  ? lock_is_held_type+0xf1/0x160
[    0.636194]  ? test_barrier+0x490/0x14c7
[    0.636194]  _raw_spin_lock+0x36/0x50
[    0.636194]  ? test_barrier+0x490/0x14c7
[    0.636194]  ? kcsan_init+0xf/0x80
[    0.636194]  test_barrier+0x490/0x14c7
[    0.636194]  ? kcsan_debugfs_init+0x1f/0x1f
[    0.636194]  kcsan_selftest+0x47/0xa0
[    0.636194]  do_one_initcall+0x104/0x230
[    0.636194]  ? rcu_read_lock_sched_held+0x5b/0xc0
[    0.636194]  ? kernel_init+0x1c/0x200
[    0.636194]  do_initcall_level+0xa5/0xb6
[    0.636194]  do_initcalls+0x66/0x95
[    0.636194]  do_basic_setup+0x1d/0x23
[    0.636194]  kernel_init_freeable+0x254/0x2ed
[    0.636194]  ? rest_init+0x290/0x290
[    0.636194]  kernel_init+0x1c/0x200
[    0.636194]  ? rest_init+0x290/0x290
[    0.636194]  ret_from_fork+0x22/0x30
[    0.636194]  </TASK>

When running without the new patch series, this splat does not appear.

Do I need a toolchain upgrade?  I see the Clang 14.0 in the cover letter,
but that seems to apply only to non-x86 architectures.

$ clang-11 -v
Ubuntu clang version 11.1.0-++20210805102428+1fdec59bffc1-1~exp1~20210805203044.169

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203210856.GA712591%40paulmck-ThinkPad-P17-Gen-1.
