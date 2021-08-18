Return-Path: <kasan-dev+bncBCJZRXGY5YJBBJFK62EAMGQEO2TTG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id DBCB43F0E8E
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Aug 2021 01:17:57 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id s1-20020a17090a948100b001795fab0f86sf5310606pjo.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 16:17:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629328676; cv=pass;
        d=google.com; s=arc-20160816;
        b=U/nNVwCI4PRUXX7Gbjo2FxA9JfD2mUMuE5Qy23nZ/uZtBg0T71KBlaYGgMkC/0r8sm
         erZEiZUnIG1uX0wxNdGfnrzRR5eBqRQdY2h8EVsCLiCzDp2KXbNJH0up3cpNFI5Uy9gC
         b6C8lHoJen1mEitIYvA/eqFp4P5AKU0taiuQalZ6WsIuwjKKnDiQyEebP2hW5yiZZj0/
         AMihPi0qQ1XrNjNymkdF8MfCgUjGmWd9RKNHMo2z6h1OYWnjQwBWLuWTzRBZPq4U9YM5
         H/nDLp5mW6Xh1ldrSnDZKy5Fb2+xiSOFPBXcVFRMv0Ui2dmJvQARclqXdXscfXWGl2tS
         ajLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=+7fF+HwhNgGj7EbIdJVZ3YMcWGIRNutfpsJkvKctTxg=;
        b=lEEnrmcY06KYHTpTUHI+QglEWRJzBYmFQ8Vs5j5BmX9ziemnxhTr7KI/bxKUGTqi+H
         asuwgvKlZviDyS+GlzD5P0hKsu/r69sS8rfji6+9B8VCDkEkDSPV1H12NbgvdHQd2Gir
         1y7xA4T7IUpOCZa6Y9oe5rqRvpaSYZ6+CmNPY75Rv1LLdRquz5EwuhCPd2KoArskaUAM
         q9UrFEYsNV7L4o7b/w9ttyh0YqSrfYycNHFlzs3NNYeahkWeWwCY40vk4Onor7SXcNar
         7pxmjxITdqZLraFrs0XLNDeTZVViALyHCR15U1ndbitJXUWOzxhXSV/pucy+FHonaxfD
         PXvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="IhJFKk/9";
       spf=pass (google.com: domain of srs0=vtnq=nj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VTNq=NJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+7fF+HwhNgGj7EbIdJVZ3YMcWGIRNutfpsJkvKctTxg=;
        b=g0M6E6Bbts1b5DYI7F3n32w9sIpdy6OQXCOxjVM7+M8B4j0NljdStdCn4/9y/c7QCA
         cWb/aloAGpyrGuO9H1KegxisOD5IwcDJcioSvCiR7Gl7JdNrz/8MwgTrKT6UiaywpGHn
         jCntoct+VqNYcQJIVKt0EUyLTe06zKCPtat6Jktwske0DgVjTSAbGtt7fQjQ+d1RXV4U
         EtVmsu6xGXysSbLPzWqBn3OFKfVIZ+FEX+n6mHpcVNRfWBzNYWxiG9wmoCcKRdXlKN5u
         fXK26YQrERWrbxjH5pPSlKFJRy4MEuEDkyHM5go7iNuXGB2Tz8KwQToDZdxFM31Q25g4
         PpPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+7fF+HwhNgGj7EbIdJVZ3YMcWGIRNutfpsJkvKctTxg=;
        b=ZVqQ8Y3sQ1/Lfv00xZ3HYBO10adT7/t3dETRwLARagyGbBIMq94tiJouwKZJACg9a3
         lUDD3uUV8dPudnGggNrxej/WgO0fWRB3ZjyXjJkbQoq55M6DTVkqIf9mD/zfeDVyfC1L
         xDf3krkZr+IVfQTtImV4T/lOZgh7YhaAfFBr7NOB4XvJVRV8wWWF1fwpAqzG9U0TmQZ7
         i3vgQVwd+cmu3UULW3k1flDp4JOezv/YGJF8T+Ddz9EVhCs8ZLlh2aEzq0vzOMGbyjx4
         E9fs+AS0mRDbYtKgG1P3T1Wqgbdg/Yxir3FekGaNVXJ9Zr0Y4tvB3lfv7FsGXrVeSotC
         kOnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MDG4WVmBiMjs6jVynxdjCPjP/MVMV/QXu5cN664NT78Vv8HB1
	uQ5Vo8jZNoGAZfg/hNJRxdE=
X-Google-Smtp-Source: ABdhPJxU++uuTh3jyd2K5uZ1zB4npBnYvlLG/gHvLD36ilTFx2/M2vPHHb8jZH5ZXCSUxNkWEic9nA==
X-Received: by 2002:a17:90b:f83:: with SMTP id ft3mr11664597pjb.173.1629328676578;
        Wed, 18 Aug 2021 16:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f81:: with SMTP id q1ls1958097pjh.1.gmail; Wed, 18
 Aug 2021 16:17:56 -0700 (PDT)
X-Received: by 2002:a17:90b:88:: with SMTP id bb8mr11566453pjb.23.1629328676072;
        Wed, 18 Aug 2021 16:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629328676; cv=none;
        d=google.com; s=arc-20160816;
        b=zEDIKIXrv/xgBrMISkE1LzSsXIo/oeMU+GNepoUipnBoo7NiSHhV2SoPr1QB9lanCB
         zyXxqPzP9uj3TWaGG1OJiHZXY3bS9xn9/MNr8IFfH4PSj3DnAwfWraCvFjSU96iVV2yk
         /XxljZcYZulHzmgLs7yjVzCPzJUPMgBI338L29ZmhdquxMaWm1/cNBWsSovT43ea/Htj
         ebdAd3kwMCPFUX2tS9nhLXwQ93rjjV7TDPWjMdBJEKeXNBvruIvkHu/MrHjWt7KePwB7
         gn4FQvL3BXWFCRZNZwNr0huDN+QPpNHPF1Pbmqu4ohQgCtVyPA5gU2j6Xs4Hku8OCxHs
         3Kjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LzIgD64rmvku6pgHDgLVHhc6uL9tfMBu+ZJtJdFYCSU=;
        b=ztOOn8phlAl1oWr6EB4W3r5WHRUzVPSJ/mV+SmCXiyEkiSPHZqpTN1yKmcfjVRxKm1
         GKCN4NtWMKWPVcVFrNhoNW4WxvQty5sqwdfQZLnttyhvXi/rVYkJMTrFe+o1xxCMWytH
         ROHcD9lnG22/C5HAJztRjorRRIhFJA7BP1KWtnHmWPixZoZ9hyxHKMAGZjg6JK6Bhrsg
         IkD1M2eXL/ZmkMNnRggvWrbTdo78KllhTb7nNbvYNAwQ8fuftf0lWx/DfBPxkWiZU+2N
         NqNEpliUuSn7pvErCiyw9YpvkxWVjm5HTZSGnSAW/YBEpPfRlpvOkNeqFHhPIFKI+QVE
         JBLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="IhJFKk/9";
       spf=pass (google.com: domain of srs0=vtnq=nj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VTNq=NJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x124si95119pfc.5.2021.08.18.16.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Aug 2021 16:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vtnq=nj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B0C156109F;
	Wed, 18 Aug 2021 23:17:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 73EBE5C04B1; Wed, 18 Aug 2021 16:17:55 -0700 (PDT)
Date: Wed, 18 Aug 2021 16:17:55 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Will Deacon <will@kernel.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210818231755.GZ4126399@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
 <20210817122816.GA12746@willie-the-truck>
 <20210817135308.GO4126399@paulmck-ThinkPad-P17-Gen-1>
 <20210818113935.GA14107@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210818113935.GA14107@willie-the-truck>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="IhJFKk/9";       spf=pass
 (google.com: domain of srs0=vtnq=nj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VTNq=NJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Aug 18, 2021 at 12:39:36PM +0100, Will Deacon wrote:
> Hi Paul.

Hello, Will,

> On Tue, Aug 17, 2021 at 06:53:08AM -0700, Paul E. McKenney wrote:
> > On Tue, Aug 17, 2021 at 01:28:16PM +0100, Will Deacon wrote:

[ . . . ]

> > > Ignore the bits about mmiowb() as we got rid of that.
> > 
> > Should the leftovers in current mainline be replaced by wmb()?  Or are
> > patches to that effect on their way in somewhere?
> 
> I already got rid of the non-arch usage of mmiowb(), but I wasn't bravei
> enough to change the arch code as it may well be that they're relying on
> some specific instruction semantics.
> 
> Despite my earlier comment, mmiowb() still exists, but only as a part of
> ARCH_HAS_MMIOWB where it is used to add additional spinlock ordering so
> that the rest of the kernel doesn't need to use mmiowb() at all.
> 
> So I suppose for these:
> 
> > arch/mips/kernel/gpio_txx9.c:	mmiowb();
> > arch/mips/kernel/gpio_txx9.c:	mmiowb();
> > arch/mips/kernel/gpio_txx9.c:	mmiowb();
> > arch/mips/kernel/irq_txx9.c:	mmiowb();
> > arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
> > arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
> > arch/mips/loongson2ef/common/mem.c:		mmiowb();
> > arch/mips/loongson2ef/common/pm.c:	mmiowb();
> > arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> > arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> > arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> > arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> > arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> > arch/mips/pci/ops-bonito64.c:	mmiowb();
> > arch/mips/pci/ops-loongson2.c:	mmiowb();
> > arch/mips/txx9/generic/irq_tx4939.c:	mmiowb();
> > arch/mips/txx9/generic/setup.c:	mmiowb();
> > arch/mips/txx9/rbtx4927/irq.c:	mmiowb();
> > arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
> > arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
> > arch/mips/txx9/rbtx4938/setup.c:	mmiowb();
> > arch/mips/txx9/rbtx4939/irq.c:	mmiowb();
> 
> we could replace mmiowb() with iobarrier_w().

Not having MIPS hardware at my disposal, I will leave these to those
who do.  I would suggest adding iobarrier_*() to memory-barriers.txt,
but they appear to be specific to MIPS and PowerPC.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210818231755.GZ4126399%40paulmck-ThinkPad-P17-Gen-1.
