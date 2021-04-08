Return-Path: <kasan-dev+bncBDV37XP3XYDRB7VXXSBQMGQE5E4FWPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 14A913587CD
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 17:06:39 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id m22sf1134339otn.4
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 08:06:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617894398; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q11Pjj7Ibi9rHwGiKhZr2CisgRyl2z2x+OgW2B5c/LnHI7C0oc6kOplgLhNEkEgJ8P
         iePQ3tFmtqP9x/jEkdCHZdmpjIdxuDyXQsP7/iC9xNjUTbR3uWz26ZudQ+R64a7rIReo
         M0QkpH+Zr863hCY8oc3IUCoq3todzQhVsnlCjxs8IHF11F5O26UeSdULhVdpMyjxc3I4
         C3TAqsDq2Swvph3a7bmmMgVrXMllhI9JtFBXgH9JZ4QiKKZbX9nC+9bd0CzKegLrhoiP
         ClMUXS5eM6yACEC121zVuC0kP4qRHAPl9MmN4kUmBkKqFfL5KOVvwTvrbsgmncFz31Sy
         OWUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kz1X/sBFERF8PyTJzBXxONEhzncSYNnik6OoiJAeZ0Y=;
        b=1KIAReVkdHwVvBNjy1F2GzQPZu4HwTq+CcOcXlU6OCACljvFoUfHyKCNXXH1yScyLS
         aprRmGulj8Y/XD4vDn/TJAXOI5A/XgwTTX+s5dHQSzTGG3otpcXTlHWBn6Kys6tZtota
         qHsFcwgLtyzV4ojAjM9KHiS5xM7HN6UswfDIjn5rRCs0/ZMio32GzNM5xeApI3PxqpQa
         bNqgcUljGCO97nbSySSZ5+1bkgQZNNDfojUoF2Wqdqrlkqv44w5TO47WCbrc4XPbbIfZ
         rp09KDX6NEq5z+EGV4drSivSO7oPfsZz0hFbnSizmWwB2YmIRFcNxwmBCos7zgBrJQFo
         +emw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kz1X/sBFERF8PyTJzBXxONEhzncSYNnik6OoiJAeZ0Y=;
        b=PKmjZj2jWS5hr+DbMuNyjK/Gu2fGYx3JKpUmLeD2eVIuICLLzSjxYDtzk5ltwSs5P/
         UalTfqdvEDCzlL1K3ScsznpCerC4eAUrCokqdV/vvqIH8323Sh8W0sFcEQGVRHbDQU8l
         gj68VBU4bXdekgZS75fhnmWqhT1XjRq04s78LGOsYBthYB9ofO9WlyQT1cm6n2M6hlZv
         yO0SoK1NKw5gQwLQr1/Y0usmaWT7R5ivmcUFendmwbjavKcN/CLSET4M6vdn7OMOmviS
         SeO+R4p0pGO7aDiQGfA1yPUlqrZf0lRCMqTU3WGGgyFlRvMnLYcHooe4WJaJ+PXOZivK
         BnKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kz1X/sBFERF8PyTJzBXxONEhzncSYNnik6OoiJAeZ0Y=;
        b=qsUNDpbcpxJfRQ1h86nmYSNxluzcXiU0qGChD3dCJgy6J+RO0u5C18584+h8CBrHCT
         N7DLTqgCJz/wRAOqL2UPS8LrHGH2aMibSpw5wPJLr7UbB70pgkNS4BLsZ0Mc441unuIP
         Yd2cBk41VrdqGbFE/x7jgpEVXdZr3MkYjehGuQsA2A1Ayhufr3C77hYmnS/0dCNfh/5D
         pM+ZW3eZJLhHJxKn5oie8tXqJvx4lWAd1f35BzmFIeSdfTDNDSX6xE9BaLTrsSzrUUI6
         xHF52RMk0B6j7K4FIMhBvsmBW5l4K1r2VwVtHSRcFKua8cbm9ejc95lovpkvBrrGDvai
         LShQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XRdcygZ39soNIc+7vJkBEx+cBApY3npbojBhgE1v3y2B5noDm
	krlz0BBymwWB4X1s/owU+YY=
X-Google-Smtp-Source: ABdhPJxTyrFPONJkgsSVNUpxRuTXT3mdBkfNWj8eeXvOO8eoSQAJ2unTY4MiZLvGkG3xu5UbnK8RXQ==
X-Received: by 2002:a9d:d02:: with SMTP id 2mr7677899oti.330.1617894398064;
        Thu, 08 Apr 2021 08:06:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7456:: with SMTP id p22ls1432968otk.11.gmail; Thu, 08
 Apr 2021 08:06:37 -0700 (PDT)
X-Received: by 2002:a9d:610f:: with SMTP id i15mr8052375otj.131.1617894395124;
        Thu, 08 Apr 2021 08:06:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617894395; cv=none;
        d=google.com; s=arc-20160816;
        b=g6SkBVILI9iL/5cETKaUKYA1bhUdZTtXukxhpZD2OIySSxKSnV3BTM0yoLbgW4avSu
         gve2JXFsOyQfOWOhtLwvClFe7zhr80NBeTGWIVsVIWz66X1lyrGuSL5ok6HZQLJc2BQl
         pULANxg7vLZL0kTZLzD7lV26sf00rcDdYv9zDc2NfD+bj5dMvaIpPgvY3QwTh3gUzp0E
         JY3OVQw0bHXgQu+cdidqQd5KlnUJcrmRmzc6WaQ2/ziu7QgIUZaecenumiElihA9TyST
         0xXWkDasvD5cDpf7mO0+yHKz2WfgpvWjv4QCLp6MqJcBx59ZXytILkvNGSIzWNN5/mv2
         dlOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=gXmfbAZnOIOLqkZ1rTdg1EnVN9yW2sGWfKonNcnG+Ag=;
        b=uB98J+YH0XGMER/ibiuCL795XzfnhUNRALQ6cyhZQWT6y9Od11ez4N6xi33AjGHteJ
         7A62eMmie+N3O6zxKYD/QKeE7BZwX3Cp7UrbkhFGN7Rjzg2KSR8/gnzgTEiM6IwqACmw
         4Uf21Tbo6oriTlL5IzLc9GTF8vhpJqnEMaY5+gELsTPMQy0LieI8FlA6fdrNYcI5O5XS
         lawmb46RFGChbEXhhz1CXmKEh7GruRFM/FO31Jvk4Kjx+ndD6f4xiI++V3/Ei4YL1VXb
         J410bUCNDlmiyqymMsVtxtq9ogcU4ZZtaabsa9lRX9Y7EhbHwvKrFYlzIkU13KmczcJP
         n2pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i14si2010322ots.4.2021.04.08.08.06.35
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Apr 2021 08:06:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AD7CAD6E;
	Thu,  8 Apr 2021 08:06:34 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.24.62])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 21EBB3F694;
	Thu,  8 Apr 2021 08:06:32 -0700 (PDT)
Date: Thu, 8 Apr 2021 16:06:23 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210408150612.GA37165@C02TD0UTHF1T.local>
References: <20210408143723.13024-1-vincenzo.frascino@arm.com>
 <20210408145604.GB18211@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210408145604.GB18211@willie-the-truck>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Apr 08, 2021 at 03:56:04PM +0100, Will Deacon wrote:
> On Thu, Apr 08, 2021 at 03:37:23PM +0100, Vincenzo Frascino wrote:
> > The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> > race with another CPU doing a set_tsk_thread_flag() and the flag can be
> > lost in the process.
> 
> Actually, it's all the *other* flags that get lost!
> 
> > Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> > exit_to_user_mode() to address the problem.
> > 
> > Note: Moving the check in entry-common allows to use set_thread_flag()
> > which is safe.
> > 
> > Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous
> > tag check faults")
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Reported-by: Will Deacon <will@kernel.org>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  arch/arm64/include/asm/mte.h     |  8 ++++++++
> >  arch/arm64/kernel/entry-common.c |  6 ++++++
> >  arch/arm64/kernel/entry.S        | 30 ------------------------------
> >  arch/arm64/kernel/mte.c          | 25 +++++++++++++++++++++++--
> >  4 files changed, 37 insertions(+), 32 deletions(-)
> > 
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index 9b557a457f24..188f778c6f7b 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -31,6 +31,8 @@ void mte_invalidate_tags(int type, pgoff_t offset);
> >  void mte_invalidate_tags_area(int type);
> >  void *mte_allocate_tag_storage(void);
> >  void mte_free_tag_storage(char *storage);
> > +void check_mte_async_tcf0(void);
> > +void clear_mte_async_tcf0(void);
> >  
> >  #ifdef CONFIG_ARM64_MTE
> >  
> > @@ -83,6 +85,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
> >  {
> >  	return -EIO;
> >  }
> > +void check_mte_async_tcf0(void)
> > +{
> > +}
> > +void clear_mte_async_tcf0(void)
> > +{
> > +}
> >  
> >  static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> >  {
> > diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> > index 9d3588450473..837d3624a1d5 100644
> > --- a/arch/arm64/kernel/entry-common.c
> > +++ b/arch/arm64/kernel/entry-common.c
> > @@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
> >  	CT_WARN_ON(ct_state() != CONTEXT_USER);
> >  	user_exit_irqoff();
> >  	trace_hardirqs_off_finish();
> > +
> > +	/* Check for asynchronous tag check faults in user space */
> > +	check_mte_async_tcf0();
> >  }
> 
> Is enter_from_user_mode() always called when we enter the kernel from EL0?
> afaict, some paths (e.g. el0_irq()) only end up calling it if
> CONTEXT_TRACKING or TRACE_IRQFLAGS are enabled.

Currently everything that's in {enter,exit}_from_user_mode() only
matters when either CONTEXT_TRACKING or TRACE_IRQFLAGS is selected (and
expands to an empty stub otherwise).

We could drop the ifdeffery in user_{enter,exit}_irqoff() to have them
called regardless, or add CONFIG_MTE to the list.

> >  asmlinkage void noinstr exit_to_user_mode(void)
> >  {
> > +	/* Ignore asynchronous tag check faults in the uaccess routines */
> > +	clear_mte_async_tcf0();
> > +
> 
> and this one seems to be called even less often.

This is always done in ret_to_user, so (modulo ifdeferry above) all
returns to EL0 call this.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408150612.GA37165%40C02TD0UTHF1T.local.
