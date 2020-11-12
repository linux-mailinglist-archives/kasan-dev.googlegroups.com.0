Return-Path: <kasan-dev+bncBDDL3KWR4EBRBWEIWT6QKGQEDGK45DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CC672B0234
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:46:01 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id e142sf2251547ybf.16
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:46:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174360; cv=pass;
        d=google.com; s=arc-20160816;
        b=VkziKxQ00YGLsMci1c/bQHE1C2xr4a5jdd+G/oAvXZViYpMSb2r1Wcefwwt9/o8qNM
         1yyTg5NrHSqD4IiGwpRR90gZSNYyCov0/va8GgiRSa+XzS9jqwD7IujuwvV2SFxmQDSn
         dIh4K2U6yTrr6vQd3ObAljjvo7XeWrgZwi2jPSdCRL3v7FiucjYgEV/kz4OdvJ3xPr7V
         CzR56B4h55pUnwRkDSeJR6QG1Y4+sBiKdwqiqPR+/08KpMfHTPFAjhVxivx+dg7nf/O4
         98rwQtHQRFtwa3TFTXs4Cs0WRnOKYNbCf/pSSfDqdefd8DSJ9b5J3jpCKfyxd59J7uTH
         844w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=NQVsiCyNwlrhXhbbZQ9Hq2y0DMO+y7FVRoUOAeq6WvA=;
        b=sjLDMihNiXe+5QlHYPeyagT5tXztPHqh8Fibl8hkPYzwuVWaFZxWOud+uryM1omADV
         WjtwDOhmi2f4rIzT0yWT6xvj8MWz/lw8vs3WE+ijBEBpncAsg3KN55gOv78VwY/vn0hi
         m5bQrbCpk6byY5trlYpIfhOQzLDfw+x+rn9MS60cuSAb/gzcW1t8ZDpSF2bjqp+cg0rf
         enoyXqH1E7gVmxzTLhpm4IEhLOKY5KC431LmO/0/JsWGmV/lWA7ytLRazCntQJjvR2bQ
         DX+J4mO5jmxSk6Z5+aG2xPrQQWxLYWQv/s8siAQdmuSxYg6sk/YgQV87mQBPyoexIzwL
         MZ5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NQVsiCyNwlrhXhbbZQ9Hq2y0DMO+y7FVRoUOAeq6WvA=;
        b=HQzlqggRv1zd5/1XOWW2lzel4Onr+fc7ipC9A9DrXp44V1IdAYZSAPYLfRqvfgbRs4
         5TnhEtgGTY5Dzc7RaCqN3+XALEVn4X/OwBROVaX618+K4STK2IxNefsA1QoqlL2mGCqG
         UHYr9aVa3rrnlIc3mFUsN5uD7SqsZt4rBMYSrOuMJUOVDaf+z50tmitIfu50helQuXdL
         Zi6CkAH2XaWNQQaEGtNAx2tNrpWZ4ROiRXLAqkBweQ1HYmndW0ncE8M+K5y37v/FqScr
         VfWcghW19XjP1zIZ1OGG3mTOEjKzajjyDIRh8YS0dT2PLOZlQyKhzlkuNK0q5dRq+6qX
         ilxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NQVsiCyNwlrhXhbbZQ9Hq2y0DMO+y7FVRoUOAeq6WvA=;
        b=SkCyMJBZMoifHU0sjaMBW3WVgboAYzgxJF3U5kRG2z+NEE81YH/f6NQ88A+o1VLbEy
         ad4Llc0F49CvbJ51/JNHqMj5zmzyKYeG+4UKVypo0UKdzQu7X+F7tnsRSljrmbRPFkLm
         IrRMaQNRJm1GyowXCcYxQ53b554pHsv5c88Q7I3xM9fDM46qaUyIk8nv+YQ/4lcLE8Rs
         0NnFq7MKiP0dQPmxcUjxDMORp2MV0FaDHQdsurJQKXsDS69m/w+a4QlFXUTkoVYBgm4Q
         Eadz3Dz0Xo61Hw9ukUNvT/qeZPRy0d+9wq5if+roDq0OeSTefosZviydDSL2dfJttJGZ
         7YAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Jh4bj+AXma77wgKOG+sebUaQPv1isF5FU3REassFrh3p9RIAL
	klvDB54HJT/f5vnfgy8RKdY=
X-Google-Smtp-Source: ABdhPJxminzaRu4uy+RpYoZmYvSwKJvCCHymDChbZ6shvJQTiVo3sg+DBzbgaSMXyNWU+7Nf5J3EjA==
X-Received: by 2002:a25:e6d7:: with SMTP id d206mr7422995ybh.67.1605174360318;
        Thu, 12 Nov 2020 01:46:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4e08:: with SMTP id c8ls1353445ybb.3.gmail; Thu, 12 Nov
 2020 01:45:59 -0800 (PST)
X-Received: by 2002:a25:bbd2:: with SMTP id c18mr41225372ybk.442.1605174359798;
        Thu, 12 Nov 2020 01:45:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174359; cv=none;
        d=google.com; s=arc-20160816;
        b=HghT/EKOs3vCLZ+0TtAPx01Cfx5XmcGGjs9y7Yk7nKDZ8k8KnPNkd8BlkCKNfMbmXp
         agdSa9LThbQjDsqaQvOOmrQ/FifCwAO3Uu+0dUM9oe2IozsV04NVrMGdTdWKM66dlvE1
         zH1X/ut9Kdr/9Zhg2XFeMzhjcxTCQjnrGzSb8LMeBjya7h/JDUHR/fptQ2mXmfuZwF3U
         swNzKRhQ9YrEqGprZgxH3o1krkZVYYi6icaGAaZZIXUALr4NNGGSrBXQ2HyCssxiGCNn
         a7/G7t2cHBtYIkHkM0bYuxOP3J7M9rCdulYeXYMLS3qiuaCl2+PpCLP+5zWANGDJHZEe
         rINw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=8yvplyIxyLNN5+vQGZ0KCddQPjDsiWtp9/Oko0Gspp8=;
        b=qYx3iQ+vkRyO3mFv6pYG3P4vOA9fxOkwIxmy+6il7+c+LjPJL0h/N8haxQ+nyJve/e
         SiJzRH0hbYQsQf752qLfZ1a5K9RcSw9gr6DMhzERK2Rmr4ChaVtrtjV2kKijizh095al
         mTbNOs2ILnLcLIyRPQt8OdgH4rDxQ2cfRB1MWBV6hDKTGW9QT1E1ee/bLXHlyrXi3+su
         I+iZQ2ZGYow7lxLnT913TY0HEZRg1MNZCIXNIyHqecMbS+SX6K8pKBUJDUE2IkGfL5Ot
         ot791kxxscbsKmDBoCxAbwqwoo+8ch1LpPOsiQE1Gk0EjXURRfqwk4StsDzBveMGy/7L
         SJZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n185si273392yba.3.2020.11.12.01.45.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:45:59 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 000EF21D40;
	Thu, 12 Nov 2020 09:45:55 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:45:53 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 32/44] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201112094553.GG29613@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
 <20201112093908.GE29613@gaia>
 <db6e3a5d-290f-d1b5-f130-503d7219b76b@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <db6e3a5d-290f-d1b5-f130-503d7219b76b@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 12, 2020 at 09:45:45AM +0000, Vincenzo Frascino wrote:
> On 11/12/20 9:39 AM, Catalin Marinas wrote:
> > On Tue, Nov 10, 2020 at 11:10:29PM +0100, Andrey Konovalov wrote:
> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 664c968dc43c..dbda6598c19d 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -129,6 +131,26 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >>  	return ptr;
> >>  }
> >>  
> >> +void mte_init_tags(u64 max_tag)
> >> +{
> >> +	static bool gcr_kernel_excl_initialized = false;
> >> +
> >> +	if (!gcr_kernel_excl_initialized) {
> >> +		/*
> >> +		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> >> +		 * This conversion extracts an MTE tag from a KASAN tag.
> >> +		 */
> >> +		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
> >> +					     max_tag), 0);
> >> +
> >> +		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> >> +		gcr_kernel_excl_initialized = true;
> >> +	}
> >> +
> >> +	/* Enable the kernel exclude mask for random tags generation. */
> >> +	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
> >> +}
> > 
> > I don't think this function belongs to this patch. There is an earlier
> > patch that talks about mte_init_tags() but no trace of it until this
> > patch.
> 
> Could you please point out to which patch are you referring to?

I replied to it already (or you can search ;)). But this patch is about
switching GCR_EL1 on exception entry/exit rather than setting up the
initial kernel GCR_EL1 value.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112094553.GG29613%40gaia.
