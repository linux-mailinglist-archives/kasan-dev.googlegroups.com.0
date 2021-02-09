Return-Path: <kasan-dev+bncBCT4XGV33UIBBPNQROAQMGQET4B4TBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id E5716315632
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 19:45:18 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id e12sf10079555plh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 10:45:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612896317; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oi8Ygu/sR5Zm40IHX1Zl442ZIHSeMgPz9AM+uKeICPU5mdyAr7nTIHNmzSPRDJmEPU
         pYlHR9VlRY/1OGQOoehhG00UB1743AkEz+Gwlfa+ziQnokXoQTQ01puXp30KmlFPPSw3
         CEddlNV+508ozL29uTe7eJfnPn+94y7mbIV8uxSTXMFyvmqoSRZRr9cu885eEE4BZ9lj
         yBFYmu0I5yeMedMlfhjcOCng1upL3YkFGnWzzR7lLLmmg9nBjUiIU5bj+TABvBGMKYNP
         wusIxSAhCsMUjdOhhZQinVmsFrYVpw6cAUcQVIeeihHg3331e/SBDRVKuj38ctHDNYOV
         OfQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BneGPIip2tEZ/oFL3m/Qp2aGBI/XAfe4uvfxDT3w/xU=;
        b=Mjg1+kTBncAM2D+qE55sOl5RNyjTCVf6Ysj+XX61VkhVqSLLo9A1vZmaaJ3Vi7r2/3
         kggEacX7Cg+TwRdve4/LnnaMYwKQuwNkZmiv5keaCmTNLLJ59p4xB07N21PjCwVNnl8g
         EGPjijL4bMXahmigvb0nAWk9+jprjB6a+1PxKfZtyRy3LJqWDOmMUbcnx9bhYTl8WqWv
         Rh50ld3cGiQ+f3t0cIJF6EWm3QahNyCbCAuBtnvxwz/RjAFg1209w/GaoFtr5yU3RtcF
         Ygw/rI2aWh44Np9KKrg9xcsaTqiXvdaw3Tf3Qz78H1fgdjljWwpE/wpKlXdYioftGNWc
         FupQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aP06nY6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BneGPIip2tEZ/oFL3m/Qp2aGBI/XAfe4uvfxDT3w/xU=;
        b=JCMdIXXlgasMmzkBbnLD1k/HJIGmPwGnbI6muhFthvxG58eMUMLBA6q9vCjiQe+uSa
         af+GnR4LeccM59PBYKBH6ivyZPP1YB140rEp/fU/Qz4AxlKmOpexn9DqhoKC7kM5INaK
         oaUtEzAsPFKGss1hmKsEcud9cxpAm8IPXz6jzvGYQdlhI50GGkO/dQqTBU7pds2Q6I0a
         8HJ1MNt8JcU2wodwrTtW6pmRILPBepI0lw2h6evnxnIB2RoDS4a344cwMDourwiZnhZm
         CCGdgvt3gA8t97SBbg5w8kfcxGvtvPWQqlMKWMVcyI/a3GuU7gA9Of2JLnOrBJl+gRUn
         vDTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BneGPIip2tEZ/oFL3m/Qp2aGBI/XAfe4uvfxDT3w/xU=;
        b=NqZeYIh/KuiYG0d/hZAKqujJNVAPB2SJnPJaNMhC4tI4S1mLgFAgKnTeIyqOGPCfwU
         bd87G0vdy6Fdv0l4XhKfq7q51RssJzu06116gVgsf+ZhQq9o6g/JvkNXnQABeG1qFQin
         uYLbkuHYNnjscrBNZzYYfrKIFetV3ZkEcp3SDyWp7IK9VCKl9QxaqvVy5AJK8C7kxFsE
         gQjWUIljiIMUyQQi7F3HCa06okBciIBtTShyvB+Y5qK2FObSvf7EdKCh/2oVnc5n0uSR
         zaag7BQjmNGK3FAZD9+Eft6DjID6cmH1TXm3sh4pvLF8d+1QAmQku50onLWgcU7k+GA0
         aV/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324kbRfw3vGAqD+NBckbVHnhF38MIJdDFOX4io5ytVUU026Ov9W
	beA9cih4sm2l5qkyAmUio/Q=
X-Google-Smtp-Source: ABdhPJxRornvO/c/6uwpT9hglUtMpY2flRbxVa1q359BhKDKq+jBAjg3nZIHSXRrVFSBRYC4LRXCyA==
X-Received: by 2002:a63:1c08:: with SMTP id c8mr23047404pgc.228.1612896317698;
        Tue, 09 Feb 2021 10:45:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls1898347pjb.3.gmail; Tue,
 09 Feb 2021 10:45:17 -0800 (PST)
X-Received: by 2002:a17:90a:fe11:: with SMTP id ck17mr5360317pjb.152.1612896316939;
        Tue, 09 Feb 2021 10:45:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612896316; cv=none;
        d=google.com; s=arc-20160816;
        b=O5ploT6pMG19RrCBuNl104JJr/1EAQOc36QL7Knq7UcbNLqL8O1Qs848Rb4H6qUKm6
         l+IiPFDR3z1xPi9ihdtDNosmgscuKzU/a6dsUutVYdruxFbjx8ZoiZ1QmBuwTjbpGzoX
         56gzWmjKZVFmJMPIETxphx9O1pBIToswm2KMmluUITT9YI9cwcZqtraDzi2RMOrkMBoE
         mhXx3g8W+gNrH7usNxsunmWap9s15SoIKWnNPgBl0rSpaC4HsEgZdQY78NGwduLWwZQ+
         n+mMwB1IJ+WTM39PcXev59zKGHkmjonK8mdYj1nWjrOckFN9xPM8EwaB993ncp2439Ej
         ViBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZSP6NZUyh3pgqRUrnPeG3BwpSMiDpG1qXXPiNtN+T9A=;
        b=wEr6hGCrlGpVHz8iKOKAvUaEwU9NMGvX+mkg6CoB3l3Nj0DIUvWPgSXmfCoNLKyYD6
         tRiwt9+Tw2ulh27bMnHcTOT7+noKHDd3ans3kN+UJS+coF8OxJdrS918FNorHIy9jLrj
         Kf7SgdYK3oZzFhatT497p222WhhTFpRPFHutzL0OcgXDTU+odKkV3oa5x+2fa0R//gBZ
         03HtouatuLZURyUmNp8ZaThBtkpY/0kSMn6McX2StbuerwyG9/5ZnmgwvrRsNwzFlooq
         qrQx2Z+WygqOSHg8hsLC30cpHUvap6F4DLi8Mlxat3FvNVq0MTLkQTCryIGYGoDf2m1D
         GrPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=aP06nY6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si194474pjp.0.2021.02.09.10.45.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 10:45:16 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B9D7A64E7C;
	Tue,  9 Feb 2021 18:45:15 +0000 (UTC)
Date: Tue, 9 Feb 2021 10:45:15 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Will Deacon <will.deacon@arm.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig <hch@infradead.org>,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] arm64: kasan: fix MTE symbols exports
Message-Id: <20210209104515.75eaa00dea03175e49e70d6c@linux-foundation.org>
In-Reply-To: <20210209170255.GG1435@arm.com>
References: <dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl@google.com>
	<20210209170255.GG1435@arm.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=aP06nY6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 9 Feb 2021 17:02:56 +0000 Catalin Marinas <catalin.marinas@arm.com> wrote:

> On Tue, Feb 09, 2021 at 04:32:30PM +0100, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index a66c2806fc4d..788ef0c3a25e 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -113,13 +113,17 @@ void mte_enable_kernel(void)
> >  	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> >  	isb();
> >  }
> > +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> >  EXPORT_SYMBOL_GPL(mte_enable_kernel);
> > +#endif
> >  
> >  void mte_set_report_once(bool state)
> >  {
> >  	WRITE_ONCE(report_fault_once, state);
> >  }
> > +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> >  EXPORT_SYMBOL_GPL(mte_set_report_once);
> > +#endif
> 
> Do we actually care about exporting them when KASAN_KUNIT_TEST=n? It
> looks weird to have these #ifdefs in the arch code. Either the
> arch-kasan API requires these symbols to be exported to modules or not.
> I'm not keen on such kasan internals trickling down into the arch code.
> 
> If you don't want to export them in the KASAN_KUNIT_TEST=n case, add a
> wrapper in the kasan built-in code (e.g. kasan_test_enable_tagging,
> kasan_test_set_report_once) and conditionally compile them based on
> KASAN_KUNIT_TEST.

In other words, the patch's changelog was poor!  It told us what the
patch does (which is often obvious from the code) but it failed to
explain why the patch does what it does.

The same goes for code comments, folks - please explain "why it does
this" rather than "what it does".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209104515.75eaa00dea03175e49e70d6c%40linux-foundation.org.
