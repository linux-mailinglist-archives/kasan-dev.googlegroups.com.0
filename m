Return-Path: <kasan-dev+bncBDAZZCVNSYPBBI7DUCLAMGQEASS352A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27A8056BAC8
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jul 2022 15:31:16 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id j12-20020a056512028c00b00482dd0d9748sf4773029lfp.8
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jul 2022 06:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657287075; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojsMr3x89DX92rYt+v85bMmqlW3d6n6j2/u/8olNsCMFSyFMlEsZiZYXSyqN5JEJId
         8unbt4tEt+PUKtDGvU1Nzx3/wEcOZn4FOWWpb39JN44MUSHu+KcwXLw9Ljhpqp8lFE5w
         FLAQnGHY+B6i34AC/Yglxm+exW/4P48Dd9yriA7wNKRiL46d+a9Jo3+zmmP5i6wgGHkR
         H5tbVDc6ScOU7SRT4Iu3AuSf5L6seaCFrT5VhuePXty1QanQ5f93iPxYJZwM0SVwLQr9
         k8HGhxVyiAbrxjvktsuYjDcuYjdf0c5F3k+T06GXxDKc1gy7khta7jviQMWH0XbA/oja
         +KDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=j24gavB2iFlowMCMSfxlDpt68VTLG8r3/vJBdznQYA8=;
        b=Fe2hLCf52/VuHwfJnsXU4/KDuKtnSdqPmGPsbHCnXscmb+66CGZz7mGBdunvbYQnCS
         1coW09pW5OFVR+9YhUxIASWZUl/hqcHIz8MT2yX+DikbyxymN6FsGpJAdZBPnXU2riqM
         wxgOMbFX8jm4baZgtobtZ5DPVnHgCndrfpOxa8lktiF0lqsuLAH1qa2qYB8Oe/Y6vFIP
         HHuuIf25BsucxGJvOb8DKM7zXiZDZal2BUJjqXiwilfM52keQgedOzUjHRrdNvUPkxDV
         C2Cnj4XntpZO2d3zXGf82c2Hty7BzItKrdzI8R84rM8FywK6E4pciBrrtd12J11zftd5
         C5sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mM4a+/N3";
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j24gavB2iFlowMCMSfxlDpt68VTLG8r3/vJBdznQYA8=;
        b=YeWZ+qaB5YI6wcSSKzbrXIYEnR1VU2FsskP7zB+pJzGLptIjpCtxs/etbZHB1OjuSV
         o3BjJ1EcofdQiBccjRmmSt2twqDiAbt65y0FgKbahTNIHyxJ0dcU/+foo6vHljuJGCgo
         Wkn2yHc/UXbIU/+XNtt97HK2BT6J4m4VRDZsa6ie8ZZWfd1abNsUSe+rmJCM4oOCZvcv
         oaxpKd5ieB8w0t8XkTnMTG673LkAQuFHu2qrbcQCvcTyNPNwhOTCFpOaMTx+pcBEdx+k
         byM1LaRUb+JxK31xRN43SFXSljHjkxHq4A71EJ1XwDiKaNOHipzB6uVqvF0qcZ8RsPRi
         uWiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j24gavB2iFlowMCMSfxlDpt68VTLG8r3/vJBdznQYA8=;
        b=46YSLDyeE0zjURmZ9fXqwkGq1e04V5NOJ7NfP2h3ZtH3LOLEN3KQ18SPffJPZz8OTS
         7BPY4+oqrDMuyKNxz62KWSXRST9Y8Pu+i5GDDPqu+DpHXKogY6DvUrAE04vHk8tAK/Cv
         1+xrpb3AmoCPUzHwGCYF+8SDNI13sDDhWMHjiAvQmb/1HGTHIFFdamMnUwaybWqseFaV
         XqEiH9F2DAfhDHtd00P1RTDiK10wPz+S0h4zACAIEpY1l2ldYGfuvvSEN2fws0YOfa0H
         DLYtI2HU0nEwhqM6v9tY4zyoDSJgsAOJMvRg7van5mlu5MywrLLKnrbZCl3JMCuDTk7c
         nDRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+7s3nOlo8qp4ziATNBdlx3wBWf8QK/s6IoA9U46BeWTQqb83Pb
	C/hcvmSl9qEPhg536w1q2k0=
X-Google-Smtp-Source: AGRyM1vTYQtsfxfq6X4yoNSu1SXk84qOH29xqsfzpmH/y+yksggPVSA/vHLUj7SaypUMyNBDlhL7+w==
X-Received: by 2002:a05:6512:3048:b0:47f:c0e3:9ae8 with SMTP id b8-20020a056512304800b0047fc0e39ae8mr2446766lfb.640.1657287075319;
        Fri, 08 Jul 2022 06:31:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b6cd:0:b0:25d:5128:d32f with SMTP id m13-20020a2eb6cd000000b0025d5128d32fls831507ljo.2.gmail;
 Fri, 08 Jul 2022 06:31:14 -0700 (PDT)
X-Received: by 2002:a2e:a7c7:0:b0:25b:b72d:aa3c with SMTP id x7-20020a2ea7c7000000b0025bb72daa3cmr2007843ljp.318.1657287074199;
        Fri, 08 Jul 2022 06:31:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657287074; cv=none;
        d=google.com; s=arc-20160816;
        b=wr2boLwr9VdFbwH0N8sCtLXa6IW0KD33S4eW0I5k9/4ZsN1dz7GuPoMzRFwZ9aEQMP
         HqI+K09rRirr/Ml2kZRNGNgNViFsDh2Nvso6Ux+9E5JEP7keui3N322GuJOyeroc+nq/
         c2VunlAB+kTY7e+mCNrWxvnCdnj/KrgcOLg3B9PQlb3rRd59VFiqyfdgDLndQjpGNATv
         L052bZYHFJjz+wxViK/zTxJbwpK/lFWnR07fxRKf9Zpvk0YSKP5esgd1mzzXF+hw3iU4
         V4D3S4GNi0oYUFhNEtsIylNX3BPDaNNJuqS9qxzqwvR75uVaXNAiWGDmLRGssGCh9VI6
         ofdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8L+LxeI9tbX1E1pK2U36kMjg9if57bZL7WJQAt65A/I=;
        b=uCyYubxBBuRtP+0F9qLLBwdAiKpolpt2TLZct/8QdZpcm265TR7nMGqhFG4E5I6hO0
         BlaqIYE+yGy8z9Tc8QZSnlBH9foiJyX17te8FifwwYKkNmCRQRZgkobG0zPPV+gZ0/18
         AujNmhtlOAlFW6fzSll5j/BU3odOwubQoj2aChC5FuGooChuUga99Pw0lxxZZU0lWdmu
         reKaDslb6WCvNxKBLt1D5ZJmUI5JryCgH8RKayBb8L07gebBcwOOY0i4f18nkrLTlZbi
         2Qr3cDFyUci3tLhPLJlVrs1TEpDOVMdCRyFLHaaM4fOCDIa+qdqhQQSv6xJJ6Yq346W0
         77IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mM4a+/N3";
       spf=pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id cf26-20020a056512281a00b0047fb02e889fsi1592231lfb.2.2022.07.08.06.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Jul 2022 06:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A4274B82795;
	Fri,  8 Jul 2022 13:31:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C4A80C341C0;
	Fri,  8 Jul 2022 13:31:09 +0000 (UTC)
Date: Fri, 8 Jul 2022 14:31:06 +0100
From: Will Deacon <will@kernel.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Message-ID: <20220708133105.GB5989@willie-the-truck>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="mM4a+/N3";       spf=pass
 (google.com: domain of will@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Jun 10, 2022 at 04:21:37PM +0100, Catalin Marinas wrote:
> Hi,
> 
> That's a second attempt on fixing the race race between setting the
> allocation (in-memory) tags in a page and the corresponding logical tag
> in page->flags. Initial version here:
> 
> https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com
> 
> This new series does not introduce any new GFP flags but instead always
> skips unpoisoning of the user pages (we already skip the poisoning on
> free). Any unpoisoned page will have the page->flags tag reset.
> 
> For the background:
> 
> On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
> kasan_unpoison_pages() sets a random tag and saves it in page->flags so
> that page_to_virt() re-creates the correct tagged pointer. We need to
> ensure that the in-memory tags are visible before setting the
> page->flags:
> 
> P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
>   Wtags=x                         Rflags=x
>     |                               |
>     | DMB                           | address dependency
>     V                               V
>   Wflags=x                        Rtags=x
> 
> The first patch changes the order of page unpoisoning with the tag
> storing in page->flags. page_kasan_tag_set() has the right barriers
> through try_cmpxchg().
> 
> If a page is mapped in user-space with PROT_MTE, the architecture code
> will set the allocation tag to 0 and a subsequent page_to_virt()
> dereference will fault. We currently try to fix this by resetting the
> tag in page->flags so that it is 0xff (match-all, not faulting).
> However, setting the tags and flags can race with another CPU reading
> the flags (page_to_virt()) and barriers can't help, e.g.:
> 
> P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
>                                   Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
>                                   Rtags=0   // fault
> 
> Since clearing the flags in the arch code doesn't work, to do this at
> page allocation time when __GFP_SKIP_KASAN_UNPOISON is passed.

I've picked this up, thanks.

An alternative solution might be to use a seqlock (if you can find somewhere
to put it) so that virt_to_page() spins briefly while the tags and flags
are being updated.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220708133105.GB5989%40willie-the-truck.
