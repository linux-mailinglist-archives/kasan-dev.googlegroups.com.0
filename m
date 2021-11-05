Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQXUSWGAMGQENOCN3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 8736C44688A
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Nov 2021 19:39:00 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id u11-20020a17090a4bcb00b001a6e77f7312sf2301453pjl.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Nov 2021 11:39:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1636137539; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKUHKGfuHJzafcKIQHcoNEw+qdAMTWdg/Q0M0HDEHuYH+BFvUGBB+Au/KoMdp7aFxF
         QuT72Kyds9AG+/9xNsRvoxMFe1PmV8/ulTGRAIf+cUXPp3ts5Y9BjjPTtdaubuMf7D7M
         MI4eR0sDBR9CePbMLp7XdBr4rOgEM7vScEFpIS0olZ2vyf0Gh3Q6amUeNDaMJL34fLbr
         PbpTEVuKj9RptTbcnglENxK+ftZQ5nkPX3a7wYurl5PJvcN1ubwqe+nl1I0cZcjkmRF2
         DLdko3m6F1j/wqyYUDFsqqvyhrmj8ImxWbCRPCAUldLd9laVQf6IEBOkko4dlTCnsZ6q
         jb5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+ZasSzicDSqVnFMHqVcDCAFne0N3NDSn4sHWUZh5t34=;
        b=CbVs9ryVlbGfj9HA/rm0xhfAB6FPr2H999SEXvLOiSkDYApWKsdC4/62u75s2866zr
         d/auUyRrLA7wOKYBifvbwN6y97XYBizuhIOOh/7yFCjNFyo8R5ZzFnffOZXZRcjTcBgr
         AdFfmyKUIWglIzw0jRr4PDS+dg9zX9xr8If+DNTiniixole3alCPjLZDr4RylvTv38Lv
         +4nwEUcvf5PZvZCCDktEUox9rNDLZ2krZQDFu66FMElj/EAOabWBj0J6gUA+7atJF7OY
         Adx2BYkzAkNZ/QcYR9S1eyhGGLAJBU8gV8i0CqunYwrqNMl5yw9jB/SlUYiwMtnVvEir
         IIBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+ZasSzicDSqVnFMHqVcDCAFne0N3NDSn4sHWUZh5t34=;
        b=Gw2dyKI36VzMhjCe6+p5Xn9W2Kzyq9KLQvyhkN+d3uCnroLAQ749YxyLsVz4K9ZiMe
         9mh76HL/b8K+Jodet8zjt4u9lcTeaQxqnwxC+1iLA70avGU0PMU88DcaHAJwDqmsufua
         BbVeOxGA0SQBtusNVMqCjfr4uY5En1057yWZIfNAeR9Q9Y5xjtF92AkdgXJqFYvpSCnP
         CundKDnbUD9j3IW/Jmv4yvxanJUWmKAJ1JHmUXqffghmzIwlEJsARUGpF/5UYcsE+uIn
         w1G/ZcnbnLa0n7fan+h8AHJMqRyNUn8dLoVh+Sa03TLMvSHa/jfdjcjBiwhzr0/OOgcy
         e3mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+ZasSzicDSqVnFMHqVcDCAFne0N3NDSn4sHWUZh5t34=;
        b=IIAgOPVkqrVIVneuheUfQ12Csk/PeR2mYoez1Xvx1bgxWtRcSEDwKLWV2ZOJmLRkVE
         OfjoyYKvvkpJQ9Ht2xNwCZj8I6f7hsgCxS7rIc5+wDBa27TdWg4bUDQlicH5Et+kpbOw
         lQNzkEYajjumRhKtuaUXebjs1N4OIFjGayUTpvpX7bu1yDfAtt4p8+Pi7jgplbGOMcUc
         ATtILSMAsejPlsGWWBuhalhzK96wDRfbV03omKPPjm4Kn67WsWUD34nH+a20paxNEw6u
         2jtcu9AyYKiQmTjU1SoKcO4XREVVm8QEWtPfPPpOVn5OXIiIope04FFvp3paJ3t23isQ
         xErA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533APksDqFI02Mp66YhIEzLQGXyPTf4s81Kg+CLH2LqXOHIl3xh4
	Ly362oTJ8DEKG7GIv8SDolU=
X-Google-Smtp-Source: ABdhPJyXOsUBp3qRgILV2niw8qGeLWw2alKg6NH2ln8O1wnogGPu5PSqevJsBBe7/wIy+bfkXx4ENA==
X-Received: by 2002:a62:ee17:0:b0:47f:f597:eb77 with SMTP id e23-20020a62ee17000000b0047ff597eb77mr49797409pfi.14.1636137539020;
        Fri, 05 Nov 2021 11:38:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da8c:: with SMTP id j12ls5261769plx.4.gmail; Fri, 05
 Nov 2021 11:38:58 -0700 (PDT)
X-Received: by 2002:a17:90b:224f:: with SMTP id hk15mr13170062pjb.173.1636137538426;
        Fri, 05 Nov 2021 11:38:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1636137538; cv=none;
        d=google.com; s=arc-20160816;
        b=XzUzr9VBE+dTosQf55QzSOfLaumn8XyyopYELVaWLivOP89Y4N5BJpc2yWjQzvA2Io
         zzyM1+1FV1tAqKS2vjdu+p9/MC1w7aFzT2Id5XTNLlb5FZ2tIo6u9lHA+xshMD+lQUij
         EKpsIvT/izdLctBwW2ijcusUXvNZVjX9V73xlG+/vSIhylWCq5/g0odAjW7R124YkPaO
         xegoy2pMFDCklP1+KlC3xzCtb2zn0Gimz1Jy/wiH2MIrziJpZ5t9rj/a0l5XE6VlBJWC
         NeQzk8ATkwjurBuL+jIVsPXcSVr+Ha4MtqWbFOOHXV20oLN+1x291iGoAhOfLNdcQ9EI
         N++A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=nTlceYOcYTEl8/B0wV9RLjMXfgTBeKQZXRjMzBzUb8M=;
        b=w80s7b/Xg8zvMZ4jEDMb8JmBHCAhvx1xBrMS8gNdvduk6XBHOaSSVpqfM/0xUA087f
         wBFRPMIsNLUS+oZpiLYp0qfRvMAxvk777QhKZkEx0yW4ZJYAlfT8Fv7XhfP2tNzhxkxK
         iWRWSWiMPSaF2fpZ1WcEuYw2EYIFEgq2zYX8Gif+EmcXZoc34zFIwmLF4B9mJLG8zhrr
         v0jyGqzHxFB7VXCEfOZtRA9ZJRCkE9sTKxRjcM/SeIgu8VlCPQYa2no+CCXCFY1VgmlR
         LFXmQrIQ4F7/ThcIv9hOuzBZYKljITbyVHNRsKt+yRsRRs/0TsMK0P1WlWssRHRYmnFY
         mrOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b20si448143pgw.4.2021.11.05.11.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Nov 2021 11:38:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EAB9F61131;
	Fri,  5 Nov 2021 18:38:55 +0000 (UTC)
Date: Fri, 5 Nov 2021 18:38:52 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Qian Cai <quic_qiancai@quicinc.com>
Cc: Will Deacon <will@kernel.org>, Mike Rapoport <rppt@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Russell King <linux@armlinux.org.uk>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] arm64: Track no early_pgtable_alloc() for kmemleak
Message-ID: <YYV6PPpH6Y+APfsm@arm.com>
References: <20211105150509.7826-1-quic_qiancai@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211105150509.7826-1-quic_qiancai@quicinc.com>
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

On Fri, Nov 05, 2021 at 11:05:09AM -0400, Qian Cai wrote:
> After switched page size from 64KB to 4KB on several arm64 servers here,
> kmemleak starts to run out of early memory pool due to a huge number of
> those early_pgtable_alloc() calls:
> 
>   kmemleak_alloc_phys()
>   memblock_alloc_range_nid()
>   memblock_phys_alloc_range()
>   early_pgtable_alloc()
>   init_pmd()
>   alloc_init_pud()
>   __create_pgd_mapping()
>   __map_memblock()
>   paging_init()
>   setup_arch()
>   start_kernel()
> 
> Increased the default value of DEBUG_KMEMLEAK_MEM_POOL_SIZE by 4 times
> won't be enough for a server with 200GB+ memory. There isn't much
> interesting to check memory leaks for those early page tables and those
> early memory mappings should not reference to other memory. Hence, no
> kmemleak false positives, and we can safely skip tracking those early
> allocations from kmemleak like we did in the commit fed84c785270
> ("mm/memblock.c: skip kmemleak for kasan_init()") without needing to
> introduce complications to automatically scale the value depends on the
> runtime memory size etc. After the patch, the default value of
> DEBUG_KMEMLEAK_MEM_POOL_SIZE becomes sufficient again.
> 
> Signed-off-by: Qian Cai <quic_qiancai@quicinc.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYV6PPpH6Y%2BAPfsm%40arm.com.
