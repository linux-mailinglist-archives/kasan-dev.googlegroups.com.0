Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEW24CNAMGQEZZOVNWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46B9160D3A7
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 20:38:12 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id v17-20020a62a511000000b0056c0ad6a1f9sf2109407pfm.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 11:38:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666723090; cv=pass;
        d=google.com; s=arc-20160816;
        b=atdmCERArvuvpXtY97ThhMP3oxx9yz8rZCUdgenzFob5H3pmCyzxtiBK4MyNmGPH9r
         TeEFu1LyxLJtd+pJd3WHXVFeUC6rAY7bJXWUoxFsxjekYivojsXS4I3iAgl11KPjqNAz
         ifVf7+/XMMn77CK9k2lsFT9GBeazH8tvKdZl1aKLdSD5r7ve4dDUbFYW49FhXJw06FyZ
         t/lB9Nne19iMczX8nL7KS7n4UY0LPzWXG0UB6AHv5uP6JD6v0DrVrkE3E9WUKCoaGVUk
         dibFo34sCnnLb+CF0JJhQK5cNKg2wrEY7scXJ0nJ85Xm1M7EpccCXh4KFNUYeXlnEGBf
         ynhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pgeoyvcGyK7EBMQXYkTcugUarZiSlliA08ojqjSY09M=;
        b=j0iGyVAnyFcl7Or/Ms05bs5vhwcEid6/4BxCdGmvAzTN9kpE3qsRGiMoS5PUxLGnm8
         480PY6ulELrZujkCEhzD4NaBaFq4Y0+GeBm7VU6/LnnAILIZD+PbrsscQEDIrVVvuiPv
         /bmGU5ilcNxjdXmS7NVbZsQFS/ROora56aWpIKtcf4JgFdRf5ZPi4Ryz3fk+QnGNJL9f
         fxsLNqpoTM2lJYZRcJ6obmz915vq0HIHBfUMtRPg2T73czzvzXLJxwTrdN5DlffZKChx
         doQ70qj+jSPf/uU9hQbqkorCPh//zZhU5WpEO5aFEvQXcCih0HIFzUP6/nyJKaejveCC
         6pzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=acruGIdn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pgeoyvcGyK7EBMQXYkTcugUarZiSlliA08ojqjSY09M=;
        b=YE6QuMGsOkouKTy5B0Jmw8xVD0c7wj9804cn76L7AtuZnHZNqQKk2PTOi6zZiAQfCt
         tq9Td0J1Mguld8lvfHnO4f8ZEVvXNxSatRZZWbHjT/Y0BDYu/XYFLtq3yTSOi6FF6sUX
         QHkQiUorZS+lIV+t4U6V10WXwuYjZxKl3UzH6xD2Y0/RlUCcbka3sxvTNgmVyZ+tOYQ7
         A1g4jfpdKEyz0E6Ru8YnJvOIydt/CaqEy1teorPqr44dVMKP8Mw5sbc6FgfD9FlYBwn0
         J2A6JZ8rb2QP+Fc1plwd+zKsEpaKURt+HuhVyO/aFd9Vp73iRVHZ+3hTStAzxcAiUM08
         R/yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pgeoyvcGyK7EBMQXYkTcugUarZiSlliA08ojqjSY09M=;
        b=2iFKTHFGFs8Lc07zA5SFOP0xOUqXjt6uCr+lIBMTk8pfE4gSXNyHkPJKyz7edpSwW9
         6cFPtHTse4+jn3jamINMcjXrZ8E+x5mEWlKfsncDBZhyh35tGG/rfYl5uLMPuPDPnL8w
         hHOt/OAwmtFH8AWoggAP6njQ/BJiZpW/D3zT4YcJMLDtxjwwkMl8CEaQHQ5VeoRO/+m2
         CpnK8qSe9yivK1UHjJvRxlOK1LmetGXHeo0XCkRvwZBx89ugKazklVjlck1lRGjsEVnr
         A1nl73z+XYMTmwfpZA19mYFoCv0dOrPSn1ygXsaUg2+nGikOiKe5UVSuqidzOeeAw+PA
         KeTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0LKeOiYlYQaBA3gSSZcyeYE/KZLlAAjiKMVfL3rynrTAYH8mQx
	zeCv2860TJOOcuHtCSpQvsM=
X-Google-Smtp-Source: AMsMyM6zbGlw4S1Vf92/XoU/N8LnF6yseT2gjHyFiQCcxlXbtLrweax31Szen2FqC0CwYvFm5T4VxA==
X-Received: by 2002:a17:902:6aca:b0:186:8431:d7e4 with SMTP id i10-20020a1709026aca00b001868431d7e4mr21750933plt.89.1666723090207;
        Tue, 25 Oct 2022 11:38:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:680f:b0:213:fe:7f8d with SMTP id p15-20020a17090a680f00b0021300fe7f8dls4819742pjj.3.-pod-canary-gmail;
 Tue, 25 Oct 2022 11:38:09 -0700 (PDT)
X-Received: by 2002:a17:90b:380b:b0:20b:8dd:4f5f with SMTP id mq11-20020a17090b380b00b0020b08dd4f5fmr82936564pjb.158.1666723089467;
        Tue, 25 Oct 2022 11:38:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666723089; cv=none;
        d=google.com; s=arc-20160816;
        b=uphBzlg2UMeYHYpfWJHMwSAHVzyjZlHgAE1NAFV/kDOF8sA51a5JSU29W5GwDoL9lJ
         8+1ONG1VuXnYPHhi5BghPG0R/J2uscIGKEMQEBG1CO2QbC6YL/P21eXJp5FrbkT2ru0N
         2oIWxVUTuiowBNqKNMiC6FfdWCctA8NgglepcKgSoKc/SiK5rEmTd9Oo84Gtn3yoROeN
         k3Nu+0RYNZDyqfGhzHpihguPpPLpaHbxtQciL62/Cr5Rsj2yrysplXLsBkhZIz6N8ZDi
         49pNI/77/CEdyuxLMyB905cYEE30iaBAgUZYkugE4Rnxntz9eai8RhMETNSkcM3vT8aM
         oQww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j6v7OmtMJ2b16XOxoV0FAPi5R9UZMGGxZ5W+ahrXitU=;
        b=vmm//93sBTX3GZZL0K0NpRRchmo5p3vOG266hMy7q0TfxqYhkfIVDantJr+PIv32dF
         wimIedCc1Hf+PepEo0ABkKX4Yrqv4UEQ5dW4xKeMPbcCesoTULvSBuu4uq2hEN6DI7OD
         IQYq/IMWka25Z+3wiHOUBTvUJmkYEFv3g8SNsx1nRSdLgndYxQRvrQKA2TE8XpWj2K5x
         CgelUZQIvF7upSwTWkdgFm5LZpMXSq9aD2lknANKYl/kA98VL3bpWW+DO3wVj4InGE0y
         HBNes/11u9F0jPIbx2FbRdbJ8nMqgaN+FlXTJSDYudTVPOKSKUF68MmVNGweQa7hLoLu
         WcpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=acruGIdn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id q3-20020aa78423000000b00562230e14d8si135746pfn.2.2022.10.25.11.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Oct 2022 11:38:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id c24so11707892pls.9
        for <kasan-dev@googlegroups.com>; Tue, 25 Oct 2022 11:38:09 -0700 (PDT)
X-Received: by 2002:a17:903:181:b0:185:5696:97c2 with SMTP id z1-20020a170903018100b00185569697c2mr39858718plg.160.1666723088910;
        Tue, 25 Oct 2022 11:38:08 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id m3-20020a63fd43000000b004393c5a8006sm1568091pgj.75.2022.10.25.11.38.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Oct 2022 11:38:08 -0700 (PDT)
Date: Tue, 25 Oct 2022 11:38:06 -0700
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, netdev@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] mm: Make ksize() a reporting-only function
Message-ID: <202210251125.BAE72214E2@keescook>
References: <20221022180455.never.023-kees@kernel.org>
 <fabffcfd-4e7f-a4b8-69ac-2865ead36598@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fabffcfd-4e7f-a4b8-69ac-2865ead36598@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=acruGIdn;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Oct 25, 2022 at 01:53:54PM +0200, Vlastimil Babka wrote:
> On 10/22/22 20:08, Kees Cook wrote:
> > With all "silently resizing" callers of ksize() refactored, remove the
> > logic in ksize() that would allow it to be used to effectively change
> > the size of an allocation (bypassing __alloc_size hints, etc). Users
> > wanting this feature need to either use kmalloc_size_roundup() before an
> > allocation, or use krealloc() directly.
> > 
> > For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> > some of the partially open-coded ksize() in __do_krealloc with ksize()
> > now that it doesn't perform unpoisoning.
> > 
> > [...]
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> 
> Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks!

> > ---
> > This requires at least this be landed first:
> > https://lore.kernel.org/lkml/20221021234713.you.031-kees@kernel.org/
> 
> Don't we need all parts to have landed first, even if the skbuff one is the
> most prominent?

Yes, though, I suspect there will be some cases we couldn't easily find.

Here are the prerequisites I'm aware of:

in -next:
  36875a063b5e ("net: ipa: Proactively round up to kmalloc bucket size")
  ab3f7828c979 ("openvswitch: Use kmalloc_size_roundup() to match ksize() usage")
  d6dd508080a3 ("bnx2: Use kmalloc_size_roundup() to match ksize() usage")

reviewed, waiting to land (should I take these myself?)
  btrfs: send: Proactively round up to kmalloc bucket size
    https://lore.kernel.org/lkml/20220923202822.2667581-8-keescook@chromium.org/
  dma-buf: Proactively round up to kmalloc bucket size
    https://lore.kernel.org/lkml/20221018090858.never.941-kees@kernel.org/

partially reviewed:
  igb: Proactively round up to kmalloc bucket size
    https://lore.kernel.org/lkml/20221018092340.never.556-kees@kernel.org/

unreviewed:
  coredump: Proactively round up to kmalloc bucket size
    https://lore.kernel.org/lkml/20221018090701.never.996-kees@kernel.org/
  devres: Use kmalloc_size_roundup() to match ksize() usage
    https://lore.kernel.org/lkml/20221018090406.never.856-kees@kernel.org/

needs updating:
  mempool: Use kmalloc_size_roundup() to match ksize() usage
    https://lore.kernel.org/lkml/20221018090323.never.897-kees@kernel.org/
  bpf: Use kmalloc_size_roundup() to match ksize() usage
    https://lore.kernel.org/lkml/20221018090550.never.834-kees@kernel.org/

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210251125.BAE72214E2%40keescook.
