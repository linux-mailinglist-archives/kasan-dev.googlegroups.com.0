Return-Path: <kasan-dev+bncBDN7FYMXXEORBKXZ4K7QMGQE57LSO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 011D5A854BE
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 08:54:36 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6e9083404b7sf30228036d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 23:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744354474; cv=pass;
        d=google.com; s=arc-20240605;
        b=d3cOW24StKAeZ4Ln+d9kEb4P62VU28D1DDUJik1s3MVeNeJ7GIHHFNLqwj3bNzO3lo
         6/vvyZLQ/B6MG1oKp9A266JAQ2T16fboSc6mvBVgytp3CF1OZz8XiAkAtd/XGAVfrEFk
         oz2cwjg3F6B+fyh24Lpe4q9S2jtvl2vFJnO2wffRyuqD5vdNfPR9GbmgbrUZu+TbNEO2
         fMLV2LZ4hWrrYfoNypqBt/re5LnEsxq+vV7ZpguoVvEGRR7Jy6Ado6TMAi8YhhCRE/M9
         LhkbHkgTVV5vQzjycDBWYpA3O+FKWKHXo6CT327He7nIV4eTUcD9wGJJDEgwpsLH91+S
         eoWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:to:from
         :subject:cc:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Pjd4/9PrIqT323PtvnBcD66LEyb6ftEBFRxNwnocbtU=;
        fh=XSwfKrEb+BkGra8LWYMcFgdsIPsjqJ9/PIw2VkKGZMM=;
        b=fllohMGfmQapeE/UhvlabnO60fJBqDum/DV/l4MD0Aygj2iau8FwF75eVk3GPIjRp8
         Qy12b87hW6mKYhJk6FAzEDsWRTPKIEEHvcEcm+1TptdDiX4Lw3pACukMlzmFaQ3uYtde
         zTw6zMNrc+epDwoQOu9fi7twd5svwaltWIuIooGGqolprwDPXoOZa8nEi/p+GpnDcne9
         2B83FgkYAo8NfqlttY6MukTxlqYVoZLtUxe1fMRtS5PXyfGohL3E2PfcAZb8rlP0Ad2L
         xiUckrdhfWqut0RoakFI9ejs6RnlHEmFc0//pqnD2qnWWGU3Qmk7iA3aSra52FE3nsSX
         zWpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HbVyhux4;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744354474; x=1744959274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pjd4/9PrIqT323PtvnBcD66LEyb6ftEBFRxNwnocbtU=;
        b=IliFQf6jlnA4KNyNwPqB4zDsucakwg1QIc6c0YPWdBBbpaopfiPViLthcKxgM76fFV
         yB0sgxRRLP41VaBm/SiBICsLlIEW2X3ZxdKnflhiYqzqwP0sE+rbZ5oCWKZljrhnrJaX
         ExYJsS6H/fTtqYQjWNcB2NLbC6rvaZfZpUGNIXeN25xjXUvmfv1DlJMC/1swvjObf9En
         FM1KlDgEVMSzRtAZyfoD74qAb//BsLZxVoM89tu867T76a/qEp77rOXfJBBQ4sr93bPT
         r8oFErA0d+NLjDJFw/Ewc+q4oDTM+BgRuORsom+Fx1JE8D+SAuhNp66MmrHWfXc/akOs
         h6Tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744354474; x=1744959274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pjd4/9PrIqT323PtvnBcD66LEyb6ftEBFRxNwnocbtU=;
        b=VxuUPqe+H2DXozjskLyxLKiejoQCxxs3e0lr1rFPoFkDixFTegcjloQ4Q1nW5ZjWuT
         cLJzFOd0lst8VMMRS2bsh6tVSHSXzUH5aRpbfU7qnhuf9sAu7SkA2scClsoe9nGNlqkm
         Tx0MJBqdC9gcOKoV0B6YhVpWhZKE68NKcTtNbR5E/0rjfk2EzKKQzuFfa7loXEOBR5Nr
         Hbxy6KAB6iIlJG8yX1/F3CNWHqrHBKlauJLEsnZncLpwhXIOmUuJP4+gNFh3pL8qzswK
         lyuRagQwsy8E+KS1CvwS4p7so+37IIVjtKefd++HFVTsPnj4Hos/M9GUG6DNGK4NO6t6
         6CeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744354474; x=1744959274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:to:from:subject:cc:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pjd4/9PrIqT323PtvnBcD66LEyb6ftEBFRxNwnocbtU=;
        b=GA7NhPR3cnXte+rz86vnZyuEcgxAt7fPsKWeD8hH7BlyqsIbd3h2YYA+qAec9Z5buW
         bmEipZh4qVxceUL28hN0Ixh55bbsniW4vEh9c9LEYPRDaSMASHDwXsQNOX0tsZke5/QW
         pNIRh9PlNNmMOSWyqPBaI51VDPC7QXFQdZV16E1uvJvBEsr7taI0Mdon3DHVb25qvCg3
         v3pmIFqINQsy8N+5ELrg50MV+OPZqHARDJ+R+zy+QXW6hMKb7wWhzYgMyd5N8KfK6chb
         GlwFTXkw2i+4d016uUZfiBIGD3txMPOzRhgdc0has80jLDAoxQqy/hW065n7Cad0xbXr
         XEHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVWnZ2/YYJf53foYlkAqZDSIowKptWuDbXHt72XDU1qfrQhHddAAv79SdWtyRgJ88XSwpHlEg==@lfdr.de
X-Gm-Message-State: AOJu0Yy47yIWskIDyBBIehPvTiSplCHzl3rseWBQcyUdC5IihiPApzDx
	ONVp0bErQ3jC/M4wWSTWNMk+S6mg+QS3utFK85JSvtwHMX6u85lb
X-Google-Smtp-Source: AGHT+IFoFG0p6zj6LPQhZ6kf9kZRiTyGysWqr2HgLv4IQSqnzblkYjA9XdoHbc1M9+4fB0BslZ4jqw==
X-Received: by 2002:a05:6214:f0d:b0:6d8:e5f4:b977 with SMTP id 6a1803df08f44-6f230cb359emr27928486d6.5.1744354474487;
        Thu, 10 Apr 2025 23:54:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKFzi3hq4ML6wabpkZeT51cCGN8WaAieaJKsu9n+nIdbg==
Received: by 2002:ad4:4ee1:0:b0:6d8:f5b9:2be3 with SMTP id 6a1803df08f44-6f0e49412a0ls15055126d6.0.-pod-prod-07-us;
 Thu, 10 Apr 2025 23:54:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUieMYuu3DNWx0Y0k64mYaFyLgdOnr4KQND2p747qS5yuTxicFCtHRUuGnwJPna6VZ30A+6NoOT058=@googlegroups.com
X-Received: by 2002:a05:6214:20e2:b0:6e8:fbb7:675b with SMTP id 6a1803df08f44-6f23843f190mr27878016d6.32.1744354473487;
        Thu, 10 Apr 2025 23:54:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744354473; cv=none;
        d=google.com; s=arc-20240605;
        b=H/K48l2M6/gHR0C/DX0tVP/8VhzL5ddrMyFfRxYGA8/u5U6SMYW9SXZq1AlH7oXIBP
         McI+9FvE6Jn6uqqMx6s/RT9jLwzqTVx7C7ozR9EjsM1YIqltjSLn+81LcCzz3WKmXIYr
         TF7e+tjMCn/FYol/HZ6vFPSba0CGacDHDBFoGqgINLwZKazT/poH4ktvG0G8MVLlsO+Q
         kNBMEM4thfAvCi18IkIdQfEtNM3NigEDWVbBPe4GngvAHdyCd8I+d2Ptr1QPgngNG1lr
         HE25ewqUjYr1dHFJ/R8LCC+WIIBGPCok9LK9aKh++dAgWGxv8ft44gzD2AAEsBXx76MC
         9fIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:to:from:subject:cc:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=EMrPec0FtWGKoKqlWKZKVYlPugkOpwSx2KisPfbkQKU=;
        fh=5DqKLHnuwF0pUhV2MOLMTb+MSjyAxUMVhJIv9UgtSOk=;
        b=RMYja09CVCeob+ICoDBmJDFiLCgmQgpzuPWarXPGo5gaD0xPoKJ56RaJLFFiZkJ4EY
         3o/4YKnHzam1C9IsEho9mSiWS/zxIHocyFIELvIcDrlLhCtPj5BEv+e5+l9ytt7be/0R
         Z8K0Ou3TCCWOOo70LjXRPBuyoe7BRIHPYa/zxXi98V4W5xa6oDmZ4UknzKS38UIAeiOP
         AonEMXNQS/+ATjedVul7V+hwR9Gqim+GPgixtezrI/YS0b9cbq+LMxijbBUUcMY+nuxl
         9HNR83wj2jt5Q5Z8PaGja7lOmHfyWAYIz9oFdjyZvAZGb3jPnvWZViOKnvVWA7d/7J2Q
         F35A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HbVyhux4;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de9eb0fdsi2535256d6.8.2025.04.10.23.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:54:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-224100e9a5cso18225355ad.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Apr 2025 23:54:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0DnX7TotW5Jw1Y7Cnm5Obx8cJErJXU/dAkJwQUpvoj9Dn5ckORrdMFJB0NH6dS5+N6vYem6WvvzI=@googlegroups.com
X-Gm-Gg: ASbGncuBrnDqwOP6cyDnpPSciFBAOrWTPr7oIjkqyAgrcT8+wUD6hhurgn4bb6809f3
	9Rdv/rubLVIqC3p1Tbb6mpHwdsRn9QqoRFgSWFYszzm/mRRf1glZIIgY4P2S+l3SOva8pTaUqkj
	4Z7E+fvmGaGOdVdoobNj1z+ctnGRA+MJQqezcfoGaChtQvF/W/vRyd2tvJKLWN5lEqNrjmyKLYz
	A6F6kugmPEw5m7Xj2z4hCRrO0wY5N9qU0bI8sWqXF3fGXBUaVtwoOc4cVMS89g/Krf9C4iOZF8e
	e0VnwGCCO7XOIf+DSZD0h2psizfK8wEw4A==
X-Received: by 2002:a17:902:ce8a:b0:224:191d:8a87 with SMTP id d9443c01a7336-22bea4bc62emr24301425ad.26.1744354472347;
        Thu, 10 Apr 2025 23:54:32 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-73bd23342ddsm728537b3a.164.2025.04.10.23.54.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:54:31 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 16:54:25 +1000
Message-Id: <D93M1ULKMFVB.FY9I2463RQ68@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH v1 1/4] kasan: Avoid sleepable page allocation from
 atomic context
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HbVyhux4;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62e as
 permitted sender) smtp.mailfrom=npiggin@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue Apr 8, 2025 at 1:11 AM AEST, Alexander Gordeev wrote:
> apply_to_page_range() enters lazy MMU mode and then invokes
> kasan_populate_vmalloc_pte() callback on each page table walk
> iteration. The lazy MMU mode may only be entered only under
> protection of the page table lock. However, the callback can
> go into sleep when trying to allocate a single page.
>
> Change __get_free_page() allocation mode from GFP_KERNEL to
> GFP_ATOMIC to avoid scheduling out while in atomic context.
>
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---
>  mm/kasan/shadow.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 88d1c9dcb507..edfa77959474 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  	if (likely(!pte_none(ptep_get(ptep))))
>  		return 0;
>  
> -	page = __get_free_page(GFP_KERNEL);
> +	page = __get_free_page(GFP_ATOMIC);
>  	if (!page)
>  		return -ENOMEM;
>  

Oh of course you can't make it GFP_KERNEL after the
patch to take ptl even for archs that don't use lazy
mmu.

Thanks,
Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93M1ULKMFVB.FY9I2463RQ68%40gmail.com.
