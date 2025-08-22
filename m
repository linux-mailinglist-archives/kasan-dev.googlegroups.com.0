Return-Path: <kasan-dev+bncBDZMFEH3WYFBBKMRULCQMGQEQVGVXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 90147B31DA0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:11:39 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70d7c7e972esf52596576d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755875498; cv=pass;
        d=google.com; s=arc-20240605;
        b=lC240dsYDBa0+rTaQpawyKo8ty738FMMJhuKiaQUSmzAgdqx7o2nn43iBosCdfmo/M
         PXBCqIFyVqODE6FdAVZLWOV1PRHTroFro/ANQKCMw8JRfDCHUpIIAcldYJ/3d+h4I9nX
         29Ag3Za9+QH7/tPHrVHOOpbvW/1X3avRvZs7kryWP1d9dT6qtxtid/wtmpPEZqRMdZzb
         N4L22m/ouBGaLu/nFRtkxE2n7RH/QS9KAywWyA3WQjgomJValEcTFb2fNmSWT+utAVSs
         ypF3cMNOV52nmdjlv2GjecXUb2svCUA5Nem2hsRgw1MGH9JnjZj+00BiFqjGk7Wjme8k
         Dntg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8dwqcu7ruLRm5tDnFSc6iNGXUF9SLizWWE2cV+RKP7w=;
        fh=DFJofhm+0rYZGAbO2u6yY1DNi7gnxo7pvmfVwKCFaAw=;
        b=GXVXfAyVkYSNr1y+I+rnuVEVgLPjZPFVhge40zjSqU93mvcYLavsQnNZLiLNc4v6Bu
         e2k6CyihZXSqn1iOxAihtU3N6A2cvFcnl6hxL+toppM7Z7sUA0x/o56a9h722qIas9zw
         VfjY1ZlA+juvgYPwoY2rxReoDx7rgyXb5G2heMQhPLyuThVKDZdpG12H7LCeB55UA62x
         A1W3YCCZl1lOuKk50991deGUA5s6HAQha7fc7OKsRRWRZ6ga3zuU8K/Y2Jw+qkp3ymcf
         JRG6zdSU+TxYhI1lbctVhW554gphysv2yHeMBk9qogPYJeFCSwXgkshwv+l2GMnwdxvf
         vwjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bRecik1R;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755875498; x=1756480298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8dwqcu7ruLRm5tDnFSc6iNGXUF9SLizWWE2cV+RKP7w=;
        b=jwNglwVdBdmqj5CL+s1YHC8DgmBZ4iZhrqg28v2mjGSWQxTgm5l3C8ZQLAVZ/pwI3e
         TVBOZIu6GEo8Z/KUSbIqFS9kzrPf8dpu9RuypZfgre+HVFNGq0jtLWCZ7IodaaSj6N9U
         2R7Zx0fQqMidUWeX1lsYi4WzYDNzx7HBhzoOxeasZAiPp9ym4qUmqCCkYhXQTBqYHF81
         UA/S5IaKKyl0R7nc78PW+VhglA7VquCdtobxVJxVxfLe+DjhnmN/nU7crBSn/gJEdXtN
         a1fy76APowEvFMd1sGe/dSiODy5zfGe9l+G3xDskZ2551vN72cJmCdMcIUpgOjDqdiwe
         h95g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755875498; x=1756480298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8dwqcu7ruLRm5tDnFSc6iNGXUF9SLizWWE2cV+RKP7w=;
        b=RSh8fx3EDF2eqsXtzINCcnE/sEb04dEf1+KVrK+maB1lOBngciJh2zP8BQkxYPEZ5h
         uIySHntQqgbqpNH+J2ac7HJJ2ftpEKXPas5/Av3sZSBr5GVn1BLOJCIJvJ07mYxVnMYh
         adacfEaqD5sPdBbKcYIwFSyeIYtu/2sYUIBABSmnon3OESt/1lP1wSAhAuh79fnak6yv
         T6OF+QCnR/niD5YpWkjDhb+/BpH+8FB+1zOm5sHMJx9RzANXOMDnnSdOhONZRwi7aj84
         EUzV4wgqKLNZX1wdFUiVVGB8XW4BHwFAQJoufX8FPtnubgw1f6noeC7ZseiNUFwxXq/s
         hjGQ==
X-Forwarded-Encrypted: i=2; AJvYcCV5ve1iwsoOGsNUmD7DzmlTHDgNubG5/37q/pTK6+Yb5yCSMHBOqS/yXwZpHVl33jBtJU37Lg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7vQejep60+TSTMQ4Ajz0JpKcuXG4FI455lqp+xPJrvK1eTKrZ
	Gd9zQYw/120Pn8FWp6AsxWvQVrWmLNXXAeOdz3gRvGAfrtKyonbBp9WC
X-Google-Smtp-Source: AGHT+IHCIv+dUNQo+QhXVlQwbkVEAgbAkOp/2yu/DxNdKAuDOKcNiUHZIXn3Ex9FtOG+EHel1jtrwQ==
X-Received: by 2002:a05:6214:29c2:b0:707:5974:388d with SMTP id 6a1803df08f44-70d97097253mr41174086d6.8.1755875498049;
        Fri, 22 Aug 2025 08:11:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZec8lDcVGr/kxspwQ3zMS069OYUxHI5L/yo8+xsfkdbDw==
Received: by 2002:a05:6214:d07:b0:707:2629:964c with SMTP id
 6a1803df08f44-70d8591d5c9ls31504636d6.0.-pod-prod-03-us; Fri, 22 Aug 2025
 08:11:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDrf8PmT6Rxt0cfgbSm5aqDeA6gpl6jzUQZqftez1BhwJ3SNE6XiSxot64zolaCodkvgdHHfvwuC0=@googlegroups.com
X-Received: by 2002:a05:6102:6881:b0:519:534a:6c29 with SMTP id ada2fe7eead31-51d0f70eeb6mr1027098137.31.1755875496048;
        Fri, 22 Aug 2025 08:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755875496; cv=none;
        d=google.com; s=arc-20240605;
        b=QNB3Zd6m6FVMdxbkLIos1tJNxQtnDWrIHnhwBADe95IF/pu5SOxVSvNi4l3yv2Fxv/
         4XILCGeH5R+9/M7gsv1U6D6IGdMePpiOY9Q6q9Xa+EVnXQHEzMuICuQBAURpDPYRqVnZ
         OGZ4p65LBc/EUS/XEhtN8z14rMMkkMsPWg+46MRsjRkzZw+O5VZKYIYgTOa1BP62Cdlj
         OLuGHt7iWTKaIgCBKKK6d23Gf07ckO6M/G2jvnzwZAP7xAxYe51WFFxlCv8YShQgiz6c
         dZUI4I8JuvFIs631nPvB20oF9Wc8uMmXHPE21nDWT9RmNmPlnu9ZLlQiNNDR3M5uVTUt
         3BkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=s/r60qpQZtZOLut5uqffwIieNJ2Wqej4s0Y2I47CK98=;
        fh=TQettBsa6azoUFn+s4mURKduHb5q3LI9P+dIVcXK02w=;
        b=MY6ctyfK7M+xB19aeFZAIEmMRQ4wmsQSp7PSThd5i0zqj0B7xCAvctfJrt9spYp779
         xZTMgH2DkxghEUxiqN5xlnUr3TAhcc9Z3RSMJzwZUaHRM3pD2+r/PGHG+umyrBUyASwB
         al2VNDdXEycZV3PAdn2oUYkOSlJiuwCsN20/XMBQT66DH/T/dbtIW8IJFLDBeDoReQOp
         n1hJqf4FpzGmcnhJWVaBZglCtFIA3wDjOhf2ViDgCqwV6IDCXUPWsPagp83tY8crim3r
         0+V0YRed7ZYRA6ervyOOml9SGu3tH3lKhGNzT3QaMwupUf75Pbjc60YURJI8h/y9bmI6
         F18w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bRecik1R;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8920cc869a4si47626241.0.2025.08.22.08.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 219FB43D9F;
	Fri, 22 Aug 2025 15:11:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7F592C4CEED;
	Fri, 22 Aug 2025 15:11:19 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:11:15 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 03/35] s390/Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <aKiIkwzNoJudCNLz@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-4-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-4-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bRecik1R;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Aug 21, 2025 at 10:06:29PM +0200, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.
> 
> Cc: Heiko Carstens <hca@linux.ibm.com>
> Cc: Vasily Gorbik <gor@linux.ibm.com>
> Cc: Alexander Gordeev <agordeev@linux.ibm.com>
> Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
> Cc: Sven Schnelle <svens@linux.ibm.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  arch/s390/Kconfig | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
> index bf680c26a33cf..145ca23c2fff6 100644
> --- a/arch/s390/Kconfig
> +++ b/arch/s390/Kconfig
> @@ -710,7 +710,6 @@ menu "Memory setup"
>  config ARCH_SPARSEMEM_ENABLE
>  	def_bool y
>  	select SPARSEMEM_VMEMMAP_ENABLE
> -	select SPARSEMEM_VMEMMAP
>  
>  config ARCH_SPARSEMEM_DEFAULT
>  	def_bool y
> -- 
> 2.50.1
> 
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiIkwzNoJudCNLz%40kernel.org.
