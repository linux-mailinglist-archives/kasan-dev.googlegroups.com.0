Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBP7C6LCAMGQE72A7NNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id ECACAB24D93
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 17:37:36 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2e617422sf49310b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 08:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755099455; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q07/Xg4ZSyEs5D2gfILQvwdEsmStHJS0ODVieWr4kKYrOZRfYH6XXIVYY6RIm4/ZT2
         m2kMVKMhrK0JbcK5ihriNyg+hySOEIMEj9PTip8D0Xo0NFIHUvlga/IH4G9fxWxXoXRY
         mKuMFJ7LzHjmKGlAdHNBm6Ud/7NtK/ip2Fa6rf9cPCCAYS4cTzVJfORUMo9fsvI4KPXJ
         vAL+ldJgjCx/nqJLY6RBbl+DpY7Ssszu7Nuq2GmKifgRw21B7qSguDTyRLaT/WQ02ayh
         3ShZnB4SfDQROtWPgbgKcwEoFF9ROMCMPrTLFReIa0YtSQVGSVbjjX1UtCFq1dSZPjpL
         LhzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0gDe8Mptw2CjVxLRRwfBv/LvW/RfDDDuGExLoCkT5Zo=;
        fh=zRB9wycJuERPIQl9Y3zm/n/1Vkp1wLDJXHBZr3Fo+a0=;
        b=JEbISPF4JtumAfkX9Oooif8Bl7BujN/O/kGkfe1+qCBUlSfTnfc+MSAzu56jyRYrod
         0+DH/8kajyu5z/swlnwz3cQyFbQLbjRJRf4HRO38UNvEGeoOVL5044bwFW6DiS4KKa50
         HLeFDaNlYzKRBLMKhnv1zNe4TLgNg0sDPmbxtls67e/1mgSJ/7CmBd4xkXo9zdAposJ2
         riEFHYDLQ/EfaGgqC4XGkPPcSCzxHYzOBlMp9/RoZwpdSUxuvF3o+T7A1aQDFbV8IBSL
         wBHNMqt8Rjg7waCByZJ+C57sJNOYjnIuSVwXvvbTg+zDLQJkxGOSJ+8akDntK73njIWk
         rkFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kkqdIE/H";
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755099455; x=1755704255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=0gDe8Mptw2CjVxLRRwfBv/LvW/RfDDDuGExLoCkT5Zo=;
        b=C9XIl1dRPd8CuEVSXqZAElmZA7hF9PfEa/zw0kWJHTk0RckHiAwv79HWAOqrNjSfFA
         yxrLkIv6c1GrssK7UeOpBGlJ8M0wdg1s+9sn9SYhdSTqe+sAqxWwwbuIk5wDbznAhmGA
         pSxMDoxf5+PLBr3Jg1QIA3o3AF7Ve4bkD/GLOuA3YI7KniBMByuB1eWpZ+WpS8g1FkTW
         1ui2MQJjmpFFc6gYa/MrDJvhWzkPyTVoEt57BW7UofbzlTGy/sX/9WkvmzDdqNpUYXeT
         ReigEO/qiQfCc59ax60cugElbyXs5kTT/+t7rV5znD1eYw5m2fesbQ01HeFPtkOcvKPA
         Spig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755099455; x=1755704255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0gDe8Mptw2CjVxLRRwfBv/LvW/RfDDDuGExLoCkT5Zo=;
        b=V9/wlXPP53rqdn0Ya+bWEiFufIiIv++0bOrz9I/RohyjHjZHcFr5tyy28qW5IVbc4T
         tMWhvBRPJSF446+XT/pvi4EVD+qOQsNbCmav3pzRGC9Pq9hGDBkqsjc+PQ7cmN0is7OV
         eQFo0UWzcuEbbl1111pIBa6e0AEtw0VjURCViOR6kEW7cIkXpKyGqXcITPE08ElPVjkp
         NF/3mqcbO4MIEnR2EgXJq4+9fZIatArYemZJUQ9XNIPtKCnGikc4jJU7YPvSXdU95AYl
         U5agY6eUP3xjHmtiRe8wcv4X41KE+ZqTu8s8GhD0IlN9kmSt2hKoL/X19eabCL1PoiIF
         hi3Q==
X-Forwarded-Encrypted: i=2; AJvYcCVRegi07hTQ7xARQrN1CrVnAoPX1KjceBS5VaNsqQ6LG9R5FOB4xg7yWLkFtsKd8dhTzzQlig==@lfdr.de
X-Gm-Message-State: AOJu0YzXIEU4yupCAKjUdU/zsi1KgIF5IneWSYMY42r3eHBszXwAmDfz
	eHLWdYJ3gKSt/MiyInrnYFsDl/+D7mZviJcCs6LQYTGTgJDRyk7g2SbN
X-Google-Smtp-Source: AGHT+IHjjX0Yz25a4hbVALA7cRNOc5UWZE5fi9Q0zH1iQRo2aJ+gzN29O0jyzlOv2Awli4HcNYBAXg==
X-Received: by 2002:a05:6a00:3d4f:b0:748:f1ba:9af8 with SMTP id d2e1a72fcca58-76e20fb0383mr4761397b3a.21.1755099455281;
        Wed, 13 Aug 2025 08:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc8bm26A8aRTkXOweL7wFpmj921aivamEOgLtGb77/Ghg==
Received: by 2002:a05:6a00:35c5:b0:742:c6df:df28 with SMTP id
 d2e1a72fcca58-76e2eab0366ls23949b3a.2.-pod-prod-01-us; Wed, 13 Aug 2025
 08:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVW7qQjFhIS2kRahjcKQGGiZVNJmu/w5feO0Vax7iuJaM3+8GCHUOXN9o+mNrarwf1hupUMRsNhxas=@googlegroups.com
X-Received: by 2002:a05:6a00:2d6:b0:76b:fd9d:853d with SMTP id d2e1a72fcca58-76e20f75437mr4040366b3a.14.1755099453245;
        Wed, 13 Aug 2025 08:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755099453; cv=none;
        d=google.com; s=arc-20240605;
        b=L2MNu5AAq1X0cX6fOwqpw7HOT4UeUH7c89TO25rlbgVGeTlmoz5LkzNc+lKaF8RMzk
         2gMl91+vbZb3tXZZr8O3baVQKBO5azL4VByKybOn8z9kJ8EjUM8GOZ+NN9eiTyfaDOXJ
         zlJWFbBtrmJQhexmmDGwN/n7+4w8H4sNjV0tjuJG7srZT0vTlsPcF3P0FGOYwLkneNXo
         QkSGYy4EtWQvdogPfE4I/9DU5aMEP9cQDcU5FA/ntIhmOB6C4suZfjOzQgPiYbzI3Mit
         5re8n6mg3UKmhy1s4k1YLQrG1ACRQq7MTMBbdM4XbcyYhqIs/LGXXkz9dBPdPRK/pUQs
         RCDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zm/dCvvK+iI7j714RjSP/vwEDHJVwvkiYDPPSLpMKNg=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=RLGClQiSx0eXnRXZbG7tLTWikiySMixxrwR4/XYAY0Y6iCbwpYrGNK11+YAylA/E1G
         WrnPPKa81XfoXy15GguDENXO+qndNFKBnwUlc/qovrvRKYF1tDg0YVm57jSqsWsqy9Yg
         BoSkJrcOpmeFWdDBZSgjwgGfcywq6LfhQGDcTTSHLWwaxvmJB+rRF/qNdrLbe3Gtq2Tr
         n8wRVk1fI+32e9hWuTzH6M/5sGVtIu3VhaMJaMpun1B033wUKkU9+7rLWLd9cX6VN0mX
         J8RoG7jfqcWI7UzzBBDhbpn/0ES89MzhdH8fGmQksSg6w3TNatSdVoGq5lkAaEaI8B0E
         C1TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kkqdIE/H";
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76be8650093si1391836b3a.1.2025.08.13.08.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 08:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B00E35C1360;
	Wed, 13 Aug 2025 15:37:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A911EC4CEEB;
	Wed, 13 Aug 2025 15:37:31 +0000 (UTC)
Date: Wed, 13 Aug 2025 18:37:28 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v1 16/16] nvme-pci: unmap MMIO pages with appropriate
 interface
Message-ID: <20250813153728.GC310013@unreal>
References: <cover.1754292567.git.leon@kernel.org>
 <5b0131f82a3d14acaa85f0d1dd608d2913af84e2.1754292567.git.leon@kernel.org>
 <20250807134533.GM184255@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250807134533.GM184255@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="kkqdIE/H";       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Thu, Aug 07, 2025 at 10:45:33AM -0300, Jason Gunthorpe wrote:
> On Mon, Aug 04, 2025 at 03:42:50PM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> > 
> > Block layer maps MMIO memory through dma_map_phys() interface
> > with help of DMA_ATTR_MMIO attribute. There is a need to unmap
> > that memory with the appropriate unmap function.
> 
> Be specific, AFIACT the issue is that on dma_ops platforms the map
> will call ops->map_resource for ATTR_MMIO so we must have the unmap
> call ops->unmap_resournce
> 
> Maybe these patches should be swapped then, as adding ATTR_MMIO seems
> like it created this issue?

The best variant will be to squash previous patch "block-dma: properly
take MMIO path", but I don't want to mix them as they for different
kernel areas.

Thanks

> 
> Jason
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813153728.GC310013%40unreal.
