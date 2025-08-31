Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBW4U2HCQMGQEA2KDPUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 671C8B3D388
	for <lists+kasan-dev@lfdr.de>; Sun, 31 Aug 2025 15:13:01 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-327709e00c1sf3681261a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 31 Aug 2025 06:13:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756645980; cv=pass;
        d=google.com; s=arc-20240605;
        b=NSMDQCSM/Pc8JoeVJjEUY/UdRHl/G7USHsy0OhWwCxvp9YIIOloH5yshtCZ4+siQ+g
         gNRsgLFoYgwxCSf3tFLeM4KLLsjZUeMIKjgpJGwVOBbVhBT1pyRbYV/TH/CKvi6NNinS
         togaqBdI/AbSPL7B4J0RElLui+k3SacrMi3aneWj+7oWls0ysUDB24aWRUdk/tde60Vd
         oApD+v0bZILvjl+DDq8usd21OJp06OM0L7vABnig3whmZuZ7Izu2fwp0hppoPV6WVZoT
         hBXv1PT5v3raMEIRzZ98K6c4DNQYp5FM3sXnJ36sefPpHoG2NyFRs9bLyaAJpmtFKrQf
         5iiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FzwXqTSc2j6zDrsgbCMsHU/9VSrQh+iqsc0Q0FEj0uE=;
        fh=KwZxY7ZevAlxwlKPwng69/MygL8ZNzfZlaPFrftVjPE=;
        b=GvleKQZ94hCtA1Za/mg+NUi2waMFzF0LD2GNftf9Zonhs5baGyJn4gtNNKzVI3D2jT
         Ca90Ly3fSXQdMHAK4SoiBtJoR/eCnO/mJ4Hxel8BGhlbnWskE90xSIWdjnowFF66SAzn
         ijKzCjkeqzyYeYkdYK6jkq0e+53Ma1itpOQ92pVuuiY5b1neGJfl/TKT3wYoLFq+FdeN
         rwBtM9EPj7rM+crRk6DwK1mRrFp0D8uIuPaNN58K/FSRfvrNRupqXfso+ndRQsZ6wQ9Y
         DkON0df5mWCUBrc3s0/MuQ5sLVH5HCCSTAotuzPDVHSYz2a/sYFpZpXpI3cN7DxFVC9/
         2cnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WMN3gtSJ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756645980; x=1757250780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=FzwXqTSc2j6zDrsgbCMsHU/9VSrQh+iqsc0Q0FEj0uE=;
        b=GSANl6iaW2azesWq28QgV3NgcXihxIKQBdw8zyy25OlDhoT/b++kI3Om/nbPEz9pTz
         fdZiDSjdqqB/vfJguLoLuDkF5EgO9bB8ckbNJfjbWwiR5j5OVTjelJEmZ00x/Rmk33UT
         przVnMZxSFciW7HovtkIAmLy0la4I9w7j1raUoKgSgdh8dlJlmZmjfxJXHNlF9YvxaaU
         FnpX3Ls+OV6GsX7L1jToY6hxRsEpSesb+F2HU6saz+5M675ETJEVSFJMDN5rj2ElcjmW
         I+ezcHX3zzS+yhYHnmVVPnxbdjo45RoYHqSJOHJBXJTjV/mnT3wY7di6TP6twDfWapT/
         iKyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756645980; x=1757250780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FzwXqTSc2j6zDrsgbCMsHU/9VSrQh+iqsc0Q0FEj0uE=;
        b=t+ID/flepJbpwJdrDz41NwM8iNEEnQopTygZIRxV564wusv2A9wqofqZx4WhTaDHXr
         K1nWH9xQPBFiQWN5pn234WUNXA+S78JgPNyRleGJT57JPnxbvj90GAJpbm5qa6Fm0LKp
         Ehhfp2L+Qs8+geDf09Aybzw+Wvj5F7ahJtfzYsjnw+8DdxtnXNxoiThaAhg5sKTsgu8M
         QaHUzgOA3N1rcRp5p5xjk933mq6B8IKfcPMwg+LRxpQwbN8MpfY+8ACmdkblENhH5h/D
         1uXUTR0bYUFGtjJYns3zfIlLiNVxih/zxYMfEZCCyVSGqR9yGPTFSiODUUcLVsRVoyVH
         54EQ==
X-Forwarded-Encrypted: i=2; AJvYcCWyWCNSkSSuwrI/UcZSnVLLb46dWI1cIfK8VWhvFBBR4q4ZOpo7MQlar+78a6bOJKPVDATJmA==@lfdr.de
X-Gm-Message-State: AOJu0YyaiVPBVb2a9/RTEYv0nJQlyjSxZAr+MaLMqAjcZSN5mhEIcfCi
	YWemR/bLaAimHeD4TQ688Gw23ceQS2a6M6JG0gd2bTV67TTdfK7DIlkI
X-Google-Smtp-Source: AGHT+IFujZR2Bn/rIRtS1zTmCZOPD26XkACsDpy5JdcIFYLmIPpd0hW1qJMUkOhjC5YwK3fojwi68A==
X-Received: by 2002:a17:90b:2692:b0:327:96dd:6299 with SMTP id 98e67ed59e1d1-328156e57a6mr6810762a91.33.1756645979571;
        Sun, 31 Aug 2025 06:12:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe70y80D2Uf7NoBmjlj3rCCNod4ry8FE9LhexDwg3eSpg==
Received: by 2002:a17:90a:6c89:b0:327:6f3a:16ba with SMTP id
 98e67ed59e1d1-327aac842fals2229712a91.2.-pod-prod-04-us; Sun, 31 Aug 2025
 06:12:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWz3/Umrn7WndwBF5ILDCl4vsEm05clEZjE9/UL1DQ54edRUOH97vBRDAtUEfWDoekIdunBLdZQyUU=@googlegroups.com
X-Received: by 2002:a17:90b:1d03:b0:328:a89:71b8 with SMTP id 98e67ed59e1d1-328156e1238mr6515062a91.30.1756645978067;
        Sun, 31 Aug 2025 06:12:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756645978; cv=none;
        d=google.com; s=arc-20240605;
        b=G1u1JovorTRqPtduZM66/dItrZzRdwJyfI/CoEmyJPbMjYB70O+9Y879VCEvEGpV1A
         ZGawc2/PmhQzTCW1Foa1F4o0I76vfoZZ1REEpEvYfWq3Z769Z7KmksxRizcZbd1W8Mzi
         ryH4OfH/ZF46UUjGyDCk3Ac65A/9aNnUul+B8xrKT4ordYq12ImSqetEIGjS/5JpuIss
         x58bzEa74J/y20m2j3S/ZZbvrK5TLAtwFIQ04xonqpuHSkvtaR1Y2OOg6MBZYaCS4a/G
         G0dMHGO3x39CZa9H5o80lOdcn2A8sKGy9BF9YmdN+OLBs5zTB+2xb8AiPbu0kWEodbGu
         9bBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ac+Ch9BPhurz6Qm+wFXw5b045ua0/xnlchZZPlAlRmQ=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=adMoZ/eUa/6hlmP5VR8VT345GQJtna+lr6WEpDiLYTGWzmyoEBpOMWgPjayyjRajRl
         f6kLrEq99k8SX8d2K6TUqpt+LDp1BmfJ/dBZLnqnC5jntVTyfd/ZVF0zvM7k7ggm1o+K
         q3vacD5NVOb6DZwOJSokmsXXVQVv5VvARKPixXX/jT69c1b/2t9FYu89+d0UjPoxxuL2
         PfWtIlc26zQ68wTGZ7HUb75ib+DYXsJx99Urjy07LJVodBIm1Y9BdYGg4RE+7aBHgkJJ
         QErAS4F6pze6H5a+2n3SevQopy79LgYGHYmpI3+nD6VkrWpvIhP1KsDSCzkeEXBlmMmm
         +yag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WMN3gtSJ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccf7a0dfasi267910a12.1.2025.08.31.06.12.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 31 Aug 2025 06:12:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D1202601AF;
	Sun, 31 Aug 2025 13:12:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BB2B1C4CEED;
	Sun, 31 Aug 2025 13:12:55 +0000 (UTC)
Date: Sun, 31 Aug 2025 16:12:50 +0300
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
Subject: Re: [PATCH v4 09/16] dma-mapping: handle MMIO flow in
 dma_map|unmap_page
Message-ID: <20250831131250.GC10073@unreal>
References: <cover.1755624249.git.leon@kernel.org>
 <ba5b6525bb8d49ca356a299aa63b0a495d3c74ca.1755624249.git.leon@kernel.org>
 <20250828151730.GH9469@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250828151730.GH9469@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WMN3gtSJ;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Thu, Aug 28, 2025 at 12:17:30PM -0300, Jason Gunthorpe wrote:
> On Tue, Aug 19, 2025 at 08:36:53PM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> > 
> > Extend base DMA page API to handle MMIO flow and follow
> > existing dma_map_resource() implementation to rely on dma_map_direct()
> > only to take DMA direct path.
> 
> I would reword this a little bit too
> 
> dma-mapping: implement DMA_ATTR_MMIO for dma_(un)map_page_attrs()
> 
> Make dma_map_page_attrs() and dma_map_page_attrs() respect
> DMA_ATTR_MMIO.
> 
> DMA_ATR_MMIO makes the functions behave the same as dma_(un)map_resource():
>  - No swiotlb is possible
>  - Legacy dma_ops arches use ops->map_resource()
>  - No kmsan
>  - No arch_dma_map_phys_direct()
> 
> The prior patches have made the internl funtions called here support
> DMA_ATTR_MMIO.
> 
> This is also preparation for turning dma_map_resource() into an inline
> calling dma_map_phys(DMA_ATTR_MMIO) to consolidate the flows.
> 
> > @@ -166,14 +167,25 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
> >  		return DMA_MAPPING_ERROR;
> >  
> >  	if (dma_map_direct(dev, ops) ||
> > -	    arch_dma_map_phys_direct(dev, phys + size))
> > +	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
> >  		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
> 
> PPC is the only user of arch_dma_map_phys_direct() and it looks like
> it should be called on MMIO memory. Seems like another inconsistency
> with map_resource. I'd leave it like the above though for this series.
> 
> >  	else if (use_dma_iommu(dev))
> >  		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
> > -	else
> > +	else if (is_mmio) {
> > +		if (!ops->map_resource)
> > +			return DMA_MAPPING_ERROR;
> 
> Probably written like:
> 
> 		if (ops->map_resource)
> 			addr = ops->map_resource(dev, phys, size, dir, attrs);
> 		else
> 			addr = DMA_MAPPING_ERROR;

I'm big fan of "if (!ops->map_resource)" coding style and prefer to keep it.

> 
> As I think some of the design here is to run the trace even on the
> failure path?

Yes, this is how it worked before.

> 
> Otherwise looks OK
> 
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> 
> Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250831131250.GC10073%40unreal.
