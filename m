Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBANQ67CAMGQEUP24TYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA63B26575
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 14:35:15 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e570090105sf10617275ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 05:35:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755174914; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dz8OqkKCqX7ckcVg62Y+pNY2rmdkzF/fPhtus5OszfJk8wJOGE/b1lmJgJNloi5/6R
         EtTnq/4r248VpTlTTJGsnyYZRbuIhIVfSRh+XNDxCKEX7R1+yCXwlNzpp5SO6/XonCxJ
         1nVmq3U8/Cbd2CRTS8xIbCzydew6T2av7UxE4tcTl2eTTWius14kNRsVHVqph8ffTOGT
         uF40h+vO9vX26ycggyt7dqTjFyQr8K9VXyfcTLdGur/d69h2mR7VtxJ5dX+WFf7wacfP
         ABhSrlM0m5o9p/FKgm48whZZffAI5ie+2fZHcrcoew3yuZPBPmlNQ5D/qQ4tlpVrqiQ1
         mLXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZdXBRvQSSlx6KryxMOjaayCJ6TKZkjPz/+go9ijuQrw=;
        fh=ENMfLyQTjQV1TiHJn66UDD2RjPC8GFrqZwBM8kh1RDI=;
        b=PlM+sYWqbR0D+ZXOpFg8Z1hcGOq49btkAw+b1wiF5aglGtet51eFkZiQt2UjR++JB9
         nUgSpovc6V5Jbh76pTctEULYOM/Wy2c2qPEvLuHk2mN2BdTXWsr4wiTo/VeZK6Syiwu8
         WtnLbqEyenf1U0gep+KqpMXvIR57ZNPhp0OsYvuEBRUIfeyNPHKq/uAeQNokxkoUE4cB
         uS6TI/uIVHXuFuyIXTiJ5RTHQh3LJkNsyvCXuqWAbhmdKplHrx/efcm5dq0Z5YYf9I2j
         i4n0xYrKmRpKPlSwyzQoJi5ixHzW8rEnIMq+52F+HNa7W47TcQfYlPDzUlO47YWY0qx/
         1Lcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N2g2BIJ8;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755174914; x=1755779714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZdXBRvQSSlx6KryxMOjaayCJ6TKZkjPz/+go9ijuQrw=;
        b=Lx+jG8X31cAyoattteV6q8WwSi4xuE/Rb24xQhSY6w8qaw4VbGpLN7c9uenvUGfZ5D
         pJ8aKTrpsdxaKu7lEav5w3fhHBoQFPwxXDETBClHkwzstQzjoRX6CNbLVkb41Yy6HvAI
         XpQJFU6vmO0lCSE67/JjAUsKfZozxiOw15/TiEAV9I+ExRp7c+DmHWeCPH1K10C7lAxY
         4TwHbUOlehRg4iwa7gQpgRrIemCJzGeXxe+PWkgR3ST7WS/S0H1UIp/JCytxRkiOKRiX
         aBvPpZjgZOGeiBMG6gS6kdEw3d02fWwNBxhA2JGzEL0PPDxt3M3kV09PN+w8hQJND+QA
         LCPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755174914; x=1755779714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZdXBRvQSSlx6KryxMOjaayCJ6TKZkjPz/+go9ijuQrw=;
        b=QN1/GHlxIDF3VQhiJDgBI54yYS/U6eZlVDhzf4ucqyOpuhhPXg/3s++fgzK+idGYko
         zNFAGQ6RV16pSCj5POU+Wv+q7nz5fVDALucZ/7UC+fHsnAirNxFMRvLlzifr6yZ83dnO
         HmEEIkAgcKpwonfbeaVEvzdEDZIqwx5fgrcv5s3f4Yjm8tHytLG8XViaS0ikBuPc/yME
         mSB7Q6UouOVng2co/zVAuUVi8TAi8NCQQ6E6Hse+AsAjMvxufdtNVBIjzqFAqWLyj+/2
         7uvGQDWhe9B0i58Qna+PeYlf/ICg2Zaw4MvdcPSb4cmqZFGxm9Nf1SS7B7qbn7uXL6y2
         AHPQ==
X-Forwarded-Encrypted: i=2; AJvYcCVgsXNeFLvlx7vTYwl37NYfgWDCm5R+MTPIzb5iTr0sDz7hETc6waww7U04lxJe3W3LA/7p4g==@lfdr.de
X-Gm-Message-State: AOJu0YxJ2u032wFh7syixNHB64XL+rY79KgJrBPdJbcB7CqBTNl/lrJf
	HjNaMN7j/3QRxCs9+PoTAQ6utxz6CEoCif3vi+6JKMFwZ1HQruLEkCdy
X-Google-Smtp-Source: AGHT+IEVsqUArzWAGvgk8iHfbas8IrFCsMs+sfoPEmRsVqWpCzw+JEpHKGZ239aiZviblACTCI8JtA==
X-Received: by 2002:a05:6e02:18cb:b0:3e5:5af7:7c9d with SMTP id e9e14a558f8ab-3e570866ef4mr56632025ab.12.1755174913874;
        Thu, 14 Aug 2025 05:35:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfcc14u3/Vl0LA43DNzVTDJVODelME4N8Ac/gtCuHEuzw==
Received: by 2002:a92:cdad:0:b0:3dd:be50:e1f8 with SMTP id e9e14a558f8ab-3e56fb97861ls8755665ab.1.-pod-prod-07-us;
 Thu, 14 Aug 2025 05:35:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9kHUeqJ0qj1jgnSER7TEN5R1p6XwQAmFCFEDBMmsuNCdkDQoib60PSR5C2MDmSeSNT+Sq6vxuTIY=@googlegroups.com
X-Received: by 2002:a05:6e02:194c:b0:3e5:67a6:d418 with SMTP id e9e14a558f8ab-3e570740f1bmr65217455ab.3.1755174912773;
        Thu, 14 Aug 2025 05:35:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755174912; cv=none;
        d=google.com; s=arc-20240605;
        b=CAo6384jUwIFfvcimZYFJf52/dksr0iPyHbSB9PN68N+bLAcyavAzesFd5n8OTCSin
         acKx75iAVCAEtvXPSf2GPoArKcCRr/7wyunlzpQIb/XMI9Xld9lOKb2UVZUGVb7b1+D4
         KuUy5mIxmvV2eeQo0DKptTpSyJ0nI/1El3YRlP/c9NIrvxij3qcSIcYyNZjZWTEr/2PG
         VUEtMwXuMN26oSzelbsSTbMdxNwVbey8KVWWMUHntmL1wsMvi/UVtCq+2vtbwsV5E1+6
         lXWzFh6yuoLkZKuLXOxrJqQXFye9PHXdfG5tdJPuuBLICsXdJr5ZStFEC+ad+h5sFi5J
         Vkww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=B3LuiEZXTU5HOjRdk69N6t/53G6b/PJMIeTc2G5XpW8=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=ii3/OSrsDBUoDvBs67Vk47bYCnIyiC01wm/+kTZmNbAiHXtTH9WbpBzlDrAt/yzh6c
         5y99fwBVlQnikNqJw6WjMQdXM2cXT3PkYJ9WOHSFFCWGpPeIlp1Tlegl4c7Ujjf1sJaT
         GcnWPk76P+2aN19+z/pzBVUNDySPIp3nv5lewiJ+9Ikb3ffhpMMX/jQQIVbEbOO4/wQH
         CH1naBiF2B9ev3eQk7QcXkdURQRmyvH6lDcGb5JY/GoZm4Uc10Ge55sP9HcdeWdzamZA
         PV15/OzY0Dxa5o/4nJU64yLxI6TC5Y3ALIN/QFz0UakFddsDC/POzztg4ylMuJlFhMlr
         XIDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N2g2BIJ8;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9c3802esi439450173.7.2025.08.14.05.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 05:35:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2039F40C46;
	Thu, 14 Aug 2025 12:35:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3623FC4CEED;
	Thu, 14 Aug 2025 12:35:11 +0000 (UTC)
Date: Thu, 14 Aug 2025 15:35:06 +0300
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
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250814123506.GD310013@unreal>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
 <20250813150718.GB310013@unreal>
 <20250814121316.GC699432@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250814121316.GC699432@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N2g2BIJ8;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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

On Thu, Aug 14, 2025 at 09:13:16AM -0300, Jason Gunthorpe wrote:
> On Wed, Aug 13, 2025 at 06:07:18PM +0300, Leon Romanovsky wrote:
> > > >  /* Helper function to handle DMA data transfers. */
> > > > -void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
> > > > +void kmsan_handle_dma(phys_addr_t phys, size_t size,
> > > >  		      enum dma_data_direction dir)
> > > >  {
> > > >  	u64 page_offset, to_go, addr;
> > > > +	struct page *page;
> > > > +	void *kaddr;
> > > >  
> > > > -	if (PageHighMem(page))
> > > > +	if (!pfn_valid(PHYS_PFN(phys)))
> > > >  		return;
> > > 
> > > Not needed, the caller must pass in a phys that is kmap
> > > compatible. Maybe just leave a comment. FWIW today this is also not
> > > checking for P2P or DEVICE non-kmap struct pages either, so it should
> > > be fine without checks.
> > 
> > It is not true as we will call to kmsan_handle_dma() unconditionally in
> > dma_map_phys(). The reason to it is that kmsan_handle_dma() is guarded
> > with debug kconfig options and cost of pfn_valid() can be accommodated
> > in that case. It gives more clean DMA code.
> 
> Then check attrs here, not pfn_valid.

attrs are not available in kmsan_handle_dma(). I can add it if you prefer.

> 
> > So let's keep this patch as is.
> 
> Still need to fix the remarks you clipped, do not check PageHighMem
> just call kmap_local_pfn(). All thie PageHighMem stuff is new to this
> patch and should not be here, it is the wrong way to use highmem.

Sure, thanks

> 
> Jason
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814123506.GD310013%40unreal.
