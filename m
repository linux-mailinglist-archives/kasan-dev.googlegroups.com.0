Return-Path: <kasan-dev+bncBDAZZCVNSYPBBIFN3HBQMGQEXZKOQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 59469B05BE0
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 15:24:50 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ab5d2f4f29sf46413231cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 06:24:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752585889; cv=pass;
        d=google.com; s=arc-20240605;
        b=gsYMjmuGqBir86B4KtXbaH8MNNj6cVSJNaXXUVKeqKQB+2vDpngnykdjzoeLV1FYZH
         XnkdiiPPSSH+IahsLcG9UeXzdFvvAkA1TkUv5e38Jr5bkf6MbxeAvbrIf80Ipa7qpavE
         6WGHHp6VWsDSMK773MGuFcP43mr0HflOeYoaKAppgOnkETgnjaETSC3XuibH4rIi+Oqw
         w4w5kl8Rwb0MkRet1Jr11/7X63m1hZ3taoIY/9w1pb1QCJkcRC4fM3T988EOy7ulDj9y
         QngyIju5DHkN556SCrjWJS1YoLveCevdpcZuuexWxUWtIltP+VeE4R6lCGs6WePI56VG
         zDvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yWvn5LmGMmvq85UZh3RY6g6fP9Pme97zwNWxKAILyAc=;
        fh=TNAMRth4cXsJgMOJTSonm52MsoiPeecXyUhneCOL58Y=;
        b=aBuARcETjPgicleweaEzpjY+d8TtAf6yTco196mDkmOXU6TM0zzAaVN0lxc0NEbUyk
         C8QIsdFntHw/o9Ead+pSwT4JgluH1Z+MEbNxnj52ZFlxzIgmiRgh/ShuBqHqF0MDm0vG
         z+BNLK3BbC6mwfrWE/5j2stf1hpHtQMMCNCMSLUnO7lgteqwoRA08bEVdXpWVGMBcUY4
         xWbIEjGEKcNqRYJtAFe6DQuswTqRBMTfbNJiPYiuFTOUSfNJpSqdthyEGNZQRPRynBsO
         Z2b4m4AOu/v20rCuB0fi3IkHFsh6UzNVfJEEbspQLlXV8UsaTUN//1C7oxKs/ya9771F
         W/fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPFgiCbm;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752585889; x=1753190689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yWvn5LmGMmvq85UZh3RY6g6fP9Pme97zwNWxKAILyAc=;
        b=j9RqSGEG6luzSjPw+zRneCrZpPBV6axNiNjdW4z+n1xO/nn+fz5M3lyozehD3cB0S5
         aLeT1jKOizvcQWoS0HEMMFu1Zb4p+tSn+JEfUSh7zHgIkJfjM0DUY6X9StEOB1CxEFsu
         qVuRZSLW4OwxJ+L951YYrKV1x/3gYHWHs86XH4KYAN9Sq4vdGVMos6Zc8PKLIa4AApjO
         scct8zqtrN8pRbwd8mQ3cQmb1paQe4ekAWu6pb56wcRR4iT19iNBCweD2MmAxzwac0Mc
         cLLDiG0Zr742RxFk3ekG5HwAgpfZxhycJ8ODW6hXurmz+LWzjLCXCF/KrxJzYbrNe8gV
         R0kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752585889; x=1753190689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yWvn5LmGMmvq85UZh3RY6g6fP9Pme97zwNWxKAILyAc=;
        b=N7ckQHiq0R0D7F9OvA2RR0DNBzSAsfQXUo3hno+7An+yoxTwALwXmniS2tQG/PIzor
         DlnJ2NidtOl3wc2uHkI2dpIxuJAqjX+TyO7pEB+k0HIDylY3iO26p2On5RRnQlO4ez4E
         ZcoaBsx31r2AKlXWLMBQDDuWGoy7e7LjI8VglMyzn+P/9zNNyttnGzK5PgHXQoi+XZt6
         VjOc/s9sEUvFDQMBfSh32vT2sM7+rBwBDQJXtuxyBNc6VPJ+qqR5FpHysb5RR11rrBCf
         qj2d/+mzYt4ltXu16qejbT0OEM/eoKEWDW6enr3KALoG2uLLXWC1tt6bIUrYT6yZ1wdo
         9wzA==
X-Forwarded-Encrypted: i=2; AJvYcCUCypfvywqmrKWmEqieuHId+2LfMG5d59kslqU4IhSgKURWI3HXZyzx8GEN251lsL0Q1kcbaw==@lfdr.de
X-Gm-Message-State: AOJu0YwNhrczVhKwiN5Hr01DDts3Ptf39uoDZ3vamm2sfLtpDkgC/6FL
	p3SGRUiPWkE8QSTiU8PAGUbw1YzSXbovf8pCIzV+I4vKmygC0b7cNBkD
X-Google-Smtp-Source: AGHT+IFMidzw8PtcQMe5DOWDcnYOhv+Wxr3K4wTnwnB2qzLsARGlVt0vk+a9RHXaHezYLrzTr2IwTA==
X-Received: by 2002:a05:622a:413:b0:4ab:3b66:55d7 with SMTP id d75a77b69052e-4ab3b665871mr210560081cf.30.1752585888456;
        Tue, 15 Jul 2025 06:24:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcVWgEOWF1IXcEljABZBcODyOT5nIdgYoUCAClT7y/+YQ==
Received: by 2002:a05:622a:342:b0:4a5:a87e:51c1 with SMTP id
 d75a77b69052e-4a9ead65afdls94522681cf.1.-pod-prod-03-us; Tue, 15 Jul 2025
 06:24:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqXwvlGgprZ/njs5YKcKYI/cPit6FbS58jlJ30uACkYcGsG0U5VupulxVa9dql4TTTj5DvhBBHUz0=@googlegroups.com
X-Received: by 2002:ac8:6291:0:b0:4ab:77c2:af0a with SMTP id d75a77b69052e-4ab77c2baf9mr66385441cf.3.1752585887371;
        Tue, 15 Jul 2025 06:24:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752585887; cv=none;
        d=google.com; s=arc-20240605;
        b=PhQ1AspDKC2UNa766XJqZ2HLcrRRGhVT/78Dxf/dq5vM9xgzPl2bpNmm/xVRBNSDs0
         j4U300dFiq3UAVVUQpzMIa7lOC73+aDma8xdRu3WcsxjZnGzJcqFFZ8ZnzW5pDOJRlrf
         WknIHaWs2vNRLdIQEZumAhRRRj1esgLFKFsn/DwGzQPepD5E1JJeFOdIVsj8LeuHZ0V0
         oxql2e1Jvh2XonoLPp3qemLhmIrYQbUZnOQzp2xE3eArF3AfoNPZd4vl69+AV1vaQg9K
         1crvmLtA4pjYm6Km+uPK74As7juPu3KUE9tReBQ/3GdfHIfi7rl1wwikZb5CDI7M3Eep
         9F6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EMDbadNseXzpLJnPf5nVCnaV4nsb0WAVNLIP5V+z6VU=;
        fh=VkhCrdyV8datbl76Fi2k/Yr6OPgTYBZIO9D/zwz5KTU=;
        b=HJ6YH0MZGYTdd0Arq9TYEjEjTDsQVaqBzyVt9Ienqgx/wlGEzjo2aedX8GKANBQitd
         ZyL7CTmpcAa1FqaI8QDaGfpv89WP5nXgpm+GeRDVP1pfHQbTIXVNYETtBkDxrI/X9xE0
         LYcG8Z6k5jYSx0+ISSyr3JSetIzalZdNLv/7XMLLu2CVTfy0VtnWTXpWE8ZkCaArcAfK
         4XvL1+TJbnYBKoZW4QgSEh3TXx5J5iFfMB6M64bdArnalar5Y1jBbznEA2R80dcOmw56
         CGXwXzPNblIizk3WnWBCJpdDIob+o3VdER53zHgcpwNShnmJgeupMcCP+YWthcTGjDqc
         ZptQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPFgiCbm;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a9edc661c4si4902381cf.2.2025.07.15.06.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jul 2025 06:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8A02F44C91;
	Tue, 15 Jul 2025 13:24:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 78FF9C4CEE3;
	Tue, 15 Jul 2025 13:24:41 +0000 (UTC)
Date: Tue, 15 Jul 2025 14:24:38 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>, Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 8/8] mm/hmm: migrate to physical address-based DMA
 mapping API
Message-ID: <aHZWlu7Td9ijFhhh@willie-the-truck>
References: <cover.1750854543.git.leon@kernel.org>
 <8a85f4450905fcb6b17d146cc86c11410d522de4.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8a85f4450905fcb6b17d146cc86c11410d522de4.1750854543.git.leon@kernel.org>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SPFgiCbm;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

Hi Leon,

On Wed, Jun 25, 2025 at 04:19:05PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Convert HMM DMA operations from the legacy page-based API to the new
> physical address-based dma_map_phys() and dma_unmap_phys() functions.
> This demonstrates the preferred approach for new code that should use
> physical addresses directly rather than page+offset parameters.
> 
> The change replaces dma_map_page() and dma_unmap_page() calls with
> dma_map_phys() and dma_unmap_phys() respectively, using the physical
> address that was already available in the code. This eliminates the
> redundant page-to-physical address conversion and aligns with the
> DMA subsystem's move toward physical address-centric interfaces.
> 
> This serves as an example of how new code should be written to leverage
> the more efficient physical address API, which provides cleaner interfaces
> for drivers that already have access to physical addresses.

I'm struggling a little to see how this is cleaner or more efficient
than the old code.

From what I can tell, dma_map_page_attrs() takes a 'struct page *' and
converts it to a physical address using page_to_phys() whilst your new
dma_map_phys() interface takes a physical address and converts it to
a 'struct page *' using phys_to_page(). In both cases, hmm_dma_map_pfn()
still needs the page for other reasons. If anything, existing users of
dma_map_page_attrs() now end up with a redundant page-to-phys-to-page
conversion which hopefully the compiler folds away.

I'm assuming there's future work which builds on top of the new API
and removes the reliance on 'struct page' entirely, is that right? If
so, it would've been nicer to be clearer about that as, on its own, I'm
not really sure this patch series achieves an awful lot and the
efficiency argument looks quite weak to me.

Cheers,

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHZWlu7Td9ijFhhh%40willie-the-truck.
