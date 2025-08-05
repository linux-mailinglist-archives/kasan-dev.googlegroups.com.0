Return-Path: <kasan-dev+bncBCUO3AHUWUIRB2WJZDCAMGQE5BVS5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C1BDB1B796
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:36:16 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e40c0ffb1bsf44427255ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:36:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754408170; cv=pass;
        d=google.com; s=arc-20240605;
        b=CXyZ954TnK4OmUHn/u/gqXYevqckF1imCeetzpbu8JkXFcd0/NuGs5oILAb7vI4HZ0
         MdVCT2PoqbyrhE1s8qdeIAI+surobDmrJv2jP2LTNJ3ACoV09dAZIniO4io14x1CsBCf
         tApJ8Pcna+nLC5cEKfA8rPZu3lSyUj88rbWB2nyHP2IyYCSDipHO+VMRXyaS1Cv7Ey0f
         tf+aBmL5CNyjYjIlwQFMF+WWTg5TtFxVLgBMZsK7DGhlUQQcwTC1huPBbcgKwyd4tZy9
         hWfcfIhm5ZBsCX5N4zY4t+5k8lk2kZh6hOJM1OXCCfldi+ZfuV3J4ST1xyVW4qNS1y4p
         UOMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vT7AXFUg6xC4fvBKD5DKzZ5dWyZ1gbtycSpfhYslDLk=;
        fh=VrG+jDd//Rpt7TDt32+B8qyCXTQ5NXjLq5vkclM1xwk=;
        b=ZiXxS6oRUOlb5CmANXidC9I4c8Bmg3Z7lZmB29gXxwHTXUaH/puGYV8eLYsj6+Qy+/
         XMKlXzWdtUfmQyOhPBWpe1iDkrWKUSkTSIA0ufx+DQGwE098sGyXAiPXgPj0ArHxq/U+
         qf7kHl3hep1AP7HyU6ZgnDzWGtZiEpyIOK4vCZgbxuYYpY+jj2S4Yoo8+2Y/BvAYn/L8
         FUpcc1TDEx7F0My8DyGg4P5w6minmTDElyaibUG1zvg0QcmO0ZWIDAfyQ9W5W+pyuhTr
         VZ5QdcuNJ3ijKBoJKCPq32jKTGpItdTK3n8oF2qHuLKwwaErwHmuJPSI3c5ztWLIjnq7
         g56g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=MPRFfpBI;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754408170; x=1755012970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vT7AXFUg6xC4fvBKD5DKzZ5dWyZ1gbtycSpfhYslDLk=;
        b=wdbojrNu2P8zFWm5fTHv1aGqMR/HrLqRhyAArUIs7+pJXP5gCET/1dtmQBj7dib4Jf
         a27xMU+UcBHBWc+gKgpuUc4tBRfyYbjfHMie5LW9IaMgEtaUcmlF//nWrLWEDIoub2BM
         0Tz73VwlhxAXoQlK1n5HeIvxZIjTwJjfbLEDRIG54EikWBLSfPfb5E7XfdWId06+eySz
         0BOzB1bO1b06RtM7Q76psH7QClxPiE4rjWAWCDx7jfZwl0yaFPk0PrEeSsQnDhrFh4sm
         w8TZ0TFsWHfW9homnp0Yq0lYJC+vMsN6SUFgGvcaoGSozKNDZrX+AbwYoMepMfOa7LCc
         nMyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754408170; x=1755012970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vT7AXFUg6xC4fvBKD5DKzZ5dWyZ1gbtycSpfhYslDLk=;
        b=bR/g2qWDZPAQinukzXjc16fOnlnjTxPRx3hovnlXZ5m2K2FdYqyRs2O6bYeiyuWgiA
         ndRh8PeeTNu+ed9T7WIgYGaoq4XxyA0D5y+rq/KUqFqoDCc7wAFDlOYlweHXg7jcr+Jb
         yyqdsLcPWOI+Aime+yrTEj9nT0QCE5iOStI5uUkCDAGm20brQ88hA9jHdXWQMFiQqrCZ
         xVU3rKqwLwa0exH7RXvP9+5pNKe3c8gp888wECv/OnoC/Xsv2NHC3Aztb3lLTuRAjjVd
         6Ekv3ptxvSK0+U1iKmqhUtEFLG8v4jwi8uJT007LO7Bz6V0bgvWKROIeZ9hvZTP4SL5A
         jatQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3Nr0oknGljJQEm18RTs7aIr3P2zyFu6L63NfdOB8RQdFsLgcdUwupr3i38iAev43LkOapXA==@lfdr.de
X-Gm-Message-State: AOJu0Yx3nivtR+zbc9rmZ8z3WyB8rx3oY9+n6bueHv5UDp9OTn8VBn5j
	JficOvllA98HP8OzchF+J3UPlLPnFZWAZh9MLKqi5m4+K5o2PXlI94jm
X-Google-Smtp-Source: AGHT+IG79Y6LPwm6tHQqrkShY+xfBH+HOf6YXfh5wKO3pBApNLzgSMl65X+pTYmkJ5JE6XUwOvLN5g==
X-Received: by 2002:a05:6e02:2487:b0:3e3:b6ab:f869 with SMTP id e9e14a558f8ab-3e416191ba5mr226652675ab.13.1754408170235;
        Tue, 05 Aug 2025 08:36:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeDR4GDJfKGKsUYn9SgIhqLpmcDaAPZkNln8qUcgTCNWg==
Received: by 2002:a05:6e02:480a:b0:3e5:16e7:9a6a with SMTP id
 e9e14a558f8ab-3e516e79db0ls2815125ab.0.-pod-prod-07-us; Tue, 05 Aug 2025
 08:36:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTrZd5EiX2GIj1YianrW+VUurdS/sdy5gSFHiymq5zXcH0+5FCrxOeVvxNfbkdb0g7Eva30HG1Fos=@googlegroups.com
X-Received: by 2002:a05:6e02:2487:b0:3e3:b6ab:f869 with SMTP id e9e14a558f8ab-3e416191ba5mr226651635ab.13.1754408169091;
        Tue, 05 Aug 2025 08:36:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754408169; cv=none;
        d=google.com; s=arc-20240605;
        b=N1laEVFjoxOANiQeJ0QNNVCN8x1FN3S75rT78BLne8sI8XTJ452JRLsBik2yqy9v1R
         QwYav6jLc9SSlMAATBAksDmkHbBvux3aW0UZKwXIj7D2KSQe856pR6Y3eNJ4xYfqyTT1
         cIQD4kPW9QbmbTJ3QkSSTs58pybmZLakwm4ihY8fN9AjqLeVjiyJMh5VsWofiFiBvkS6
         KMiob//43mbJOZHB/H8GGXyniIUnmDJa4jPqTPx3lwtfKkKPATSp+wxCQKx2+ogojEU/
         RHtikVC0C9ZKNrua6jHb2rJo5TQhQijC2RzD/KXuFGIGfgyE/vqBKZF5xeSLBLvJdplQ
         hhqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=N1MKz8dfPt28HzEOpdUPkfZENcnUFV9NfsoMVTYwzbE=;
        fh=M56K91/lrdmiuXEzaKT0OgBjlgo+P+qJvFX/9TbUPfk=;
        b=M63fgSllR2bQoNysUK5dv8LOycGUlPrs+2UqIKAfJXsRsMyXEZ62eL1/bvBnXgirrr
         kDU9IFXC5+XinRBHvpAhJiMq48jAbbhK70qn46jp6yU4E+FKTP+uLrNfqIbPE31eCUjc
         eZbtjViXj6t4AcJ9Vl6Hi1p4I3k4lg5UvosHV2Spdlkn94jGKlnKy9iphYkJWZnZuurY
         WeipJY3LeM8fNYtjE9p/ZcRHdD7niZPcsjKkVzFNYLk0J5Z1/Im/VzK5Jo/O5vK3hHEz
         nEu18C0GrzSmmla5X5QzGTfDuM5l6Nw9eV5qSimcWG5s4cfbv3SpmPZ7TXSRpDihzDwy
         fRfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=MPRFfpBI;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e4028ba392si5576695ab.0.2025.08.05.08.36.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:36:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id af79cd13be357-7e182e4171bso470719085a.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:36:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV7SAjq55NzklzHTRZIxrg/lXOGA8qBNvMBiw9HkF6+BBI1+3pSPqfYQfFT/Y1wQix4wlrJmj1smRg=@googlegroups.com
X-Gm-Gg: ASbGncs7Ir4XqAOilBHzr6lUtnBij262MRg/5CtYvus8f8RLmdkj4HTNxTNK3xkoM0i
	e0AAgAmP5dQWL8VJSLZQk2bezPIUYZBSUEL8+ETamcdh07IQ2iOgPTFITmx7T1EsBfuAzX2dXYj
	Xf6jUkz8CPSF6JR/0AyLKF3awvuX5VAONvJ/6LFZ5G1OeCOjL2wmdV6kzOfp+6pouysuG8SPQwi
	HuJpghS3QNsDW+Km3+oJ4jd65SiuiOpllzqOpAijdy+2035Q8jJ2Vr55lbo8U393FmcvNXQ3wlJ
	fseALxniClArZU2VRXFlYVzk2xmgvX6cOvSBo9V0VlFUzY7OYopWIdPiePmHalpSztSOBJHwkIk
	9g47IbtG7zXQfoCvmJEVrKLL5EMKvZ9WYbbeXD3KT0WS5PuSQDa9DTx+dlBaJljL5CcDDhO9qcs
	m5GbE=
X-Received: by 2002:a05:620a:12c6:b0:7e6:8f41:2055 with SMTP id af79cd13be357-7e6962e0c1bmr1733279285a.21.1754408168128;
        Tue, 05 Aug 2025 08:36:08 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-120-4.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.120.4])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7e67f5cd63fsm689744985a.39.2025.08.05.08.36.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 08:36:07 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.97)
	(envelope-from <jgg@ziepe.ca>)
	id 1ujJhu-00000001YWx-3rSt;
	Tue, 05 Aug 2025 12:36:06 -0300
Date: Tue, 5 Aug 2025 12:36:06 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: Matthew Wilcox <willy@infradead.org>
Cc: Robin Murphy <robin.murphy@arm.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Leon Romanovsky <leon@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?utf-8?B?UMOpcmV6?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?utf-8?B?SsOpcsO0bWU=?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250805153606.GR26511@ziepe.ca>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
 <aIupx_8vOg8wQh6w@casper.infradead.org>
 <20250803155906.GM26511@ziepe.ca>
 <aJArFNkuP8DJIdMY@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJArFNkuP8DJIdMY@casper.infradead.org>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=MPRFfpBI;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::731 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 04, 2025 at 04:37:56AM +0100, Matthew Wilcox wrote:
> On Sun, Aug 03, 2025 at 12:59:06PM -0300, Jason Gunthorpe wrote:
> > Matthew, do you think it makes sense to introduce types to make this
> > clearer? We have two kinds of values that a phys_addr_t can store -
> > something compatible with kmap_XX_phys(), and something that isn't.
> 
> I was with you up until this point.  And then you said "What if we have
> a raccoon that isn't a raccoon" and my brain derailed.

I though it was clear..

   kmap_local_pfn(phys >> PAGE_SHIFT)
   phys_to_virt(phys)

Does not work for all values of phys. It definately illegal for
non-cachable MMIO. Agree?

There is a subset of phys that is cachable and has struct page that is
usable with kmap_local_pfn()/etc

phys is always this:

> - CPU untranslated.  This is the "physical" address.  Physical address
>   0 is what the CPU sees when it drives zeroes on the memory bus.

But that is a pure HW perspective. It doesn't say which of our SW APIs
are allowed to use this address.

We have callchains in DMA API land that want to do a kmap at the
bottom. It would be nice to mark the whole call chain that the
phys_addr being passed around is actually required to be kmappable.

Because if you pass a non-kmappable MMIO backed phys it will explode
in some way on some platforms.

> > We clearly have these two different ideas floating around in code,
> > page tables, etc.

> No.  No, we don't.  I've never heard of this asininity before.

Welcome to the fun world of cachable and non-cachable memory.

Consider, today we can create struct pages of type
MEMORY_DEVICE_PCI_P2PDMA for non-cachable MMIO. I think today you
"can" use kmap to establish a cachable mapping in the vmap.

But it is *illegal* to establish a cachable CPU mapping of MMIO. Archs
are free to MCE if you do this - speculative cache line load of MMIO
can just error in HW inside the interconnect.

So, the phys_addr is always a "CPU untranslated physical address" but
the cachable/non-cachable cases, or DRAM vs MMIO, are sometimes
semantically very different things for the SW!

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805153606.GR26511%40ziepe.ca.
