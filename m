Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBTOA7DCAMGQEE3QKCKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DF87B26DE1
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:43:43 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61bd4ead77csf1579685eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:43:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755193422; cv=pass;
        d=google.com; s=arc-20240605;
        b=a0COfIgZ/jpR7r3OW8CVW759U8aHDU23o0pDPO/Oz1tBJ6euOnNb/i3vYvy0FDiDMM
         7/DQhXvHi52rknhNXOFmkurLeYgnTBfSZ9//zN7Br2XU0/YS6eY1fhcTsI3GppL7aKwc
         pArC9La51bNMPwFVcn1vS2UWmCULXcYUqsFIkiXotzel9fe/9IZMG9jRoerv2aiT4gmh
         YXN11m7NRuzCC6FCaXpfXXTlGaGNklTJXsh6iL4YLkG/p1DQoKkmfBQ7MTruTjMPgH1w
         zxuGL99v4KiNeIKDIO8q+rplV/I4mLL+3P5IHt4bwrgz+/rT5pzeSEUvROsCiupf9XMf
         AD1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=x1as/A95589F6dg6LA5bYIsTh4gugVyAZP4Gp8ULv58=;
        fh=wlWyma8kf27/2gAYdPy4eyHqv+R41a9xsVUT1ALUEtA=;
        b=TFBr3ltLlzekXrnsyANeHeE6uPffe5dvBVMqmwNvsBZWnW7nSOLiqC6aWitV7FLNSv
         Wcv+LPRU24zBJR2aUaC+mh7724MZuWOAthjQq034qxFF7IrYt3IRDa6SnFK3RNak9dlv
         Zt4SbuuyMusdGKxiEuDWBC4yKKR3egcSqN+uN0njO7XtNsUh75wllbBfziXlcw1yzrsz
         CMqhI+on1V6ThifgQv5XK7KjWyGwJmo+UOnYXEXsR6waTlug0Xb0l5EXZPlsgyzassTu
         XsPNoSQL3qNoN44wOEeEum1hO7AwT/iGmjUxrHjF0hY5IFIn8Ak11DWmY4E/GiPIjlv7
         kGlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qET8o0Xv;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755193422; x=1755798222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=x1as/A95589F6dg6LA5bYIsTh4gugVyAZP4Gp8ULv58=;
        b=Wl4Vl21aTWRcch4wnUjDY2zI6LF0Odrzvl9hwqFB2rNw8y+6WH9eoxYW3H21qSgiGZ
         jsFWKA++0gUsg+OOtknIss2gXlLcpdXkl/7j+pwpH+t6bFR/mKEbzw62CFD1AnI/R8R0
         HWDh3Fk6T/oFFGZK3NjUnv6O6NLXyD2q9h9sCRNetKx0Mrzf7Y+i385BauLQ7S5FVSW1
         sJUta4z4KRhMGfPmYj3fvb0J1e7LM9XOdvGay+B+yQSTFEb/eL5seDh8Kr6EngDoKxbj
         BSltPkCOiBp6psdMo4BhzfdS2z/zVrn2Fqax7MwJuAF7U/klBU3A2mi8D0X4Sx4t8JCu
         j9hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755193422; x=1755798222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x1as/A95589F6dg6LA5bYIsTh4gugVyAZP4Gp8ULv58=;
        b=rORdJM8ykb/PhGHZu44+kHNiYhKGgV+ncZ6EVkDFZZ9u99ZYDiQch9xP5KCeINBTob
         38qHmoItkgS0M/NEH54wQt7RN1gLgYem1IMPuM/aojpk5c+fZ71/CMo8tRLX97Yq2b9b
         salUPWgHvCaRGQopQmK/rXUHS8U1gzPAxD/+d0vAiq0VO0zTLYonwfb40tV607ta5lhU
         X1Gqg9S/qtnNOZJGf4p2sgKUkEpBAXdafJMye3Zhp6SYIuE6Nt71juTaHrWl0Lnhn8pN
         D/IXMbWZuFokXNTl16GWEV4oVIgjlemwY7wQGC3pk7OV+kBZOkdsAOgLVJg+BpFyEmx4
         TBcg==
X-Forwarded-Encrypted: i=2; AJvYcCUwWVB7/daoJ2o0XyG0rxtWU87pOPL2mIPlL0DZx9aDtLV6aaad64AMM7lyp3v6ENiKPKmDbw==@lfdr.de
X-Gm-Message-State: AOJu0YwvflBPlo5raYY0Da12yKOxVFKsxjIhglwPJOXamsUw3NdcT5t/
	HV+D20aXv/dPBYKQBbuIWvmf701g+zeegkOhB2+/qMBaQ9U3yQLYSaht
X-Google-Smtp-Source: AGHT+IEWFj6sZ03fxm/Glz12IAf/FamV9hLtOs+HamVODLfopVcc8EodwcvXUJp89FQrlNpjxlnyQw==
X-Received: by 2002:a05:6871:6a8:b0:30b:e1cc:3385 with SMTP id 586e51a60fabf-30cd0dae823mr2419585fac.7.1755193421660;
        Thu, 14 Aug 2025 10:43:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhxkDMCyMX3PjJp1wy1pRP6KSKkjq8oBEA1mAneyZSSQ==
Received: by 2002:a05:6871:7d9a:b0:30b:cc69:32a8 with SMTP id
 586e51a60fabf-30ccec16549ls472024fac.2.-pod-prod-08-us; Thu, 14 Aug 2025
 10:43:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVH6SRwyu7IXVE2UQ2AUrjwyV19QJYMRLacZNd+aHdR/i+3oBB9q6/bQYYCzNOBbaUzLsRImm71LeI=@googlegroups.com
X-Received: by 2002:a05:6870:ec91:b0:30b:6fa2:6974 with SMTP id 586e51a60fabf-30cd0dad366mr2406416fac.3.1755193420525;
        Thu, 14 Aug 2025 10:43:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755193420; cv=none;
        d=google.com; s=arc-20240605;
        b=Y0uXqQnUjfBI5RrY7k9g9NcLbNUS52g96ffp7EBhOM7fVJKzE/6hmtYni3ldUIQgox
         Du16Xr1J5tKDYewlbOGfmRnKQRcrlYQ7cYYuKWgljSecreaV8AAc+U9wmdDazKEWgq7J
         OVAx+oQRzOnm1eYKsryPunkuW8UDJ/UjcXVC+wSsvp98MRhlpM0255FxSM11sQ4E0rVO
         uNc1pmSI0iMVVcIR5xaUrJULUrn0n05qo/nqijSgEJ23lR0Pyf6o5u5FGjUXmwSPnccA
         48evexMK7TKz9nQHlrlNcj+rSxgBb2NJfAI/8W4TKK+GBZBvDFjxs3JAos08JwsBnM1x
         nTmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Z1CFrWb4l1P3vBMSmP6h2aBCsMLffmmJDEsMJ59wit8=;
        fh=CiE5Hhxoab+Jz9u47DdXC6f7oFMliQbF+GZzcyYRpvs=;
        b=axtFfHBuAdSNt5V+OwJweQezsKpBhkOFL0XFXGD7JzvSq+uo2+VFMN+CTk+BAZVktA
         tMOxPxB9vrFx8GDq+qk0lcYTspjR+eiJaTDdjpp8B3/HbR+sFhrSoKdKysRXNTjCtAGT
         g+q3fphYWRUi7UiVRx71ftdjazaNIPnKrbIXy3pmuQvqKCc18Ut56zmCPEubzvDEjELB
         Nmk/3PHG6xyoCNPCwgzNAkbjpPD8bfUfKqoISK/7Radh2eXYqdBpdiIQPGdOOhUeskfZ
         RQsq8QPYUKI6FxDUTI+FuB8MLHXPHg2SdEyllcclkiuuZ2tlkeVHYs9f3DB2jnW2LrGJ
         eEcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qET8o0Xv;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30ccfe22501si124787fac.2.2025.08.14.10.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:43:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7FB4F601D8;
	Thu, 14 Aug 2025 17:43:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66588C4CEED;
	Thu, 14 Aug 2025 17:43:38 +0000 (UTC)
Date: Thu, 14 Aug 2025 20:43:33 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
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
Subject: Re: [PATCH v2 01/16] dma-mapping: introduce new DMA attribute to
 indicate MMIO memory
Message-ID: <20250814174333.GA8427@unreal>
References: <cover.1755153054.git.leon@kernel.org>
 <f832644c76e13de504ecf03450fd5d125f72f4c6.1755153054.git.leon@kernel.org>
 <c855a4f9-4a50-4e02-9ac6-372abe7da730@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c855a4f9-4a50-4e02-9ac6-372abe7da730@infradead.org>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qET8o0Xv;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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

On Thu, Aug 14, 2025 at 10:37:22AM -0700, Randy Dunlap wrote:
> Hi Leon,
> 
> On 8/14/25 3:13 AM, Leon Romanovsky wrote:
> > diff --git a/Documentation/core-api/dma-attributes.rst b/Documentation/core-api/dma-attributes.rst
> > index 1887d92e8e92..58a1528a9bb9 100644
> > --- a/Documentation/core-api/dma-attributes.rst
> > +++ b/Documentation/core-api/dma-attributes.rst
> > @@ -130,3 +130,21 @@ accesses to DMA buffers in both privileged "supervisor" and unprivileged
> >  subsystem that the buffer is fully accessible at the elevated privilege
> >  level (and ideally inaccessible or at least read-only at the
> >  lesser-privileged levels).
> > +
> > +DMA_ATTR_MMIO
> > +-------------
> > +
> > +This attribute indicates the physical address is not normal system
> > +memory. It may not be used with kmap*()/phys_to_virt()/phys_to_page()
> > +functions, it may not be cachable, and access using CPU load/store
> 
> Usually "cacheable" (git grep -w cacheable counts 1042 hits vs.
> 55 hits for "cachable"). And the $internet agrees.
> 
> > +instructions may not be allowed.
> > +
> > +Usually this will be used to describe MMIO addresses, or other non
> 
> non-cacheable
> 
> > +cachable register addresses. When DMA mapping this sort of address we
> 
> > +call the operation Peer to Peer as a one device is DMA'ing to another
> > +device. For PCI devices the p2pdma APIs must be used to determine if
> > +DMA_ATTR_MMIO is appropriate.
> > +
> > +For architectures that require cache flushing for DMA coherence
> > +DMA_ATTR_MMIO will not perform any cache flushing. The address
> > +provided must never be mapped cachable into the CPU.
> again.

Thanks, I will fix.

> 
> thanks.
> -- 
> ~Randy
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814174333.GA8427%40unreal.
