Return-Path: <kasan-dev+bncBCUO3AHUWUIRBTMOX3CAMGQEUAFKFYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FFBFB1946D
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Aug 2025 17:59:16 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b06228c36asf6055691cf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Aug 2025 08:59:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754236750; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mnrz3yfWHjFDVybVzjnMWFzfs/oLgRgQvBXCw8MHNJbKAxIwOUHpEDii3UNz7Bo6zf
         If8qJTOEw5EwMAOm1VMII3inJalCydMo8jIgDZtmPu7uJTOzlUynopomw3bM7g5Ki78B
         52bjFkjCgd4bioVcxtGY9ydXH6K3P2uIF2X8nqR78XbZoYESmzE5VMrzJQKcNG+FHDCL
         kH+FGefiN+b6dY75nbMe01MsJ046wbavafJ6vtUX/JHEu5wW6o+Nwx+XHMS2EsVVSn0U
         1MzorKSHoBwvk1G0mF8BktrGzoLQwmhvszZwK/tk260XqX+L1B5KrdvkMo90UpGPZYS4
         JPiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OKzXCoALZbX2f4Cg0jzR751QhAAVUu+CgkWR/fdXIx0=;
        fh=EzGguyBnYJolKYseVc73qGzedJZF8/LxaSSlXHtyns8=;
        b=RXA5cH5xKPcrWEJxYJLcg1vAzyR/6O/yNFWVyUyKYn9d0UQ/+S/HMpv/PbpHluLssT
         HDcZDBqjYGT3/sIsNfr9cSgIs+hEi9x9LOC3cbFlQIBBwZHeaVywYV0LRJF4sJXoypev
         3Uqehv9NW9i6Ev0LUL0JMPP/N10XjaT8hFUmk+re/SNfeazpF9aq3s2tdu1CN+YHeEHH
         e19ma2Zt8Rg0Gi1vC51LhdgW45hwurZIToQYcBQREkch7B1WJlmh/k6uLODyxYGz5w7E
         7rJYjhol1wT9WGFbjrOJ0NMTVaeFJtwspnJx6R1RUo0z9+EoektM805lzy8LxzfYoA8s
         uzlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=pD0YJ+Pj;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754236750; x=1754841550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OKzXCoALZbX2f4Cg0jzR751QhAAVUu+CgkWR/fdXIx0=;
        b=NpK8Tf7MIlA4tkMkAGBY50FyjnCMUxIG5kq6NQEBdmq5PbIAeScYCkjA7Q3R/2JmHy
         8x4rkNy+bf9Jg++DQUnP8gI1RVZRU1+tq5tlg6TBB3bcZ/BeYHADUF5noG+V3j+CQ1c+
         ujxfuj7fn4c6O7SZ2ylpavXUHPwMKDI35C54yOTHGEQgnkLpDROW1SJWRMhwCOiFnW77
         67r8KR4Ipk1icMNGxwRwGwp4dZBqTqFGF08WRNVtGIEbzsn0z/tI5mkSFD36dprgsTDb
         Xr/WuAQebD9aDHlt9lWd8bgRdHr0JbYSNQZ4WfWA4cnGUCsQFeY+DmSC8qjUwseSIDiZ
         PR+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754236750; x=1754841550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OKzXCoALZbX2f4Cg0jzR751QhAAVUu+CgkWR/fdXIx0=;
        b=eaORvDi984koyQw6VIGihgF965WhAUVYRuodgFAngwldry3/CoWRxfJtOhQ8+jT9j+
         6KH+DF6VEN8WAgYHsN8oDY5efaqCzXAXvTOFbYaUEPDg3qYE19mNRCGAS7vVQA24OHms
         nKJzWNlyLuqBqj94icOgZe+swSvCT59fRNosjHGQLRIIHEYwZu2HivRyYbYDouwzKxe+
         yQBiJKPT4lj+rUWTegSxwymB9QKvNZ+enTMH74x73YwErJExeaPxnU27JNYrMORPsvI3
         7v4IpjzlwRip6UEfrFyx5pNB2Vp5vOWG28unXCu39xLqr/jUBokEb697i20wuWGiRJxo
         ubDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeklhDCLZc47G2Is/Qi2F8EvOfYPP+JyrhjaOnFDawC8pevLV1cjot+aR1jFwG7WEcnd3FVQ==@lfdr.de
X-Gm-Message-State: AOJu0YyHSHujyyqXDpcN/n8oy7SesYjlST+pcaImh8rPZKoExXkNQyji
	dUpOTpbf1uVzUXIT4LVYFBo8asheUA/7CfNUL3g/GXd3ylJx0LwIlAey
X-Google-Smtp-Source: AGHT+IEYHd9Ksb7nR2Fib4Ja3SBolpQEJapjckXh+emTZTQZuQTgVgEB3+fDV49eqah5tyUIz8D+qw==
X-Received: by 2002:a05:622a:4a14:b0:4a9:a3ff:28bb with SMTP id d75a77b69052e-4af10a1abd0mr119763481cf.25.1754236749859;
        Sun, 03 Aug 2025 08:59:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdOHNG7c1uv+yj/9Ngz4FJR0zfmM4c9ZvXgmhsmd5++ug==
Received: by 2002:ac8:5702:0:b0:4a8:17dc:d1ee with SMTP id d75a77b69052e-4b06d51411cls5453101cf.0.-pod-prod-08-us;
 Sun, 03 Aug 2025 08:59:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUG27VAzBi3sVYeNyDPMlCY7NMQryHftAhkArx6XfXnZ9zX6iHkmHJKnD1oBmOHO7jpNpGaUJnuoi4=@googlegroups.com
X-Received: by 2002:a05:622a:a708:b0:4af:21e5:3e7d with SMTP id d75a77b69052e-4af21e5404dmr56107601cf.38.1754236748687;
        Sun, 03 Aug 2025 08:59:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754236748; cv=none;
        d=google.com; s=arc-20240605;
        b=ZIoIRowKWyEuoLrFQ+1Vk8peDKS8Ih3WzEraSV8AlRRa6xAr62NF3qK0/yWsZwSsq0
         8bj5NFhDS+MgsGeYV4/dnmryXqLpZzGaCcktL2Oe/Txiqn9u7aw7UQqMGl+a3ZCmfWwh
         1nnQL7qxvSyOzdK4ARuOG7xqrn25p5Dr3qdOSN8OivQ0hnv9KRFyiDZFTUDaWouIQO95
         6cLoWcxdCi4EOnzJ3Kr8Jd/rWu6QQ9YRpJuTBMqMvo++D0Zava/+yiISO1eXtH8HUvtL
         /GAzgsetLaynMQSoHUX45fXgWMsyzgW7I/FRwbcV7bOY6P55IO/rf/DbV4rGsuJRoS98
         Q/Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8slyx6E/zt3CNU5aqFjzFMTLA7WC2ifuj8UOdB6q15U=;
        fh=Qnhfg71vOxsoOscUum/RFD5ulBixJFPSns6y2tMYo1Q=;
        b=UklfEcCBe1FKMik7WtEhmkjFiacX/fKs5DRu9taPzO8fgynEOzmsg6K6V+4DU9uHD1
         1ajhFZX4CYovmjTNf1qaiqruIegvB32VKLpe/tqcbEGnYRy7fROebAQLrhwsUEWS2+dw
         Kesf1G2nt33jdPiXkYMqg5kout4NLkoaJhSPWIbFQdkrvHRqFC/JPBXHNlo83lIh9uOr
         36cmCb3DS7erLOjbhx2i2f5wBEqweMTsQnhOO3IPceFp2ODQ5Frw9v5Dw5Pvk+clcqpI
         vtzJZKjjirg0q3Pm7+d83vStPDs0NFIXS40WeRTqRJmZKx6E/Bx1WXMu5KggbCcGNzsQ
         dkYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=pD0YJ+Pj;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4aeeea2f135si1782191cf.0.2025.08.03.08.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Aug 2025 08:59:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id af79cd13be357-7e62a1cbf82so151385285a.2
        for <kasan-dev@googlegroups.com>; Sun, 03 Aug 2025 08:59:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWadmVll12ksb4W8qiqoLn3oXvydfa0GR0bphyGzOvohoHhEPAf1jgFVamJ41nhf9u/1YxKvFQwLVc=@googlegroups.com
X-Gm-Gg: ASbGncvFQ1puo8hynrqMGdICTfN8CtUEdGEU7AyB3P4b+QoxrwGs/rneLnp5tA7lUxl
	GU4LIIMeLsZvAIpVqcOr3yG2J5275laaTx790wnMOsgVqSTJFuJjp9iVsQobndnpEPOraSkRU7E
	M2MqvhYUybJWrOWeVi0j/RRPsZ0/1QeRPbdrP01gD1C7c6VvxnpC8P/frLO0TwMHO5w5mbaKoGm
	Hcs/a+RysnYym6xchJydtjSP1pOpdK/sSDoOC+7kNeQ9O2Swe46SV3GZqmeeaaX9abw4jV6Jmoi
	0iwwoSKW+jzrLYvFu9gHI1PGs8Q7kAMe11n9uz1zOxMIIcoDb/i271LmHcSiY69Z2m4I/GNvJpv
	RUPPx6Lv5iIdFqND9zUpW4pwkVdnKj/rlxUoL+KsQyROawKJLivdr0mnApnuOaXV82NWk
X-Received: by 2002:a05:622a:1dc5:b0:4b0:6da3:26df with SMTP id d75a77b69052e-4b06da333ccmr13497821cf.29.1754236748067;
        Sun, 03 Aug 2025 08:59:08 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-120-4.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.120.4])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-4af01e4aa4dsm29318401cf.23.2025.08.03.08.59.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Aug 2025 08:59:07 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.97)
	(envelope-from <jgg@ziepe.ca>)
	id 1uib74-00000001Hym-2XZx;
	Sun, 03 Aug 2025 12:59:06 -0300
Date: Sun, 3 Aug 2025 12:59:06 -0300
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
Message-ID: <20250803155906.GM26511@ziepe.ca>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
 <aIupx_8vOg8wQh6w@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aIupx_8vOg8wQh6w@casper.infradead.org>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=pD0YJ+Pj;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::730 as
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

On Thu, Jul 31, 2025 at 06:37:11PM +0100, Matthew Wilcox wrote:

> The replacement for kmap_atomic() is already here -- it's
> kmap_(atomic|local)_pfn().  If a simple wrapper like kmap_local_phys()
> would make this more palatable, that would be fine by me.  Might save
> a bit of messing around with calculating offsets in each caller.

I think that makes the general plan clearer. We should be removing the
struct pages entirely from the insides of DMA API layer and use the
phys_addr_t, kmap_XX_phys(), phys_to_virt(), and so on.

The request from Christoph and Marek to clean up the dma_ops makes
sense in that context, we'd have to go into the ops and replace the
struct page kmaps/etc with the phys based ones.

This hides the struct page requirement to get to a KVA inside the core
mm code only and that sort of modularity is exactly the sort of thing
that could help entirely remove a struct page requirement for some
kinds of DMA someday.

Matthew, do you think it makes sense to introduce types to make this
clearer? We have two kinds of values that a phys_addr_t can store -
something compatible with kmap_XX_phys(), and something that isn't.

This was recently a long discussion in ARM KVM as well which had a
similar confusion that a phys_addr_t was actually two very different
things inside its logic.

So what about some dedicated types:
 kphys_addr_t - A physical address that can be passed to
     kmap_XX_phys(), phys_to_virt(), etc.

 raw_phys_addr_t - A physical address that may not be cachable, may
     not be DRAM, and does not work with kmap_XX_phys()/etc.

We clearly have these two different ideas floating around in code,
page tables, etc.

I read some of Robin's concern that the struct page provided a certain
amount of type safety in the DMA API, this could provide similar.

Thanks,
Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250803155906.GM26511%40ziepe.ca.
