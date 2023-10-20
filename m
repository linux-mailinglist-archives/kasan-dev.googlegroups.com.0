Return-Path: <kasan-dev+bncBDUNBGN3R4KRBDUSZCUQMGQEDGPCTBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 786937D0773
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Oct 2023 06:58:56 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-507cee14477sf333064e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 21:58:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697777935; cv=pass;
        d=google.com; s=arc-20160816;
        b=BDejRxHAZLrWk648cbh4ZV49q4wHkOiYh6fPlAJdulQ2Aud69pDHonz8o0SXv+f5z2
         3lx1cUqiooRBfEMgjqXv4lCLoKIE0chv9Ig+8f8DTavdb9LG6Lm/eVc1V4diPDoOCIJa
         2pkd+95WdAJQuvOGRnV+ebG3NnZDy7EZxIWSXmbqbkjEHhRFLf5U2C0MHHFZBCmXu2go
         u1xQdYzKm3Z5SX3fOBGv6fngX9kOUsfmCDtW/cABOEO0u39o92DviYDX5zy97neQV040
         MP35hlPL6/M0Aq36TSXUBVs+noTOF9QjmiZvU99wzAzrO0F4cdZud6dANFR11kvZFmPu
         XfNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=M37t4QXzySVLB4C1Mctx78paANRL0d7tEn5v6w9cGAk=;
        fh=dy++07K59ThW31JhL4sQAS8m0qX4lJuwFPGTLWLDCA8=;
        b=z/WLxjZttKDrhu24YWrqU7uc8nPNVCEuAFhP16OKbrCXUl2C0dRT3/SCogPLAMfAnx
         LIOn9TKA77oxJpD/5UKbDTMHxlr/tGyo3Q2OnH6djj7/Y1R+sEhFqrP0Q827gtQYk1OW
         2Ql9wFTUeTU4MEGSVsj1EyWvVXyMgvFR/z+nlTTfgoH99qdBeswQYUNGTM8LdrnU80rI
         4D+/RPd2QGUaxJvrha8syClT2InKgmGlW9jkKXChadL3cI+WX1Hy3jFivxGVKDyVkXp8
         DuZ8oRtgb5jwsZIgTJ4M8vkcOMfRy4LOumWCrjRsFw9RJBtkGLoZ3mRbCWZN/YDUggVH
         LHWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697777935; x=1698382735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M37t4QXzySVLB4C1Mctx78paANRL0d7tEn5v6w9cGAk=;
        b=ijLmD6H9sCSf03CZpDOiCoKfhWsLXTG8XfwfXkGoVlAWh+IWKkpeGsn5l+TZIL/XZZ
         ELaqfrH9hTLOI0gyPnvM8tPCH6EA8iz7dCAMYBs9+vAuEVmvHRbDgmlbqii9qnZ/r8V+
         1bWKwO2l9lk9RHOqpOFPctbRuQpXkp/c/T5qYPhBydELqbQDciFq+KqgcYeHF6dVc0T2
         dKnASRs2jBy7ThqRoIXks9Nq2CrId9i7BMYWQufcOLFzTAVYFTFU9iXxwCbfDQzq8OSt
         SbhNjdQxe841piXNRWdaPhJDyM0PgZOFuTtJQZl5gZkrbMJxzJhfKAyKn/7tfrsYaCRM
         0Qcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697777935; x=1698382735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=M37t4QXzySVLB4C1Mctx78paANRL0d7tEn5v6w9cGAk=;
        b=jp4642ps6Losms6WwYEwgwenT/4siLB/nlAuP3kuN1Z+2KShiNyR4r+wQhR/okKM7B
         9mgNdmI3W9KbYW4L67P+gD1JKg+uj3Me32ldYDRjGq5aLiSX9daxHaaanoF4bpBj3K4l
         RIL+VATmiyKNokPRxfVlDkUPlwwHwsqznECxAK6DLO/W3hk+A9BNHAoNU46YRDZguffy
         zlxHeB735elz6oo8R1JhOKJj/Ztfm4L1bjc7VWvPo6vULe/N7LbLUUOW3f+g8X36CO+2
         GJnz8D68vb3JHxFT8h0vRqJ281rDTo8OXfWQbHypaMdgoA5jAKbU0sk1lQGQiStyiGaG
         y0xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxj6hE9xh/DvcZahiHKzTXwAEneu/NtqxbYVzGZniOyhQzPpq8o
	eh16Gmo7R4GmX1zIcr912kI=
X-Google-Smtp-Source: AGHT+IFq28TONgHCbZyJ6YIk2iErqtEkh7qGbEIdmlIPJCWYOx808vd88Svd54PCC+1mr3WOJ2QqqA==
X-Received: by 2002:a05:6512:3c83:b0:507:9854:3b95 with SMTP id h3-20020a0565123c8300b0050798543b95mr544744lfv.14.1697777935160;
        Thu, 19 Oct 2023 21:58:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b8f:b0:503:a8b:c1b with SMTP id b15-20020a0565120b8f00b005030a8b0c1bls22434lfv.2.-pod-prod-02-eu;
 Thu, 19 Oct 2023 21:58:53 -0700 (PDT)
X-Received: by 2002:ac2:4c3a:0:b0:504:30eb:f2ac with SMTP id u26-20020ac24c3a000000b0050430ebf2acmr393308lfq.68.1697777932851;
        Thu, 19 Oct 2023 21:58:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697777932; cv=none;
        d=google.com; s=arc-20160816;
        b=myrzADgYXwCuxrwJqhJ/j8rOzOinhkG2Ze8Asz3L384FfZTExgA0nTu4QPrk5zQSFH
         3uqPKzFeF46h9kF3B5MHoS0D7SdCu0DQxhrnjnhGoutHm0TjhTzif4jfFdcN2zUu8m1g
         wpKOwRu/J/tK3n79w7zt7f+oHfsQafwi5bqJF75KdBtVYoM5+Yn/CMqvJZm7dfcq56EY
         K5JggjYHvmKoA/K375f4yH0XeG20vC/fqZYOYr4etEvtt9qvYQl1Z0w6uZL7IMOti1OZ
         IfTi/C3P8x3maSx+4X3EpMhG39YUd2xMfNPYi25w3wH9UrlLmeYG/x1LNfsxr50Lw/J0
         If7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=W3WWvFTG6WcEgC54KTmgHVx/nDtmL0uUHMEt7d4H7yI=;
        fh=dy++07K59ThW31JhL4sQAS8m0qX4lJuwFPGTLWLDCA8=;
        b=SxvzfcQ0+zdvJN/vgkZ7jWjUkJ3BkODIYOW9ezD472Pgs4HXw0bHpY5bRSsCFZnf9b
         KMnCcTIcMt+mWDMLG3bkVt0CtluwwcH8w6s+mNDuJJFEVTWJcxAyiASkpUuZEjAGF2ym
         E4Zp4TTTNrsHmlpWNySIv0kXH7ZH7Nd7+gqL9EPC9vUxw//aumCvz2/AJUnhrQ7eyMZO
         RMb5xaN1DC+0SwBrpNpdH+oeP5UDDPCjGe5nhIAH/SNNXnTU8cspr54JDaQ5/B2Thyxl
         IyVZqCuCaMNCqEXzk3RtuWMLQcLgePdQfYiD97iuEsk37AC4U059jmDA2IMyZIIuqpT4
         3GfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id bi5-20020a0565120e8500b0050446001e0bsi26889lfb.3.2023.10.19.21.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Oct 2023 21:58:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id EA8CA67373; Fri, 20 Oct 2023 06:58:49 +0200 (CEST)
Date: Fri, 20 Oct 2023 06:58:49 +0200
From: Christoph Hellwig <hch@lst.de>
To: Matthew Wilcox <willy@infradead.org>
Cc: Chuck Lever <cel@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
	linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
	kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
	iommu@lists.linux.dev, Christoph Hellwig <hch@lst.de>
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Message-ID: <20231020045849.GA12269@lst.de>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net> <ZTFRBxVFQIjtQEsP@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZTFRBxVFQIjtQEsP@casper.infradead.org>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de
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

On Thu, Oct 19, 2023 at 04:53:43PM +0100, Matthew Wilcox wrote:
> > RDMA core API could support struct biovec array arguments. The
> > series compiles on x86, but I haven't tested it further. I'm posting
> > early in hopes of starting further discussion.
> 
> Good call, because I think patch 2/9 is a complete non-starter.
> 
> The fundamental problem with scatterlist is that it is both input
> and output for the mapping operation.  You're replicating this mistake
> in a different data structure.

Agreed.

> 
> My vision for the future is that we have phyr as our input structure.
> That looks something like:
> 
> struct phyr {
> 	phys_addr_t start;
> 	size_t len;
> };

So my plan was always to turn the bio_vec into that structure, since
before you came u wit hthe phyr name.  But that's really a separate
discussion as we might as well support multiple input formats if we
really have to.

> Our output structure can continue being called the scatterlist, but
> it needs to go on a diet and look more like:
> 
> struct scatterlist {
> 	dma_addr_t dma_address;
> 	size_t dma_length;
> };

I called it a dma_vec in my years old proposal I can't find any more.

> Getting to this point is going to be a huge amount of work, and I need
> to finish folios first.  Or somebody else can work on it ;-)

Well, we can stage this.  I wish I could find my old proposal about the
dma_batch API (I remember Robin commented on it, my he is better at
finding it than me).  I think that mostly still stands, independent
of the transformation of the input structure.  The basic idea is that
we add a dma batching API, where you start a batch with one call,
and then add new physically discontiguous vectors to add it until
it is full and finalized it.  Very similar to how the iommu API
works internally.  We'd then only use this API if we actually have
an iommu (or if we want to be fancy swiotlb that could do the same
linearization), for the direct map we'd still do the equivalent
of dma_map_page for each element as we need one output vector per
input vector anyway.

As Jason pointed out the only fancy implementation we need for now
is the IOMMU API.  arm32 and powerpc will need to do the work
to convert to it or do their own work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231020045849.GA12269%40lst.de.
