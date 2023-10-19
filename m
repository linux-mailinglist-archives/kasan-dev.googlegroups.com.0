Return-Path: <kasan-dev+bncBCS5D2F7IUIJPIWFVEDBUBDVQJRLS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id A78937CFEBC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 17:54:00 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5308cd0f6b3sf12034a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 08:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697730840; cv=pass;
        d=google.com; s=arc-20160816;
        b=WUJ7MQ6krPDttH9QyB6Q1LmPbu1RTgAJndcdS9eMdg7+5XaW0pc1+7LG1hhWi+SAPs
         YwoWp0Tf0Pm4kLQCv6rr8vEwbfUSz7A87onL8aG++gLHJhEz5XeAdu6BtDR1YPrcKDIk
         GGSea0Vj4/Fh8rhpOO4SG10yRqJPfIYcI1ZZOXMHY2z5HeR1larovukmyBWdjdXey/2w
         BieCQsYTQ4+8aiqLvcFsY6g7gY4IeEt7ZwXjWov/LLjRD8sglqTvUc6DgUe3BMKgrskO
         WpUpCWogiiIFxhx4RKRQajuqj1zX/4rLbJzVCm1n1K5HtyJwUsckZnbqj1adG2ixBjk6
         VXOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GEI4tVNHAI1ka5ONsgBl8W9SnVALH3GhmNFO7ol43mU=;
        fh=8V5I1S1vugYhc2KsfZ+Gh0bBIxsnwn1/o89jS6X9JgQ=;
        b=HERf2A9pEKV7UhJ44ZHpYOvBn15tJo2QOdMadrAgibD0l6zELTpzPXwxe2KnZ7gB7C
         q14xAW4F1WGSZjQoBsDi0FbIBVap0u259B7rsQj36eu4t4LNRZ/2K1U8Vuim32DqgHeY
         cwFZM4uKuzz9mGyQnkh+oFMILy4mWt1K4lXUdhxV2fE1+dcAUKit3YvJrjn0XY1CdwAF
         6vTvDexPyG0YctcVHVlZ3m2EQodmY2OTcscUbl91JvKsRU8OiP31tBBo41PtbMbOeKCG
         EktiS5pw5T2JvidI0kmLGeR6tWm5wZ/ZKOio2bMRmEXcZFOM1rOA198JrBs0KkPExPMK
         nbEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Bn7c8NCn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697730840; x=1698335640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GEI4tVNHAI1ka5ONsgBl8W9SnVALH3GhmNFO7ol43mU=;
        b=NNVkHzVNYewWgLyopDkM+ivByAGzxpevpdnb2VIJYLIdJ22SdZnAQsCXblJL3vUa7p
         TetbcnPRwWJusi4EPGLL+V/pLIlPR4Nn9kMR+vOLztMR50TNCnB4aNEj4HSJKLZp5tlx
         /vc7o/a/IAdv3XTDNPm94BHgx3L+QaL1hHDJkfezG4pfLQYm4KfgxETaEYtUiShY07NJ
         z5BsHlmzTOFimpKGQhySQz8dp3OqQfP1Afml40T9NnefoJSM5PLsfo+z37Nv5W/0wIoR
         yqp0H/ABoLaPAbjR58Xc1g8Lgw5Dw6h1mZshtVIq5LuFOhaNsmadjossyZ3FDtZoJRGh
         y5mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697730840; x=1698335640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GEI4tVNHAI1ka5ONsgBl8W9SnVALH3GhmNFO7ol43mU=;
        b=GD4ATg8s+oNn0VO9WWvFywmLkffWZiridTpgM98LIA7uGy9uQL89DEkbpuXv+4MaFq
         KkuHwRncQ5coAwUgB5R36tEVgn5HMzLMaZRmlO96aRqELsSYTLSWr8EyrhjoSN1yHMLF
         WwEuVweCeSo4izFATMG/I1E9XRqshRUEsonQqiejqK300y84eFtDNcJzcGQ/jMFo96rG
         i/a6wHHSUta7GIwQOm3ULzJzAq2OsJHvba669x9/o6znUQ6WPPBt3xKBXqPxO1qrYDuX
         u2rM0TU9bn41PA16LSMplPw5qNwDUgbBjna5MdvGwRh77vhq3eJBWTzjgVbJxs+u7B+t
         VPjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzQ34lGHAtgjgDwZM1D8ibkp32TIqJl0Vd02lFGcieUfc40EDSK
	reWCw7ONCy8SFy7nj3jWDmc=
X-Google-Smtp-Source: AGHT+IEGNNDGmQOwfkx2qDcB6tcOO0tPYf0lbVQ1/xl0lFMS/AW0z4p6c+eExdDmiE+XKqGXQ5SUSA==
X-Received: by 2002:a05:6402:2cd:b0:53f:9243:310c with SMTP id b13-20020a05640202cd00b0053f9243310cmr121551edx.1.1697730839839;
        Thu, 19 Oct 2023 08:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f21:b0:532:c9b6:5c14 with SMTP id
 i33-20020a0564020f2100b00532c9b65c14ls3873eda.2.-pod-prod-04-eu; Thu, 19 Oct
 2023 08:53:57 -0700 (PDT)
X-Received: by 2002:a17:907:940d:b0:9ae:5db5:13d with SMTP id dk13-20020a170907940d00b009ae5db5013dmr2203859ejc.72.1697730837782;
        Thu, 19 Oct 2023 08:53:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697730837; cv=none;
        d=google.com; s=arc-20160816;
        b=AQReBhdD0nYetWz5ubzSvCElOv7M2QU1s1Gwj6N6BCv2tiu8TWxSfHAD5ixiervVyW
         aPANy69hdAtLxZgBUN24kKkBNKZ1oqCsHrCyZCfx/Wy9ADbQXyNDE1q8CdggjsPZXaBy
         12MR+t0IjVzvywE83niNAG2OgeqJhoQ8iWYQYGvOl9Kv+qgI4lLQUgAGgkJ6qQIcjT91
         sHstvOS01IpZp/9QZni2LkUa+GgoG3ifJZwipFbn35zPK0PlBaAednjxU18AXIbz+lyc
         GLP3raC18cEERMTSrSmks4RNEiCR6gMGUq2vrYJO5TUOlJBv4VPBHWV/bySZDol26+ZR
         NjPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=F6/o8Z2i9JKu0badnkbxfHnQMRLlqY5LsHFDEapT+28=;
        fh=8V5I1S1vugYhc2KsfZ+Gh0bBIxsnwn1/o89jS6X9JgQ=;
        b=lVnn6VrUG9t0VYH+372T/oQX0c4y7KM5pmyERe/NsbHODhG2MRyrEJ9uJ3Z+vlgnDu
         BPRBRqoAmdqQaCwnDzK+74EUby7qCdrqNMKTOICip+bja5BNFn21+66d1f0pbrEAWBHW
         uOpfFwWrFz8sJiE4ZfxAFK1+nUsSlwPlr8Z6E/1rkSKh5bKqGsisXl0VS/UTCXFtbLaP
         WfX4Twns5gw0p8Xsu9+3mvf3lWkANtzfBsAV0HZKLgZFB+/nDM4rsmCgNjHtJAyGk2mB
         K/eVkJprb6XqfM8uSyJX7ik1AaMcXetXiGngVCu8TcuLwDZdc8oLUyae52a8z7LkzTG3
         1MTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Bn7c8NCn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q24-20020a17090622d800b009adbab54deesi207289eja.2.2023.10.19.08.53.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Oct 2023 08:53:57 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qtVLD-007u7P-Tf; Thu, 19 Oct 2023 15:53:43 +0000
Date: Thu, 19 Oct 2023 16:53:43 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Chuck Lever <cel@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
	linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
	kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
	iommu@lists.linux.dev, Christoph Hellwig <hch@lst.de>
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Message-ID: <ZTFRBxVFQIjtQEsP@casper.infradead.org>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Bn7c8NCn;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Thu, Oct 19, 2023 at 11:25:31AM -0400, Chuck Lever wrote:
> The SunRPC stack manages pages (and eventually, folios) via an
> array of struct biovec items within struct xdr_buf. We have not
> fully committed to replacing the struct page array in xdr_buf
> because, although the socket API supports biovec arrays, the RDMA
> stack uses struct scatterlist rather than struct biovec.
> 
> This (incomplete) series explores what it might look like if the
> RDMA core API could support struct biovec array arguments. The
> series compiles on x86, but I haven't tested it further. I'm posting
> early in hopes of starting further discussion.

Good call, because I think patch 2/9 is a complete non-starter.

The fundamental problem with scatterlist is that it is both input
and output for the mapping operation.  You're replicating this mistake
in a different data structure.

My vision for the future is that we have phyr as our input structure.
That looks something like:

struct phyr {
	phys_addr_t start;
	size_t len;
};

On 32-bit, that's 8 or 12 bytes; on 64-bit it's 16 bytes.  This is
better than biovec because biovec is sometimes larger than that, and
it allows specifying IO to memory that does not have a struct page.

Our output structure can continue being called the scatterlist, but
it needs to go on a diet and look more like:

struct scatterlist {
	dma_addr_t dma_address;
	size_t dma_length;
};

Getting to this point is going to be a huge amount of work, and I need
to finish folios first.  Or somebody else can work on it ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZTFRBxVFQIjtQEsP%40casper.infradead.org.
