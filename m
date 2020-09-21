Return-Path: <kasan-dev+bncBDAZZCVNSYPBBL7SUL5QKGQEAZEGC3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B03A427270D
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 16:31:12 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id d21sf4071329vsf.16
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 07:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600698671; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6WpgwKCqxOiJEdmXzNLSfIgbZHuerKQmnA/xuozz2biqZ3JFKrkVFjRfrfE9oxvvZ
         fkgnpzbkC0qPTV/a1IKrpiizT08BH3MbFCK6AJXPRlzwbIFrd4pgrKr8bXfToXWHWjLn
         jbgTP2myEGhNrdqXzQczqQ4UAku9jqYIp7vjLprC1NTn7tIh+s3X1r6QQfBEuQuhf5Hk
         GE9QOc016Ec7JP997X8s+wYp3zQopTNSnRViRlF3eUtIaco58Z12YTzquSqUiCf7lZ4i
         SMkw5XdKWcW0d3L7vFAFPlS4NQl89+UAkqVx3lnLkgqjC46y/cwOHmz20SQV04/1g1X1
         cfDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sc36s7mTYMHgJ0qIGvBD9yFkm3DJUCGW8uYRDLM5XKE=;
        b=Quf/TLPF8NVzVvp3a/Sv0NHUx80fM1DlhCf5yz19RlNSas4vXYrGcPGxWQzOgyi5T4
         8xbecDEX+lXYE08tOfjpDLjGXOyXrt9nryW8oON2TgH26X5BQDPgvGNcwzyPMYqpryiV
         G4YLz2p7KHd69okdttOZ2n/fyOjf1D5nOBOzr6mj2SfxIqsaUZDkd3DcH8XQSrcbdtvg
         +O/HTr8LOqNha/i8MXaS8V3aelUVifB+V/i5crxRjbx5rSUL9DpcLO+2A/nxyUjNR2yG
         7fMz8aoC0jsWzUJw21NxyKh+NebX9wVDiRW/IXOE0AEFKO+S0ayi1M1sPzewC1p4eELe
         NgPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=w1R8TSnt;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sc36s7mTYMHgJ0qIGvBD9yFkm3DJUCGW8uYRDLM5XKE=;
        b=rDKw/wsLDh3pDk2f6s54uHA70pJCRaj0PbTIfFbDbzKr1jrHR8CgIOls5Y3n+bcBog
         Iqv7q243dpMC6XK4jA/s6QzekwHhLBJbTuXZa4Nd0+BkZtjYiRiUgZpbx5hnrO7jP9jV
         g8FTexrvaSTmqsZtBgYbZr+EOW+b2PBhkafhQW+k6/hexV2QQxzwQ8zW1fRet1gRNQgZ
         oUrG91lFxrY7ggZOa5Wh6K/090Yn5iMzw/TYDvMNJtOW/s81z2L6GfE1pGO0upLB4zh4
         QA5sNW4D5UgKSU4RVbtO78uuPAQ4k6R8S8Z9PWzIrJjoUHGaxUIa0PK4wl0BnoLaAUUS
         1k6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sc36s7mTYMHgJ0qIGvBD9yFkm3DJUCGW8uYRDLM5XKE=;
        b=UmQTRdOEHMob+axVjFvJW2JSHwtxoIzvc5PyL6Qx3iO0Mbtk/I4X+XCJyDpqRR8Fpi
         J6M24mb7JGvu2XtVyHlt5yuHIzzYxY+ex+637fuxdfDC9kLLKy61PtLekJeU+IIlWvuH
         2+4n/HdwqyWRDjzmAhhA8EbVFgNv4kx3NWQxAWAv2Uh4ahTsnzNc33pUFaVVcVMowsRb
         BRhoNbg/NRJKfLddNGiaYHPrxulOJkQBe6GGPQe6Mwp8SLmXW7VN23iSkoVhnPGDJh8G
         qi1ONPyc7dHHjsHMvKSHsMiQ5NsZfF17isVb/QOQhQmsDB5AnNlKy+5yH23HpUcjaD1r
         74EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uAJXAG5LQvrfEeTa9l/+RgvFqPMVWHOVxSXf3n9KHEtcSstdL
	YpdKLIluZxVvGTf3HvUACag=
X-Google-Smtp-Source: ABdhPJwkfw9314jZPDoCG4GWAfilFXpCC5l5Cq5AOtp6hgC78MC26ZXqModOfOqutKWcCPJmGVYYkQ==
X-Received: by 2002:a1f:aad3:: with SMTP id t202mr297297vke.18.1600698671415;
        Mon, 21 Sep 2020 07:31:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3d1:: with SMTP id n17ls1505316vsq.2.gmail; Mon, 21
 Sep 2020 07:31:10 -0700 (PDT)
X-Received: by 2002:a05:6102:379:: with SMTP id f25mr191819vsa.47.1600698670874;
        Mon, 21 Sep 2020 07:31:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600698670; cv=none;
        d=google.com; s=arc-20160816;
        b=yGS/AknQB0Ci1muBAbA4webf39GI/OFzYQNv2xhp2mndM776GuclIvk8+iJtCTSV3v
         4syI7mIusJVPcfEkm7nSQ9I8PnnbxY1qrZMGMznr8I1c29c5EfqLUkgLnESdp0R/i/0a
         fLbb/Rgyl08TQLVj8oDGIDYD2AO2p6JKsR3kY7CNBdYks3asR+tcmOv3PUi/U8NVU8uU
         Eab/MntN4wj0hwFsVQ/gIenMtEalf8hi2jHFlbj7TfTXNlOwnodbibvNltocW+RnIoxh
         fiunSRnT2A31mkvh+A0PfLi1DfhC+44nj2fcoJVCjmra2p3ZMPQ8a4FNeGLtPAxuRNr6
         dpTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zr46E7SCC2RF+ZuHUEhPmsYZ6RfOF8h1FZN/tO9mX7U=;
        b=AQKkV6u7NGgFPZRQGtzs7UHszs2aFHXSv97zNucP74k7/NEWtHnRQe/iuCRk5kF5Ob
         db3gsMOepolxNnvLg8TaVeMfsdeqW2p3cPPt+sjRqAmiHUgwFA2YtGBXVTA7g8+oMrDt
         oi4t9dfUKbj3pH93lLDRMJ4HB3+rI8pIcJ4yi3BFrimv4mBZKOHyXhUEauQyVosqBAWS
         hq8arqg+atbh/Z9sp/iSGAALu0QX6Z6pm/1ZZrNrHDEQnEInjT8C0IaDP2skWu6WE5lO
         GZX80VhmbeHPiGh23HrS3HqlVDnO1I8yLINykjWoNR1FKL4LIvmbp+fdBFiO+hNVD34D
         b0nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=w1R8TSnt;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y65si679641vkf.1.2020.09.21.07.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Sep 2020 07:31:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 821E721D91;
	Mon, 21 Sep 2020 14:31:04 +0000 (UTC)
Date: Mon, 21 Sep 2020 15:31:01 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, catalin.marinas@arm.com,
	cl@linux.com, dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org,
	peterz@infradead.org, sjpark@amazon.com, tglx@linutronix.de,
	vbabka@suse.cz, x86@kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20200921143059.GO2139@willie-the-truck>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200921132611.1700350-4-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=w1R8TSnt;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>. Currently, the arm64 version does
> not yet use a statically allocated memory pool, at the cost of a pointer
> load for each is_kfence_address().
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> For ARM64, we would like to solicit feedback on what the best option is
> to obtain a constant address for __kfence_pool. One option is to declare
> a memory range in the memory layout to be dedicated to KFENCE (like is
> done for KASAN), however, it is unclear if this is the best available
> option. We would like to avoid touching the memory layout.

Sorry for the delay on this.

Given that the pool is relatively small (i.e. when compared with our virtual
address space), dedicating an area of virtual space sounds like it makes
the most sense here. How early do you need it to be available?

An alternative approach would be to patch in the address at runtime, with
something like a static key to swizzle off the direct __kfence_pool load
once we're up and running.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921143059.GO2139%40willie-the-truck.
