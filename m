Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBSUTYLCQMGQEKSR5AJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id E775CB3A6FD
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 18:54:35 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b302991b39sf14490391cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756400075; cv=pass;
        d=google.com; s=arc-20240605;
        b=e1YfnMefPMDke6911GOOYQSNO/NNWhkiR1IgzhxDp1bHflJ61244r0ArBXMT8vsFDt
         tv0/PVHjxH5pTnyqpKEgQW7hhMuIPMYc5FOjnSHdWNP8kIqWtFFlFJ6PC3G6h/8fRaN5
         AEBd7Rz/7fJZHGtyunK6AOG8I1//kqHw1K31iCxIUg4evW6yDAOooqNNVQa6xiSkyTub
         mRTlu9YlAEjfW/Fd0JODyjmZJtVcknKs2fg7TnC0pJj6pThxiac8BAQPnoLR+Er2vSGX
         lzKFuHIvfzt6UtfL7DoHLndtSjkTHlHor5yMKRjiYAcKP7DPlLJdlP0lWVQEN05g2k6K
         b/nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=kKC3n/l7vUZ0w6A1tO9u46g5ds0KNyipPvWpMzl/IqE=;
        fh=cOKyZuug3QljqaEGQaV6h8+sPhnHpWCxfcuLILdXuRg=;
        b=Fc6fvkEkJDaB6qfJvd3Xqyl9oPdw/K0CSFhvLCZ6nBOg3rSa8ItBwCR7ggMawp4bwK
         4d6HG237LD0DBQCSK7WKLjQC9b+LLKZvYjbzjM03wbp9s/KFqbHOJ44fzRKrQiIiOwWn
         0fUkksldCzd3OrRQVVzrQ4oW8bG7xckAsLDj5MeOG3wFT0yQNuRUKhmlodypEXzMbuJ1
         8dvGgzMYg95/iC1LOnFxVPdnky3x1p2hmYnM8FQYD9oLgM/t1z2PSAvSNIKtCwndmCvA
         iPoqrqJz0SpnlVowWR79u2ekRwP9PbEEGUpD8YyZECYXvIjG0VG0VLS5daSo1wcHXPZO
         Yh/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Utug3C4q;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756400075; x=1757004875; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=kKC3n/l7vUZ0w6A1tO9u46g5ds0KNyipPvWpMzl/IqE=;
        b=nCL/9D76d3rcccuWPwr/yNBWTwb2LQWUaMvfjABX1KPBrn0g0MjoOrxuYIAVYUyfun
         hgkULreAKfO7CB3TtlTXQoJuGMbMxtmXscTNkdFVmCWKb/qasP/4ewxEqGZgq/aqjhZ2
         NvJoYMx0HKc5ndj085hncnzxkxQqQ+qV2KVT/Vy7Oxig2jZ2N3sENKcxzj9TowESjcAi
         Vq7jJKF+kVhMUeRx/SAobj3QrhYoqtZ9ePByeuQcioSyYYn3qYGJssZ9QMlsrzrNB0e5
         y1teCifaTXvry0JfMeJCpTfGXLMMg2d9cFZf4N4+Dql9EzuC5jZZUQ4E1piruw4WG9+W
         zwCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756400075; x=1757004875;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kKC3n/l7vUZ0w6A1tO9u46g5ds0KNyipPvWpMzl/IqE=;
        b=C/6WIxW0ATb0EAWUp1+6a9dFodOtPj4tqMP9BHVvaCSg2lMAK9gLvls2vk5fYUSwHg
         m0Ix+HfohKBEm3JRsOqXksBP8Bh3gMKMp9BAebWZbi/7tTNdw4aH+VSXR94qVGKiWvXO
         ex+yIc90OwhAnfrJ4MN/ngJmLsxf5X8dopmf5bpVnpG2v/SmF06XFtD4eMoIoYzUhYO6
         Jiq0gOsGWBWr+hv3TAeGRfee9mHlISr+YNO2zLi3RLfkta5VT3QdRlIKxin7XsD6NQFZ
         Rlf8PU+ilYCvhzfQ8Mzx3KciCAtCdxKD+kZrU2UbVhqcs4+03BI3DFh6JrQ/l+ynh1VH
         jhbQ==
X-Forwarded-Encrypted: i=2; AJvYcCW1X2Jl9j65jiXjEYlPjkqcuovyLTTO5E+vNUSNzxx+rHNRYXOWLncgJUH7+L71URbLNBHUJg==@lfdr.de
X-Gm-Message-State: AOJu0YxwFj34Akf/HZCdSI5tRBwuYGsd43zh/f5LIHK2coItYC6bg2oY
	ypdm4Z0q05TEKQnJHtmq54s9EOOgfjktdd3lwYJdvKAZtz1BcYELySou
X-Google-Smtp-Source: AGHT+IG7Pkw2HKGDHCj6SsBWCxDR+GkqYmRe0VCQpJ1043mdGSIESf4WQc3JbO9Sc3XxDzwowC9tVw==
X-Received: by 2002:a05:622a:540b:b0:4b3:27e:72d8 with SMTP id d75a77b69052e-4b3027e7eebmr30998291cf.40.1756400074849;
        Thu, 28 Aug 2025 09:54:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfaxS1qgbwq/8wi8bwqK3/M7wUjoIC0gw4ye7Ibd0lSnw==
Received: by 2002:ac8:590e:0:b0:4b2:deda:ce94 with SMTP id d75a77b69052e-4b2fe8da446ls15984661cf.2.-pod-prod-02-us;
 Thu, 28 Aug 2025 09:54:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7nHqIlrmue3xb3j/FeqEB54q4cekKS2f1dKguo9EOQled5Sxhw3x6X6iKbCVaF8bmUG578X0xzOM=@googlegroups.com
X-Received: by 2002:ac8:57c3:0:b0:4b2:d3d8:9a16 with SMTP id d75a77b69052e-4b2d3d8a152mr207200661cf.79.1756400074008;
        Thu, 28 Aug 2025 09:54:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756400073; cv=none;
        d=google.com; s=arc-20240605;
        b=eWMGjM96IugU8UDvIanhokh8q88C7yK6GEfauW1kfXaojMphfYol+iVh32JMkdfAb2
         6kUsSiu+szhO/CTx2wjExpq2E4v3YGjz7nivcenyEd1BTXuuvEb7hD6WXwUVi0IPNAPq
         1sx/yrzT+aN9euyagvxlY+PYO6RAXEYj+O6syMbfz40ncDJbquSAznlVhXh5JwOZQQLW
         bFRmf1VqR08wp+zQTR39v27akXb6RBsvtXyEgkR8fgBdrzFfsyqCrvpyildazdeXbDTt
         hoxBI5vOqlt+L4GflU34cMwN79sQO/k6HFStxWDFuMbMYW/q/q/a4Q9WSbGXZvKm8SKy
         A6qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nk21NoeFbSZuqbZYbv31DbqcJk0/VzI2uLLcHSo6RQc=;
        fh=cvJqwa9D6klxr9M/R2BFyGQs+0bGOcmoFa28xPnkBT0=;
        b=X/uw6h8nkK2iGVIsALrjj5l9Fo86PaXRTxaxKOG9cPJvc8SBqP4pnHJ/ur7DVIm3LB
         CE/4NwQtnIx3uRuRWm7jAv+uEe4FwGmvDsQ1eb+mqlIDohQ3ZhaKcEo5iYIuJ18TiKlm
         gl1i/I6IeMLL57RL+jNx2FtJPImULCERVVy6k9HMxhvQ8na28OfjJers0Z+o7X5JJqB6
         pHjhaoUSlEJGxoKewlzLtDQiqzC+e9f5Uem1Sr25IPsHwLaIgf/NvL3g8XRCuO3T5Gxv
         67bIBGtsI7CAlE9AuCpkLxPsTIxJiKf7/3zKBVpm2eyvDw2nLllfgTk0xXS5VIRdeWur
         qIQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Utug3C4q;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b3e0756si63821cf.0.2025.08.28.09.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 09:54:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0F66D45196;
	Thu, 28 Aug 2025 16:54:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E6C34C4CEED;
	Thu, 28 Aug 2025 16:54:31 +0000 (UTC)
Date: Thu, 28 Aug 2025 19:54:27 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
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
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <20250828165427.GB10073@unreal>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aLBzeMNT3WOrjprC@kbusch-mbp>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Utug3C4q;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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

On Thu, Aug 28, 2025 at 09:19:20AM -0600, Keith Busch wrote:
> On Tue, Aug 19, 2025 at 08:36:59PM +0300, Leon Romanovsky wrote:
> > diff --git a/include/linux/blk_types.h b/include/linux/blk_types.h
> > index 09b99d52fd36..283058bcb5b1 100644
> > --- a/include/linux/blk_types.h
> > +++ b/include/linux/blk_types.h
> > @@ -387,6 +387,7 @@ enum req_flag_bits {
> >  	__REQ_FS_PRIVATE,	/* for file system (submitter) use */
> >  	__REQ_ATOMIC,		/* for atomic write operations */
> >  	__REQ_P2PDMA,		/* contains P2P DMA pages */
> > +	__REQ_MMIO,		/* contains MMIO memory */
> >  	/*
> >  	 * Command specific flags, keep last:
> >  	 */
> > @@ -420,6 +421,7 @@ enum req_flag_bits {
> >  #define REQ_FS_PRIVATE	(__force blk_opf_t)(1ULL << __REQ_FS_PRIVATE)
> >  #define REQ_ATOMIC	(__force blk_opf_t)(1ULL << __REQ_ATOMIC)
> >  #define REQ_P2PDMA	(__force blk_opf_t)(1ULL << __REQ_P2PDMA)
> > +#define REQ_MMIO	(__force blk_opf_t)(1ULL << __REQ_MMIO)
> 
> Now that my integrity metadata DMA series is staged, I don't think we
> can use REQ flags like this because data and metadata may have different
> mapping types. I think we should add a flags field to the dma_iova_state
> instead.

Before integrity metadata code was merged, the assumption was that request is
only one type or p2p or host. Is it still holding now?

And we can't store in dma_iova_state() as HMM/RDMA code works in page-based
granularity and one dma_iova_state() can mix different types.

Thanks

> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828165427.GB10073%40unreal.
