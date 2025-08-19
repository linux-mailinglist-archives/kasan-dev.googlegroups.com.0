Return-Path: <kasan-dev+bncBD56ZXUYQUBRBY5OSPCQMGQE7OL5NDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 48AC8B2CD67
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 21:58:29 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30ccea6baa0sf5024422fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 12:58:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755633508; cv=pass;
        d=google.com; s=arc-20240605;
        b=cJDm3MhN1UMfRtobLQa2bmM2zv1E7dq7L68TH/24KLiCILVF50SkUZMXq7FCBqLkvj
         Bb2m5fB8CcQfe6ussMdEu38u9Ic6wd8Td4ghsqQC+JoRTGs4+/hVowxGj2p0pJMavOAX
         tMu0iVqCBeW/UQOoQG+CzUDFU1p3Zge5WCDT+YnId9gMYjsVzRc93B0gGVtNSAqoj54G
         rL6+Kg5aCvNacMw7noQLZcv7lGJFaxEzlaG8UKHg3M57QOuMmAzZVhXOmlWmFT4JKqst
         XDW3tdBGAbyFjM0JoK7uyk6VAI1lNXDWT4ZyFFfYuP7DkWybQtEfI4YxQxEvLmyFuQFK
         YEmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ieEKHfLnJYonJqLklemGO32vKZeaB2KapXdu7j9nnKI=;
        fh=VJIlIVUEne1+ACn7gJUdM+bswh326QUdXoY1QLhjyG4=;
        b=lP4FtcnElJ/pXgnsntZuyjTt3j3USy/QKCqShB23kbPk3FLdFTS5ZnfCVCzN6WcxMf
         3VlIfbCwiD33EPU7KvRTAHhhK6X48TQoG7Zc3384eV66VCMUf7tvwkqJetrL1zPHVyG6
         6qadlZEgGcjEXpmrxSg+5ReS9xQSUmZLO2yBXUmZIZopq8LWtQ1gUm+GHlf4yogNIRPG
         LtkvmdRGldMVcIKXTL+flNSPdQgySxOEn4Ez4gCX7CA81nlARnS4Z4BR6k0qZX/hFVVr
         I041Cd6PyHOPyMTDQNYO+S6OuWAy+aTSMOCnV1tQ6qYxtvnKVr8alSvLVizDLOyZmxGb
         Pppw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z3cV0Sxj;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755633508; x=1756238308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ieEKHfLnJYonJqLklemGO32vKZeaB2KapXdu7j9nnKI=;
        b=WOKjaMyKeK3F5tDPLbj8JOtW3ivrw+EpReVzKz5s0ti2WQ2RH0l/8qm3LZro4J364B
         bEhBBspmsxnYsTTxTZjbWIx8UNYtbpW8UZIElzWA2VgqR8+o++1VkLunUub49znKGSXI
         XBVdlBxGCaJizsiF2mCerkKStBI67BPBwmwg8P2dxThz1sw2yLx8sdfDlbTlkcWa1QA3
         oYiGJ4BWNDcK7/7ohnthcie0SFfxMuysvowf1UTcZkE03soopOJkuzt7/jmW8Db4JO9s
         kHIJptwU8AJ6e7BVewKFtBbieDdFGLcvkiRATmuMkqsARMj6pm1XZq1nsSeWLeel1mRf
         Ny/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755633508; x=1756238308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ieEKHfLnJYonJqLklemGO32vKZeaB2KapXdu7j9nnKI=;
        b=dqEj5ofl9/7dM8dQrFKxr03CdPfsXTWSDuzG0phv+F2zWwye6ToaURGiffF99x76Kt
         6P0PrZQkoRKseOaxWJ7ces/JpdsolQuoVpba80in8q14zzvGzVk5tky3AB1fP2zL6sCI
         YLYhIkbREkc2ytbRXNDFsQPf7b1CAl2IQVhz2LPTODJa6Nhv1MC0nqFEHzb9wLCH8T4I
         n4CEQz39E8Rl1ECbn50qe2ihY0op8TB+o93GU4+pCot00pnZRQ8Pg4l87ZeEmZ14g4+O
         /Ihqabfax2qHozvQ9F6G9RsvB7rwCnR8ZOJ1n98Xan0nz5rSEP5eP2iz3ddGvSPOEBx7
         hOlg==
X-Forwarded-Encrypted: i=2; AJvYcCV9alBaMa7GuQY5UQifsNQOKG4/nFYlZXdHPDaBR90jpY2OWR8fRxcNkUyrluY36FgD3eltDw==@lfdr.de
X-Gm-Message-State: AOJu0YwdimR5A4A0TkkTcifGwgeP8xNU2LzMLKKAXpQTBgi5bm+GdZa8
	B412PwKtBbhSakSZ0UauBZIBfFLuK8fg7rz5BF3/G7Yl5tKLFrmcMVli
X-Google-Smtp-Source: AGHT+IGCd0vAjS0mFq2Y+pGaPpA7RW1ZNKKHBEfDx+gjpn1e4Z3cE9bFItLdEehWvJdLP9hQiNWAOg==
X-Received: by 2002:a05:6870:331f:b0:30b:e02b:c806 with SMTP id 586e51a60fabf-311228330e9mr211779fac.14.1755633507873;
        Tue, 19 Aug 2025 12:58:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfffvm2bPacZGMZ0tLZVqG8g82x3d436jrXrj2ZGYZW7A==
Received: by 2002:a05:6871:a90d:b0:310:db86:8d91 with SMTP id
 586e51a60fabf-310db8695fals1063517fac.1.-pod-prod-02-us; Tue, 19 Aug 2025
 12:58:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9zNEU/3oA671Tv4dXA71yj+VhJGx26Lb0r0lyp90FFo5a9OilaWwl2LvMo2f7F5oWJ0CRR2B3LoY=@googlegroups.com
X-Received: by 2002:a05:6871:5b04:b0:30b:b37a:6bb6 with SMTP id 586e51a60fabf-311229f2464mr196975fac.28.1755633506914;
        Tue, 19 Aug 2025 12:58:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755633506; cv=none;
        d=google.com; s=arc-20240605;
        b=I8wQBb5mM4KPJ/x4I/6OTKNqHH6iTM+kgBEjtrx73Yc9SnaOPkT5IpYJ/F+wm8AT01
         LyO2Wn+zdxV7CtHJV3T1cD80azybLYxEIi6t8quw43eEE4qhIH5DdGOK8wtYul0XwAUb
         7xPFdBrkRy8SNGkMNm8I9G2+MNGceFso2/yLJfkBoX1XEE9WGwFTsyjg/9Uswbc3B+IE
         zAqX7c+OhptdH12VZcM8fQowkNv0lCaC8Pj7U1TyXRo+VaDIeN8bTxGK5OAlZmFbw6No
         twyKRZPYpy9y63tFAcxUNyYl4ikqSipJuiZTcGIULdX73tC8r1RUu7zgRRUUmntkj70q
         o3pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Vouc/RnOn1OR1o/ff5mjM7Yg2TfneybwsfyI/BiiIXk=;
        fh=j6sgmjYfcl3NT0NcHnADy1HyK+NYf98K9zJ9uHWD/qk=;
        b=hmNWKkhbsnBlNqZOzlomxH8CqoTv6/7kn7/prHHYitfYgLy/Eu8uMrFMWZlGOh3BhQ
         QO7t/TkE1JvDywWq/ObUcwqcdTs+9mI79OblH1X1nQ+RaS3YzTOWwwlJgXYXuIRtuWbC
         ROuqG8wCQx0tuXTBU6zhstFD5vS2IQ5ep3HDuDRb/gnT0OV9qTOGzHzrA5TWBj4iOGy0
         kF++9jCMAgQNQbA6qtXCs49YUb2pBvFTYwLQX+upKAWjaY6RyuGLLXJJ6MqnTuIx12kL
         Kz0X/ZSLGiPvBtEsYFa57O1qO6Yu//0nznFEK4GP6CJ81FdHSJf/rT2lyAWnZjAcxWRQ
         3b9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z3cV0Sxj;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310ab91bba3si594273fac.2.2025.08.19.12.58.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 12:58:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1DCD345455;
	Tue, 19 Aug 2025 19:58:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 63D9EC4CEF1;
	Tue, 19 Aug 2025 19:58:24 +0000 (UTC)
Date: Tue, 19 Aug 2025 13:58:22 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
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
Subject: Re: [PATCH v4 16/16] nvme-pci: unmap MMIO pages with appropriate
 interface
Message-ID: <aKTXXv7kE0pGGn_8@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <545fffb8c364f36102919a5a1d57137731409f3c.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <545fffb8c364f36102919a5a1d57137731409f3c.1755624249.git.leon@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z3cV0Sxj;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Tue, Aug 19, 2025 at 08:37:00PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Block layer maps MMIO memory through dma_map_phys() interface
> with help of DMA_ATTR_MMIO attribute. There is a need to unmap
> that memory with the appropriate unmap function, something which
> wasn't possible before adding new REQ attribute to block layer in
> previous patch.

Looks good.

Reviewed-by: Keith Busch <kbusch@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKTXXv7kE0pGGn_8%40kbusch-mbp.
