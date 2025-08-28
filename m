Return-Path: <kasan-dev+bncBD56ZXUYQUBRB7PGYHCQMGQEDC54EWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E0B5AB3A412
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:19:26 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e96d57eb1d0sf1126408276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 08:19:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756394365; cv=pass;
        d=google.com; s=arc-20240605;
        b=LvRRPeXkW8dUnFnvNv9rV2Rt3CZdgyl8IHqcswZ0wkLUHBnKswrfpHyYWqFCWVV8zA
         6J0TMQGU8C5FjcmiujyL8DHiTxFySpLxbk+cg5VBJjzQU0eyDL3fmEJKz0bZDTgbiD0B
         bU3tahOxyc4MQjzDYoTO6/Mu7DtFbUEXc/r6oYGKIZoq97STEEl4H4NlEzEhqQi2LzyS
         btW0L/etWnTEoNyORotsWn6/gJtzSHv/C+7hIw4ZfNXL+X8Cyf/rrOahdYT8gyUmzkbg
         FhPmM5v8By/MRSOqQxUze830Jfd0pUiXjOpiACordkzS/4Gqqm6rfK8PS5YMQdc6pn1O
         h+Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Cix+aoCi3l/LVTI29numsg12Qtt7kLYl6J8XR+xE5aA=;
        fh=TKUqRPq4MxNMxWcG6oQlfhhz21KziRQ1Kdu2A0ZevUM=;
        b=NAifYdd5wHkkyqfJNr/Sidhu5HblANEqy/i7ou65Txbwn4GmAgZ6RqbpRDgtXgxaiP
         aTCXewsGXrH+McOAXBXPVeVOPlxI58tKEKCwDlJsSY4aUqBfvyazJOhBEfUbJdRDjSU9
         e54po7dXKV0YhSyRNszJGmxazRNRuAN/wyePOgzsMp66JqrQegAJJvt05m91O9n8iDkP
         sdDS3h5+InzWGTR3RycOoKyICg3qaotjrNNJ1kmimIyjifnKKJFaP2f5D4pSHOb0Mj6q
         o/HeODf596PDnFXQ9vJ/yYaVMq4xHO/svHNB1CqRNbvI2uQAxYA8cUCirmZUm5+yBwHP
         4yXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Fiz/IFX/";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756394365; x=1756999165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Cix+aoCi3l/LVTI29numsg12Qtt7kLYl6J8XR+xE5aA=;
        b=xZfJ+Qg67bYRAF7GpywAMcJ/1Z6Lxh0Bm75t92eWjRA+ok0/RxRsOxEDFc3OYYuqrx
         0NEx60qgNrBROatcBcXVeAYTChShXHCcB0XobUt4wW6LJDzl8m7xve1i4ezJx8L0ir9D
         Pr44wYIW3m57x/1w4zJBohaKAAD529Vz7kD+frcpD+OovlKKJIr2g1OnLe/6vEnQv0Z9
         ndTZ6jjvQYSGulutEtjGLpJQsX7eyZfuZXZy8GLxXnvOE8VKLaJcnmNWuc9zTRKH5YdE
         eoq7BgzEJxkNlSCmF9Ju7mtNk2rDwNm5vmraNLsvnqY4FrBEU0NjQqbuBSoJjQmFQvV2
         bRgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756394365; x=1756999165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Cix+aoCi3l/LVTI29numsg12Qtt7kLYl6J8XR+xE5aA=;
        b=PPUI9Hw8Yalc9/D8myhTXIUKPDf7wej6Us4huLBHZbyZdtdhss0KU+CdoJE2V6ryfp
         t9IiGBBHgv83HAI92Qu8FnuyQ5PH0+zpan7V9xhwq/6uazsRDhVC67xpAMr2btFbeXR1
         kHCMAiXlCzshDLe+a7Ct0qLu7iMQYfklax1z59S3U1k5qXQtEiryd6HLWJk5pQhkYrf/
         mpJL00g61N8W2Spm/OriyHt4Yx4+WX9r8ft7Mi+yjudXe2MZ+KcSs09/VKJtvIeumoBj
         MV+NlNTtFJVg1wwwBULcymuqTvPaRK17sytJikWQPC2G6PAVG1vWtBAL2hSqAvHtyDx5
         zJGQ==
X-Forwarded-Encrypted: i=2; AJvYcCXGGwkdKxbyPWzyMQUiJlBZcyOH9FxX1UAlg/OZ7D00HqdLeWbTx11O7Yb6V1jiuConC+LHhA==@lfdr.de
X-Gm-Message-State: AOJu0YzW4t2gDlYxkeaHMBJF+xGLRXX/2Fc10f/XAZRx8ufbeFuVzR70
	8jasUz7FeE3TFfByg6L+VLgpPq3bUsx7ttP7PsxDRQpbPfEP7W2JeSpQ
X-Google-Smtp-Source: AGHT+IHY40N0WO3xiXccAZjJVnpRigH/6XnRJYxajczFmEwmFmFztIHNO/x5slD0GLhNC3DWT+pSVw==
X-Received: by 2002:a05:6902:1142:b0:e96:fca8:9c57 with SMTP id 3f1490d57ef6-e96fca89dc3mr5048751276.18.1756394365487;
        Thu, 28 Aug 2025 08:19:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvkkzeNcJ5l7hVZISPsn4Yo1rObm0Bl6XijT3ko65kzQ==
Received: by 2002:a05:6902:a06:b0:e93:3de3:82c9 with SMTP id
 3f1490d57ef6-e9700a8a980ls1048703276.0.-pod-prod-08-us; Thu, 28 Aug 2025
 08:19:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjX1TSy0ReCcC6oYN84xUu+4wFF6pHg9HHZB5boHYVDuP5JHaN/Jl5wLEB+RZbzZIu7vCxf0yqWXE=@googlegroups.com
X-Received: by 2002:a05:6902:230e:b0:e97:d52:c5d0 with SMTP id 3f1490d57ef6-e970d52d159mr1496284276.2.1756394364342;
        Thu, 28 Aug 2025 08:19:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756394364; cv=none;
        d=google.com; s=arc-20240605;
        b=NmVhDFDFNpt/zqp/6T46tMkKI3AIUTC8IjtSSAdm7pLFVFzCV3hgpd6D2R1Sky/AST
         rC5a7ipx/QbdQNXbp6kZUTDapE1IzWb5vR/xhw+5lT3odzupqUC7rvt5qmk3UEhGkF7p
         iKXoMDL/wb2ZXzu3tFBxLjGDyVxqXiFVqpYwFLeOn3XOoTzMejPzeZImaN6/JFig4Yz8
         hinQgyzGM8hdrEqg8n30e10amVh8qZGQIfcLL9ri909Ai/0QhtwleKvaKZAlk91lNj8+
         UN/5o8YVLadGDfFdOobWOPqa78fxUJ68g5j1fA6LOyPPy0t96y+RNVDVwBfcJna0mcvE
         pk3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+Wz4elI208IK+JSajFW9ZYSY4sJyfxAIN3oV4QuXWNY=;
        fh=j6sgmjYfcl3NT0NcHnADy1HyK+NYf98K9zJ9uHWD/qk=;
        b=R39g6oYxviHPOIdOXKjvZG8HiMd9e+d9mBpHVxtsm1n/4clTFY1eZSvx4CM9YSbcTB
         ROI/PNMnJ2DDmODVbG47FXFDgd9uRzT539+eSUeUAknbL6rZyCOW3VUyW4CqARRNZvsX
         wdUusteWe9Ke+NvjnY1avXftIFGLMsIU5iD6d1E6ddTVts49E2RKtljcriRatLeG8LWu
         99d896/quRcEuHzfKnhDD/K+4bOcrS5D5cbVPT/ggmjmLOO9hZlt+2qPbkT+aXhyBMJz
         kl60NEKsnSG2LTQg2dYteHnesJTj6BWicwYLGzbuSbAXFZha5z7819bKC6LPGVdPzxHJ
         jrVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Fiz/IFX/";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96fc73fb40si169738276.0.2025.08.28.08.19.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 08:19:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8EB99404AA;
	Thu, 28 Aug 2025 15:19:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D216BC4CEEB;
	Thu, 28 Aug 2025 15:19:21 +0000 (UTC)
Date: Thu, 28 Aug 2025 09:19:20 -0600
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <aLBzeMNT3WOrjprC@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Fiz/IFX/";       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
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

On Tue, Aug 19, 2025 at 08:36:59PM +0300, Leon Romanovsky wrote:
> diff --git a/include/linux/blk_types.h b/include/linux/blk_types.h
> index 09b99d52fd36..283058bcb5b1 100644
> --- a/include/linux/blk_types.h
> +++ b/include/linux/blk_types.h
> @@ -387,6 +387,7 @@ enum req_flag_bits {
>  	__REQ_FS_PRIVATE,	/* for file system (submitter) use */
>  	__REQ_ATOMIC,		/* for atomic write operations */
>  	__REQ_P2PDMA,		/* contains P2P DMA pages */
> +	__REQ_MMIO,		/* contains MMIO memory */
>  	/*
>  	 * Command specific flags, keep last:
>  	 */
> @@ -420,6 +421,7 @@ enum req_flag_bits {
>  #define REQ_FS_PRIVATE	(__force blk_opf_t)(1ULL << __REQ_FS_PRIVATE)
>  #define REQ_ATOMIC	(__force blk_opf_t)(1ULL << __REQ_ATOMIC)
>  #define REQ_P2PDMA	(__force blk_opf_t)(1ULL << __REQ_P2PDMA)
> +#define REQ_MMIO	(__force blk_opf_t)(1ULL << __REQ_MMIO)

Now that my integrity metadata DMA series is staged, I don't think we
can use REQ flags like this because data and metadata may have different
mapping types. I think we should add a flags field to the dma_iova_state
instead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLBzeMNT3WOrjprC%40kbusch-mbp.
