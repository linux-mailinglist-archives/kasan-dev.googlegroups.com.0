Return-Path: <kasan-dev+bncBD56ZXUYQUBRBZMASPCQMGQEWBBDZEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 288E7B2CBBF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 20:20:23 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7e8702f4cf9sf1518010985a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 11:20:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755627622; cv=pass;
        d=google.com; s=arc-20240605;
        b=jhUxpNv80fMeIIcSLE/uLWatVqn5TiR22XSkOtl0SusYjQPVkK+JXu9XkOCzXzcgpX
         FAmW+2jx3KAbT+kkhm53khEUk8t6ngfRPp+3WEPRumzsogd3y6bRDdRUZamUiGotcA0x
         O8R3rg2yHaAXb2+fUDhm1l5ZnXvujE7IhOLsBU8guPADtx6mBbfNT9rMvZOaqfzEVknu
         FwNbwr02fSnYe+GPmf+G3ZpEG8GyC6DEr2wZyTGlWGUeYzwvFROV63thM/3HJUI0JWpF
         BiZa9fuPQpiOUFg5R41Ft2QdW6GgR73W4n6krVSGw7a96tT2uIj/jgeesv9vN3mH5rpe
         VRJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Rj8Phxqv0fbmzf6XnlhyqTR5TvG64flpXoXsl0ei7YA=;
        fh=NDyJc50BaHG2VH5xpAbIdFXfe75E/ePPgBFch+RslZU=;
        b=LCMxaE6Iq8q/9yA+zAHGn0dCTAjPx+q3akjQPvVyEOJqWN4qxr4azV6ysXHqZ2Gwwv
         Jjg6aywA1SAAkCj+JNlv35X/9TyLNu405O17NLmu+QsM9fPVt1BRmHzeJh/nxjwv9TI6
         WdE7hXYO+lsylX6lahPSCMFM8lYT9XwYnEtlZEnlNUxnlYOC8UfM0/y/M4kfTmKqE3UQ
         v92cfi4aqqNIoMd2ZnpnNYtlQbUwkQ2irYuDZOMVBCXZ79zq0d5yxJ1Xk5rIwl+XjKyS
         48sJHh8aYM48uyqYOUyJ4/7ZxOqNjR5DPu0OllX17aeMurHCuGwxRT3Q0SiRAXPYKaHo
         9aWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jXjytkUF;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755627622; x=1756232422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Rj8Phxqv0fbmzf6XnlhyqTR5TvG64flpXoXsl0ei7YA=;
        b=MZ+I3Vwqi3/xYHrGiw0thFwIUxPXEB4cggaXPKzEm7bSfPk6N8nqHN+wiI3e9u3wHC
         BPMHZkXdcyfuk3qaCzkf7Fz00hAt1mtjzS3q4gycg05tcXz5Df990NMyBQ4e5gZQmTB1
         UEXOnh+ZzfnaQK7sn492myd9gzC0uLSg4dayaMOdS7s3IModd2MA9Ncy47HtVMMspKNt
         6YxThyjSYixxBUqTlcya2iK3+99kWCGdtwUcCa+N5rIQwYZcULPEZnYmZ3s8ooIBwt0d
         azYEntPuLo7BG78gPW1FP/Z+MOhnocjOIquA1NsOCOuHCupFOTGPOYbHgiSFnJ9AMuo9
         df4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755627622; x=1756232422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rj8Phxqv0fbmzf6XnlhyqTR5TvG64flpXoXsl0ei7YA=;
        b=uGLM3o8WULAHVwWYwjw+Mh7RYB37ijSUgSDpHSQWy0c5iMwUOHgUDJQAXBgtiaT/tx
         X/yQcvBslfKdMr9A7YoAfqjDeCQ78YUF35BgaugPqWgS+/M1R33ziqEILnPSjjI7YiRf
         15wTUKH6jPP262e9uGjdH7+I1Y8pJiwtVyWRd3kR1jTzrb539I9ef9w39Y+x+/JafeV1
         cwnDsQxrENOo2ZrgPVFktGk2NoUbHxh+07IKOd7tRrSOyStfmGsrzAkZxpHg2e3vDK5p
         UpupJYS6wsbwjHLWq2+g+/jaIhrVVnFZz+3HegPjQimwVWPFX5NBfALCE/HFStwj8n1S
         Jxaw==
X-Forwarded-Encrypted: i=2; AJvYcCXxPHUdGcG1JotuNnHlRblIBWgJnaGAi5j0x4YCKOblmMqvu/r3o7WQbzrc0PF3iTm2j1Ti2w==@lfdr.de
X-Gm-Message-State: AOJu0YwH91WWb2EigfY5IgV1M6qMUam6IezEOcXGt1aYphGNvL3hrOmA
	NF44eKtyTSfXwDQaPR6QN4hPysHsmgSBQ28O9638siNI1AUSg/UICpFr
X-Google-Smtp-Source: AGHT+IEb32Pxm3GC5/6UhGVAxxSr8mQ/3KLUK0u1UKABJWzyxTmUFi4nt/bx1vaP0oEDrQQdcmhJRg==
X-Received: by 2002:a05:620a:40ce:b0:7e8:5c4e:44c6 with SMTP id af79cd13be357-7e9fca9adeamr36420485a.28.1755627621696;
        Tue, 19 Aug 2025 11:20:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcF9VFZs7IGAjCiBD7HlehV3yUIUXf4BD5RezZkiicx1A==
Received: by 2002:ac8:598f:0:b0:4b0:889b:5698 with SMTP id d75a77b69052e-4b10998a9cbls90267701cf.0.-pod-prod-03-us;
 Tue, 19 Aug 2025 11:20:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUuNHshuFFOLrAtuZF1hjcijsDmMHRT+16qaipSDlX7M5C0GldS8zPgiZDrKpPPf5hnzEm/oVgBS8=@googlegroups.com
X-Received: by 2002:a05:620a:1729:b0:7e9:f81f:ce9f with SMTP id af79cd13be357-7e9fcb7bb8cmr27156685a.77.1755627620622;
        Tue, 19 Aug 2025 11:20:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755627620; cv=none;
        d=google.com; s=arc-20240605;
        b=F5ZQJvz0tMstFSky7pVDGHCEMwPWq7fUIG/Qjr3ojnSJpttdspuNpj1hp8ZRuLi8aS
         Fcjxq0EpEPQOs8ujjbPepta+MEuePWCeXwAUWuaT2SMk02PDwXiMUbAshgGs8TJ/0Krc
         JfK3aQISje3VYLhkNbMcyXPnWeHFWmcISb+CiMxq1VhkGBg+H+0B0LdYSJ7ZtgT3ufFE
         DES5ie6cjijbwHT29Ywx/zNIdFcdLZggP3mJJbci+VkRUaj/KDdYHlGr0f2iHQC/1WF4
         4/95WUBZJdhjx/PF9O8zJS/a1PhMXgRP0tRygN0Hen/MGUl+RgiE2cVJT9N1Yw9fQ0iw
         HuBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jxMRJz5w5n4PxTFk/2BTZWr0cMwftnWj3iBsc1w/fNg=;
        fh=j6sgmjYfcl3NT0NcHnADy1HyK+NYf98K9zJ9uHWD/qk=;
        b=SC83KfPVqtX6fi+1EACARGEck6ZKI4F0rnLPmPhjiq3eNDFKi3pbEbPYC+5HavuPB8
         EFQQc43UKjGhSSbtqtGlhO+OiWW+2FdkOyfFjERQ2tSAynn/6SqfUmciUAeQVE6tYasr
         gl77Om3HCz1UqIcO+mzGmQzigbxZyVEgHeB8uI8xThgGvjE7E/kJ7OWcuMlDp/+d3svz
         0o80kNWVhtur3IR6BrVTLWlNCfl4I3UIhwwd8/hEEjbaFcTwc+6ukEx+qE/+RAc2ShkT
         YQpcPWtqyXDcWMuLMFgVrfqQdD69erINl+Y+cEZBBmWGvrkRnjIc14HB/yhXshJJD6Xt
         VEWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jXjytkUF;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e0e7865si46030785a.1.2025.08.19.11.20.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 11:20:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C14C74588D;
	Tue, 19 Aug 2025 18:20:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E0BDC4CEF1;
	Tue, 19 Aug 2025 18:20:06 +0000 (UTC)
Date: Tue, 19 Aug 2025 12:20:04 -0600
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
Subject: Re: [PATCH v4 14/16] block-dma: migrate to dma_map_phys instead of
 map_page
Message-ID: <aKTAVOBp0u6ZSC4w@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jXjytkUF;       spf=pass
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

On Tue, Aug 19, 2025 at 08:36:58PM +0300, Leon Romanovsky wrote:
>  static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
>  		struct blk_dma_iter *iter, struct phys_vec *vec)
>  {
> -	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
> -			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
> +	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
> +			rq_dma_dir(req), 0);

Looks good.

Reviewed-by: Keith Busch <kbusch@kernel.org>

Just a random thought when I had to double back to check what the "0"
means: many dma_ api's have a default macro without an "attrs" argument,
then an _attrs() version for when you need it. Not sure if you want to
strictly follow that pattern, but merely a suggestion.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKTAVOBp0u6ZSC4w%40kbusch-mbp.
