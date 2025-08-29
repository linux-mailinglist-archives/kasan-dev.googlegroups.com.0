Return-Path: <kasan-dev+bncBD56ZXUYQUBRBCV5Y3CQMGQE3ASVFBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A193B3BB72
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:35:24 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-327b289e88dsf1923184a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:35:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756470923; cv=pass;
        d=google.com; s=arc-20240605;
        b=bObXTL29cZn5wf7RnAnkEMnAO5Kmk2OKUnWU7wIcLAVOhW7k8JaBNcEBYr+23ilN+H
         YkStPcz9kg3LF1hQlyTonZsHV6lSvDjxTFAeJteX6Ft4rmtkODvtPpZEXAj1+RAspFql
         Vsua63dfZ7ACP4wlDszp9uZSsV/9EtN8Yz12vspSaG8zrwvp82HBxk8rIhILIC0br85I
         XU9VIF5Syx5GGy4Ryk6iZEHxfrrVAJ/YIquQoF+zRE/oJPOreopwI+hxRpsUuIAIkaB9
         dtIcLiLqmRArIs73JkOBL5/s3kLYzv39iB92Kv0HyetiVTFluuyqasFxdPSy9QTRLy1S
         yQtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ofIUv//CV22GEMjZUZiaqQi+j1jBRehc9z55lzTTesY=;
        fh=Ed4+YRNFoiowcOU0XwY/CP+vyUFbsB8logmXGoo0efE=;
        b=jtOqKss0aIJiOKD4jKuAcq0iRiOuPLzy1QslwB5r0tdtuYJ0CDLkQjNBHBJpxHzYkQ
         8wEAoBZyD68BaxUt1sDO2lgb58yqTunsipC5ucvcmbzrGx8/NSyDgEtolKjbb5o6AKyg
         q58T2mG7S49NLdpT0Y0rE+SH4OTWTV2Ix1D6E4uOKostSj3SrXbGCeSLD9Xo66h0Hy9h
         1dQdgPsmBciPFUTHEa3wu4KMSS6+58U+2cidAXud9uYFfqgjwaXwx6L0doWbSD9midx+
         b0+bfLynk9DRfQkAcQTukMZmepfciEAwT1epVItk8bYjBC5mx5tpeIEdDBc4bNZvaOHk
         8tcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Mxl8/qU6";
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756470923; x=1757075723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ofIUv//CV22GEMjZUZiaqQi+j1jBRehc9z55lzTTesY=;
        b=EP+6x5aU2+snEpj4mvlihXPSz9s5/Hse1zLBoL/fb4x3iNTMLzMdIdIISTjDr0bRC8
         mlwYKlUDKCK52ePdulwClbPOVQbEVTBxHTaGgYhxpLkGWFMtJ0tulcl2dW+vruOPhpGp
         RZXZTmAFkUP/MOiPJoUOuv3sqK0GQOWeJ/6WROTo7eR0QTlBe4hZGWy6zp4KLaUBvL6N
         1RQrRsdVfP1S4WZGqCuVLNeUQTfiPhkbORL9YGRxdXRe3qJjSYcVeeKmv5UbDkPpxwPs
         r/ByQZdosrC1Zc7UYo1AbaVuhIZHSLR1TlhoejZrLxLQGLvkUYJ1/f4L8yBWsRzu5Esj
         WRqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756470923; x=1757075723;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ofIUv//CV22GEMjZUZiaqQi+j1jBRehc9z55lzTTesY=;
        b=XO7Vxlg6fq/4vR/p8cVIkwVhtzhposgwXovmpNCRFq5sb/NXnoAlIxM7wpSC/E47Ur
         SdUGVQHO+Yw7H7Imjb498jj3n9GIPrUpDtuxgoB7B/wLPOXHpOS7kl75CgKNVs6yeHJk
         neGQ4vGHVhGMUt/d031tGFpaTk09x/i8ucnmgwbQBtgxzwcQRvvciJgmSsxARS8/FNQi
         yQiqutsBmXyHXCnDzAhHrdW28lK3AcS6s0lZ99eCHlTm61WuLhxqFZgrwnJnSq+hf0jQ
         lwHc/vuEQgTfu9lSQHfM6s93VjzbrDwx9+u5VTGQEWci7RSxbytl/N9LaxzDNAkZ1foL
         uwbg==
X-Forwarded-Encrypted: i=2; AJvYcCVy+WPl4FgHDlOd0wXkJtzebj0R7C6/bBmAD71mrVAJwgCcSTYRh1ixGTVcCX6KSzs107c85g==@lfdr.de
X-Gm-Message-State: AOJu0YxhN5TaIclySo78ZROkAP5lg041AdPqdYf6Uwrjaj6skV/keC/9
	9UETWETsyDw6g9w//Ijtj6A8NSPF9J2CHiFy7O95MognJL8932Bnkage
X-Google-Smtp-Source: AGHT+IFje9ZskuDiddN06g9/iRb349VmKV/Vg6wfwmWfmEPSgekTU5F6/bITdrwHnC0eudo+dB9cpw==
X-Received: by 2002:a17:90b:5787:b0:30a:4874:5397 with SMTP id 98e67ed59e1d1-32515ef215amr35122142a91.9.1756470922728;
        Fri, 29 Aug 2025 05:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevnSAO/W7moOcQc90Jj5fMiwL4JiO+lNOQwZQZtZKyqA==
Received: by 2002:a17:90a:a8f:b0:327:646f:bb64 with SMTP id
 98e67ed59e1d1-327aa8dcc77ls1603690a91.0.-pod-prod-01-us; Fri, 29 Aug 2025
 05:35:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV55bF3o/cXLtQm3Y5/FyGOT9FwHgY9Qn680EtgoyOFSUPER9lOxKShRKhglqdkrK/DiZ1jtvZzX+w=@googlegroups.com
X-Received: by 2002:a17:90b:4fc2:b0:31f:6d6b:b453 with SMTP id 98e67ed59e1d1-32517c23e05mr32973515a91.30.1756470921204;
        Fri, 29 Aug 2025 05:35:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756470921; cv=none;
        d=google.com; s=arc-20240605;
        b=Fl4VhwszTGn0YSuB3FzOC/rsJCZ9lp2XpS0FLwlulXxcvAhdUXpbM34Boxvc9DvOoC
         FC/xCU/lWxyF/13yAL4kePcK5CglG08pEGNzzpnRwcm59TUadS4v0wJqrVazNBd1rp2O
         wWHwmFHE3/l3MVy91rvh01GC3b8xrcuQ4/R4F9Jqbhh1bg2/pU7sdvpAqnthe0IWsQnv
         ZkJIYOIeaMn7i0mpQZxy93M2K9HFsaSMXtUYW8IdnekKTSY9F3+yVaNCUu/AprL2fqNI
         MDqWJnqPe3DmE/OlI+kWIRb1SYhgiQW7GKjq1i3zKI/uPyBEPX6jd8H7Zy4FFW9jIGtA
         6plw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5zSMrOVSNClOrdiZ1EgFy9NdG3HEevOLe/lENj4ZGeg=;
        fh=kGmHQt+14enYEes1OrQ0DO+++3SaqzFzOlO8vwACg9o=;
        b=aqaG7y1VYXsP0dpjCeGNMO3arxz7OwblgLMlEGIfoX41TsOV7gFniWu7WOMP0yAeoj
         cm7yku4d60LYwc3YPteSbK5ctnSfleROumHXK/vMyavLL+ZMy9Cx3y/gjCQFxl9/vyxO
         O0DiCqFcAPTBFtDCp1HyK/jZoP9BJfgzXlt7eZQZxtKLpVhizib36f9CRbi4mO3Ioivi
         vIhwNQMZejS9sx6IRIzPfMEM57WLLhn7PCJi3CH/r2K7GdfQAl6FjMJRDUqAMi/CAYff
         PGylr+qVxtLOKnXy3Fcx7KFms/MxaIgjzcJRNBOb9SWleYM3yiSnfeHPKzsf9DZkmy4D
         fGrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Mxl8/qU6";
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccfd81d13si77452a12.2.2025.08.29.05.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 05:35:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1499A60054;
	Fri, 29 Aug 2025 12:35:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 49DF0C4CEF0;
	Fri, 29 Aug 2025 12:35:18 +0000 (UTC)
Date: Fri, 29 Aug 2025 06:35:16 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
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
Message-ID: <aLGehMVsTEXrP_R5@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
 <20250828184115.GE7333@nvidia.com>
 <aLCpqI-VQ7KeB6DL@kbusch-mbp>
 <20250828191820.GH7333@nvidia.com>
 <aLDCC4rXcIKF8sRg@kbusch-mbp>
 <20250828234542.GK7333@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250828234542.GK7333@nvidia.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Mxl8/qU6";       spf=pass
 (google.com: domain of kbusch@kernel.org designates 172.105.4.254 as
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

On Thu, Aug 28, 2025 at 08:45:42PM -0300, Jason Gunthorpe wrote:
> On Thu, Aug 28, 2025 at 02:54:35PM -0600, Keith Busch wrote:
> 
> > In truth though, I hadn't tried p2p metadata before today, and it looks
> > like bio_integrity_map_user() is missing the P2P extraction flags to
> > make that work. Just added this patch below, now I can set p2p or host
> > memory independently for data and integrity payloads:
> 
> I think it is a bit more than that, you have to make sure all the meta
> data is the same, either all p2p or all cpu and then record this
> somehow so the DMA mapping knows what kind it is.

Sure, I can get all that added in for the real patch.
 
> Once that is all done then the above should still be OK, the dma unmap
> of the data can follow Leon's new flag and the dma unmap of the
> integrity can follow however integrity kept track (in the
> bio_integrity_payload perhaps?) ??

We have available bits in the bio_integrity_payload bip_flags, so that
sounds doable. I think we'll need to rearrange some things so we can
reuse the important code for data and metadata mapping/unmapping, but
doesn't look too bad. I'll get started on that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLGehMVsTEXrP_R5%40kbusch-mbp.
