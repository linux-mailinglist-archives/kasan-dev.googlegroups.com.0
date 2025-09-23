Return-Path: <kasan-dev+bncBD56ZXUYQUBRBIWBZTDAMGQEXZU52JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C1A7B97B89
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 00:35:16 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-4247d389921sf5410795ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 15:35:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758666915; cv=pass;
        d=google.com; s=arc-20240605;
        b=NeUn0a8vIMeE65byukmcspky63oVqu38LRGgVj3LOVYuSdb9aHtLGDCsJjjHiYmSti
         catF0YfG9asOW9BfArdjcI5Va6dkfMyD9FT+oz5vCYmpXEveRjnxSQG+/HpRDK6Wruq5
         Hffm82NXORegX4wGDSWhj+t8MTsE40ebdYe8ZZwOp9mGxrOe4SuQvzfvdEAPlOLqjZ2f
         LCv+uTX7KWCJ6mIvJBzPAW/VqBGiyg+waB5URa2+b7qzAIPAz4t7MBvhZE1Jnb/CtaSr
         vaUNpmmUR9GVmIhBqIbAqr8BR6yinWELZC0EbG1jKbUz3eTlWOprtcbHDMSSKU05Yl19
         Tq3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ThSudXa8r2QEfx6LQ2CS/mW8raesokZdHBuQEJmrAGU=;
        fh=Ii6VKICTQt3c+k3wI7nhCU8EFP5QQq7C/wh9pWSCDkk=;
        b=OswPaiPB8r7syG9wQlAb8E9M3XBymJR8dt8DyFEy+wyBSh9Vg+o9Er2huUYf/ARBwg
         MbuZ1dCEmqbW5TTru/+mkkx3VyLajuKVn59d/p9FPVOlEUmNnqHlhHGDSdLGOWwaIZ1a
         2pFUfxqABTDdFFc49h7FKQ0eXQXqmSzxNV+nwS88fQd77F5k049zhBygLjnCvqBwtUI4
         +TiZeITNnGb2WvAhZdSC987+it8ZuqYQ0TX+rEFjW+bNPKXsxL+aqPTCSJh5P8qghIPI
         tfUFNxupNOGEpN/ivAuQMDOrWr+ZOn+ECK4VvzZWbyaacaxQL5LTb+au5ptxznDGxDgb
         5DSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NfvKLIEC;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758666915; x=1759271715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ThSudXa8r2QEfx6LQ2CS/mW8raesokZdHBuQEJmrAGU=;
        b=jfE6LpIFwJU7JYKDk7NNY92hkRbIkG3jODQIQXJP1jGjDikKvX7CnF2bti96dsrvUY
         EwxRAVPlt0Yrkh8PIzG/BUeADjo8ad7FMjzi4+45tOReYBi64emIj18n3NhrjBIJh4R0
         g0mm8lely1xmvfPDld9eyOCZGJiY5BVJIe7DHJBpG3EqJjp4WKY3b5dPWCud68EGD6XW
         bGqY8JWIekZ2HxAdsOX5WpxTTvDfh1KtJb5SegPlxayuzetCy1vSpXaupFlEcecZQYUb
         JwRWfwRiPfp8m/LPGDkk2GIoirPgde6VUTKzpZ0bXk8M/1MGXejyHHK1acJtLNgSK8yp
         CoCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758666915; x=1759271715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ThSudXa8r2QEfx6LQ2CS/mW8raesokZdHBuQEJmrAGU=;
        b=M9muIt7eSWwtM4hnlTBODj6l+DUZlqpIw177O5hRkfi/GUJN+I9YD5JkJdlvdDziJ7
         1qRTntRZ+YzH3As4FGWHkVw6Ztcqm9BUyVo2r1JhEEsS3sk0todrDeBuWvTJmBlMxy8u
         FaXw+ckYpyH54EibkfDBrg8GjhByCJxenMccQMzIlGP9OXYqkz57BfDwlVkfYZBkGbBv
         wo1kucw9VtvjIw41YPabblV1Wm4/fMjIsgQU/I65RI7Mi/PFLBk0tyMGkzb1kqZC9upx
         pny6tfcCInVQCuFCG7gFHNGMA4rpUyeyLwcgCOdodpgLFW3onRHGKxLE2tYTl28dYmOq
         XaWQ==
X-Forwarded-Encrypted: i=2; AJvYcCWcnyUac45lBQo0QYpUxZYk9vJ4C6d86d7yL2/QG5tdR2lmGiHsrkZ+1rTrCo230SKKAvXi3Q==@lfdr.de
X-Gm-Message-State: AOJu0YwUgxz8cGt8vXWQH0Wz8XeOUb6/hyIC761PMXdEZISaLTVd1m4J
	u72ZrmSf9G6A6pB81g6eX+Wp+Y4e8DZKI61zEkcsVrzayZBhES240r5e
X-Google-Smtp-Source: AGHT+IFaX/lKW3B/rTXe0yRHGbXs0sC6sDk5koCAdSoWSjSbBuon7qcsHr1VwqndtMyIHpxZtvuWIw==
X-Received: by 2002:a05:6e02:b46:b0:422:a9aa:7ff4 with SMTP id e9e14a558f8ab-4258d8aec7cmr4662645ab.11.1758666914698;
        Tue, 23 Sep 2025 15:35:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd50vomK1DZw1EeWk9FKvKHn2yW7SZ9WoTaPwHckNv58EQ==
Received: by 2002:a05:6e02:490e:b0:424:84e:ca1c with SMTP id
 e9e14a558f8ab-4258b3abd0dls1576305ab.0.-pod-prod-00-us; Tue, 23 Sep 2025
 15:35:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXy+2sA2T4QU0JuCbH9ijOW0EUdh9kUgpwx9+Ni9m+xb+kzrOAL0asiZIPdhTNyVgXtyOGoXCDtT0s=@googlegroups.com
X-Received: by 2002:a05:6e02:2141:b0:425:7a75:1014 with SMTP id e9e14a558f8ab-4258d8cb0f8mr3871145ab.12.1758666911989;
        Tue, 23 Sep 2025 15:35:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758666911; cv=none;
        d=google.com; s=arc-20240605;
        b=kNyMxi+tdg5MTGT6e3JxS0ES00g2BPoFZ5NY5Pz+SWTtlDnENvK0ZKoDgIFy51jvPs
         o6UAEDFmCESEYgs+IUMGbeg9ubAKBggVtcseXo3jvyO23rB8ErcqXHKt2WTsW1KWKSma
         sKp5wzP7g9+FccK5yrmGn1zZyyJQmSLx9UBLRt5r6vtRfCMphj3MXCWF038RbCyoQZQF
         lJE3Pix30W2cqNZ+wbKvGOXq5q9TNEG6QAPIcqBfkYrJ6yAZ+nocepQH+jCEE+avmxTw
         fTaEgAB5cYb2DzWD7M4p+NhbW6teCR1vuPFTyWt8lT8Hn8TEBNKM8nkSEnFpGy3SLJ2/
         bMZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=K+REPAt7YGROMU060Sut8pDiJmmKCZ4JFkal1RQOmGs=;
        fh=wB5rWgJB0RNxJt9sN6dF69FyVhDpMnk+gJOyItA08gE=;
        b=DFjPzOvAbFWZ2/oBNX4iGNNuhZNvLTZxVt1GH0zLQ45zwZTbwWkR0DSjDTyUJWO6qr
         MGbV+Nhj4mp3rYd8eLbq6ub5YNJO+w4aAj3eUGDDoEIA5RZYq0AMLLpabh1bB0kcYZGf
         lakwgV6w3yXXAh9fZeIBs7Uxa6QN17kh+7uQ7mEBGdgUt/qJ/WMq/BkKSXzsdrfXcPNQ
         lA9GQQwTds3QZVbKPsVYME6ZVhkNmGqoBXIk/SYEvRukOVmj9cJPRa6AOt5t0zHWVhWW
         8T0Mpu6bK6/Iuvo/wmMotivo1bomNdHXaQ8QCcN9EhATPGndBYbEfvJU91+Bu8xUmmDs
         81Pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NfvKLIEC;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244aca860asi6928855ab.3.2025.09.23.15.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 15:35:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 34F4144593;
	Tue, 23 Sep 2025 22:35:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68E0DC4CEF5;
	Tue, 23 Sep 2025 22:35:09 +0000 (UTC)
Date: Tue, 23 Sep 2025 16:35:07 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH v6 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <aNMgm33W7gh75h3t@kbusch-mbp>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
 <aM1_9cS_LGl4GFC5@kbusch-mbp>
 <20250920155352.GH10800@unreal>
 <aM9LH6WSeOPGeleY@kbusch-mbp>
 <20250923170936.GA2614310@nvidia.com>
 <aNLnXwAJveHIqfz0@kbusch-mbp>
 <20250923222216.GC2617119@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250923222216.GC2617119@nvidia.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NfvKLIEC;       spf=pass
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

On Tue, Sep 23, 2025 at 07:22:16PM -0300, Jason Gunthorpe wrote:
> Very rare is a different perspective, I mis-thought it was happening
> reproducible all the time..

Yes, sorry for the false alarm. I think we got unlucky and hit it on one
of the first boots from testing linux-next, so knee-jerk reaction was to
suspect the new code that showed up in the stack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNMgm33W7gh75h3t%40kbusch-mbp.
