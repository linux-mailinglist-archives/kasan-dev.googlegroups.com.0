Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBEUEQLDAMGQEX7EUQZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EDB0B50679
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 21:37:56 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-319c9bb72e1sf9137455fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 12:37:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757446675; cv=pass;
        d=google.com; s=arc-20240605;
        b=bjYUz6/E+mow7ZMLgrfZnsalXoHNAv3+shkYuG307uo2Mmd3A7t/LonwM1VDWx3TIS
         0iBI/OJD0yfI+8PjCjK6OxOQcD3/1zHh7UG1VT81m2QQ2IWiZ/icp8LVLNiCCdGXfvqF
         Hf4kdm8FIA07jNuPE6eDYDd3xr4itZv+od2gy3vCtHHl2YwZExquXS/zBCfmZl4dOWx9
         /BT1WsubpxDBQMi4nUi6GvwGhM31QtJqMhu3LdFUt/jN2IoOu3/UJNyuhG34iITqUz7G
         UAZc0z7l9QVMqrVsSv/bsjGpjexqzZGaRZvOjZUtKCR+HdWSmc3B7QI5foKpkrbXTNwp
         Y13Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Z2YiKcvdE7ulEuk0o8cnWtWOgPPG9OTqvF+s/VhPHSQ=;
        fh=osXSRSOAuSv2AWkP7wCvlZl9831zQEZ9EJsc+tR5pB0=;
        b=HMldHtknODjbEpnQn1Uk7bYIyOIQolQ0HxInoqqehD6HXvh/Yw4XJUk45CTHUCrg5h
         yotEGMY8BZXaZ1caLNZB8K0QekRhRtmSZqz3A6HTWSPKbMVxOiRi3yWSdVzTgQvKt0Pk
         0DjSXy4Ae6oBmRGFaeQaR+GqU705E9g3AmkMFjQGz0yNzIA95i0ZpAaQrbe14jUYTwmj
         5ryfwYYBC7onCH06+aMFNxcipjHiUJwAooZuF+7/e3d9FIJ5/P4dnrUkH3FSqWzjM9Vl
         GDGkGNy2CMInNczblTFDnHBNpGCsv65jyqUznv5tntCo3SqOFQfWNYa99vqaQjJq+fiu
         sknQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BK33sGpV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757446675; x=1758051475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Z2YiKcvdE7ulEuk0o8cnWtWOgPPG9OTqvF+s/VhPHSQ=;
        b=BfI6mLaGDsYZr+7E1xoIfTeJohmAlqKb/tm/u42jGXRcZQsqe58orhojdP/v8hgBCk
         YAXHx4YqRTQBfG+N4rrN5CKhokJd3w69A3RdadE0kYTB64hgn6SE4MLWD/5JMM3qOiIl
         Kyr3Dunh+Xs0uHQ+iFblmnBHWIo2eKBscSqAFeBenxecK036cxdGOkCqOTOCTnZPOg0I
         ydNTqVwlmjX/JCodKrD2+dQxLoH3hrQt9ECxdtSzT98Kpm1ZmcpwwNOGDBwQGF7Y7Phs
         ZxWmu8U4VDWvqkzm5i0YqIzyXfMamd42tuvCHjoac135tPDjjnuhITsktYyys7YHVHWy
         4GAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757446675; x=1758051475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z2YiKcvdE7ulEuk0o8cnWtWOgPPG9OTqvF+s/VhPHSQ=;
        b=lGby27SZ3rTYoANvM+3wTLaJqMYn0PlfOkeWkrnJ3K7rHuKBK9OyNhh0s0fB9MkLhT
         Fih0rZO+yswCpnssNqbnSnb4AxuJYXq3bm+uwDhJk+0rQh3xPPlYJZCh9pVx9E+GnzQy
         q6ixy0a+JTgHYvzDYpAMbQu9DhjgJ7D3hyP+0O7voF2Avy5Qaiel6yB2/nV1+M9cJuFh
         NTftwixbY22m1cicNbO0+2nat0qWm7rZ08e2g6Xu7yvHZMl3EJdQk5VM+gjIedJAq4Re
         aPHLFNpSLgOV3lqmFX1+uPOxrlFrBjRQIIavOU28pBEHDPbgZL+T0gqHajaEjE50/7Io
         rz2Q==
X-Forwarded-Encrypted: i=2; AJvYcCW6fi3/dTEYi6eIdfK90LskH2p53+3cJkNPOv1koLr+q9n85jFpj9WgIj83h/vxmtn/3AIwvw==@lfdr.de
X-Gm-Message-State: AOJu0YzuOMToPNreFNpKpfWqC5b9GeHLN0SDRZD4utIcXO4tidzIiPyR
	U994MUp0qGZKtFej7C+XDCrT1B6BkHCml7lhg/PMU8htEWTsGHghUeB/
X-Google-Smtp-Source: AGHT+IHLonGtdRBRyZtQH6CCJnqJYN0C1f3Himg3yq4mnUuL5b9mWjXNDYExtpt3PIBmLolk9NiaPA==
X-Received: by 2002:a05:6870:40c8:b0:315:91a3:2fb7 with SMTP id 586e51a60fabf-32264d183bbmr6824293fac.35.1757446675166;
        Tue, 09 Sep 2025 12:37:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZciYR7YqEHO7c7b2NkEZTgRt4WNbHCpCtNkzh00tin+2A==
Received: by 2002:a05:6871:181:10b0:31d:642d:3aab with SMTP id
 586e51a60fabf-32126e748f7ls2125722fac.0.-pod-prod-08-us; Tue, 09 Sep 2025
 12:37:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbUwgsvL974TGfbmOMa5YW2hr+QFjObcTRLU5NfyJZ3RQvag3RRmOhaZSQgnnpypYWJpK7wwf8EyA=@googlegroups.com
X-Received: by 2002:a05:6870:f6a5:b0:30b:abf6:637b with SMTP id 586e51a60fabf-32264c20bb6mr6113562fac.37.1757446673805;
        Tue, 09 Sep 2025 12:37:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757446673; cv=none;
        d=google.com; s=arc-20240605;
        b=UCyAHVGHz0kISEWEi2T/EEwNch1KrLtIi77YvY4GN4W36VzqnuZtUz5JmT6t4ZFdsy
         y3rRR+emGfdTQ896xgLti0tDKCIMqVGL7XxAUa7UksQdH0uIbVq3NEyayN5C8bjeXSnU
         AkZ+507kzA3GVPHbZOc2EjXD1jKrcpI+/9tEybeNi5UEIv0w95h8UiLKHgEYVTmva7Wv
         Nt4e/xdU7zWeBwp2/SFdFZoT//4syZJp5vhxzxAKRzNtwB09Zmk22FZap+zjzfyVmqP2
         w0wLPOerzvA8hw57Uc4wREv99fiX3T/IQ5Xx4JyCuPDuAFPIHoqM9++Gmg4pT/P6Tz/p
         cc5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zMm2NBLKPbhkgjTIqBzOjplNw/nP7kHLNg99irSoOEk=;
        fh=0KZfjkVFrBJ1A8P/k5PTY2PAUr+/l0FquzWeYmXM7tg=;
        b=f7adDT/g9MVKt7zaNEe731wexTsnCCe1pjRxnpaVHeGrlBGORbrj5mcgddMio4ERw8
         GH84bk6exnhi4diGnx51oB4ac0V/mjhKc/EWdplbsOgVbZOt+EvS2XFOnFZWkW29+nQA
         W2ficLGRaxjcBux4ml1rILP2Rv9NHeDorgnnbB4VPMjhbTR/3g+i9Nv8AkrUDuHS5lJq
         6Cj+FtneMxCj7I0zzB6qUkznndLvUzTi+uSUNjrC6NBvO+91rYbrileHhtuTUDbYxNrN
         cO2IfI+dOMUIpWRHdB7ZptzES4B1m4uh7C2o8Gdw5EUaxLudbgrZ4ALkfqBslWYi6BTW
         gU/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BK33sGpV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-327d52e98d7si287704fac.5.2025.09.09.12.37.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 12:37:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0F194442F8;
	Tue,  9 Sep 2025 19:37:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30BB1C4CEF4;
	Tue,  9 Sep 2025 19:37:52 +0000 (UTC)
Date: Tue, 9 Sep 2025 22:37:48 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>, linux-block@vger.kernel.org,
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
Subject: Re: [PATCH v6 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250909193748.GG341237@unreal>
References: <cover.1757423202.git.leonro@nvidia.com>
 <56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BK33sGpV;       spf=pass
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

On Tue, Sep 09, 2025 at 04:27:31PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>

<...>

>  include/linux/page-flags.h         |  1 +

<...>

> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -614,6 +614,7 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
>   * available at this point.
>   */
>  #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
> +#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))

This was a not so great idea to add PhysHighMem() because of "else"
below which unfolds to maze of macros and automatically generated
functions with "static inline int Page##uname ..." signature.

>  #define folio_test_highmem(__f)	is_highmem_idx(folio_zonenum(__f))
>  #else
>  PAGEFLAG_FALSE(HighMem, highmem)

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250909193748.GG341237%40unreal.
