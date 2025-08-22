Return-Path: <kasan-dev+bncBDZMFEH3WYFBBN4SULCQMGQE2UWUKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF3EDB31DC6
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:14:01 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-3234811cab3sf2514449a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:14:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755875640; cv=pass;
        d=google.com; s=arc-20240605;
        b=ArHm2MaowLYxAKU66fj9o5SCPGiE5acJQQg4nc88iEevm2pP5dUZWLuAbPLHsVOxtu
         4RWJJRbdNr+DckjaNFEgLrlnyHHSGQ2927/JDP6werC3GtihGw6V+ZoIXEbhHSrCVY/S
         RYeWi4Ve0atOLOBFtxzUVgTQkrIw2OqRTBdb5/BfMC2g/6mKn+241aVi2Gwv1d5oSiay
         PJMnqQCnpJqwXyO0SfQiytPSKtElwfr8pK2ruB3k8WVwzIHSiPvqdKbA7zGh+RikKL6j
         EPLDAYVuNngKH57158OwYNZ5E/fwf+dHVmuBEXn2ojo4tZhFTD3LTrGxiniSUuTQ5XbY
         pBoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/C9fd9eoiZdweABtSuSbozoTuCoVVrjF8SqQHnyuryQ=;
        fh=VZY1Fq15WQOpQxVz8TB8rBTVS3GD/IbOc/wr+YFNCvc=;
        b=ex9yz0ANE5gMCt+GUvawVHfuMP5iKJpt85ADyTwF0BT3W6ItFRPcy1KsbMRg1kXqV+
         9hFX49m1um02cuiqWXGX03YKg4kTtEXmqBvBKhFzY+uuI6+v4kBVCLOfec+4rNdtKF4/
         J0Q4cOlYr5/YD2SdU0DGsqZ9aZwv1geh5MT/miP+xYQ7AG3+FBJiKgzI1j/3aJvwz4NM
         bBW/CJ+qZXrr8Rr0mlQb+Dt0RZQfLFlSbwcyyfAjxNnb54hBUqidBQ7TvLfCJ87uv9Yk
         5X5UTLpMIxBe3nASC25aut9kpfP/NRscbbGZKbr3fIaK/kNCwjZMwGeyBoNZMFx9PvUE
         VQfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Oq+YiBtz;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755875640; x=1756480440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/C9fd9eoiZdweABtSuSbozoTuCoVVrjF8SqQHnyuryQ=;
        b=MHg5Z+f4MkBowUtm1C2q2t2zGTfTkJdUPD8eXNQ8iVQ+rndYszNWcTYO2nLs92MdVa
         Ss+cfoeE8rmBuSmpQsORAT2tT6C5Li32oLpPunp4hFNZAndlLsFFYfatz23bGAi6x/3I
         mYFUTD+AYI8vNhKXqtXdPOYG+NYz1nc8LGPMKOfq2asq+yG5eCqhHl4yOmS+yaghBQGA
         0R0QN/qPNQN27nL5xasarpMo4Xuf51LjX1KjDEFhV5GXvAjpE2H83PQUhzarHZcXTarp
         YdLfWWQGJhXozR9QYcYWUZhr0RhD+74uyuUcrmBqYKmx+FqjkLLZj0MyslbHS9NPWzF5
         wpEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755875640; x=1756480440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/C9fd9eoiZdweABtSuSbozoTuCoVVrjF8SqQHnyuryQ=;
        b=g1RqSOnf/aPdEdhl0N6td6/JR5aQtgKLWwF9C9tEA/wsxegLCypGMrE1mnRIpispA6
         lLs0VDYPT2jRiCGEa4K5PMa+MY/KHpwzgoGfhk37iy04ji9UGO7t17iL+sjWuzPSt7Jq
         kRfuYktlH/Fs3lo33o9yvNSgePnm3PK8H3ii9R28dvx5b8wj7CWluqmG15kiobtF+sxO
         cbmnd3UgsJYwY44obQwP/lfNAkow1laEWvbBu1o97vAh27OHKu3yr7AaxheqpL8acCm/
         AgIaO/4YwAWAAZ65bOufbKQ7lmFIQiX/dwptoFeT8zFVyH5HjgOlzdyZQ4tFt0yjYHvT
         PYUg==
X-Forwarded-Encrypted: i=2; AJvYcCVuoSPA+e8oYQKiXv8shn3VrUxG3ZDP8aTiP2TrehfCOo+/Gi8qS5Wq6g+8s2ebguHnfRz3iw==@lfdr.de
X-Gm-Message-State: AOJu0Ywg9wvVBDbu1vxVL9hJV2Jub1pyZkjNFwRe4SGrT+uHh0GMs5A/
	eQTu4GKfKR6ZhlPDbk1y/Jw5TMNOLXiSJI8v87u83kYoIfWu+IQBRP1f
X-Google-Smtp-Source: AGHT+IESK/OKRgEzkCG7H1hZN9Mb8howGGOzNK5kJUVUgJtMtSTaWPRvbML4FzkfhsAJNJXds3bMgA==
X-Received: by 2002:a17:90b:2e48:b0:321:160f:3349 with SMTP id 98e67ed59e1d1-3251744c8d4mr5083269a91.21.1755875639746;
        Fri, 22 Aug 2025 08:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeddOBRO5jnOqk4c6h8Uu68Wmg0eCoV4yg5yEIb8/PGLQ==
Received: by 2002:a17:90a:1589:b0:31f:7cc:aa74 with SMTP id
 98e67ed59e1d1-324eb8538fdls1697484a91.2.-pod-prod-02-us; Fri, 22 Aug 2025
 08:13:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6RcSaoZiKUh02VJdHauthiicfRu8s901FVMraTubYpqhf7Tlqujm2IWW3p0KxIH42LBVGtQCRBDw=@googlegroups.com
X-Received: by 2002:a05:6a20:3ca1:b0:240:1d13:cc9c with SMTP id adf61e73a8af0-24340d7bab7mr5139581637.31.1755875638007;
        Fri, 22 Aug 2025 08:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755875637; cv=none;
        d=google.com; s=arc-20240605;
        b=ClOkocBnXRC12EJ+9ui/DUIWqoDGlX6OI6fdllWYeZ3alSCgbCP8CYsD/GCR185Y2w
         rLtB2AkMIlg5+u60RlsHf/Dx5njHgodiRbrfghNAHorRVME3+Wla/4h1O0LFpvxzbqFy
         sV48oLpSJwf14CXWrSKH6fW+Ac3vPTTI3NvW3Oy7zHpnt3a7uFKYnIe9qzcd500BuiOK
         pFQXSk59HV8D9fqTlaIgRs65y1YkHushzKWezSs6EGsNADJ1xNSn494cB8J1cnkPuJc/
         VwHVDq0EwhV44Dy1PTSZpaSCDzkNajmmWNdNPaT9/jNyUbGr2+MhTDCSnaan8bEywKJt
         4znw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=L7qMagALD0IoFhMlbtYj3vAqhjRthxO08VDRkg86DzE=;
        fh=PB069WnjKc05Jfqe6XQmsl5b5Etj5tUlknoldBMFEc4=;
        b=Nxb9BukHIatEnH4qbTry08hOXzZZUkdmwwPM+w1GtryL2jhG0VbA8mRvxIepyc/mVl
         Exh1Ybj+a62N2VcK5gqbivBRuDz5knN2q088lEEIw1872/m1tQGrE/XZNs/fFq6zzzhv
         xX9oKmEgJtPCsSkUa6Yz957BmXHqKijSKLw0eGOSJJf+VR4hxrZiTx+z5WkBGJlao1EW
         pG17PS7Tr29H+gtW5UNKml87GM7OMSkSLiPoydQqBUNKBpbNGhO27M/ZU1N9+eBReXrx
         yreA17PHEXu+OB6ed1XweuXME/FQMVPAQlHfSEBEC5m67biC76yuuOur8peQrJ2K1JvR
         F7AQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Oq+YiBtz;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b49cb8b9b1fsi6460a12.2.2025.08.22.08.13.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DBD4344F53;
	Fri, 22 Aug 2025 15:13:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4A19C4CEED;
	Fri, 22 Aug 2025 15:13:42 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:13:39 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Shuah Khan <shuah@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 05/35] wireguard: selftests: remove
 CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Message-ID: <aKiJI0jiFEjtLE3l@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-6-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-6-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Oq+YiBtz;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Aug 21, 2025 at 10:06:31PM +0200, David Hildenbrand wrote:
> It's no longer user-selectable (and the default was already "y"), so
> let's just drop it.

and it should not matter for wireguard selftest anyway
> 
> Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> Cc: Shuah Khan <shuah@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
> index 0a5381717e9f4..1149289f4b30f 100644
> --- a/tools/testing/selftests/wireguard/qemu/kernel.config
> +++ b/tools/testing/selftests/wireguard/qemu/kernel.config
> @@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
>  CONFIG_FUTEX=y
>  CONFIG_SHMEM=y
>  CONFIG_SLUB=y
> -CONFIG_SPARSEMEM_VMEMMAP=y
>  CONFIG_SMP=y
>  CONFIG_SCHED_SMT=y
>  CONFIG_SCHED_MC=y
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiJI0jiFEjtLE3l%40kernel.org.
