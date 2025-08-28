Return-Path: <kasan-dev+bncBD4YBRE7WQBBBXUFYDCQMGQEWGMOL3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 35BC1B394DB
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:18:56 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45b7c4c738csf590715e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:18:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756365535; cv=pass;
        d=google.com; s=arc-20240605;
        b=jVzgIT8cHVJxHJr/QTBnbbLg1FKtCo8IfBjFj5rSajirz1FnRvXpnys3be0+jgun/B
         Dd0lNh5/7IWKdNG2zgR+2xhyVlm82zP5+g5AiZ5gksg6MopvhkAidu/wJ+RbL5aWwnYM
         DbRfZKqDQ7KfnXjLiZ7lq8xUVAVq430TEZNp4X9ZNwbegWmdYZv58ed4StAl9yLf4drj
         tw9dKPKxhjGSVXW0UFHixe8diEocmS8x1ckt3M8ucqNhEvlh9ttJY4kuraR/TlHDy0O/
         NWY4d2GOBvqQcdZ/kQ0t4u62+lrHzRLQyH3FKqsVyWY7dTDOYzsUAfijaAJUfQQbHd8I
         p4Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=Mjg5YQoqGkYP8bejCPD+8Yh8eQCXz6odLCbDy7scIsk=;
        fh=3MhidjmkDKR5giOFXB1HJuUMlkVcCQI1AY/BuZ7PCdI=;
        b=KRDFQiSEFxWauV/i5Jz8yHiX2EPpLynqwBOv68Cl1+FmnG1MF7bPLFzLwB0BFmEb4Q
         fOQ6/2T9LtjZ8E1L/eb/Nl6LaF8WYLncK7rCnB8U7YG8IQKHIBEy+liYZ6yHT3sKxg6R
         MuaUXqfz6icFqNnuSsdM5z6JlQtdLwT5Kxd5Ut2XC4V515bPuNQfgRtX3IK1zAWn+4+/
         1NjD7uup81SLyxn0qnR5j4ufbqgu9WM7m+Ha46/ZzTHdyLM2/4x7xC7lbnwI8xz0Sdkz
         fKBejPf3XaEMG1Lo9h+33gH/v/AurOzZICTPeCsAsuY23krNOvFyMETXyNDcTxfP82AU
         Ye+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQQtJH7L;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756365535; x=1756970335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mjg5YQoqGkYP8bejCPD+8Yh8eQCXz6odLCbDy7scIsk=;
        b=E+mGr8RCNM4cUd2LErP5ijfh6Y6tCwwGx+qugidZNIPMuAFbspV55d3+bW5rvpPpJ7
         FyvxlCUzr8BrhYmFtbSxPNFDzvEQQ3LoRS2in2PsrxOgPLxaQCjIOqKgwGYiVfdIVS48
         xq13pGERWxjBdxzsEN+M07F552WkRzH/ENRVhiHj+y807vgRuENSkiEUlbPt/tViVH/j
         S41Ch7I/rRIWNAVAMO1tipNNre8c1jAd6BFo4nOD+2y5tLZ32lHusPe6Eig2GqWRdbFk
         OEoPSqFqZpxBFRUJitn89aeKSTgvLZB4WZ1lIULJd72aGZeh+CvxEaYubOLGobRQ+XIO
         KaUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756365535; x=1756970335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Mjg5YQoqGkYP8bejCPD+8Yh8eQCXz6odLCbDy7scIsk=;
        b=l2aQGQR7bGaQmyHtubKP9HV6rM/NBlFplbBixfItrtnEy97JsVo29+lQ4skdClOqoq
         I7ZJMz0uj3mfVoccxhfN+y1RwARZGHDnjMEKq0fpMZgLd2mUZ+EUsnF4ZXLz4duHUAl9
         yxzkv2Wn2/Ps9rExoKIpXx3OpJ4lc6bzsStsKnKxsulb9Wb2D4VH1ztaoS2WcfpQmix2
         8ERU04gibamtIugbtUr4tLUI4px2d+eI4ihCbtsnHZTdRA7oEclLEF7Rzk9Y+36gkDBr
         Ke+zpa6EfzOiBSbzEhQmJ7decKP9BptF8QRFfrNiEIXYObjcJ+p11hqIrgWh/+aFMyvG
         7f/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756365535; x=1756970335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mjg5YQoqGkYP8bejCPD+8Yh8eQCXz6odLCbDy7scIsk=;
        b=CI+iKk8To9TEaaXVqlu9fal3xuLRfDN14H/gWHN0GhL7GpS+hUwjZsxNbcjL1hOiml
         6v24u4q6PExCTEKcW+PHUWsJDNuuXzfIafWkUZXG58VnIOpWXvFo7FrH2ZsbPMiVlMpi
         aPe5EW/126sJLaQKmuJnCsLVeYIYd6o60p7awGx6eZfmqNFu5axX5gTw9Jp68zeQtnCR
         o0WgDpEyX9+3VdQ1uqVu+obixyrbUY/KvJpMKjzYDZSbC27OiFeXlgpFY21VJ2VlgKJY
         2ARmKi3ijUfCIrkttDt/chHajTFHNVvGswghyhqJ9jA3Pw4vidi1vmsHuXO255s6D/On
         weLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxFRh6bnk+wzWiZf4sxNL8FNZO2xm2Em44qFdX/VnUkSAkptQF+Lq6VcirYXfDFvzIqGCC6w==@lfdr.de
X-Gm-Message-State: AOJu0YycYC9ilx5YHGWV5UxtH+ddsR7D5Qfa58uJUUuW57M7u4qxFDZw
	4y03acqcC/O/C6uf1tAsFnY665haHn/TNN5qeOGGXX/NgB5iN9V5Naz5
X-Google-Smtp-Source: AGHT+IGAUyOmYs7c04tpcdOjwPR85QubQor1CGeQnhqIAiCrDHgJar35RZeHvtw/g7d+1dv/fkRNuA==
X-Received: by 2002:a05:600c:350e:b0:456:29da:bb25 with SMTP id 5b1f17b1804b1-45b517b962bmr184760115e9.19.1756365535087;
        Thu, 28 Aug 2025 00:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfA6bO3vINVSlRDEWKN85vVoBzUUmmxRH6a7MS31LHRgQ==
Received: by 2002:a05:600c:8b64:b0:45b:60b6:2966 with SMTP id
 5b1f17b1804b1-45b78cb88a6ls2256295e9.2.-pod-prod-03-eu; Thu, 28 Aug 2025
 00:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0DY/IZm71uj8kDXakGbspkD7CT2sho2+aQ0azYGbKM8fmx9wYSTLZmuURsmkbkg2WE8l47LeaNak=@googlegroups.com
X-Received: by 2002:a05:600c:3b1e:b0:45b:7a21:9e96 with SMTP id 5b1f17b1804b1-45b7a21a19fmr10954025e9.37.1756365532303;
        Thu, 28 Aug 2025 00:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756365532; cv=none;
        d=google.com; s=arc-20240605;
        b=QYgzgtmCf642CKBmwDTpYLtV1nyupX5ZfwpvN3jZIPUn0B8bDWmQLB3OkHMNPuukQA
         HOe3qE1O8G7txk0kXottNlRfEH/GnFrDgH/mUpNb0APnzASBwWaVVyaC4SdmeaIMnkGB
         Ckmq4GoPXKrMX0ctJd8K0UsPjpIyrBQ9UG5NLiRsQzVjjohxR0cbUbkkzrZjNeMQQKQT
         JIPTFOsfdocLE31wDpifI+UqKmoj3lQaSLab7GathuUDGQEAjYYbBIIY6iqWLkq2c2qH
         /pqYbYw+BWPF4TlvABYChq1u4BGgusdV+3GZIGL+htCVuxjj1VlpgOOW1dwIqopA6ViA
         iyRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ACPidqQG6DQZNVxh12NaJPKP3Jkf06hyqyPjQ1p5F2E=;
        fh=0uebTO2tmFz+7zRwJwa8CYL6gU1KT8lhPHvTGSB4L8w=;
        b=KB6EB+PgTTzxc6I8v8zV32YrYZ0swY0tHUeLJLhPkodsD8bErTGN3NzBJRHigy0Mao
         HVHH9Yi4FmuCt4QlGb94wI20fO82i0Due1F4a7qh07LaB0HmkDg/a77N+xdrD5P2XsTg
         sTVeDlNoOhLF+0Q2fM/r/9GmfCYqC1FNatNT6gLfwQEWQHHHCRAYO74hcXwpRz3FCTAt
         r4TZxlwI6g7s+7DjW261Epx8fx3ALv+YKD7+/t6y/y0lXU0rTg1Jqpb/4XG2PgQsCb9x
         INe/fOCldV4KZL70nwCmtEmWzmuFkdawW2jrPEhURbyE4NGKO4aAGtYDWAZaYbVFLge4
         jIcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQQtJH7L;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b7554915fsi621145e9.1.2025.08.28.00.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-afe9f6caf9eso87483966b.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZGMs7dajH2g46s1+S4AkSbwdlGZ74Vtzs45DDUVsHdYYUe1SB+yVj8e/HVYhSWp8h0HtFufjRd00=@googlegroups.com
X-Gm-Gg: ASbGncsWCDw+0TYnxUqZSJwuprEUrjjreVuypchAPO1uBwuoTYj1s0Vjr/lb4sKYmEd
	2l68rT3X1LBm/2wzVB/cC2yOuNCl1hEcs+mfXk1UtCYO4Zf680nVcT6mdcdlzRGBdf05kvr8Uxc
	mBWyAfTqappENvAGUWIh98qYGKgGEDrV4i7XRHoEDl4tDxKGtSWoVG0HfsQHkN3GNNSrgk2PcOd
	SL8FeMIQGZMBz7PA6lEnm9MA6beAXnnT3sGX/nyhXysktGxoWGNj8ejV+scPL9U0Ln5ih2/fi7J
	FDcULlBX1ehYtaPJsOOKh94Xd1WsHh3lp9gO50F0d926mIEKkpc+KVVF0l23tpyq7f67g43ogr6
	JPmq+Kxo9HDG71Rya8qlhYXwMGoDdwDMEspzR
X-Received: by 2002:a17:907:d2a:b0:afe:dbfb:b10e with SMTP id a640c23a62f3a-afedbfbb935mr140730666b.47.1756365531421;
        Thu, 28 Aug 2025 00:18:51 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-afe98ade972sm616427066b.50.2025.08.28.00.18.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:18:50 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:18:50 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	SeongJae Park <sj@kernel.org>, Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>,
	"David S. Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
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
	wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 01/36] mm: stop making SPARSEMEM_VMEMMAP
 user-selectable
Message-ID: <20250828071850.kl7clyh6e75horlk@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-2-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-2-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GQQtJH7L;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 28, 2025 at 12:01:05AM +0200, David Hildenbrand wrote:
>In an ideal world, we wouldn't have to deal with SPARSEMEM without
>SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
>considered too costly and consequently not supported.
>
>However, if an architecture does support SPARSEMEM with
>SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
>like we already do for arm64, s390 and x86.
>
>So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
>SPARSEMEM_VMEMMAP.
>
>This implies that the option to not use SPARSEMEM_VMEMMAP will now be
>gone for loongarch, powerpc, riscv and sparc. All architectures only
>enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
>be a big downside to using the VMEMMAP (quite the contrary).
>
>This is a preparation for not supporting
>
>(1) folio sizes that exceed a single memory section
>(2) CMA allocations of non-contiguous page ranges
>
>in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
>want to limit possible impact as much as possible (e.g., gigantic hugetlb
>page allocations suddenly fails).
>
>Acked-by: Zi Yan <ziy@nvidia.com>
>Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
>Acked-by: SeongJae Park <sj@kernel.org>
>Cc: Huacai Chen <chenhuacai@kernel.org>
>Cc: WANG Xuerui <kernel@xen0n.name>
>Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
>Cc: Michael Ellerman <mpe@ellerman.id.au>
>Cc: Nicholas Piggin <npiggin@gmail.com>
>Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
>Cc: Paul Walmsley <paul.walmsley@sifive.com>
>Cc: Palmer Dabbelt <palmer@dabbelt.com>
>Cc: Albert Ou <aou@eecs.berkeley.edu>
>Cc: Alexandre Ghiti <alex@ghiti.fr>
>Cc: "David S. Miller" <davem@davemloft.net>
>Cc: Andreas Larsson <andreas@gaisler.com>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

>---
> mm/Kconfig | 3 +--
> 1 file changed, 1 insertion(+), 2 deletions(-)
>
>diff --git a/mm/Kconfig b/mm/Kconfig
>index 4108bcd967848..330d0e698ef96 100644
>--- a/mm/Kconfig
>+++ b/mm/Kconfig
>@@ -439,9 +439,8 @@ config SPARSEMEM_VMEMMAP_ENABLE
> 	bool
> 
> config SPARSEMEM_VMEMMAP
>-	bool "Sparse Memory virtual memmap"
>+	def_bool y
> 	depends on SPARSEMEM && SPARSEMEM_VMEMMAP_ENABLE
>-	default y
> 	help
> 	  SPARSEMEM_VMEMMAP uses a virtually mapped memmap to optimise
> 	  pfn_to_page and page_to_pfn operations.  This is the most
>-- 
>2.50.1
>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828071850.kl7clyh6e75horlk%40master.
