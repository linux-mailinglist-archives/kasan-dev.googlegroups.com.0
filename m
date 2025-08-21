Return-Path: <kasan-dev+bncBC32535MUICBB6PYTXCQMGQEJJOW4UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B518B30364
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:23 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3250810462fsf499866a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806841; cv=pass;
        d=google.com; s=arc-20240605;
        b=AXyWaUIOYEBGP1lTXZCTAScxuW0GpSOYVInfUo8PWHUc7D22ag8OSgkMpt/0/ynExV
         H+2evC6UKp19ibnGjOjcdwjrmUFesRb/lwuJPcsh9lItCeVpZNpN2RBFD+D2aylP+XZa
         atV3+iInkeDNhIycZ5uSTw4h9Se5mwtcaCYn0fBJzmNtxyPJyVMnKWuRIXptGLpPz30a
         8nO63U5+Do2lRdOu9ybf1vC1XgkGbsF63gzlcH00ukm1LdJPqXOL5Q2WwIPK+yLcHXCA
         Q72EhDDc37arh/eGyKGh9zXPuC3Ou7OU4yG8Sa5+Pt1HNHkxT623hwrdCF58vpckuqfC
         VPQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4fMxh+mA+5VcIP+eOPz0Yu8oVzD7EyNtUC+d/srwuP0=;
        fh=mV9K0964r8ys9Hny2eMGk2B7e0FF3n11O/wAfDid/rQ=;
        b=K/fa76s3nEzbjaZYq/q4Dz5vEH57Pjq0J/uNvKscvcrRSuq0a2e/EQ7luwy6pAXILs
         iffqszvdQBRvD0QBa4QQiKNFWxQsRAsMyveoL9UoyhsXJcwuimKm+1dXzTGcmxnOa6Mg
         jXzqPiASqmldfhqkoyqZ5dAC3bbMqdfx3ViJOe62S4c9JjFqcXhE5KUj01ZbRmxpsMLu
         EwpTSXB22UIEhQTmwHeS43vVQt+ha+8HY7z7SrMUOh9BNmWnspM6s8bA+wQGOSQEVdza
         WCvomUDxIRloSSKGsHhaG00lC3ClihU+N2fT8bmmJtMBbdXac3VcU+68qYAO6GSiNfin
         f+8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YpZB5gOl;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806841; x=1756411641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4fMxh+mA+5VcIP+eOPz0Yu8oVzD7EyNtUC+d/srwuP0=;
        b=peIkOzTC/EGok5kjywYn4Qa2oBjVp6WKtUZqroM5VXrHLVhdC+kvydV1EAWT5jXjPu
         w3ns4VX7l897thV9AaEo9GAVpzOYdhHr0Qv1WSWY+ECaI3jKCNTlLoJj7BAX2XZCQv8f
         TGSQBcX9VyPoywmefh1zOTmALd5G62m5WYBvPZAYW/zG1Dec+e+HRnvmVPKxH7utxAQt
         L5rgNuKu3qA8MmBVi4PWa4/yeAYTxzCBAKrxIZs1EevwibigC2Dte5e/0+lXgCcHJSHd
         cVLUi6kZAv0JdoB5kMTQ4DFpKWhJl7u8hmk/M+glXfX2s6VqXCfG9bqyTFourQmScN91
         zXNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806841; x=1756411641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4fMxh+mA+5VcIP+eOPz0Yu8oVzD7EyNtUC+d/srwuP0=;
        b=rqHTnFxMcLMJXNjxpJGyjrg/o5q0OPSO2T/IljCq0PQ9ZI32dLwVx9JSlMB3ZZwg05
         0WCfyHtrlEzsPOoUD/zrE8/J9WH0iB7CDQBp08zcOP5B3O/wR7vSjOytm5ZhvbRhU9qM
         O/gz4xb8GkpD/Qnp7x6nO1AmlcsvhBYnZF5fhQhj2+9iqB68hOgIcB8m6dKh7YQs4xre
         uE0VGUVNYgCzRtuescSUSMnP3/9G5gHPBTNDE6VLQvhTIAxIoruVrQI/Lir1FNULSf/E
         OkH7fo1k1wcDZDQQ3mF8WLC83C9bgTYCWnxKDfKiNw/a5uW04vQj6+4TPyWj5K9qe+Eg
         i/Og==
X-Forwarded-Encrypted: i=2; AJvYcCXS3wzpMfFGTIXZrHtiTYEgWvsHmSeriPYlCbk704eponQx+LKxMUujhxn2OGafIy3dHntuBw==@lfdr.de
X-Gm-Message-State: AOJu0YzotlXv7O0/XLkXyJxOWBbyhWw/Fu+RMJ8poe83KZl7i3TwYB79
	yNOca6jK6nNDdQE3BEwCKzMoxHsQYrR3BrgpM3YW28CtiqxkHlsYPIgh
X-Google-Smtp-Source: AGHT+IHrj9YNphMkGxYpluFJ3crFa3Ac+BhEhpwPPmCvANvIiLVYUV7fEvLDym0JHTorvJUDrLdSkg==
X-Received: by 2002:a17:90b:1d91:b0:321:59e7:c5c5 with SMTP id 98e67ed59e1d1-325177426fcmr742896a91.27.1755806841377;
        Thu, 21 Aug 2025 13:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeazl29GFMG86eB5K7AjnyRXznEcw0ZG4xzc62uai6jLQ==
Received: by 2002:a17:90b:2d8b:b0:324:e3a0:46ad with SMTP id
 98e67ed59e1d1-324eb7e56dels1545161a91.1.-pod-prod-04-us; Thu, 21 Aug 2025
 13:07:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZ79Su55Z4r5Jr2ktcSxoy2kRZo9JdxbN1YEsPRO7C74Jfxshbh5pcfIlRd+Xl0O/Ip4PEUpY/T9c=@googlegroups.com
X-Received: by 2002:a17:90b:4d07:b0:315:6f2b:ce53 with SMTP id 98e67ed59e1d1-325177426bamr673917a91.25.1755806839700;
        Thu, 21 Aug 2025 13:07:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806839; cv=none;
        d=google.com; s=arc-20240605;
        b=c+rwBJwOy7wgchQGT4e9NagK7Y+Iqy17Z81+3qt8gUYuZr/dsXIikS8Ega0VMvyvcs
         gG/VLVI/FgpVcnfuFS4GfLYv8skkb2f6bFN4f9kA3KJtW6QAdh2FLCpCuPty5+6Y6Bvk
         xYnOu4q+7JJj0WgrsQxuZp6JVdSqTlLj0+kWvugYGQD4Q6khoi5F34nLBclpwrNOlp7U
         MQfJmtsSNcy0ydj1MBKE257t1uGdHe9zWL+zjA8RPjADaisB82VkPwZwnBVRsA4OPszg
         hZu8waz/fQJfu2lUKYXXEP4XInuflz4jLTyH1Rnsyp0GkwM/d+T7hXGOLIw1ZsRrEE6g
         m8ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7sWLap5u4LkaWlbSo2T/W3JLtp2tuveUv2Z9sucaeo0=;
        fh=j9q6bJxU7f5YjUHBF9zUnGH6mL1xPeR7oG1cqvRQslM=;
        b=A2uzGvlug/nV4aS3XadzgHcCr3e5mhMyv77/zpVzr/Wha4b2rdCJK5udEZBNrF3ibJ
         IE7xJTbGkFY1kR9MVgHWSmHG9fx5OFkesOWaH6D+2NO8BLRhcYzxIZ4idvEV0qGJ/gOC
         d9v2izQte7fb8DvX8nVpv3WcQveXo0AF93EjRmYFEzHLjObxK7DjLuYglQLQWMFzPfDW
         M8crDJcLSEhZsiCn3zHTlMEPetm/CM+dvI9oalQLDJRBtnopIXqcTX4S8xyrsZCoyPid
         x5CYJBhTDWQT2T63ZvYngqXjhWqGe/IRqOh4CcgGEkOinr6m9ekUM/FCkvS0YTN6W9pP
         l5dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YpZB5gOl;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-325123dfd27si38975a91.1.2025.08.21.13.07.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-59-hNNvBNXuNz2vd_bZ7zIu9A-1; Thu, 21 Aug 2025 16:07:15 -0400
X-MC-Unique: hNNvBNXuNz2vd_bZ7zIu9A-1
X-Mimecast-MFC-AGG-ID: hNNvBNXuNz2vd_bZ7zIu9A_1755806833
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0b46bbso6492565e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUeNbHFljDfV08Y7JlQS2fJXJ2ueGWKRm2P6RiH3JCFOx49LTqRp8d5W4C+UJy8hKuoeFhQSA943k0=@googlegroups.com
X-Gm-Gg: ASbGncsOUQhHGEMXehEy2yaqEfMlC+xsj2j53HowSWnZe2aAg7Qe5U+1v1Op+DRypEn
	bKogZA+kDs3bMuHZsIjwuF8yzIpBi+YkrSvTawLmaR5YtnyCadSTOIeLzQeqOTR+Wk+3bTNu9ID
	arSD9M7ecqHkuzyqHVA8ZcLwCnu7HUxqfZ32sXZaZkLvM6WHgll1erT4TRAhuskhV4MRqymH2ZH
	N5OyRQ8bUIsnCLrUnXh3e2diZ4vc64pDihkDhgrf21NE69eFteZfbLqu/BYCSVV+jlP1ukg516t
	fo3hDrIEmo3xdZOJ0uDQOjbNm6z7g9HzT5xL4ozAHQvoAqPSdfi6bPu6ncVzXu4imo24enOOyrm
	ohpVylAH4NB0QJzybvBqW7g==
X-Received: by 2002:a05:600c:1d06:b0:455:ed48:144f with SMTP id 5b1f17b1804b1-45b5179669dmr2598205e9.14.1755806833342;
        Thu, 21 Aug 2025 13:07:13 -0700 (PDT)
X-Received: by 2002:a05:600c:1d06:b0:455:ed48:144f with SMTP id 5b1f17b1804b1-45b5179669dmr2597955e9.14.1755806832889;
        Thu, 21 Aug 2025 13:07:12 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c0771c166bsm12916801f8f.33.2025.08.21.13.07.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:11 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH RFC 02/35] arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 21 Aug 2025 22:06:28 +0200
Message-ID: <20250821200701.1329277-3-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 7aojyXLRf1QWYzL1-5Yk3H4K07qVNX045f3dsUTzxvs_1755806833
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YpZB5gOl;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
is selected.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/arm64/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e9bbfacc35a64..b1d1f2ff2493b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1570,7 +1570,6 @@ source "kernel/Kconfig.hz"
 config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_VMEMMAP_ENABLE
-	select SPARSEMEM_VMEMMAP
 
 config HW_PERF_EVENTS
 	def_bool y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-3-david%40redhat.com.
