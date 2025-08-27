Return-Path: <kasan-dev+bncBC32535MUICBBGUBX3CQMGQEFZDHKIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A3D41B38C03
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:03:08 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-246de620e6bsf14189275ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:03:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332187; cv=pass;
        d=google.com; s=arc-20240605;
        b=EKKxw/5WhxGoANrrXsNqck/OkvnDh6XtEvDO0M3MkxpYs+XdIIvRVanGSvJXrXxj31
         lJaVfu8gMgAO0c6H3nLRwH991nm+/v7w8v52rVsmkjikqNLKHwKd5WIIV1OuRfMCqbZF
         Z+t83bcHVOtVfYx2BY7jsZc7KAB8Xeb3Ua91CIBJcFPn0BrFPpQFuY8fCtjSP2NsAbyv
         DedRzvsZ2nbTmS+BFNkawsJwlueQGvji2M/xvHNAtORNdHKY57uqG9+2MnSapHVr0UKU
         azmL8e28M17wv/Z6d7BSnwdPncYYyUSCRarNnW7p9OtLz/JZGWuHSw3oaKoXGvLH47uY
         5ucw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=C84dGj4Y1tHWn3ZiXpo28U2oWtSLUtAwVIMivuMwwHc=;
        fh=u+GMG68lOLYXMbW7ip5HCb9mibH0+T1PyRa53MWbN+c=;
        b=kiwMcIYSliW88w76kVUPqjyrkD1wLFiSEUvRQUyqe+Z5hFGjHOTaKwVRohogo+mNap
         r0+ubFiZVKRPMYeCjZIT5k/Fc4+bJbT0Y4xVm990tz7fk/Ayi37S3iwSZ1si7bdNKSjt
         10/coG+e8w4VkcQtZn729EyunGVUmR9jq90Kxk6wyBPtbkOOlVj2aw6Awi9VJoXJ5DIh
         fhk8Kv1oVrTEbeJIcb1ZITGxMzrG+mXkq/uHcmTaVXDqBld9QfanasYIogGXDQi5cdQ4
         21qTbLChE9PINwUHRzfQz+nd2nslW+5upcAM+qvVsm5+gbs24+7WyhnSfrc0UpxiH8p5
         rmJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hPZoyu9O;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332187; x=1756936987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=C84dGj4Y1tHWn3ZiXpo28U2oWtSLUtAwVIMivuMwwHc=;
        b=MMLk1vJgQOUyWqiGDU/7gefJSt0MLb3j56WGgFUOECQz7qcu+5eaEZlLUAG4fySSll
         oVPVHv2Nxuxm7VIvEd+bq88DPoTRg/3VxcDd2XqoqNKoYxYaqj53fATrNfDfjR3rqmjo
         VhF3hMwmCq5PjnSm6VsB9vXbtJEDFghyFikCESrEfn8l9QQNklFOZ15ZCEKYm6gaDlb7
         9S8DP/aQpF7ZGrsK+M0HQ7exIvijfvnyKkHzlyweAkVbDJpIJ/tdj6V6MX+Cqm2ylQRU
         bALke9St41lTyc1xBxzx4Ay3oav07rbgPikufhc7TPWFQPSwoukAFbF+9RqR8Q7XiUdO
         8Ehw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332187; x=1756936987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C84dGj4Y1tHWn3ZiXpo28U2oWtSLUtAwVIMivuMwwHc=;
        b=SOckq5i7Ddp09PGLUBTSqXEcql2MtiG4i6+JFCbozrNLhc9jWpgBs7jx0WEmBiQt0X
         X69yZWcdGJqPDTzUd5J43h0uVXF0/qoWODdShXJ7vXouf6Cr9bvvrxSslivnPG6LD3/P
         aIF8hUbpdoLhVgl1CyIYnXpfqE8hZ0dyuBsoC6TdHj/m8y7e+qtCSHcMUQJcUvKgyRsq
         23FIjjiQ4uFvkoPaZCO8CHXlA6ENolqO9DTgEnx98gH0B39+Gy8yrUzJpa1CMxx8Xhdy
         vKOxrpCXykDhLhxapxV0GwMy5JsEUCX6cFKk0GEBmys51qBMgumr7iLHL4iw9GSjobub
         wTzA==
X-Forwarded-Encrypted: i=2; AJvYcCU9WVXO0llDJqewpe5B+ddkqtrSWl9KQ/LbrTrU5/rXqBG32LcvNAJA50cC+3Wsip/Ho2eKkA==@lfdr.de
X-Gm-Message-State: AOJu0YxIlWuWfAHIhfNg9nv6jiCbyCvrfgrGfD6mIHgeWPpBknedc0nS
	HgL+gyqVOivb6ABij9PrV7dPJd2o1FLGWmTVpjXgBYT5TNAeOmCMh5Cc
X-Google-Smtp-Source: AGHT+IG1gNX4Yd8cXWqYEdeqNJX8ewW2JyDnNo18UxHb8r1giXjy4wYblglNVLL67TCya/h/7AA0kA==
X-Received: by 2002:a17:902:f551:b0:248:aa0d:bb22 with SMTP id d9443c01a7336-248aa0dc0c1mr41189915ad.0.1756332186319;
        Wed, 27 Aug 2025 15:03:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdz3UsSGGc267Gnkd0ZSjtM2aEXQ8E4PUmw2T4GV9wocg==
Received: by 2002:a17:903:25cc:b0:246:1164:522c with SMTP id
 d9443c01a7336-248d4dffc81ls552695ad.1.-pod-prod-00-us; Wed, 27 Aug 2025
 15:03:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUvOAzlQWIRfFm4a5B1xGI89hnQOO1vjPmvETP8GVX96fq6RpbNhpkU+nC/VuyQF4aDQY+WnrcIOc=@googlegroups.com
X-Received: by 2002:a17:903:22d1:b0:240:86fa:a058 with SMTP id d9443c01a7336-248753a24c4mr90238595ad.7.1756332184894;
        Wed, 27 Aug 2025 15:03:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332184; cv=none;
        d=google.com; s=arc-20240605;
        b=cqGJr+dy7y3Nsiif+PMmgG0+GgokcQvZNDufK6mCBaylct8zywWb0JqtCzr+ZOwwnA
         Wdx48G9rq2Zw5UaLnx84FtZ8JlxDh5vvcGVJw2vZbiTZigzjUuQR40q/vRzwfo6euq9R
         8UmWFfx8N48Gy0+0ZbilKrLd46p8lUy+s46Pc/t8qh90Ah6obRihrTL01nrxXmdw6NNK
         vHj5JSrNBp98psQtZy8vYLjg9waH/4o9dOdQhp+1g/wGzal9jK+WKWBDG6pmxSCYQqeg
         oxRcjfjnV8lcz3dJIlZidzlJWsKGKoEFhm74KTdzDpy1tjxBhmEC51agJHmJtRqU6EK3
         Bx+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5DykevL+FF0TVTnCIKFrimPfVjOwsHIDZG+ZjBK1smY=;
        fh=yD8Rny+G0xXVHwhblnNyg/JtyYwHKKxpGXqp1xxDTzA=;
        b=Yme5/Zfg1QW+e0DkBOsiEI2bA4AMOvbrPDP49qMlworWWo/55YidA2rI8jico8USqB
         aqey/LgkEffOhwHGFFr4pLqyuiW8U78v83Hf2JqfuSgoZtnt/Plr1yLnUHeLDn/4Odx7
         J7ikENGHl345sTnVRaAT/3AB6/mX0gHdTZ/+0AXoqgj/UzSRo9qPkfsQ8TK04GOyPPdI
         Rwi8YkfRHDLjH0A00fScEEkkQAqHr7n8WBoUUJK8UMzQauM4h+a9nxXbAeG9yp89671X
         TJm/s9aAsCon05qgazVAajgGOOLR5t0SjJJigNbCXxxGPCCkqBTf8JpJWD5PfSophi8y
         dLmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hPZoyu9O;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f6ad8b5si148430a91.3.2025.08.27.15.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:03:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-18-QHoxSYI_OH-QMUQwo98hZg-1; Wed,
 27 Aug 2025 18:03:02 -0400
X-MC-Unique: QHoxSYI_OH-QMUQwo98hZg-1
X-Mimecast-MFC-AGG-ID: QHoxSYI_OH-QMUQwo98hZg_1756332177
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 050E619560A2;
	Wed, 27 Aug 2025 22:02:56 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id F159030001A5;
	Wed, 27 Aug 2025 22:02:39 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
Subject: [PATCH v1 02/36] arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 28 Aug 2025 00:01:06 +0200
Message-ID: <20250827220141.262669-3-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hPZoyu9O;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
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

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-3-david%40redhat.com.
