Return-Path: <kasan-dev+bncBC32535MUICBBL4DX3CQMGQEBFQ6KKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id DCE7BB38C96
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:07:52 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-88432e1630fsf38156439f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:07:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332464; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y0YEfSG4MnHYKaTGBArGpuz6EuvyqVCRMVMSbYKmap15rLLqwHB1v9M6f/rjbs95Ch
         nerX03yyo4lJme6Uw2UUddGSy/+6aV2XgWj7M286cF3QaePdDVH5JygUOSt5as/PNda2
         QJNIYrQA1hRabseW/GmZDer/qW/LXZR7L8BsrvnIN9PkGi028usd/WxCHbc2hb66fM93
         kxyhcve8s/azSoqV6+/6llyo9/T4AUS6DFMp2UQQ0wbeRLKNmR40EDDFITd/w2w53PN5
         AnJBDT+taO4yZwuE64ji9VGaCDI5g0LdT7/CybPgsBzfW2SsPsUqryVOAhIpSvDoZjep
         omig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TKSUMlrWPCQzKmileLcqk6jiTxg2Wtd1cDgpQ7jxoSQ=;
        fh=jB31iKayHPojQK+Pse6ODQ60qu+0QgaooF81vk2Bk5U=;
        b=I0BjqpWrP+vKI5FBR+4z9yYCJ0PGkNDfyeikKDAimDn/M7glJ38Z/Ifas1LtH3Dm02
         IjelFxF/0TgOj4+xtoU2c0I7aDisnGGuNYHW7COgo3UH7WMR5BxA0lMHpgHScMBdmP8Q
         oRHdfhHrvqYPJ1hxn43QKRJg1V/Ca72ou2tG72Lh4eBWw+G+Ifvmw+99GrEQkD8g9dhZ
         0D5vrJLD79NBWstEmHAb/fskPsxP21sJHSLDCguciIw6t8ab72dZGmP9qnAkRTNnUOQG
         ZVh0CId/Ea+b/NvJzrxvznolxUWPnsGRTP2zwkGm3KE0/7IG8qz0h/HcBwxQ5QTfuQMh
         VoSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=exu8+pBG;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332464; x=1756937264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TKSUMlrWPCQzKmileLcqk6jiTxg2Wtd1cDgpQ7jxoSQ=;
        b=gBgQLtJWXvOGosFE0ipTgoG/hRkLFwYfrXwnXNsQ+BWD86FmzqnDP0UyGtqpK1yfMr
         mMJfUnfMckOTjxkyhMGsh0z+BNPAuM4+Bbj2Tev/PziNB5kq874z+x5H6+t9SRkDOolY
         Yc6Wta9dqFJ1gPThhapfv0WtaVxoVFqvQhNX4w95NqZbmZ40DMFu9p8aOxJoDUC4N533
         r+9K6e9Jac51evMpzFrPsailay+NeQyJJuH7udyCVBamNA1KzlcJPic8zQV+nwASnrFt
         4UYCo9cJq9OgLikntwRRdyz31xNp42izuZqbcERSfcLN9J+Ci4TjWpO8S6/HUerIfk70
         Ncqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332464; x=1756937264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TKSUMlrWPCQzKmileLcqk6jiTxg2Wtd1cDgpQ7jxoSQ=;
        b=cb+pfOpuA1An5YhqtAAxb5N6v0eShttTEMS8VnZz5zKdTBs62k0KAYEkT76v0V9gJH
         ES/rz6yuDYpPBUwH3Vpf/dA38p3eiO4v0BVRfy76pfI1EN1mp36ZiH/ZJNCSPdSFlR6X
         51PDDnKCQ7YNeRypGPfmrtqY1K0jHCdvKoa/6TWAY/zqbbO28t0RN7tUd5u8JYJSKbmW
         bFjWVZLjgbwncc/AfM1bgL4fIGTjMrINpNHYZWIJODHGBHYESfYzeXMoqoWT3qQyUVkz
         kuX4KgJKxCVzwP4qbiZLDNxAhqXxv7p55pugvS4Wpb5RK0+O+NAWIoTE0hnRyjxFWr5X
         lFHQ==
X-Forwarded-Encrypted: i=2; AJvYcCWg8ox+fp/ONbwreDRSt3DKVoYE86aN87/NYl0LltexU4jPId7pKvOVaUCkb1uJo4GhLpa/mw==@lfdr.de
X-Gm-Message-State: AOJu0YyJKZdvm+IeQeVVkfAiWFOiQi9O/l7uMYaLR9h/lz3rw+cTAz1G
	qENOzoH7ryNONRP7YmsKRH0rfwQg8mjlCf+CdTsBDsK8L5DDF3vfwQRm
X-Google-Smtp-Source: AGHT+IGuXperbSnScc8+LaH2Wvd07QHFuJgJfMuYuaxAaKRtqg2FbwZqH0RTUt+qAyvd20jB+TpRqw==
X-Received: by 2002:a05:6e02:190e:b0:3f0:f671:aca5 with SMTP id e9e14a558f8ab-3f0f671adafmr24705025ab.19.1756332463793;
        Wed, 27 Aug 2025 15:07:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfXyPIppMeHg3Ie77T/4Jg+gNtyDC/ea31+6ptijw8jWw==
Received: by 2002:a05:6e02:1fc4:b0:3e5:8140:1e59 with SMTP id
 e9e14a558f8ab-3f13a20a41bls1481035ab.1.-pod-prod-03-us; Wed, 27 Aug 2025
 15:07:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6mBa8at/J1Gcsbu19clgFcczm8Q297id9cgMKZQ6ryZmS5gotBAFkl/vSWGYMqi6G8XzIeuqDmVA=@googlegroups.com
X-Received: by 2002:a05:6602:3fd0:b0:876:a8dc:96cc with SMTP id ca18e2360f4ac-886bd14bc1emr3288749139f.6.1756332462219;
        Wed, 27 Aug 2025 15:07:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332462; cv=none;
        d=google.com; s=arc-20240605;
        b=bEMXZbhXI5L2AZVqPNqwZMsB7Sunr0wNjRkObUIILHsciUR8L4Ht4iBkXVgP3KgwQU
         my0Noat9AuidkkV4JB7cqSIDEAVso+krE5ooSAlHURubL8dTSSqzYDP772ej68ro5yq0
         pA11GpPvr1VZxyUASTzsJO9c/bWlpsXccgSxi9e5ktsa4FGkfDDN1sgPIkNNLbzU5dRa
         T0mOAIG8vtZR0vYg5c/lBkTLts0rkBiU55cm+psbE6OCt1W063HWaQZRJOOiq0K3wkpv
         M5PhnEOYmRjuldHs77kK95o2s2IRNE1xfmZUvio+PzEOw/YxqCM8B3eyigSMqPElECm9
         Tv1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jRdNfj9ZJOGMCBURzHWfgI671U+1iCcASfBCX64ogeI=;
        fh=GKvoD230zqeY0ALym3XoeB0P9h1NYXuw78UG2ikYAsE=;
        b=FNkrt4RH8TyBAT77r0dHF8JOKhcmrgZYjNxouG1FVkcFnQXaLC44M6HsyoFpRKLEDG
         Aal7svbE1bh43PHFE4Ml7mNIU4IWiWml+t7o9ICo7XRAZzOuWn63KAwihaSfd7SxD+VS
         a+CIjCACJF5PweFHD8eT+shUFtMVN/C5HOokPgJGp4ty2M8IyOCHydOjQ95Gbu9OASE8
         DUj3Ho2qbQD+4yEML17SLcsiITxCONDyCMLUGXhJGU+3opWJJEFqKLUGFC6X3jYSNi+A
         zupkg1ym+R2ENlA/TfjkS0QOo4OE6JodOhuzPsqZHwtTNLMYJiZIPymkjX9p5HNylTNM
         urIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=exu8+pBG;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886d85baa27si50632239f.1.2025.08.27.15.07.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:07:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-552-hUo1S-tsOY-l5AExsMPNLg-1; Wed,
 27 Aug 2025 18:07:39 -0400
X-MC-Unique: hUo1S-tsOY-l5AExsMPNLg-1
X-Mimecast-MFC-AGG-ID: hUo1S-tsOY-l5AExsMPNLg_1756332454
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id DE2EB195608E;
	Wed, 27 Aug 2025 22:07:33 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id E10A430001A1;
	Wed, 27 Aug 2025 22:07:17 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	Jens Axboe <axboe@kernel.dk>,
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
Subject: [PATCH v1 19/36] io_uring/zcrx: remove nth_page() usage within folio
Date: Thu, 28 Aug 2025 00:01:23 +0200
Message-ID: <20250827220141.262669-20-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=exu8+pBG;
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

Within a folio/compound page, nth_page() is no longer required.
Given that we call folio_test_partial_kmap()+kmap_local_page(), the code
would already be problematic if the pages would span multiple folios.

So let's just assume that all src pages belong to a single
folio/compound page and can be iterated ordinarily. The dst page is
currently always a single page, so we're not actually iterating
anything.

Reviewed-by: Pavel Begunkov <asml.silence@gmail.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 io_uring/zcrx.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index e5ff49f3425e0..18c12f4b56b6c 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -975,9 +975,9 @@ static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
 
 		if (folio_test_partial_kmap(page_folio(dst_page)) ||
 		    folio_test_partial_kmap(page_folio(src_page))) {
-			dst_page = nth_page(dst_page, dst_offset / PAGE_SIZE);
+			dst_page += dst_offset / PAGE_SIZE;
 			dst_offset = offset_in_page(dst_offset);
-			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
+			src_page += src_offset / PAGE_SIZE;
 			src_offset = offset_in_page(src_offset);
 			n = min(PAGE_SIZE - src_offset, PAGE_SIZE - dst_offset);
 			n = min(n, len);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-20-david%40redhat.com.
