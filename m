Return-Path: <kasan-dev+bncBC32535MUICBBD4DX3CQMGQEERS6HQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (unknown [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23E6FB38C86
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:07:13 +0200 (CEST)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-5f9e0741d14sf498810d50.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:07:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332432; cv=pass;
        d=google.com; s=arc-20240605;
        b=ea2xdAu5OAgjbFA/e71Zwu7JlppsKSBkHPgf0zzBPePvivjHG4fRYHPH9pHeluOnVV
         fnA6InoFceMHcuZoAXlEkM5AWkt5mDGU2BxLNKsUr14uxyiO1qAyTd9X1acICa3ndn/q
         ic2wdvR0tG1SZrXIVNmDCEY72SA68o1MMu5jL0ZOx7W+nYWnPqpiAXHmRwBm71lAjuKw
         kngOTyUB5/fY4SSv5jpbkjWW0k8cm42Jx+k6DvRCc1vpnNS4Bl9nbIo2FtbTPK0yKbDx
         ayS/USun3qTpsAZM9fpiJvNB0JhMr9by1ZpC+ewepi8zQvqpqnquGi8BXdOuYspLFAyB
         3++w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=y3LPHszIbe0izIP8tt/+vSmmaGrG5Bk+yscVdOQCjlE=;
        fh=O2RVvYs8MEPsppXByz1xUuUX9/RvDCpfn0pmQT7lfko=;
        b=I4H6tbSZenJph3MB14wg/QcCs/s/lVowmci0NaNdhygVw2KGqA9bgnkO6R+sdxeRSN
         264wnha+DzacJf4o4Yjn3JTjdccoQYiRV/nsih9ZxOWZlDMmMv0C0yiYZBwov0qKOx5Q
         TXOqQCGrx+V+8SpprP2SXyeJng+vYmO9yHfkfD+EC8QRxEUnL6TpNcqZ6I5aeX94455L
         cHhwzTte8RCH4KwsYyDl/7kMMm1WbZnaZ7FWxJwR+ywpHysCjNN2rB4kCH0U/TACN0bL
         bJ5b2oK6mmodvnIln5KnbTcre6TU7B8A2bXo2cTyzBc11az6gUeqeVl4aCPxaavbeyZH
         mmNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ftvEY9Qb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332432; x=1756937232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=y3LPHszIbe0izIP8tt/+vSmmaGrG5Bk+yscVdOQCjlE=;
        b=vmTh7pXeThwIDDMdJu9D5xWBJgF5L5FEOS1IVy+jMx8vNSQhCNYUxftdzCH/QUwShY
         YnnMrh0JOQklrkxpLwhZWyMYwIxfma7yuESxCfGr6rdi44ZfBgk6ZFsWNAKBnYrjuIdQ
         EHiaLgE02fKggiUaBy3ELY6+TsELgz863/y5mS+OQ6LfVhV/VAtGl/R0i67IoJ6W8PQj
         FJAPEYj5ynsmHI7tdchsOIgCeh98+pr8XqpAGAy9jR+mQgbBYs7tmz97PWyNvi58iKZp
         FB6jGXjQL1sWjAL43dIdcyQX/0EDsu6aLNrMDdU1lfCiADWGRWApodGUEwjPyRX9ZfX7
         4w5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332432; x=1756937232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y3LPHszIbe0izIP8tt/+vSmmaGrG5Bk+yscVdOQCjlE=;
        b=RzCQd1OixK5a8oKGKvsIAql9IaQ5IJqulaPXI2R6PlEZTvUmnLfaTzAqKuI/4JZY5J
         DyY5hkPnhOlLGU/g4skQ0xjAojf8A6Y0gq1j7rLwfWatfz39FGRL8Aibq3W9iNlDM2Eq
         q83/KLmIVPZbIyZZTHsKBVHeeyXbwj1w6Y8I+BgNiqppKamxC8fzQxWdZ9tfIvDcG1L/
         +41qkIdSgo8wyWP9Il/6jFvGNrw2pwQL1QOET8gEAY4C4+zhXE68yBTO+O0o67b4jKIS
         Kl03CQdYeTYC1EqlxM+7OLGb4RVMiMPpBcFXcSnreZ7bKY86y+2mT7KDVt3igscXg3OL
         /F5Q==
X-Forwarded-Encrypted: i=2; AJvYcCXqfzb+f2VV6ZocEMN7E4kH8kmKL1D001+T84lugHD2wdbPQhNB8juCrUPvaE3iOIWLfQAExQ==@lfdr.de
X-Gm-Message-State: AOJu0YzXxZNwYx3uBRwSj4mlE1faMIOi5SfwRXgoXPPV5Z3sN2Ov4+mg
	yS4c/1XeCAVtMNMifSn1Ygc/9D2IaheBQAz8zMZtSPz83WQD9h6ZzLZO
X-Google-Smtp-Source: AGHT+IGFFdn+zkssvTS4C71BiOymzSxIVpyQUblYNRTcoNyDHwfzSx40D3oW71qDrZ6iT/jgQAqW/A==
X-Received: by 2002:a05:6902:6316:b0:e94:a1a7:c6d9 with SMTP id 3f1490d57ef6-e951c40210bmr22719089276.45.1756332431758;
        Wed, 27 Aug 2025 15:07:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfY8ML8fmQ9943JKJ5dwjFqOvcc22H4zWf64zggvpQtXw==
Received: by 2002:a05:6902:1706:b0:e96:ea30:d8cf with SMTP id
 3f1490d57ef6-e9700a8bfc8ls164615276.0.-pod-prod-06-us; Wed, 27 Aug 2025
 15:07:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXin42ku1oMTm81AOdEr60atRwHVEby0YoVQYu44HSn0qaD+1o2k7mP289Qd8OLX2d8OgRJG3s4Gpg=@googlegroups.com
X-Received: by 2002:a05:6902:6b13:b0:e90:62f9:b1be with SMTP id 3f1490d57ef6-e951c33337cmr22914016276.22.1756332430722;
        Wed, 27 Aug 2025 15:07:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332430; cv=none;
        d=google.com; s=arc-20240605;
        b=AQIpKbI+v5u7XkYTX2gNNKuGuzSB5qfmQoHN0xQ1HZa/k0mZWD2Ln1vnEzH9PR177A
         PQf4GaQSYy6uV7FePxT159xCXDQPYv9SuPfPI7oNg12QJyZakPo4PrMX0Cbc+8jiPB/z
         JqWKva8RBN/ZEVxHgjJi9W6Xb96XYqLzorjNF7smdy9wU5CNLd++YDGAU9LNQ66UTNun
         o2QUbeiPMM8TzWfye4CplSsX76hOhInVfm9jkQosqePBEiuNqGJBpo/B2pO7362pbNOq
         sIf81nSzZ3+aUgM3aXrpeF9d5B4IGHhcMKafihMSAghvPvmVNsuUxeCEf6Vs4ev7Ij7D
         PDPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QCvnB/7xI7T/4p4mwWx/D4+W6s//h9G2+oSyfbDOFZs=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=KEkqGXD7v/ZqmZjxa3Mz25mxelOU4QOq59ym4JA55OflKRPzcC/i8sqtF27Xd2A6Pj
         k9Os0/qh52+X0DFfbdZwv/bHK2WzH5/TJF5nojT6xZgRlFbKCG41j89cEnPEiWdmmoKE
         u8JN7dFq69zbOA4WqMXoq6vyWv0GCO/KNEZ23NkYh1Y8v8Rgxu0WawvzaC2DxRABefUb
         aiNa2/OR0ej1LoGRpMTTWeLO14OEQdaPolq+YmYL3qqrThIL67WNzNHbE2QjXZIZrFYe
         v2J0Kdffmr0U5vcDPJqlUkR1nT75OW/w86+62kfiSo4BVVMzUb9/1/ZMiJlPgyz6hQk3
         P/lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ftvEY9Qb;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96fc73fb40si71870276.0.2025.08.27.15.07.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:07:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-82-ClQKmaRWPAKB1M2iEYT62g-1; Wed,
 27 Aug 2025 18:07:06 -0400
X-MC-Unique: ClQKmaRWPAKB1M2iEYT62g-1
X-Mimecast-MFC-AGG-ID: ClQKmaRWPAKB1M2iEYT62g_1756332421
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B7B791800285;
	Wed, 27 Aug 2025 22:07:01 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B7D6F30001A1;
	Wed, 27 Aug 2025 22:06:45 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v1 17/36] mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
Date: Thu, 28 Aug 2025 00:01:21 +0200
Message-ID: <20250827220141.262669-18-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ftvEY9Qb;
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

It's no longer required to use nth_page() within a folio, so let's just
drop the nth_page() in folio_walk_start().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/pagewalk.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/pagewalk.c b/mm/pagewalk.c
index c6753d370ff4e..9e4225e5fcf5c 100644
--- a/mm/pagewalk.c
+++ b/mm/pagewalk.c
@@ -1004,7 +1004,7 @@ struct folio *folio_walk_start(struct folio_walk *fw,
 found:
 	if (expose_page)
 		/* Note: Offset from the mapped page, not the folio start. */
-		fw->page = nth_page(page, (addr & (entry_size - 1)) >> PAGE_SHIFT);
+		fw->page = page + ((addr & (entry_size - 1)) >> PAGE_SHIFT);
 	else
 		fw->page = NULL;
 	fw->ptl = ptl;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-18-david%40redhat.com.
