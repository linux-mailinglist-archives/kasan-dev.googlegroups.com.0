Return-Path: <kasan-dev+bncBC32535MUICBBF4EX3CQMGQEPRBCDQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A6C3B38CD4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:09:29 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70d903d0cbasf8491036d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:09:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332568; cv=pass;
        d=google.com; s=arc-20240605;
        b=kHSXFN8R4qsErC0klB6PVrhTdX+0A6pYJfYgP/9aRdCjwbWRxugRJ7z3clgTMRyRUZ
         SRWVMnux95hHFoRLHCpz/cFxbQD2cEknKmvQ1vKfLuJlChZq+EWizxTUIH5nkhwh7Cex
         dvutRHUJNqeKYdUYrCF20S5JHOwl4WXJmMvJGxccjiSvxW1UtlCUnBNVlwPseT6cy1NH
         ZCbIsI5Lxn4OXZw0Ndx09dgVQCDBNDcvHL3Ko6H8Kw8clqkwInV2lT9vMDuXFyYdudSI
         EFhbeOZ2BB25QBycnItXwGkXMVcCgP0iLVsQLOBAnxpzNgsHpXs9YBrXDsYBYcPCDXY8
         n/dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DMBd8mbavB7ay1o5kfVNioBEwgVM5f/D2uXysMgxvDg=;
        fh=vhsoFt7QvKrKEPqWrFGIICFFT+7b0coPrsnyjg85BvU=;
        b=eRyhi2ONCos45V3vX9hccIEof6CJ7UYCbUcMyPzKHzBwT7p4YsdDdRhh6kbm7ZoDW+
         pxOPXgrW1qB6IUMVNsv2PuS7t9+uW2EtY49W6XVmnQ+wIQghR7YGFysRl9eOjpln5uVe
         iMpZGqdHCK4XU1IcwRz7scpCHCvWGUNRX2HWE+tvC/UHbMi+VOJ1ad8jLwoucSWC3jZw
         bMdZZeR3EKhaqcFN11hT2pd/g/c4Kv6wzj/wrd5mGliA8vYKI2WMCMXYWYbYIeD7Pxl/
         81mZmDJNBlpjV+yE7BSQDW/V/rHxVugK5gMP0IX3/gVOeiE2RJw1VcCPuqiaKEPu5cXY
         C9yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UfJsf0k5;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332568; x=1756937368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DMBd8mbavB7ay1o5kfVNioBEwgVM5f/D2uXysMgxvDg=;
        b=Gl1+87O5Mvsbr1ImNCX7QeXBXTD2ex93nqtuQN9QFHhdDJoas+ETFgj/DYlmdKq9df
         wB/nO8DaPejjnrUCHu394cehas7XIrbV7On55k0T41VVvW00uQ6dhASJF4Z/hou2/yQS
         yLWbX5cAGBeCD/FP3FNJI1IeOqSh4uCR3QePX/FvC5a9ybIEtzD2FArgzJoGa8v712a/
         gR0syYzI6UeoWgbEc2cqoMD4weFoJYBL6zdiv5xs8/o5yngZjocFJQAVvH5hmRZz1KqY
         QH/RRMi0yXwfiE/Pbr0DDiHnfi2pWB78QnhyOE9AX/nn5jVBFPOucEwP6EdpqaDw1OR3
         ILJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332568; x=1756937368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DMBd8mbavB7ay1o5kfVNioBEwgVM5f/D2uXysMgxvDg=;
        b=eRCDw9s/IjPLKUEQbx6+aS46qe9Gbvq1BNHOWJIG8bJe0aabQ4kpeSJvea9PdNAWJU
         oG0ffR70rpWPSwq6fxP0ICe1+PrA+Z4p2UmsMfr80bl/YEHcvJBFY7SO9KmB4vLPFrRC
         7gRXYfs2gBGH2ltn27f7uZyBLjN1RfV1xH5kjRMd5UKM6yyr73m2WbBDOSIsAf0wVtxP
         dYA/eBer9BST7MTrIkahWVoyKKz9t3AMRTSzCSMXo3qM5X0uXBUV1B2kZkRoLyYWx4rt
         o1eiizqad4oxgQWXyN+ZTISpdvExKnmeWJS0CvTAjm9zADLe4P1sgSapKG2tTafIxpRz
         MW1Q==
X-Forwarded-Encrypted: i=2; AJvYcCVnts7MJhGA7+YHO+3J43OrcSsQmAMqO+iDCt8Hzhw0XVUxLgh0oDjK5Kgr2BBNbCDn+ZlreA==@lfdr.de
X-Gm-Message-State: AOJu0Ywaa6YHJAwRXK5zSR89P4jbgCUirdMozmmCq73vKHvyshnja9yK
	kLBxJvDa+tzUIMAtNarENYGYpb1DzqZy68BdtVaqRgnGAhp5vVL1SytI
X-Google-Smtp-Source: AGHT+IEKB5m/9BVQ1pukX8/p81OXJ4mP2V3UitV2m7RtRAPd7bsvW7bvAyGwYzjnc8RIo0d0qSP/Fw==
X-Received: by 2002:ad4:4eeb:0:b0:70d:b128:88cd with SMTP id 6a1803df08f44-70dd59c0dd3mr72585716d6.5.1756332567708;
        Wed, 27 Aug 2025 15:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcz6VXfgPUmK1A2hEDXsdh9cIQLbOAad8BQYewW+XEReQ==
Received: by 2002:a05:6214:5018:b0:707:5acb:366c with SMTP id
 6a1803df08f44-70df04ab851ls1611416d6.2.-pod-prod-00-us; Wed, 27 Aug 2025
 15:09:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIpY7/3wFB6vQpaiJW4/Bn/qOSmQnHbFaJOVK3y7knWhggjSpkxrzBm/bneeytFF+ajlbBFU5txi4=@googlegroups.com
X-Received: by 2002:ad4:5ae7:0:b0:70d:c4b3:9437 with SMTP id 6a1803df08f44-70dd59c31f7mr72204026d6.28.1756332566796;
        Wed, 27 Aug 2025 15:09:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332566; cv=none;
        d=google.com; s=arc-20240605;
        b=ADIKIKIOzHoQzVujbTDq7PcyZIKYn+F5b9/RFlkljv1iC0UUNGWr72q7VhA0rK1phF
         iE/OjPdVmKCQnbDFcHUu9UkdriXUgEKbrn643zII0t8Y3u1gapTk5ReWX8cuA3qN0tE+
         uX9tNSS35vv2AfDBatoaLdmI5EcJ+0Jut5BfCXdWxFZ9O+CsGdZB3V/sOkT4uQlF747i
         YI+Ou6R4bUyVeRJfDzEug7ZTjwUL7VhX81Qw6zcOHOGZKPuG41oLzy8/UzzzIyaowsvU
         MwDJhwZFSIjLGyegNftQgWR256Hc0nYYrpZya+9KUECCNqp4kaYjs07V1g5Ksou4QJRN
         O6pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5INZuVEW8ZoCVRVHt0CSLhpT4h786L9PUsnD4NVlnkc=;
        fh=tX3l54BsOqbux4m2hJkE7JGCkTNLMAUhm2gNUEJY+Lc=;
        b=PKw9TP+7t8xndk9Rm7DnQTL8CAigL2qlXedEtYya2y7NVKWT5EUY7E8VzJe3aSOIj1
         8wvf3d9sSuBGUdzjW4sWlyO0zYoiVnJMsrgoN6vzW1u4VBfEuEinyReLWYYL05ITMvRw
         Mbjgt2WKm5OnWS6w/DJMImeur5IsIvB31hRFlXgI5IX1inhJW2prvMrt+1FacE8HI9q2
         qTwAZhJSdAiYYUg23RTx2iAoDwHjIviqG/SDHHj6w6u3fcFXhClSz4lp8IvOzC/FXQ/x
         prCgVV6jrIPGnRq7lTtviELB+YV9LStLFCLwQOpLntnQvILX1b01XKb61CxqYe0HqDbE
         6PJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UfJsf0k5;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70dc547bfe2si3751996d6.1.2025.08.27.15.09.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:09:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-452-xy2DE7SVOeOfWFxJcT2kQA-1; Wed,
 27 Aug 2025 18:09:22 -0400
X-MC-Unique: xy2DE7SVOeOfWFxJcT2kQA-1
X-Mimecast-MFC-AGG-ID: xy2DE7SVOeOfWFxJcT2kQA_1756332556
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 3265C1956087;
	Wed, 27 Aug 2025 22:09:16 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8A03F30001A1;
	Wed, 27 Aug 2025 22:08:58 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Jani Nikula <jani.nikula@linux.intel.com>,
	Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
	Rodrigo Vivi <rodrigo.vivi@intel.com>,
	Tvrtko Ursulin <tursulin@ursulin.net>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
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
Subject: [PATCH v1 25/36] drm/i915/gem: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:29 +0200
Message-ID: <20250827220141.262669-26-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UfJsf0k5;
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Cc: Jani Nikula <jani.nikula@linux.intel.com>
Cc: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
Cc: Rodrigo Vivi <rodrigo.vivi@intel.com>
Cc: Tvrtko Ursulin <tursulin@ursulin.net>
Cc: David Airlie <airlied@gmail.com>
Cc: Simona Vetter <simona@ffwll.ch>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/gpu/drm/i915/gem/i915_gem_pages.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
index c16a57160b262..031d7acc16142 100644
--- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
+++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
@@ -779,7 +779,7 @@ __i915_gem_object_get_page(struct drm_i915_gem_object *obj, pgoff_t n)
 	GEM_BUG_ON(!i915_gem_object_has_struct_page(obj));
 
 	sg = i915_gem_object_get_sg(obj, n, &offset);
-	return nth_page(sg_page(sg), offset);
+	return sg_page(sg) + offset;
 }
 
 /* Like i915_gem_object_get_page(), but mark the returned page dirty */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-26-david%40redhat.com.
