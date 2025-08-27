Return-Path: <kasan-dev+bncBC32535MUICBBMEBX3CQMGQER4OOKPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E27FB38C0D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:03:30 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b29a0b8a6asf8941921cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:03:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332209; cv=pass;
        d=google.com; s=arc-20240605;
        b=XWgAIZMEXEvbnC/IIEUqa5KqGl6oB2sD9UCYwoR5cTw9smqouidNuyR3Qh62A0vvQO
         +4PfnVg77tDJmRtLw2J0e2cSWMyHY2SmrdUJjkrl2rjRtjcfPqYqi36q62pgbQuw3vpw
         ULjiTIsdYn4CnSHOT/HfMBI/D/4yD+6VIOwH5hszufg9zXhIoM9mzjixiB8RWLPZo9Ne
         6WQ7rHOT0Zo6N3zWa72L20jdcVUY4oIiCddfd6aYqtlCgH9suZ0QDjxW25u4Pn/9d1e1
         oP4hX2JBlNPufpX2XbFiS/o/ofnCHKxY2pOHpXjrRp0bJKkiD/mMTeYTJaAmowkVabOJ
         Omqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1XxvT7Rvk0h96WgGYPRwsXiZ8/GLXSfkMNijwr7+hPI=;
        fh=JEIzdaB1gL9IB9to+suAbcWI82j6tNzuCbk8YhsyRb4=;
        b=SL50OmBUPpzeu13G2bPxTehIpGWYRN0M6ww9xkXkrfpB0m54kktDJPuxGoDP7chvar
         hpUtaHrWNgD+Xi5cM/Fw49gsNH6yuchwDJJuyjKl6kBnx3Dro6IE7U9FYnXQnWo7Sio3
         vhlR+TY/IAGseFcxrEWk830kWJCXDJ6mz7qmprnVzfyXpQjbY5BAhlmuwFVoxNsysFZo
         drvf9Cq8NJtnz+ljwD9bSWNOYQ5wKVZzEY/9lVLmW6piDbBwbZmCAULwb7jBo+sPfe2n
         SevT7LCSbfdnHjjb1GbBd3ulGUJS6b8fYLmXQVCgXhVl/ALsTd7onByZdA4Wq1HSbkGj
         n0Ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IMBUmo2L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332209; x=1756937009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1XxvT7Rvk0h96WgGYPRwsXiZ8/GLXSfkMNijwr7+hPI=;
        b=sFSTQ5EsP+GFCwZBPLTnvDHadfWeufuy5sTbozpZeomwX6HkSPN5oiMYKi5RrgPHVV
         FfJz5CzjFkfZQaP28n2e2Pau+nnNk45v2s/hZZiTzI4TBkBbK0ALiXoGx63FaXxDFykZ
         Qv5WyZUeUW9MaEU1PO3SitONPBOYpzxgU1DKj6wl9b4ecaQx7qZ1dwd+joc54dMju1WM
         KaKQ56hzKJwEBjWnEHxOutTiBKD49y/i7agZh4Ki+l4sk74bAuEfz76hWWdf5YS7r7m3
         0G7jFJuXCyejSK4D8EVinVbmPQhEoQJZLzUeJnX6r10XNyS1mWWJP9sm4j4JWW3XNu1x
         vn1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332209; x=1756937009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1XxvT7Rvk0h96WgGYPRwsXiZ8/GLXSfkMNijwr7+hPI=;
        b=BmjW98j9h5XfedMPUAa9xzY9MWuMttHOxEORT8Z6/jXkWKA3Om+HJ2W2dZb2y5VDr8
         NjgG0CWNNSrewOBSvZBhzRwwnGlR9lTsZARInl4mt3eDz1alGWnZUA/xLhzKvIWgLbLf
         ZRFP+WiCO6AkF8sHoLH8UzgdtBVTngrMLzaz9iOrTTn8R8X/BGlHsfXtSoJtI2Mg+aP0
         WkC1fQbP5HmOLiaWJ2MPUOgsksQBGB9jy6gPdlOzbnMkYVt6kl0q203EKDU67S3wRMvA
         MGKgxbf2eAbZB8ua4A/qRbpwHzxZ4dQhm/qSSfk0TOTo8G8bLrsTw4wr4LXNogOyMjv3
         Ti4A==
X-Forwarded-Encrypted: i=2; AJvYcCX6RITMmnpSZ6wZb/IWf8RbYeXCbPVFOdBozmZkGnxvheEYh795tMjym0oseA8WVrSYFYC+Vg==@lfdr.de
X-Gm-Message-State: AOJu0Yx4MrAzF9BMx4NNjO6HfFN/DfqdaNe36hHQYR3qHSfxemKFVQaB
	glfGtbU5C/eOzJGxe4VJRNsqpLJhZ1yZSXApMpxkf6G040DRkP5L+CHk
X-Google-Smtp-Source: AGHT+IEUfvZH1C6y0r2McjllISbovbKrCGWVvwba55TjQcD5ReosJcuTRTeQnvFGE9qMxjM3nIor8w==
X-Received: by 2002:a05:622a:1a16:b0:4b2:8ac4:ef58 with SMTP id d75a77b69052e-4b2aab438b4mr280527631cf.79.1756332208907;
        Wed, 27 Aug 2025 15:03:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZffFWrUceE2o/jhgW21lmqs4uAWXoliO4Tfvuc6xF83zQ==
Received: by 2002:ac8:5895:0:b0:4ab:825d:60e7 with SMTP id d75a77b69052e-4b2fe86dc86ls2303381cf.2.-pod-prod-01-us;
 Wed, 27 Aug 2025 15:03:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcw9tb1HMHE+ra3ex8r2MHdTX387WwR352UbYfBJfv788MLg8nkMz0u7qyJ8yThh64raRFW1WxOz0=@googlegroups.com
X-Received: by 2002:a05:620a:1a16:b0:7e8:589e:1724 with SMTP id af79cd13be357-7ea10fcf86fmr2648418385a.27.1756332208021;
        Wed, 27 Aug 2025 15:03:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332208; cv=none;
        d=google.com; s=arc-20240605;
        b=Rw+V+qT8y3dAhBihRjpGKey7zvZ0AkUxJs6owh+xlCuTHbib0ZVCXIoyqX/4aTul/Y
         BNHU3NPBCnNkvY7AbrDMTaI42cJ8Rj+JPK5N0JlEp9NVJPlzPuu8WOmmD5qS0ml8ZGaN
         /oeSYERUHSs/EOUl4beX++5jB8Rb1Wrsclzk+MUJB+Dxp2x06MQSjvlhnvcyLgfinNUk
         LPS2BDS6kwNkiOK1ptpXC85S1yL06aUIo4cxzfjScZMyoDmL8H+phxnvlJDN2V16y8WV
         tzLGzGQ70O51UoTw4B8YzbO7YqnGEjX/nDg0SyOF6Q7CRWBsSIy+P1Uzmbw9qfn0LxnJ
         6zbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3wE/qMBAOI7UvFOFlFaewQkiF5uwI4kbjc+EesVZbC4=;
        fh=aiQn+/xwIuboxtj+ePrvcxeDN+/FHFxsM//q95xpK34=;
        b=YIiz53okMS0S4wZFPY4mY2QOspkW/kOUoxIPsqrc15NMNrvSWCDOumfpQZtlxKfjuL
         GzPLaA8lHMXQJ0exufJMxB9Kvhd7gX71xkidNBooKTljCXteywgfC5C8F6V4TTXnDX6o
         VYL6+8wNhfoL0TsgNUWUmqzBqT3/Za/n4rydmdWUNvqSoytrajkStGdZ5sQsSc9Ws9U6
         5ITdfFGSJDWSWmWQ+fmUlapk9v9PMiXNNkyun+/ukSLoAb0+rcR9yBix6kV3iYtlYviP
         PlUVZbVQkCYIq+ZV2aFG9yQCnXJrZCL/IOn2SeQWMSpY+K3a5Q+rQIL6MzGyC/wGKP7a
         soAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IMBUmo2L;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8c4f53dsi484771cf.1.2025.08.27.15.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:03:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-48-aWxloNfqN1GfaKF83zeK5A-1; Wed,
 27 Aug 2025 18:03:23 -0400
X-MC-Unique: aWxloNfqN1GfaKF83zeK5A-1
X-Mimecast-MFC-AGG-ID: aWxloNfqN1GfaKF83zeK5A_1756332194
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 931F81800352;
	Wed, 27 Aug 2025 22:03:13 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8DC1330001A1;
	Wed, 27 Aug 2025 22:02:56 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
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
Subject: [PATCH v1 03/36] s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 28 Aug 2025 00:01:07 +0200
Message-ID: <20250827220141.262669-4-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IMBUmo2L;
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
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Sven Schnelle <svens@linux.ibm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/s390/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index bf680c26a33cf..145ca23c2fff6 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -710,7 +710,6 @@ menu "Memory setup"
 config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_VMEMMAP_ENABLE
-	select SPARSEMEM_VMEMMAP
 
 config ARCH_SPARSEMEM_DEFAULT
 	def_bool y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-4-david%40redhat.com.
