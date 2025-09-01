Return-Path: <kasan-dev+bncBC32535MUICBBQ7M23CQMGQEQFCPXPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7ACFB3E83B
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:05:41 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b4e796ad413sf2741891a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:05:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739140; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZLtGZYaGF/LfhBGgrYk/xVcmJ9nlrtF2vu4VgqPRxMwWaEBobvpi+KDkj5EVCvUU7s
         lWU0zQwcmNa1dNzqVfMqJz0NtJMPi/pzaRPlDY867uZ90JXakeDEZtZymLqQ4XFtrwkH
         h6wU3cn60LrdUaoWGigZQzYq1iDNhnebG7S3iPyObtbgQXCFg41pN6SEnccazHFlCJzM
         daVOvVBok52veZSE/IZa+cSLWu1ZWh/gA3qJ5dU1t7dmvH+Nmrm0YMxVMMu/vz5inTia
         uDg+qHRKBBLey2WyDjkrfKazdY3X5Aha3NWZMNvSmNlk1ekpHHdXmXI1BHl8MEv0xsCA
         Djag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=J4nXbNAPBhIZDV+OckeYm0vTvoL2KOaDm4UxMt4Kw6A=;
        fh=QceSYA6489JBSzGqW4b7oJfZssMi78HCc/SCp+ggWZg=;
        b=Q3ylImeZFcjHlY7RzQXdH3rHp/Bu/ZN8Y4c3En+XmQY2FPv0D7p+YXWjPJu10h3jrR
         84gxdib4IrDR0r3q7/oY8tleZ1ATCE8v9LnqAytjHoog7GXkGUH5pNou34AWf5RbSsKa
         jtr1G8lQPNIUclDmKEEOGQJHx2jx5laoTKGHglu8euL3wDvWW2JiyPvNdq5pMKsfgf2x
         vU1ZJ0AUYyDvDxj7l3PUCXNDAbcW3FaECiwRA5n2IGHk0rlxBi+BOdcKhXj6bfXGZSW3
         ew4Lne7i9fpMF8t6kAqJD3G3xyXHoouixal7q2jAQliAgvIkdM+NK8e54EcgQJKCNpC3
         41Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ODoXfTmC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739140; x=1757343940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=J4nXbNAPBhIZDV+OckeYm0vTvoL2KOaDm4UxMt4Kw6A=;
        b=bXP33e/bZehuBxEK3IfdkLt86CtLOgw32ij6Cxr4Iv2WnG7f4YewkTVegcPSdCy3Bd
         gPGgGzkwNTSDtmAFNOQ463EVp6uOrXJJ6Zy1S6JyKA+YKelVY9ke2FpkHI8WA0PRetAc
         FWy0Xpu9atN1F1IPKmgBGuXNcAed3D4rjf9wizkR9cGVdLKIgDOGMhTinFEMwFCx0GaI
         a879NHH34oXVT/I8AFKgZscsPQ0VQnAIFZBKOJJMYEqBzaHWkGE47+qfjPzMKk+t0FU0
         FrJBJy44ODFsu9uKjhBxQbrbETo9tVZBC1mViCoRKuqx70jkvsEIdyV2bT3tW2rYeyP6
         ap5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739140; x=1757343940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J4nXbNAPBhIZDV+OckeYm0vTvoL2KOaDm4UxMt4Kw6A=;
        b=ueiMLC6PwYjLPhLv0diVLk28zG1z+o33hIBEX2F3ArJ615noeVC2vDIr9qvB8PaWLS
         KALgpdOy3gBpv0pw6VNT0FQQTET/3iblJ5gFGNtZWRAC0/I01C9o85rYVA9FUK6vUiRL
         L18Pozk1GF350JSH7wYWnhVrL8qDssajCXHpW27csZpFv0yDDJ6UpYb1yN6UJSko/z80
         y8NpZdhaqt4jIOjl/XSQRfXdyVuA1wpnP6wAV6CvV8WPAejEuKVUB02RcVJzkqv0+P11
         jug3Nhsl/RRAv6FuvsVGEKfuc78Yt4WZM7lriFc1hL5w+B/Uj185WTON92FBHVx0JyWO
         Q9Nw==
X-Forwarded-Encrypted: i=2; AJvYcCVDkrg1sOJZP1E7njVOM40tMjmzZaorzHiTEglIKHZOu1AyTNcJczGbTcU4hKK78Xrc9MkRxA==@lfdr.de
X-Gm-Message-State: AOJu0YxTq/Yc4SONvcea6IeQLP3solG7iZ63Eq2qEpxNT2m5LA6dCQ82
	5f2dpFAmmM0vWznvr9BpZiXkOLuQPBbD0wiaewS5AnZPmInoRXNDqwxg
X-Google-Smtp-Source: AGHT+IGY0jkyvLlgN+0/hO91vML8U/9WPtg8M3OW8SwrLde8laJdwViSq/1HD/U6vAHrvtjat5krxQ==
X-Received: by 2002:a05:6a20:734e:b0:243:d679:7188 with SMTP id adf61e73a8af0-243d6f02a28mr12935487637.32.1756739139596;
        Mon, 01 Sep 2025 08:05:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwMpaArTevL6s47vm3YP7J06g/AKXIikFXdNInmOSAcA==
Received: by 2002:a05:6a00:b4b:b0:736:b3f6:6e6a with SMTP id
 d2e1a72fcca58-7722f755f6bls3323450b3a.2.-pod-prod-06-us; Mon, 01 Sep 2025
 08:05:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW278PaypSvFWRbh0eeiSyAO+QLBh5ZZb3QBko8wR5dKyTmtVRf+hT7w7a/L533ESVvJ9q9BCnPElk=@googlegroups.com
X-Received: by 2002:a05:6a20:3ca5:b0:243:ae10:2421 with SMTP id adf61e73a8af0-243d6f02e15mr11927441637.33.1756739137107;
        Mon, 01 Sep 2025 08:05:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739137; cv=none;
        d=google.com; s=arc-20240605;
        b=R51D4G1T5ZKmTIYPXgoEgvBAOZ8wBAbdQHA6cXlJ7FqFwdJdDTL0Fxo9B3pBPcXpS3
         fKtr7tn2KL4yOtBDAAtB8xDm5U47tSD1vNDCvBdWxIwxburU/WrS+wGgBJOL3LCJHkSK
         l3YSb8MYBndEH59ZULUTvLOhC0WE0XOy5Yw9GVHuzyMwS6Yublf29/rfWOvKPkvevEgu
         kCu1RTgWLU743ZLhQO73KEeprsdORXuJssWUlVnrX3WUF8Wvp8IsHYltT1SQmPPDiid/
         3OIt+c7CjWOru5hNmvXNN2NfI7GA7N0jFbvNk9J5XhZiHCFDq7cGtX1gm7i4Jvf64FEn
         TB2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vbF+Eclm8a76znTMytGJjLFZFrrqxTZ8tlcAavdISGA=;
        fh=+ox8c1Dzk3bfJ13aNRR2ip42/bbpN5/Jgaqicnyvmzs=;
        b=hP9+vLvGg6TnB9yJO8JVPkS0EzMi3u6x2bN9AemlQfeotgUIQprG3wJbdMyAihF8Vq
         wjUOkD4J40tHyKLYcauoPA4mdCdtBgm6GP4hlXJOV/pwvMxc2Z2Nx4yqnVMshoqtT0E4
         ptkidlweJ6nMtQy2JAovx0g7+Edq4f0RkmfzjNdOtNFlA+CBzbWiRFkaL/IFhgdAsvIy
         3t4Fgx5ZfLL47vZft/q7NKPtRi+6WXduHLSzLFkd6qIyj/Vf4RIErpQBFpK2cGKULyJ0
         QWoBangjuJj9LlKGLpf7rE9UjBeyibG9wUnzIcIh9ke2Q3u4oQmyJfL0fzS+StQ9mdHx
         4Apg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ODoXfTmC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c23si242838b3a.5.2025.09.01.08.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:05:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-444-EqzKMDgCOYua6LxcHPSp-g-1; Mon,
 01 Sep 2025 11:05:34 -0400
X-MC-Unique: EqzKMDgCOYua6LxcHPSp-g-1
X-Mimecast-MFC-AGG-ID: EqzKMDgCOYua6LxcHPSp-g_1756739129
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 3EC86180035C;
	Mon,  1 Sep 2025 15:05:28 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 3D05F18003FC;
	Mon,  1 Sep 2025 15:05:11 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
Subject: [PATCH v2 03/37] s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Mon,  1 Sep 2025 17:03:24 +0200
Message-ID: <20250901150359.867252-4-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ODoXfTmC;
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
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-4-david%40redhat.com.
