Return-Path: <kasan-dev+bncBC32535MUICBBL7ZTXCQMGQEAW4P5ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 2651CB303A9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:17 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-7e8704e34ccsf454915585a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806896; cv=pass;
        d=google.com; s=arc-20240605;
        b=TXRJoIhMICuhQ52mlZ+a5P7TPP1nID10QSyVzgHnhOQfJxTscfZMZlOi4UlYVjtLi3
         sR1pCl06Kj5+sgrAnlrXZ8xyEuozb7fAx6haIRkCghFLqXqfccPI87hVP0mb+7d5ojhA
         3sdoT9PWIFUvD+0d+s45QiSDyvSQHj+KZ2PGY+9XAIrhJNlYRnI6kW48DLNQc9uC40V+
         fNrlEaOalikhcCd9lEYaJfpMS3ih7PzwxTUAX2Y7aCIHWM23qMtcfVWafcJPYYjj5QjT
         gxX/tb+7eWo+IXlInWtH9jfye7U5faXaI0Q1zrWHsW7JefoLhBakxEYydyt5DhG6zI33
         j/fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=9ruquGjVjQoSXYidcAb1J2FdCICmB253eXD6HiLO80w=;
        fh=De+upX8XO1YZHMDITO4EkjA+D8k6XtTvQsolFlxct0g=;
        b=BBiIpmjFpU44RdnPF+TCE3aLy67I9VMC5auFgGkgrEhvM6iAZP/mFSRg0MLK8CBgyb
         lvJYbLMunu3TlkGXsfVcmtfDKqm7PBU2mrOy5jb+vt6nAoTBh0bzaBPFL3y0fnbZ20w9
         GogDKydYf8DFt5OYxhr6Ukv8fMZyHTk7SeKjyVW0skxOc1KYrTanOhoGnk5xzFzkjKV4
         UR+TupoqDJ54cB44rlUVrDCMkf+y4ogcKiMjTuCVVlo13O8+zCyZreQWq9SwhdR1gq2W
         29q5/92E/sXV6SCQHolevlsVNE9gID/cq824JcMWznO/MgtEzSHk/mED5gD09xB0ObGD
         7tWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Asgvc2nR;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806896; x=1756411696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9ruquGjVjQoSXYidcAb1J2FdCICmB253eXD6HiLO80w=;
        b=VCiDyXCnIB/tnroEbHvp6xi7SOKK0ufMfpySrl6hjpSJHoGWTEj0nwTNRaflM9hMWm
         Rf0fROXPpqvgqy9dCLtVeiqOh9bpEvdJ7tXHFU/fc81Vz1GqTq7UbZEzFNhSRjlYqjP6
         ZlJXEPGtZ/MolJ4D2nsBGs8JOcpWzVOnsAu4kK/XEUPvkus2L9Sav2m+vZmconaJFL+4
         MRH6XsTj6OPCPWh7xyO7OdnkAb+bNPTOIRgMwlSgxf+PACrOi/ovkfUa9PKIn41tzVgv
         XlGF+T6z4dOV8Y0D2Bx3ffrBctgug9w/Larow1shJNJK+aCpU6/kWbaeQoQetvQFEHLT
         VORQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806896; x=1756411696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9ruquGjVjQoSXYidcAb1J2FdCICmB253eXD6HiLO80w=;
        b=hhJr+8FTo0/02pu1dgjdfnjAPeapu95IY0m8LPr9DRCvyOyk2a35JooirSBIrfptrN
         7I6SEQ9CzdxR5tQsDpiFe8mp7njC8FwomymFoMgaCkPR6UoL4VwbvY29RBzynR45rJKY
         cl68rXnn23ZmhIhW4IpF/3Db+eHkKSc02zoQpYQfOh4ib3yeARyhpF/XkZSURvv6Unkw
         ydMi/zTEuJdR4AI836OQkK8WTzzWOixtCvJTlnrSkyPq1JXplY1B1X9xCtI1/XsJXlM7
         MHUPX717GYojtcLP/gzMJNnKkva/QTXFygnQa+Pyo6YNb0N3IeR3GfCPDuEs64ElZGzL
         H+Sg==
X-Forwarded-Encrypted: i=2; AJvYcCWczhI01OuCncNHgMoJ8QlthBrzDUhHHL++bekcLmUVrBdXobVE67whojvXS0A3xM23KTgQhQ==@lfdr.de
X-Gm-Message-State: AOJu0YybfdupfWK+DzUjVRXe9GxgH87BHSbjaXOuVw9kZ8KA1uHC1iIS
	veT27cqf1cKOnUpNUfJTBXwGReLN0aTi9fHvhlvDYB1gbs68zqn5WsJX
X-Google-Smtp-Source: AGHT+IGqX9CUewuzOTayQjEtcNCkk9NrHKtqGAN/b4O6KBMMbgssl5uH6dQz1a7gcS6t9tk2Vu6AsQ==
X-Received: by 2002:a05:620a:4304:b0:7e2:c5ff:2078 with SMTP id af79cd13be357-7ea10f9074amr91337985a.37.1755806896015;
        Thu, 21 Aug 2025 13:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9YNqVMX6YqUmVn6bE++pge0mPn3sQCH32s3NSExWZ2g==
Received: by 2002:a05:6214:2426:b0:6fb:4b71:4195 with SMTP id
 6a1803df08f44-70d85cd6edels22595316d6.2.-pod-prod-06-us; Thu, 21 Aug 2025
 13:08:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxDaBsLffIx8jgdaaM1nh8D83TA0kiSwcSyOfsyDxKfuttztIpfBb1C1eZUCKLQYEy7DYySe+S7dM=@googlegroups.com
X-Received: by 2002:a05:620a:1a99:b0:7ea:458:e6e2 with SMTP id af79cd13be357-7ea110718edmr80823985a.77.1755806895031;
        Thu, 21 Aug 2025 13:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806895; cv=none;
        d=google.com; s=arc-20240605;
        b=hJdUHIBxlI4EUPDbrX4uxjHmzzn7z4Ai+lpo7THVDbkqO3iB1a7AB5zSFBY3Epu6JB
         ehD1UeCiXGr6XQrOUk5vJ4BItbEtJXpKhTJMFf3P4xgwXJyxPUvV8jzD+vVTzrG3ZmTD
         s66IXsHHqcSPFsQfK34AySoXW75+ujfjm7MInz7eESXabOCSOlBaiA9Ljy2NY7RY/SpN
         pMu//ESnKSy2oXFx2xAqOzGFManykqedTQIVHjpmjmekcTJLmn8tjMXmhwyhjwyGVSyf
         WYDmBwO44fXzR/qUIJ6tqmhVv0D8Sg4pj5tlJ1F8n8EO6JPM8vFm5KnID+2FAHolZ2kq
         n5Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NKFS9/TuG2v9AIcAoooIJr3bGKW6zmP0XL+5izT5Y+4=;
        fh=8WYysaxY3oVcGxDZsuhtEmu5Axw76lMKXpjsYFlV52o=;
        b=ZVRpmC/rks2qgfscSL1jYCeX33qW0Q56mDtQJzjNrlN6OBAaeINWKhasINX8ivURa3
         O+IrVB9uiEXkg7aoJ65vHAyt5IOm3uGERuhBq+SwQl9wAsbtNVvgLsqd6ZJ7WtmSMBKY
         IFwksAbY0vf1U4PFm9qbtzSqCIwYamKQfPl5dWbN6oqxij0VCYmkG0lnH2w3y5fYMdq1
         H/wMPORAK5YOwzw0iBC5JwkqKnzwBhvJB/9aROFUHqfIROuSYLKjRdhQ9iV5LdZkN6lD
         0ZLE1qFdlJ3CkIZZbFqdAtRjxA12ugFW5DWSyfinBBNd6vWrJCSckABlOdMgAXipmSoL
         5Tmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Asgvc2nR;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba91aa2b7si4539166d6.4.2025.08.21.13.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-227-KVgKqsl3Ow2RA0aWd7s4-Q-1; Thu, 21 Aug 2025 16:08:13 -0400
X-MC-Unique: KVgKqsl3Ow2RA0aWd7s4-Q-1
X-Mimecast-MFC-AGG-ID: KVgKqsl3Ow2RA0aWd7s4-Q_1755806892
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0ccb6cso6975095e9.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFt0w3Uf8/ZV434HKenwqPqfcKt0zzxv864eE2s2j9VwF6Vmbul1C8IrDsh+QYk10pABkTkmWZ8cs=@googlegroups.com
X-Gm-Gg: ASbGncsT2FpQoPJ7syb8ZL5Y6/Y4hx7DyTV6k0y5CBv99ErJxlrGR8xxsvPBbuf1610
	U4LFe49IFNkTwUSjzAsZumFZsKHkgmQQlWpmojI3xzEtOpGhEXc5V6xm851yLGbg0DbJ76nSMuB
	EGD7xqs+jtAQF3D15821DmyEoCj5ufhCvbl29YQ81FIT4YDdvxQQJk1b6mufxWCTuxBAkoWg+em
	72or5n3ZhbUCxMApcAEvw6TCSs43e4DQNNAF8mEYV4N54OAQpv0Vor6gPg1Uj3xkIMtNAfEgILr
	IaWuQvUt1U/UadovYOtnvwa12UCC7it6BHOYdUI590XZmWzywMZrCOjob6xRULMTeObkLIs22JN
	F7iXJJQ9ZnEsVlWJycXO9AA==
X-Received: by 2002:a05:600c:1f1a:b0:45b:43cc:e557 with SMTP id 5b1f17b1804b1-45b517cbee2mr2552445e9.34.1755806891757;
        Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
X-Received: by 2002:a05:600c:1f1a:b0:45b:43cc:e557 with SMTP id 5b1f17b1804b1-45b517cbee2mr2552235e9.34.1755806891155;
        Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c0748797acsm12277591f8f.10.2025.08.21.13.08.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:10 -0700 (PDT)
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
Subject: [PATCH RFC 23/35] scatterlist: disallow non-contigous page ranges in a single SG entry
Date: Thu, 21 Aug 2025 22:06:49 +0200
Message-ID: <20250821200701.1329277-24-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: rsUWAmxw8CZSwffBlEIefZdHDKoXQDRYh0yN4yOJ31Q_1755806892
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Asgvc2nR;
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

The expectation is that there is currently no user that would pass in
non-contigous page ranges: no allocator, not even VMA, will hand these
out.

The only problematic part would be if someone would provide a range
obtained directly from memblock, or manually merge problematic ranges.
If we find such cases, we should fix them to create separate
SG entries.

Let's check in sg_set_page() that this is really the case. No need to
check in sg_set_folio(), as pages in a folio are guaranteed to be
contiguous.

We can now drop the nth_page() usage in sg_page_iter_page().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/scatterlist.h | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/include/linux/scatterlist.h b/include/linux/scatterlist.h
index 6f8a4965f9b98..8196949dfc82c 100644
--- a/include/linux/scatterlist.h
+++ b/include/linux/scatterlist.h
@@ -6,6 +6,7 @@
 #include <linux/types.h>
 #include <linux/bug.h>
 #include <linux/mm.h>
+#include <linux/mm_inline.h>
 #include <asm/io.h>
 
 struct scatterlist {
@@ -158,6 +159,7 @@ static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
 static inline void sg_set_page(struct scatterlist *sg, struct page *page,
 			       unsigned int len, unsigned int offset)
 {
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, ALIGN(len + offset, PAGE_SIZE) / PAGE_SIZE));
 	sg_assign_page(sg, page);
 	sg->offset = offset;
 	sg->length = len;
@@ -600,7 +602,7 @@ void __sg_page_iter_start(struct sg_page_iter *piter,
  */
 static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
 {
-	return nth_page(sg_page(piter->sg), piter->sg_pgoffset);
+	return sg_page(piter->sg) + piter->sg_pgoffset;
 }
 
 /**
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-24-david%40redhat.com.
