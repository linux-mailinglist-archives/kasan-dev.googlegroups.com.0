Return-Path: <kasan-dev+bncBC32535MUICBBHUDX3CQMGQECU5L5YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AB95B38C90
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:07:29 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-771b23c098dsf215232b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:07:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332447; cv=pass;
        d=google.com; s=arc-20240605;
        b=EVtctHJFMSTvkQkHciAXSTPm+PyFcQACXeqUIHzeWPl8OckBXlkXBLDxIFiaPnn9g9
         AqwiD2cCillZ/0TUt69BnAXxzv3kRQrV9LPgYX+jhr2hidqnBf11gD4TIMNtyQ78gPtf
         73voF0zlLPovDrMSgm1y5I378q1LTQAifWiyuz4WMp2EvsrD2nLA1RCSRKOCAGC0bCQ0
         56VLiV7dDWy2xqlBQ5al0KrQSQz+OijH7o0OvmXptJFT/BzxuZOyEDiC+DIEpU9qCzoP
         CgAXqN4CS1aY4tMIkZns4A9VkuEyW4YkADLuVY6ngrsl9aS8KO1UlvqApYW2dSs+aB3C
         AZow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HET93Sb6isSvy0X0VB5iVHsCF8bIKoWAHmH8SpQoW94=;
        fh=O7Ncvr9oXB2SzeJ7QX4Gy/h0hYp4wO9DRZKCltAoriU=;
        b=Q+CvQMssvvkT4VFXoKgowahJu7iSBj2pQ1MZnoSoAw9+4n9bphoYsXcNX4eAmAVxzS
         6W77SCF+GEvnUOvI3t9JrpRudswfhUQvATx2bis0POYP30mDNqmBjUyvo1YBHhVh05d/
         aL3Nq0D0h5RpjOq71pFnmKjE+4XDmIno1NtpDcnAwuCNkvNuRL0OPwJ5EFLYNUtDA6qv
         IRf6sKOPSEGG8+Jew/6Oyb85FpckAwH8PbTcC+lYPHWboP1iO+GpQFSnUPdERWCoJQ3A
         7lY7RvTrnhI3bz//Fr6T2/GsbV4fx1qWY/bu0GYuCiFyu/hDcjRniX4KJG+G4sL9KHR2
         G+mA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bjZV8VKO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332447; x=1756937247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HET93Sb6isSvy0X0VB5iVHsCF8bIKoWAHmH8SpQoW94=;
        b=c2gIdxvyYudu75gX7gn2fMTq46i+fQabjehVoNJQ8bUopUAy55ld1il1+IvH9i0lXG
         b3o7PdqqaWyC6PVOzCEMzR8zAMfCCzZ6c/1fcDjIdszzDUuasApV1vtnbo7DV9bb+bEy
         UTqvxgytS0sODRYtKG2fgYHqkRgpzqJ3tFz3spdyvdneuCVrKRCDMcMcSRfVihhNvPIe
         pMzoTTMpc8zg57QNX5k2RRAmRTFWOBFW3HjtLN796JBQ8O9XQnPRHSIgAywvGfgXe3AO
         2lqzfDgfcxkW5djm3shEojSX/8iFGqnDUe/ZHq0ASTj4TlkbiDLj9U6sS1UhZg8vt6aB
         5Zxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332447; x=1756937247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HET93Sb6isSvy0X0VB5iVHsCF8bIKoWAHmH8SpQoW94=;
        b=sP1JSK5YXVDaCPsizNtCXqtRM9nEUaAA/maUtPnaM3mbPkNoTOfJI5xmhMbH7/e3MP
         fg+b/Fp3SHPp3aE9Y4vE8ugMk/iC3aBhBDiMPRc9TnocRtqrGfk5PpkSks/uqDGRZuYE
         OHFVk4runoCAmYOis220ZLKI7MkMdJ3rblqpusI6zLGbRzft6I0VoR1TY/uRJjfm6PTn
         giM2vsGmcr/s4GrT8ZL4rrzLMBMJUKAzVfM95t+WmgefwbvrftGm+L2z0JljqocHIDkb
         6EIxIUva/YHINa/motrUvGKmCYExtuSNXCWoDC3tsB657C5jdmO5gqsqEo+OU+ZVh/oD
         Q9Bg==
X-Forwarded-Encrypted: i=2; AJvYcCU7885wxMhoMRBSP9TsVi3TyBVkyMOy8V8hOAZE7rta+SM/leJbLB44kbzsbMJJm3z39CgQYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy4Rov5dpTOGQGEHziKB09yDC224XqiNaqZDxg6vp+q8bMEYbj1
	r0Mzqnl/wbtelUewRcgmG8oMkrYH9PM8hbaKao7LLpXHCMK7KEwytVoL
X-Google-Smtp-Source: AGHT+IFEdAI23lmh29jV9wzNp2wqN1gX3P5yxSzGj3HYdsHPnOi+k/dPIdBiw7PSsQhfwakSlaKUeQ==
X-Received: by 2002:a05:6a00:b44:b0:771:ef50:346 with SMTP id d2e1a72fcca58-771ef50091cmr13333930b3a.15.1756332447292;
        Wed, 27 Aug 2025 15:07:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1WinnIGOGspwOkFbJhs9MGTHYmQGW6xYfDxrhgew8Yg==
Received: by 2002:a05:6a00:3686:b0:771:e960:9564 with SMTP id
 d2e1a72fcca58-7721824ae52ls137945b3a.2.-pod-prod-05-us; Wed, 27 Aug 2025
 15:07:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyOpEkCGdITnKOD8nmnX9AmOB7o7fiX985jLguK+w59X0oYMqueeVOA0kJ+EE+JcBuZhh1JaR8ih0=@googlegroups.com
X-Received: by 2002:a05:6a00:1896:b0:771:e7e0:5fa1 with SMTP id d2e1a72fcca58-771e7e065demr13211284b3a.26.1756332445804;
        Wed, 27 Aug 2025 15:07:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332445; cv=none;
        d=google.com; s=arc-20240605;
        b=dSAv0DJxQoorJdjO6BEUktfTAQ9u5TgKBTY9cLPMdYavvR3RGYZWf6SKY5HwDps1yZ
         hMPs8gY6XamZAm1V8VtL6fuJ7ymClGQdeOb4QxTsImg+5TdvVEAWGsJRfxvqbcy+znif
         QAA6Z+pCu++BQivSx3gAJFvHTv/Do+MN/slLj9Qn9/3aT5dmwG6tlqasfz5Vtb3I6y4K
         ZxwSGrUNBPSigND468vovQTbVxGewME409N0t1KfCxJI1duIh9QTtFaO58UqHLLcMiKn
         +q+aGdtrldCLe3TbVDEJzSFy84swMs42xvIpKP1cwhX4tgItaTnAb7bvced2qrJ5Z/KL
         GYOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mae/7n3uM/9R//Wdj7TtDbDkO9ysL6apaiu1QaIksGk=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=KJrnnArR1sSz4BWA0E7QeIAgt5qY5zB2+mALrwSfjXDUKdQo2AKf+mw2ubb4vhrZ9X
         zNh4WrDIY2KbMhTB5khv+vlZzTOgApC3EE7RnQaZUfJLOnKGgL9pvOYxga1/HSSFbd7O
         2gFBtsoJPFBnCwUyBk1gvM5vki1s38FUDKL1mLXIKR4rv6+UIZTLTfai8u8+068XWty6
         cO7TqQrCYBHi4zhi84eu+OPuZgIqJYzHo2wjv6Yah7ys9aPovruRoWuSKC7qq9e9Ef9/
         pKRtgY9NT5jtUs5JFpQSP86eXmJHLfFDfJb43JtXDxqT7M9BrmQQl7n/x8Ilvkhp2zuz
         dLog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bjZV8VKO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7720e184669si93814b3a.3.2025.08.27.15.07.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:07:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-484-meNFbt-4OO6MS1lMNpb3mg-1; Wed,
 27 Aug 2025 18:07:22 -0400
X-MC-Unique: meNFbt-4OO6MS1lMNpb3mg-1
X-Mimecast-MFC-AGG-ID: meNFbt-4OO6MS1lMNpb3mg_1756332437
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4DB08180036F;
	Wed, 27 Aug 2025 22:07:17 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 530E930001A1;
	Wed, 27 Aug 2025 22:07:01 +0000 (UTC)
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
Subject: [PATCH v1 18/36] mm/gup: drop nth_page() usage within folio when recording subpages
Date: Thu, 28 Aug 2025 00:01:22 +0200
Message-ID: <20250827220141.262669-19-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bjZV8VKO;
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

nth_page() is no longer required when iterating over pages within a
single folio, so let's just drop it when recording subpages.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index b2a78f0291273..89ca0813791ab 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -488,12 +488,11 @@ static int record_subpages(struct page *page, unsigned long sz,
 			   unsigned long addr, unsigned long end,
 			   struct page **pages)
 {
-	struct page *start_page;
 	int nr;
 
-	start_page = nth_page(page, (addr & (sz - 1)) >> PAGE_SHIFT);
+	page += (addr & (sz - 1)) >> PAGE_SHIFT;
 	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-		pages[nr] = nth_page(start_page, nr);
+		pages[nr] = page++;
 
 	return nr;
 }
@@ -1512,7 +1511,7 @@ static long __get_user_pages(struct mm_struct *mm,
 			}
 
 			for (j = 0; j < page_increm; j++) {
-				subpage = nth_page(page, j);
+				subpage = page + j;
 				pages[i + j] = subpage;
 				flush_anon_page(vma, subpage, start + j * PAGE_SIZE);
 				flush_dcache_page(subpage);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-19-david%40redhat.com.
