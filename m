Return-Path: <kasan-dev+bncBC32535MUICBBC7ZTXCQMGQE5MTVQKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 808DDB3037A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:40 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70d7c7e9732sf32477966d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806859; cv=pass;
        d=google.com; s=arc-20240605;
        b=IPCyuA6K0fDNqgyj1grtZWmcb4XPY7Nj3XcJ6fvqN+8U/cYe7H7PrdN4Ej/ogYUAWl
         3KFKCc+Osiciny+g3YCC2bGykNlgUqHGE0M93xql0VDNhJmprY4GgbM8K31LY2xb4Ndi
         Rv1DUKiGLck5ixvLiGelRri30IXGUWW0Um9/kHIC8IxQp1XknfZ7ChfWUWr5J9JrqUIf
         oNAxf82lZAIN4a1YimCe27tb+y0dmxH686Ao9eBtAWdaNGn4jfLoxMXab4tHEtWkV74F
         0pHNIIe9M6qyKg10gZ7CkdK17OCAJNbyXjAGxf5QbZEVyDafVL6Uow5zTWVugUZa1JQo
         fO7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=O2+xKFXr+YA7nvrqLMS0hP1AA2R5QNPdj04ByLWo2WE=;
        fh=7cSlXG0tqA3PUfoNdIk3g9/7bSsUJRzvqb2h44evvvk=;
        b=FwSWu+3degAgKZK0I0m0W3lA6Y/1K6ONtjcXaiCJP9Mh5T/Po0mt7UrEyHWvzAjpng
         XwhZIUK9dwbWKUTkczICMRpLfz7A7PhpVXpbrXMZwI8rDq/aFTF68+6LoVFa7C5pLMc0
         p1o44+yaQqxEuIG058mdYnXRzY+jKIBUqJI0NsiqMO9QZaXwk95Mb2u6L1PC4+BfEYYr
         /O3O44VTtZhqbk+Gv6iL8FHiCY0xscbAv++z+E/payv3cltG/8vNiJdBFDHxfTRg3Lc2
         s3f6mDR9UPsTROT2vuyl4uh4yKkcN2PAdobeoshKXN0K7ZTxdbwqauvcImYYlstvLefN
         0msg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Wfr3qStU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806859; x=1756411659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=O2+xKFXr+YA7nvrqLMS0hP1AA2R5QNPdj04ByLWo2WE=;
        b=Ex+5vOhYAUcKLcEo6YVKon3wfXFhQzh5m4P2I+BIr1tolNQozjHTcn3IC5ltzLiimM
         zLSaGW4H0IJb++q+dyr607ONJ+JL6MVfzlwtbKmjjvTGhdalp6v+E2rWo04p9lOkDsj7
         NcLkgqI2wSSzd4NdpK8ohxQFrcj4NZjR3rbZnJ8cWauZgM+LPnZmnSF1SkZBW3RMJWNA
         CxMXKX+uYiYlJDU38JE1gqYR4l/+y+jISeGHhIUUoaMBW53dVD8EkfCvk+n+HH/ab6IH
         wkZdqbpycivJHhDBTyvMJ0AD6hqnDOKaFWg2FBTq3KG1Vp51Mc8JqrLzNe0qKDHIEFk9
         9qBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806859; x=1756411659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O2+xKFXr+YA7nvrqLMS0hP1AA2R5QNPdj04ByLWo2WE=;
        b=wnb5RpE9Zcj3dNNGC+fbTG0MEvHZElKu2CwB6PbFcx3VQnXMGOPF/8pIjdkuc+7NT/
         aTl0DaVE8Z+cd3c2XrIBKzD706jKb9c9MvvWP7a/fCJMpbsluuPsJzg8I5ljsy4fZBpo
         g9xt9tu0nNOe6WCxIz2vFcflai6ar5/Gt0Fh5rGG3F8LiUDdHouLU8+dxZMoBklPN2Gb
         F6bbqhvXKlUBofT+YyiD1Xt6f+e98oUHz5NAH+ZxX+TKTMEGiNrRrF9y+asDDMUAGv3e
         7IuFoJU+hxCQJpGTAy1BZQBKc+Y/TaWvXZSlbR3lWnPsC55dKxZJgmaQoR+GjulAdt/k
         BOSA==
X-Forwarded-Encrypted: i=2; AJvYcCXYTyn7BLzBTlHupB34U/4q5cv3N6OYK+5lLmVTdD6QETwBjJ0HdAW7bg5z0ioMyVy0l7WSvg==@lfdr.de
X-Gm-Message-State: AOJu0YxbmsoCFZ4/rNp6eJnmpIo/X0J/Iw+oupME0CSK7EMDtVrdY1L3
	w5yEee6RkCAez0pP5nsjeprXkPk92HgqAFWXJFmAtnmbUxFdTLTFrRcb
X-Google-Smtp-Source: AGHT+IHCxOeTTPvFCWU2GreRDhSAJGbk4nfbXSKr/1wNKbz0Z5K4wNt4uiWv9NzxmV/yWJX5cW3OYA==
X-Received: by 2002:a05:6214:d6d:b0:70d:8d5d:59a1 with SMTP id 6a1803df08f44-70d97205d99mr10836806d6.45.1755806859205;
        Thu, 21 Aug 2025 13:07:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeVHy+wt6rwQQPT7zvcZA7EOL+WF5YanmAhkHN88X/W/A==
Received: by 2002:a05:6214:f0b:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70d9522245als7916276d6.1.-pod-prod-01-us; Thu, 21 Aug 2025
 13:07:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTTVoHDVvSJ2uJQPiBEMRsrjybPPFIIr2nwI3QmcKom1LPhnhuu0rJygBdTya1JgzuS4GUgXj3LlE=@googlegroups.com
X-Received: by 2002:a05:6102:6886:b0:51a:4906:f196 with SMTP id ada2fe7eead31-51d0f709e3dmr167026137.30.1755806858222;
        Thu, 21 Aug 2025 13:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806858; cv=none;
        d=google.com; s=arc-20240605;
        b=bDOXtRLVsA0+J4TLJ3SrEHuUwh9jkoVLToG4ISqaEsVnmWhBzxCQ8cS8LL8M94Mjc/
         CMyhZliHBuZHAA9cuDzmoZsx67STjcVO/bWh/1T9oyx83usK7XllwaSDto8nuSjdPyC6
         XNxnn6IIzyta1ToKhVtlzM/RNkF/61dpY0VSTcPziK3SDj/08kudipyxV+PVmXCEXr3H
         o/nyIO5+4CR4NTjaYhbL02hX1DJOjlfi+V61EPOA1AC/InT/naqMSRmgOtDnmbkdHC7V
         4EjrW0N4doUcDrw2dFAmPIZalN9CS/0Ire3p7TizSkeykXzntfAi/US7a4M6YjQSFq4P
         azow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=r/kmddABpvZJu5K+QD662cz6jOGE1r8xokeQdlRgepQ=;
        fh=NTBzhfcpfzRZ5S9YXfblDDAUr60gvsLOTiqqiJRZcQI=;
        b=RY7+jmCOPwImc7Z97tX69/cFLxAymuC/RQLtwBynM2Nqx7SB2fhR5AEF9xBiNBsYeW
         VhB0Dmr74oDs7i+38DBPxiBYQjVcL6YtnxvSLP51eMnki8/f4XSAMmnm4E4nGz5Jxtgq
         mfE9aS8apf9iiTCGcJnNUAQyP2bffuqZciGCfyCfYPh5zXKiSOrIGU/fd+w65OKqIgtu
         u/2nSjbQ/DKdP58ehN/2zvo6CK5QrKQgJsUbb40yHOfzSMWSEgtOczuIlifLncjKUf+I
         vmLsz+t3tfUJo9zlw4rGWgythFtSdUbyZhsrbRWYQ9DqQRBQsnhdq7JcPJMMD6/JC8qC
         zWpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Wfr3qStU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8920cc869a3si112321241.0.2025.08.21.13.07.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-422-FWVHJ2jrMoSyMssce9G4fg-1; Thu, 21 Aug 2025 16:07:33 -0400
X-MC-Unique: FWVHJ2jrMoSyMssce9G4fg-1
X-Mimecast-MFC-AGG-ID: FWVHJ2jrMoSyMssce9G4fg_1755806853
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9e4157303so922418f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFDxfiZFfqPCNxybK43JlCerWeTi7Kk/Z4tKx1KnIY8EDggjRr87RJaAAduVk4gnGgqdP6oxuVTAI=@googlegroups.com
X-Gm-Gg: ASbGncutLZJCsQQzukhWycrR7hNxPzoF2a05lCjsP6ZfEqehteNoXN/4f0lU8SbkOr4
	u6T5MHn1VHh6YGpWfwiyUlCNO0c/uIOPJPgn2rN4/0XUmjLMXX/svewL2zlg3cCoW5fuYAK9BXz
	ycPEZx18D+0l4gnqxsSOvbvciMVOqC8hMFsFFY/KUrCDm8p8b8G+1v0s1U/ltZueNiKVGOhfqg2
	z1K8WTf8igyDxKkHp/88+4fcFQuktcGosckpi+rlh0Ilrmpxqm/P9xkHDopUrvhvJEnTEdM5lJ0
	unswH2xsagfOK0VDYuXQJKZOPlXY4ttwuju2wBq6zDDcvhosVR/hFmDs/Vk3P2aSRgnXeoECuJO
	XjqUZDLYYM2s27mEvAdpDEA==
X-Received: by 2002:a05:6000:2dc7:b0:3b9:15eb:6464 with SMTP id ffacd0b85a97d-3c5daefa9e0mr244717f8f.15.1755806852625;
        Thu, 21 Aug 2025 13:07:32 -0700 (PDT)
X-Received: by 2002:a05:6000:2dc7:b0:3b9:15eb:6464 with SMTP id ffacd0b85a97d-3c5daefa9e0mr244660f8f.15.1755806852102;
        Thu, 21 Aug 2025 13:07:32 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c077789c92sm12629958f8f.52.2025.08.21.13.07.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:31 -0700 (PDT)
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
Subject: [PATCH RFC 09/35] mm/mm_init: make memmap_init_compound() look more like prep_compound_page()
Date: Thu, 21 Aug 2025 22:06:35 +0200
Message-ID: <20250821200701.1329277-10-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 9yq63Z574r79J-Nx_d-63xGumaQ6o8KTyPjwKOwW8us_1755806853
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Wfr3qStU;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

Grepping for "prep_compound_page" leaves on clueless how devdax gets its
compound pages initialized.

Let's add a comment that might help finding this open-coded
prep_compound_page() initialization more easily.

Further, let's be less smart about the ordering of initialization and just
perform the prep_compound_head() call after all tail pages were
initialized: just like prep_compound_page() does.

No need for a lengthy comment then: again, just like prep_compound_page().

Note that prep_compound_head() already does initialize stuff in page[2]
through prep_compound_head() that successive tail page initialization
will overwrite: _deferred_list, and on 32bit _entire_mapcount and
_pincount. Very likely 32bit does not apply, and likely nobody ever ends
up testing whether the _deferred_list is empty.

So it shouldn't be a fix at this point, but certainly something to clean
up.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/mm_init.c | 13 +++++--------
 1 file changed, 5 insertions(+), 8 deletions(-)

diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..708466c5b2cc9 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1091,6 +1091,10 @@ static void __ref memmap_init_compound(struct page *head,
 	unsigned long pfn, end_pfn = head_pfn + nr_pages;
 	unsigned int order = pgmap->vmemmap_shift;
 
+	/*
+	 * This is an open-coded prep_compound_page() whereby we avoid
+	 * walking pages twice by initializing them in the same go.
+	 */
 	__SetPageHead(head);
 	for (pfn = head_pfn + 1; pfn < end_pfn; pfn++) {
 		struct page *page = pfn_to_page(pfn);
@@ -1098,15 +1102,8 @@ static void __ref memmap_init_compound(struct page *head,
 		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
 		prep_compound_tail(head, pfn - head_pfn);
 		set_page_count(page, 0);
-
-		/*
-		 * The first tail page stores important compound page info.
-		 * Call prep_compound_head() after the first tail page has
-		 * been initialized, to not have the data overwritten.
-		 */
-		if (pfn == head_pfn + 1)
-			prep_compound_head(head, order);
 	}
+	prep_compound_head(head, order);
 }
 
 void __ref memmap_init_zone_device(struct zone *zone,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-10-david%40redhat.com.
