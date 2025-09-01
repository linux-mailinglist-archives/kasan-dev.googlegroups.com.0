Return-Path: <kasan-dev+bncBC32535MUICBBQHO23CQMGQE6KU7GPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 00645B3E8AE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:09:53 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e9b92d422c8sf410322276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:09:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739393; cv=pass;
        d=google.com; s=arc-20240605;
        b=NLCXtCp4xZ4clJFs+kC7fCiMqXuSDxAQv4VPwaptIBeC/9NgOotKRULURh/fb3pooN
         kWvCaJmwljXB2KZ2lwO08n29OFpHH1vPWWzertIuuKHIKrg82zp3KIWjxZ2lMeUgiy/g
         mp81p8Ad0h2zBsYluZLTcgrIwU6rW38mh9j125s3op4booOG3llTXDJKDbRtH3k+2IFh
         UbjtLxYRF25a3GWJHg95iE/+TYdfeAf8Y/HTyrbCkxAK2fyF29FQGKrJFvBfv6soorSk
         JBgi+330VCGz0rCFvG/P8oPe69PqRAhagfuT5sH8I2ECVAqaEnl4Wx5mBl3hm6l2cthZ
         kAAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bZ6vZ1fp5Udiw21rRA6fXkKIXV84BNwLjL9cmH7lH8I=;
        fh=YpYEgq2Gz+6SdMVQ+OMwxErVTBmfq4bv5yJ/bKnM9WI=;
        b=K8y/qsSNulNIf9hiI56DneMvB+UO26JpxHiKGTAUKoVAXL5WofjT18psKGpkl6c2aI
         0yjcUGmgj6hPHqjahVQsHbd/9n69jA+f8SP1njd5IniJKq+VbavdfPKxsOppNzStSrN8
         zum4gQgjH+vdNZxlWFIA3DUZ1cevoRlL2UbtfiEg8AKunVATsJCOM3tCy4CqneHNDtEk
         +FDDW3Yj6VWCMdUzNwPOvhIDRTCefbBacz1a3ou/Bv5+d8t1835zc1TQspGIV4XbmV/2
         BqDQzSFqsXnJk/zqFIhAJbrgbaQzX3B1arC4HUiuyvJhM1vBzpTKqhGeSVe5buJuUCVB
         CNFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vbj5Orhh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739393; x=1757344193; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bZ6vZ1fp5Udiw21rRA6fXkKIXV84BNwLjL9cmH7lH8I=;
        b=rCFgAkn0CF18fFbQODlyT0+DZf2v46iiSuaVF0JLRvjU1KdzoMBQXzBVdNGAsTt8DW
         S7wRbiTq/9/6rlKaSPxxp6HJqgo7OqqviZvEwR4r8/FoWs4scCOa6UrbCj+yJ1K0mvlI
         /b4nrI7SAOqzvTEtLtWJRDGmi7av4ucFwAfzeAeI2J4JG4GCWPjd6v+9mgVSnjKdJuYu
         tJYV0UH7FRzOOnhGYemra3Oe8ov7IEP6bPVy0OQ9rgTPVgs6V/bo3/MOMT/a8p/jl9UF
         f8/3ERcY50F70AfQy2HXHiiLa4FbiAt0PqIFN58aOyK+H5gGwjr0vcSMZY1nJSO6w+w2
         CT9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739393; x=1757344193;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bZ6vZ1fp5Udiw21rRA6fXkKIXV84BNwLjL9cmH7lH8I=;
        b=LvnNMBPGSSOPiWnHly3UUCzTRo/WfmeRQQYgB30xKrbc3d6GSiypJqNIa7ZwTbZBBG
         zdqS2qtdmKInU7JnisjXaPiMmwFgUeQgqimjcUM+DNLP+8haBLNOnNZoHJY7jxhmKgUj
         Bqzu0ERFf3DB4ztMGgXnzBzTBk97VJ3D2XzeffexyPQeU6JK67cvTkkFCsRy2erUy+pr
         2jDjFtYqpDKPvVaLrtdRaIL+WeXION3zS7UEW9KmQboc/iQREotgmaO8Kp2XNyw9J6Sx
         GMv/f/xfMCpVwVPCpse1cBKFigcdRSVPdlIcN2rwVSRo1LAGsbZ0nx4AV9oRF73Dri0X
         yYgA==
X-Forwarded-Encrypted: i=2; AJvYcCXKDeQhhgShxMpddKK2AfMBEbBb6WylYTVFzIDoj92l1mhhSagZFc6BxXnpZy71dlVxITHjpw==@lfdr.de
X-Gm-Message-State: AOJu0YxYJXEyYHqHevwG+QPiXP9erF8yqCCj26RoyXtv0P5Hg9L++HeG
	VXcR4nwnl/svNzEg3nsFUfnHDfoEjl1VJyH7wai6/Y8pQ9eebkqNc3yL
X-Google-Smtp-Source: AGHT+IGHiFT1+t+UEs8pKuMyzqaw+c+bmXQ8P9xJ1s5uOhfUsy5+BvhvNZFJiVqT9xlHVO5L0tUkNw==
X-Received: by 2002:a05:6902:1b11:b0:e97:f18:125 with SMTP id 3f1490d57ef6-e98a575e3d9mr8762179276.11.1756739392514;
        Mon, 01 Sep 2025 08:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcJBPD5w9byJX9MhEmRUt1xQYgqZTn0MhorHsL52gjHow==
Received: by 2002:a25:dc11:0:b0:e98:a130:6d3 with SMTP id 3f1490d57ef6-e98a130315als2238060276.1.-pod-prod-02-us;
 Mon, 01 Sep 2025 08:09:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAxw8HqVL2GQKShUuxrowxMB01A2MToK4zzaz/WuikuuOhmV0xybURlO9BmiNXvVEBdi57yyser2M=@googlegroups.com
X-Received: by 2002:a05:6902:3d1:b0:e98:9646:21f5 with SMTP id 3f1490d57ef6-e98a58281e0mr8117168276.34.1756739389082;
        Mon, 01 Sep 2025 08:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739389; cv=none;
        d=google.com; s=arc-20240605;
        b=RBO87ddGA54xwldsl3MJOBHnS97Jbsxt4xvEc8BozALLgiDTSki+9//s0aOcTKKIr6
         4hxdekuzGP0pqpRPwr+sTsFmrr7LOQWV7Yw9VNVZ5vN/pzHNf5CL8iYQnM/hMsQLpxtT
         mYogbZFxgFeg0kvUd4SR+dP9wpFlQQVeHR9yS+IIBbblECqIShVu/nkgNfrhw8NuO0sv
         b2febVEC+P5mFoMQfw4ovoJAm5P+dgmUbqn1eulcxr9Usfdt6YPHTDMrzd/uKEtCAMVV
         82+y00ZN0SGPBD678nJl/bbSgl2CnWsEOVlqgiDdFdN0dRnWi3+dLJlNn3OvdvDtOlqz
         2Tmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ofhABKsmQsD0ka1l5H0E8RzWEQACOMy7wboU2BWZCLc=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=dGBMbcoH84zFaonqk2ApmL2TinqCmJmvOgOEdL11+7YaJzySEkBmWf0GzmOlZ3bAks
         p43HrRfJbyhfd9M9/Rh6pp17Vwxx+j30T2n8kR+wGFoWTwTUFJaYPSgGh86us7ayHKX6
         7smPTbsYuolzFSEVXtPRzHrpB1qrYk4nS8YIfr9tv7Md+AYcToY02nRWcXCTZpWRvXRf
         Nf4KtguOxLreU0qcDwiXmITIsm2ZjZupGtWvVQLfY76gINRxjdE92Bsu4DKfhh7hCMUN
         H6+D1XljhepYUWwVu2nSoQVJvOJ6hhXB+ukDTAQ6F+hONS6775TilkBgTacmvTYjUMBJ
         4PSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vbj5Orhh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e98ac2eea0csi209975276.0.2025.09.01.08.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-630-rpW4Z1WtP2m8xTNCro4Y-g-1; Mon,
 01 Sep 2025 11:09:41 -0400
X-MC-Unique: rpW4Z1WtP2m8xTNCro4Y-g-1
X-Mimecast-MFC-AGG-ID: rpW4Z1WtP2m8xTNCro4Y-g_1756739367
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B75951800378;
	Mon,  1 Sep 2025 15:09:27 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 79F631800447;
	Mon,  1 Sep 2025 15:09:13 +0000 (UTC)
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
Subject: [PATCH v2 19/37] mm/gup: remove record_subpages()
Date: Mon,  1 Sep 2025 17:03:40 +0200
Message-ID: <20250901150359.867252-20-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Vbj5Orhh;
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

We can just cleanup the code by calculating the #refs earlier,
so we can just inline what remains of record_subpages().

Calculate the number of references/pages ahead of times, and record them
only once all our tests passed.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 25 ++++++++-----------------
 1 file changed, 8 insertions(+), 17 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index c10cd969c1a3b..f0f4d1a68e094 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
 #ifdef CONFIG_MMU
 
 #ifdef CONFIG_HAVE_GUP_FAST
-static int record_subpages(struct page *page, unsigned long sz,
-			   unsigned long addr, unsigned long end,
-			   struct page **pages)
-{
-	int nr;
-
-	page += (addr & (sz - 1)) >> PAGE_SHIFT;
-	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-		pages[nr] = page++;
-
-	return nr;
-}
-
 /**
  * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
  * @page:  pointer to page to be grabbed
@@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
 	if (pmd_special(orig))
 		return 0;
 
-	page = pmd_page(orig);
-	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
+	refs = (end - addr) >> PAGE_SHIFT;
+	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
 
 	folio = try_grab_folio_fast(page, refs, flags);
 	if (!folio)
@@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
 	}
 
 	*nr += refs;
+	for (; refs; refs--)
+		*(pages++) = page++;
 	folio_set_referenced(folio);
 	return 1;
 }
@@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
 	if (pud_special(orig))
 		return 0;
 
-	page = pud_page(orig);
-	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
+	refs = (end - addr) >> PAGE_SHIFT;
+	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
 
 	folio = try_grab_folio_fast(page, refs, flags);
 	if (!folio)
@@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
 	}
 
 	*nr += refs;
+	for (; refs; refs--)
+		*(pages++) = page++;
 	folio_set_referenced(folio);
 	return 1;
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-20-david%40redhat.com.
