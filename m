Return-Path: <kasan-dev+bncBC32535MUICBBHHZTXCQMGQEFOPMBEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CF036B3038F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b47174c65b0sf2598411a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806877; cv=pass;
        d=google.com; s=arc-20240605;
        b=JQ1enyK+792irt5/dLXS6zs97s6vOUb3FTsW98+tCKk65pVsdaNWNXWXETqit1NwS6
         mqYRaEM3Hll6BlU0yCYE5n0frymtUCy8Rzjeia1RvwRLSnQbOchnxOceC9nCegQhJS6Z
         djlHdaL8o2V9c36a4gBpV84iU+r66FvjiERWOccDLweVYndMSO5KsoHFjVOWRFI5Uye/
         QpLIzk/ftfbZ1R5PYqQRz9CYNRXgxpzoFHpbJWefKyCd3pqNVSuKdMVIY6h8h/2ug4BI
         59nYRj8KVPJ1FQkeZJUQkhqsSy2Isy7Nj76iZ2687bLCP47xOruM3hAY5cPxHMbig6Yq
         4LXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jcFt7uBBPjkUArGlIyWOgsDqGJnH269tfmoF9qoJUSE=;
        fh=87Fppqq1tCqtDaleX81fO7RanLDGhdcHZv3lDKkwxhU=;
        b=i2/SDaZvh+YveioeJO06k1W7xqbN3wBIPx9hDIcsl7fNlheWKLniIHOeyxvX/Dy/jP
         UBS6esNOv2UpDYIAzFEyMWwQR+dD2ydtugRElHZKc4j8ai1ZlY8iueKCxn7uzSzjeILs
         /rxs/SBFU0IzY3Nym8+5wP6Cq6F09zeh5S5e/V9Ax3HvhbVUzJDXo2U59SK+Zy0509vb
         EBtuKhgGLk/U93iDoxpi2pztChCzzwLH7wJLmaCxVi7YI5ODEZ5Oz0aEePinQfQDf3oS
         g49FpHRdOmQJC+eMGP9yaKL08oIsAfAVmb0ECK4A6y4ADb6uQWJdcrZqBhvV0qQ2Svng
         g0YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gw13t9nD;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806877; x=1756411677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jcFt7uBBPjkUArGlIyWOgsDqGJnH269tfmoF9qoJUSE=;
        b=eLfk6EW7czmFl3kgx8L9pOdk90aKOH50jxIDROLFpedq6C+5AYwsy2XzJ9HnALmOK4
         rNLtlTjMn4HvmEDMgMG826JtcF8z5tcekwyUA9Aw4kgU8Sd4qjqCMF2DMH1CCpHALXmY
         yWKfyI+dwyu0HDjORKnsY6QWL2cFEssG/iJjEBbIZHHjwbAU3Z2ENY1p2EqCJLGltSg2
         NLv1OPzWtszHCqyovaapN+cW7mkaqm/2dHhciz0e1pww9johqTOFPFDxCW/p/t3gsYm0
         em52khPS70cobAISY7vttXBtX8i/eE0iJL4w8JEq6qCuSvikGxKg8fJZk36AZRzijxVl
         ll9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806877; x=1756411677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jcFt7uBBPjkUArGlIyWOgsDqGJnH269tfmoF9qoJUSE=;
        b=Y5VHPYhwexoVv7dT+4hytG8VUTZAT9eFQPmjtZARk4YV2TjCqoFA9+9EcWAVsTgBbY
         W3INVxGMtT5D1anf2yGTZSy7HIoSME2UIxcFxvZtJbtkBdvlbk/b0hbL3t4YRLHZVsJj
         DGwe46jMshS8yZOyxJ1aFdHeJ6dKxdQVhyoTKENCL8eDZcgOIKaAIdlq2iwnFlWLtXz0
         lntrqIZGNMai/47STcOYFL0X/TQxEDw71iDVuFjQPOiuDfFy6KkhQtAMizK/DhqovBwU
         s8P08Q06RN0Jm+unhO5TKK1NwslOxpS1h+JpfGNlp3UbXGxVibqPb/rkykSIv/3/IXPB
         0hvg==
X-Forwarded-Encrypted: i=2; AJvYcCVrN8qNz9CNgX2N/ok0BZ/k16KA9mlGXjOPzRSa/LmrTmg+h+R2VMkEKAaR89LAK+E22x8PgQ==@lfdr.de
X-Gm-Message-State: AOJu0YxHWjywe/bQKftw2Bwz82HMyOHOxSMEREL+fWUh8xHELGEh1wLE
	BpMPHQeqqq1wFIv+TgZxQnqH5HnzzoJga/dG/9Wu2eBsc30JHPUwOG67
X-Google-Smtp-Source: AGHT+IF6G3YbYyel2smHYANmCzFcVISBiuImIZjAQhHxy0/YCKrI/IMyvS7g71NPHHvxMyPem+0Qrg==
X-Received: by 2002:a17:903:32cb:b0:238:120:134a with SMTP id d9443c01a7336-2462ee7b633mr7149275ad.22.1755806876758;
        Thu, 21 Aug 2025 13:07:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdrODWws+xXendqZbG2ecksa2+R1811Uqz3XDd4hPiIYQ==
Received: by 2002:a17:902:dad2:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-245fcbfe918ls19328595ad.1.-pod-prod-03-us; Thu, 21 Aug 2025
 13:07:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFZzW2tViFtinIGRVIt81pf9Kw7Mt0hDlq/hnD33BOb9kzTZ9QQJ4eFZ2XfjwWYDlRrw9sUS+zEgA=@googlegroups.com
X-Received: by 2002:a17:903:230f:b0:242:8a7:6a6c with SMTP id d9443c01a7336-2462ee59160mr8254175ad.17.1755806875222;
        Thu, 21 Aug 2025 13:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806875; cv=none;
        d=google.com; s=arc-20240605;
        b=BVFMEBGd3f5sXhM9X/1yTM+rK/aYAKHEMRKzikYuQCJTkBjar3+VwPjFRmhhLmNKJh
         cSUZII9PUWuzN9v99sbsE9H41MKPBMaCx6shccT/eNXOtuErQCwHBI+B2mDfGCxnN769
         NBZ4TvXXTFHZ47V4+TuaX5H7C2Pah5o51Id3ydFk5Orw1+zkqwOt1Ma4dczJRwrhXl/7
         CNbVdqkhE/rFeP1D1odQ6xqXJKLVrQXxGUJtMFEsn7d4k0oqbX0H43zXUiYiT2O1BIv4
         84cXI3ZM9eIsPRRqBqaeFRTESSZ9BTiJiPFJY0q4KB9DwZ3P6l4dUzmrwmc1joKLOyWL
         cjdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QCvnB/7xI7T/4p4mwWx/D4+W6s//h9G2+oSyfbDOFZs=;
        fh=Aeof8WVLAg81iY6mlU9kjXlaSOG2n0/TUNmp4zyaQKE=;
        b=LYDzM7rzLjgVoo/HQs4wUZ1lwpMsq0qx/BAxe85YpUZ9r9DYmhfVQjkor+yYOJIBxs
         DilRx9HMmhZXslKPpKn45+YXI7sQYRniJacYENETWKHhgmP5t5+NhMbi/HAqlmiNZ6Co
         JQudvO4XJyG/G5Lee5bjsAv/cxo334FLTPGQH6BRAD478cc1o3AZOZAvTjeUt3P47BGZ
         F/1OAH8zcAMR+pjUBEtdhjQVAJW8dcZVlWIV3/g3rlCpraTCzWrwZ+5Ugeb6bayrGI01
         zv6Kq7NL8AOhlspQ+uIBS/4wd58qhgIemJd2+46zgRLMDknziKbFGsGx5eqUqmIkVYue
         3tlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gw13t9nD;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-245ed44d7bdsi2262125ad.8.2025.08.21.13.07.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-625-Jdd_8SYdO6q7x4UZa20Mhw-1; Thu, 21 Aug 2025 16:07:52 -0400
X-MC-Unique: Jdd_8SYdO6q7x4UZa20Mhw-1
X-Mimecast-MFC-AGG-ID: Jdd_8SYdO6q7x4UZa20Mhw_1755806872
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b05b15eso10519505e9.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbkpNbMynpYCqzjYqFLUBSb+nJ0crBBVVSCUrYbC7T+vvLTRBi978F5MuETx4WSvRHamiQcIcEd5o=@googlegroups.com
X-Gm-Gg: ASbGnctvHH4VzYp9hzeHbWoVFY4IKe7w7oLvphJGwK0mjaW4hlN16T8syIXUvIpUIk/
	Ousqp5qUhiSpEREbWEaI4u33gIfTViKMAh5ZgfOqIUC9MDNxWY3VwqzDGbeJXOQU+F1bZfz8PS3
	HoP1X6103jW8+tmt4G5tODDcN4hR3hs7J6OmwWMvaUMYZSew1SagjVLegGcggDtqpEEF5IQY6ew
	OPgM1Bdit2NFuN2OJvEcSvgrq6kRePb0veBLgs1m9Kzu0K5DAhPOvXdSdA4iQVW9jV3yhiywn3o
	wHl3O2PUa2N5fttMRbdRvbCPyb9XWav6LU/TC0joOJH7lpNKxAdMTOzo8u1kBQvltw6OGAPLhUg
	N0VPW6I3duYyjYZ2bMaab3w==
X-Received: by 2002:a05:600c:1d07:b0:459:e025:8c40 with SMTP id 5b1f17b1804b1-45b5179e897mr2278965e9.10.1755806871594;
        Thu, 21 Aug 2025 13:07:51 -0700 (PDT)
X-Received: by 2002:a05:600c:1d07:b0:459:e025:8c40 with SMTP id 5b1f17b1804b1-45b5179e897mr2278575e9.10.1755806871147;
        Thu, 21 Aug 2025 13:07:51 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b4e1d77e0sm22159155e9.0.2025.08.21.13.07.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:50 -0700 (PDT)
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
Subject: [PATCH RFC 16/35] mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
Date: Thu, 21 Aug 2025 22:06:42 +0200
Message-ID: <20250821200701.1329277-17-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: FUtFzr7ZV-bYEYT3UutwyZgT6PeegXlkRVAmkmX1KW4_1755806872
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gw13t9nD;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-17-david%40redhat.com.
