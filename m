Return-Path: <kasan-dev+bncBDZMFEH3WYFBBGMGU3CQMGQELG3JYQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78545B327CB
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 11:00:11 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7e9fa5f80e7sf683821685a.0
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Aug 2025 02:00:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755939610; cv=pass;
        d=google.com; s=arc-20240605;
        b=fEmC4npe+g4l3BXe/q9WwhKy2xLxMq4fAH03HAeCJpsnMRdhbtrUy0GF7hRPx95kq6
         jXI3zLv5jOcAjQm2ahzOqfygDUtUNy8HnYepwCZ01+WCyP4AXEo7M+Y8exxwODU140pa
         o6ScdU1rn94E64ibweLnXtrC6e7EfkC+SERCnZkJow1ayfB8aq4PeFILe5LCq8/UupLR
         eufaT7N92mDQkpX+vOYrpRrHnVj1g1fdM8D6X/PWE1v2dCLh0D0Jn1rDBq1TVSI4Rd7v
         CNI8X5mk6Vf3Fp6DFRkFWHgL13aYzHlzUEDuNueXmA+XtSmGygZ+Lv8ggMTfUpLNcAOt
         zcnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=yA6rXPiQEiylox1M23IDOcq7Ig3hYFsfoXiYfhMi6iE=;
        fh=ADuDiFADpowAHzgcGxU1uLGOzPwYSKAC2kwCNx+Kv5k=;
        b=g2QXtTLH/sHJSrtj2BOrBLzrNWQrajUGnGj6eObVJnE/ox7oaF2j6+CGkx/xx/LeXT
         hk5OHnijj0Q2pGyu6kj4dOQ2NF97A3BnryR+cy5147FUx6N3ayYmnF13MN1Fq+vjJbcE
         WaKN3uIUeZExSStq4/odV8g/NjJpYcDR0ouQdBi/dpRMUX/Q9eCGO32Fq/RiKy5SQeK2
         bBbMczK9WnEDI+L3JCdxMVewsWa94vTt6Bu1oQtENaT2A1C6GBwHX1XiQ41z3ZPYP0X2
         uQP9K9tzBpwcdyC4WGeF78qqOB1bjjpHF0FMNOJ8x+DZMXFjs9HOrWwxFJR3ZA98O5VZ
         oNmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rOGkWtsU;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755939610; x=1756544410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yA6rXPiQEiylox1M23IDOcq7Ig3hYFsfoXiYfhMi6iE=;
        b=Zmhd4UeCnwwvSDnKmCVJcPGhDeo8Me+/PPZYhW5eA6A/LSekflvM5DeUoyzrblIyMk
         l4uDKkdiy8y1qB8nxFxKSJmOCIEDlikTZOWpjqMUdDIPYgJuOaEhqHON+raYrJyZIGX0
         1D1VqOuN/H/AngziQvfLqe4HdGGlLuT/FWy9YFPaFCehd11tu0NySgAwcLDK4qqivkA6
         JoQAMaU4ahkduS798rabgV0wQ0sUmri/hW58NWtB8LTXL4P0xc3SXM0w8uDdX6R+n0dO
         /D3rKTQfJ2bvcnfZsjdZIBIMn30rYUA350G7Ni08Kxj4Vna8sw8iOoqWcxfUqtCD3ELl
         T5XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755939610; x=1756544410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yA6rXPiQEiylox1M23IDOcq7Ig3hYFsfoXiYfhMi6iE=;
        b=C4ALx7tJWHWOem04pmdazddFU1FTFxhf3QvqvqAAdKP4GvEROZV1ClgGJTKcuVNimA
         yxiS9VfvfWtm2odVcyIyKusrZcrbR5VeSByXUDAk7GOQBmz92xd8Cq+7Zw9aHnFNCiCp
         f0FMnABkh/O12pIB0hKPbyU0XZRIDdBxEBqtMZCdQQ7Bu1b8VWQD7OVrH9auLvC9zAIw
         jH9mUw8YQlkiabVUlBJ8dANRf0IulSn3KXf+UZJZWvi3JQdH4pzF0b748DcA2un6cgG+
         ParkyYdv7YAy+fpJcOtREBA75dUNTn4w9Lw3NkBz8zDRE7Zo5UqhVmehrLAYdnpM3QK2
         hK8w==
X-Forwarded-Encrypted: i=2; AJvYcCVnXi+getFEQM1TvqfJBacd884PlCHckFsSQYfKF8seL1If5IJH+En3SzXlYwys2RkFA3DY9A==@lfdr.de
X-Gm-Message-State: AOJu0YxQshp5pgMXKYCnNW90kPqMfBlJavmulbwOl6hah43cusJuENk3
	jk2i+7qsas1FbVhOPDqmfOmEv9QBmUZFWHdwxtBxWs/M+tkGbSXnqh70
X-Google-Smtp-Source: AGHT+IFoBYpj8V4F2/XaEVnwBUXCWgqDgkwJFIPO+SYNTgZOVHYmLdmQ0pCYlnk1DzOl2AWZDElcdQ==
X-Received: by 2002:a05:620a:371d:b0:7ea:684:9dcc with SMTP id af79cd13be357-7ea10f88cb9mr661748385a.34.1755939609978;
        Sat, 23 Aug 2025 02:00:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcLvkYi/YpQiRuoTHevHnQfydjkv03wpnPLUngC01K7ZQ==
Received: by 2002:ac8:58d6:0:b0:4b0:7930:aefa with SMTP id d75a77b69052e-4b2c42c3a20ls447941cf.2.-pod-prod-05-us;
 Sat, 23 Aug 2025 02:00:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCkPdNn87CSZR6TDSzmgTfI52/Vu9VgKKmTh/u65fM2AFkp+fE8EnkiCO4x9Go+obfdJ636OU01p8=@googlegroups.com
X-Received: by 2002:a05:622a:24a:b0:4b0:7e8c:64cd with SMTP id d75a77b69052e-4b2aaa57eabmr75324051cf.4.1755939608887;
        Sat, 23 Aug 2025 02:00:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755939608; cv=none;
        d=google.com; s=arc-20240605;
        b=DmVpVds0y9y2Wn9gzfPUeZfcmcfbuNkpUE9Eva8jzx6YIR727SGPnsuvGl3mad6zkj
         jWho5T6/ROXW6QRiLw8Whx9ZN5I3f3PQKoqm7TUM1gJxnQsZJhDk1N3x6HjgcLrknIRd
         fJY+cT8x08E0igMdNQepOBbj1RPSRLOF+3Xbk6qd/5L3gR/FAP9BLDQz+1dnl+27hBYk
         PrWJJxY/DikU8OPRwwMQ6pgFmjtyt9KGzl9ziPYiqfvBZlQnqISO0vzMwcbTwImbHS/O
         /JglpmZj2nh4kLM02aL/1oId5Hkb7QlV+D/+xiAeGv/7hat8bhBZiIL1LwgC6bTw7Ema
         bxtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=A3yFDc62nC30c8ipPORCXl1/TYX9qFzVOp/OlRE3m6M=;
        fh=SnWEHMnw6q5A1i5gHssHZhjXePV2/MD17aPBvTeFLno=;
        b=PdXHCIL5FARfay7I0gar3W2HDPxGElJXvuHEhXETw6CQash8aOnei8I06LeXElR2oA
         5XtvAiKjOM8HJG7YuT65gKHLH0xDQfzywoUUztAbEPZ9yGXcOSOaDVEXZAxvfB58m6Dw
         UywJKnnjfitVjcWFvYfOkYdUJ0pHrAocPKurD+nikhDP147mhplo6e1gi4uHJ3bT+3cb
         shQWPazHSPymrNJlnBU0T3+yxBm+YoHhlRbTBmO9Aj9IdNGsmXw44BUl6DI/+loZ/fHz
         +kCw2Plwz0dZ4NQGmhLu5jsumQnlwguyDXNj/XjH8MA5QDx9fcYRHRGiKqeCfPvw25B2
         vPQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rOGkWtsU;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebf03c4a9csi8616385a.4.2025.08.23.02.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Aug 2025 02:00:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6ABA25C0FCC;
	Sat, 23 Aug 2025 09:00:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F35E6C113D0;
	Sat, 23 Aug 2025 08:59:53 +0000 (UTC)
Date: Sat, 23 Aug 2025 11:59:50 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Mika =?iso-8859-1?Q?Penttil=E4?= <mpenttil@redhat.com>,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
Message-ID: <aKmDBobyvEX7ZUWL@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rOGkWtsU;       spf=pass
 (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
> On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
> >=20
> > On 8/21/25 23:06, David Hildenbrand wrote:
> >=20
> > > All pages were already initialized and set to PageReserved() with a
> > > refcount of 1 by MM init code.
> >=20
> > Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, where M=
M is supposed not to
> > initialize struct pages?
>=20
> Excellent point, I did not know about that one.
>=20
> Spotting that we don't do the same for the head page made me assume that
> it's just a misuse of __init_single_page().
>=20
> But the nasty thing is that we use memblock_reserved_mark_noinit() to onl=
y
> mark the tail pages ...

And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INIT is
disabled struct pages are initialized regardless of
memblock_reserved_mark_noinit().

I think this patch should go in before your updates:

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 753f99b4c718..1c51788339a5 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3230,6 +3230,22 @@ int __alloc_bootmem_huge_page(struct hstate *h, int =
nid)
 	return 1;
 }
=20
+/*
+ * Tail pages in a huge folio allocated from memblock are marked as 'noini=
t',
+ * which means that when CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled their
+ * struct page won't be initialized
+ */
+#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
+static void __init hugetlb_init_tail_page(struct page *page, unsigned long=
 pfn,
+					enum zone_type zone, int nid)
+{
+	__init_single_page(page, pfn, zone, nid);
+}
+#else
+static inline void hugetlb_init_tail_page(struct page *page, unsigned long=
 pfn,
+					enum zone_type zone, int nid) {}
+#endif
+
 /* Initialize [start_page:end_page_number] tail struct pages of a hugepage=
 */
 static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
 					unsigned long start_page_number,
@@ -3244,7 +3260,7 @@ static void __init hugetlb_folio_init_tail_vmemmap(st=
ruct folio *folio,
 	for (pfn =3D head_pfn + start_page_number; pfn < end_pfn; pfn++) {
 		struct page *page =3D pfn_to_page(pfn);
=20
-		__init_single_page(page, pfn, zone, nid);
+		hugetlb_init_tail_page(page, pfn, zone, nid);
 		prep_compound_tail((struct page *)folio, pfn - head_pfn);
 		ret =3D page_ref_freeze(page, 1);
 		VM_BUG_ON(!ret);
=20
> Let me revert back to __init_single_page() and add a big fat comment why
> this is required.
>=20
> Thanks!

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
KmDBobyvEX7ZUWL%40kernel.org.
