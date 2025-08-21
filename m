Return-Path: <kasan-dev+bncBC32535MUICBBQ7ZTXCQMGQEFAGSOCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id D27F3B303C0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:36 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b109a92dddsf42379331cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806915; cv=pass;
        d=google.com; s=arc-20240605;
        b=XFUwCpxlsMwHn0gVlTHQnbRtG3Xl28tLyu7dEPHDiCTqK9HZYb2AKQSIQwSjfSvup2
         5fFU+Z88MGVAqSJgNvwv0RR046ZsE7S/dsHpMnkZIvF8KeDzp2LschlWxuadDF1Jvc6f
         /V2ryv2f9LTOPUjaprY8N5Zd+3NenDiq0PSQnaWYNi/cV8Iq0muqZFtD5U6YGlaWqSlt
         jShvq61enOS7/JPr5lMKOryFxuEkE7BdFPw2tq1VEJjv0HYDnb5w8MMtZqb//mwiS1AH
         JYtDFeRLwudyT+VkX7NIFAGJScrHwxLLWHDphiqfB2LnCO4pL6nJTkiEUKKAjnTeFBu3
         xs7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=57O3+DHNDVIi0oGnEqKkjls87/nPBLt+7O4BOgTJ6P0=;
        fh=XtgEgDIGgCtKu9qspOg7hkzbqc8WMPgFXAGSmvutktA=;
        b=X+ZmlCfSEaOmxkHFm95H9sXs6fBrn04xIhrS7i8TD3f3HmQRMSpEbT1lI0GEt7YtFz
         AwrJJkpefx4lMJAx2e74E6k37uKNGApdYbWuMMdeELyDdcIANIiksW76bdCy1qcBXX2F
         5NZEcqJZUFCdB8OekURSjofYa4vuOlK0kD+prz9o0A8on6fN9H2xZtD/ktdHKXJ0U8/V
         qEAdBjJz7ALrl/jKDPXjMJZAVWU0Cg8QKJIFkgH4Asine/TO1u9dXC5/KrtxvdAE38zy
         Ta9vViYMOwRI2carCGI+eKp6mbF6pjHt61ihfq4hl5S3prwsJzZmcVqKRPbXgBEmibvD
         18Yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ag6xg8Rz;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806915; x=1756411715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=57O3+DHNDVIi0oGnEqKkjls87/nPBLt+7O4BOgTJ6P0=;
        b=Bwx7XwEinc2GiucytTSrFMOo3ZFj/qo00kcNc6lvWJFnVMiQZ9w70oEPfKelItEbbE
         E/VBGsrMXSxPxjrmzmQI+yGg+3l5yWEpL4QnwyEEUZtIAb3YYqqO3giF6ZQRR/uWJSK2
         8nlVFyJiDMh/K5Nrkj2jiL86ksH/G3vhJcAKNCD3YWhV/n7pO4FX0U6G/MjJBlqduHVA
         vVCyWUOJijWE8Oi0vx2oKPXrOBNUheMy2FxIFZVrJSczoXgzr3nndX4vnJjDnoFc58xC
         kHpBCXcIQNfGrpwJV3LS1M4R5jZAu664jv9FujEHtx87CbUEn8gfxnwfkbrGPCMNy8kw
         h2wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806915; x=1756411715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=57O3+DHNDVIi0oGnEqKkjls87/nPBLt+7O4BOgTJ6P0=;
        b=iDaoqOPWhMRrHBO/fHvFHknWiBjKbBUP0lymqWpP1qQBHgUg9eNMAkDIxFt0PbpfpX
         eizWLihCUeoZGIdixKkZGGk/rEb3xBsZQek1VV0p8lEPRdwCaXRC/8IiydhbjsiIK90q
         9qiQtx3M0wSCTSFiSZ9cSoBFKgLgnxfuGIm+AJO5EXSQRb06cj45wMVs4TovyqoMHy31
         hY3KOYbXUvGFhSSw+q4BzAQFvYrGsfQrDDJdv4Ty4Z+ya+cmsTMFtDeXumlZx1uUajeF
         nf8N4mhAE/HIEdPB5e30hGwwdkTr6vd/GJaA5XbES+nFO6DYB810qu2syO3ixvg+CX6x
         a0sw==
X-Forwarded-Encrypted: i=2; AJvYcCXm2oksALDjUStApP4MAB1cQFt+B+QZ7X4H/8dmpElJdUkwY6nVCKqq8jAXIT9CII37PMWMgg==@lfdr.de
X-Gm-Message-State: AOJu0YwM+jyVDAy+ZibaWzYvhS+vTm0NFHzbPPWCcV/tebV4Wm3FBwds
	mGy82d5BPuN3Oj7GAyHb9UqW2fPW+sZWdfa9DiTno5FZFItck5He+XGJ
X-Google-Smtp-Source: AGHT+IFZQ26a9p/jBZqfRKuN7/quPBRNZLQNilXVscRYtyMhm01bP2QLRcxtg1vU+4L9SM2PxSMVHg==
X-Received: by 2002:a05:622a:1214:b0:4b1:27af:f1e with SMTP id d75a77b69052e-4b2aab2503bmr6800991cf.55.1755806915492;
        Thu, 21 Aug 2025 13:08:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcGvSwEMPLGcqntnbUT0yujTIgMBWZRElh/Zc578rD/ag==
Received: by 2002:ac8:5a96:0:b0:4b0:64ac:9be9 with SMTP id d75a77b69052e-4b29da26290ls21078381cf.2.-pod-prod-03-us;
 Thu, 21 Aug 2025 13:08:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBLk+OC1ZjJlypgoRQhepXH3WFVntToD79bgrjTaAcYd7s7DtrGTAQPRvpbhIGVMeYpTd49fhmHOI=@googlegroups.com
X-Received: by 2002:a05:622a:428c:b0:4b0:7b08:b072 with SMTP id d75a77b69052e-4b2aaa27e30mr7019611cf.9.1755806914517;
        Thu, 21 Aug 2025 13:08:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806914; cv=none;
        d=google.com; s=arc-20240605;
        b=AbhN9rFWmS+3wk5jJYnp3lCoJPja06Oi9qI6hs/WzZONmOg3QylQ90ZBEQHcua9lvh
         dTowlJpRc4pMeErDk3AN3vIzT+Y1hYdH1w13UEMhK1DYbA5P3RWNNPUbc3Qhlo4/0ITU
         9yrqfk9JkUpJ1jrfMlQv41u0i/PhbgBOFoCEuOmHAUa9gVDHYwYI57wj9AIhSPLPkfAG
         i1OcaXwkHmJnt88vntzRMWlmd5qGZhGQ+O6yesgY5K9fSzA1qJizlA7EM2wkDLhhEni/
         soo7SfTV5ycOHtFSgxjqBHgJNupLBSCbL58dpxFfSHnG0L803rMvd5ctZAolZR8sOHqg
         wEeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6kuJ+10C4pYxyWPcGDJkWqMBAcRGmXje5KFYns7NWu0=;
        fh=7/+FAh/fH29RXCOWalWeKWOv9+WJgBTQRMLzM338t3g=;
        b=FVoJpA0O7/H2N5Um3CuP1hmocEKoq1xsurizhc1PdDLJQ265uzAoLsCPJV6ylbe8L5
         xgAXvvdXwkd9lTKy31xQqQ3W5TJrcyjI78a3yiKy9JY3vsc6p0MSqvLLxy7IGoqFohD9
         E7MQRbZAsAFFhhaliUzT/cYb9Br1tf28cGVqcgSa5/IZG42evonIW9dmQE2vETiGlDxz
         5qg0HI5cDoI6JMYX8sCGJhQSyfRVtMzIHXa8h/Zt4btstxT++9ddZtO9a3b9h/K7S8ZL
         OKWQbdN2soSphT694HJgj+mRfETq+4CHeKeDYmckoYrnkiasIxh0AZ6obXF7yj1x9POv
         /CxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ag6xg8Rz;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1dcbe1si73199185a.5.2025.08.21.13.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-185-oRMO3_9XPmSJ9zPQcEA09A-1; Thu, 21 Aug 2025 16:08:30 -0400
X-MC-Unique: oRMO3_9XPmSJ9zPQcEA09A-1
X-Mimecast-MFC-AGG-ID: oRMO3_9XPmSJ9zPQcEA09A_1755806909
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9edf34ad0so613402f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUphZlvJcAF937RN/KWg2RgvSGf7NCkpHL+/eJ0MjJmNiALWULwWVUJrcOKqAy2RnR3Tc+yMv0SCq8=@googlegroups.com
X-Gm-Gg: ASbGncs0uBIOyx2Z337iLJeCPYuU4M/LGoJe+WlAn7hgcl8MvbTCC55l5VqGAik/U99
	6GCisSo9v50mzSuatAD5tJkHO9zLmhbT2dSNQtdDkQWZfz+OzFL5yuhbTW2quQK5CXBBS8/Pv7s
	0MBBODuSFGP064WOVrXxCzmaucc6pEsIqVlhv+B5uXq0O1NS4/w9g+JaEiLiM5KOvbyeTB1n3aG
	JUtr+qAoZWLA1elEH6th6NqKjLpfzF5OTalw1E1f+CwRF7yCf+GRUK/QwkhlQf5ogvo1nRoIx/f
	ig/Bo/qx16hvbID/jqU2gi5xgBzEH5S2e3UJqM8DmB7Q4AgZK1/Ye0DRRriUV20Wjimk+GREPJu
	WD1bpT5OujFcZ6/ycH1E2ww==
X-Received: by 2002:a05:6000:18a6:b0:3b9:48f:4967 with SMTP id ffacd0b85a97d-3c5dd6bbb33mr155516f8f.56.1755806909410;
        Thu, 21 Aug 2025 13:08:29 -0700 (PDT)
X-Received: by 2002:a05:6000:18a6:b0:3b9:48f:4967 with SMTP id ffacd0b85a97d-3c5dd6bbb33mr155476f8f.56.1755806908930;
        Thu, 21 Aug 2025 13:08:28 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c5317abe83sm2432791f8f.40.2025.08.21.13.08.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:28 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Doug Gilbert <dgilbert@interlog.com>,
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
Subject: [PATCH RFC 29/35] scsi: core: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:55 +0200
Message-ID: <20250821200701.1329277-30-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: If12_O712EHXNbBC0Ie-7zNrKtHDa0CN93qjSAJvyXs_1755806909
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ag6xg8Rz;
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
Cc: Doug Gilbert <dgilbert@interlog.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/scsi/scsi_lib.c | 3 +--
 drivers/scsi/sg.c       | 3 +--
 2 files changed, 2 insertions(+), 4 deletions(-)

diff --git a/drivers/scsi/scsi_lib.c b/drivers/scsi/scsi_lib.c
index 0c65ecfedfbd6..f523f85828b89 100644
--- a/drivers/scsi/scsi_lib.c
+++ b/drivers/scsi/scsi_lib.c
@@ -3148,8 +3148,7 @@ void *scsi_kmap_atomic_sg(struct scatterlist *sgl, int sg_count,
 	/* Offset starting from the beginning of first page in this sg-entry */
 	*offset = *offset - len_complete + sg->offset;
 
-	/* Assumption: contiguous pages can be accessed as "page + i" */
-	page = nth_page(sg_page(sg), (*offset >> PAGE_SHIFT));
+	page = sg_page(sg) + *offset / PAGE_SIZE;
 	*offset &= ~PAGE_MASK;
 
 	/* Bytes in this sg-entry from *offset to the end of the page */
diff --git a/drivers/scsi/sg.c b/drivers/scsi/sg.c
index 3c02a5f7b5f39..2c653f2b21133 100644
--- a/drivers/scsi/sg.c
+++ b/drivers/scsi/sg.c
@@ -1235,8 +1235,7 @@ sg_vma_fault(struct vm_fault *vmf)
 		len = vma->vm_end - sa;
 		len = (len < length) ? len : length;
 		if (offset < len) {
-			struct page *page = nth_page(rsv_schp->pages[k],
-						     offset >> PAGE_SHIFT);
+			struct page *page = rsv_schp->pages[k] + offset / PAGE_SIZE;
 			get_page(page);	/* increment page count */
 			vmf->page = page;
 			return 0; /* success */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-30-david%40redhat.com.
