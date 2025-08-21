Return-Path: <kasan-dev+bncBC32535MUICBBH7ZTXCQMGQELY5OVRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E4A18B30390
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2eac5c63sf1298585b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806879; cv=pass;
        d=google.com; s=arc-20240605;
        b=PrWpM8Usi2QO89JKlPf3OoEpIfs6D8k3gL2w6bz8ITZDbxi4oHor3fBVO1wuOCxPw9
         /MBNiTCVkxWRVguaZN7mBWV6r1WyaJ66SqG/pGU6IZRLq3mZhXp0dTHJWq/ejLsCZpa5
         zoEZPn7hEL5PyOjGxwIWWEb6LEPNIOMLrIo1ZS8qIxZzNjl8AOzxsZqoo3l/hwBKaQMJ
         b7k69A4cUZcCC35r1ymATpTToAs2v5ft3MKtuR7Lfkiy5j6PWR3d5MOGmGruBOc7HiF8
         kjjd+/EKwYUrzjMq9A4oOsXgGCuuGkq+WOCREFH4yJWzQeXryU3Ee/cYzAxrDHylPn4Y
         zdNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=nl0Rso1hk/pCW0nDgnTRuBo0+28yQsoPVUVNvl4npdk=;
        fh=CqdstEQXyhWB6sC7xeQsh9XxbSLQ8fnhBJGp8mTBUYw=;
        b=f1bsX2tpnBr2EvRDb4cgiwzXzQNrXkECV/v7EC/PyuynDLuzKac9KCT74nDHYV/WXv
         KlrKMgOC5iZOt5kXO5ZLFhFyfr6SBBmoB4A+7XWT57AzoawUAfNRqS7qSpjiI+ff3/X/
         9Ibygc+EqP4T2s0goxeBIQVEXZMhZtYO4ooK3txfL29SDnxkYwf+SMNg3MpbWykI1Ugp
         osQHlstM0qcJiXF8G6+/1n4vlHT+yuQFnfkRaHsNlkSMimFOTCxwqgvpE54jgjbXtcje
         fsOdmBs8zI79lI5vn87Ck1lmw1juWGdHGcxeoNyIdHpGeltzDoz7O+kTz4pBOjwNb7MP
         pMIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="FEc/ixVI";
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806879; x=1756411679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nl0Rso1hk/pCW0nDgnTRuBo0+28yQsoPVUVNvl4npdk=;
        b=K93YZuodAywjSPrkJq1a3ZQreJJ4Ukj9DW9kHUakitXq6k76sIPaKhhsv+YD1cgMs1
         2dMOkrY+6Sus/N2fYKaJdMSvRhJKf8yjBAI2uzrYeEx/se6JaqLheCu3jc5QDBAuE+lu
         essRE03wOULzrKwodLY8sl8KFPwG22pWkfS94TWfVbrGsXpVKU2jVGTtHiD/e2wWaAvl
         88TfDMtSRtsuZ+uxfQ08PlZ6mI3yQEGkL4zJyYcxvQ/Zwh7GqkQ1ALgIX6jjpl4cnpQF
         2av96V64Ab1ZUEFdScCviDw4FjkUTzTBz6saOr+0Rdz+GNKbsW0i0S+tydgetKrjzD8y
         LeMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806879; x=1756411679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nl0Rso1hk/pCW0nDgnTRuBo0+28yQsoPVUVNvl4npdk=;
        b=begQ6ubgaZGa53QoJAOLKZym+YlChwHQ60Cs8lY62HW09XE/Xh6ywu3/ZX2EBhtSlL
         fFX23iHUm1YZ3nyeIp2lGh7jC01gdkk3tsDmGYQkeROQ3z980H1yvSpk8njtnEcu+B1h
         1AeTxnRFzLC5LDDJqVeSRAzTlDbigknFBb8/DSPVZEenMsjtPFKJAGnhEBPNJJGP1nxe
         CXyKpcBm4r8V/K/lmJlYrNjzZPmNFd2lh+MSeBwsj5M7GutOxnKOXKsqcOY3MxcE9Q4w
         mXC0c0SAfUQV8q7NZozyc6LHG9CWlQUk4q1tkugPUA+hEblpnkSvJOXXTo1UOzaCay4P
         lLQA==
X-Forwarded-Encrypted: i=2; AJvYcCWPKhxNVpVxlIieMx9YyjRNuVbCEmXIi/Q+fhVwt2Sod5F+HnonxQ5+4VVtF2rFIEySdSNvsA==@lfdr.de
X-Gm-Message-State: AOJu0YxCq2GnmltaE/KS31GkPggp8c9SiXcSIiL3GsrQs3eEJqB0IFPH
	hMlGxbW/smnCniKhwND2rW7VAD1IKk47TnzFF78+KSxVOGKRmB9vC/Qr
X-Google-Smtp-Source: AGHT+IEieWDlE7osOm9unvwn+mj2WYt6Opl0zuE4KVuZir4zWrgeDMxiL7KGPjABtc9pFbLqRtt9zg==
X-Received: by 2002:a05:6a00:b8e:b0:76e:9906:6e47 with SMTP id d2e1a72fcca58-7702fbfd961mr640406b3a.28.1755806879319;
        Thu, 21 Aug 2025 13:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfwSuo/3Y6YqGznhttnY5txLQ8xcDhVl23xPATENK0HUg==
Received: by 2002:a05:6a00:b8a:b0:728:e1d1:39dd with SMTP id
 d2e1a72fcca58-76ea027e0e7ls1496492b3a.1.-pod-prod-05-us; Thu, 21 Aug 2025
 13:07:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoIkVwPYUXnWfWkS6g8osch60olIg9InnZvn62iRF0wGiRWcWkPmkHWdyWkTzaJANJoCgB2Jlp8qQ=@googlegroups.com
X-Received: by 2002:a05:6a00:2383:b0:74d:3a57:81bc with SMTP id d2e1a72fcca58-7702f9d6d04mr757671b3a.2.1755806877826;
        Thu, 21 Aug 2025 13:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806877; cv=none;
        d=google.com; s=arc-20240605;
        b=VlMbQ7NRq1E7ejqj3QBbIqD5AivERuq9yFyBGIKNi2o3OC8SsxJaAyuFFykhJ5qVD8
         bypQC9dfbcsweTGQxJZJmTzJIR2f/uzK2d6/hm74I3s9f6nzM92z1ya+84sDM3+aNyUp
         FwflFzKwSJyiNWh3RidO9JxuXT1jawC84oS6f4Rcrofiwg9ScwoRpOd+CqgNoVa2QY9A
         6TucjuYGAadQKu1PqkMmwvdGOE7vylkRJSpWtqtGtlW4umD88/+T58kIzs6sLLFsNzZt
         +/gqJJKljO8rmC7veIcecQUP9abF/t59NBMeOE3klPKvCcA9cU0e1ECjQ5SXF62f1eC+
         Ff6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NPs2EdTZ9fd3MpWdb0ATDCa6nUqfGtFMv2uyZP7L+uU=;
        fh=WogHXY407jpncSPYn7+Ce8/BrbgmWKlsETmAvjCPj+4=;
        b=Py+brFwaSM0G1+F3dl3q2gKD+Cww9/DRfLeKij9MbjT/oxV+H5FOq0TIMHUsm3PfkS
         c1FAFX4qNkUXMzxDS2nxzxCd4TsFt092URlU6n5thjYChuq76WV3OLMdn2VDRnzwM4JS
         bj0Zljr8eoEkC1SNsffDskWwfx0vpnehctkRJxRuTcRQI1YXD3T3QSfS/u8kBI9hZJM0
         yExBAHdxPV1ANqwLrZqb4kYyujj5/SJkEdTYeIjVEflWPiIjTjGt8Rpscasswb6CpNLz
         TXjZuaGkU29rCUo9wILZXaOhfJpbQjMWViMMBvU3JfsAM99vKMs7Fsn2RtjF18Q/OyDx
         PT8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="FEc/ixVI";
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7cce9ba0si159659b3a.0.2025.08.21.13.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-498-zjn7fUGtPU2JFoDL6xIs-Q-1; Thu, 21 Aug 2025 16:07:55 -0400
X-MC-Unique: zjn7fUGtPU2JFoDL6xIs-Q-1
X-Mimecast-MFC-AGG-ID: zjn7fUGtPU2JFoDL6xIs-Q_1755806874
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0b14daso7258465e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCGIVH/F2mJvCIpNdcMkofBtoWRjqRDg6K7ODbvTF2BAqbfe8Y9GTTOFxJGRaBewd22X6Uah+aLVk=@googlegroups.com
X-Gm-Gg: ASbGncsruOmjAwevn7Q+kgrl9uSiU8th95eMsWjMZFvoTWMc+s4wQSmL4B7y7AvorFu
	3TYd9v4ld114oBxxQDua+K4QCI4L3jXFoq3FWldcQfWnTddK7JR4JEEA6bM11bi+inI/HMyIHIb
	QA2coD/pcbsi0UU3cQf6AwfE2kfqCUjqQkeTTWLOnWwj2wTctPm1i+4w7FzdY7eG/115XzLRZh/
	5nNe7JAcXH1N3RpinpuiV0BA5HEMZ9HCE5I0qBU1AhjUjQkc7xfmKPgTaGDQMEE8rD5KIlkL9XE
	jB12szMJpdSK6Pgtd/b5D2TrYQN5LdbuISa4Ze8e02zaIjOg0gqHZ6o0DeR+xMelQJlLsb4q7IV
	pDO33GYEl+b8olk7L01qVig==
X-Received: by 2002:a05:600c:1388:b0:459:d451:3364 with SMTP id 5b1f17b1804b1-45b517d40f2mr2554195e9.24.1755806874310;
        Thu, 21 Aug 2025 13:07:54 -0700 (PDT)
X-Received: by 2002:a05:600c:1388:b0:459:d451:3364 with SMTP id 5b1f17b1804b1-45b517d40f2mr2553905e9.24.1755806873856;
        Thu, 21 Aug 2025 13:07:53 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c07487a009sm12690403f8f.11.2025.08.21.13.07.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:53 -0700 (PDT)
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
Subject: [PATCH RFC 17/35] mm/gup: drop nth_page() usage within folio when recording subpages
Date: Thu, 21 Aug 2025 22:06:43 +0200
Message-ID: <20250821200701.1329277-18-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: jDUaRcQODU6vxkyK5djIyLWZbPo8l2NX4vwKKsi5GLw_1755806874
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="FEc/ixVI";
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

nth_page() is no longer required when iterating over pages within a
single folio, so let's just drop it when recording subpages.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index b2a78f0291273..f017ff6d7d61a 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -491,9 +491,9 @@ static int record_subpages(struct page *page, unsigned long sz,
 	struct page *start_page;
 	int nr;
 
-	start_page = nth_page(page, (addr & (sz - 1)) >> PAGE_SHIFT);
+	start_page = page + ((addr & (sz - 1)) >> PAGE_SHIFT);
 	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-		pages[nr] = nth_page(start_page, nr);
+		pages[nr] = start_page + nr;
 
 	return nr;
 }
@@ -1512,7 +1512,7 @@ static long __get_user_pages(struct mm_struct *mm,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-18-david%40redhat.com.
