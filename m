Return-Path: <kasan-dev+bncBC32535MUICBBSPZTXCQMGQEZQS3KWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E668B303CC
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:43 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b0faa8d615sf65096661cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806922; cv=pass;
        d=google.com; s=arc-20240605;
        b=b/n1sQP0ASYkXCKkFRo846LsjfPyInEbsIe5ORd1BcoL484mcMUhZU4qB3srBa6Fth
         2jFRGAGtDV/wQAzxsrBjoF3sqx4jI/QkqPNRkzIP9QQf0ZiCv9Aw9fC91YKV4T99Ml+8
         xNcEJQTypAqTuCYSYPhs3sN8HgNLeDJlDtxVkU6yWGRHo/r7nzO52FgjyR+9DdIwsV1P
         KJe5ZgYFyKbSfQYfoVzlcqgWA9G74q/hxIp+JYafkaA4sLzu9z80JkXL00BCJzJ+WLZH
         lGTsSpdzHphUBXRif9Y5XJpTJmWE6CJr1XQ/6CFFZCPtllxzikACPg4u5+OwiJf1Uefn
         yYeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T/qQuYVF4kLNZMrZwuODGhVoKgFZ6+0s3fFfVF07rYY=;
        fh=VQ9j+KokCeCwAjNp459kS4uqXNRJWCVtSrEB6OYeGw4=;
        b=byesx0JlZESZn96Yu/0AbNWC25DzwgaaKHYsC7ljXTCWAq3/z1jkeQvECigJ2mB19p
         jgfDJCjGKhXcBoMTgJQfVh1rVNZsch5qyLkmzEzvPPhGO3uycNR85UAqI5JR6XxAJjox
         zc+jkG77yiAPad/K8qx0/hIml3jejWte0g00dgFNsCLs8lEAixtbkSLeN4LLY5jvHJsZ
         SRDdbpgsksg2WqaZJ8GNEr3IrUQod1lfcTTwG3ZAyiuI2lcjanZUAAF2ADjTOOtdt+bz
         K55NKK4ZdXhJDjqkesjdPP7ULXV3xuGtTouJfmzbKuz7dO7NLvMROrteVOVOJqcXTp0N
         S69Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fOD49HRF;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806922; x=1756411722; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T/qQuYVF4kLNZMrZwuODGhVoKgFZ6+0s3fFfVF07rYY=;
        b=EVQP/bWbBnBCg3897s80TG3ZfJtpMi/pjo+4rkaTOrgE/kfyvD3b4WhKI7NGX8qK6o
         ehPfliBn5AllFn4zEZopc4FggBpsmYT0FwXy0TXJOS81oIQKVT2CkI2XRgPiUDbtkfQU
         7Z2rMw5ZQpmtIXhrm/dPX+nRHR1xCjl/zICceZlC549hrUoC6FLmgzqsi9rCkUlU/aMt
         LoxPuffHlCXD71fn0oqu3DMazGLphnlsviUWiqFdeb8fL6SIGaqDmCWXtEUuRom6GBdY
         Yn2Fd0ATlxFpo1HJVcHHaaIRhtQ1qQA4GAfw/PYKa9vE4brHYS8lDJopdWKLtNIcBJGe
         Vvxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806922; x=1756411722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T/qQuYVF4kLNZMrZwuODGhVoKgFZ6+0s3fFfVF07rYY=;
        b=fKI7H0pOXD1AYNp7aevhkHYyeGIeW0ao0iOUcf19K19cv0Ph4Yvewyl8Fy1ZAMXnlp
         Vg3fG41AMRk1X8QoAI86lKXnnut8L/AQImbu3oXIW3yAk15LrLRg0TWctzDc1fBDdprA
         9JHPZeFA2RtjDNmLRqzVTXZD/mcRYT3rFp9cQMrDkYdriIIMrpNRzfsFwv/kIKH7msYS
         3yJrvgdqxEytCtsbe13eU5IONWBnLpkMdSoU+9cAINRPNCKhnBmR1+eq5gytGbZ6dcnD
         iOH4CMOl3AvAI3mNqHMUjNnWl1TcblhaSg6TqPw1pyfBk1t7JdPovh1rRJ5ZbizaHHAZ
         D+Ag==
X-Forwarded-Encrypted: i=2; AJvYcCXA5pLnDS9a9y7cxevGyr76DO+YVN4kW6j7CC2QUDqzxOCgEesjtBgchPvgYdFM2nJJPW7kCw==@lfdr.de
X-Gm-Message-State: AOJu0YxP/XUbEa70p5K4s8aqnRPXRcl3B3aZakMGLUH6s6KiYAqxJIcX
	Lnn1MpaTbSxH8FECj4RW6Mz9thNVdZ+Fc1JwUfe36F9BGPocn9ZcgELV
X-Google-Smtp-Source: AGHT+IEUWvmmJRszrfx4GYKXD+nUYP2R6khc0F3OfDlsJiTjbm2FpP1X6wG1bV7hI14ePdR/4/UMPw==
X-Received: by 2002:a05:622a:307:b0:4b2:9883:830d with SMTP id d75a77b69052e-4b29f9b5a0amr41623411cf.0.1755806921966;
        Thu, 21 Aug 2025 13:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3h9gUfMl2D83l4HnQ89U/qhWVz2cESrcTB8tXBaMwNg==
Received: by 2002:a05:6214:174c:b0:70b:b416:8416 with SMTP id
 6a1803df08f44-70d7587bd7dls13054326d6.0.-pod-prod-00-us-canary; Thu, 21 Aug
 2025 13:08:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcziiABxI0ZV2S0WmftSpp8moDFsClIHzVuOlvylJaw0C0vRiQXhKN+9J3SRLlpU/9hqAFeMaZeus=@googlegroups.com
X-Received: by 2002:a05:6122:3118:b0:520:4806:a422 with SMTP id 71dfb90a1353d-53c9a642bd6mr150143e0c.3.1755806921189;
        Thu, 21 Aug 2025 13:08:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806921; cv=none;
        d=google.com; s=arc-20240605;
        b=fdIxxfj5vmsixYjMp8XgdZlcFEeuBGSWIvRHkXL7pZMhKSwGA1WOo8GUKWeW6vPRjQ
         agc/qOP7tvnxbmm/g0AwT9KA79P6wjsWd6//deCc1J+6V7KkG3tFexdHVlxWiZOiwsGT
         tIrEK0vhqjplzjb6ATNxsCCJ3AXeXtJTBPF62cttPwZ85UuaNpoHcTNR00GoCgkq/efX
         iyINOn5tgHgBSJUvs2buVVoGlJ+SnVeL3K4FJmfo1gMNhemA/pyVdXHTElbosRoCAi9a
         VAVuPEF3z5ujhn7QT4mSwCHreqWUHCHrJezl8wXIk0g2+AWjNLbaaAygE98HkIj0KJAj
         KKVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wK69Pd9CHZjKZhmlaft7kkJNdToX7IH/S9WvVIRScQg=;
        fh=nzBrbf/WN/MeYZ2YrarztAviIX4mokisNk5MR7wiAdA=;
        b=O0AJjXTAWyhrfmfwjjKop3e/sraIG9rURsKMjZ0wuRC4C+whOlvDeXZOS5WXdhyisR
         7G95RCw4VKMm1qMgXr3DeKxYOhKa9YzO43WfAQ4ZgVIs1fu27Wdrm0AZjU2zglq49aJO
         ovLqrCIV9ycfaRQ/BEtZIQW04SVuR/YmOGru1qo4COi1s6gOGSZ2hYtz1yfd6jegeDrQ
         DODeY2hM/v4R26uqNGl/HKyc6Qx1yqesuo2uLbwUFAAVCd8jtW2PQdhe20MV1RzV55Wg
         koS63PuwIvjbLDsuYdSsOVPaMQZXN0sPFgWdSgjpsul3WZfVD29rcCk9RYZdARtlxyv4
         QWiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fOD49HRF;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-890277e552csi727011241.1.2025.08.21.13.08.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-550-aVA2T9U-NrupVKAhS71O0Q-1; Thu, 21 Aug 2025 16:08:39 -0400
X-MC-Unique: aVA2T9U-NrupVKAhS71O0Q-1
X-Mimecast-MFC-AGG-ID: aVA2T9U-NrupVKAhS71O0Q_1755806918
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9dc5c2820so445752f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhZZrbeKNKPJo4nrtwTz5Fr8+FGolv8W9Ka9kblFI+fBgO90F/91S8/blg3BG2U7gtAF491DUS3bA=@googlegroups.com
X-Gm-Gg: ASbGncsJtR+jcDwLBV7wXFpYT7RwjGsDC7v5AcEEOyjuFP3Ua43LjeNGqvX+/UTUDY+
	CDwaq3qCPxfLRPnthv1PUU+SHeok53sIQU3JUuAFtIdzd4oj10Z0h/R0WC53WdWQcuKcJmOnSSi
	eNsvP3PjrS+DshDztP12zXjqlalTMyMjUJcBjU9J0Eyjda2UCgRuFwCqWLDzmXkyVqQh/N94ktD
	KEdqLwmePhMvyQ/d2dyveewZNotah6hMAX9tZCWpRrcyIsKhs/JRQz+xRVcXq35IgOcbZDv7gzK
	AeYD+k+DPu61AW6B4jhQ5LLnzTxTo9lZsQ+1PNLGBcg45H0TrspMQvx0pbaZgDvRh0hrfZmgUp2
	Hegc49Xv9tLEXYsgMgmjAZA==
X-Received: by 2002:a5d:64e9:0:b0:3b8:d7c7:62d7 with SMTP id ffacd0b85a97d-3c5daefc298mr218325f8f.16.1755806917863;
        Thu, 21 Aug 2025 13:08:37 -0700 (PDT)
X-Received: by 2002:a5d:64e9:0:b0:3b8:d7c7:62d7 with SMTP id ffacd0b85a97d-3c5daefc298mr218279f8f.16.1755806917364;
        Thu, 21 Aug 2025 13:08:37 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c4ccbf04fasm3355197f8f.7.2025.08.21.13.08.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:36 -0700 (PDT)
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
Subject: [PATCH RFC 32/35] mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
Date: Thu, 21 Aug 2025 22:06:58 +0200
Message-ID: <20250821200701.1329277-33-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: b9bCrVO8OCEb2spwbOSL5x3P0U0zFtHnWKqzJpa2bQk_1755806918
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fOD49HRF;
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

There is the concern that unpin_user_page_range_dirty_lock() might do
some weird merging of PFN ranges -- either now or in the future -- such
that PFN range is contiguous but the page range might not be.

Let's sanity-check for that and drop the nth_page() usage.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/gup.c b/mm/gup.c
index f017ff6d7d61a..0a669a766204b 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -237,7 +237,7 @@ void folio_add_pin(struct folio *folio)
 static inline struct folio *gup_folio_range_next(struct page *start,
 		unsigned long npages, unsigned long i, unsigned int *ntails)
 {
-	struct page *next = nth_page(start, i);
+	struct page *next = start + i;
 	struct folio *folio = page_folio(next);
 	unsigned int nr = 1;
 
@@ -342,6 +342,9 @@ EXPORT_SYMBOL(unpin_user_pages_dirty_lock);
  * "gup-pinned page range" refers to a range of pages that has had one of the
  * pin_user_pages() variants called on that page.
  *
+ * The page range must be truly contiguous: the page range corresponds
+ * to a contiguous PFN range and all pages can be iterated naturally.
+ *
  * For the page ranges defined by [page .. page+npages], make that range (or
  * its head pages, if a compound page) dirty, if @make_dirty is true, and if the
  * page range was previously listed as clean.
@@ -359,6 +362,8 @@ void unpin_user_page_range_dirty_lock(struct page *page, unsigned long npages,
 	struct folio *folio;
 	unsigned int nr;
 
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, npages));
+
 	for (i = 0; i < npages; i += nr) {
 		folio = gup_folio_range_next(page, npages, i, &nr);
 		if (make_dirty && !folio_test_dirty(folio)) {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-33-david%40redhat.com.
