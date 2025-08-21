Return-Path: <kasan-dev+bncBC32535MUICBBLHZTXCQMGQEYGRALXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D7270B303A2
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:13 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70d7c7e9735sf62117696d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806893; cv=pass;
        d=google.com; s=arc-20240605;
        b=FKaKjuOryQY/v+VN/OXcqeoccvrHKzBXIifZsFlqoZQRfYOviygrT1A6ZOLO7tsXwK
         oSIGhZB9bfB/2HHIlssYSokdI7NE+X3x8ZWhn0e22trO7Zhl5iZxYtPgLhNUT+nSci/A
         TumThZqSBkZL5wZ4RC+My7yNxqVtheNB1UvcUPg+I5LIPwdk1Gqtfbkg9J0MRHj0FeY1
         sHWXpCFYfXMUcH/aR5Uj5tppqRgHB58KygaT1iTkyjwJjrDPpLKkXlStFc+xDzLdzrNZ
         hwhyct1GVPcBP2nUVEvUeMRGOVGcFagZ88LFFG7qxU5oGHztrdCtBEdpA2dEtgk/lj9v
         LI6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+vu38W3Nk30wTHUrstUUXkQQ3/+SGuFC7xSuhzKEYvQ=;
        fh=8r6102EJdITNPE5s60uk6U/sQS3S85J15hrkNsta/KU=;
        b=WG5K/uRFawdzczOAuqXEuPl1rGTpb2EvGIebavZvoIcBUdBff8/mwZl8w4rva4D7eG
         4VKOCVm49mVrAV4Xb1a8GhYGOlbcnEc1T8oyp0uzfBWNVnwdKHB8ThQqf3nDGtigCtlv
         v0kGkJckF8PAzaauoU3oEf6AXhE0DioUF6RgXmUZJWkEkHazMUS+xp86QABxP5c9eetc
         FzF4RN1USV7FM/Xzh1au0+io/+irD/qWxLzf/5zybUwSpVt/yDLebPIAnmMkkN7pmkgm
         zV/hwgbKQ7V4kl23JbRDQx2Cy3vzplqKh3W6jBc84qpcI7TYav9ThMxB+AzysmebOfeR
         zwyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LAuI4ObQ;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806892; x=1756411692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+vu38W3Nk30wTHUrstUUXkQQ3/+SGuFC7xSuhzKEYvQ=;
        b=BhQ6kagzj8+Nl3WQsRb7qL72XMtXpBljcyoNvrFSpuCgGVrWYfxUzk/GGyxZu5UDRU
         yGAMSXI4/cQwBtrdQfZ1L3Q0DMSn/IR8SAQfpJ9fKKrzFeMCgjGTKbCV/0J23RIofSXK
         fH/GW6YLbj3TIFm1Fi/dPu33RptpwKCaHaTXoQCAKJg9N+eKIRiU1SgSWB4pdK+376ro
         7QdUFJNEhuqoBkmrKlL39qAcJKC4NaeeOV7KzwtzWeNYueymniNJcTUFwYcltrngy6Ns
         i+ZpH8Oe7tNmFluiQnhV7sos/j+h612aO+ofkQM+dz6mqO0/7O5iluwknLQ1hgjq9BhR
         GefQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806893; x=1756411693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+vu38W3Nk30wTHUrstUUXkQQ3/+SGuFC7xSuhzKEYvQ=;
        b=gnPN3NFDlH8BaeXJ3mB7KOSmLIT9XBfYtD8844IQ+B3nLFdPxBIBMfPA4TL+Lo1lSb
         HWb2mke8dYa1gPtZWEJCVMI2UZbPFYsdRRSUf9mnW/F5300//Ju8nOx5UT5j1n0e+Z8r
         yNH2iNW+ZwhuAj1aLmNZIRSVubwOw92EBbeLbTpHFXOu4rSmF6jnLzK7PayCEcxnXhYv
         aYz/QDte2NT1Kj5NF/hsXROncqqWenkZIFE4pDpEcrDuJa1wNh/JhoI7DlHyPdsnarlL
         gJtzcEbIu38xmlsg9NVhmeRwmqrVKVDjVBIrG4IB4dB26FXloLFX1GuOR+zLA/9+/9yS
         rSAg==
X-Forwarded-Encrypted: i=2; AJvYcCX8hA4x0bBjxQfR0Rk2iz/RJuAe3xs85P6jMa2x4q5qUt/QsLkLFotgrXtDGH2dLIwdDSw16A==@lfdr.de
X-Gm-Message-State: AOJu0YyiTDWMk0blWc9yJ+2DToYbbpvnu/wBmwDmqde8zypjBPYPg7jb
	Wl2oZfCrxHSTHN1zyrc4wjEKW9ZsYr/N2CEEoQHdXQ1kbfzNGupMVUrs
X-Google-Smtp-Source: AGHT+IEtJGBEoZJsjYGoMBWEyTmTSlKFLTzFAlbXyOn+jG9wKGXWHv1g4EUpAG17PIBriAkm2iTzfw==
X-Received: by 2002:ad4:5d68:0:b0:70d:6df4:1b0e with SMTP id 6a1803df08f44-70d973bb7a2mr9479126d6.60.1755806892587;
        Thu, 21 Aug 2025 13:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPb/utCBd1YCv5tPtSlGmgFTRKqDmrQM9niaoJ3oNCXw==
Received: by 2002:a05:6214:21ac:b0:707:4680:6fef with SMTP id
 6a1803df08f44-70d85c8f307ls20131076d6.1.-pod-prod-06-us; Thu, 21 Aug 2025
 13:08:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPrFT3o+6QNIRKaUWgWyfCzmnqjwOrZ/KI2ptLB9RfNkd8BqCiOQtV/cnQUAUgs06Pvk7jvpH6Its=@googlegroups.com
X-Received: by 2002:a05:6102:38d1:b0:4eb:eede:ec61 with SMTP id ada2fe7eead31-51d0c6bf425mr188579137.1.1755806891726;
        Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806891; cv=none;
        d=google.com; s=arc-20240605;
        b=WVxVgpiLj7OpPyzGj134jxVzZWMjT512+AtP0PblDeufAIiwQHBZof/1hMW0YQcNr2
         iFIi/Q499Y+JHJSOdQr3wef2Gq2s+mJQ/VzzBtDtRaodG2tjrRwQJwN9z4gdD+Rhqyqy
         UiuDBPTEA7mdMI1c9X0epIZxtbUb3rtMn/iDKsS0KjIlU3OHjU/EF483iUuAofRczwjK
         LciAN5urX4n8hPgUVvlOTONKqkrhh1PStEditzhyjEc27S/pBu7m/sNY3ZjzBoZA+Nbd
         +2o9xbS57TlR3hIo1+dYVwsILxNHz7YclpbbWsEfEU7WVx20nAKlSB3HzAxANDZaZ0yo
         b37g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Pq6EMCEhMXNA7HGNe/O1qYHWHhWZrBzRdRZ7YmKumJw=;
        fh=Mtafmwa3ZakgZjReprKjDpQOpZDe1efz3fCvYK5DLEM=;
        b=CO0NOBVS8RshTXcGi7oT0zRp8qfTYfhhYdf3cp65Vp0Op+HWkYrRywVah7KvCwGKSm
         BSCRiFTrp8NFVAv8534l7PmRjUuODrmlBjpL9mnFpRJNOxWWcI8+/CjVj6dxFL/Gx9x3
         /XxPY57yhq60mI9jO8ZJiFh7LUqUY1DjrXoGqovswDvvvZdOiJNLDdOz617ZzpCTJQ9n
         EyN26jrH4zrIN/IMW4rdmxttwTyfNOqN2EmW+hXS5MZadEV0Uj6Bgm4n7s7f3ls0/09i
         YHdVudWib+P38m/El8nSL6tV9W0+tQ1To1qLIcYXkw+atair+DY2Q97oescSOaLj1mme
         vFCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LAuI4ObQ;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5127d4dbe17si617322137.1.2025.08.21.13.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-509-5x9p1ezmOF-I_rtBMbKFYg-1; Thu, 21 Aug 2025 16:08:10 -0400
X-MC-Unique: 5x9p1ezmOF-I_rtBMbKFYg-1
X-Mimecast-MFC-AGG-ID: 5x9p1ezmOF-I_rtBMbKFYg_1755806889
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3b9d41b88ffso838247f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqq1r3APAzmghHw8Eg8G4/AQWo/dnK2nD5imDOoL70K06Y5eOtggUfkaKJukRm2acflKRxDW+R9jg=@googlegroups.com
X-Gm-Gg: ASbGnctA9sWc1r5Szi6RlIXckvlGiIIEP/jniEfDYrddyAmeLNl+90Sx6mZIm8+ZLp/
	N8zZYNUde0AUvl2sG4Gaxrzk6lvM57Eu2kacLR+IuiJOV9Sg2XTudU4rOTELA5OVmz+2yImC0T3
	D4u5Z3ExY3CkXeNNzhx9yZdWiojQel94avmpSryO329+12MXTaC40HFQGNiG2MxHWxBuB9QCkX0
	XvY8OdyoNlvWsqeACcH0N/mFnbhjEkk03RbXn/WzbVHqkzi5hTvoTWN/7CwkmhBwY8eB0VQr0es
	tCrVXfR4bb8TjIRbd3G96aM+nIShXMcgStN11YyEgTGR9kVjIPYSKEFFVy5E3mequcfeIC6z1cC
	RtQYqdDkCSDye7CyAOOmJYQ==
X-Received: by 2002:a05:6000:40c9:b0:3b7:911c:83f with SMTP id ffacd0b85a97d-3c5da83bf5bmr151933f8f.9.1755806888881;
        Thu, 21 Aug 2025 13:08:08 -0700 (PDT)
X-Received: by 2002:a05:6000:40c9:b0:3b7:911c:83f with SMTP id ffacd0b85a97d-3c5da83bf5bmr151916f8f.9.1755806888456;
        Thu, 21 Aug 2025 13:08:08 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b4e2790a8sm21120815e9.1.2025.08.21.13.08.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:07 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
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
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH RFC 22/35] dma-remap: drop nth_page() in dma_common_contiguous_remap()
Date: Thu, 21 Aug 2025 22:06:48 +0200
Message-ID: <20250821200701.1329277-23-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: tkc6zOPc2ys3dfFgDCUF2f8FdL52yHMnRjIhzqQQ5c0_1755806889
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LAuI4ObQ;
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

dma_common_contiguous_remap() is used to remap an "allocated contiguous
region". Within a single allocation, there is no need to use nth_page()
anymore.

Neither the buddy, nor hugetlb, nor CMA will hand out problematic page
ranges.

Cc: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Robin Murphy <robin.murphy@arm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 kernel/dma/remap.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/dma/remap.c b/kernel/dma/remap.c
index 9e2afad1c6152..b7c1c0c92d0c8 100644
--- a/kernel/dma/remap.c
+++ b/kernel/dma/remap.c
@@ -49,7 +49,7 @@ void *dma_common_contiguous_remap(struct page *page, size_t size,
 	if (!pages)
 		return NULL;
 	for (i = 0; i < count; i++)
-		pages[i] = nth_page(page, i);
+		pages[i] = page++;
 	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
 	kvfree(pages);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-23-david%40redhat.com.
