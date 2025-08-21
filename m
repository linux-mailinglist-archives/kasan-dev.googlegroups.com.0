Return-Path: <kasan-dev+bncBC32535MUICBBD7ZTXCQMGQEDCKZXAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AFFBB30380
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:45 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2445805d386sf16657515ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806864; cv=pass;
        d=google.com; s=arc-20240605;
        b=SDVfiLsJS8fgIXDe//hhMs0n7Gwc/Z6TI44Wl9bHXDjLITLICp7WqrQAG2xV1fqagN
         fVnWlqcLWHMta8uOWQdF+Ln5WqjzakE53FlpLSkZJY/x36NoF3DnwoIkUkzDgOFrsKT4
         Hnxg5rhXMIxt+QCGf7Z9A2JwiGxXOtwIFW7W/Boxp1ObBTPdZZWF0Hmoyvr3rZ9TFwy9
         UoSjjDr1l/dGufsA5xuOI78v8N3slRoLnPYfRqZBFhL2yFC2/GJh1A31ePuD2Wkou5Zl
         b8PsuRFwiAsCkIpfw2qM3JtVCJCFbri9g91SzC9EnnrSji1Vp6JxbuSIWF+pEhGwUXll
         6pSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NrAKt2aUt3QbdW7+qSvOhsoPs96P6i2MmYeJfHu1IUI=;
        fh=e8at9G/RdrCbr1Fn92b/nVq33pPFtEFRdG/wqXXL3VI=;
        b=Y8Jg4P5MOnUYriLNBYUz/hb2/w6Aud187Kvy8QMIggQ1fOnSUPQNRSw60cJc3rtXnQ
         3P69qAQfy7ZuKrBBqiUXdfof4e+YhSwuLTRD3dqMrcJBG5c/XApr9F/uYgOzG3hRR2Rn
         uoacQPS7U0v8twqunG7MiVjHs7VT6YhpHJRpQ7o0Xomr8rc4qw8ha1zDjJi0Nnvt8GUN
         R6tIwpL/UkINjqMsvB7YLIQAJcN41VNBc36m/vtAvXriOmp2GW5z56D+Sfeas/w4CveM
         n7d92K8NwTDxi4uHgxOZmKfg/zTRYI22ntHyH4zfYLSwqVkRQVh3we08NmHiZ9T0P4YR
         yKTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=e9xXcRIA;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806864; x=1756411664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NrAKt2aUt3QbdW7+qSvOhsoPs96P6i2MmYeJfHu1IUI=;
        b=QvbcD8jbwQMrwkiVeO8Iu8jhe0ZvQ34HoONG5gfu+B/vwQhfBNjAJLmknwH2ux1px/
         JGwaeYT4MosDOMgXdk1D2Mpo21zCu0YzISROV2Q0H9CE++eXJcJVP+hZW4gbnvCgbUM1
         dMO8NUo0vjvOFzQ3ve1V+qClT7fAzTEkm4ovY128wQsDfQG6kxki+26Mr6pMsD1+2TVQ
         6nwvpSHueAna15Jygevw+gScBQcapId5rX1PBKasspQXhFRLZM5QFMEVOKgCtRaItx2V
         u3wf0xFuohK2oO7BnFD1fn7qVJE86upYiQ7HISQVTUlHTt33J9zRuOKi+/6dPT0wThva
         LMSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806864; x=1756411664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NrAKt2aUt3QbdW7+qSvOhsoPs96P6i2MmYeJfHu1IUI=;
        b=cOKoIsCySKwR2kOEh6s6YqJ/o2jdGLVCs10v/JcLYmn+BecyoV1DMs79MdAt3XsIIm
         pwgnWG/o+I3AVeEfAG845W9SED1RQQ4dX+2E6iwjS9cUHRsMdQ0bMoMYxD0U+yTI4cwj
         Qo/4xSdeDT3glNJMXlkHu3t/QtMVl7VAp4MTglOlVM8YTQRlZyQYKPvwYljh5LpDgF7t
         AKMt5LoLJbw0UW4VDW7Hc+ESJbigrQSUhK9Gh8WcgbHBd6PZ4oR2fIGT+N1P9m6x8apH
         FDtOgudFCuGiJP2Rhj09I2BydVSXUt2c2lDapjuDoe5fu25FwjLLrWBlkVlm9C/N56CZ
         wjvA==
X-Forwarded-Encrypted: i=2; AJvYcCXMsQG1Tjgm2HFihqcz8Ogl0MIx4tFfIR1wkAzQ8BUKtJuanwLmQDyjXT8azlzVyPhBu68DqQ==@lfdr.de
X-Gm-Message-State: AOJu0YwqsiKXnUx/ts6nkXSza1Syyh3h8PjZytqBvlr3pR3xhYTv216D
	45FBOds/Qn5bPJwcdAyY6o0pViY26hGz9wXqMCJ9b7p1RWwaXrsMgMdH
X-Google-Smtp-Source: AGHT+IHfBnoIhbvVJLIUARaIdTcL0G7tJmIM1NsRvvqOzxd9NDeCYm0Rqvp0iQcwc1EAosoDVowSpg==
X-Received: by 2002:a17:902:cecc:b0:240:25f3:211b with SMTP id d9443c01a7336-2462ef98a8cmr5610475ad.51.1755806863506;
        Thu, 21 Aug 2025 13:07:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3psntaXkADHmAs3uOceQqSb7DzelTCAugIX2sDZhdjg==
Received: by 2002:a17:902:fb08:b0:240:3c26:a31b with SMTP id
 d9443c01a7336-245fcca302els8277435ad.2.-pod-prod-07-us; Thu, 21 Aug 2025
 13:07:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcaYtSNM8cgyyq9oqSPt4JAdXjN4Totbddy4W6vIjkPuj37Qh4dbvAxNuW1nuEZKuVNiuB9dm0DUk=@googlegroups.com
X-Received: by 2002:a17:902:fc8e:b0:240:49bf:6332 with SMTP id d9443c01a7336-2462ef6d9b8mr6996935ad.47.1755806861822;
        Thu, 21 Aug 2025 13:07:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806861; cv=none;
        d=google.com; s=arc-20240605;
        b=fYDwx7ynnkTVYv9kE3xaSjgg0oWYMjnx8MHqYgAkIEs0STIURsmoHXglIBe4qNAcAi
         EThQ1EXvRqyzxReB6S7NcS2PRQBhwAh4/YIev3niSnt4hnZ/hoFZYXk4kw0LBdfz1Os8
         wZyGnWF6PkcKrCW484RCcGyk1Phzqhyx1dhyZOtmGpafmKhO5OvNzFAM8W3T9Zzmza5Z
         IbsRzJFFErQ8D3uRvOiXSl3q5KufvEQyZWl3xJBBZNNzJjiHPyNc6X/Zk951Xx2vJV5r
         FSNhmSdPYdR/+FDYbZuROkB3nnvyvjyiMsXqx4/kPfrg2StdKmyynVBEWz6bz2jMHnMA
         8qYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QQ4Uu4zoWyKmYQrq0i4l3HgKr6VpAHaNUVdQgPTsBAE=;
        fh=v0WrGFe71PJ3+nfS0BRExroxtuQLdzodhFVyTF9khAE=;
        b=JxSxhdnX+NDcC2Ko0TAZo92DykodEhJn7l9YLUW3hO0A4RaLNSmF/g/QS8LAJCP6Vh
         jE7i0qSPTOhiYDaporxlF+JqJDbwfHYw1EwEz4ZpdBcjIZMN0kx1bPxqDGGIBH4VoRQe
         FYbCWV9gTEMQTn0+uEfqKH53V/wjGXyAQ1vmToLgCFGHbVFWihHZs5XK7ADDJ1yIS6Mv
         9svovBYGXap+DYt/3AscQRoVkh9pCd4qnXmzfYMIpXTtS+qjsuWIlses31GQxoI9qWmb
         P+Xk92P/SpYHTBymQmUiVHMvS4azZRTcrCAyGgIPgcICFDxa5lQeq6pXSEe67JvzqqYJ
         TGTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=e9xXcRIA;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2462ee2b0desi212605ad.5.2025.08.21.13.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-328-q248E2dpPNmkL8KG0IaQIg-1; Thu, 21 Aug 2025 16:07:39 -0400
X-MC-Unique: q248E2dpPNmkL8KG0IaQIg-1
X-Mimecast-MFC-AGG-ID: q248E2dpPNmkL8KG0IaQIg_1755806858
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a256a20fcso8251785e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKi2XnoiZ48FFwZ4Mnl1WyDPJ3sMBJl5kfOEwpeGB08xFK7/1vQ173RemIdXrCLzXIpDe0ZOtiftE=@googlegroups.com
X-Gm-Gg: ASbGncusjTD2G6RkSaM5ugDFsuN+oa6l30jWnhBqvcUwLXihkbPUUppxPTEQM3dwvHE
	dXvptJz4G7rCRSufk9b9CpuKi+vbl28U644vyoab0yL3Mqlgp00n2kd5+g2p+Fv/IguAzH0HHNH
	Jk/1w99ElKGxwtempG2lbFQq0wyXn9EVcz3276B9XE4Xjzb/T3G+LY4Uf8LwbScWWK9kKguTF79
	73bS1aHvPMNtotqdgNV1fV1sJmbRqllHb5bX9mOhgIKL715sH0bZnMYU9H7nCYJHGu1gR0NQG9h
	pBJIWtJwbiLgsLDFYxoBPjgJj/znFaIW2HJykmelsV4aEwehKaxtBs2AS2dAWstxht/TJ1b0r1n
	s8TUg5ixZ9jQ9pM3PFBXWSQ==
X-Received: by 2002:a05:600c:5251:b0:455:f380:32e2 with SMTP id 5b1f17b1804b1-45b517ca54cmr2646485e9.18.1755806857885;
        Thu, 21 Aug 2025 13:07:37 -0700 (PDT)
X-Received: by 2002:a05:600c:5251:b0:455:f380:32e2 with SMTP id 5b1f17b1804b1-45b517ca54cmr2646245e9.18.1755806857378;
        Thu, 21 Aug 2025 13:07:37 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b4e87858asm18672185e9.3.2025.08.21.13.07.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:36 -0700 (PDT)
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
Subject: [PATCH RFC 11/35] mm: sanity-check maximum folio size in folio_set_order()
Date: Thu, 21 Aug 2025 22:06:37 +0200
Message-ID: <20250821200701.1329277-12-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: KS2QlWHfuhDxTdTEyaG7zltGRQTPMeXT4mYfSFxRdpk_1755806858
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=e9xXcRIA;
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

Let's sanity-check in folio_set_order() whether we would be trying to
create a folio with an order that would make it exceed MAX_FOLIO_ORDER.

This will enable the check whenever a folio/compound page is initialized
through prepare_compound_head() / prepare_compound_page().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/internal.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/internal.h b/mm/internal.h
index 45b725c3dc030..946ce97036d67 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
 {
 	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
 		return;
+	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);
 
 	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
 #ifdef NR_PAGES_IN_LARGE_FOLIO
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-12-david%40redhat.com.
