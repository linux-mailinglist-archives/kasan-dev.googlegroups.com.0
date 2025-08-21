Return-Path: <kasan-dev+bncBC32535MUICBBA7ZTXCQMGQEY64SLYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0559EB30372
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:33 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b10946ab41sf34291831cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806851; cv=pass;
        d=google.com; s=arc-20240605;
        b=g4f8AhBFRX3X8vzBHDOPY5ScjbKfBYNC1mlredFUmCo9yDktadLuU2mZVCMKMkX4o4
         O7gs3yMr4HUMXaxE67h3Taq/BbewP96mx7kDfEh8aNHtoe6z238Az0aNq0HozrCD91Eu
         ozshKYMMTH3fz5QJCnanPeCIwJuhXd/iD1RbArxOVyirQoEsuPs9X7mGbQzI7z4yAMFJ
         +jRfP/r2s90mWKi4GjcY2i8fadCUMWFLnJ2M1h7xooCpW5saVqZJID4t5Z9B7TItm/z7
         pC24s7i369FynQ/w3nh2s+qqgVJpJ4oIR+b/YTLKmuet120FHRkTIPbSjQdZjkNt8JR8
         Whlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=KWiicLJSV/RPJSmNX+A3GWAOsaUo7+MXwt2f/8RC0F8=;
        fh=SJZ6+3Pgsa+HG+WpZ7HlenGxBZeSnC8DNIhi50f4mTI=;
        b=MJ1weZUMF8Tf4Y++TE8spt3FGmBmqDccueeQaiRc3ea8P6GtZUHiY71jm/4FRvEAC1
         ZEuXeK1Z2NCqq6yToSs221uvMSyKm49QY9Kb6g5xKPhZixCJLu8CJ+XQ5eZky2apAeOr
         dE0+kES6oOUuBfUAvlZercTptwswL0ZU2xnWAQDsI1R94c8QE6QpFj/B/JV7oPpmtF5b
         80nP03DFSxF8SsU/3RXL/XfzKD69jKP1LeCWd264P2ZfogM7SX5mhbVzbx8ix3oH0ly3
         QvPmZEv2g3bMSXpptOxGzfH3BSFoGJ7Z6dKg4ji5mCadFZYqUQNdZlYmgWN6KAcL65VT
         HpYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YjT7EvFr;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806851; x=1756411651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KWiicLJSV/RPJSmNX+A3GWAOsaUo7+MXwt2f/8RC0F8=;
        b=nY2QqRphAFpJrhwu7pxvI9zcVjo/WGPrmxiZ/wIL9bsi2SjrHHAKACRj7Ez6C5cKrn
         /H/toTeq0GSQgLcbgc316ltYhPqnjZbNBvFMikgGMjGyfDmUvbLbC65JV/dOijOYia2j
         A+tYPeeVzf/LwoKD4ERsmv0R/1kuNx9vFRleIRJPfUpIF28ZS6VgtAs4ig39ywohbWyl
         662oivODBWtZvACgFm3U5qhFj0uLHbDuoaPZ1QcjZyTLGbtfoPCvp6H1bgi1PNxzQAwA
         DyXkftKBFsQQk0Nqse7IF05NzeiA2FpAY2BIAeb1AF7FS+k+RFhJCq1tjbkHR8+1MRzL
         38zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806851; x=1756411651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KWiicLJSV/RPJSmNX+A3GWAOsaUo7+MXwt2f/8RC0F8=;
        b=hahuY86XIUT6klX9clXXYBhEmoM/9cH8j1s457C3jro5viiYAY+ogAzCtxmJbFi6dJ
         LaJTZLd3x1BQAaxYP2jrQb0LeuNk7Gn8WBHn5LCGJYK1KjKjJAUdE8EINmbG+07NVBjQ
         ucyuI2amDhrh7V4nNM9nvkJdhxLQCNrMQNzEMfwHI+SDHKblXIU6/Ol7Fgw6fOM8XpGI
         g6tHy56pBhKlzucsFMntryELAtD/kJHqyusblEAKpzlFLjpszrNHAVsGZGbddQ4hTAzR
         LYmxukK/uivDB6vuVoqocTMNsdFEd7oP5cPeLYYvNT8njSpKcy1s/D5Tnb9SghTWT0t+
         N8Ag==
X-Forwarded-Encrypted: i=2; AJvYcCX6jbFjwhUcPwt43HR1tY3uLzNzhLJYAXHEJ8DIX7+xpYvN8ysN1UK+nvo1PJ/O4zqL6231Zw==@lfdr.de
X-Gm-Message-State: AOJu0YxbKjuyG84uq2Tg1abc7rLobxtklcDgE0xKRGRbB6sMyCPiV/7r
	BcrFwkHjWBhR7awPTG1kvDPRMJUDgbUF57DEqc3hVatuy8rgQMhR0caZ
X-Google-Smtp-Source: AGHT+IH+iGP+4T35cCaTNC6pDq9XjKdInrMjWxsPuH+8pLvkGMVrHQ8YatA2AkWYXeGzDzCk0CbIyA==
X-Received: by 2002:ac8:7c53:0:b0:494:9d34:fca5 with SMTP id d75a77b69052e-4b2aae662damr8322431cf.13.1755806851387;
        Thu, 21 Aug 2025 13:07:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZck3IckNQIfFMYPDbDDhGKm5of5yz3UapWeVGo6hfJR9A==
Received: by 2002:a05:622a:1444:b0:4b0:6adb:de19 with SMTP id
 d75a77b69052e-4b29d7b50b0ls11426221cf.0.-pod-prod-00-us; Thu, 21 Aug 2025
 13:07:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQpbGPnJ69x9pVhfbH3GEMJjSizYuz4y1HTPaj1pvnfbz+CLbPryK42lWgoN539zGZ0bdtm93BdQE=@googlegroups.com
X-Received: by 2002:a05:622a:130d:b0:4b2:8ac4:f097 with SMTP id d75a77b69052e-4b2a00fcca8mr40584861cf.33.1755806850350;
        Thu, 21 Aug 2025 13:07:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806850; cv=none;
        d=google.com; s=arc-20240605;
        b=WXZwbi7ULCpD6zXIeNM+tULaqFLwKDAEaBH7gYsOJlILZdChbAJ/eziJR3OrqBZ7am
         bg/ecpApJ0XN8tcX9bew54bzPe2mh8W7aw/r/f3yUpEM4OuWz2+8ryaIl1IAKg4smhkB
         4zN4sn25QHufvmv/E5DgHDEMw7qkgMRyblRbgB3/ZAn3LgxJNqq2BmI0vjbm8yG41PF8
         ckibSQt6tbYfDwkWxPRD/7l/gVMaghPK2/hGYA9biaKeSczK8CPSTNSisrH6UgQUmgiJ
         zTl6M4aKxZPJfIXEZzJcM059FW2UE2v553a1coPEyw5c2GJZiHSIKkTmhDY0bHMNHwWy
         Mnkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A9Znt0atqEjtEUkbTSfKRsvBJ9rEcbnqI7Kn1XkJSrA=;
        fh=miKEjCkrEEUSE9mt+AoTpyMTmwmnX0SZf5F88vTHpds=;
        b=Hhyw3lUMAZ9a8ijz+oxvaynmL9GhWwrQo0R7VHUhvIXpixE6A8V8NynsYZfeESKTdp
         P6I2CJcl0kB2VCDKKgvFP6nQVaEwMlmxkvG2YRz+n47k/Vv6L+W9pdzJcCfoB+RgrVar
         U/CLQ7BdT3LR90nFoV+W8xK5M96AavrJGs0nrESYYWgLvqLEAa1hTZpkNSkE85Ph8Qql
         EE3QpRSWC68l1kJ/phJHLs6hcYWD3BON1uNShIPODOvq4hDI/OnEZ3g0ETyAIrIOvM2F
         0z2MsaYlqUhM6qeUL9dFzcBMBOeei3R5HdaSzUNta/+FIwSJDxWtAVHLRYna0SRelb/N
         ESZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YjT7EvFr;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1fc34esi63765185a.7.2025.08.21.13.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-206-fj0-X5bDPrKRCBR2dJTfFg-1; Thu, 21 Aug 2025 16:07:28 -0400
X-MC-Unique: fj0-X5bDPrKRCBR2dJTfFg-1
X-Mimecast-MFC-AGG-ID: fj0-X5bDPrKRCBR2dJTfFg_1755806847
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0cb0aaso10735305e9.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXidKrXR0eomtKkIyWH5Tv0b8GPcYMqXi1Ojdx3AVTkN6btlvYXIkTp4hRNV7hTY853RS12WmJJidY=@googlegroups.com
X-Gm-Gg: ASbGnct0XzFcRDz+f48V3e4dpBzmXnwIQC3tx+fGqdQOWEOirX1sNpaIEIsmpchq+On
	mJLhUIos2OissNrOtBc8QoJmkvSPND8PPNbIHURs5YMThlgD1v53ipX8Bq6rnja0VmLO+ZXNqQp
	sEE03tvDKZ4zKG7zzJL8XaVgivihcg+uvlQ9CReowoW6GtGoYI5DDwYB1WAdMKkVUR0kbRnSQOU
	K/1E3cnL/UtfLkDyQIkvoW4b9UQszAistv9sL7qt8R7h6v0EYZEqWbfGV7tge4Xi3PSK5QUpYBF
	v9C2Cis8UN2Zso7WdIAFw9UpO/ivJMvHgsbVy6UBrjoImInk9q5Ot6xShqAYK3kpbVPoW397a8x
	0xt99+J4Z9E50iBMocbRikQ==
X-Received: by 2002:a05:600c:3552:b0:459:dde3:1a33 with SMTP id 5b1f17b1804b1-45b517d26d4mr2922375e9.26.1755806847241;
        Thu, 21 Aug 2025 13:07:27 -0700 (PDT)
X-Received: by 2002:a05:600c:3552:b0:459:dde3:1a33 with SMTP id 5b1f17b1804b1-45b517d26d4mr2921795e9.26.1755806846742;
        Thu, 21 Aug 2025 13:07:26 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50d62991sm9535385e9.0.2025.08.21.13.07.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:26 -0700 (PDT)
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
Subject: [PATCH RFC 07/35] mm/memremap: reject unreasonable folio/compound page sizes in memremap_pages()
Date: Thu, 21 Aug 2025 22:06:33 +0200
Message-ID: <20250821200701.1329277-8-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: WlSz26AtVerftMgFjXl2bzk7norIBVLQ1SOKZIu3Mcs_1755806847
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YjT7EvFr;
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

Let's reject unreasonable folio sizes early, where we can still fail.
We'll add sanity checks to prepare_compound_head/prepare_compound_page
next.

Is there a way to configure a system such that unreasonable folio sizes
would be possible? It would already be rather questionable.

If so, we'd probably want to bail out earlier, where we can avoid a
WARN and just report a proper error message that indicates where
something went wrong such that we messed up.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/memremap.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/memremap.c b/mm/memremap.c
index b0ce0d8254bd8..a2d4bb88f64b6 100644
--- a/mm/memremap.c
+++ b/mm/memremap.c
@@ -275,6 +275,9 @@ void *memremap_pages(struct dev_pagemap *pgmap, int nid)
 
 	if (WARN_ONCE(!nr_range, "nr_range must be specified\n"))
 		return ERR_PTR(-EINVAL);
+	if (WARN_ONCE(pgmap->vmemmap_shift > MAX_FOLIO_ORDER,
+		      "requested folio size unsupported\n"))
+		return ERR_PTR(-EINVAL);
 
 	switch (pgmap->type) {
 	case MEMORY_DEVICE_PRIVATE:
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-8-david%40redhat.com.
