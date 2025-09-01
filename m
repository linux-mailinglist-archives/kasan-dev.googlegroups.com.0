Return-Path: <kasan-dev+bncBC32535MUICBBMHN23CQMGQES55YLIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 85317B3E86C
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:07:30 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-244581ce13asf88548475ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:07:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739249; cv=pass;
        d=google.com; s=arc-20240605;
        b=KussxB1mOXz9+jg50YoaiWJAHHck1v+FeQ/9EFmwUHAGdT8MZdnnTNTfedeW997Q7C
         pJJG5zgP6P6pCutnyikZI7NR3mpJENmqyEKv5AASi2NZhLdrN1F0HeCPIpEvd/GH2V/e
         V/FB31QgpoaAhxLNxiQCwvTEjOju+Rx4lfXx3oIPmb+sKEeosGOFWUK+zNZvybSSAt8O
         S5MDXiORsPQkfomNYY4/TySNS0ulrKQljO0AJ4OGrUtrVKC0ycUbpBzaE2QniY7SuAJh
         gq1kBeah+4Qvx3f0v3iC8Ldhp8zBW/XrYC8rPuqC2e0N/jNBS5yjLMQlx0iCDLrC+QuI
         tLYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=v28OcadCt5DQpt+CivYZsBvXv6AAdPKUJ0JyMl/CYow=;
        fh=JJ3R1r/S+03XaZMzIXNi187vp4quCKJb+I0OqCol/OQ=;
        b=fvyZY3+89I/k7lY9Zm6L2wvIwrhjIEGm7+G83AF3x0Zh+wDwmi/BhYXP6pYDRKVLz8
         cnucU+mWc1ias9Khz9oFcGr1jdeR22GJkwfy5glEdJQBMEjmhuponpY5c1DckHEl628I
         J9lc2riH+jTQFxIakHG72CUhIadkD3Wscp4Qu/VxxFiK+ggm61NwSKA/8jZlFWBMmTsm
         jb+MgV8e2Pk+OhfUoxYG6ZR/MqxOWtlZfsjik1lQ+IaIP/uWwlSxFcywqAurcw963sgu
         xvISTN7cu2kHbtPlDFj/CK6L/1S4Ouhf+jaVkPNtXiQ2ffeI8Ay1j6rQpSwCSrF5y5QJ
         cFHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RbSMFmaC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739249; x=1757344049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=v28OcadCt5DQpt+CivYZsBvXv6AAdPKUJ0JyMl/CYow=;
        b=vQRVyIKgLvRRy/+7xFZBWTX0AOWq/j1y2TmnesiCTiXfTND++k3K57IXXlhk6819v6
         XOww/8xocSeWig6BAdx+LNwJoPqhoLr1kUpon2OdUx8bNwzpVMY6mRm2C4PL4gi5Win9
         +Dqor+cV0dv9rY4FH81jOr96OyE6XvRf2H14aQ9mD8TyfXZk/87UuWm409KZfIOCrBtg
         YoDkXzrzM82IG96+acJ98KozxlyHwWmJoVv/GGme3S303UV0tx9FPIkQe3vFTxuaUugQ
         wTRjhg7DtVygFW+VdzkQf41KBwTEg1Aff+KjiZoE56N6IoLjEQ8FjRl+U5n4hG0UVUgM
         TqYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739249; x=1757344049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v28OcadCt5DQpt+CivYZsBvXv6AAdPKUJ0JyMl/CYow=;
        b=SoGNEmxCpstAEFHq77CNjPd+1pWCcxhou8QIENOC1YZxf6zqCaBYUkTAB17r7FtKUG
         0hbZSunRaS/6I6Yreii1tkJOHSvHohX9Y2iR9VIhUHPytG+WtFVl4QQxGMO4XLhQkiDT
         1Uk22apoR5YV8wLN3jeTaGLXh5uyQ2lUrLCBAApcbJ3AgcyMaT22sH/aIe/apjDjVD7o
         HIKWj4Gzp3wrIOAv7a6GzUeNYvNIbF6BTXeM7Wex05dOUF8NydHFQi8LIzU0kGLhMVjq
         FORrmYCULbyblKXN46YC0xiIu+K3WhEytkVMHj/G32w2/8LOQe4bmKlovvJDSkU7aooh
         w31A==
X-Forwarded-Encrypted: i=2; AJvYcCW54RQA9jmVXbJDkzsba2HoB/TxH36qA8aFdBBgeJx8F+o911cclkRJeZHv5wiQlYlcmiMi+w==@lfdr.de
X-Gm-Message-State: AOJu0Ywxvru3NSwL92BNVmKajTRbLkhf2p3U4VCFBhtk/TM0kzcgZcaM
	Ie85M12NSY0ikctj8tz+0sMF4WmxKAtWJ+qEv+6BWsrsS/v14PzzSXnH
X-Google-Smtp-Source: AGHT+IHipJ9zGMfqsdotovIk2CXrEethggTd8gPiDTkjEL8xQNqbumjIpIrgIpeNpXxTDDSAobxt3A==
X-Received: by 2002:a17:903:41d1:b0:246:ae6e:e5e5 with SMTP id d9443c01a7336-249448744b8mr97361405ad.8.1756739248587;
        Mon, 01 Sep 2025 08:07:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2epP5Y5mfH9ZDoiDQ4kqND/0Z8m2x7QjoJkAGwsRITw==
Received: by 2002:a17:90b:2ec8:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-327aaccd947ls4713660a91.1.-pod-prod-03-us; Mon, 01 Sep 2025
 08:07:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUhibaerDRCMsf0McUjcZLw4ae7nl7va1qiEnQ4RCWhM6iFCp8IpVoz24Jr6H1kzdRAXY4UVGt24Nw=@googlegroups.com
X-Received: by 2002:a17:90b:1989:b0:31f:1757:f9f4 with SMTP id 98e67ed59e1d1-328156c964cmr8563901a91.24.1756739246351;
        Mon, 01 Sep 2025 08:07:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739246; cv=none;
        d=google.com; s=arc-20240605;
        b=V757UEScxWSgudH+C08tF2Jr0aST+UyQsYpm9t8ux3HFswHw1tMpKfWQ0Y39vqQ1Gg
         OP+9W6WkLivAGgyuTGsmB+xQ5E/tRE/fcvexPfcfKApyngEtM9Pfr+5vKvX+DZKqBCyN
         pkOfGEFn3Azt7ykOmoCt+MjpKj9UrN2/5zEvz+FUHIdw9/AkyNpjqk5dmbLTcf2fdong
         3T+syu5wyKAz2fSe9QsdbkO+PTcBfkMUExBfXl8+OUaA4H5M2jdzpC6eKxYv+3L88ihH
         vtG9v5EdgBx1V0EYUupazbNdNXOU8K3KA8ra/QJ+7TG/j9bRiC+OnINdueCLVofA2Iwu
         lbLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gFQCeV5GlShS/zx1bu5/T/iLUPYfRFaciJSmR65IujE=;
        fh=FU+UfFMNNgqwB/q22cea9lEjzheMb4JVtAveqFQJofo=;
        b=ilN6W24qMgemlDL8yGo2ymO5bWM0i7WtVzH30lvz9F32v3bO7V/y01g1dOV54jM+d1
         xkDv2i6VomZIVEe76TszGhgIHNhHkfSNA8dDrUitIsyLPoo0Uz8Icu1kLXPsesAYGJIo
         BGUkcoxqfrMDLDQY6tpPUSISBWRviRTinitaDWKujvLZDfqhcUrc9HehUF6q5ZdVXlsY
         XEt8p/7CrT91VMOPfa5Di6mUgFSbe/GkGIFeoSD9g84IOFLqKeZgWWsQPFc5DF8Yi2bz
         cHWaqNwWSeYsW+TDy42Y/i/tdRpQuAj/YpWsYksaFKTmOU3TgO/BGOKXTsetIxYYMExh
         lyUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RbSMFmaC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f6ad8b5si663870a91.3.2025.09.01.08.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:07:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-616-CT1kZFJdPz29r0kFU6Fbtg-1; Mon,
 01 Sep 2025 11:07:20 -0400
X-MC-Unique: CT1kZFJdPz29r0kFU6Fbtg-1
X-Mimecast-MFC-AGG-ID: CT1kZFJdPz29r0kFU6Fbtg_1756739235
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 09663180035C;
	Mon,  1 Sep 2025 15:07:15 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 90EDB1800447;
	Mon,  1 Sep 2025 15:07:01 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
	x86@kernel.org
Subject: [PATCH v2 10/37] mm: sanity-check maximum folio size in folio_set_order()
Date: Mon,  1 Sep 2025 17:03:31 +0200
Message-ID: <20250901150359.867252-11-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RbSMFmaC;
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

Let's sanity-check in folio_set_order() whether we would be trying to
create a folio with an order that would make it exceed MAX_FOLIO_ORDER.

This will enable the check whenever a folio/compound page is initialized
through prepare_compound_head() / prepare_compound_page() with
CONFIG_DEBUG_VM set.

Reviewed-by: Zi Yan <ziy@nvidia.com>
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/internal.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/internal.h b/mm/internal.h
index 45da9ff5694f6..9b0129531d004 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-11-david%40redhat.com.
