Return-Path: <kasan-dev+bncBC32535MUICBB2HN23CQMGQESGMUQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 67EE6B3E889
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:08:26 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-718cb6230afsf15102826d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739305; cv=pass;
        d=google.com; s=arc-20240605;
        b=IuoowYqkDZVZn8AspgB571vqDF/eiq0LFebjQd3FsDEVYUp5ZOBgqFB2b+kjGQYOLT
         hyCPtbRfvn30uBmibI1UVYzeDP0C9w5rbB0+d74g5zS1R+aSTKWc7Kp2vqlm/73EpVjA
         1uKWc04bYVJlbM0bX0GAsXDNJJTISan4gY3CH1jO/Ds8ywLYqfQeDvM3qEJ5OytBkvUS
         JbVQxSoM5uyWx6T4jO81vz6FlLb22u6rbww5mrECG5Th5m4WqShHJ01O+8HxdOKuylIp
         T7oSUC4v+iNbtZrv1lLR8vzLqOvSlo5vtpOP9c7Zzi5hUndPWC6q9dCY29ie8AUradQp
         teAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AhTHLOeAJ15B7SyQzUU7WvpZeNTh+j0Jqhh+Vxbtzn0=;
        fh=p5Xx6ZypyDE7OCwn0j5L/2JF9DVEz09f8m2hV0vZ5e4=;
        b=i7oxPHB8oi/cMPclQxEPKGsyQkPX52mzYhnkyqhsoOnMulp44H+R5qfgLVeBQAITYk
         jjmz12hL2RXz172/t5s7rt/cQM+SlQZGQd4NLDQv9O4FPDFRfaN3GPv9NoeTEjauT6is
         TGPaZBga/BhE/95XrN19cK6Tr1K3Nz6AtMQK/nuxNGQ3r4RjXGDzaFUMWATaQadFgZQc
         Pj/0I1lRynEwPyhXWoRn2+MfewZdykqoHwPXilPGJ+C3CIy2eDJtXd8nxVBUp0wVdapt
         3OgqtsOQPR/0+UXpGWZ3D2LW4AsFafI6byIdf6mmyOdGQ2+8NJS8JYFYIfa31BnClY8S
         Vn2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WFqQfaGq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739305; x=1757344105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AhTHLOeAJ15B7SyQzUU7WvpZeNTh+j0Jqhh+Vxbtzn0=;
        b=wgxaFe6IYc3Mv+vhNsXIIHJ99MsjqTyovG/xtqBsfmPk7KqR/yYFB9LDXcG8BXGLHe
         GCelH262CCdXQjd8McUGJ7OMGzcj3aInvbGAzKLvraAkAVkcFySdlEaqQJ5sIx32rnQA
         gF7rpxIzn6gnvjxHnIaqvoupscKVECrdicnlG5Hsa57gqWv4ryeWsU9fqOcU8478UMD2
         q7IIHY8Sz6bM4725/Ei9jTfYi4Kw2EoAwmaVD61YS9Z/MXCZvKgsVi9h2FFa5WXh+pM3
         b1k9MaL4Kkr18x4o7qFLbdCrGDIQ9eQvtfyHugCIaO9OS/m1up9BWmiuz43MR7vNDZcj
         syXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739305; x=1757344105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AhTHLOeAJ15B7SyQzUU7WvpZeNTh+j0Jqhh+Vxbtzn0=;
        b=eP0J57xUJNVNg671h69asVBjx5xvkV2Ut0+A5t4LjgP3j12iBvFeOvTpViTmuhhgJB
         jdBQbi3H+MjrxSDPW3h9FgKHzt7r1ujC2gnFeTbHRNL6maNkcWiG8gBaWLqCLLupoiiL
         oHItWuV/oHsyCNIXBnxryq22EqppJMEBCaJ8H8bGZ2HsSgEoZjbaIY1Vul4xsrxO8Ivd
         3aSoIy/cLXE9zkAjslG/IevN5TYHcYL7eDpoRl/ma9t4DandbH02xCjWGiSF79ht2B2N
         /4a1Z48n/B5k7338Dx7kXH37dzlWYXk04E3QRNcEX1TAfyF3m5pK7YOuisNlPwUnQ4Pr
         Pakw==
X-Forwarded-Encrypted: i=2; AJvYcCVNU7/T+eYivbtMj96yCduTkmePeAZ/ey9HeqVyzdUbR0a6IqSDs7FyQi8WcE2giDKuEeibrw==@lfdr.de
X-Gm-Message-State: AOJu0YyBqrjZWvNz2jlGS89upUkV6WaLjXXC502olTG6XrHycuQLe150
	tw80xJ0WXeoKO0aq4dM6w58hB/+lPt10w8x/pCc0jStvTBdb1ZQ7mksG
X-Google-Smtp-Source: AGHT+IHjGWB2fk0R9QvExv2U9knPmWBR48MXxdJwZp9Gw0q9XBx8K4y4huTe+mv2V/VIolVTHnV0Bw==
X-Received: by 2002:ad4:5ce9:0:b0:719:e824:5a42 with SMTP id 6a1803df08f44-719e8245f8bmr31142396d6.49.1756739305104;
        Mon, 01 Sep 2025 08:08:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZey3n3Hw3iETUZr032Lj8oFtQyiPAuJntQBBQgPhJjO0w==
Received: by 2002:ad4:5f49:0:b0:70d:a88f:1918 with SMTP id 6a1803df08f44-70deff90278ls68918666d6.0.-pod-prod-03-us;
 Mon, 01 Sep 2025 08:08:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWof25lNhKAEFyy2n94jSqS546NRnZ2LaN1whv7u3To7jnIcAjhVI1/y4XWxh8InV/uQsX/46Q6AQU=@googlegroups.com
X-Received: by 2002:a05:6214:240e:b0:714:91a:d51f with SMTP id 6a1803df08f44-714091ad6f4mr63205696d6.24.1756739302665;
        Mon, 01 Sep 2025 08:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739302; cv=none;
        d=google.com; s=arc-20240605;
        b=KvDJLTlam68E8YA7+1IFim2pOtelgV0vytyeM/Z4ph+1onqJrO1cnpguSV8YAFS3t4
         2QPEDqbLAKFqqxJBpkyXfBONEFcM8a21zLyVnK5Q3GM+gksgB2PDcJQQQGDrYNhWWZFQ
         5Mz/PzpRngBVQSpPqlWTqh3I7CL+IgeVamC379MDVO647SGXesaIYTPbs69J+q8Kmss6
         5UT/IAA4w0r9KuZ+QUq21oD7/+pmPtzroPEb79pkZ8fLfYu/VqkQguiPmV1W/lTDh6Yi
         q4KcFWMQX8NLMHHvnssrxmgKWw4grbH8LWIxS9HU7cowVtq6Yogb3M1OIEEEhdBx1JQE
         vYxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OnikdlkxszJnxILYw/0FQIsaidg40vxq0JvbNkA4kBo=;
        fh=/E6tkKVOuzBmayN7VWrhfRPnEmOY6l2P9TuUpRLnJco=;
        b=TIj6eu9M8FnQzGUVdV4ZhtfCQ2PdHCIBkYqnS/T9zlkjxK1Ua1oa61egvSoi43kSEu
         9gm4lU1x8Nv6gjFxp7hzkSC6/1as8uJZHT7CpSul/uWjhUunGTl/sUMoZ/mmU4DVjI7H
         5oUMoDq5jnYsRMLC4ZUs17+u/8I9J1m+nuSkVKehRZblrVaPfavlCj9l2BhRPwLnB2CT
         YpWI9YQJTAmFPWm8r1lFeqPGD5kG2pyM3hwh/DzolhMrdz4oNeKQuomh7AZNvBOxBBQn
         EFJi+S849xAl6oJYUD2gEBnKOPf80RocrHdjsLZPSiTYPKArEKvS7BaJzbQ4jF7JzJoS
         4XYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WFqQfaGq;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70fb27324d9si2228586d6.5.2025.09.01.08.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-66-OMQKCEc3PTWsL06WnC7hMA-1; Mon,
 01 Sep 2025 11:08:19 -0400
X-MC-Unique: OMQKCEc3PTWsL06WnC7hMA-1
X-Mimecast-MFC-AGG-ID: OMQKCEc3PTWsL06WnC7hMA_1756739294
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 41CE81800446;
	Mon,  1 Sep 2025 15:08:14 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A308A18003FC;
	Mon,  1 Sep 2025 15:07:59 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v2 14/37] mm/mm/percpu-km: drop nth_page() usage within single allocation
Date: Mon,  1 Sep 2025 17:03:35 +0200
Message-ID: <20250901150359.867252-15-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WFqQfaGq;
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

We're allocating a higher-order page from the buddy. For these pages
(that are guaranteed to not exceed a single memory section) there is no
need to use nth_page().

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/percpu-km.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/percpu-km.c b/mm/percpu-km.c
index fe31aa19db81a..4efa74a495cb6 100644
--- a/mm/percpu-km.c
+++ b/mm/percpu-km.c
@@ -69,7 +69,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
 	}
 
 	for (i = 0; i < nr_pages; i++)
-		pcpu_set_page_chunk(nth_page(pages, i), chunk);
+		pcpu_set_page_chunk(pages + i, chunk);
 
 	chunk->data = pages;
 	chunk->base_addr = page_address(pages);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-15-david%40redhat.com.
