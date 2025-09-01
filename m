Return-Path: <kasan-dev+bncBC32535MUICBBHPP23CQMGQEGY66EFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 249A4B3E8CE
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:11:27 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70f9ef27113sf50389176d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739486; cv=pass;
        d=google.com; s=arc-20240605;
        b=aYhNECmWwANw9njBJqS/e+sas56yAAKGammYCJID680ybBDoZd2YZpM8lB6USXvE1U
         pioqB1Pjir3wq6XQfLJMUR/h4jmKKLfkbSkrT173HtUVz/SSePLToNTS7TwHZwKSUrQE
         dKPprkwAGz6Y96U2DKLl9gWsSawe+fWviSCzdYv8HztXbE0xG+ZhgBIBCi/LH39n+3RU
         VqeWNk98coZcgJciBq0L0TLa1fUuD7HuKBZicTPvc2mRlTVhzXVfsdjeQClZ6SWsetOl
         /ON/BVjymCHSt61FcJcVojq57vzbnNhArMeSMmxBWz7baCmIkNi87oERch6YfowZiRKk
         ngag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+W2QnFFKyH8EU1CVQXDZDaQlloWzx1lPXObNXGDlZz8=;
        fh=KnHQoAioVqrGPkc4u83cU0E5bExch85hzYVKKPbuBkA=;
        b=F5FW8vgDilrNTX+5nSKgnar/q61ETUUC5xw6kLry5CIzMK1z5tfXh8pRb1W+0K8I/1
         zICHFLEezNDY8BtIz3Lenic5uFTXbvUhlLmbJ3Wfu+LawdL/L8eSq+aDAbaOR0CkdeSp
         6CJSOIriopSZud+mPn5vDNi54YFsiPhku95I4DqiKWp1Pa4BwNU+VApu1i6/xRa3lf/0
         I74qAU1cJvXmbTZK1n8F1H7/bIrL0jU83nAF971ezq4N3QHZeANcthVNwoc7IE6gx7J/
         aol5bSwtEiox70wUtA3usqaAvA9i1kDvUGOD4HZu1lls+IDxPWotyIUd/zvNXCP4Qbkb
         QTeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FZiMXx7r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739486; x=1757344286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+W2QnFFKyH8EU1CVQXDZDaQlloWzx1lPXObNXGDlZz8=;
        b=i6nlNOfVnbnznpm6Ok26Gf4zd0WsDC4SEwcQOXONVtPMH6Gx1OHSD1tZ15ul171Ruj
         MPdJnBsJUWZPYRox0Qe7Y1NRjAPBKXNXSqUewGiAYdAkqnd2My5zKAHCvDGL2yySAVRn
         E9NH85eS5xBmarUe878yrIphihaDwVyOdQgTPCdeGBeFnBWayRErg/lXhcli7IwXaz8g
         Q7ZY6Jz2CMt5+qutsKyNoPDlOO8lwJMshyaOalbBAv47YQ1m/Ka6QedWKcoAtZQeV/kX
         ngvpY14LP0+j+FHbXIPc/8gh1B/215iSB3LSqf1jHLjtePCn6I1GApUME7cbxXDkAeA7
         mgFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739486; x=1757344286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+W2QnFFKyH8EU1CVQXDZDaQlloWzx1lPXObNXGDlZz8=;
        b=IkuL6kbnODDumKsxMDagqF/YnOEWrMpSGBdpQeM8FZyidFfXLDtY3Yk85tmqptSu61
         diqucCViafI1tvDmBhE6fWkEKjlqcDWNTDYM/G0j9bsjdDPhz0unQPeZITOzdTHQIfuy
         1jMTV8GatX2+9lNMA5EQ9/x2JyziRrGM2RjMqxtUmHJubjZeLCldojQaSxYXk/aGjNTA
         6SMLZU7Lpmp2or4Ec+PC9JMvY0RxlItfagulJw1iF99O3TS2fN/B5+RNe4Yw0Y8ZLSup
         /Jr4IK5Vp7M04J8K8BP15NzSyOvAIF4hXbqrrzbM8jacQ7OpgP/mh8uWRBBmrnd2KwjT
         yvbQ==
X-Forwarded-Encrypted: i=2; AJvYcCUMke0QJntSnRmtYVlxjRgNq9AiBheJLlyWnfNyE3TK2xu/wfVyE9VF7k04Euc5nGwlx5nvWw==@lfdr.de
X-Gm-Message-State: AOJu0YyQ7Ei+a/KLF9SXj/GLlYBC6rjl7DBO5EdDZ3kYcxI0CJXNzLnB
	/zdLVPkNpFRq91MaNU8ACNEY6aUqy2u1Lmr+9Yz00JgmVmqM2TJ+tcOE
X-Google-Smtp-Source: AGHT+IF8drGbow7pT0m78617NpfQSUtTk6X9YlIMu2U3+y4MjX8HUnuahN+fiWlrHNcVOfLnb9x3lA==
X-Received: by 2002:a05:620a:711b:b0:7e9:f1c3:6850 with SMTP id af79cd13be357-7ff2bd67a67mr854291885a.70.1756739485811;
        Mon, 01 Sep 2025 08:11:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/uB7MKAe5kygd2RnQRKRUQ8PcPXiRGR6JBF2vinLlTQ==
Received: by 2002:a05:622a:1828:b0:4a9:e227:30b with SMTP id
 d75a77b69052e-4b2fe8c238cls83643081cf.1.-pod-prod-02-us; Mon, 01 Sep 2025
 08:11:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMWQG48HQIKWTLHxt7rWqjjrmeKbyjCR9rZsJ0r5757YFEdztS8a548NCL8+V4A9/cTZcUhB0DSjM=@googlegroups.com
X-Received: by 2002:a05:622a:4e:b0:4b0:b7ce:90b4 with SMTP id d75a77b69052e-4b31dcd88admr96020481cf.44.1756739484277;
        Mon, 01 Sep 2025 08:11:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739484; cv=none;
        d=google.com; s=arc-20240605;
        b=SUe0q1GlcuyaLbqEGRSYZIUGxAOtF8euSICNlF1AabwxMq7Wcl8hDYpG3CCJU+0hZN
         fYvVf/ND6cCqIdhv1puwjtwlk5Glvupu3LWDcgAo1uvIESlou52zqmVp5dHvOqXzZCGu
         CzLH855xikEs/wpmVIIKlO3v5veZa25wZkPVX82abNvdOXdFq5UcblDh4qa5Uhn6HZEf
         VpgivJZplb3x5M1X1XZwQ0+7lIMfTCvXFEHHfuA8sSXHWzV9/mwJkqnehwuTUubiA/Ym
         H66Uc1yUo0+VDhWV13H9LisW1LL3czyyF3f7SFnaqMDEQHmgGLbqkptmqdvIybo0L6OW
         hZ+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EAbURELJ45jcqE6eG2dah5q682UY9xPl8wQ2wDImPZA=;
        fh=oJMj0agCFmOChlugfMFrHkBtqvCYP1TEO2nDmLWCKG8=;
        b=cxD3geq28QP4lUPDG4eE4LTaNEc18uSFKFSCF3n06kdPHhxctDANLcBq6tayEsKr4Z
         yKuAvnnverHP3cc5gtIUniQYewlDzZErd70Kik6HGKlNfPVlq5Ps5sKlN+g3BPHNdkVq
         UyvANLfAaI1TC/sYy2HlT2aBCQJsnMUsgMJR3t5h4Lqj3A+gW9qPmxufnd+ovx4z6uyL
         ESMO88m0eP1saSotHPhHN4wzmKXrIzV4nSys47Rn9rY+XpVrdsHC8QnZ/z59C1n8MxKn
         b8QO6qEoHybZ+3nayt3+3vEHHJZjUCE/IJZb6+DMJcoXGeP7yuBK10xp6ThO1r8WTOHx
         Fulw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FZiMXx7r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b660eeesi3502831cf.4.2025.09.01.08.11.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:11:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-33-LCEUb69uOTm7Rg26mamX5A-1; Mon,
 01 Sep 2025 11:11:22 -0400
X-MC-Unique: LCEUb69uOTm7Rg26mamX5A-1
X-Mimecast-MFC-AGG-ID: LCEUb69uOTm7Rg26mamX5A_1756739477
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6565919560B5;
	Mon,  1 Sep 2025 15:11:16 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A6BF518003FC;
	Mon,  1 Sep 2025 15:11:00 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Jani Nikula <jani.nikula@linux.intel.com>,
	Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
	Rodrigo Vivi <rodrigo.vivi@intel.com>,
	Tvrtko Ursulin <tursulin@ursulin.net>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
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
Subject: [PATCH v2 26/37] drm/i915/gem: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:47 +0200
Message-ID: <20250901150359.867252-27-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FZiMXx7r;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jani Nikula <jani.nikula@linux.intel.com>
Cc: Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
Cc: Rodrigo Vivi <rodrigo.vivi@intel.com>
Cc: Tvrtko Ursulin <tursulin@ursulin.net>
Cc: David Airlie <airlied@gmail.com>
Cc: Simona Vetter <simona@ffwll.ch>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/gpu/drm/i915/gem/i915_gem_pages.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/gpu/drm/i915/gem/i915_gem_pages.c b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
index c16a57160b262..031d7acc16142 100644
--- a/drivers/gpu/drm/i915/gem/i915_gem_pages.c
+++ b/drivers/gpu/drm/i915/gem/i915_gem_pages.c
@@ -779,7 +779,7 @@ __i915_gem_object_get_page(struct drm_i915_gem_object *obj, pgoff_t n)
 	GEM_BUG_ON(!i915_gem_object_has_struct_page(obj));
 
 	sg = i915_gem_object_get_sg(obj, n, &offset);
-	return nth_page(sg_page(sg), offset);
+	return sg_page(sg) + offset;
 }
 
 /* Like i915_gem_object_get_page(), but mark the returned page dirty */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-27-david%40redhat.com.
