Return-Path: <kasan-dev+bncBC32535MUICBBNXZTXCQMGQEXKMWKBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 308EFB303B0
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:24 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b109bf1f37sf31744961cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806903; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tzbdy8/Iv25UCCQ0z6lD0/6u3evbu7g2cwH37Ha8nKdMXA2jIU/xA5cN2Yy0vRgB45
         o5EsMp6K9wnGeXdTcZp5im23dFFiV5xOzjVligI73786JW9IN8e2ViOHbBjxT9Y8YtZV
         QNSS7B9ccOOh0Q/NkP2Nm8uGBNMokxInyTlYyj8qrlLnLq89FE1WHH5seRBzRSk9kOmC
         ORjeTBNK5lgVc0UKr5nIJeBwNmXY3v82MUxu2BwasQwMpEEMTnCi2mIsHRUUSKGskDhv
         l0vvMYssSZQqplNyQxPp/YGcQp8Txh+APf28Ea47WypY0wiAkaYQ+5Wrcr9mvN8uifjQ
         /4Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=R7FLOWEk0LCsGS27D3Dj8WJD7Zd8DG4fJYobk3SF0so=;
        fh=SzYGr23NBA5jSQNfoLrbuY3rBQ5BIApFiFsgSGTh0EE=;
        b=RERyc/IrLKEJdQ3ujzl76s7CvYGY+TpI9ykz2LThW2suTL4RRbt2RCbMuPDn6j9DV2
         PiUBDcvmJp0Ht47BG3qWwU+aPwhgIakoJcxiXt4/rs+ue0YONj0qQQ5eSCQ17bsZPNMt
         j+qB9Yoa3kvoF0x+eBlzVLQSaTxKjpHqjrDzCdggVDX6W66Q53zv7MDNQEBkXhpYC5GR
         3n0mSmYYkn8Stgh6PAgReC+zOD5b8Yfczm9WbmkAU5MkCmEknAy/X55jiCPEfGk6or0N
         tfmEinDGcqhuOaLkrjxrqaZC+6c7E1hvEeCfxf56oVkkr+5yTyRLpfT2ombmcXAGu+JT
         fnrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=VHXQnlag;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806903; x=1756411703; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=R7FLOWEk0LCsGS27D3Dj8WJD7Zd8DG4fJYobk3SF0so=;
        b=rlBsWhpxnmQXiwCN0cUpC9G4jGb95eOacXVXM0jV4jmwVxycNx73/3ErA+3qym5EGJ
         hAZ+WT1kauRwfvjvdrkJemKXPPQkesOGW07oOcBJnVzV8m/GqAcUiSB5e55iwzldz09F
         ZhBaQEtcgvav+8/EJpY32T9rmIDRoasBw3DUBZOVmSbeLKa+E3sr4nOeQkBodQSq1RAZ
         3Dz5yrMngs6QWa1pLtmkuDOxfmEP6peWJuijpK+dAv6AQZCd2j+d5fUPzCBU/HYSZREW
         KSZ5TBMMv/fzTG3LyjlFaGS+uLn2TFew1G5lKhZweY13wPYFsxpX3VtiQmdp42hFNUSp
         WZpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806903; x=1756411703;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R7FLOWEk0LCsGS27D3Dj8WJD7Zd8DG4fJYobk3SF0so=;
        b=VFxA8Nm7k47Gf318s8/XsqU7aLlNxMYeQ1oBmzbT6EZLzd4dFtQOgeKiLQ+d/yG36b
         tF/lyPqA5VbYvvpSZtNSEMIcdd8smkIF+v0bCUCtty9MaRaiQOch7Mkhf0MAlrs3x8os
         plceMYvadA6SaP9dDrm4v3ZmPUINv9DW32faIJk7JZLSp4kuhFYkFuUEFCRX1M7Gvyzr
         /7A26QO4Ni6mYbFffvWGRgERJuUNaAhgaxhqD811lIuzy64erDfz4BfOAYLWyCUjqdcs
         Fec+oodzZkE4IO1qR2HPO5NoxPJuG9+PD3bRnJHC3zHkkp1vUa/PMHumTTMkRjGFzfMn
         O8+Q==
X-Forwarded-Encrypted: i=2; AJvYcCV7+M+1eqI33wMe8dDMz/wtXra2wrcHeNY0gtsGUgr0JSUauWnWiFIIY3ARucfJGP6osxMj3w==@lfdr.de
X-Gm-Message-State: AOJu0YxbILTKmYeeYAFAB75XrZwXhlofK27yyueaWNjAtAa9cVKzgO84
	TqI3vaczng2SPF3gtjpqteBQ64qGaSY9rrM7Mz0qgPFmivh8brcDhbHv
X-Google-Smtp-Source: AGHT+IHEtcT7+YIlK8tySPRYzu5lAYimtj10wrJMr+2QHBAOOq5KzSwLU+EfTHZrbm+BuqZmdk/smw==
X-Received: by 2002:a05:622a:5ca:b0:4b1:d6f:f97b with SMTP id d75a77b69052e-4b2aab0d437mr8249871cf.61.1755806902821;
        Thu, 21 Aug 2025 13:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuTqmLJ4y6wfEX7EvLtWwLltjUAEpz9DO7BpRQCqHJxg==
Received: by 2002:ac8:5953:0:b0:4b0:8b27:4e49 with SMTP id d75a77b69052e-4b29d8f8f78ls19669171cf.0.-pod-prod-02-us;
 Thu, 21 Aug 2025 13:08:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQiMdjzaTlz8XH6XkHqLdnf8z7367WCCwrDb63q04cOd42Ahq9bX3cvD6nKVFzcVOZb3MlVsRiGNA=@googlegroups.com
X-Received: by 2002:ac8:5e0f:0:b0:4b2:8ac4:f089 with SMTP id d75a77b69052e-4b2aab2aad4mr7777931cf.71.1755806901746;
        Thu, 21 Aug 2025 13:08:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806901; cv=none;
        d=google.com; s=arc-20240605;
        b=hdyng+usL9xIHDYkK9xEojDXBHZB4+v6Fwnj+2u++F0vnnOo0dPmoTdRmVO882+jSv
         9MyxZRCzLgYtI7Awxg6y6q6AkbSOuiIZqYpuxJ/EzN5f33CqzFjmayHM/1Gtzl/ytO4t
         t3P1QdDwvzTLY85bTTM57mjbcnaFZvlLrtenD5+urnIo19y33kD3l+UAcmJCgT6i34jp
         ipR1EZBLn7C9Tl6ZmvuLSmd+Sc4lffrQqyYh2XUiKO/xYNofRMuF53UIxTeU6/o6iJc5
         Dw+VUkmu1gx52g92v4Fx2ychJrj3KBjP9JQ4m5oiFjPaZooxQmS4bBq8J1rV32yAzJFy
         Xt2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5INZuVEW8ZoCVRVHt0CSLhpT4h786L9PUsnD4NVlnkc=;
        fh=tkZACM0u0BhmsdvmDvZql7m5dRcEbJIKkOYDS4qfJrI=;
        b=L7FiuVNHsVfV8yvzr2ublNsZVNwwB7uVvGIl0K5eQQ2lda5Oh49AU6i0+1DK7eUyeu
         RNIhVRroJ7vj/Ee5Y/QNeRYOPxVhcSE6ALtJd8mLBNnzcxdWxXy0awLS6F2+ay3NMYDZ
         sNJsk8CPPtfsoifD1BuAKK3NE2vnjVBnvwD0YNTzJFXjHcfLc+u4f0+ORgHcwzxmAlg7
         IOi9jrtxvmPjQ7P2u5O2HDS2jixBeDZZdvr82fdZrnx8eGjU6e/d1exV6gRZVWpQAXL9
         3tAamkBW1Z5KvH/qNUURs7k/2C8r97dUIb719/nwGPycyjRL56NDVu+CqICEfJR0efdo
         8E9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=VHXQnlag;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1f2beasi75624585a.6.2025.08.21.13.08.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-689-LzOX93alMoCfel2MwQBu9A-1; Thu, 21 Aug 2025 16:08:18 -0400
X-MC-Unique: LzOX93alMoCfel2MwQBu9A-1
X-Mimecast-MFC-AGG-ID: LzOX93alMoCfel2MwQBu9A_1755806898
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a256a20fcso8254385e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVCAiMC8r4XZX3PZI4TQ0G8vbBIIBSa/IBXfbK23XO+BbysePYJTmO+cxduYZLMgI92VDt+pzY7wY=@googlegroups.com
X-Gm-Gg: ASbGncuP+F1k+c8oc0Koo4lv5iFnS4RuLBPOUNzmKJfnnQ6odFpxAAVs6n0Y4HQaDHG
	J9rZVJQJpIDey7qSoulVP75md/i0A/yO69qScRoLKSrz8k9xuYQVieiKDG2/WBbhOd6kVSd1801
	YV8TSBLMzAngwkIEcOWbHsU8TccXkzHTHyAe9dPJn9rlHXunMXJ/i274Ay0CjGJjNYsn1x5mM/T
	ugbMiLoAj2hmuurcn0J8j6P7b82Fx2KfxCjHeNIXQefIMmWl88b+5k9ArhDNeBs/A9SgaKbziC8
	IWM3VUcaML2xmvSbOaeaOEKcoKyyg2dQ99brteVANKoQM2KjWDl1bNiuCx/A1qT/d6Ipofv6MEf
	ivWsyJFpvH+8nNOTjy5vacA==
X-Received: by 2002:a05:600c:470c:b0:456:285b:db29 with SMTP id 5b1f17b1804b1-45b517d416bmr2506285e9.29.1755806897487;
        Thu, 21 Aug 2025 13:08:17 -0700 (PDT)
X-Received: by 2002:a05:600c:470c:b0:456:285b:db29 with SMTP id 5b1f17b1804b1-45b517d416bmr2505625e9.29.1755806896948;
        Thu, 21 Aug 2025 13:08:16 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e3a551sm8831035e9.19.2025.08.21.13.08.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:16 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH RFC 25/35] drm/i915/gem: drop nth_page() usage within SG entry
Date: Thu, 21 Aug 2025 22:06:51 +0200
Message-ID: <20250821200701.1329277-26-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: hWsxzge1-Ts6rw259SckB6bTomHVe34ka5Lg2gA7OKE_1755806898
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=VHXQnlag;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-26-david%40redhat.com.
