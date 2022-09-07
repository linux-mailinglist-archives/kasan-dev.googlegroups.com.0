Return-Path: <kasan-dev+bncBDN7L7O25EIBBBUI4GMAMGQEE6AYHJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E33305AFD21
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:11:02 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id j19-20020a05600c1c1300b003ab73e4c45dsf7464728wms.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662534662; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nxxx46czl4qRfkbISEfrHchy/lhKf8Xef9KO8dPMaYO83vf/IXRmWymsvUgqcv9FFA
         26CgooDeHdCqQMWhiS9n9pwvWshKWnekqlSrXv28FLMXZpTr53aiSFmDw/19sWyqj2aw
         j3pu8q4dhb4Qz+B/bFftqIIzq+e/bDEQiLNDUpDA8bS2+MnvXVNDcGBc0huiAqQ6oq8Y
         5pHmViaJvj6yrIQKzzOxWabVqXXeDSm9+oDYD3x/j6ciESv4loSAF1t0uuWI48xNlq6B
         AoKSDwQ12i6vU4o7Tn7INvDj4l+S9eT1Pbh8NYeUo9RtZf7KHALIZlNPkyNrP0irzceb
         nIXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4PeqvbRiviTFiFU07WWkIEQhRZfvE/umgmDg3vkxx08=;
        b=D63vFVK10zFrJNWLZI+MFRWc0aLxpGUwSD6TB5o2e+mIC1N/E+XV5vcgDZzWu8zJPy
         nYmOHMrD8udxRWFoM75XEFacw3Tr0DKLvM5E5rZi26MywvPTOsUup7XKUsocuLwRxNr9
         b7QU8dvt2GjLvMVfqiuVBFDjeoEvkrD1UE7WQZcuAmaHkzMwi7DtZ9CDvrCKFUvQAh33
         J6k7NGuWKWzvMtDOCJk0QBeWyj5ykgeokZDxcMYzAg5yK19G/W2JVkuFIcjOJOv2AA1e
         L+iuboBQPQVuzEzb2Inf1HaoHxMG9zAXzts3ODPsTcCZ7sI2eCiMMabMsDE8quAzOd/x
         QAoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jVHHsOXb;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=4PeqvbRiviTFiFU07WWkIEQhRZfvE/umgmDg3vkxx08=;
        b=kUmKBiMJbW+WvbALho8NOe3YM33LjVZyG+HZGpO+yQaqjw1MHroXLEOSHC9wRnAUt+
         IQ2c8GYAxWyy7oc7qynf2Ek4i1JocPSMw+4Zq2Y4hwCKp/RKYb0tq6ddMttwyT9QTTqn
         VNbhzIyq2pxL88taqc/5IWJqjQJlDnX7F/PD5PrcdyEmBWVr+FvdoexQShNGAlZWjg6/
         baSAW+YX4+/oqBbxb8odZIHdkGba+iTA1W1hnIYlj75GwMP2DswrRRikAqyEzYApn8a9
         5MFqXNENHVjfamdmmW54gcI8QxjFociS33IHsHI31oMjOMXS1WNK0PdJRxqmw8YiSnwx
         4iqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=4PeqvbRiviTFiFU07WWkIEQhRZfvE/umgmDg3vkxx08=;
        b=JnZ3JbQnObFFHaSg2QRzRqWYMlgMg0k7RjNxN2DsZGumYOJ1wK1ZbeRYkCYPfW1FFs
         Vgrf6yG2hmDEWf4TvzIk/+FGRjkthisf26abLjfntdIuyRKZBK9CMtMhmia/Sz8oMGvm
         zioYaYivf9wjgWSbAJbhjogmLvsGO9oPb8jjGzacDZFs6cKqG+KQ9Aii0Y6tKSnXeqbJ
         tUQqAlKwy7oGdoRUVXCzOEOOEWmTtzRLGMfxSolwGlZvOD4ak1ODAW5jHISLgS/6NZ/C
         1IL+bbUtQjHRlP0L016d83IHVyy0aESSv1MF+c2/5vrqatD70YYFOgtns5+1lXOzUDZV
         m9Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0Rw/NJOipv6cOZJ22wLPGEGxZDnbOrd/Xk/dqs1wKuxZOKCMWh
	YCk52xUIIyFPb8c4tbTxlHI=
X-Google-Smtp-Source: AA6agR60/XYZ87P6+rHBw4d0DWGn+ZJZZSo7hwVlwkmnKsCuvuTKN4W6bGexWIH6fWkcjwxTy8YTrA==
X-Received: by 2002:a5d:5981:0:b0:229:47fe:6f3f with SMTP id n1-20020a5d5981000000b0022947fe6f3fmr446765wri.279.1662534662584;
        Wed, 07 Sep 2022 00:11:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3a5:1ad:8654 with SMTP id q22-20020a7bce96000000b003a501ad8654ls297893wmj.2.-pod-control-gmail;
 Wed, 07 Sep 2022 00:11:01 -0700 (PDT)
X-Received: by 2002:a1c:6a0a:0:b0:3a5:bcad:f2cc with SMTP id f10-20020a1c6a0a000000b003a5bcadf2ccmr15836182wmc.74.1662534661669;
        Wed, 07 Sep 2022 00:11:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662534661; cv=none;
        d=google.com; s=arc-20160816;
        b=IHDsuPOlXoMNXyPPo84OHTiQvEoifB9GHmCzA+EMQ2qd2msftNLXBLSgoEQkPsWcX7
         IvOQtB+jQoXnHuChu+XvMe+xCAbBYYmviFxKsUlh8Tgjcz+icfiP9sWzU0oZQmww2Une
         emYD6SwBMY59+sZ00hwt/JuHbb9ZKlb1HrBL1geDxPFnxP5vkk4BHJcY0X+C8uKMudj0
         QbnldHq1t4gfke9J6N6GERI0xlsfIDfh8pKCwzijXqIq5PcMhW5/CgSaiaPi1VlNLMRc
         CUI4U+/hjgMjR7ySloLRQKLbegnW5zt4sjwYYonhPMI1EVkhTE63t3rL7GMP0gbWdn9+
         qQcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C2AvDIQQEePpY2JC2J8eigLe6k04A+oww6op+x2ryEw=;
        b=L+ZlUMeZqBz1OuvY4bXHYAhLK56n4CzNVh0StGoSP1KkU3mzIl1kee9uYsIKc16a7s
         FSyEWJPsgYFy2auJ+FzuvOyIkoPB7eJQaePHpbnprdx35RtiY9YvHkQfjXCJRmwa+H0I
         k26PK2oiUVnjhpZE/lwMtqmz7g4s++9J7W8Kesmh5UtEAghlUp9HTJGDQYuTPu8/megX
         pjb7+foYLECBb4wnsKTpweBXceuwIDw9bXz1+C24OLXbIL/5hc0eyh1kibHb37C33NwY
         iCuiiymKCrpCNlv8n+O8JFdSVW8GQSFM1tUO+xGaEqWmffgTaoSarYfEednMsYUReWGj
         258g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jVHHsOXb;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id y18-20020a05600c365200b003a5ce2af2c7si724421wmq.1.2022.09.07.00.11.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:11:01 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10462"; a="298115309"
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="298115309"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Sep 2022 00:11:00 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="676053451"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 07 Sep 2022 00:10:57 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>,
	kernel test robot <oliver.sang@intel.com>
Subject: [PATCH v5 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
Date: Wed,  7 Sep 2022 15:10:22 +0800
Message-Id: <20220907071023.3838692-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220907071023.3838692-1-feng.tang@intel.com>
References: <20220907071023.3838692-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jVHHsOXb;       spf=softfail
 (google.com: domain of transitioning feng.tang@intel.com does not designate
 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

When kasan is enabled for slab/slub, it may save kasan' free_meta
data in the former part of slab object data area in slab object
free path, which works fine.

There is ongoing effort to extend slub's debug function which will
redzone the latter part of kmalloc object area, and when both of
the debug are enabled, there is possible conflict, especially when
the kmalloc object has small size, as caught by 0Day bot [1]

For better information for slab/slub, add free_meta's data size
into 'struct kasan_cache', so that its users can take right action
to avoid data conflict.

[1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
Reported-by: kernel test robot <oliver.sang@intel.com>
Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 include/linux/kasan.h | 2 ++
 mm/kasan/common.c     | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..293bdaa0ba09 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
 struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
+	/* size of free_meta data saved in object's data area */
+	int free_meta_size_in_object;
 	bool is_kmalloc;
 };
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8b..762ae7a7793e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
 			*size = ok_size;
 		}
+	} else {
+		cache->kasan_info.free_meta_size_in_object = sizeof(struct kasan_free_meta);
 	}
 
 	/* Calculate size with optimal redzone. */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-4-feng.tang%40intel.com.
