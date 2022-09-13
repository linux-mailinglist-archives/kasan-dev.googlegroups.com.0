Return-Path: <kasan-dev+bncBDN7L7O25EIBBRGSQCMQMGQEP7AVRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 783425B6832
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 08:55:00 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id f14-20020a1c6a0e000000b003b46dafde71sf2810875wmc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 23:55:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663052100; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZuZR66Ljz0kfuKuQ3eYqAVdltoeR79zzT3FeayOHUJkgSGFcO+O0BH28W0RY9aAH5A
         qtccQmpTK7zMSI3FLrlc5RgM3S9Z9VnAiK8qwfM3w9BYtYzBqNIE2fV9TJ5zYLPcUYWL
         fLXpH8zHBrKK/Z9ancxlBxcV7uOO3RtX36KVLOT5n/9mfVPxW5aC8wXluheXWJEZCHYt
         AS2wyAu0RZ6It6KpHJSrJHOE02R86vtLNWEoF7ckgrTFMMGh0O9sxRw2xlfQsynf9vhl
         ZC+4Gr4/+ZR4iOltlLWmcbYZ2Qv2uM4MqYUp+CVcKTtfJaBzKTL4cj/aW/jOEd9Wz4d/
         8ISA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cxqdzjsCvlznfHXtDmATNXmXkN9U4Fw+GaJ8ndGMNg0=;
        b=qIrPGq7ifKtsS9nRK4+nldHrBMkED/zEWzJph4ADcwuKHGbNccLtNqwUBFudCJHWaD
         0PE05+nh7TMwtxPOWIAJZxmub0TG7zaQHwC11X6xBH5AptUlkE8CITW8hliFfWLZrjrC
         HY0Ee6I3Oh1aNncqFyeWJcggwV8GCXevEysUT1/vB4s8GGFZvLQ4RpkZL+RiCBNOQunm
         XC5jOPUd1IGtI1KDY3S2Y+06F5OSQS86zeCme4ki4NNaI6oD6yYLnZzjI6qss218x8nZ
         3op8TV1EVMJeeb2m9yQha8LlSaL61rNAH09sfDmnL0pykwcARVKO8KI4MDqF3r0j/IOR
         8BvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DPACgOaC;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=cxqdzjsCvlznfHXtDmATNXmXkN9U4Fw+GaJ8ndGMNg0=;
        b=GihjWyoudb1eqoYEEWXVe2d+aGOX8bsWC4yWP0eS21jD7h+TnJJi5nnBHAkOBCKIEA
         TB0B5BNyU28fbB9HH1FXNSfE4i+j7jkCa4QDDXxJPLyhkbkxCmenRNwzhp2WMQ/dFtTc
         BWf/UHT/QxxHmfg7GR/wlvAhxG1u+o08tGAGJRvEiPzF+M3ZUulAO1PLnlUo34Kq/D6t
         dmz7Pa7CiKbOhbnk1kztTX8Ao0c5WhR/r/dWByFOBMmQA6vLW9K+QvYhgk6OKXi0GeZP
         9tCgu7++x5BrweImAybJuIEJy31YzOenBZYeBXW8sguW8Hb0dOKDDumvRKYGWbVLJqH/
         YCPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=cxqdzjsCvlznfHXtDmATNXmXkN9U4Fw+GaJ8ndGMNg0=;
        b=QUlwsNDD9NRbQIGZ+9LBTomAkOd/zaM47Bv3e92KJuDNI1uYvkdgU7j2QcL0d+7SG7
         3/xgyp7hP8zrOtquZ/G/BBSg6OCMeA0l4vaoTX+bqwxec8SHJ//tM29E2+lPc5m+NTkX
         kJckDS/kbdHlIvSiHLLemNyBdt2rl7mIKJvnlVy7NVNDCHcRxwez23JTzHHW15O4Z20p
         VAimwytKD+uzOg0+L77ZKyiLRsDP37FzYJT2eSbj4ORJ1PO6FbiQi0Kz1qM9fpklLwQh
         LNOjBrP8a61wLbZ3qvU9jr5Ci5OBODZLi3jQe67zkxcmC787QxkXTLQtOB8cDRqw2cty
         aVdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3lG48ahJyswyb4ZTWyucCj1hLXejFmsbsD9PRBKflpSFGWl86V
	sga2nkRCyvOL3cmAy0L89nU=
X-Google-Smtp-Source: AA6agR4AafVEKpRjm2nSI9ThZWH7bU5RjuiJxHbzSbjafqg2tekeBBzhpy2HzJ5mX2FqR6Z62MMMyg==
X-Received: by 2002:a05:6000:812:b0:229:4782:d333 with SMTP id bt18-20020a056000081200b002294782d333mr16269488wrb.136.1663052100306;
        Mon, 12 Sep 2022 23:55:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3a5:1ad:8654 with SMTP id q22-20020a7bce96000000b003a501ad8654ls4667636wmj.2.-pod-control-gmail;
 Mon, 12 Sep 2022 23:54:59 -0700 (PDT)
X-Received: by 2002:a05:600c:3781:b0:3a6:804a:afc with SMTP id o1-20020a05600c378100b003a6804a0afcmr1211250wmr.27.1663052099311;
        Mon, 12 Sep 2022 23:54:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663052099; cv=none;
        d=google.com; s=arc-20160816;
        b=p9lEw0qSEbWSY5pEuCIw1kCk8rdw2ijCEz6ARDqjjOx42dXeZSEG0IahP+h6aTusIp
         NThinxwfugdBAw7VZqyrtJTSZ6I17rvUJ9kpTS0eg/bD0sNdjn3L8ecZswY4PdOM63DO
         wV+rYbRUhgnnmGxkX6wPj3/RUhxE4FOglKcs68t9UaejaurXfd8buUSbqdr0m7+TlTBT
         Tc+HZE6Fcu4o5qf6PforNJ//n5FuUJODE+XOKmdFNvevofFTqTByM0I7jPSbC4j1QuhC
         ZxlaHkHSymCU1ozCWYgMTQ/gp8lucXyOKOUe13lyIGU+ExF0eRsf6ma/fejUoe6l56v9
         G6FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w4DAXzPXkCbDYCXb48OkMTjrkf0UJXQmQ3pLbnSy+bk=;
        b=yuA2agbIVPvAtabc57crDW9qOkYbLTq2deX7lmfEip6QxsFB71RSfUx/f7neFSYkX4
         Hit7hSRcKJHocUT6+69Ldk0QTwwazPf0GRdKP1SQdt+31XleQAfWTx3qa/m3TARWy0T+
         UDhz/gp0OAOtVL0ML14NjyczqtnNdwPd2D7xJ2muEuTOMO7wAuj20TsZq/9UQBtVoHU5
         J1oj96TPzOVG4fGZoGXAPk43OJYo0DDn5TSlasVad1Dhzk5jnJEPkq1Sg0mx/QQl0Nmq
         yFZVUm8yvhLHigrVcE6REE312lS5r/0xi1pQUWV+lMTyA6bFw/yst29+FBDK1DW3ux8J
         a1+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DPACgOaC;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si13124wma.1.2022.09.12.23.54.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Sep 2022 23:54:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10468"; a="285079408"
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="285079408"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Sep 2022 23:54:58 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="861440734"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 12 Sep 2022 23:54:54 -0700
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
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>,
	kernel test robot <oliver.sang@intel.com>
Subject: [PATCH v6 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
Date: Tue, 13 Sep 2022 14:54:22 +0800
Message-Id: <20220913065423.520159-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220913065423.520159-1-feng.tang@intel.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DPACgOaC;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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
data in the former part of slab object data area in slab object's
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
index b092277bf48d..49af9513e8ed 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
 struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
+	/* size of free_meta data saved in object's data area */
+	int free_meta_size;
 	bool is_kmalloc;
 };
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8b..0cb867e92524 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
 			*size = ok_size;
 		}
+	} else {
+		cache->kasan_info.free_meta_size = sizeof(struct kasan_free_meta);
 	}
 
 	/* Calculate size with optimal redzone. */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220913065423.520159-4-feng.tang%40intel.com.
