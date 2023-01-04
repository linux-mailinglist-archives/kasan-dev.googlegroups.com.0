Return-Path: <kasan-dev+bncBDN7L7O25EIBB4NP2SOQMGQEIP55OPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BCD765CCC7
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 07:08:51 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id l15-20020a056512110f00b004b6fe4513b7sf11686148lfg.23
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 22:08:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672812530; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fy4jPHvj1CV+HYR17RZR7qhNUYWCy7SpqC6JJwCpBmzBniOa7f5uqRH4sVcez31ExL
         mvs3RvIlCVunQ1RvPQD/Xulf8+5jyzxSKkdatPyABNTQU/GPIKSMyttwW5g4dcZRlg0w
         Tg3kzVmDp4eas1H3kK2PwGBvv3GAFlcJw1UCJ1Hz3I/Rz40IGDOHlj9p9QuhKuzRX38r
         lVJU1JH2Ata8S6kIYceIrocaXy8wDn6gBdZ1sy50zaiKeYMnsSu/Gnox60347TU1hp3x
         FTKCxJjVd5nrfdgExafAuG3W9en3M1+P157ZiQggCo2a09Ybwb0N8T+omIJul8yQSJf9
         nXXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=j/9xIDssrmms0rLEEg4e6XC7FPi9Jp/CZhxhiqxFAjE=;
        b=RM28hfn+eOP/S9rGzm7AY9hWW0Jwz+1MfhzPyqZaeZGrakwRU2Au+qiymmtN+ooziN
         g7xQymTzQCcdBnt3jzFNg+FPsg24alf7XUJ+EFZGwa1pN3EC+QfxMuzml/B0nWzCJdCi
         /OsdLdCRv1LA3ah53LagH04Pga/5fE0LKZ6CsY+x8juXLX5R8usr6aHCdVBRWcgWZqV7
         nYAA2hcSyyC8LVQUaCbjwUBxKuZl4mTbUejcEM3jgOCDs+S7IHiwdACxpBJKg10gmIBc
         9ApbqK8PAqmmXfB5iZ1gqzOWE7XFqJFeYi8WJQL9YkzOxAY0D5P/zFWGXjxCUlyKBeOq
         InFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DXrhVRY8;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j/9xIDssrmms0rLEEg4e6XC7FPi9Jp/CZhxhiqxFAjE=;
        b=ZYfUKAeCh++o5/1b0J4XOUVy/+YmUoIcHmMYR+Ki11jEcmikj/pm28uSRquP+zdpEz
         +Vp/7fqVOmHuQftXIdFvgj1njW2MdKk37leGcFkP00UY6M7NKGYwHbDn+2PlX8sg7UsZ
         2I56HBqbnKJg/DA7wdLx5IwB/MEvIMetajWBc49sa1YJ9muiBReavyDlyAvwcKrd7Oz9
         +/dtncamk0Gj7qfHxzkfax3LgbXcra2iySfKD5/UP4FDeZZ1Gyj9cHQTXj2tnny4IWlS
         XjY382X7mT9mPeR2e2tPgStPPIfR6sMps3aSGJZHGH4GFbq2k0bNk9tlAqr3mV7prwBv
         qrng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=j/9xIDssrmms0rLEEg4e6XC7FPi9Jp/CZhxhiqxFAjE=;
        b=oktqbviyQDMbAdrOWa4t/28liel3WoFDKblNwTDZlavR9XLeE33b+8VuNHHnHJNaLW
         VjRezYk5G6J4v5+9aAOxyzP/sT927Z+ZFDys4h0DewQyPKTcozUSYFWtzktPHKlwbKqi
         vVcZPcH5jE5j88WKOIcgJLET6HoEdiES5MtKBH2TzWDPBpudx/lFI9LMYyHhvfuxQ1jW
         +krxJJePXJKx/pYTV6wJVMU72971PTW+7hXJGc2ED2RsWxMxGAAypad7z4IGraEIqW9q
         08yicx0qJvd34qGAWK6Ak+n56FQx2q4Dcqu1Nz6er1x4CtMbgUQheKex5wj+5rf1ngn4
         OS7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krlDU78i2YstEdypnoEWABJk1mWOnzOBtnt9Qb7mFEi+itApO6W
	cYfAjAdcmrRIJjYjR4y09NI=
X-Google-Smtp-Source: AMrXdXvvTMsUkpG6ZhJLAc66Y51U9I1P1/rtOZFEQHc/xHvVlJyUS5Tz9NRDv9qIXTukWS2He4+5IA==
X-Received: by 2002:a2e:82c8:0:b0:27b:5631:8a4 with SMTP id n8-20020a2e82c8000000b0027b563108a4mr3896806ljh.326.1672812530131;
        Tue, 03 Jan 2023 22:08:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e8a:0:b0:4c8:8384:83f3 with SMTP id o10-20020ac24e8a000000b004c8838483f3ls2601265lfr.3.-pod-prod-gmail;
 Tue, 03 Jan 2023 22:08:49 -0800 (PST)
X-Received: by 2002:ac2:59c9:0:b0:4a4:68b7:d621 with SMTP id x9-20020ac259c9000000b004a468b7d621mr12535549lfn.8.1672812528973;
        Tue, 03 Jan 2023 22:08:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672812528; cv=none;
        d=google.com; s=arc-20160816;
        b=qOEaB7EF05kvrmQKig/EcLZCciFWXF3p8sEcRP7BSVuGjyEe3EiJMUvNT3bDNVNsPa
         zI0APJRZ79D7eRzBkzDo1ZdjUr/8NdMp79P+LrrC16GkViEVGi2D0xdXppTmZ0cWhzOb
         A6LH54KNeMSIxgvgjMzX8XfrUmmug4D4THv5gHFqZMbi8NAgtVlim3gtvf45XuiIs1oD
         AgFf+deuWyEzz+6wnN0rX67p/CZExmhGwW4DM5nI3ywJQ2hYgMLfUlV+yQd1u1OfG+l5
         LFSeA9wOBESldtXXuyYAaPyZ5ACyVcjchx47dfNelT35wf7caymQmHPosBtWc71rxctw
         3aFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1s5P6iET2OaU2whx6wnFdyFdaEhzKdZCflQd8AxmlTo=;
        b=wt9mBvdhyttzNEOpS3BZ9pMEClBo9HlksLKolurOjG9IealTwekbL5us9BePAtJIJ3
         PC5Ya67QukD9Dkp/q1c0ykMQFRv71ofa+EZlD+s+CSgNdanES6FQ4jtYUw5QRsXzTJfV
         y35FG/pOYzsDEPhRgmrH0rA20SZ14DmnIW335+A7KvknhbP33e4PllQDR9DHDRjvCZm0
         d0MQFqeQ1a+UTFlbPRzkQJ1a0B5VIKQdj9Y+FeVkSJKIYzQw71MNtiB+HKNSbD6dxGqC
         uXhGqeYcbKiQO6bFSTmYv/8bAW1+KuuV7S5lJNIOG8ZyH9hfEOkGRjFM71Ab1PX8nDFu
         W7zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DXrhVRY8;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id o22-20020a05651205d600b004b5767257ecsi1249279lfo.8.2023.01.03.22.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Jan 2023 22:08:48 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10579"; a="323840105"
X-IronPort-AV: E=Sophos;i="5.96,299,1665471600"; 
   d="scan'208";a="323840105"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Jan 2023 22:08:45 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10579"; a="779094063"
X-IronPort-AV: E=Sophos;i="5.96,299,1665471600"; 
   d="scan'208";a="779094063"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by orsmga004.jf.intel.com with ESMTP; 03 Jan 2023 22:08:41 -0800
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [Patch v3 -mm 1/2] mm/slab: add is_kmalloc_cache() helper function
Date: Wed,  4 Jan 2023 14:06:04 +0800
Message-Id: <20230104060605.930910-1-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DXrhVRY8;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as
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

commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
dedicated kmalloc caches).

Add a helper inline function for other components like kasan to
simplify code.

Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
changlog:

  since v2:
  * fix type in subject(Vlastimil Babka)
  * collect Acked-by tag
  
  since v1:
  * don't use macro for the helper (Andrew Morton)
  * place the inline function in mm/slab.h to solve data structure
    definition issue (Vlastimil Babka)

 mm/slab.h | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/slab.h b/mm/slab.h
index 7cc432969945..63fb4c00d529 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -323,6 +323,14 @@ static inline slab_flags_t kmem_cache_flags(unsigned int object_size,
 }
 #endif
 
+static inline bool is_kmalloc_cache(struct kmem_cache *s)
+{
+#ifndef CONFIG_SLOB
+	return (s->flags & SLAB_KMALLOC);
+#else
+	return false;
+#endif
+}
 
 /* Legal flag mask for kmem_cache_create(), for various configurations */
 #define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230104060605.930910-1-feng.tang%40intel.com.
