Return-Path: <kasan-dev+bncBDGPTM5BQUDRBTMSS74AKGQEEQULT3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54B7B2188EA
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jul 2020 15:25:34 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id h19sf15979962uac.14
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jul 2020 06:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594214733; cv=pass;
        d=google.com; s=arc-20160816;
        b=xn3I358Gs+UTAjczLOojbXdOD+8nz78CP774r2dpNJGXSKzcd1MFNGFNA+SRqmUYMc
         PQ9Icb77Xr+0Z/if4MFfvXcfS0/avN5YhMGcaEBS+twFxxRl1LyLBxHiNvpUDSEt8q6x
         cRzy20dmfeKLaIRxjNSod6mAES2AS+2ztR96fbrAOJXgJ6XWAI6pfgUCdEYsw+tEPCl8
         PpAsR79EsaR+YJ5R4OWM/CMlN+vErG+tUPIbxrctqQ87rTvMJsBMgy6LKT0wVeEj1FL/
         w3eKk0cbLM4Dcv5k9ox4aDex5vAoNUOSgtiB0gIp3N1e418XojvUhwPIpV0pUK1h1844
         bBOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=smxRb/aBhQr8ekd3n8sLCnXl/m9rtu8RgB+rTJB9poY=;
        b=mJ7nW7zWUdSbD/E8SMYVmrhO9sPSnyF6Ahe8P/vLcv/U+kiJB51RO9Db7/6wQV+lbJ
         IWJlQ1yH62fM7IVbp7LB5ie4UXjoLvvTDeHXaH/JJ6lxphlQkKX/4RPJPzPlBq1GpW1K
         YgWajRf/zCNdeRIecMB76eH6ZQ6QHU//dAkqoewzyNXkvMOo2YbpuDdmWb613zHmb0/c
         Qycng0QC3Fy53JdduTj2JgouZ4F112AXo/M1favFzTJ9+CJMlMMWRyxGkrOOV2UQO5gy
         48yhedHOfNstQyr4mPzutmTu89J8UJYEgkXIi9rQkQfvUE5L0mHc7L0gT9TuQtWRt6/E
         hu7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cGKo3kW3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=smxRb/aBhQr8ekd3n8sLCnXl/m9rtu8RgB+rTJB9poY=;
        b=hS3ZNFYCQQtjWU8vzNsZdUPMniklxH5NyB3RHkezPGblKVVmlsHjICqeahOPvYuKmi
         GMkeErKODU2DTOBL4yGU4Ewk9Ig8aP0XphyL0WTMiiTvYFy09hR5xZZoHaOxGA/rdV/z
         tnEMXCm+KJfb9LXO239HkxJ3eYEvigzXVB/HllP79Fyf6Afqki2erCn3qofYIw2CI4JR
         4IbVSB5s+aVHKnBkQnPmJ74iJaeKLw2Fq9VHG7ocYizB6d4pAaO9v5cQ1KetnNXnAKYF
         i0JI4AIuHDYZkPq0Z7t+Xn8n8Lp7SjInjDHjtjWsws2/DGMZvyGs+HWxzRwAYyCtnNTl
         Aieg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=smxRb/aBhQr8ekd3n8sLCnXl/m9rtu8RgB+rTJB9poY=;
        b=cKW0t8pNAxYLLDjWwFXquaU075n5nZ9oMrFmZ7P/ZKjVCbfcGo39cxcLSXEoKkvK+3
         RVaf+THYh/seXWfxNvEvypQu2OYrXl5B/W+02X1mjIS9d6+0hBQaTlKtcap0vcDJrynZ
         VNvT5uCHQ3iyQVPPBB5/kQQZXH/igu+foIRYAC6ECUb595lq0pIA/qc+/HO/ZhoNlsFG
         ro3pWdQu59qiYTdzrM/5kvKLYl501MobflpQf9WUT8cp1BSiPLFbDbYwAOOabwRMYcA1
         0RqEsHVTe73s4SU+cJUYwMHCwA1J8rhbZGvCTjrdlp2HdbXSizDIQtWLRYTAZxoiE/ZA
         M9eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BMzoa+JfU01jqQocRHE6OKmG92RnYOg9f+gWDMxCiBt/upANJ
	47b96Umo1h+qUzR21Et6bRY=
X-Google-Smtp-Source: ABdhPJy9SM6K6TkfQGKWk6cxzllc3rTVeJEKqqVjkU+dCk+hHKXWX+Hn6/ezbprTrfxXuC15TNgKvg==
X-Received: by 2002:a1f:a616:: with SMTP id p22mr26202836vke.96.1594214733088;
        Wed, 08 Jul 2020 06:25:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a04a:: with SMTP id j71ls116725vke.3.gmail; Wed, 08 Jul
 2020 06:25:32 -0700 (PDT)
X-Received: by 2002:a1f:9545:: with SMTP id x66mr11494028vkd.90.1594214732659;
        Wed, 08 Jul 2020 06:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594214732; cv=none;
        d=google.com; s=arc-20160816;
        b=JyCTyjKHNcB/7U+LWlHFTtiI5us0FmTyLsj/+8ngbVWONjU5INdkFr0tbeBBCdDKmY
         GwqLQm2ipTZ8zAMxMlhIXwZZA+OMwSeHR1fu1LD4DM0QmbDzqOFfEJ5geQFnuWbzLSU9
         06s6m9IrvyWl3PdHvVzOf2VwCmHrwCHAbBoKw6sxJN34IwF7eUwY0aWP/aPGwWTLIWTb
         cVebpjhJmX/xgubOqINmpbvbBRv7M8zGBr4XBku9IKzTfGr/xxJXihFAw4tFfBzeiSXP
         Blq0P51d1rBrz9LTO2fp13QD+vLRS9ftfqPXgxR/CVjVvozdlmFeuHPwsgMl2Gnet7MO
         C6gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8MKbH1IX9Wezlb1mLgBVH7giMxWeaQpi+Vzc+0gSWkA=;
        b=qCSMMPJ46MVTBWQSZzxsZhJZ89asA3SajO7C6+QrEivM6CACdIgOr0+wmbKFBkQtNl
         CvVb47SbkZnoVCBvey6NFKWULzBrPK1jPLQCtnstWGLwFR4D9CP7FoW38cnI3RTgCUer
         vZm8dtQR3osnlqmc6FBK5hN4KhwJBnSsTBtAN7JC0HXvg7CMSdRRO7yB52QVpAWG194y
         f4ytPPtzTqJv/i6EeZTGx3LwU22Bc1bOBse1iwYDRytFBpgGU7kveyGG0r0KjiiNOOUQ
         lCROCgXVMCW+Xl7evEDeCAqRnPwMFsZWfk3ojbCtZPI7klUVWwLeao6wr/ad2GXkgUzH
         d96g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cGKo3kW3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y7si1231872vko.5.2020.07.08.06.25.31
        for <kasan-dev@googlegroups.com>;
        Wed, 08 Jul 2020 06:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 88346041bab743b293e7a3a8d908c68d-20200708
X-UUID: 88346041bab743b293e7a3a8d908c68d-20200708
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 280638738; Wed, 08 Jul 2020 21:25:27 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 8 Jul 2020 21:25:19 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 8 Jul 2020 21:25:22 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, Andrew
 Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4] kasan: fix KASAN unit tests for tag-based KASAN
Date: Wed, 8 Jul 2020 21:25:24 +0800
Message-ID: <20200708132524.11688-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 4FE038726111CFDF32B6454EE1B6840009C597B427D47AC810D59EFB2B7294702000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cGKo3kW3;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

We use tag-based KASAN, then KASAN unit tests don't detect out-of-bounds
memory access. They need to be fixed.

With tag-based KASAN, the state of each 16 aligned bytes of memory is
encoded in one shadow byte and the shadow value is tag of pointer, so
we need to read next shadow byte, the shadow value is not equal to tag
value of pointer, so that tag-based KASAN will detect out-of-bounds
memory access.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---

changes since v1:
- Reduce amount of non-compiled code.
- KUnit-KASAN Integration patchset is not merged yet. My patch should
  have conflict with it, if needed, we can continue to wait it.

changes since v2:
- Add one marco to make unit tests more readability.

changes since v3:
- use KASAN_SHADOW_SCALE_SIZE instead of 13.

---
 lib/test_kasan.c | 49 +++++++++++++++++++++++++++++++-----------------
 1 file changed, 32 insertions(+), 17 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 61a3cc11556f..003ea5b49f4c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,10 @@
 
 #include <asm/page.h>
 
+#include "../mm/kasan/kasan.h"
+
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -40,7 +44,8 @@ static noinline void __init kmalloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 'x';
+	ptr[size + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr);
 }
 
@@ -92,7 +97,8 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 0;
+	ptr[size + OOB_TAG_OFF] = 0;
+
 	kfree(ptr);
 }
 
@@ -162,7 +168,8 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
 		return;
 	}
 
-	ptr2[size2] = 'x';
+	ptr2[size2 + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -180,7 +187,9 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
 		kfree(ptr1);
 		return;
 	}
-	ptr2[size2] = 'x';
+
+	ptr2[size2 + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -216,7 +225,8 @@ static noinline void __init kmalloc_oob_memset_2(void)
 		return;
 	}
 
-	memset(ptr+7, 0, 2);
+	memset(ptr + 7 + OOB_TAG_OFF, 0, 2);
+
 	kfree(ptr);
 }
 
@@ -232,7 +242,8 @@ static noinline void __init kmalloc_oob_memset_4(void)
 		return;
 	}
 
-	memset(ptr+5, 0, 4);
+	memset(ptr + 5 + OOB_TAG_OFF, 0, 4);
+
 	kfree(ptr);
 }
 
@@ -249,7 +260,8 @@ static noinline void __init kmalloc_oob_memset_8(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 8);
+	memset(ptr + 1 + OOB_TAG_OFF, 0, 8);
+
 	kfree(ptr);
 }
 
@@ -265,7 +277,8 @@ static noinline void __init kmalloc_oob_memset_16(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 16);
+	memset(ptr + 1 + OOB_TAG_OFF, 0, 16);
+
 	kfree(ptr);
 }
 
@@ -281,7 +294,8 @@ static noinline void __init kmalloc_oob_in_memset(void)
 		return;
 	}
 
-	memset(ptr, 0, size+5);
+	memset(ptr, 0, size + 5 + OOB_TAG_OFF);
+
 	kfree(ptr);
 }
 
@@ -415,7 +429,8 @@ static noinline void __init kmem_cache_oob(void)
 		return;
 	}
 
-	*p = p[size];
+	*p = p[size + OOB_TAG_OFF];
+
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
@@ -512,25 +527,25 @@ static noinline void __init copy_user_test(void)
 	}
 
 	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1);
+	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1);
+	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1);
+	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1);
+	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
 
 	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1);
+	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
 
 	vm_munmap((unsigned long)usermem, PAGE_SIZE);
 	kfree(kmem);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200708132524.11688-1-walter-zh.wu%40mediatek.com.
