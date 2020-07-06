Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRUVRL4AKGQENFY7BTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 04C16215126
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 04:22:00 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id y5sf27268798qto.10
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Jul 2020 19:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594002119; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzcFlmrYcweWrnToQIpnMQJbk1y2V5p0GsdPpRxkzI/2AJCqMVL5fUVlklIoEBXgg+
         NzLCMCek489zRYr8fHoSvUdPxENb1TfxoAsMVRPDMLeQLKTCrqN72iXv2ahMSfJZoeIv
         KG05+zbQPpS/YD2lcRddrNmalewFsWrGXOAQe0YNXvWEcKjSC1KQyNWZ+qRxEodAf2Ox
         0hT70XIwoA8butEJy6sXlImQdFZSfhUfCrFW381ESlQF0P+reCUvnO33qH2Jecg19zMV
         mZb/7PrpVR7zkcroiMLA16h769Px9sHXs/9cSuoXXCn9RH12V1d86SMZxFqP9Qzkru7w
         m5Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=m9jpaNkFnUKJoesaNcFWcHsMUJlnOlCX766o9Hxw7nY=;
        b=TEnSdvxFg8stG9AgyYIS+GgTOZgpVtsCZlQbx6pnMRpz7r5Wt1828fsONoMjOWiImM
         y98awbz6iN/PYD2+moKcXsR233JoOkJwVg2kd1wIDhMly8TTMUnH3tT7eNQOGuU+pnMZ
         ziA/Y5ZCurMo005k5Yg+bVEY2YHDikM4uyJCnVyYVBs5NKr6El7NTOW2upjJb14TEHX1
         ZyvTVnyfFMlKDTPpH+Yv8LSS9d5/tXu9Lc120P0WmL8s8om0JuoZrcppoP/4TbRYF895
         lbAIb8rQIBQuEKzQcG2aVwFqG5hHZ0QIU7dAyQQfHUKMAjnOpJ92YwnEkVobuTcVjLWl
         9AYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jouIo6bW;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m9jpaNkFnUKJoesaNcFWcHsMUJlnOlCX766o9Hxw7nY=;
        b=BqyYteMp2ALN+0Uczsl9ifF3TMsRlzuTeHt4Gdtl5HY8XNXLgT059+GHMs290VDVpu
         YxLjxbdd0wMf/bdWb/lUGGSEc+tFeYAOfuPpn/qck0YL6nuQy/6VTo7J2F5W/AEw2rYw
         GJvnq6UOjz79kiLAWV9T2KU2s3MMCJAMV74u68mYv/o9/+b0lF/fhBUfbz+GkvLXIsvo
         YEa8+bV5q93Ez2cXBdYlzpiGfgLFO+T606PjpoR5pAbnfPK6GRzRujE7iHW6zMNbAN/f
         JwR/xcGP1o0cOMOc/EeULBdcgt+iWvfxqxYUYUbnsWFhSIRrX8OuSfMv2i2krp4GbSea
         Hk6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m9jpaNkFnUKJoesaNcFWcHsMUJlnOlCX766o9Hxw7nY=;
        b=dN1bR0korSK7OVbVqDLGMMIrKNF7iSxMDrDknsBXFbkgPbIu4a8Z1QVF1gn2m2FTRh
         H9hkbUDSQHnZQh0idRSgfTCec6AQfNGB00ZO1rdWW1DldOOAGXQi/fIxFBaJ41dM+j9a
         4/KPnqRDYgxIe+m2G091fkmgF9/MIew4AhSsQvoKju3fU5CteafltLo7ljn4VjOinEIJ
         rd58g4Fa4lPf7PN+leh0yZZFaqm7DRoZ3FNfJnihimPNjjmJ/a+Xk7QoqzvLp/yVYNQc
         KK72oN6UvqmhpLHo/l60jv2Y8ZP5dcT0l/9cqYd5j1EZMPBoZNjJX39nw5FpA3xNDupG
         zo4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bLuKy+mdDp8C8qmfi5Nu57KYJDrbDotgsDhoW7xqgoE+gW2EI
	JzP34R6aS+q7JXiSoUxDO9w=
X-Google-Smtp-Source: ABdhPJxKvAA8dhNWqq1zMDyEuP6bvzSLqyNZaupv07LVw4Tnm+h9jGJTqsd537QslmcxGVifkQo1Xw==
X-Received: by 2002:a05:620a:994:: with SMTP id x20mr43603729qkx.367.1594002118868;
        Sun, 05 Jul 2020 19:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e56:: with SMTP id e22ls6132977qtw.3.gmail; Sun, 05 Jul
 2020 19:21:58 -0700 (PDT)
X-Received: by 2002:ac8:4e81:: with SMTP id 1mr49645009qtp.364.1594002118512;
        Sun, 05 Jul 2020 19:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594002118; cv=none;
        d=google.com; s=arc-20160816;
        b=z4IFMjrBExKVNElqH09zKEM562RwjycGWA707MyKdsfZZmM8bmC3gwAXOnvCYlkE82
         IfAwu/IqbyU4IzOs5gffWfekNa4G4qow5EBW/PzyM9LfzqU0z+O8xEHOT20VcWozqUA0
         drwFxYDqhPcftYbOep7mx7wBlS9k6Fk9CFJdU4iqeaw53eZmZEtlqQ18paILR//s32pd
         AynVKovrsWBmycC1SuEor/6VKTfHELREcX+fPewoCIEnsc4YKSAshuI0sw+8dVtUQfeP
         0B7XH9gLAtQPdcVuWNnRg/YGsTW5jNl5vSYQfAqVBh6rOSKhnCELek7ACwbaz5bN9HTG
         vvWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SiWDphWYGnavflkljTLom2j3mHnFMDqK/JoyQBPF1o4=;
        b=W5EeRaT0uwl01oA/pmhnjvy0yn19URsbdHkhQLlIByfvd97nE+3hFXAPkjkr9sKFt/
         +FWEvuZckftL+5Uji2AxkQedgrtRWLPm3DWspvG3/bXYkAkTRoPEBM7i+E2fckCi8bjY
         Cc7VONF9mY96OckAwQhW9HpfhWPI+2gZ2hX2Vs9mrkGKuYn6ecgheTLPuWfHeymP+W++
         XHbpoRCpDCRgvAYbXq8YOpRqInhKbh39fdnPmCJ+pvHj7EbOkB2x2iiNoSkENoIGcmkz
         0EU78fz2MVszKba32I7vOKOqnau20vZr2Jg9u7XAYy7m21jtIPK10wzndd6HtPpSNP8J
         shSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=jouIo6bW;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id d27si780329qtw.1.2020.07.05.19.21.57
        for <kasan-dev@googlegroups.com>;
        Sun, 05 Jul 2020 19:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 728303f5350049de813bb76e59e979b3-20200706
X-UUID: 728303f5350049de813bb76e59e979b3-20200706
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2007695977; Mon, 06 Jul 2020 10:21:53 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 6 Jul 2020 10:21:50 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 6 Jul 2020 10:21:52 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton
	<akpm@linux-foundation.org>
Subject: [PATCH v2] kasan: fix KASAN unit tests for tag-based KASAN
Date: Mon, 6 Jul 2020 10:21:50 +0800
Message-ID: <20200706022150.20848-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=jouIo6bW;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---

changes since v1:
- Reduce amount of non-compiled code.
- KUnit-KASAN Integration patchset are not merged yet. My patch should
  have conflict with it, if needed, we can continue to wait it.

---

 lib/test_kasan.c | 81 ++++++++++++++++++++++++++++++++++++++----------
 1 file changed, 64 insertions(+), 17 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..660664439d52 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -40,7 +40,11 @@ static noinline void __init kmalloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 'x';
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		ptr[size] = 'x';
+	else
+		ptr[size + 5] = 'x';
+
 	kfree(ptr);
 }
 
@@ -92,7 +96,11 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 0;
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		ptr[size] = 0;
+	else
+		ptr[size + 6] = 0;
+
 	kfree(ptr);
 }
 
@@ -162,7 +170,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
 		return;
 	}
 
-	ptr2[size2] = 'x';
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		ptr2[size2] = 'x';
+	else
+		ptr2[size2 + 13] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -180,7 +192,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
 		kfree(ptr1);
 		return;
 	}
-	ptr2[size2] = 'x';
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		ptr2[size2] = 'x';
+	else
+		ptr2[size2 + 2] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -216,7 +233,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
 		return;
 	}
 
-	memset(ptr+7, 0, 2);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		memset(ptr+7, 0, 2);
+	else
+		memset(ptr+15, 0, 2);
+
 	kfree(ptr);
 }
 
@@ -232,7 +253,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
 		return;
 	}
 
-	memset(ptr+5, 0, 4);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		memset(ptr+5, 0, 4);
+	else
+		memset(ptr+15, 0, 4);
+
 	kfree(ptr);
 }
 
@@ -249,7 +274,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 8);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		memset(ptr+1, 0, 8);
+	else
+		memset(ptr+15, 0, 8);
+
 	kfree(ptr);
 }
 
@@ -265,7 +294,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 16);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		memset(ptr+1, 0, 16);
+	else
+		memset(ptr+15, 0, 16);
+
 	kfree(ptr);
 }
 
@@ -281,7 +314,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
 		return;
 	}
 
-	memset(ptr, 0, size+5);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		memset(ptr, 0, size+5);
+	else
+		memset(ptr, 0, size+7);
+
 	kfree(ptr);
 }
 
@@ -415,7 +452,11 @@ static noinline void __init kmem_cache_oob(void)
 		return;
 	}
 
-	*p = p[size];
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		*p = p[size];
+	else
+		*p = p[size + 8];
+
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
@@ -497,6 +538,7 @@ static noinline void __init copy_user_test(void)
 	char __user *usermem;
 	size_t size = 10;
 	int unused;
+	size_t oob_size;
 
 	kmem = kmalloc(size, GFP_KERNEL);
 	if (!kmem)
@@ -511,26 +553,31 @@ static noinline void __init copy_user_test(void)
 		return;
 	}
 
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		oob_size = 1;
+	else
+		oob_size = 7;
+
 	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1);
+	unused = copy_from_user(kmem, usermem, size + oob_size);
 
 	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1);
+	unused = copy_to_user(usermem, kmem, size + oob_size);
 
 	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1);
+	unused = __copy_from_user(kmem, usermem, size + oob_size);
 
 	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1);
+	unused = __copy_to_user(usermem, kmem, size + oob_size);
 
 	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
+	unused = __copy_from_user_inatomic(kmem, usermem, size + oob_size);
 
 	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
+	unused = __copy_to_user_inatomic(usermem, kmem, size + oob_size);
 
 	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1);
+	unused = strncpy_from_user(kmem, usermem, size + oob_size);
 
 	vm_munmap((unsigned long)usermem, PAGE_SIZE);
 	kfree(kmem);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706022150.20848-1-walter-zh.wu%40mediatek.com.
