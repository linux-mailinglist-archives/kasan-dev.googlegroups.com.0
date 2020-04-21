Return-Path: <kasan-dev+bncBDGPTM5BQUDRB7M57H2AKGQEAX244NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 596AD1B1B4E
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 03:40:15 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id a6sf5075358pfg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Apr 2020 18:40:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587433214; cv=pass;
        d=google.com; s=arc-20160816;
        b=wQ9DK/iODtNCd+WYpih9JYFok7TbiJUpNtPlqZKIlRyw6Mgz46a6WI3RsQOXq+x9eK
         uCvP5kstWAG9rSj0t52w6hk8Is/h32Zs2/JqrQHHiFEFSCQFUUEzibItvA0BOVfG7N+C
         4Kv/jpfTzdZRYN22h4qDbSjYZRl4eB58Algyw92bv2FQqw7vutemU75QnLmRxPln5Top
         7F5xvu5JmVWzjWFZAyI6mdO95DEZPJwuv9myOSzXjsQV8ioeCFl8mAqRU4ODqQqInadh
         ro9f+oriGz36wIaOWDpgX96RnfrQtXkGo0wPmpYxlP7LJAUo2gE+s54fgKVvLqhEuVkn
         MnKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=37fyBT4wGvkG8EvgXJX2K0cDOU/S8yLOIby31/VgQiA=;
        b=lcIWCJBHvXd5vPlJbi5PVmMhkuE0ki0ETyI7nXPjFwyq678sL86bNKUKqaH4Kn7zdu
         o1h9L/zpBkG2zB7vTYqOZ/joZzJqbrqnphgT/YvBgwN2w59Tr90ngmREWsdS6MAyUvaY
         eP4nmT2pmwRt7+0H/Q5IKX+PULCdYSAirwHGN1RuES0Igb+smrNMpnWin98HiD11O00G
         JNTtwfuwPExuz7OGO4hlXTsnxbEjK+rna7AHb3gPx9V03JqTrDVbeqvGgzaNmdTkj9zx
         EPaW5yIfctqr8GlSH6yJcJ47VVjmOdYFG+c1bNQ5AjUVwprGfBbrL/ah2r43t1p7EkO5
         vwzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=L20rOhkQ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=37fyBT4wGvkG8EvgXJX2K0cDOU/S8yLOIby31/VgQiA=;
        b=DsPrUVLrZs8hyei+TVXR6GfEdaWZ7oDaVid31HEA3oQg4h8WvbmlQig8D/HDbKsAXk
         KumS3i5nyGGpascEzHHb+STlT2ibTyeGwfznnb3fxFVrxvZgHavoljx7ZVcue+xKJy71
         x05jAI0ZJaENSVxypnOKpnAGobmsgt2GfhTR+qqzwy08VVZGv3ZQ6wsroHlNzgg1MyHX
         inif5Nn2xBMjz/8uaGkppzPgSFPQ1ft1jBOKrJfZ9ojdgchHerRbY0oriD5MQKZz6PDk
         ORLTIEBZirNS0f3lQA65yQl2SBYIyHmjvoqBhE1wRo0P0H3gqzuIRqnM7lopbqpRmiJN
         cFgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=37fyBT4wGvkG8EvgXJX2K0cDOU/S8yLOIby31/VgQiA=;
        b=j77TV5XlIkIu1x+sQyWXcOq69ltNVJLg04tPrP63QUKeVqoY2lvkvtLhre34R2/PN9
         cGszaXP67gb6k/QGIx4YNWP75Q7XO2FaxBK3V4pDrqhsQ2I0+nL4VtIrI6H7H2B+JLQe
         3mHb3PwSRM4SWl/Jjbnu0EpCkuIuYQyOXIVlYv+omYziRsdVY65S1EdmcA4834W4f4Bs
         ANfBaNz0KKOUOm+/uCChW4zR758Qd6oVcjXWCt2FkKZEmJiqIWu5Mx8czeYw0DlKy/uf
         C7R0e37mEO+M352EjgX0bM0Go7fePk8D6GpemR1fhWOKaS015gQu5i1o/+bl+ZiR6LMS
         PCIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZUmQy3vitgi9PtqF7NMeMkbFBx3sZQMmGE8C67gsFeavCvyZPD
	E+dHgnYVsRA+tTKZxFb8xQo=
X-Google-Smtp-Source: APiQypIf0ylIHRTXx9IEV+zIzOD/dVBzMDm2PyC4w9VQ9omn6sKNiY82kCpnXWisp2nb7zTPgGCRWQ==
X-Received: by 2002:a17:902:bb8d:: with SMTP id m13mr18230004pls.250.1587433214047;
        Mon, 20 Apr 2020 18:40:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:a50f:: with SMTP id n15ls11897801pgf.5.gmail; Mon, 20
 Apr 2020 18:40:13 -0700 (PDT)
X-Received: by 2002:aa7:85d3:: with SMTP id z19mr8197809pfn.215.1587433213625;
        Mon, 20 Apr 2020 18:40:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587433213; cv=none;
        d=google.com; s=arc-20160816;
        b=uSnNemjIaanGVaAt9li7c9IwfmZchWV+B4lZOcoYo8Xk9itb4vQNRcziremFNIl8Ej
         K7WaiihaKRzHFwAM8MMzOhn5dajDMZ1V/4gyS1G4MJ9pKnuGBM7JoRrI0XUegez2PPsI
         LP+P5BOLsYekw5DzKn7kEc1dJS8Z+ZopPtmRrcyhnv0yqM2G40vYd4zKEGxpAUw5O8lH
         T23/wioY9Vhixp2bperWAC2fLf6zGHyF1mx1zS5r8s0FMt11cHfnpjjfZbe/PnT7f6nd
         waLxw6+kWg8/a9gLlP6+cQ95rWRrZvKqYu+Z3D+Aas9UflDLKL71sq/J9lObzY9nabZT
         IiXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kvJkIFmK0+Fajj8XRCQra0WIBlEJ5d/F7a174u9kVSw=;
        b=yoXzXvk2Lzb8aW9J/ZgtEiPR2UnFC1awY1D4MgT4/Je22U78BB9UD6b6D725JoMSq4
         lVyUADVsDL6ha6fC0JOW7mTQoavORZ/XDcDHv3hw9aNTPWctdyAGJ+SMK0zaXvEBnXgb
         TnmbWAZBL68OJdKXYpKO+8odR3EOgL1f/OrUCfO+YrOGvA4p+vueZLvLXXuLC81i40r4
         qDnGQryAJx51/pvJArcwq5MI0HLDOjNVqKFf8yQ0VJh8Rh42m1xunMb47bGOLZlAwhY0
         1JMNppD4l52+7dpB5+7rGz+aTOIThooZcgfYDNzWn1JrBMfOCruW1TsVXCYh2xCMY970
         oheQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=L20rOhkQ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id 138si43832pfa.6.2020.04.20.18.40.13
        for <kasan-dev@googlegroups.com>;
        Mon, 20 Apr 2020 18:40:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: f69d6d55cb2f45d897c05192bdd4f3dc-20200421
X-UUID: f69d6d55cb2f45d897c05192bdd4f3dc-20200421
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2126729325; Tue, 21 Apr 2020 09:40:10 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 21 Apr 2020 09:40:08 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 21 Apr 2020 09:40:08 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, Andrew
 Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH] kasan: fix KASAN unit tests for tag-based KASAN
Date: Tue, 21 Apr 2020 09:40:07 +0800
Message-ID: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 2CEDE98B7C8540AA4DB9C008FB938823D9E9F478584B868D577067E8D6D705122000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=L20rOhkQ;       spf=pass
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

When we use tag-based KASAN, then KASAN unit tests don't detect
out-of-bounds memory access. Because with tag-based KASAN the state
of each 16 aligned bytes of memory is encoded in one shadow byte
and the shadow value is tag of pointer, so we need to read next
shadow byte, the shadow value is not equal to tag of pointer,
then tag-based KASAN will detect out-of-bounds memory access.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/test_kasan.c | 62 ++++++++++++++++++++++++++++++++++++++++++------
 1 file changed, 55 insertions(+), 7 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..a164f6b47fe5 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -40,7 +40,12 @@ static noinline void __init kmalloc_oob_right(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	ptr[size] = 'x';
+#else
+	ptr[size + 5] = 'x';
+#endif
+
 	kfree(ptr);
 }
 
@@ -92,7 +97,12 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	ptr[size] = 0;
+#else
+	ptr[size + 6] = 0;
+#endif
+
 	kfree(ptr);
 }
 
@@ -162,7 +172,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	ptr2[size2] = 'x';
+#else
+	ptr2[size2 + 13] = 'x';
+#endif
 	kfree(ptr2);
 }
 
@@ -180,7 +194,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
 		kfree(ptr1);
 		return;
 	}
+
+#ifdef CONFIG_KASAN_GENERIC
 	ptr2[size2] = 'x';
+#else
+	ptr2[size2 + 2] = 'x';
+#endif
 	kfree(ptr2);
 }
 
@@ -216,7 +235,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	memset(ptr+7, 0, 2);
+#else
+	memset(ptr+15, 0, 2);
+#endif
 	kfree(ptr);
 }
 
@@ -232,7 +255,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	memset(ptr+5, 0, 4);
+#else
+	memset(ptr+15, 0, 4);
+#endif
 	kfree(ptr);
 }
 
@@ -249,7 +276,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	memset(ptr+1, 0, 8);
+#else
+	memset(ptr+15, 0, 8);
+#endif
 	kfree(ptr);
 }
 
@@ -265,7 +296,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	memset(ptr+1, 0, 16);
+#else
+	memset(ptr+15, 0, 16);
+#endif
 	kfree(ptr);
 }
 
@@ -281,7 +316,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	memset(ptr, 0, size+5);
+#else
+	memset(ptr, 0, size+7);
+#endif
 	kfree(ptr);
 }
 
@@ -415,7 +454,11 @@ static noinline void __init kmem_cache_oob(void)
 		return;
 	}
 
+#ifdef CONFIG_KASAN_GENERIC
 	*p = p[size];
+#else
+	*p = p[size + 8];
+#endif
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
@@ -497,6 +540,11 @@ static noinline void __init copy_user_test(void)
 	char __user *usermem;
 	size_t size = 10;
 	int unused;
+#ifdef CONFIG_KASAN_GENERIC
+	size_t oob_size = 1;
+#else
+	size_t oob_size = 7;
+#endif
 
 	kmem = kmalloc(size, GFP_KERNEL);
 	if (!kmem)
@@ -512,25 +560,25 @@ static noinline void __init copy_user_test(void)
 	}
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200421014007.6012-1-walter-zh.wu%40mediatek.com.
