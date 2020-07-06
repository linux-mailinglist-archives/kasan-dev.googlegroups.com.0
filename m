Return-Path: <kasan-dev+bncBDGPTM5BQUDRBGNART4AKGQEDINDVXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 48B912156B2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 13:50:50 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id y12sf13131218uao.13
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 04:50:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594036249; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0VhnrsxLaIxqLhUrSoUNqs96mVvNcdjJUOGEl+UTB67JlUmZ/4a+wSNg3MbmmNXuF
         6g1GQwZG9K+Qr4z5lwQn5HSq6WwrUpQDM4npfeldGcC9f/9AvLzhMakWcRSKG6yJs0HH
         +i8WxeWSQ0MgXMwPjdsnfo4harP75WRrt9gigv3ZinG5KRBkxKC0t0DY+NoPZwy4NjMk
         lqpAWHSpapMnaajp7nz+8Hf/PqmzSjiae6xIv6yDBjy4ej0xtboJ5bm/PkiNl4JWNTYT
         Brm6x+kv6qasVuoL6BUkpMjo+oEWW0CgJ90cE1p/HH7CNRSDb0n2pweD7JhHpowE6nS8
         Oy3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PnejpATI8jeHbKw4ZzS96QGP7ljIXUKvUSzUvhL9Hs0=;
        b=eNMrOwIWHV366krwBsvYq2dgfbp0bnFoQpb7dPdLh9c7VxTspenDf/fZZF7pb0g4Ww
         rVOn0gABL360TY5IXrI5/5InyDTAHXuoXkma/UQFxd2aklalclVHSad2LoUZUUAtz2e4
         9mLdU+hlnRP/rIYVEnwgtD1FGBxL1j2X5gfFg2sT9ZnjGftCynOGzzNSLOuOlamw04Go
         Dhj+Gn4Tq0CVU/ri8FqDEe+cAJjbHjVnZd6SoaAkIU+0oo77+qa3XDx72tPSJDdyOAQ5
         wkh76qg1wdLqlK5m+02iyX1RNwVpRvE/oJDyD4QNvEZzWWinrp3YPYOE5R9PG+blJNfL
         J38A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="Eil/MUly";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PnejpATI8jeHbKw4ZzS96QGP7ljIXUKvUSzUvhL9Hs0=;
        b=nYJ7f2+BmTCtNWfVb50rptel3CiM2CTqksnLSpLnaSw/wGjV4qhUkSqfF42ZVq5DTX
         w9cRuMEUKMWi6mZTBh6mdmI27/Cvd21mXQsCyjfNcefmXKeZK0F9u+R7USa6tuzaajNn
         LaBqPxo4booJPY9reZ7L1tijHwxJmjzTC/+V75m/H82YaMpdHZSe1Cj02q2/M8bJpP8e
         tbgVw6p5loga788o4BLH65YiS5YkT7WVPY5feH3Wiy0uP1ZcN16DZDolDfwiZ7xLOhb6
         cEaPiP/v871jW3XbHkKcUlYfanfoajvZ7HhtE8cFIEy555nkbwGUXtjOZGZP9WuxiP0S
         LycA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PnejpATI8jeHbKw4ZzS96QGP7ljIXUKvUSzUvhL9Hs0=;
        b=tezmgLJlsGPRogH+ZsWpJj9dCq8kppUaBFDGMeSwUoPX39WDLAEqhaV43D7bHoLxMz
         hOMu3B8kVloHxahT7EkJxL9Y52I7YvBih2+1DaOcQLLQGT0wKw4uSM+zskv/SFnfXHfD
         uD/A0aM8V8fZmzp5DmwDtxZzV48gHasJJwFwGq3d+i7j2Pw8Tk+jbucWG9uM+j43I2AX
         1N7Qvx1ujyihSsGclZE04NHyI3cFXmi5AQ5VvFPhQX40RAInB4TN4Sp3XEWSQVdxhWzd
         zqhn4ehUiylmei2ADYIuHs1hw89tcIwlDW+ZN/qFPoP5FjGzavK+gqcfdPOyLaSoMNkM
         lfLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VqXjYcoPMhEsUiOb6Z4os6LmkK3J6es4Yx9r05K7MQDQ4X7lx
	ahdNVYhVimHHFvR4hR6Tft0=
X-Google-Smtp-Source: ABdhPJyQYnusCRc+876MqPJZFCNCsvhiMYhcDMfdXKBUTRj5ikuI1fy2yIRBs9LEtPU7hr4MUIoPJA==
X-Received: by 2002:ac5:c912:: with SMTP id t18mr709390vkl.54.1594036249085;
        Mon, 06 Jul 2020 04:50:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dc0f:: with SMTP id x15ls926012vsj.3.gmail; Mon, 06 Jul
 2020 04:50:48 -0700 (PDT)
X-Received: by 2002:a67:643:: with SMTP id 64mr3218244vsg.32.1594036248678;
        Mon, 06 Jul 2020 04:50:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594036248; cv=none;
        d=google.com; s=arc-20160816;
        b=iPKIruYEDWBJJ3stryi1BMlYGRPtL1cKyBbYQyhhtv9ATIzOkCWk2n5+urBFM4LUti
         Akj8nT7BhnLa+MLZss2dJdws17pn58KEve6FSkpp3oiJdAuPeA0zeoDumeqd7MkRFU9S
         hy3ePXMRkFaiod8d08W4WYz9TM71Z5Ab+lxYltPAF1RDDSjuyUNE/RmekMMdz5ZTCKc7
         9XMyrmHEIxSRMPiuyZOApZcVU0rB23LWpz28znWTsUFuAWqhgxcifDpsOKWsk6l0G8Pr
         xUh8SXqgMTubb7kgbWq4a2rdgfIxe6i+L8hNijg5AzSpy7QDm2sje4FxRvC7Xdqi0Oku
         puRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=HgGv5GllBCIs4pALjjuZNyjAbCUoNT8X/DWFg7aCCeA=;
        b=GAsrUl6XC0DsRXFDzr2wLMjQUTsOEqT9xgZcskXXDLoBHY0/uWn27U3ZO+6/NNXTkQ
         IDo2TEuZ6xcK8YSq2SLHGAXMNciWzPZfrosVzkNYhxsBpPVsyEY4nmJo4xQFrMOeMbnQ
         Vf37nuxOiNnP+KCLM9cyUafYGJ/k9g47AHOBfwqOqjA2mQzK1WFma0CYrzNvJqBkpfWQ
         dPxD9sXfMtmPlAK6KUTfspL9jhXpNguy1S5SKx3nGQFQ6oHhYPIZZcPG5hNfHXBjaovm
         0mqg7msLR17DTaEjicHsykNwLyU3KEvJb+IdMSkiY/OVtnBXvp6W0NCJSxPufaiqUkiJ
         1SNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="Eil/MUly";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a68si1197244vke.1.2020.07.06.04.50.47
        for <kasan-dev@googlegroups.com>;
        Mon, 06 Jul 2020 04:50:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b63b5d4ad2d545fcba1674c27f637cfd-20200706
X-UUID: b63b5d4ad2d545fcba1674c27f637cfd-20200706
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 776962270; Mon, 06 Jul 2020 19:50:43 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 6 Jul 2020 19:50:37 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 6 Jul 2020 19:50:38 +0800
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
Subject: [PATCH v3] kasan: fix KASAN unit tests for tag-based KASAN
Date: Mon, 6 Jul 2020 19:50:39 +0800
Message-ID: <20200706115039.16750-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 2696D56F8A745539E46ABFD94ABC60186801271EB9B4EF448FB11D58BE36061F2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="Eil/MUly";       spf=pass
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
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---

changes since v1:
- Reduce amount of non-compiled code.
- KUnit-KASAN Integration patchset is not merged yet. My patch should
  have conflict with it, if needed, we can continue to wait it.

changes since v2:
- Add one marco to make unit tests more readability.

---
 lib/test_kasan.c | 47 ++++++++++++++++++++++++++++++-----------------
 1 file changed, 30 insertions(+), 17 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..b5049a807e25 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,8 @@
 
 #include <asm/page.h>
 
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : 13)
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -40,7 +42,8 @@ static noinline void __init kmalloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 'x';
+	ptr[size + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr);
 }
 
@@ -92,7 +95,8 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
 		return;
 	}
 
-	ptr[size] = 0;
+	ptr[size + OOB_TAG_OFF] = 0;
+
 	kfree(ptr);
 }
 
@@ -162,7 +166,8 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
 		return;
 	}
 
-	ptr2[size2] = 'x';
+	ptr2[size2 + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -180,7 +185,9 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
 		kfree(ptr1);
 		return;
 	}
-	ptr2[size2] = 'x';
+
+	ptr2[size2 + OOB_TAG_OFF] = 'x';
+
 	kfree(ptr2);
 }
 
@@ -216,7 +223,8 @@ static noinline void __init kmalloc_oob_memset_2(void)
 		return;
 	}
 
-	memset(ptr+7, 0, 2);
+	memset(ptr + 7 + OOB_TAG_OFF, 0, 2);
+
 	kfree(ptr);
 }
 
@@ -232,7 +240,8 @@ static noinline void __init kmalloc_oob_memset_4(void)
 		return;
 	}
 
-	memset(ptr+5, 0, 4);
+	memset(ptr + 5 + OOB_TAG_OFF, 0, 4);
+
 	kfree(ptr);
 }
 
@@ -249,7 +258,8 @@ static noinline void __init kmalloc_oob_memset_8(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 8);
+	memset(ptr + 1 + OOB_TAG_OFF, 0, 8);
+
 	kfree(ptr);
 }
 
@@ -265,7 +275,8 @@ static noinline void __init kmalloc_oob_memset_16(void)
 		return;
 	}
 
-	memset(ptr+1, 0, 16);
+	memset(ptr + 1 + OOB_TAG_OFF, 0, 16);
+
 	kfree(ptr);
 }
 
@@ -281,7 +292,8 @@ static noinline void __init kmalloc_oob_in_memset(void)
 		return;
 	}
 
-	memset(ptr, 0, size+5);
+	memset(ptr, 0, size + 5 + OOB_TAG_OFF);
+
 	kfree(ptr);
 }
 
@@ -415,7 +427,8 @@ static noinline void __init kmem_cache_oob(void)
 		return;
 	}
 
-	*p = p[size];
+	*p = p[size + OOB_TAG_OFF];
+
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
@@ -512,25 +525,25 @@ static noinline void __init copy_user_test(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706115039.16750-1-walter-zh.wu%40mediatek.com.
