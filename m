Return-Path: <kasan-dev+bncBDQ27FVWWUFRBT7WWPVQKGQEY2DGNJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 218E8A54B6
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 13:21:53 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id u10sf4810208oic.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 04:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567423312; cv=pass;
        d=google.com; s=arc-20160816;
        b=hJ+AA4B7RF3v0zK5Lbk+TYy5uqTyer8pLnqIxCXOisQooAtGp6zFl1MQqO2XXXeHKm
         SMgWUjG+25an8YscukmHA4f9ikfrXY5Il2JqEB8y9UGJ5BQph4xMk3z684o+ikkVOLjm
         6OZCdVsuCUIi4MX2ci+HaXLo/T/npVx4ZwYY30j3Yf5YD/F9ppcYnpYYcajYhf0ZobeK
         H6bO3fm2daKj2MnXrUZqoY9poLCz41OW5jsGRkwnrqrlM4EoFbj7QLr8a0RaMz/CxLS0
         9d25OdJxhzklSmibBWT44bC2FGQN4Lg88feUtcnq0AXzcl0QQsnFEblZxmPTOsN/J4EJ
         2Fnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lrfXfTTLoPV5dMtS7c8M83X2O/8vYlvLiRHj7v2cOHI=;
        b=D2/MZr6aKYifdUNLfV81R3CLe8nH21ST2+ozRigh/cgXwGARt+IYOrScA0zKvMGVZS
         NXjN88bPp4PAQsIeBmSwKsuQ0lMuMgzU9qeT/5WG4vLV5friFdVThecZi4ksABM693SR
         NduGhpBe20kZMOlnIytHhLUTzjiLshF/hLD1A3qHbjWoX7FqBLn6883Z71q3XvX4ERy9
         0fjWFPBxazJFAEjcyMp4jkNbXnoOtt4aKwn3nX3sV06HbYNObhyaCwooSl7XD6m2NfGB
         9IM/ZbJcG1Gd7Ryf+AJ8DtiMH3adVllr1nAIb8de3vce+vFeqqIFjVWAHQHgKjw51ke0
         HCnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GKuCbVx1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lrfXfTTLoPV5dMtS7c8M83X2O/8vYlvLiRHj7v2cOHI=;
        b=oCsLvCY29SOjTonffIo4dJk6gdMWENjdlR3WdoWYJFnnvrVhFUEzzwc3EzaYgofTqB
         iF5221wvCKaTjCAspXJVIElW4j3updAjy9tW56LU4ytN1BID/0SCiqBn7wGAyLUi1Tb3
         nBhlN4rlt2cmiqlc7wCiS/bZr07TGZRHe6LYGLuHgPxP3z0Duieg5PtsNPmbhWdOfXXR
         eaMkFG7WLVmWOvjfa4hnpGh0DHs+5ES2Wk9SkMK6OX09WuC8JELI2D84N877gTSeFj7L
         eX/ARDHQiQcPmVajdXPisOhPYQ97IR2sKBY3Zd1UXayv2vPJrMRjcAF4ANcvtbaNM4TO
         ei3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lrfXfTTLoPV5dMtS7c8M83X2O/8vYlvLiRHj7v2cOHI=;
        b=dk+Z73mTYj1KPq4Nb9/EHGjNdMh1gn8GNmrXDWKPttm9O8diyTw5QlrO8Ps3nkY+Mf
         oZ+oz7HCFEggQ1lrfGfa7cQqjykAivUqhNK6ghp1l+R3B/wC7o2UiOLfbZ4ipzo+QyT1
         P4JHPnELEJFwCUBisG69KQRH+cO0f9hCQ36ynkosGHi5vWlAZefUV8n7Okzqg54/gmIt
         mPlSx+JdCawH1EmvH7RDnLkqiiB4WpZJi9QLsjUDca/ro5JeQzmUQ7SghKR54WVMRaSJ
         OlxOw6Z02OdPyeajMvbqGnM6sX+l7/nSSmVv2JM0eVIwNUGM83il96nlkB3WG6dk3HPL
         Hp9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWpM0BE2rECSHa/Gspt1niAyOX5d3j2JmeJI4CG47Jblup7w3Zi
	R1iKOD4htl4R/N/Yc+QvFIE=
X-Google-Smtp-Source: APXvYqyEeZY1U3K+U7psAatgUYUsg0lN+JLd/vT1qnWzK/iJyB8P+UIa3r1GkLFO2ImdsFwLcLvL7g==
X-Received: by 2002:aca:61c5:: with SMTP id v188mr19445721oib.34.1567423311943;
        Mon, 02 Sep 2019 04:21:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:448b:: with SMTP id v11ls1231079oiv.3.gmail; Mon, 02 Sep
 2019 04:21:51 -0700 (PDT)
X-Received: by 2002:aca:3388:: with SMTP id z130mr18870023oiz.81.1567423311724;
        Mon, 02 Sep 2019 04:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567423311; cv=none;
        d=google.com; s=arc-20160816;
        b=tUxh8ARdGPqX1zYzn6fUBB8NjoRf/KLwIt1uaq7JPmbpODK63afdgsly5dE1/CRBrR
         Je2iqBSeKoXn3GPy5D3XIkTfIhD+oJevye70GyXhM0tOXKa30EGtOW0WO3+SUnF8O8t6
         UTxMxQt5qm6FNi9mcgnNDzQs/VKAE7ynyJK6ilWfujNjlS8JIDmoCp2FjrJrif/nodEC
         UftThbo7QsY9gozwu0QfwF4olx+9M5JjOmSiya2nQx4hQw9ktPp4bUV0Ey80g3xFhpD+
         HvtrSZNusyq+JWJPet0i/q2rTC/7Tgi5/gHhUGAVamKq71OOXUTqANQXJ1ffi97rpp8X
         OivQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNDV9DT7O32N2h9l7CrACdWJSzNVfR3Dv9pnUT55kOg=;
        b=jWUD1UV7T2Rbu/iLySWn44QauEo7ZaiMagUBzEgCAiMBebsEuUzcOAKfza20FJr9z4
         wJheDOzU7M/1tq9X+vNOdFpTNt1xpG7HTEo76LjKqUYA/hsLonLUBo2TP5QWhuvSvgJX
         29J0ddUT/87Zpy1dTclpny0QzekD2VtOiw8Yqz6zRu29UTzIEhIokH92360wrUSNPxXI
         PkFC3iNg5TW0PxI40hbJOcIdSXWrw9LIx+/Bc+YHn17NJv9nec7qopMeARye444EsE8m
         HK0Xvj0HRZRTrM5zw0SZPLdKxxJQznDkGA51bS8Y13a54vBkJJbOU1D69i6mMU1w8r4H
         tn6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=GKuCbVx1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id l83si696995oif.3.2019.09.02.04.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 04:21:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id s12so1855975pfe.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 04:21:51 -0700 (PDT)
X-Received: by 2002:a63:b904:: with SMTP id z4mr24200059pge.388.1567423310696;
        Mon, 02 Sep 2019 04:21:50 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id o64sm7133044pjb.24.2019.09.02.04.21.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 04:21:50 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 2/5] kasan: add test for vmalloc
Date: Mon,  2 Sep 2019 21:20:25 +1000
Message-Id: <20190902112028.23773-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190902112028.23773-1-dja@axtens.net>
References: <20190902112028.23773-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=GKuCbVx1;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Test kasan vmalloc support by adding a new test to the module.

Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v5: split out per Christophe Leroy
---
 lib/test_kasan.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..328d33beae36 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
 
 #include <asm/page.h>
 
@@ -748,6 +749,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -793,6 +818,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902112028.23773-3-dja%40axtens.net.
