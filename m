Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNWHZXUAKGQE6J5ANXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id BFE305689D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:23:19 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id i3sf1359918plb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561551798; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYpETcZsTkDRSoOtQQ4JyTZ80kRK2QKI1Dz3K8gM09zyypNHP3Tfycz77CpXb4/4hB
         6FwnfkkuVEEAx/DnvOzv3wMAtm5sdmp4mAa/3qHbk00oi9zeH09cYztG/SULpp/CLetX
         G3pg7Ioyh+obGQOQOtch+4pMzlnlKETguvM3T22PimUoilNVKC3gQ1N9xcZZeriXPYY0
         k1cBpPufDVkocIsPhiRSKN3Rv8W1NrIWweym5y3+59NLaRmLLtAlvd6xbSXqempMz2SH
         r5vJWCB5drjSd/TSNan3JsZ09g60dMwmSoQlMKoI3y9fJO25i/qqZlEh5pU4XnUgZpR/
         CTxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZFwTuyitWpcMAiBXvPdSNoWB0HCS8R0GGpthpoFKDDU=;
        b=x90BBO8Rv2jKOIhjbF6a5BGZnXNOHbpF3bMC5M07vLXfbaKGIC7IArBxpA4Rky7vUB
         KY48vcFbB3/1tvR3e1Yr2R1Uyn4iwJ4qVo39pqKvku+0rwsucQTrrOzp+oG9jzZJUvpf
         lKfGOIqYARQNQxjdwHEZVzCZ+jBlo7d+ara78lz/GsNd4Xqofz/rWIDzfUk90hIrYqpn
         91dAFsfpa7B8fPKkOeTh076RpY3FCMZ3jTa1qwAtZvoBu33GwmZgOhX1lbYeic/sXIM5
         e1DMOZ5QCEU0UqOzZgf7eolCepE8jXk50CvsMyfUlA+UOSPOekFd+/Fs58JrIRpPJvkU
         O01A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bEoviPlE;
       spf=pass (google.com: domain of 3tgmtxqukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tGMTXQUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZFwTuyitWpcMAiBXvPdSNoWB0HCS8R0GGpthpoFKDDU=;
        b=cOUgVa8SDzZArpltd0uoP25Zy51O2mLEgikzHAG0Q1wugXK9NSWeCLGbl0IFEU0kh1
         7//1RIWTNn6/FUQOSH0SP9+/JdVOvRhECqHF4hx1ywlst7YEm6Iw4XP1iVNqMUtpCaR6
         vZoYDLdVTbzfM/pYc1bfFqk8/JqRyUBhhO5fID8HR4idrg92GvLb40o9Prn+SuNZOAvh
         GvTeWMvb024xJGYQGSmHBQPFp6+ef78q2LQHmNPMOZMUK7v8MidEVjHdzq24dHqSFytD
         bD90xzfLMPbrg2mJB52Rq+KCmIPqRJGjVZVHama2uq+jWlN9cXyBHRmDArn+DSbS+8cv
         BqRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZFwTuyitWpcMAiBXvPdSNoWB0HCS8R0GGpthpoFKDDU=;
        b=sLIsoOxWIX0wNsD0WvuXmwKEqVO94PmuQShsvF1J1HkU4/NrFPQL3OmWBnIE9/5LUF
         r4OurGyzbj3Bi8Dj5S6fAThk7wYVw+rRdXl42s/TbI2MmioibA42codQZZFoumukMw7j
         Qzi5UiS1X4vXvg9MXNp+mmsa9YBARMaPKnOM9bG43hsOYpDu0sMbOz0bqHXekFtXA0SG
         CNJWEKz0IcyZN9yr7N4/PdA9TXBkRBzgNvNDKSNX3g42NiTo6eQggxG2v5IgYd/xQttU
         ywDUJp/Mi/VhwHKTWspgfwGsmbapxcAap4TotD8YLcK1L0ALU7vqM6+Ip7fVNdDObt05
         T4Nw==
X-Gm-Message-State: APjAAAXSMDOQvNHAnTZVASzh9DUTPbEBpUT/nnIPj11WV9wZN0aASePI
	TKOI8oPNMpNqc+IQE4Jq6us=
X-Google-Smtp-Source: APXvYqzYtMy1IycOVbVr5wjJr0cvQYYd8tuMhuuuHrS1nCsLPhuAWGgQTxCeG/Yrzz/NmYYM601OIw==
X-Received: by 2002:a63:6dc5:: with SMTP id i188mr2688827pgc.188.1561551798260;
        Wed, 26 Jun 2019 05:23:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd8b:: with SMTP id q11ls676994pls.4.gmail; Wed, 26
 Jun 2019 05:23:17 -0700 (PDT)
X-Received: by 2002:a17:902:9307:: with SMTP id bc7mr5020231plb.183.1561551797880;
        Wed, 26 Jun 2019 05:23:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561551797; cv=none;
        d=google.com; s=arc-20160816;
        b=LAkxsPBfkmZCWyLDv5fuvoBckZr5VXQTRcFCkdFtGUM4tlZGxBgsFGixIHrmWC0iUD
         RlpdqfYl0/MI+O7gPeZ66JehXRSBwrFiB6nO8YhgiBRB5FbUmo/7N+ICbTYb8ynVZDai
         aT/4s1OnQxy1wTJuy0BIW0fGHNVbm8orQ06eBlHAFpNE2PT4vgxrWeZh27cSg+Ce8QEB
         /YniXReCblfn7dRLgFJGZCG2zpFqdVlxIhfnUm0Qq3rDlL6z+A3usVGpkHn4RJCauaaW
         lWARFVxWBBRGznVU9QuTL0+8+euzk3JlTNQqmfXT/ksjStU6oG4rvhkjAv9yYSAJkJB9
         rSZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XRvnKModUVHTmFHrHwuo1MwyIF32UbSI8S8OvJKLAFg=;
        b=Yt0DDaLXE3Q9v10G3YL2v0En3kDVhZ2DLAu8OB0vqGkNZ0vG/z11aPfucV6D4QFeT0
         yQNWlx3QlAxiaFnUTQn31V51lglxWw23Y7OUp9m5AqzpJ/Ht3Tb3qT3Axlk8YmiFoHaR
         c/mYUBZfTeYfRohF5XZnBPeWiVVnRA41uJoBvRvfLNQKZtSneGHUsXdX3xhbRgh1ZV9E
         jEijp10XMGe5kksCKERO2I/NEi7V8Ztn+ocsg0heEMU45+GHUKbKpj+DuL1NDDFKdbe6
         /goSxTvO6juCZJcEVuccFzT4KrVFa7sq/Lbbth5it2Zy/2Hfh1Xs0JX30MAY02Nl88Xj
         rbnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bEoviPlE;
       spf=pass (google.com: domain of 3tgmtxqukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tGMTXQUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 69si760351pgc.3.2019.06.26.05.23.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 05:23:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tgmtxqukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id v80so2322286qkb.19
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 05:23:17 -0700 (PDT)
X-Received: by 2002:a0c:d604:: with SMTP id c4mr3199153qvj.27.1561551796862;
 Wed, 26 Jun 2019 05:23:16 -0700 (PDT)
Date: Wed, 26 Jun 2019 14:20:17 +0200
In-Reply-To: <20190626122018.171606-1-elver@google.com>
Message-Id: <20190626122018.171606-3-elver@google.com>
Mime-Version: 1.0
References: <20190626122018.171606-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v2 2/4] lib/test_kasan: Add test for double-kzfree detection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com
Cc: linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bEoviPlE;       spf=pass
 (google.com: domain of 3tgmtxqukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3tGMTXQUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds a simple test that checks if double-kzfree is being detected
correctly.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 lib/test_kasan.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3c593c38eff..dda5da9f5bd4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -619,6 +619,22 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kmalloc_double_kzfree(void)
+{
+	char *ptr;
+	size_t size = 16;
+
+	pr_info("double-free (kzfree)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	kzfree(ptr);
+	kzfree(ptr);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -660,6 +676,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kmalloc_double_kzfree();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626122018.171606-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
