Return-Path: <kasan-dev+bncBAABB3O24CPAMGQEG6P6OYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id AE14A681BBC
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:49 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id l19-20020a7bc353000000b003dc554c8263sf2907149wmj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111789; cv=pass;
        d=google.com; s=arc-20160816;
        b=DY/KB/hi20OEsRDM1H4DDKFfqZyeMJLaUmPgkByeFqqVfMCzsM+JHxRYzyJGXXEeTk
         fqyRzBlcpZWCFnN+ke0Ethrl/GEJoaxbbKdYaMaJ7JNcndbDf5pZ3auPl70sd9MGomBL
         lraz3nYEfdvysLe/v5Ge1W6AiOn4wmgoR5eBCavG2cwX642Of69+NhirJR+loJ+FM2gv
         F68TncTcC7J0MJLvz6/rDfSTr5ctc1L71hXQIC0FCOmTdzEtqJEujoG0IT9IMvGnyrra
         gQQYVkatwdMyc6MdMPu7Ly0WhZgyFHk2csD9EcJEfpnYx1k6JYnT5Olb+DMuRpewa2RO
         Ijlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A3zelHnh1Fqjq4hMifRloz9IU1t5b+R1VIbP5i7DnGo=;
        b=NAsKvZKAsMlrmQI/7SmbwGxU7QO4rWrizccTJODhbr0EURNHqzoR32rskaMpHeIdjs
         SUOcrua+htQdV+RefD2tE0+kQNQ0Z9wEx830Li2G3K+uS7urHSgmw+9ADlrVCM2TVeBr
         butduHK/yYrwEqhh9z5fUf3AKy/z28eiGKPKTUIPGSCaCk39OZaj4WsA9Py6JFGjGzie
         ZnqCcMlYznN8NYRxRW9C9uwKFPqPfQxq0Ade8Fj0yanQb3tJNnrpHJW3R5/OIfceyvn7
         xIn6BXeCdFcecOoS6DDXOx+wKJ1MYV2ZtBWI81TNPksR3Wwhm0a8z7yfB1M0tmnDvVs2
         OeGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SpOJ60TV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.36 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A3zelHnh1Fqjq4hMifRloz9IU1t5b+R1VIbP5i7DnGo=;
        b=bHKVV3A3bnOc8UmdahEhsNLihfd+rrdT7zVzJA04q0LQb66bRVM+bVn0weuMI61g3A
         Q6VBe5PwwrpUo93yMinaRkqi2BPlRIaB+hhP3N/ayucm7X1No/x2O7dWmQFFn1mNBF11
         jO8vfOxJU8VEObvtQnZiIKS1CoMn4puvQaB7oq6LqXCbB+JGaxlwnqKLKiPpz9vzCrYe
         irekYTd3u6Zqgsl1vmkDKff39wKfCwHcqDfH1Tewpq1GlLHQdupzvLfatylRFyP3bPeV
         QujEiQp+LBftPoeJmNAkDOsqLqzdVxSxOjEXYxzUYjJW3MTgtafZgmmrXMtW/hjUJ4I9
         /ajA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A3zelHnh1Fqjq4hMifRloz9IU1t5b+R1VIbP5i7DnGo=;
        b=Fo27QziV3uHssYfUQEljfk6Djf6gWkhFaD8nF4Fhgq5Yt5UnkdNCkioueBiTb8gfAG
         5EffYuHhH0juUIGtDO3DXbpdi1Vp4UmYWL2R6Bn9nqt2M+2vr1x54ZdDhtxVrO5GswWn
         lDL15k5II/qPwqCJEsedyq2/ydk+GjXPbmrdjdEVqtehzbCCvG0S9GeWhDziSii4Z21g
         ov6DQhIRauZnVG9cK+3MbFkcsNpWcBPKmfJyUuRcEC3/g2kfUikastrJAf4C3vxuv1z4
         EXTVcg1+KZKSw+6rZiu8wHLfFGO0pICjZ/WpPvq3YVIJaBe31JqVGz8GB4kfW4VqMiTz
         SH9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU+O6TmqkfNdU2NV9n8hY0xbmlt/pwCgc9GJXJ6fLn2Shkk7B5s
	aunB2YL/53xHoV9A8ELVuf0=
X-Google-Smtp-Source: AK7set+ScvenifqIDbEE54FbvEAOyM6bgfZfG7OR6OKtk02gmIJVI1/p7+zj+whZ+wePEJKspzDzuw==
X-Received: by 2002:adf:a3cf:0:b0:2bf:b65f:d143 with SMTP id m15-20020adfa3cf000000b002bfb65fd143mr1192458wrb.593.1675111789366;
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d83:b0:3dc:5300:3d83 with SMTP id
 p3-20020a05600c1d8300b003dc53003d83ls2926931wms.0.-pod-control-gmail; Mon, 30
 Jan 2023 12:49:48 -0800 (PST)
X-Received: by 2002:a1c:4c12:0:b0:3dd:1c45:a90e with SMTP id z18-20020a1c4c12000000b003dd1c45a90emr350447wmf.25.1675111788431;
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111788; cv=none;
        d=google.com; s=arc-20160816;
        b=ZG3mxYzfn9dFTrq/WoSLmfjbWljfQRrh9vQOohssd5ghnM+K+Hc+KSjiemg7omsisV
         AtVsh/vxw6InNXEUxw35LWXYCNEttLwKhEAP/Vh6XDEitT8Abgt8JGCyhBp5NdThYn/y
         7dSSLHYCbgIoGVdZwROg2m8UGYqKVQzwrqA1xCOqvnspu7Qu4AFbAeY1m3RaSkLYlQnG
         +YHzDKflVOYgeXRgmOnKbQeB3e37485UUw5TFptLeW5m3QspLMhpiP40n0Vc3svss60i
         JaNbrStOjGsrxyXDnnPDgIsIWNddE9Zpek32iqnRxfAYqix+4vF8zJUHscrO2bdjAe4e
         jU7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l0DgDHv6v1bes9QPJYpLqp7kkvT0kapBOv6TW2IBB/k=;
        b=oaX1hsYBlJ30l+BtdGLiZ7X294zfhx5CweYgXZ7B+MI87Q3IL4zpNuHHJFjidpjayJ
         DToVxEWthkktSCxzPXpLFcaDxTix1hKruRmATrnT13MzDsWmp34ptjuQr1AgnZPiE9sc
         r0fYqYSI0ONCSfJpDqFdruqecvhv06EFaRmBmJa+OBDuySKHkMIaUzeG9KAlBIdv17Ng
         JX3ZY0b2ZsKooUKDSGabsCfTYiD4QgMVzTqB1YnAhOP3afV5atHdyte/YNlPFi1eqT73
         9srVJuKGad5kc8Ko6Txu4d7jrlby1JQcJ0iF8LDFFbUfZhNT3QwfoSnKr0rrsux9lwaI
         nHxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SpOJ60TV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.36 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-36.mta1.migadu.com (out-36.mta1.migadu.com. [95.215.58.36])
        by gmr-mx.google.com with ESMTPS id bi21-20020a05600c3d9500b003dc43c78e98si555715wmb.0.2023.01.30.12.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.36 as permitted sender) client-ip=95.215.58.36;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 03/18] lib/stackdepot: use pr_fmt to define message format
Date: Mon, 30 Jan 2023 21:49:27 +0100
Message-Id: <3600069e0b0b3df602999ec8a2d4fc14fcc56a01.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SpOJ60TV;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.36 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Use pr_fmt to define the format for printing stack depot messages instead
of duplicating the "Stack Depot" prefix in each message.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 23d2a68a587b..90c4dd48d75e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -19,6 +19,8 @@
  * Based on code by Dmitry Chernenkov.
  */
 
+#define pr_fmt(fmt) "stackdepot: " fmt
+
 #include <linux/gfp.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
@@ -98,7 +100,7 @@ static int __init is_stack_depot_disabled(char *str)
 
 	ret = kstrtobool(str, &stack_depot_disable);
 	if (!ret && stack_depot_disable) {
-		pr_info("Stack Depot is disabled\n");
+		pr_info("disabled\n");
 		stack_table = NULL;
 	}
 	return 0;
@@ -142,7 +144,7 @@ int __init stack_depot_early_init(void)
 						1UL << STACK_HASH_ORDER_MAX);
 
 	if (!stack_table) {
-		pr_err("Stack Depot hash table allocation failed, disabling\n");
+		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disable = true;
 		return -ENOMEM;
 	}
@@ -177,11 +179,11 @@ int stack_depot_init(void)
 		if (entries > 1UL << STACK_HASH_ORDER_MAX)
 			entries = 1UL << STACK_HASH_ORDER_MAX;
 
-		pr_info("Stack Depot allocating hash table of %lu entries with kvcalloc\n",
+		pr_info("allocating hash table of %lu entries with kvcalloc\n",
 				entries);
 		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
 		if (!stack_table) {
-			pr_err("Stack Depot hash table allocation failed, disabling\n");
+			pr_err("hash table allocation failed, disabling\n");
 			stack_depot_disable = true;
 			ret = -ENOMEM;
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3600069e0b0b3df602999ec8a2d4fc14fcc56a01.1675111415.git.andreyknvl%40google.com.
