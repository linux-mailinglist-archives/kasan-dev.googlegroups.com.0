Return-Path: <kasan-dev+bncBC6OLHHDVUOBBFH52WDAMGQED6N5GQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 73E363B3CE2
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 08:58:30 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id l10-20020a17090270cab029011dbfb3981asf3287149plt.22
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 23:58:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624604309; cv=pass;
        d=google.com; s=arc-20160816;
        b=BCarqmihhfK1BY5Z9c8js0VkKCRKQ01WbE6X9NgOwAP/hk5cxq74gf5X7QRWDOlLph
         mxK8RsSB3LnhHG4H+P1B1jOO44rEtTHfXgsrR7BzdpRTXiCHZZtQlod8DMZb8WbGwRyP
         20qWLWS1ug2ZBSc2rVAlvPY6yxcNONmBsqY7eXKhV64j0inVtMBGZFQnJFC7SzPaDivv
         DiQFJhn2H2esGYwFkHUAYZLWde/gRVeAs/CpVmPcQkbDOPTPuj5HmFOGIlEUBcFok4w2
         OfVIRZMh/cg9A7YuQIFJOKu+2OWvQMsitrRGU9zdpltA93sSXLhHSsfom+IgjiqOd7Ec
         HrhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Voiv7ZT9q3PzIOgkBToxWBeTaPAXQbub766pRoL5gvA=;
        b=lMiv9HITrQurLn3z94aMVUBrbNyxGKFdhAph4xZM5SIWWpKKgKXxcWxzTnGV1+m8Ta
         ZLN/RUfEidHZTX0ohFVujwDDPzBfZ0uo8kyXQYUwpfF1f55BF23PzvpZOLtOLXjvJIqe
         tSTz7tt7Xhsv7yupdwC2nywZKplinsTBqvg6gn7z0JASwYWdvH2+vEUJsH6FAPdiWAYn
         pe7wzKtcqDoZFVGtqwxnEfaWyVUzJZ/9RxRXvVoDIPhfwYZw3k4z5cdl8HpYXrnDUZ88
         dzwDDbSrSIf9eB1L3yYQH0ecsI9iYVH5blJQNYdOoU2zcjM2e6+V9Urc9CN0fi/dlR9i
         zdIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i1Rc1Z9h;
       spf=pass (google.com: domain of 3k37vyagkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3k37VYAgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Voiv7ZT9q3PzIOgkBToxWBeTaPAXQbub766pRoL5gvA=;
        b=CaFQWpqOdEUi8y7J24eEK3ZlqapjFUbOhjOsfVL2LsarBOKejeoNr4jo7qS1wsCTiq
         0NA9fspdVsacj6Y6ANf3CD+j3AuRmb31I5st/MzxPj6FQrJh4fRmqoytmmian23/zpt3
         sDJGdnRloCWKCTWEmM+mdegIjIWaSZEawlOWF837HxWoRQyPfO8O46iLGkuK8eY2w2a1
         3e6JC8qRtF5nGEABoiekvikblUqV8VFJxouDOhYjBnnayEgl07h7JevXDiLvJ57bzBuf
         YTFX9qwtQzc/P2UiwWO9WGZe8n1mSPbwq1MdwCJrzvw1wJZzbT+Z82bigSE92estDfMl
         xROg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Voiv7ZT9q3PzIOgkBToxWBeTaPAXQbub766pRoL5gvA=;
        b=Nj+hwAt1KLBWvvku/Wzfb1Dxbd+FYPZAsjJ+lS0qoPuXgiS2/zVk3LXpASk54RN6ER
         z1dmh/hoGFLpJoFdGULO6AWeWQfDqssM6Yuq+Jwei1QgQeOU64omrZ7CvoRoTTAKDI7+
         dyyJcIws/b50eEFu+r3b8wcBoe1O+078BrUAG3HRgpujj95nTT5KnH7fPsEGDmrnMdF5
         dHwYHacTK1X9z7Mlz1T7dMiX6RxSFj/5pTMwOMomqOG0oqXcW/DuCioC6Z1pkExYErji
         rx3BUlauPkYTIpCP/suAe+QU70dyZNAFJI95kYbcw/blVEnVvuymJyU9VeAssqjzwNGT
         cQIg==
X-Gm-Message-State: AOAM530rKFERB+7iupDk4b4rdTf/WK76RfHdlcsT3+wd7qRGIFULuj7c
	rRPkcwYXeVDn3ugCoWEg6lk=
X-Google-Smtp-Source: ABdhPJxHq7uhxbbFm+kg9HJbmmoj1vd7M5ThW9MaY64WGeV7FUXtq6YEittfPJilz59CxsyCkkwCGw==
X-Received: by 2002:a17:90a:16cf:: with SMTP id y15mr1783583pje.219.1624604308795;
        Thu, 24 Jun 2021 23:58:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ea4f:: with SMTP id l15ls4165064pgk.11.gmail; Thu, 24
 Jun 2021 23:58:28 -0700 (PDT)
X-Received: by 2002:a62:b415:0:b029:2f4:829f:e483 with SMTP id h21-20020a62b4150000b02902f4829fe483mr9245732pfn.4.1624604308172;
        Thu, 24 Jun 2021 23:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624604308; cv=none;
        d=google.com; s=arc-20160816;
        b=pJDAMDdw75EVHbFdOkbPZUglliBIFrjEIOka0+xJ/KiNWXRU7o2IE3zOdBCk9nTQkZ
         16d3RT4HcNpYVfPxiGYWR036TKKK7lVSqoIqgxapOBZNAShlZjCeHwJ+gHUeusB6lZs0
         fWICn5/xB3H5vXlHMwPEMDuYw1e0pvx6w4r6p8EOjj2Jx9lReGVXuuw3J57eWwCyGOkU
         fMS/O3tc40BC7L57ARfgs0ecT0SYvloEd0hgt+SwYochPdwiIYreGI50LBR4XScYoR0u
         j8amiFiR+P2w+J++dY/i031zyfLplrBXKejV4fMFfuvmMpHdsm4IHnns5qJ7ZsUQzS2d
         8MEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2nlTYNdkTccPa1M8YvTTP6TrQq3B5YIgoTfwE0h00Bs=;
        b=XkAzE6fAGZi2RbTxZUNsPaqHv5Gq/B2J1HdKL3yxcEzM5r0DVQZrJMI3P7gcQ4G2A3
         JGo3cf1MxgdD6kfzdJ32TmvjNG417sZY4WcbNcqQ1e2tEOx51PFcB0wpyD12A8dEwxCy
         3L6M3aVQ77upiyJ0Dmr7U8Z7TggzwTDnUkDzm/1dPHeuTOFhkdKQVT1udAnlKar/pLXF
         omlY7hmtVSsBVRcdYytXf/dJk6A9AFo2r2mNZpXkvdpef1c8wvu0g1CNVBbur4mirYFe
         uCJRHxSuGGA+bKwCaXAEYUNq/HY1341JY3pMvrZio+sFUpdQXk0E23gNaqmxBl3S+UlE
         WuOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i1Rc1Z9h;
       spf=pass (google.com: domain of 3k37vyagkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3k37VYAgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id b18si387955pfl.1.2021.06.24.23.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jun 2021 23:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k37vyagkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id a4-20020a25f5040000b029054df41d5cceso2974874ybe.18
        for <kasan-dev@googlegroups.com>; Thu, 24 Jun 2021 23:58:28 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:bd17:f9ad:979a:a3a9])
 (user=davidgow job=sendgmr) by 2002:a25:2c02:: with SMTP id
 s2mr10313364ybs.139.1624604307372; Thu, 24 Jun 2021 23:58:27 -0700 (PDT)
Date: Thu, 24 Jun 2021 23:58:15 -0700
In-Reply-To: <20210625065815.322131-1-davidgow@google.com>
Message-Id: <20210625065815.322131-4-davidgow@google.com>
Mime-Version: 1.0
References: <20210625065815.322131-1-davidgow@google.com>
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH kunit-fixes v5 4/4] kasan: test: make use of kunit_skip()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>
Cc: Marco Elver <elver@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-kernel@vger.kernel.org, David Gow <davidgow@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i1Rc1Z9h;       spf=pass
 (google.com: domain of 3k37vyagkcfixupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3k37VYAgKCfIXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Marco Elver <elver@google.com>

Make use of the recently added kunit_skip() to skip tests, as it permits
TAP parsers to recognize if a test was deliberately skipped.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Daniel Latypov <dlatypov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
---

No changes since v4:
https://lore.kernel.org/linux-kselftest/20210611070802.1318911-4-davidgow@google.com/
- Rebased on top of kselftest/kunit-fixes

No changes since v3:
https://lore.kernel.org/linux-kselftest/20210608065128.610640-1-davidgow@google.com/

No changes since v2:
https://lore.kernel.org/linux-kselftest/20210528075932.347154-4-davidgow@google.com

 lib/test_kasan.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..0a2029d14c91 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-	if (!IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " required");	\
-		return;							\
-	}								\
+	if (!IS_ENABLED(config))					\
+		kunit_skip((test), "Test requires " #config "=y");	\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {			\
-	if (IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " enabled");	\
-		return;							\
-	}								\
+	if (IS_ENABLED(config))						\
+		kunit_skip((test), "Test requires " #config "=n");	\
 } while (0)
 
 static void kmalloc_oob_right(struct kunit *test)
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210625065815.322131-4-davidgow%40google.com.
