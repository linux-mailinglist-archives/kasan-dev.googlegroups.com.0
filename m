Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7US3P4QKGQEYZSSFNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AC4B244DB0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:27 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id b8sf3617651wrr.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426047; cv=pass;
        d=google.com; s=arc-20160816;
        b=LsteFooNz++c76bVzHCw2SglhAz1ow5Z81FUwnirzcIZF70FEX0oyRQ8J1xXz0c8Hs
         dZGkCqI5h23pC4lzIA7iPZf6N6zeuJpqLJ6dQXFXGoq3cvymMb0PdlxLTHsQl8SSYqki
         CW5GSS9KuHLcoGHbaPAUG5z3h1Bt+Xy12Lz8oSGyaekY2LILwBmyfgzUJezeg+hxm0If
         q1DJkv86IpqrqEk8XjkX4N7HKXKAaTCeDBfx4CiptYcpirtXKePI+GYW4EbgxFhy2AbA
         0Ioe+MQAtbZ/6/OwQRvIxCghn1Qa5kQRHZCVYCIvL7Ja80yZs7HCiBx6Hy2WWW6+fWvL
         la4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nvs2jebXaZo13jAouVsfH0BSC3WxpXmhbOn3+N8Hats=;
        b=tjmH9geHuuQV57CIsgRu8VYwY5T1d/ZHR/rh6NDC2y+hhZyke0j6kG+A+N1FjOXjlR
         nNtmpzMIv5R4UGy0sLQ3dVQeKZac6j5jLpIj1hBv8y9WFm9UBkD9YxMFHV3+jzDL04Ue
         ff2xBR4U/PzKzBZ75+eCip7mcsAlTB57AH0EaWVvQ888eS0wlTfNWiuzkoBGWzscZjP6
         jQR8FCqkupQDpmpxkllociH6N4h4RIIz3W5myCzR7mj1KojTeWezzy+T2a6AG7YSB1Xj
         KDNurDEOSgrgmI0bQ3RlbYICCcyyZ4VtrtE1euR0RaqeUcMXpGQvB1edKtbot+K6i2qj
         EN8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OFCQVMh5;
       spf=pass (google.com: domain of 3fsk2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fsk2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvs2jebXaZo13jAouVsfH0BSC3WxpXmhbOn3+N8Hats=;
        b=JJAuD0ov770zVObkZXBeo1BDBVNOueAzdWYWEJzINFuBywO0PA4cXPAdkdyK2aGele
         mrqnBhA1jXKdkifbJgIL5MQ5AgE5XhKnv56F0F1P9nFcuVAX3kzYroDYVfp9ub1sciAg
         nK+1/+e/MzeLK7R+nmoh26TCFv5+m597qGQ0dVANVge0UdG4Bn8TPwL/9JoTVvB9yclb
         VOa+GNzpSwC1arX0m4y+URKFO0RPl68TyoQ1zVX7TuJmPofN+NRYde95ygnZV5DGIz4S
         k6qOe8gNeAR1YVUsX29MfHl2BPE8QRAbCmdOS7vsVL0jjcDwhP5uCeNcGGv6cIFhTECA
         dMZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nvs2jebXaZo13jAouVsfH0BSC3WxpXmhbOn3+N8Hats=;
        b=dQI4/OwoQ0nVA7Z8SXqhYdwqplFWzvFcWhSfP64A8f20EK8g7naQRUvz8WGETR2H9U
         /W2us8RM6Jplxzdp9QBxcbN5grbEHmDFs0iURo3LbzpRuqgDrTt4DJzZ8XFHNVkIOUQm
         FGojuYdpUEf/bdgCRWjFNtuButJDDdY0U8MEsNhjMQejSzOt0nXaW2kAMd4QMcNGM4bd
         iti+eAcKe5gl9mU4cbb/QGf1nbrx6TiK0raLPkWTsy/tUy4pOfXQsQr5MCfGTosFg7Cz
         z3H3EPF8CxCPDEgJe8rlbOlD+GSBHArYY3z4CzMXIEsZq6KtpZqeBSsPQJC3dus3oAZ9
         RzYg==
X-Gm-Message-State: AOAM532WStg8Fz5N9Ouw/ldMj2EKqFrRDy+xYMM+NPcfjP+h+lTXFqaz
	4uKJwXsAGIbg9N/kuSBqJd4=
X-Google-Smtp-Source: ABdhPJyEC8R316c7FAqpDCagApDMPnEFtgY8+b61dSgldr5kAim3KUfJo48XZ0Pdcsv+5FIp9v0Z4A==
X-Received: by 2002:adf:9125:: with SMTP id j34mr3975186wrj.157.1597426047034;
        Fri, 14 Aug 2020 10:27:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2049:: with SMTP id g70ls4454469wmg.0.gmail; Fri, 14 Aug
 2020 10:27:26 -0700 (PDT)
X-Received: by 2002:a7b:c954:: with SMTP id i20mr3669397wml.189.1597426046508;
        Fri, 14 Aug 2020 10:27:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426046; cv=none;
        d=google.com; s=arc-20160816;
        b=LJG9bRHYHRs1ikMdhEuv/+F2Oxqi0k0yzSiclX/q7psXxdO7v68RRpZhnUDUCvI4gh
         avfHfP3Zm0FVyqtJg97fZ5l8A1kyV9vy1IoJWJYCXsgrocspzk7Y2z5TPUlHeOo4xbFh
         nnLg7EDAQuynOyLsuixVHxHST4SMESR5GRTQ0vO+4MD/aOkvsovwulez9cg4BheBPcGU
         Lu4W1bFdNb8rjXgzd0Ueb98BBcdw7eRhk5HppsUPoI4yTZYL+f5i7avcn8kukw+8tTag
         cUST3LVXPRGL5dFNn5wZQ37HlFLa0IsLitz+i5WxiRlh84vAG7/GFNeD2eDMRVd8sQrD
         tuqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=g4f+/WfnZkrMe/HqGvZOb2vGCvbeoVKA+YRTcEBLbjI=;
        b=KuAX/gHPu+djCwqELu1VYxUG9LBbwu8BlZiTqhuycfJZQrCfmvW9e1PO1j9LLSRxsa
         6wTnFY4ZqTgOm7nnmwbGDkRMeoswbzGWQcDtFdJlYq2NvnL2RQxmTEZWMBDJ/6GSxTtD
         65hGNg6MUx5+gsidGtLhzPRoL4IfciwPLXe58SwjLEUnVGMuln1X/XiJp/eDshnLHoAW
         xcMZpCd69mQTCXLy7ajDPrWQbfTGZn+G0SRD+1DGPn5nKfI99YROm1KucDiE5wCffkTp
         3O2blT2duVXVc2ccc82YsfAlTzbF7XBuxoPOikicgEyvBV7VSGsLoavy25hebpnjv4Jm
         C8QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OFCQVMh5;
       spf=pass (google.com: domain of 3fsk2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fsk2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m3si496436wme.0.2020.08.14.10.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fsk2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h205so3547669wmf.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:26 -0700 (PDT)
X-Received: by 2002:a7b:cd97:: with SMTP id y23mr3561956wmj.21.1597426046055;
 Fri, 14 Aug 2020 10:27:26 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:43 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <c36842a403be0fbf3dd63b16a7cd231ebd6d4d5b.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 01/35] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OFCQVMh5;       spf=pass
 (google.com: domain of 3fsk2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fsk2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..e1d55331b618 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c36842a403be0fbf3dd63b16a7cd231ebd6d4d5b.1597425745.git.andreyknvl%40google.com.
