Return-Path: <kasan-dev+bncBC6OLHHDVUOBB5VG7SCQMGQE73QY6BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 013E339EEFC
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jun 2021 08:51:37 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id g22-20020a056a000796b02902f0483fd9e4sf2511708pfu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 23:51:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623135094; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxasptZMxg2GwK/i+U6dXZJFbjfAXY7cSKrXEvaPFLLZlxsRW2DEQQcP9uwHc4CNzK
         p7Grh86By+X3Laf2cww2dTB2ItnfcBJkndYPhHo8EsSip+pvxCNm1zvlmPMvmFyeqSk2
         fGgAg1PEe9fPF2IJWGO16zfuA75sK0TY5RjXeHlqkF0RPJBwhuJJ+272wK5u7LQfPeF3
         CVaCyXFMCkyb4ktHHbDM4X9nrQTjGRE7hgrUl81iRzblIRKif62GCqKkgC4HzzaFXWR+
         Fq7+foE/jiWdajaqy2WteYR8TcIC6xIaZMGyHECImNkX5lVCAB7VdgL9FzqAaAIwpfQa
         vrFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LP/RAwgWrCvDuu8NHLN2dHESHFRsAbZ9H1SfafcrmGY=;
        b=DqEEpEQHtYsQFMIdcEFEd2JA70bJiG+6Dy9viM4qdZA3BqYiFJTGgsT426kyJ95ng5
         AOvhIUyREdoDE7KgYHCvQdznQ5DX/eE9IFyQVZD9CvPS2pnYmQYDZS8iyeujrdvoKeGD
         9ZbnKRslAfrlU5P+TP5UPl28KhOk4iUyjIn76MnjMzwZQN8qWRD81RNVNURr9WtDW8dy
         zT2VtLRqMhg3CZaZWSMUOrgPAQOiNDBc11y9fQslNsBXCMYmN9mleiT8J6p5D9lrLdVl
         9NK7yLfKpy2JzpU3JPDDBczOPdvEDsbIuwbpyAIuUjqPL2glfpIT6DDHcXti7hUXYV4M
         11PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TVpKZCnU;
       spf=pass (google.com: domain of 3dbo_yagkcamgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3dBO_YAgKCaMGDYLGJRZJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LP/RAwgWrCvDuu8NHLN2dHESHFRsAbZ9H1SfafcrmGY=;
        b=rZQSTVG3hYTGiaR6IFhIwHd9iGTE5bNqiWPfU4KL7VISZPVTbbXg96B9Ybmjzb2gbj
         sZrfwPNurxZe1hNueOcRcNYjc8FL1dl7Zf1q+4EUYpJJUVjzfyWq9ompi5hbqBZbrXJX
         bnsevfFELWi0gJEgTYGPpGbltL8Nndz3VEH0QjEJHfMYV9JUh99Eu61IZjWPfMHRjTP+
         mrx8INZ9l/UD4L8o362VCpxWAfOni9L8fPZWvwZ/+UGl80L5OM3ca/aJxI8bZrz1etdc
         5a61xOqN/5qx3cXTVHA4bCTDDHDSBrYeurfxVAyVWgf7GQO0eMKiKDD95kzzwTm0ZkMn
         cW3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LP/RAwgWrCvDuu8NHLN2dHESHFRsAbZ9H1SfafcrmGY=;
        b=den1GTWL4jGnUvw/B0r/LtVEVa2SSNnkADC4awrgWN+dmZFiVBDtec1kyhUaVLZ/fI
         ihlgVr/ks/Y8C9HXbGqadiGxpy9cL+4EzURr6xecEXF0VwiB9JRRhcjX+B9LWXie7d1P
         yBafTX7OtR2WlucPrAYIl5reb4z2tZuBlR3b2ewBkFyAZvoCLE8QgHgA7B5nLs+FbjqA
         pGB5ye7OPufc7k73lct8/0+SGXMKTXbWOPwOAJBrFp7LDBunU6P+8eBP4o4z+HZ+oNV5
         wQtERmy3R3s2i5oSGqjXJkBuOmtLp/Kq7uqlNqFZKp6kMzeMofXl6Wryn+G3mk4G+ZYN
         Axcw==
X-Gm-Message-State: AOAM530eipSnI1fsYmvl8VhAlI9Ceon2zPIp2jirnKcSZ7/s7R+VwbEh
	ShmOK8AWi63v3KX0+rYSSqc=
X-Google-Smtp-Source: ABdhPJwtr/oGRKPLS2XDy67R+EZvst3RB+voc1987KHaLNA3s5UpExivIx5cPJlJxq+zjsfBQCJ5dA==
X-Received: by 2002:a17:902:ab95:b029:ee:f899:6fe8 with SMTP id f21-20020a170902ab95b02900eef8996fe8mr21559758plr.81.1623135094295;
        Mon, 07 Jun 2021 23:51:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b185:: with SMTP id s5ls9891747plr.3.gmail; Mon, 07
 Jun 2021 23:51:33 -0700 (PDT)
X-Received: by 2002:a17:90a:31c4:: with SMTP id j4mr3258524pjf.105.1623135093718;
        Mon, 07 Jun 2021 23:51:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623135093; cv=none;
        d=google.com; s=arc-20160816;
        b=oLH8XbFfnZ07Xxru2MzUmbciV5U1Jz5mMK2ShWnQTEcWhwzWAvJ9QhjX4QF/TbolnB
         XOVqQQc7g2h7I/aAHZnhJHORJZXc80Slq1z0nL9W0iqDpCLe6WonyKD9Pdgm3LjWAjkb
         TVKLsLUgVAAhYW2rcnsBSFwvGq15YyA5Bnfi8fMmTb3H/mzBpMFttLrlkx60OHf3Xcl+
         6seOY1eh796dCHsqKsJ4TQ/LeyhjwN+NfGcEDT6cq5OLhbZ7KhExpbCsxMi7LoJq7aKR
         de0M4w36cOUO2APc/1vcnXNSv0Epu4U4bVVvxoWw3F6vWmEWw3spBcZw97kx7B2f1B5C
         6QIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=el9m4nJm2ABZGSXDbSDzRvh2IOwN+krWXJF343PJuq0=;
        b=UORbAUlf2fCyUPRJjgiqRaCRZWd0HKNhCByS6zyfgaZUm7SF+tGfhacuJxd3O5GRpK
         2yg83btHIjzDac+vztKA2NrsqaDHf5kaqrwegJsWOe3k5oWFuemvA0THrlpEc9O+ik0j
         /RiBadYc9S9CZthHxVgptRJAW2LS1UaIurF8Y1u5SKlyizOvDZuwQyeC3FuvMUmW/vYg
         Y1Q/hKTCOj47Wura7gvm1hALLeWWYdOrcxDI2yNGDq/GgG6IAyW5EcHaS4gL0jNK8ar7
         6dk90ZRlqFcDfe3KRVpzqbTE8PMEC3B0zQzKNITzW/iDflNJ87DNzEql2rrN6kyWsOMA
         +SDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TVpKZCnU;
       spf=pass (google.com: domain of 3dbo_yagkcamgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3dBO_YAgKCaMGDYLGJRZJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id b18si673534pfl.1.2021.06.07.23.51.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 23:51:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dbo_yagkcamgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id u48-20020a25ab330000b029053982019c2dso25574074ybi.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 23:51:33 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:868:b4e3:8c14:177d])
 (user=davidgow job=sendgmr) by 2002:a25:a449:: with SMTP id
 f67mr32854218ybi.388.1623135092957; Mon, 07 Jun 2021 23:51:32 -0700 (PDT)
Date: Mon,  7 Jun 2021 23:51:28 -0700
In-Reply-To: <20210608064852.609327-1-davidgow@google.com>
Message-Id: <20210608065128.610640-1-davidgow@google.com>
Mime-Version: 1.0
References: <20210608064852.609327-1-davidgow@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH v3 4/4] kasan: test: make use of kunit_skip()
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
 header.i=@google.com header.s=20161025 header.b=TVpKZCnU;       spf=pass
 (google.com: domain of 3dbo_yagkcamgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3dBO_YAgKCaMGDYLGJRZJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--davidgow.bounces.google.com;
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
---

No changes since v1

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
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210608065128.610640-1-davidgow%40google.com.
