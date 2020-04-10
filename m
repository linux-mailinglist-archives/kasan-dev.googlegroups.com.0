Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46EYL2AKGQEBY24K7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BCC621A48A2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 18:44:35 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id j22sf1494088wrb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 09:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586537075; cv=pass;
        d=google.com; s=arc-20160816;
        b=MtWjTmx52fBmfoNRDIqx/dEqkEEJXhWX9lYJsZOGoidqbVpmwGsJ5qCV8iO/cm5qSm
         /tECalB5ZhkZa/nG4X43AwCPlqyhzbgvS6SN8ahQE3BiZJOIk9ewMrRfvaclXOvJtcmb
         p+0Cc2N7oYgsVn0Az6Fk80svgRSDvCw4PSJ+2/UHCPs3tdMBwCoWz/hKZlr6WSXxNdf1
         TbLRSsAJmwtOmEptbDBSFomnWlsPETPMXnEDgPPKdpqS8xeF+ZRkXfqJCqKyenWGAHM8
         zlIHtqbalV/oAJXaJBpIcJwo23q6iLJ6R00kCueO4U+yKhuEYfsWK250jH/EDVK+lubf
         iDoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=br2Uv2zdCSZyJAx7a1YAVshGqX6sxheChNpJPzXJ+BQ=;
        b=A1PL86Ix+hF78A2Mlz5vbd6BPRNgypbDye7RF4oTbTKOhn++BLx2IQX7+3UJZV6RQB
         PlS4jW8iXS2EIhaGCSosFqVPDhgVQ0DvpyRvODpOyqMb3641YPPA31VTjjcrpJvJtIP5
         clDA5MtHWI6cmbd9APIjciNzC5Q56PLP7jJvpiHLSIoGRtaIfli+j+NLLU4k9d3r9Fqz
         FJGClY3hZ0Gkrql38YPU/eMznPpyQ98AAGgcWfgoJ2rlEsKbF31ueg6V5a75DZSDH8oi
         SwPnDAh6c+X+UinK2oZH3vBnGBHaWCGlniGtQklSxBfNBku+ud79l9yN0FxDW0mSR/PG
         Aesg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KQyOuVLH;
       spf=pass (google.com: domain of 3cqkqxgukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqKQXgUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=br2Uv2zdCSZyJAx7a1YAVshGqX6sxheChNpJPzXJ+BQ=;
        b=V0yq39K8VHlcv2wYDOWf0kuOTiswAu3hg94DJIdiBlHeQiiGsqhc4nxMcFiKX3t2vH
         Eh+6rxImqx2p0/HkwTeKVT2x/PA9iJwIspK6rzJTG6EDSxtgomsQHK5ikwuol6F05FB1
         TxXwCED3C0sjptU522pD/TmRVa0zvOBTTaquQWMrnm3sLuwWDSz9bJKbbTN4Ot/f8url
         4RF9rgJKkDlr8bRjQDLaD80Vn9pSS0XTN3fq/S/yapS8SE3wyFyeFsHXmFpYWO+11Nhz
         evNDmp5txRsZUOCSngv9xSdX0fDmQXtxGlN2cXKBlnUcSktQFryO8gC1QNt7gmbkqmjk
         wVxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=br2Uv2zdCSZyJAx7a1YAVshGqX6sxheChNpJPzXJ+BQ=;
        b=e7I4L7EL/7GMd1Cqr3NrSH5ZpaxrQu/JIUiiq+FB8qIaM6zygKxXfASpJSKLQ5wv7W
         Yj/RfMlDjt7Kc3ANbw9jclgRqXYXkBg0ikAskZuS5UukkRIe9j/2H3h6bRViGXqpWVEe
         scSRAUGoAsQuY3SlFGwrZCcKeW4+E9Bt4cbEzPxRvMuPxgvUY/G3iZuoZC0BjkkSTriu
         DKu5Y/XFUPuMK2t92pxRX8whUHWrNLBy9bUywX/2fbBKXHWaD20DtC0YMhTJvgmzO+f8
         uNnnKZmonaKZgibCAFG9xpsLSFQzr6yJGcFUhZ3GQvpE+9cI3mKawxjfCDHSdnlFw61r
         h0ew==
X-Gm-Message-State: AGi0PuYyEfP52Mxtky2xcTnQC3DZebpZXy4/WRLre4o2nl/Ke9R/AuHW
	nP3zAUGbIyYzTiHE4son5mQ=
X-Google-Smtp-Source: APiQypI9IWobfYGk3LUqRnDNiFG8wIkFBF5T1bnAlZENzoT/f9A9DEkS/aKUlnlDNhYYeSouz4lqBQ==
X-Received: by 2002:a1c:2d95:: with SMTP id t143mr5949057wmt.89.1586537075467;
        Fri, 10 Apr 2020 09:44:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:42c9:: with SMTP id t9ls4148881wrr.4.gmail; Fri, 10 Apr
 2020 09:44:34 -0700 (PDT)
X-Received: by 2002:adf:e9c3:: with SMTP id l3mr5818753wrn.229.1586537074784;
        Fri, 10 Apr 2020 09:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586537074; cv=none;
        d=google.com; s=arc-20160816;
        b=zpMZFnrFQ4U6PVrUgSbP5fl5+BVvJjjefwubtlPRcCL1ZnepTFcXfM1GyXUjWgBr8j
         yMMZlWKKu+0Cd4H+wAVjR0DFqpu8eSfk+ruBC9DT5BtLcoZuuKvIE9itsvae8DBvhnDw
         dcDhvjuWvOItw3gbsEDGzsHnxbPqplkH303GQccuvIgJ7OzxC0pyTWZ3VQCfxpq5jBDK
         /nlbVe3/SJJzCAvIFA4JCE3+u/OoNRgvjW6wE2zbPFex0d5JWwDgASdszOSAeDtgqDSl
         IFOZ8X8VQMjqX+pYciVRzSTCpnWtZS5pFIhY5MxQWsHGzujVKzOlhzz6cAX2lcAC45pc
         00kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=jktZwzpJNVLsGLy9KhviNEQJCLl1FlOOKSWLnXPYqxw=;
        b=GX7rNTG85bXiHGvK12ER1o2sinXcHwaWrQZ/jNThGjAgktrNyii5GUz0LJ3ZyXTzsg
         BhnxBLK/Z1CWVIrstZ/0BXfh6FxjTgVbrcVo1lrRc3WG4e/1oVYyk2TrATr537lB128h
         r4kbYkJtVbVl9+atuHK/bBMBWgQMWkSzzMiL3jY39o+snPzLqeMWsMXreH4iGmqu2+a0
         VIyVLavOdkSrQWNlY14hXzz/Z421AvusZGnsFm4UeEyVL05FFLDb/kfaI7gokddP7FlE
         8V2r3p+alXfe/HOuL0MzQl1dcG0zbjx2OShmesmI6WqsS8iItKQZwLtPsYtMRvEkOehw
         iMFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KQyOuVLH;
       spf=pass (google.com: domain of 3cqkqxgukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqKQXgUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id l20si158065wrc.0.2020.04.10.09.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 09:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cqkqxgukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id b203so848680wmd.6
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 09:44:34 -0700 (PDT)
X-Received: by 2002:adf:aad7:: with SMTP id i23mr5391553wrc.184.1586537074302;
 Fri, 10 Apr 2020 09:44:34 -0700 (PDT)
Date: Fri, 10 Apr 2020 18:44:18 +0200
In-Reply-To: <20200410164418.65808-1-elver@google.com>
Message-Id: <20200410164418.65808-2-elver@google.com>
Mime-Version: 1.0
References: <20200410164418.65808-1-elver@google.com>
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH 2/2] kcsan: Make reporting aware of KCSAN tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KQyOuVLH;       spf=pass
 (google.com: domain of 3cqkqxgukcfmzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqKQXgUKCfMZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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

Reporting hides KCSAN runtime functions in the stack trace, with
filtering done based on function names. Currently this included all
functions (or modules) that would match "kcsan_". Make the filter aware
of KCSAN tests, which contain "kcsan_test", and are no longer skipped in
the report.

This is in preparation for adding a KCSAN test module.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 30 +++++++++++++++++++++++-------
 1 file changed, 23 insertions(+), 7 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index cf41d63dd0cd..ac5f8345bae9 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -262,16 +262,32 @@ static const char *get_thread_desc(int task_id)
 static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
 {
 	char buf[64];
-	int len;
-	int skip = 0;
+	char *cur;
+	int len, skip;
 
-	for (; skip < num_entries; ++skip) {
+	for (skip = 0; skip < num_entries; ++skip) {
 		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
-		if (!strnstr(buf, "csan_", len) &&
-		    !strnstr(buf, "tsan_", len) &&
-		    !strnstr(buf, "_once_size", len))
-			break;
+
+		/* Never show tsan_* or {read,write}_once_size. */
+		if (strnstr(buf, "tsan_", len) ||
+		    strnstr(buf, "_once_size", len))
+			continue;
+
+		cur = strnstr(buf, "kcsan_", len);
+		if (cur) {
+			cur += sizeof("kcsan_") - 1;
+			if (strncmp(cur, "test", sizeof("test") - 1))
+				continue; /* KCSAN runtime function. */
+			/* KCSAN related test. */
+		}
+
+		/*
+		 * No match for runtime functions -- @skip entries to skip to
+		 * get to first frame of interest.
+		 */
+		break;
 	}
+
 	return skip;
 }
 
-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200410164418.65808-2-elver%40google.com.
