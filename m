Return-Path: <kasan-dev+bncBAABBKNH3X2AKGQE5OU4ZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E8B291AB0D1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:18 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id o9sf6080528ila.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975658; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ojr2f0S5isBNNtzZ5vlIj2BDFt1cx4V0tB3DbKUdehPLr4fmhS2/4w1xGwZLk8RUJP
         3hFz+ZIyqYjjo2YE3zga2NWAx0BlSqYoabit1vRWgwAT8j3MG7qZI6PY5WbKMFkRe2kb
         X3OeqaEs3Mlu+L7tD+Ab9LF/r97L/E9JOonJOZZRiEzPM/le2+ZUTLNEgxG59ZO8jGNn
         QeEJf7++QjSJ9f5lC4RxEgeDKBeb5lbrbQ7ohHJjjIfHy/he2p8NZM5byOypasnEYS8I
         bDJ/GnEEtkmZJkErMjn6U8lQHT6ZK+9Hxz4TnrGW1FKKETs1AihRp5SjXVY1HyMi+bcT
         ht3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=yNS0SBNRqQJdo1Zyw1cLdOf3hGBEPhIwSwJTthzORTA=;
        b=V+3n0Zdi7IIasNRnqcuJUeLfJl2RjNInb3KAj9gCApB/ASXc6BYOmbifcgwHpeHX28
         FeXKmXEiFE019F3b0cbmg5GsC6Jc0uAQXh+RH/jJrsmelMwW6KEqGO549VepcJaFCNis
         ZZaTp0jJ4T//mcR2hkQy/pDrecCRtX/lEq2aKQMIMDS/AMcCGAsJzScH5yquavldzXLW
         +vMymU2XcjMjIfeSJIoVOgZ7VUkwNbykknkZuOpKWJKrwc5aTRqptwudDwVpPQhY4Z0Q
         Uyfh5vm9uAZuQRt6LwpkSvQCgRJ+tDwmku6a+dQrEVsnFhyeUC+tw6bseOEmIXgM9ZBx
         SrGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BH0Q82AX;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yNS0SBNRqQJdo1Zyw1cLdOf3hGBEPhIwSwJTthzORTA=;
        b=c7/upIXBAme/yGoLVlgl7cvYdGiq22Pg1OvHsFUzIzDL9uFHEIqTujeXu5k0hcszvy
         uwlCBUZjKUXxUQ5tFqCyZ9u5EBKC+sDy71yyqzzVPFptsBwz5capBqqTRRp2J6tIE+0t
         mNyVZUSp2S6sYsSvhs/eEFhJ+641y9VI+3/qKJ3REW+KWW/51G+45mr2DcqjFfLj49Wr
         zMdkVIM5FxhK+nfIVQnQtUS/2GpTTWDDiMUTcUCDmmdpLOq98RhRJ/Y/TkBggi4gRvyj
         ZdobdxUGMysTO4jsOORclkzQKCkvYXwAddkQ2enncpYNaejgBsFfOQynT+ufz+UWONv5
         b/gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yNS0SBNRqQJdo1Zyw1cLdOf3hGBEPhIwSwJTthzORTA=;
        b=KZRKnk2g+1fvfR18z98o5wR9VD5JzGCjKbBuzBsiHmZe7yaR6VXlPFQoJV5pS4bUj0
         TQmBML9o503xYFsh0/viYs7WkQPXBi8QW7sZH8wXz+j+UlIf901Yqw2HEOu4fEXz2S+z
         B+PMplcMWxFNvyg58oLV4mIapl/+age31a2eIAiwabXllPCp0a7oW06cUssdXjjcyhDG
         9qMjoUE37A28ZRBijS9modAwZ3hYy4aAfvpshmx9FTIc7FzBistqEvCkM8lg1Hn89Ks/
         D1jSu/Dw1YIXxyyckVGzltFsry+sfoVtEjdNZ9nMMazm4YSRTB/0xD5Iv5+uGCKFnGDe
         dcQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY0oZGE0tCaZEIujOkIB9ieBOA2SsHW4JqPgKLZHD+AwJkHgzS5
	vEnjb2N5NN1i78/zgkqNtfk=
X-Google-Smtp-Source: APiQypIekebQgHbFMke3dC8HVEF/UKluDlnAwTYBLIx6jwWqvYd5mu7e04ebGVkDWHbAV5ULbcwmew==
X-Received: by 2002:a05:6602:2182:: with SMTP id b2mr27062349iob.19.1586975657882;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3d10:: with SMTP id k16ls1351089ila.7.gmail; Wed, 15 Apr
 2020 11:34:17 -0700 (PDT)
X-Received: by 2002:a92:ba46:: with SMTP id o67mr6770966ili.66.1586975657600;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975657; cv=none;
        d=google.com; s=arc-20160816;
        b=E/FlX1giN+wYOzuo+FZA8WFZT1Hjcehb3BWMLp75PNU/1VXmr0mex9WT35DZb3FhfW
         P3klVAnYKgA+vrL2PSnN92BbM3SXCj1tNOj7bm2fZwDAkeF7tEdJYPAskQdDT4a2glih
         rLJLmlCTDxyhsYu+OWdfhXjRa8mPc1QY7AqFYAISaw+gvK+b0LpsLaYwW+9h+z9gOxZo
         yhceEBaewztATPEY509orhMXH7hzAa64HpUJiA1LEZKEa3p5cV8yRj877q567YLcQ3vP
         dRSS1CG/F15jy/8wP8ZCWSB1ZX4YShzyFDb2LvkDsGYLVqOHl0yrgxlO/DuPO0QoIO78
         16/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=h/fZ+ii7/JA1RITYMA8XJUi2zUgJL9iGc1bpY2h/+lc=;
        b=ZkzrBFOC3z4WLQSmJfqdpsXQzCkSOTHQVNP+2xXoMXnhBw/oqo6xgqX2eCTn+B+kzS
         4e1aTOGx7ffzeoHh2NeKZwL9af1Nx4yBpgJBxI8M38lbkNBcylK6Zjn6YyCrgChtB4lK
         tUHImVyoPjhN342K5TIk65EYEUCBH3FhGQuOBzT64klFkrkALzKAtvhfp61NJ8OhIEp9
         D+Itj0LOnrlOlLP7k8t+KfcUYdaig2yzRPV/WNNp9hPmEl9kelL11kFubHZeSdtGcI5X
         MqhAIK+eJR4ih5/ZnKWGe53xnDk5FWUJFkRwtLjRnMPeetgfbbXA4ffih4GLWxtOPnYW
         QkFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BH0Q82AX;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v22si308361ioj.2.2020.04.15.11.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DB9082168B;
	Wed, 15 Apr 2020 18:34:16 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH v4 tip/core/rcu 15/15] kcsan: Make reporting aware of KCSAN tests
Date: Wed, 15 Apr 2020 11:34:11 -0700
Message-Id: <20200415183411.12368-15-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=BH0Q82AX;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Reporting hides KCSAN runtime functions in the stack trace, with
filtering done based on function names. Currently this included all
functions (or modules) that would match "kcsan_". Make the filter aware
of KCSAN tests, which contain "kcsan_test", and are no longer skipped in
the report.

This is in preparation for adding a KCSAN test module.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 30 +++++++++++++++++++++++-------
 1 file changed, 23 insertions(+), 7 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index cf41d63d..ac5f834 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-15-paulmck%40kernel.org.
