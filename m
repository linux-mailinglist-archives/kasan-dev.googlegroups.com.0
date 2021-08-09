Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVBYSEAMGQELOFWTXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CC4A23E44C5
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:54 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id bu41-20020a05651216a9b02903c171c5bf72sf2659771lfb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508354; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZAQunzkimu4yTOMCYllQnvCeZlls4hbUCighgKOoUuZPd7Je0ybFlwdrBknTLPlWK
         7Qv1jNS44QQJo1tnCr5Z72I9E0mX1Gd0v4EeiEy4I6TybMoWzKxGBcRRldF6+Yc0OLC+
         bEu4P75wbEFKF4VjfcUJti3w13keVTegqzCweWqQnfcylTAD4+uozHDCUpCuIJ23V74t
         AF1Un5UnXacWUBN8Jy8RH+tBmS+cr6rRz8TUKu9EszjMx6nHQr8BVAnoLuv/35DaceLY
         PTktQ2CbI0+ldQOSiIaMu8Knee6Ws6yonx9ZQsgrZsNKrnX5BcPhRo9eOuNF5KzMB/gF
         nDZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=20RRxKouCDNekmhKKJhrX6vArSqIIqNg1qV0Fla5MBk=;
        b=Y3BAfVHa/UU6Djx0jEr2p7gVibfBAEF+Szs3VJ3KMRDSFNjfJ9NMsh62d5fhMUGFg9
         /VbQbU5BgZ3PqR8gdtzAvhI8Ka94SU6rZWm8nvl0wcs4shdKX4VkLeLVIl856QL4p0Ft
         SgvMQkN6/rBT4P8cUm2j/5VcsbfxesNdt0WDTsgdFh+jufB5v9qTlzLYxdRK5C8axYbe
         TbBeY/fYf/EUuqrElXrp8ATRoFxUGQgXW9y1SdLAw+5jKvJWLPvAj1oY2b+uIKrUIEIX
         apaYezN1yb9rLpUfm2HidsvVdufpaLrds+7HhKSTE4j7eEH79GBRdX9LBHBQxzG9E41W
         4rvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cVbOSapt;
       spf=pass (google.com: domain of 3wbaryqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wBARYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=20RRxKouCDNekmhKKJhrX6vArSqIIqNg1qV0Fla5MBk=;
        b=CY8i7zpc5JY0wuqDQKjOgOOFTuqvYkWaGglX7j9cNNYgF39yCyh11he5EzEWTzwH0P
         2TK2FjqCVZydHpaDre3yOltGPcfdQlZoKzNSe8tcqANBZyW0s390yCcD8y/lnfc9Wdwh
         rnP04rutzzvchUjTp3bJKcMrH86sZuJmFBF2Ec0cP4HK+LScBODiuNzBpqLNG0s1LdZq
         zQ2ug9R1UGz9/D4+2xYCqaBxDQYHVy/DShkrjUqaP8RgiWyIIYSZNqPREVskRJaKo8dT
         8Iu/Os+Kbt2gM1sj19PORsN+omEokbM4lsVIFHPwqwYiX+tsyMjSIDQNk3vjH5WxCpt4
         +MBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=20RRxKouCDNekmhKKJhrX6vArSqIIqNg1qV0Fla5MBk=;
        b=qZf56/lO9bj8khYJ+/L7tutPFkbj0/ODJMav+GSTuNh/0GzQU/qXHxOq3lOht9rEX7
         BbImLPAT6F0Xo/9JcM6socHRXRxATJaHQFMHKCQ3RVEKv2xfjU3kOb0WvcTIt4lXdtH/
         B6gOCxpDmRyENueLPyWmNCCy8Tlr44X4OEgjWT3po+nV4t65C9w0GMrcLJ3QynT2w1JR
         /GruVbuzjmPTu81+YoJbk4eFjvPAd5YxdtTFRqMSCpD5z5b0zdgS1oOOHk79LXNKb4pZ
         Jse4sYHyxm9c6OdHiI2d3wXHvpVzEdPPayvstwNCMuid+EJm+IayVnAz8NoyGwCyi+QP
         OSBQ==
X-Gm-Message-State: AOAM531+Tf7zA3EswgyUsuvc7X+1yEj7NXlhvc0z2YDCvUBxicYR6NTN
	mNwfjCSyNSLOkSRSsYcyAdY=
X-Google-Smtp-Source: ABdhPJzVuAbutE0KrdUyIQLJzHgT9TlSFB8lLc+KUsJmBlt8W75gvP0dggjmImgY4cpbc1mvnwiyKQ==
X-Received: by 2002:a2e:97d8:: with SMTP id m24mr8219060ljj.156.1628508354428;
        Mon, 09 Aug 2021 04:25:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5395:: with SMTP id g21ls10641181lfh.1.gmail; Mon, 09
 Aug 2021 04:25:53 -0700 (PDT)
X-Received: by 2002:ac2:54b0:: with SMTP id w16mr16563038lfk.577.1628508353303;
        Mon, 09 Aug 2021 04:25:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508353; cv=none;
        d=google.com; s=arc-20160816;
        b=dEzWFsIKM4x0lL+yLJQ+py3tgswyM9rVoNJmUVPN3ycKK4D3Pt4hlUqyUAVJcOaqyg
         2fnXjjx6sZHjOb7gRYGOGNoDRVC96oH78SBbx+lnS+DBuQc8MyoFNWW9P8UmFZxkG5B4
         38nusJYHkuvrDKjb+8r+Cp17RgdCnZjyQpaWyfJmoFRT3B1I7tDSkriCHoIG9TceZzSm
         gWslwpotJ3vweozAHKev3thdlF6Jfz90VqbViyZzlssS7R0jv/JxSA8a2wSWo+5TYIaC
         MtQ9Lgemy2ie6dgcEtWvu//EPPGtlbf63S1jHqRi6awJ7/ylHle+OebbGpP22nzJDzZL
         hBTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=P7GOzPu0NcYglTRl+yIv+BtZNtyGAI762LUyqxvjzUo=;
        b=y1a9RnHb2Kor4tGbbz6WufMqGldT1M3k+UO52dZPVxlsb29FUB6AU/LBn6CKJkqKNN
         zrK6ue+fLt37ljI6Xd5Q8kPSYzA2YUh72Jhdx/rdMxzES9zmwBEiE4CAaWP9S8PRtB+N
         8kN1zFmfKganYzqq08kDkxrlEHRZLa+MLI+XY5DRQWw2JM0JlojLOYM4oreUEVdXLFq6
         E+tezoceG6ldaXYoXCHivl1/fiM59Ujm7OMAHHY+xnYJJZpi9ZnV5rcKKmf3HfpkcXzB
         5DFSxxJSIDZmG3XDB1Rz6cdEbuo9sJ+yKJKtr/xjSVuQqQhLHlHCkjd0ILsTqL57T5BF
         Lpyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cVbOSapt;
       spf=pass (google.com: domain of 3wbaryqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wBARYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a21si783478lfk.12.2021.08.09.04.25.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wbaryqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id a9-20020a0560000509b029015485b95d0cso5269249wrf.5
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a7b:c106:: with SMTP id w6mr3129102wmi.152.1628508352701;
 Mon, 09 Aug 2021 04:25:52 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:15 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-8-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 7/8] kcsan: Support reporting scoped read-write access type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cVbOSapt;       spf=pass
 (google.com: domain of 3wbaryqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3wBARYQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Support generating the string representation of scoped read-write
accesses for completeness. They will become required in planned changes.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 8 +++++---
 kernel/kcsan/report.c     | 4 ++++
 2 files changed, 9 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index a3b12429e1d3..660729238588 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -210,10 +210,12 @@ static bool report_matches(const struct expect_report *r)
 							"read-write" :
 							"write") :
 					       "read");
+		const bool is_atomic = (ty & KCSAN_ACCESS_ATOMIC);
+		const bool is_scoped = (ty & KCSAN_ACCESS_SCOPED);
 		const char *const access_type_aux =
-			(ty & KCSAN_ACCESS_ATOMIC) ?
-				      " (marked)" :
-				      ((ty & KCSAN_ACCESS_SCOPED) ? " (scoped)" : "");
+				(is_atomic && is_scoped)	? " (marked, scoped)"
+				: (is_atomic			? " (marked)"
+				   : (is_scoped			? " (scoped)" : ""));
 
 		if (i == 1) {
 			/* Access 2 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 4849cde9db9b..fc15077991c4 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -247,6 +247,10 @@ static const char *get_access_type(int type)
 		return "write (scoped)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "write (marked, scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
+		return "read-write (scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "read-write (marked, scoped)";
 	default:
 		BUG();
 	}
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-8-elver%40google.com.
