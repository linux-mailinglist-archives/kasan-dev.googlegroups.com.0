Return-Path: <kasan-dev+bncBAABB7NZ6SMAMGQEQELSAQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9441F5B4AD6
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 01:25:50 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id q5-20020a2e84c5000000b0025ec9ff93c8sf1446813ljh.15
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 16:25:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662852350; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pau0zppmf6tCinP5JWYUn8BcqMth/L72K70gndeGRnPbwR2EekkGvHliIGNFY53bv5
         zMw15jWMT5M9sN5SniHUl7jztoLJ7eqYXZGyZ1F9z8YM/ZCnmuJnSLb3t9gfy00txUOE
         9Zn4Neu90np7bDzC7tiACIrmtLX/2nTKyzQuLwXehlx9vz/XfT/dtSF53L4mcjmy613Q
         MUKX+0UD2s2BVnWr86vBKNoKH6qzn54QFuuXT57mc05ORj1q+nNJjE3gDtoiqIWuNKgD
         otO9NNc3tXUgtZ6IvefIDIoaEb6bdwdNzLfsVKoktWBssY/0rrBuxGaBjJ0e7XxUZVnr
         vt+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E3FYrJ76ggD0DoeQZOWD6GIIh+r1ml/aQ03/insZD5Q=;
        b=RrRAs/F9VaC7vc5W1i0Gc7zEAgmZnvUqDHctVZtV9MFeMxvcvOmeELoyTlUnlST5to
         mAjduh/a0eQKS5na/BmJmDGgDjT6Y3X1rgsO6C1tFRJobxfhkmV7WKUrxHyjMsireFEe
         zO86Qj96Ool6NpLbHgNGz1ELZZBoeakpHdQfREWcYB0Gmc9X3Q+q3GTzaB6vgjxHnhKt
         lJdLbmFKu89BMlR7YD/0hqowWcpo/wHO0eT1ZjCOxLEEyWrkjOYqU17xtst3sNXpXyPS
         6ihYsh1kd97uvviqfBioEYv2+U7aLmHGb1Fv7Sw6vFzAk9UWaBZRfbA3XLFY7DCp5xCe
         7Qpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LvJIOhNP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=E3FYrJ76ggD0DoeQZOWD6GIIh+r1ml/aQ03/insZD5Q=;
        b=YpPCRVbCQ+UTyMTPGSn/CIf/omjw7lPKAKqyvBB8c69JqLCt/F0UcN48n6u5bXpOBw
         imf4i3BCQ0lk31RDe2oxjshr5DMlkOe1TZeY6bCb9cmkCcPvTPpizFTZyITjNtvVpFTb
         JgnHqhNnoxGbsb7hyC63GYO+AkgXVIoaR/G98ONzEg8CVpyS1SjA/8dp+83j6xhxzAP5
         YOrxmW19SH7Ud4XVBN2u4Tj0s5ckaeYFjm2CjuSXCVuob5T2ikDQegQSIM4FpmR1ueba
         6aV3sjow08c1W5XqorOSAiqqaom7tB3Zw49W6AGJw26kQ39R9/Dr55L7Zud9FK+b3/Nw
         pp9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=E3FYrJ76ggD0DoeQZOWD6GIIh+r1ml/aQ03/insZD5Q=;
        b=AGQf/UWY+rFwimUVybfsS9lS5ywLjOPbA0aFe57fX5r4d4sdeUjcaS9Wn/9mFaU4iN
         uSvZLVzI+xydtIUY+XACvrFc2DcD5WYFsl2KAHj1mDDVFRPCQC8Duz+WK6Be+UZcBIlO
         T7zAHrUmhfpadm3Vjqylu5wk8ReXZ2yyFY7c8cbQIIi8hAbY5rsude782vv+H7rpML6f
         og1bToUi19Jox8OTwK7nrrhAjYjm8XFWdNveYcO1noaUcQstN9gIWn6Trip8cBcxsZEx
         ZiabQ0wF6PMxg2ri8SyLoiSNK4RnxSdlVEwPu8N/cPU7T62UqQvs8/yyyvo4mA2JES9Y
         NqFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo39NQqiIh51LvNkefEGzPwqRt1pi+pDfTqS8Lk6OkSyVdqPNHxT
	CoU9UPCXl75qQi4sPOGMXKk=
X-Google-Smtp-Source: AA6agR7P1K5FNyYMjWWFR0NEXqx56pBX4yOpt7UuA1lx1RcpB7C1FX901jQY0Zqv4UrbyNBOCjd9Zg==
X-Received: by 2002:ac2:5469:0:b0:497:ed1:97c6 with SMTP id e9-20020ac25469000000b004970ed197c6mr6079205lfn.248.1662852349666;
        Sat, 10 Sep 2022 16:25:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3602:b0:497:a8d8:d9ad with SMTP id
 f2-20020a056512360200b00497a8d8d9adls171396lfs.0.-pod-prod-gmail; Sat, 10 Sep
 2022 16:25:48 -0700 (PDT)
X-Received: by 2002:a05:6512:10c1:b0:491:4104:cf92 with SMTP id k1-20020a05651210c100b004914104cf92mr6805241lfg.211.1662852348759;
        Sat, 10 Sep 2022 16:25:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662852348; cv=none;
        d=google.com; s=arc-20160816;
        b=M0V8nhQKi70WVBqjvSgVlQ8lVV+j0SOjxaUBpLt34PLuZIQlB0vZ0cU2qydbbrZ1NC
         BkBlAkKiOT6fY5hXYtlxDMuytwqoqe+0t4UqHsBKnAF9d2bGLUUlIPTT7q8upoVZZeLP
         w0x7jhQI9dLG+86PfIdH1Zl/PLZQYaLFL+E200KEl6okh2/eDRVSo1XA9fFmtK6XbGKS
         GMewO2KDcztRSY5iJ0ggqbbQySpWsedlq+n454I9CJCcIy9tUphs4DUrWbbU758f5m2l
         aYIq7+Zkt5kUULmVsXzcOD1twg8SxEz7gYjZAWAAE1IFS1evVnhI+E+nsd7N0fJSrCDj
         3zrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=IWRb6xubtC5pF+wzMkdOEJAm7Xvs8Cx6RhZM8IbyZTw=;
        b=L1qvjfxb4zp9DJph4BdTEassMw5bKDNsnI3FLjFaPr/T564KLUduO3KbfuVpm6sbV2
         EaENyeATky+uCIbDGZ+sIvCy65N2A4RcvGTWnndKUYJn8gFqUXSIoYn7WpIMRxe/EyRl
         H6XtJ7M31jnWdI6Wb/PsB+Yvfv5YnP0OUAHTCTpigUem7plQhBmUWj67nKXT9fiiIsGa
         Mh/tRZKt6Pp7AEhhl9eG2HYnCXwo1QlV1/8WWhBGMqxPygV/PgakbWPJgHVXlYsa5t72
         lJKTJAJDWsGXFzUOsiEmwivqyq7b0FsV1QtEAecF2vqOgfXPj0r0t4CMVXWSRUTw0w66
         8vGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LvJIOhNP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id a8-20020a056512200800b00498f2bdfdcdsi116275lfb.3.2022.09.10.16.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 10 Sep 2022 16:25:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: better invalid/double-free report header
Date: Sun, 11 Sep 2022 01:25:30 +0200
Message-Id: <fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LvJIOhNP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Update the report header for invalid- and double-free bugs to contain
the address being freed:

BUG: KASAN: invalid-free in kfree+0x280/0x2a8
Free of addr ffff00000beac001 by task kunit_try_catch/99

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c         | 23 ++++++++++++++++-------
 mm/kasan/report_generic.c |  3 ++-
 mm/kasan/report_tags.c    |  2 +-
 3 files changed, 19 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 39e8e5a80b82..df3602062bfd 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -175,17 +175,14 @@ static void end_report(unsigned long *flags, void *addr)
 
 static void print_error_description(struct kasan_report_info *info)
 {
-	if (info->type == KASAN_REPORT_INVALID_FREE) {
-		pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
-		return;
-	}
+	pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
 
-	if (info->type == KASAN_REPORT_DOUBLE_FREE) {
-		pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
+	if (info->type != KASAN_REPORT_ACCESS) {
+		pr_err("Free of addr %px by task %s/%d\n",
+			info->access_addr, current->comm, task_pid_nr(current));
 		return;
 	}
 
-	pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
 	if (info->access_size)
 		pr_err("%s of size %zu at addr %px by task %s/%d\n",
 			info->is_write ? "Write" : "Read", info->access_size,
@@ -420,6 +417,18 @@ static void complete_report_info(struct kasan_report_info *info)
 	} else
 		info->cache = info->object = NULL;
 
+	switch (info->type) {
+	case KASAN_REPORT_INVALID_FREE:
+		info->bug_type = "invalid-free";
+		break;
+	case KASAN_REPORT_DOUBLE_FREE:
+		info->bug_type = "double-free";
+		break;
+	default:
+		/* bug_type filled in by kasan_complete_mode_report_info. */
+		break;
+	}
+
 	/* Fill in mode-specific report info fields. */
 	kasan_complete_mode_report_info(info);
 }
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 087c1d8c8145..043c94b04605 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -132,7 +132,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	struct kasan_alloc_meta *alloc_meta;
 	struct kasan_free_meta *free_meta;
 
-	info->bug_type = get_bug_type(info);
+	if (!info->bug_type)
+		info->bug_type = get_bug_type(info);
 
 	if (!info->cache || !info->object)
 		return;
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index d3510424d29b..ecede06ef374 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -37,7 +37,7 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	bool is_free;
 	bool alloc_found = false, free_found = false;
 
-	if (!info->cache || !info->object) {
+	if ((!info->cache || !info->object) && !info->bug_type) {
 		info->bug_type = get_common_bug_type(info);
 		return;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fce40f8dbd160972fe01a1ff39d0c426c310e4b7.1662852281.git.andreyknvl%40google.com.
