Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7NJ4SGQMGQELIIP4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AAFB474D80
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 24-20020ac25f58000000b0041799ebf529sf9184284lfz.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z1+A+I9NJO8dF4nT8yxAWlEUh3mbkOrImEkqkZ0dEFqJxFbkPgfuQjbitOZxpGMNga
         ROCJ/Rq3sz3AHX4NRUgGt9f2fPKtLn5dp6iNi7hWqGnfnOAGrRNJJa8XlV3m1evzun8U
         b5YQrT9ji4teLqQ2pQRlLITOC7CfjfNn0dkLsgp0Reffu8cHfRyV+GmcQzGyquqpj5l2
         khZaHWAJQG7HqGp+AX1coFSuC0gp/I1ISbHgQ3ry5J4xrGM/SxKyHwyONPQvI/zkGN6c
         TRm63RPSoSJfwy0SfyI3cSvahuEDk4VJM+un02uK6Yls+8hpj80AEupbNn3dgUS+uRI/
         z5Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QKvOrNzZaUjWM7lu/OimLfdcCLQ7Dr5IREqWiel3mKk=;
        b=Wzuib9pz6IWWBurxNY+qTA4/VZh+aRoYODNvH0ueignHneUvy2CHVqBqz0QaU9BC5Q
         mfGTdLH2xRvie31veF6KiOtoX5XV87gpgxAHUTjtBmpFPjof9m5Ml8br8Z+XzCeESnih
         /q68ykaK2YyIkFO9kMN+MxFB77vHwlvOLZ+PUInDJFTNKftXLVh9GUrjyLy/mfG1G35l
         QQAbDOV5G3X2NJUXFX645TTBO4c+8aBtje74chK5RUgbYzKeDGYBb+s2QhBdzGquI7tZ
         jpaW35orM0BftE3W8l1F7YOtbMegQWMs0X3zUHlpbFzHcaNJjSPtb8IAtvu9bcjCiH5i
         Jhdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jmp3We0G;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QKvOrNzZaUjWM7lu/OimLfdcCLQ7Dr5IREqWiel3mKk=;
        b=P0rq5cmnZo1ejtq804+YZG/8vbt96F/2/cR4kT/cK8xPaNZUcxxwXg/6zpPi2a/bFJ
         +q8KlFOhPuF7NJQxdwx8eb7LLJyayc1RlDTZcU59lkqeHbtgMonuTx1dMtcsTL7e5/Jj
         i5EB98eYEcYOm7rAMJo5rNlpoo8EF4DhoqdQ5+FvUCLFubvrdqnd2bOMAdpZEtF6tEPu
         PnAHPSzNQtHjWZd7bnygFJu28mI8E077Ldao5LGAJvXUVdAKdOiJ0LXlsVOnRQY8yr/3
         xtncWSrDmvBQNv9OWc9aB+ZVjiuayH0C/wBxduOOOiAVmp1ruvUaAd0k9smgt6H4yU7c
         ZSNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QKvOrNzZaUjWM7lu/OimLfdcCLQ7Dr5IREqWiel3mKk=;
        b=QMZY7HFM4etuzm7fNmW5UNv7pezwsMkUYI8VN9gNSWfGU7HHEsFwwXQOjjMLJwTSQf
         q4ml/DtuPPbj8MxCO/eSp1+cFvjJvm8lRRHaVpDgL6TX/V3cpuU6+JESbC+tAMkymxW/
         PuyfEM5UUSOZHlZQsFgDxymCQiThwax7sxr0yhI6QFsElyzXwWcz1hJk0QUb3fk5QtBD
         RHCq90Im5qS2REQ5T2mKR2NlZXQ4tI6QPkJRDN2wQI1LnRbYoBiPONk5RWGFqXIbpYrc
         uE1yz1Dc9Z11Tlbo3cZI9U7nh/Yv6ceeW8DTBbGxRS+ZplRQ6M8gvnjnV8P7voG4Yncv
         06Hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316UDOw50bfJlkYwnX/kugHhYiRYDkZiXjVGRw02LrCJ4QFETPu
	OP9sHi0Mo/LiqSbAh8YD/aE=
X-Google-Smtp-Source: ABdhPJxnwQ/Caei0YqeEVsQNkwdhFvFyhWmMuOlqC+koIGXy0H38GBfh0ZIyBCuQ9nmkfpcq5pwEkQ==
X-Received: by 2002:a2e:b6c5:: with SMTP id m5mr7375931ljo.469.1639519485870;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls100575lfu.0.gmail; Tue, 14
 Dec 2021 14:04:44 -0800 (PST)
X-Received: by 2002:a05:6512:10d2:: with SMTP id k18mr7117518lfg.259.1639519484584;
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519484; cv=none;
        d=google.com; s=arc-20160816;
        b=LsH2+onn5Q2fkpi2eNUwovzzNxWB1Ic+gysrUbIoob1uN02ajAGGJRtXTXf6uC6J/N
         Bq/Wyb5ezF8qwMmT+DU8VWEUJM0vUsC5PTVvCrGXSphKFjYv4l3HUIwAugA5hdElEo2g
         cNmt/usuiOoWMlvzxoFjkjJlVNBrRS9EkM7FuqpT4dM2jRrCvO7WnfL3TrBl4xjQB9P9
         JNeLLUZPWHof5g7vnKyK5Uczw80LCZ/I2F0H+xxWhJ9A3VP8RCIaAGQ8U4BYluEKzbQt
         V2llzOM5+Xd/fynnr04o4D1lFopnL6YQpzQmyydOJQMMVtUgq+N2bIRphJ1B2zInA6HP
         Bwcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BYi+zjfoDuOvqNIEKgdh35lPhGl7HKbDkFfCnDVKpQw=;
        b=wO2D3yPN5Tsrh+Ac0L2E+eFXxyU/u18zOXCO1R2MpIjpVI/jPVC4Q1NylVQXf+Gmt6
         9MQiuagaBTu5Z91vZ0DPaoBpdXqj+8eb8nqap/mZEO4dIuDL20D+mavAkGf7txDdKJe6
         tC6I2+3XsUqMjk3guHk07gRTlvjZkIXwK2zyJqmul+DdrjvojAl9LLL6ZnOKyhyqUecO
         xQVeYHTdkuVLteRFNJ5vvObcOeN8KnJDEvZa1ZT9EbtCMGgl9i1OS3eQhh1D/N692So4
         SsQ7ara/kBlqIyToF8pHFbJ39wlt7S+mfjgL9GuctgZ3EgWKvV/18+Wod87oCr7wtbhb
         KP6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jmp3We0G;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id w21si3022ljd.2.2021.12.14.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1C31F61727;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D775CC3460E;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 66E9B5C1411; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
Subject: [PATCH kcsan 07/29] kcsan: Call scoped accesses reordered in reports
Date: Tue, 14 Dec 2021 14:04:17 -0800
Message-Id: <20211214220439.2236564-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jmp3We0G;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

The scoping of an access simply denotes the scope in which it may be
reordered. However, in reports, it'll be less confusing to say the
access is "reordered". This is more accurate when the race occurred.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c |  4 ++--
 kernel/kcsan/report.c     | 16 ++++++++--------
 2 files changed, 10 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 6607292385880..6e3c2b8bc6083 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -213,9 +213,9 @@ static bool report_matches(const struct expect_report *r)
 		const bool is_atomic = (ty & KCSAN_ACCESS_ATOMIC);
 		const bool is_scoped = (ty & KCSAN_ACCESS_SCOPED);
 		const char *const access_type_aux =
-				(is_atomic && is_scoped)	? " (marked, scoped)"
+				(is_atomic && is_scoped)	? " (marked, reordered)"
 				: (is_atomic			? " (marked)"
-				   : (is_scoped			? " (scoped)" : ""));
+				   : (is_scoped			? " (reordered)" : ""));
 
 		if (i == 1) {
 			/* Access 2 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index fc15077991c47..1b0e050bdf6a0 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -215,9 +215,9 @@ static const char *get_access_type(int type)
 	if (type & KCSAN_ACCESS_ASSERT) {
 		if (type & KCSAN_ACCESS_SCOPED) {
 			if (type & KCSAN_ACCESS_WRITE)
-				return "assert no accesses (scoped)";
+				return "assert no accesses (reordered)";
 			else
-				return "assert no writes (scoped)";
+				return "assert no writes (reordered)";
 		} else {
 			if (type & KCSAN_ACCESS_WRITE)
 				return "assert no accesses";
@@ -240,17 +240,17 @@ static const char *get_access_type(int type)
 	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "read-write (marked)";
 	case KCSAN_ACCESS_SCOPED:
-		return "read (scoped)";
+		return "read (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
-		return "read (marked, scoped)";
+		return "read (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE:
-		return "write (scoped)";
+		return "write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "write (marked, scoped)";
+		return "write (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
-		return "read-write (scoped)";
+		return "read-write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "read-write (marked, scoped)";
+		return "read-write (marked, reordered)";
 	default:
 		BUG();
 	}
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-7-paulmck%40kernel.org.
