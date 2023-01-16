Return-Path: <kasan-dev+bncBC5JXFXXVEGRBAFSSWPAMGQEFXYY6FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id F38B866C097
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 15:02:41 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id n15-20020a056e021baf00b0030387c2e1d3sf20929541ili.5
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 06:02:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673877760; cv=pass;
        d=google.com; s=arc-20160816;
        b=0QFDQ4pBhdIESp04gr8UeIPW3OD+hyDzYdWi8i9l5SVxbJxLEsKGmhwec7215jprTd
         mruQwUj7jFTRCEP+CADBzqqd3Ybf5rK7T1L6fghN9sks0VbwX48W6uTNup7Yg9NqjziU
         +vZko1DgOiBWtUDzWYgazYAg7mOiyL1NAuEuc+dX2xseXIbO5MhGPaz2kWCHNiDLaIuB
         lBD61MUPS9WA289fbqOeqVhmK+OFkdUIJPz7ghUFpRQDS8qCCOxdOE5WyVaJayzefHvI
         OJLbh1jty6HKru3YNyGCZEGfcp5Y4+scrstpd1IFgEVxfJZzMTyAKz50ujN9NkQxKHXf
         T5xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UoJshtMOCTXUEY/9CnBsv6yfNmCgqOgVYc0ZF1A8V+A=;
        b=UR88lv3MtkMSX1CVawJc8lx4fM3aqYvaB6NqqIiWCrklats7gFkcSVyYm9iSxrNd/1
         Xc2VigNptBB+nbqN9J3sL+atHGBGb/7TWzKGLc5ZzJ2z0K+eA3OTM6yhn6MNktopITMR
         I6VUYsL0mRZ8QD7CE71vxLC95yyLDw+VLHlMft0Qyju7oRGru2J86NTbv4oNSTUqL66m
         99spyZ3+z+PiBnovcMd8FqAxoW4LlEInxlAny4IGs8W9Q4Eij9QUZNXB0jJm6mdVLYNN
         zY2CTODWDxyuWigmVYOQBt48ERgFjfu7jXHrJpIixVOmmlhOuOoXyaNz6i1xKm/VT9mm
         rILQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ej3odWh4;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UoJshtMOCTXUEY/9CnBsv6yfNmCgqOgVYc0ZF1A8V+A=;
        b=l9pjxX6m7OiKMSYFAoJxAqIT6s2aeHbl1vAbxoPfdHvujaiUK4wJUWdij753V5df9y
         s1y5DHeML2OpJvK50YfKSETGEvjQdRi2N8t0o21ZqsSCCK/dLLtd6sALK43sHE1GS3YP
         8n4GPMLbhLag2hx5pUzFrNs660PTqJigQFlczLgfqyFbCWwXmjevQi7rOQ07c/MDsRol
         XgWTgRaiwKbNiioF7ymYFJRhPvKGKenUcvhIUhlkYIAMD/xJkRa3cF3dFVPt44SQKz1c
         vV1P+MBehjMoAl2quTduXEnsevJ3QH+8jeEgFSVHwcyCoke7qFYA9xe+5SUuR+NT6r0W
         NHfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UoJshtMOCTXUEY/9CnBsv6yfNmCgqOgVYc0ZF1A8V+A=;
        b=2uKTqVTEVzeiIbUj4IoW60bykR/YHuPHtWRIhE4S1Elbv7ASPCbvFj41VFj50SRCXX
         kGWATg63w+bXsHQzO6SM0kwKbSNsP6/GJouBgQoiEGcjDbE1y0Stm64Bmkor8EMlJUti
         2mqItZTqIFTtahqJTQ5EnJSAWME2qgeATcqDkXrjgtpomWbRXeagH3szp2c2kZxGk/0e
         FUvHbfZ4YSRNkeI0jF218zFAagGHZ1ntJGgo9u8UJTdiGzT895afmo1XrH7c5dFu+tfa
         mkwoVZb4mIMQ/4+QwMWoYAqYv9a/0Nqg1Mpfjd9KreVpBSgTOLXju1HwigDd36af9B/y
         wtSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koz4CTZdqzvZOIjGmrmKs/v6luqS/+0IkET+oeVcV9+RPaAi0og
	uGqb41FFhGz94vzvc0eETSs=
X-Google-Smtp-Source: AMrXdXsKGDfHIUFVDrGnuQihpbnoUVPM9zWYx+BSF/ZTtLaPEv4+O3KktFDC26rQwFsnJRNqld9cSg==
X-Received: by 2002:a6b:790d:0:b0:6e2:e7d1:7e02 with SMTP id i13-20020a6b790d000000b006e2e7d17e02mr8238332iop.191.1673877760190;
        Mon, 16 Jan 2023 06:02:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13c8:b0:30c:3a08:da82 with SMTP id
 v8-20020a056e0213c800b0030c3a08da82ls1121986ilj.6.-pod-prod-gmail; Mon, 16
 Jan 2023 06:02:39 -0800 (PST)
X-Received: by 2002:a05:6e02:1ba4:b0:30e:ef30:49fc with SMTP id n4-20020a056e021ba400b0030eef3049fcmr6750772ili.32.1673877759485;
        Mon, 16 Jan 2023 06:02:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673877759; cv=none;
        d=google.com; s=arc-20160816;
        b=KDB98V457Re7peQa9oR2/2hQYwfQc1FBX/mGU+XA93qL+6Q4NmS0F6s7yJwNGUEQdd
         ovbqXzkMIJOMExThNnlEdxkEt5XZEVS7WRwDvaKlhoBMi8tC6MqzDW+qNRsjT1Ba4jMI
         yP1FO8OmUJ4Q5pThLL7skCtfIvFSj+FCYhZFobnN27ILx2e/9CkU0tZRfiGCQ0hQsmpP
         YPzs9TiW/nRQbwcQ+fOrzZePR1hVCUvTVh0kUWVFIKsoxn1snKV0HrFv5EzSylTAStXp
         zUQRumXZKOdNyCVF6psMp7RRkCquOwCORedpAW8kT/Jz+jAdXrq5lml1aFvEr2MKEPBU
         haiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=M3xTDj+OeARH76Nmv4pr2ITIBH0G8p//P+JSM/8zam8=;
        b=Di5jURHy6yi72JJnnWVs8vNaWB9w/D50iVqBv3/gTAWFDGAZ5O6bc3RlMajFIPqsjE
         TEKE1r+ydRN8rC1NUcmcg/b3GKC8U2hv4yIbBRladtac+IdHM+mrcVfHEzDmAI0QClbe
         t8I+YtM4qMObRjBNR/PIaHIqyXrJ27ldpmTpQw9ZsNblQMXjpDFZ+RGvFvCSvaiWtEca
         Q8oO8lWArWRWHOFPNV3KauGAduCu9VxlSc4itNti+/Bobph89OgTHBcntAAO+MLO0tMA
         Ka6/x/HoJRN9R/RaDivp3Pn2dWJaXyfV28gqgV1X/ZKcF+yCV0f9IVk9cChKdv3ZaOfr
         /0tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ej3odWh4;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o8-20020a056e02188800b0030ef19afcb3si502203ilu.2.2023.01.16.06.02.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Jan 2023 06:02:39 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2A75660FDF;
	Mon, 16 Jan 2023 14:02:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4BC7AC433F0;
	Mon, 16 Jan 2023 14:02:38 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Max Filippov <jcmvbkbc@gmail.com>,
	Marco Elver <elver@google.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 6.1 13/53] kcsan: test: don't put the expect array on the stack
Date: Mon, 16 Jan 2023 09:01:13 -0500
Message-Id: <20230116140154.114951-13-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20230116140154.114951-1-sashal@kernel.org>
References: <20230116140154.114951-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ej3odWh4;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

From: Max Filippov <jcmvbkbc@gmail.com>

[ Upstream commit 5b24ac2dfd3eb3e36f794af3aa7f2828b19035bd ]

Size of the 'expect' array in the __report_matches is 1536 bytes, which
is exactly the default frame size warning limit of the xtensa
architecture.
As a result allmodconfig xtensa kernel builds with the gcc that does not
support the compiler plugins (which otherwise would push the said
warning limit to 2K) fail with the following message:

  kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
    is larger than 1536 bytes

Fix it by dynamically allocating the 'expect' array.

Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dcec1b743c69..a60c561724be 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -159,7 +159,7 @@ static bool __report_matches(const struct expect_report *r)
 	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
 	bool ret = false;
 	unsigned long flags;
-	typeof(observed.lines) expect;
+	typeof(*observed.lines) *expect;
 	const char *end;
 	char *cur;
 	int i;
@@ -168,6 +168,10 @@ static bool __report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
+	expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
+	if (WARN_ON(!expect))
+		return false;
+
 	/* Generate expected report contents. */
 
 	/* Title */
@@ -253,6 +257,7 @@ static bool __report_matches(const struct expect_report *r)
 		strstr(observed.lines[2], expect[1])));
 out:
 	spin_unlock_irqrestore(&observed.lock, flags);
+	kfree(expect);
 	return ret;
 }
 
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230116140154.114951-13-sashal%40kernel.org.
