Return-Path: <kasan-dev+bncBCT6XLET5MNRB2XH42ZQMGQE52OBWVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CD33915615
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 19:59:08 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-250a7122b8asf13826172fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 10:59:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719251946; cv=pass;
        d=google.com; s=arc-20160816;
        b=te8r6OarZ+7zU9Owf3utwVb0Ijuy7Fads5qwdRdF2FU/6ywnymx7GTYh+FPQyEMdGJ
         4ZspNxfLFb3VG8bdYKbV4ypHzXNPuntSNK7bfs2lMZdMkPgjhBjx+ss8tgm9suugq0vx
         82c20eyDDS1+XNqfn/fCDsPq657oiX0Qw3Umo7sacdH4UItGJj0cL4+0Sl+EmgmYOySm
         cTIJIjONMwlIHJA32YImLkdmx0Ja0Ylqd4lyMaJkjJOXMhq21esujWOO5BIpFX/F0PdP
         vH7t4RnB6sfJx7VXXCVsGbqTxmgCgYJVIbdHaYKJVepJ/HsVAzj7Dsje0Yt3AxoMLMoZ
         JjMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JdIgQ6B65GGtFo841cycSm3l8j7/tZ50GQ+U8dMk1g4=;
        fh=lDU7sQIeeQqQNZH0YAV7P66Duazv/mQo8VMO3qInld8=;
        b=rWAOQRY66FZO1uwyU3X4yxp40FrM6xFdufdJiCqDpPmpk11PVFp6rm65ZYmClRmaqV
         Rx1WziixEYil2PT6GhdmRKf2jAok12WAveII1hVW1cwPivbRZANv22BdJXFbR/VphHv0
         KgXMpmZWHpQ46Liqrwf3MAm/+YdA/adHJ08xk+NL99r9toIOMywjGsuU+RIQMAv7eGLJ
         8Q5qSmC5v78E+I7vbxUYHbCX81ylh82QTjg75suDWl5D+Zp04Hxn9/B9zY6gJpjMx0mc
         usJ7xYZFId3Sp2ucrrbxS8BNOF8X5KJxoiX8z85q44DBVKlcLWm8JCGuf91MQEiSGsMf
         Djdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b="gcYRhj7/";
       spf=neutral (google.com: 2607:f8b0:4864:20::429 is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719251946; x=1719856746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JdIgQ6B65GGtFo841cycSm3l8j7/tZ50GQ+U8dMk1g4=;
        b=dcwQ7QfB34ecSwj4spyYBatMXBgM4MuADdy8buO945i8R/m4HkRp1ry1pHuCXdspKC
         lTVo+2ib4tUftqpBYCsmkmfWCPuuz4kRubaRumTaY+UvYHKlBcgFlxAxzeFuL34PT8pJ
         9SR79O7wGSXgglDRak/fpTbn55Zo9sIdz72ZPKp7JKnJyVb3/YVn3PQ0H07gh4QU1gtJ
         QHbWGahBX+OmnsPP+Ws9lZUPe2cxa0lzfA2nSwLLQytXPJOF4dtsOurpdSdJwYfyBJ9a
         2kwLd1UzJNExXRx2AMt9vj2NNuFlFfb9K7c5tIm17G2vwYSWjjABp/sCvFIw+jymDSHl
         gqUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719251946; x=1719856746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JdIgQ6B65GGtFo841cycSm3l8j7/tZ50GQ+U8dMk1g4=;
        b=hfT+xhl2NtzS16FKBpKsM4nKZn6L/UIemrxghPHBDcCuGLIFowe1X6Y8Akc0rjBmnN
         nUy4FnWZJQ5nC1XJDOK107nqq2UyvW1me0Ga827c/A3jsxUl8k7GoG2tBcetWfZZSqU2
         02BPgLwN+gn57RhSlwVM/zMV/vvEp3i+5FCOtTiuiaB6WsB+s3dGhBhhKxl5r2asB6Pm
         TJQxnBv+yhXDxwIjgX0zJIQGasdwql+dztHW7mg79wP49RAkbft5CcoFuhoejRIKiavE
         5Og61/2dCTRLkqg9j9e6rJvYxkGSiDc0zMl6qySX0c/1E4hx0QPtcfGRR6pQeJDCNlRN
         VT/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzOFu3r2t+IS9h41xJSGQlPdmAmg61EI/o6PVG4bSRZb++CPKSWEgtDxU5fH0fdOH3UY4n7fDGRlSfwBlfvub8a9Pmc6kyHA==
X-Gm-Message-State: AOJu0YzmW3cImEosagPcjsZMujpzKPTvNCVDaQJLXzlJr7Qoh1LmnpAt
	0utCZzLsJ2ijd28mwE8wsUfht7ar3QHGTXIJNQCvdnnQkpdWRJqF
X-Google-Smtp-Source: AGHT+IHU5kwC4KP8Y+9j/wggFgmY/weaOr7TtNXNvCk9R0UpK56Je9U5SBqy0vY/7fKYiVfUYOOIvQ==
X-Received: by 2002:a05:6870:470c:b0:254:9570:e5aa with SMTP id 586e51a60fabf-25d06ef5925mr5866822fac.57.1719251946534;
        Mon, 24 Jun 2024 10:59:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e70c:b0:259:8c55:f25a with SMTP id
 586e51a60fabf-25cb580ebb9ls5187801fac.0.-pod-prod-05-us; Mon, 24 Jun 2024
 10:59:05 -0700 (PDT)
X-Received: by 2002:a05:6870:ac20:b0:254:826f:a9d1 with SMTP id 586e51a60fabf-25d06cdaca8mr5712500fac.28.1719251945741;
        Mon, 24 Jun 2024 10:59:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719251945; cv=none;
        d=google.com; s=arc-20160816;
        b=PURNYvmBkU6YM/1ab2GbJfYaBWnRAWDScRJRJ+n0voApzNOBPrynTykFIlcos/MPR0
         p6Wg3HhNOscVaO3vLOioi1nkgELO1FsHZbw5xhBtx5KZkwiYddhDZwPXXzVpRDPE94jd
         vSReT1QYN0v1grJhaGCuT5p6jzGlY9tgbof7Q+Zxq9MwLKxSons4jDnJEx8wNppnbQFW
         L982NeGmqps6fIlRMC8Y+I57ux18GUYHzu0uQsxc9ekaKAGTbzWen0owpeBgTmTRGE5m
         uwEAJ62r+doWnAbnyMsuBr4IBtCJqq0tUAw3NrPl8hwBrku6zIsT53ZutqTe6ZLHAewT
         x6fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=bUkG7WPXxoFCKENTQnYrOokr0PwEX3Pguw8rWa7FZAs=;
        fh=P6Ei1vdTJxi4nhO4E4P2fD5M4oleVsy2C6NhEVtdjGs=;
        b=Q2oDnAwAxbS2X9sLC2pk/s06js8y+JVVKLgZPrGlZkXWwF3xobdI5veTe0Ro8/w2xm
         EIUrjWVvOrcy1yEgyOciebbhhrNrnkWanWZ1BxsqSurgPbDVr6PgCX8HoQpOg+1zWwAX
         i0U/AyHh8wGJrTLuuyxj1HuAHM1EnZo2WgRHzkcRd3hGWKUpehHaI+41stxqMkMPW8KK
         ZkfySzXgEwEddhAdzepug6kH+9JFybdaDhH+2+nezNsXSQkZHj3TPT4KDdHgS4ry4m31
         WHhcSNr5gYXSB/vQ6rAShc07beKXoBe/OiKfJ1AvV4pARM6TZSZMXsqpIv6hKh0aaAMh
         FB8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601 header.b="gcYRhj7/";
       spf=neutral (google.com: 2607:f8b0:4864:20::429 is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-716ae2ca591si288107a12.0.2024.06.24.10.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 10:59:05 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::429 is neither permitted nor denied by best guess record for domain of thorsten.blum@toblux.com) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7041053c0fdso2708747b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 10:59:05 -0700 (PDT)
X-Received: by 2002:a05:6a20:8908:b0:1b5:3ffc:b3c9 with SMTP id adf61e73a8af0-1bcf7e2a56amr4065302637.13.1719251945206;
        Mon, 24 Jun 2024 10:59:05 -0700 (PDT)
Received: from fedora.vc.shawcable.net (S0106c09435b54ab9.vc.shawcable.net. [24.85.107.15])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7067bc13770sm2868633b3a.56.2024.06.24.10.59.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jun 2024 10:59:04 -0700 (PDT)
From: Thorsten Blum <thorsten.blum@toblux.com>
To: elver@google.com,
	dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	paulmck@kernel.org,
	Thorsten Blum <thorsten.blum@toblux.com>
Subject: [PATCH v2] kcsan: Use min() to fix Coccinelle warning
Date: Mon, 24 Jun 2024 19:57:28 +0200
Message-ID: <20240624175727.88012-2-thorsten.blum@toblux.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: thorsten.blum@toblux.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@toblux-com.20230601.gappssmtp.com header.s=20230601
 header.b="gcYRhj7/";       spf=neutral (google.com: 2607:f8b0:4864:20::429 is
 neither permitted nor denied by best guess record for domain of
 thorsten.blum@toblux.com) smtp.mailfrom=thorsten.blum@toblux.com
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

Fixes the following Coccinelle/coccicheck warning reported by
minmax.cocci:

	WARNING opportunity for min()

Use const size_t instead of int for the result of min().

Compile-tested with CONFIG_KCSAN=y.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
---
Changes in v2:
- Add const and remove redundant parentheses as suggested by Marco Elver
---
 kernel/kcsan/debugfs.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1d1d1b0e4248..53b21ae30e00 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 {
 	char kbuf[KSYM_NAME_LEN];
 	char *arg;
-	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
+	const size_t read_len = min(count, sizeof(kbuf) - 1);
 
 	if (copy_from_user(kbuf, buf, read_len))
 		return -EFAULT;
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240624175727.88012-2-thorsten.blum%40toblux.com.
