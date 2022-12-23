Return-Path: <kasan-dev+bncBCYPXT7N6MFRB75XSWOQMGQELT5DRLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B908654CF2
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 08:42:58 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id t25-20020a056808159900b0035ecfd3fa78sf808836oiw.4
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Dec 2022 23:42:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671781376; cv=pass;
        d=google.com; s=arc-20160816;
        b=kQKju4pKH137oNAu8VMFz88CuXsd81pmho02B8xRaLpqLaXaCqwDcwfXSDOWVEDfLV
         zxtuY0jDntpML31M0CKeJwCRLlCPetEbykAZfNrU8LInxF+XRLt3E1RerJyWzoXAx3Gq
         z+8Hssj1kWrl2480RhpeVns1hCm0m93M4kRjYOenzyAymQi45UpBDk12OmL0b1yvc3LV
         s40k+YsgQVyEe9f66KJUE0lAGwECAO6I660glXeOF/14JqO1No6WniJ7Fd+RX4m/3rMj
         okj4ErsJ7SezoTvdUZ5C9wAyMyCptkXUdEPevoQlJtC682i/piBVjb+5fgb0g18n/Qjh
         fRZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=tJTIfJK79MMtoiEu+tWaUab3+OsYwnqYHbTPZ5+XYDc=;
        b=OZ9piVsJDcXgo/2CGyCNa5xly0YYEEXyX8zVsXVTTRG874SHQLUEax93Y1A3adMr9y
         NwTLk/n4YIbYndl1iid+pT6KC1ZbVgYmCbq910J4a8NDIh7gVYDpzp5dMbSXOKsMNbwL
         onozXVjx2ovsu1TYOu2uc6LR1q3E6hU/CF31mjJX1j5uBJzJW7cp4QJHfXkK0flgHqCw
         BKycDGOy+sS0YPwjBsE6UNa/PSh4TKJ3F8fTepDJt/axfyfsaR30T9Yh5Nd95JB7m7rI
         IZgqp4dHMR/xHHUGZc4aydOiWmBp/CrIhd638lnhCZhHSf28IeD0YEDoMGyy3bXcTraQ
         prPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qBmFxZfk;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tJTIfJK79MMtoiEu+tWaUab3+OsYwnqYHbTPZ5+XYDc=;
        b=Jko7/4BoylEfVWRQSdYfL7pKXzewdEf7vLqU1+2W/zMSjb9urd1zzvOAnAmpcbFOCe
         yFJIdiuMLsyRILAyvUnF5wpC1f7ce0b4jznwBZWqxRfNBGoBkWP1toDbBCL8QF3cNgdu
         CHvCDZWCBHrmsm+ryynRv8YA5QU4I8wCzboq1jpJSoEHkx6IWY4bsqsMlB7P2PtsoQXK
         NL+Q68i3MJY2B+1ehDPSYjeNVjeRhwjEmoUsEvbgGA6CptP9LSlXRw87kgWr0rW2/tZ5
         SxF3nxNCobF5uQo0wNmp1sl9kbHNBLoidqfHZXDZPCXqH3PfGYv/4GUAjhywAQfFYhUv
         leog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tJTIfJK79MMtoiEu+tWaUab3+OsYwnqYHbTPZ5+XYDc=;
        b=LgvYVb17ml9ZevClsKRNBog8onz9O17qIiO0lF0slc/6yaTuwKpmnNPkH9ExlRocN3
         oRTet1i8mmWmIkybGceX2TNle3789q69OWMTMJy+mHzs1Q3iH/+o+l0yMNhmnT3R5Twn
         QzUHf0o2QNyhKioIqx95KeUNq4TqKq1oqvdtMUD027ozz5Wkqagc+gueXL/jVNuC+yOh
         ikhhCfJWhIM/BQF/YkIFdEuCkc9P3D7VJ+Hmz7eDTOv96HVvfGRiOrM0GJfgcavXwuys
         biQWz3HZbxG4M9dc4A2PavTcSDsbYs0+104CA4T9lesNq3FnQhBhzM1frRhPiqdhnQ89
         5xLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tJTIfJK79MMtoiEu+tWaUab3+OsYwnqYHbTPZ5+XYDc=;
        b=xPHcU9LG2K53rjEp1kQ3+Husyl/KzJTLq5X5BQ5oWalCBiZPcB3hIodO9Nzrimbyvy
         v5BozF70FVOZlRDB8aDn1YLO8MleUd6IxHlzdXPRZkJVVlzhFVEObU+n/SQjQs6wQVeJ
         bsZc91DQozMyzPPcRUHw/kd7nL/y9baWse54ufya0IdJRPwOTNHbNKXepLFL7usRIjAS
         HcnsRoDeFRl3MusKqt1JkDZ78im7C9aGep2s+/dzFZ790yEBio9sfSdhaW3tNKWsllRM
         t0OlArTY4/7VJ+iMV+RUsha+rHwpG9TDtQ6O/H62Urp7oVFk2cu7rV7LfaHF3sUnpA9L
         2hpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqwQ9crQG33IkuHh0pgG0TysK8slb8/F6BgrxdZc+C7B1y5cpwY
	F+5hBXOmoBJs1EcSc7RBwQg=
X-Google-Smtp-Source: AMrXdXv4hhopxX+E3EEWTot0GPEPuIQaLI4sA6qrrRiI4smPtd6t+TbydF7BBjT92ToG38ygYA8j8w==
X-Received: by 2002:a05:6830:2653:b0:677:916f:9767 with SMTP id f19-20020a056830265300b00677916f9767mr555816otu.58.1671781375982;
        Thu, 22 Dec 2022 23:42:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5aae:b0:143:5382:1db4 with SMTP id
 dt46-20020a0568705aae00b0014353821db4ls1416574oab.8.-pod-prod-gmail; Thu, 22
 Dec 2022 23:42:55 -0800 (PST)
X-Received: by 2002:a05:6870:4d12:b0:144:a3c0:2723 with SMTP id pn18-20020a0568704d1200b00144a3c02723mr12209626oab.38.1671781375636;
        Thu, 22 Dec 2022 23:42:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671781375; cv=none;
        d=google.com; s=arc-20160816;
        b=jC+U6xyJQz5I76bD4j2nViJTZyAyyh6wwmUXBDu4gcMasUyZkSaD1OtlhyR1KpjtWl
         1qqSupfd6dZ3TKhg3kiJgVA7oVZ82NcKXZ8kESZwlQ7SEOQBbLJZuDX4FXwxgXeOPn1k
         6a8GS+KWy+0Vr3PxeVoroelG3fHABAIqakxgwqt7Sh0qvQlCcNVfLU+psQFkCVKIae8e
         P6o3PZdG/vgrXY4Npx3KWjT75EcDZUwlnynsj7nUn/I6CBZtNxg/eWeg+x477PppkdGv
         I6M5GHGZyRDDfkJpr2AVLZPibeZRhzzl1Lgwawbz+JbDmAXGvhWLJtQcl1aPhEOY4RzF
         CjRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=xwkjPkB+HDgaumLrNe3xi/8SHaA70l8jiLgxWpcwsNs=;
        b=M7MLjxT5QL9lH5i6zk62FfYzoKX+619lsAymt0NHVmHHrGfLkB3KPOq357zzEHdJgA
         GbQoLjC6E/rwNBbbRoYOb8QaYibwKOCDHIQnMqUvIh3S5Vq9QtDejgBeiGFJpIhfHolp
         yucoAeWH1YtKLObKkm22ByXDiXU5xNxHztbM35KSdo7E5WyCOu5Phpfry5ZG+B7dzRur
         8nAQ7a70yZVOTZ+ZAZEwCzaTOYo7DANYilgwCQ7LfmqGIk+FJOB4Iso3H4Rb3vtjIKqh
         zxH3MyBhba8wGN625lLLqs2RT5Uaem9q80Ctyklix3f9Oo9bebpYvDtyRnt5Yhbo/6qo
         hlcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qBmFxZfk;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id a19-20020a056870b15300b00144a469b41dsi294249oal.4.2022.12.22.23.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Dec 2022 23:42:55 -0800 (PST)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 36so2834016pgp.10
        for <kasan-dev@googlegroups.com>; Thu, 22 Dec 2022 23:42:55 -0800 (PST)
X-Received: by 2002:aa7:93b8:0:b0:576:95ec:bc93 with SMTP id x24-20020aa793b8000000b0057695ecbc93mr24262725pff.23.1671781374955;
        Thu, 22 Dec 2022 23:42:54 -0800 (PST)
Received: from octofox.hsd1.ca.comcast.net ([2601:641:401:1d20:3ffc:2c70:d62e:faaf])
        by smtp.gmail.com with ESMTPSA id 64-20020a620543000000b0056bd1bf4243sm1887187pff.53.2022.12.22.23.42.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Dec 2022 23:42:54 -0800 (PST)
From: Max Filippov <jcmvbkbc@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH] kcsan: test: don't put the expect array on the stack
Date: Thu, 22 Dec 2022 23:42:38 -0800
Message-Id: <20221223074238.4092772-1-jcmvbkbc@gmail.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qBmFxZfk;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::529
 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Size of the 'expect' array in the __report_matches is 1536 bytes, which
is exactly the default frame size warning limit of the xtensa
architecture.
As a result allmodconfig xtensa kernel builds with the gcc that does not
support the compiler plugins (which otherwise would push the said
warning limit to 2K) fail with the following message:

  kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
    is larger than 1536 bytes

Fix it by dynamically alocating the 'expect' array.

Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
---
 kernel/kcsan/kcsan_test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dcec1b743c69..af62ec51bd5f 100644
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
+	if (!expect)
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221223074238.4092772-1-jcmvbkbc%40gmail.com.
