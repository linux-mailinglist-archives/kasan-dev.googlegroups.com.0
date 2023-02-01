Return-Path: <kasan-dev+bncBCXO5E6EQQFBBEFC5CPAMGQEM4A3EWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6919B686062
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 08:13:21 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id y26-20020a0565123f1a00b004b4b8aabd0csf7819909lfa.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 23:13:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675235600; cv=pass;
        d=google.com; s=arc-20160816;
        b=lNihvHkxSYiytnDoN5RK4Q/QFwHQFq2imJ3ht+WAkBWJY18LOLFWOFBn+fgC+rYivG
         ya/VLDUf8+zyIpM6E9kis6EyhSvZNYo1OcpKX9KIETH3qybOSF2Q4ETI43sfxEmbPSMc
         q+dM/2H2lZK0j+A1EETkBp2SJUBoFb/mNfl+qmuvp6FuUxEZn/ZRAiOBb4woU98UbCB0
         na3tPKitPwYxx4uPhKZEIeb5LLME4mr9WwdMHI30QlZtR2hdTc8SpCepPq1bF+PCmCVp
         gVZd+yjo23z3oBWcNE5yBdlyH3GHomNr0l46mv2f/OQwprw3Io4yFr/lMF8s7kuCgw4Y
         y3Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZOXVH+bFW4zVj1pDVt3vmllq6UOQScfjvr8yUSnRlXU=;
        b=OBT7SUVf6ta5Io+2xJ7LgLGiU3quZRmjKa7GWZJ98DuX9/XlE4XdfYK4srguD6yMIV
         hp5uu76tyILpnGp448g7OSfGuA3f2BJnv3HFqx1fCEL4vgCxdzwogYcnQTdrvjGzDNZZ
         /z0OVkGt+KqqpRfhT+QzTnTyI0lmzfIrgBjLHgGRTIImmRORlE29z04THrJr82INEvjC
         q2lMa7WQUjiJTtbvbiAD0mhCbeGqLG4ptjfPqHHUjYDYLQHcFWWYH3wTSpfz/bd/VA2e
         dX1AMyZre3w6mBoqQo3Y2ROxatix0LPWn40Jp+DzWoPDVqk971rL2IPQckuvPYsBEVUM
         Fz+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mz3312IU;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZOXVH+bFW4zVj1pDVt3vmllq6UOQScfjvr8yUSnRlXU=;
        b=acWkd8CkngztXES3FYxqvw4FMrx/2okJLG2d0FTrIu4Db6aga8AWbwHQtwA+MxoNRa
         gB9rvIeAkPhi72VFP6JQaZq0MlTPJuc7I00yOAbHS7A2S/t2OCN4Lna6k8NrG4P5Ut/Q
         Ga8ltSh4g3ZC6YWdnC9UrMTJ2+hV8WRbpHx3MK8GDXihqQB7eGu3ys52kXYfWIPP7kTk
         Owan6F3hl6gHMwjJVGGrCiBHUXJW6jqOo518FjbLJvLUABtOgPuvNh/AszVLeRbwTcju
         edwJ0w053whN2LyjxxP1G3ecTw/gUXoNtAXV0D+ZNkmHZ9cUqr/pFCTlewSQCXWMwshQ
         9g+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZOXVH+bFW4zVj1pDVt3vmllq6UOQScfjvr8yUSnRlXU=;
        b=P7rwk7Emq7HPk+COZ+UiJDlgDn0Oic126KwWbVC8w2KffZiaFcwpH0CUxlSI7ItdJv
         FGUzPQ/rD8XuyKjxfX21coDCWauAUcg9gH62B6YS8D9f+sq7hycZzeOxtyOkz811DsSE
         Ks8MUqqawk1g2jJFpx96f1bqZUd/IMF/+wYwYNMQD90luhjtCiwrPJiPo9EFfCtFreEF
         w21mKhcEzJQmRe292FBTWcxaub8QUOHnyMIpEmuF/70h0qYM2yhRCHa2WBin+l9Ck7KR
         Tyz6erHsiG4VPzqV1hRro9pJKBnzqOrPWLZhpgPpKLxpgIZoPc90ECo1D2ISkuIfqwoJ
         WbCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVuMl8A2LkHBITbGx5dh6smdRMCy5LJLz0LBnPL7dV2iirk0kN7
	AyFi2BfqMVVh/dpSYUegZDk=
X-Google-Smtp-Source: AK7set+3ovDjmE/yMgxcfR6OmxdER8yhFrBK3+BAI7lEde4rXCjNDjrlw6JOu257ii3Wb06sR3EXjQ==
X-Received: by 2002:a2e:b54c:0:b0:28e:4d21:ba27 with SMTP id a12-20020a2eb54c000000b0028e4d21ba27mr160581ljn.210.1675235600648;
        Tue, 31 Jan 2023 23:13:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bd87:0:b0:290:623f:774e with SMTP id o7-20020a2ebd87000000b00290623f774els1298462ljq.10.-pod-prod-gmail;
 Tue, 31 Jan 2023 23:13:18 -0800 (PST)
X-Received: by 2002:a2e:b4b0:0:b0:290:517c:c89a with SMTP id q16-20020a2eb4b0000000b00290517cc89amr186228ljm.43.1675235598466;
        Tue, 31 Jan 2023 23:13:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675235598; cv=none;
        d=google.com; s=arc-20160816;
        b=yjHlNvAJSkJvmFvpRHZX1myrbrcNjsX7uMPEj0uA/bykZ4DzXtcIdNjQ/TsqqY57PV
         CGsNgJ6xSF07cnSQbEIMBcZIyNactDIOiHZFmvePLfG+6Q37fvbhqDjsOewnNgYPf7nR
         ayuoI71O8u6mMw4EwevhJsmD5Z9EJmS6a/nEqXF7LDQkYW+4663A/E3DLWW/kclS1Vo0
         M+/Vb4rl8yK3WPWcoVUYPwPCRlqws8skEjPspBcY+RUCdn1oLTgk0ZSYrV5Zjmpxgqsy
         o+3DkoeQXIXGMm5jZbyu5+L7DkJwBX9ZVkB1wBSyNSvg7JPs9dfzWk/gKzrnnxPoRFqa
         AAGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4BmlzaxYuvz6yK8Z6bcg8GUmZ6rvSFskLQ6yKMJuJi8=;
        b=ReJpXmwrmmrZlIsQng64+0d0pBEnnVQfAfq1yfBSbvoGPv5OVERKN3aQH452q3p1UJ
         dAMtCrYteHy+b5lCrxUQSUNJvE7xut9yulua/hNV5uTJB6NKi1Q1ovOrhfdKY8CDhI4B
         h9IMPM5YITurH7JYKKhHHnYKsy6WPa8Acu/YeJ05avE6SmqQfzOtzfMrAVr1JKzaZY7d
         avEujxmj7Lf9Jne51M6m+2yH7QtypKKNcxZQjN7t9S2kMFt0RhPslAenFPatk+2vNVP2
         tki5aA6SDSlyrM6EBkml5fbtqSXnOuDfWBCiRCMfb0p3FdUZraWJEeL5LQBwG5f8UBZL
         FrkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mz3312IU;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id 3-20020a05651c12c300b0028d0067c3d4si464767lje.2.2023.01.31.23.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Jan 2023 23:13:18 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0485DB81FF5;
	Wed,  1 Feb 2023 07:13:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 22D8AC433A7;
	Wed,  1 Feb 2023 07:13:13 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: use %zd format for printing size_t
Date: Wed,  1 Feb 2023 08:13:04 +0100
Message-Id: <20230201071312.2224452-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.0
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mz3312IU;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

The size_t type depends on the architecture, so %lu does not work
on most 32-bit ones:

In file included from include/kunit/assert.h:13,
                 from include/kunit/test.h:12,
                 from mm/kasan/report.c:12:
mm/kasan/report.c: In function 'describe_object_addr':
include/linux/kern_levels.h:5:25: error: format '%lu' expects argument of type 'long unsigned int', but argument 5 has type 'size_t' {aka 'unsigned int'} [-Werror=format=]
mm/kasan/report.c:270:9: note: in expansion of macro 'pr_err'
  270 |         pr_err("The buggy address is located %d bytes %s of\n"
      |         ^~~~~~

Fixes: 0e301731f558 ("kasan: infer allocation size by scanning metadata")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e0492124e90a..89078f912827 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -268,7 +268,7 @@ static void describe_object_addr(const void *addr, struct kasan_report_info *inf
 	}
 
 	pr_err("The buggy address is located %d bytes %s of\n"
-	       " %s%lu-byte region [%px, %px)\n",
+	       " %s%zu-byte region [%px, %px)\n",
 	       rel_bytes, rel_type, region_state, info->alloc_size,
 	       (void *)object_addr, (void *)(object_addr + info->alloc_size));
 }
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230201071312.2224452-1-arnd%40kernel.org.
