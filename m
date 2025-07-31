Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBPHCVTCAMGQE653FBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BD45B16E14
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 11:02:54 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-7074bad03d5sf4254826d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 02:02:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753952573; cv=pass;
        d=google.com; s=arc-20240605;
        b=ES88DFqQPkCBwJ+QM8MistEtks/xrPumiAng6ArHNpeX+XHsX4yEmz4Rwe9BprFqr0
         tiC6VtNPon3NDUmsDr2B74R0lnqYvXASKIBamzvrE7wc1WRAUd3EB8c92PDTUd81wTYA
         xmwrk0fcUWIGgh7zrD2JEPPKKXNcGvfgAYm2OvwWD29t2/MyRiXoQhxmyfCB/CieHsZ2
         ekJBvUs80vynWctYvz1oaTaJT5iCHMtVSQXm2XfMUydO1ON8eng8jOxvnaNm/Ez/2eWO
         yjJOJXmUBXh4o5fB5s4Op+H3nKODrzA+la4fi3DrixxybgXWpTcp5M3dlumFncJPdXJj
         +6ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rJrLrS/iLsAqyi0QSYwSCVSd0kXsglAEiP4umy/ZN4s=;
        fh=pLdPqWggOQKmWV8bqFHD84DNOTa7t0jY5PhcpX/8YQA=;
        b=f9XOzFUuPW6BjnI+cO0ULDp/LwpnGL6/EOJkNGhnAZ5+R0eCq2fcj6kOgiDokpCH9A
         n5KBWr48621yibbyTdy5tJurqKffjTKev8df/LkB91FoK0lUjR6aevOsmXM8oGNwXGFp
         qgHpNzKT3s/hjAZXObfDZ/1i9esr6xmpIBCn4zQDqUawDe1ng5iVLlYfV6PBz+hRGqm/
         rgYhPOx0SQKYedP9ScJ6E5XGswSg8lIygeV+WGL6/IztR4Hg9oOWOg8kWyaexdiKglIh
         +Kl2G0HUdudPQbuHo/LmxSxDpEAvLXLHvSGcX1fWwky2l//8d3CgH+oPiya/RuHVx3BS
         Cq7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753952572; x=1754557372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rJrLrS/iLsAqyi0QSYwSCVSd0kXsglAEiP4umy/ZN4s=;
        b=OJAQt4cmBo5AkPuYLi9xRdj8DX41l0KeOo2fR2k1GyxDFGihAfcibKbSh/BFxOpj+W
         B762xwM5+I2AWzq0AKzyg+aSpjerG/r9KpbBLyaC2RJAtvRTbYh9cHzTWy2mSx0wxa5D
         7No72f89S6l2btDLRdeeQlF80alu+of85Ud0cwQv/l1AeEgTS3Bca7RuZTxW/iq+4/8j
         ub286PySlAttPG/SFtACDb4kubCaDxh0UifdqWxXUVNIDCobeIDJTmnqptv9cVNRph33
         7mT7wf/lARpXzFqOfROpqv15gfHZrskqVl/WCJXV8k7/qLgNMr7t6QfFqqbEoId3TRRa
         SX9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753952572; x=1754557372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rJrLrS/iLsAqyi0QSYwSCVSd0kXsglAEiP4umy/ZN4s=;
        b=WuAwul2V6X04KQ0rnAsQrLq1UiY0eu3laNwsB8LeSiQAcnkM44bhFtNYpbz6f0obHp
         97hUsI920PgRzy93lF6Zgorfw5TvG6JmEaldo8GRf2mOmTw2wUJOexGR6N3deGmsFhmh
         n8fkDfenHqrXgQoGW+n3eGfe77j+5XTXpGMJ+lwKLz9zkZgBANFnnUzMu803ZaZEvCxD
         0f6a1a/RLYLr42mh08aRDp8xNWn4GEqicSsQraTwFkh+lg8eOzV6LcJxaBOUiI/3TCdU
         jSI9lUd9scUk2dH0+w7HnDfOUoUQmem1elXrdJ2aHBapRIpYVvH8fCN1rSjeVHdMJMsu
         DTPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6DztqIyPQhtkaAecEwQ0POMq2Ls7olbe6oESOAqOc91JvMRHTHokwt5HmoHtkAa61vXXHCQ==@lfdr.de
X-Gm-Message-State: AOJu0YwNehAaCSRkiYRrfI661SZ9A+hMWhO8m7kLrRap1ZycyyeLbuc6
	al6uBlUDNV/0suC9KqgNiNUkcrowfkSHmM05lMCFnxWcJfly92mTWsFG
X-Google-Smtp-Source: AGHT+IFFvb7WxnxhnBuo0AF/JW31pPK64vfOY8LOtkyYbCxIPvZ/dg0iZO1Z7sY0/kKRTGmfJDQuDQ==
X-Received: by 2002:a05:6214:5098:b0:707:51a6:184f with SMTP id 6a1803df08f44-70767431a40mr77440446d6.48.1753952572246;
        Thu, 31 Jul 2025 02:02:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfICSp4k7/rzWeW1KpRhKbff7WA/Eu5N3pMVWRbej+sWg==
Received: by 2002:a05:6214:76a:b0:707:4680:6fef with SMTP id
 6a1803df08f44-70778d6a75als10073656d6.1.-pod-prod-06-us; Thu, 31 Jul 2025
 02:02:51 -0700 (PDT)
X-Received: by 2002:a05:6122:88c:b0:531:2afc:463f with SMTP id 71dfb90a1353d-5391cf0d8a5mr4023207e0c.6.1753952571219;
        Thu, 31 Jul 2025 02:02:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753952571; cv=none;
        d=google.com; s=arc-20240605;
        b=AyksrYKF1Lg1EW1Lla4VpTEO8pZU8ylJu2ogYNzepXn1BQP78IrYPpCo9zFpj4vDP1
         52NODK/ed9MyzDVrc5Ky6y6EBbRDXSeQX9js1kxfJljS1jk5sVaX5timTgyu41bLaSNT
         I7Db34t9AMtFmm2dY9B2mGVH4ZeaAfHXBUN+vbRPzk+YcO0jOPq+bV06JlhzPKfKdUVf
         fesgIHeo+lPkvViGXF0s1nPAylgfnoWlVn3fdvT/jTRgSH/TrxqTHQU64N1rMO+CReZb
         hkQiIc+8j1e1aT/Ahe1rg19AYYQpyn0jy3likxNMVq2cGzWmgbi+qNwPRWuwY9M+3tnn
         9wbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=pyDBUeJEYlBK0pxsU0xvDjddAfItdO7IM17eUG01F5w=;
        fh=71qf1XhsUMVck3bUB1GC0b2bIUAUQcW/LpjUmsQZfNY=;
        b=TpZij9cGAX6WZ6P2IbTnm4qEcYl8lLnklIRFTkx71LTGMGXzmt57K62PHccDvJAZ4E
         m0NOJGyXtzy7TkuOpV0Hvtw9Fr8govmpuIAIEkOA39XHhuH9D10zKii+0okNJKIATBfM
         Ys4Z6JrsyhVqrAJ+cVINT15gsQSDs9EXQcG4uCGqZeRIc7MfYi0FrO4ELmoC9C0BkUc1
         OMqi5xE8Pe8n3QhGLxOqZrLJsFff7OiBEsaEjZZkW3ojUyOlhxiSElSVmdz3SxRuXEzH
         biVpWxFWPAO+pfOHtof6O4Zdb5quKXmy9Nlr7S8KF1EQE0eJvXn08MNTPd8h4gXLqNBF
         2YiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-539369375adsi60921e0c.0.2025.07.31.02.02.50
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Jul 2025 02:02:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4607A1D13;
	Thu, 31 Jul 2025 02:02:42 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id A62AB3F66E;
	Thu, 31 Jul 2025 02:02:48 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH] kasan: disable kasan_strings() kunit test when CONFIG_FORTIFY_SOURCE enabled
Date: Thu, 31 Jul 2025 10:02:46 +0100
Message-Id: <20250731090246.887442-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
triggers __fortify_panic() which kills running task.

This makes failured of kasan_strings() kunit testcase since the
kunit-try-cacth kthread running kasan_string() dies before checking the
fault.

To address this, skip kasan_strings() kunit test when
CONFIG_FORTIFY_SOURCE is enabled.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 mm/kasan/kasan_test_c.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..1577d3edabb4 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1576,6 +1576,12 @@ static void kasan_strings(struct kunit *test)
 	 */
 	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);

+	/*
+	 * Harden common str/mem functions kills the kunit-try-catch thread
+	 * before checking the fault.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_FORTIFY_SOURCE);
+
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);

--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731090246.887442-1-yeoreum.yun%40arm.com.
