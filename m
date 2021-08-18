Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC4K6SEAMGQEGPLBDXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 41AB63F0426
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 15:03:08 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id d21-20020a05651233d500b003cd423f70efsf576346lfg.23
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 06:03:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629291787; cv=pass;
        d=google.com; s=arc-20160816;
        b=sMu8V5t3ojdYOt8yxgFEMROMiNOnvoo5I7cDF0n8DGohbLiIk0/tAowilTjRyV37/h
         Ex8DksLLChMp0UkD8cgAYeMPPil1uT8L+91KtWbYaHgvglxxw7nvlNLfqNANqrxMGzhQ
         dTDNQAWe3s3PbeRjKrKnsHHJZ8ITgv6m1pwEnKLLtEtl8BhKJc3+SX89gLiUdUeaYhZS
         yuP/gP4JXje0kDiJ/GPnhbmN8U448ZeL7WeVTnOnVwZFZ0Hg7/dQFHqgeKE+BBGycOhz
         TgGy6RRdumKHPwZvJeS7TNX+Sm6yLDHgmMK2+H+Y7nl1Lu5xSFz0eFCG9COxxx3i/5b3
         pKVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=hpy1tx+Hkg4l53geVS7qNDoNBYnfMu8AeKW38brI2MY=;
        b=rKcU5asPLWx+9iTEOXgZGZnxk9bBnQirKWJV/RDuV0d37MH3op4FSoe+sCw9iuM2g2
         /zC/SUy4gHnrkR+D8AZXqQtl4G63eg139hLWkq5l099HDsJEzqtjtjgg5boOAz1tAafO
         OWsL61EEOFRpd7msQ610S4jfnL0tDkRTaMX33eXw/hpUVCkp0x2mzF2ef9IdtfYuPImi
         TroiUE5gxvIDb/KcOXiGgjQT4YRxzJF45Sda/v71hJYvlwrvcmFyuGt06ZYvQZJnNUIh
         sWQaL0GEOoAQ6V/15lhMJOHOGqnNDTbNOv4D9gCcIFuIX2DC25vDKNzELSj89BV0D6y0
         pM/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mUuxo16h;
       spf=pass (google.com: domain of 3cqudyqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CQUdYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hpy1tx+Hkg4l53geVS7qNDoNBYnfMu8AeKW38brI2MY=;
        b=q3wIL5BrA6qCXnHrVaPNY6gFzVTVdaV3Wl1tr42vjk3LPuEnf7PxMnjM/q6Xpm1FqC
         bmIyC6u3eX7YBW/MBwskOQnvCo0pn55EHqikBPuIIdVWJ0nNqjbEyBiEzCKVvg+HWuCT
         Wp5I6TxxLJo3dMVVp0TSN3ZKfDFAxqSOa2R2xZsM95LfBF5WQi89OcSDXPV1AWCGgTlh
         p6Q9XprPG8jYTYKRahuFe+A7AViwW6RsdCBQMCcvBRN83x8QmJ+90QrFw/hLY58SP/xc
         7vIt7Sdf2yHLG2O3rnvQtB8F2uYUskNsmqdcVSDPTxc6mXOwbcaoPA3kv5fyt/QYIV8E
         r9jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hpy1tx+Hkg4l53geVS7qNDoNBYnfMu8AeKW38brI2MY=;
        b=IIJpuTSL+jswtv58DpHvRlVMKOQIBF1/gQ0iNZHgMFzdUI/+fQwSs0yT5ecq/uXvVm
         flc6CNnEMoara/UlnhgMtfT2173MnzLSpaMA3vX+FjhcLwEEXKUdbPo3eRTBBKfJy4Xo
         8UKwjR4cQVoBo1IpUlju7+MdoUpAbdeouA5YvhUcFGn++ajLS/WHD1o294/d0svlUMGk
         mA8W1B0jBtO1j2lbwg7xE7uJinOIdRUTXLJ02Z7UvmLx8Gt/PiKaBtzDvqb6UHcUKOE+
         FQ7xQNB+NvE2wLZPEsfmNk1oynE3TlcmCqqTiqnlVhh1xpiIRgnIDWbdv3VxnW1yKtip
         4FWQ==
X-Gm-Message-State: AOAM530TrdF9MvIPhT/7TLIhuZSEjfJZP9TSCA4QmlJG9zaYofyIihbg
	BbmqukJjxbzRwK+ByW4Rxa4=
X-Google-Smtp-Source: ABdhPJxTFb+c+1OalGbSuNl2oqEi2MwbwZwsqs3b6q8IgfHbq5PM5evXj0RU27sXQOA0DIb4Kes1LA==
X-Received: by 2002:a05:651c:1144:: with SMTP id h4mr7600758ljo.396.1629291787749;
        Wed, 18 Aug 2021 06:03:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf26:: with SMTP id c38ls386929ljr.5.gmail; Wed, 18 Aug
 2021 06:03:06 -0700 (PDT)
X-Received: by 2002:a05:651c:158b:: with SMTP id h11mr7746454ljq.395.1629291786420;
        Wed, 18 Aug 2021 06:03:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629291786; cv=none;
        d=google.com; s=arc-20160816;
        b=w4t9iPQ4zoJkrs2/xHyriTzpWGgHlH7H6MyNFz08B02Rbl7HXsdlD/dHXKWcn8Jm9u
         KA+PS0+CYAIWdZkwHbNuqCSG4tbeGzxWDludf6VoAYp4PgGfJnn76t6HDdggXaQqWvPF
         VlfAs5CjXkpSDpksql9mE+8c8K+NzzQMvRRj8oZSLH/3vhi0TMrzk7z9PTKEB7i45TyV
         j8H22olemd50n1PH9qsazVMtlpxVTlfR/P0KcZHzGRZm81HTiehIaz03cpvjm9TE36u2
         yCqGFRwYMTzF4eMIZe/qCgzhZ1877veeptoHku9oc3pE719N6BmFtht5cGfI2+eTo+bf
         Oxag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=RrG3CyO9Gjt37gk9O8igCLRvqsHUd/YOk6xR8PM41xQ=;
        b=WseRZQT99IyHEkiRBHms85pp+wfMZ1XlmyQNPe5Nf9rIQLXM+2vsClDG1Ru7cykLdZ
         u/wxqHHLkzY19KWFYEH63BNEdmPZb86dw9kvHBTta9D9fNEYagpIHjJDSkEywI84jevT
         ZsH9ctLWOhYRyBpIxK+JXe4UlKAKmryOqcUUzqeij7UMKXXdPvJn9yiyFe7RxsFO0RKA
         fS+M3pMaSFN31q/dDCglmMIznE7/IlvOoYnTPYiZV/+ztb8eNzsGfnaZpZbzgUz4xnuZ
         hPSSnBi57ivBCFpV0IfyP0b2XBSVikjhT+R5cOjdCpcVZeYa16sG7HenU5d13ce3fAYH
         Ue8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mUuxo16h;
       spf=pass (google.com: domain of 3cqudyqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CQUdYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id q8si267895ljb.6.2021.08.18.06.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Aug 2021 06:03:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cqudyqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z186-20020a1c7ec30000b02902e6a27a9962so2220987wmc.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Aug 2021 06:03:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:52dc:2f6d:34df:96a5])
 (user=elver job=sendgmr) by 2002:a05:600c:35d3:: with SMTP id
 r19mr574288wmq.1.1629291785265; Wed, 18 Aug 2021 06:03:05 -0700 (PDT)
Date: Wed, 18 Aug 2021 15:03:00 +0200
Message-Id: <20210818130300.2482437-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.rc1.237.g0d66db33f3-goog
Subject: [PATCH] kfence: fix is_kfence_address() for addresses below KFENCE_POOL_SIZE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mUuxo16h;       spf=pass
 (google.com: domain of 3cqudyqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CQUdYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Originally the addr != NULL check was meant to take care of the case
where __kfence_pool == NULL (KFENCE is disabled). However, this does not
work for addresses where addr > 0 && addr < KFENCE_POOL_SIZE.

This can be the case on NULL-deref where addr > 0 && addr < PAGE_SIZE or
any other faulting access with addr < KFENCE_POOL_SIZE. While the kernel
would likely crash, the stack traces and report might be confusing due
to double faults upon KFENCE's attempt to unprotect such an address.

Fix it by just checking that __kfence_pool != NULL instead.

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Reported-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Signed-off-by: Marco Elver <elver@google.com>
Cc: <stable@vger.kernel.org>    [5.12+]
---
 include/linux/kfence.h | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index a70d1ea03532..3fe6dd8a18c1 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -51,10 +51,11 @@ extern atomic_t kfence_allocation_gate;
 static __always_inline bool is_kfence_address(const void *addr)
 {
 	/*
-	 * The non-NULL check is required in case the __kfence_pool pointer was
-	 * never initialized; keep it in the slow-path after the range-check.
+	 * The __kfence_pool != NULL check is required to deal with the case
+	 * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
+	 * the slow-path after the range-check!
 	 */
-	return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && addr);
+	return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
 }
 
 /**
-- 
2.33.0.rc1.237.g0d66db33f3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210818130300.2482437-1-elver%40google.com.
