Return-Path: <kasan-dev+bncBCRKFI7J2AJRBJEVTCEQMGQEFODTM7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B00E3F718D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:17:25 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id u22-20020a5d9f560000b02905058dc6c376sf10458715iot.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883044; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePoMkjrmapbJGd3RqfBweVZihNVImAPyIA6qLNNbDg8QXZ9pX3s6AWVFZ6DCa6c7WL
         DT4JeHk5c8X9DGs0YvRadFlKuXdwPmX2Aj0vFRLtJCudD3ze0tJrJ6kL0KGg94CwpFBV
         gBPYHFYQJi/HpjkBPbnU2/dQN4vBcqXmIL8M2NvE3VtIWX/eEfW1RrM8d9BGue7hliF1
         lDqC7W3B+3BVrTdvfrrJm06dZnNXNIxY0OvC4D8J1mNrRg+odURiCllPjPwKRdSpLiw0
         9+j0ropg98v9inUzKOA64rcsCGlq+sShBGFZs6jnkuSzd6BRjFZQCZ1HPlusJNetoFfr
         KDgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dUSHZTNI1RuN0Tphqil148pxqGldKrtrOFIdA6nVJJ4=;
        b=zwXcNrgMiTKJSWdUBbiuP3GxgC0Xz5Lb8x4LhCuuXperjDZQghu3W03u0zpoJZu31r
         s7fJzIPWE5pm1q9Zl2AuqlvlrbZG1Im0mC/G5xgPSDi1RxvsAm783FBFn0TK4rAmWvZ5
         ytpvQMEz0DKT+5NcpxpCb613j7ZzSBh8XAbK7+klu2AJJlwYm0VRLFaZ5GM0EF1uGY1s
         +jt8fV/9wE7LnZXDerl/DW3hn5P7gqZMDdD/jxj4akQchV24HdyvrXXYPdf9POcX24bR
         RRB7vaP5xAxREH2Dxuk0N/MzraKaC3+zpbvadkZcwat+eTR7Cs7ROXD++Yv9xrsNUQ5S
         mA6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dUSHZTNI1RuN0Tphqil148pxqGldKrtrOFIdA6nVJJ4=;
        b=RPJK2oVaOKs7kbDkENziPOiTUfPpK0YqDIuf4x5Ddiqy55sSuqKTYfdyyxKwGRNve8
         soreMUFDFimk4Uy73bUe+/03V9vl4kCUlQUZt2WbsO9BXHhwYb8yH+Gqb2WbDDYCe3nx
         YZVKRHEk3uw48XY6cL+yqytoNnl5TkYt6r5PS1Y/uTv++ncCcJIvIIoG+L738VrCKAJY
         +P0fsmHma+3VfvrZyqScZ+ZwZqwCjXOqkzuyTO8mymVY75uYpCqdnL0AC5VJdH7ExLc1
         WjGeAUhN9DBDCjYlDb5Tinwg4YqEJqfy5X9P9IF2moN/f/dVFO+NB3//xGThBiFa71Sk
         KJVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dUSHZTNI1RuN0Tphqil148pxqGldKrtrOFIdA6nVJJ4=;
        b=EU64xMm7onFJaJeGNqLalih6vPVJjSVPjwQEmIAYuUQIctSPxJE2yoRpAmUBHOpHlz
         2UsHfifBBurTKVmJqpGG/KoLPEqlAjvftGhgZieju+rrseMjJngypYFZc+aZfsls6Vdw
         gsyzmoSyMEDFpwINjICUk75MrUdV1DfHmhX/VoqHGuiMLjPCF5xJMcdTul8xes2/kkWv
         sneM/2TROpcGaObaNrce+42mks3rZgE6OPoa2W3cs8fja561aXC4yiocyOS7QPD+sRC1
         8qeuRos6fNUoy8+Ydxmn3F/bMtrxnYzQcqDf7zlU1YCtTnt00nD8S/ypPmFWGEYzfR/a
         dECA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GowCX93tL8ablTUxKjdW+y1wllXqc9+U329qkilhvnPHheyBi
	uDjMb1WoNgA6otT+fBeQa18=
X-Google-Smtp-Source: ABdhPJwLTu3zecWCL+akG1DA35So4oexPvK4i0Zd2nOR/mfdafZxNNx3mpywaigV+9Gusgy8KuGMgg==
X-Received: by 2002:a92:d3cf:: with SMTP id c15mr29633964ilh.131.1629883044493;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ad09:: with SMTP id w9ls338935ilh.10.gmail; Wed, 25 Aug
 2021 02:17:24 -0700 (PDT)
X-Received: by 2002:a05:6e02:531:: with SMTP id h17mr30068233ils.288.1629883044208;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883044; cv=none;
        d=google.com; s=arc-20160816;
        b=I9X7j7mHahdjhGADE0TBFCIPNdR07b8mxG5iHpFJBeW3H1P6RR0I3yilPyjxLfErLs
         6v32v/PlaQfXRazWsu6/VPk5JjOIXwJsJh7p8GS6uU2lvF6eqJGXFuQao9lgaRjxgWt2
         Yfr49erVaLjEfHDT74pSF/S5yAbOFuUPDZuwuDSPlJs3Syl4r7kNPj7GMaIB0lMmBgvz
         bI57Qt5v1QtThuP6wSfEgHQZ7PUW1ASja4URG6AGFZoNYjYOsrRTOgLKKK78AyL+XRrQ
         YutG0Q5Dv74cCmLpN9xdnm3Chy23coiL0CYkStRmgx4GSafbwlXp4l0Yk2t6LqvdlvEs
         /Hcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=W3oRoMTidPhjDRcCCniMaWGaIYpEhnY6qyDt5lAbJ24=;
        b=X6VLmXKGc/0ciDRh/c7wK+z0TGzTLePK3yHjc9xuO1nvHRSdn5Kx9h6+bmu9QyOKL8
         P7QEha1y1Iyh2I5DHiY7RCGtVy2lDu+UnJaCPp40BfsHYsk/U/LX0yvG81RHFinvTZlW
         WhSlKRNAL0ZI8d6NnhT4MjS4dC70YcCrYF++ilsrYFpL6KZQdj12hatvQSJ5WDMyPvR9
         yIfYIt7iLM9iXXhCkBJyDWBE6ZndA5NO4cD+WFFbWUKtX/ZpOH8U3HRgRiMmb/dk0BnH
         bjAxqgR4nPuLsR/ra96oU4/wy0p3Vtt1A0v6rbc59MwiTsYe/+efw59tzWmLzT/GNi83
         EmNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id y16si984310ilc.5.2021.08.25.02.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GvgJD5blFzbhGf;
	Wed, 25 Aug 2021 17:13:32 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:22 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:22 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH 4/4] mm: kfence: Only load kfence_test when kfence is enabled
Date: Wed, 25 Aug 2021 17:21:16 +0800
Message-ID: <20210825092116.149975-5-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Provide kfence_is_enabled() helper, only load kfence_test module
when kfence is enabled.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 include/linux/kfence.h  | 2 ++
 mm/kfence/core.c        | 8 ++++++++
 mm/kfence/kfence_test.c | 2 ++
 3 files changed, 12 insertions(+)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 3fe6dd8a18c1..f08f24e8a726 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -22,6 +22,8 @@
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
 
+bool kfence_is_enabled(void);
+
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 #include <linux/static_key.h>
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7a97db8bc8e7..f1aaa7ebdcad 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -51,6 +51,14 @@ static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE
 #endif
 #define MODULE_PARAM_PREFIX "kfence."
 
+bool kfence_is_enabled(void)
+{
+	if (!kfence_sample_interval || !READ_ONCE(kfence_enabled))
+		return false;
+	return true;
+}
+EXPORT_SYMBOL_GPL(kfence_is_enabled);
+
 static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
 {
 	unsigned long num;
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index eb6307c199ea..4087f9f1497e 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -847,6 +847,8 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
  */
 static int __init kfence_test_init(void)
 {
+	if (!kfence_is_enabled())
+		return 0;
 	/*
 	 * Because we want to be able to build the test as a module, we need to
 	 * iterate through all known tracepoints, since the static registration
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-5-wangkefeng.wang%40huawei.com.
