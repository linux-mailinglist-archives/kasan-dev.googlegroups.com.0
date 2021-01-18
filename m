Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQFGSWAAMGQE2YFWJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4D62F9BD0
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:22:08 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id b8sf7995842wrv.14
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 01:22:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610961728; cv=pass;
        d=google.com; s=arc-20160816;
        b=eK2Ap1mCbkzUtsPZPqTPDXtAQs8cct6BqyYXlubBdTHO3ZNCMBfWB4VHttyiYh8f2k
         oRLsr+T+YMflK4oboZ5i/jxOatIRig49bddwSewT6sgPMQPrhvoepl6KN69aOh3hPeBL
         f58SWMXRw2e7eRahwmhWrb7OhHFcdMNrlc4DXQMn3SrQ6aqpQFhXyUwLHXhr9IcWHxQt
         ixjIc16IMqNhfoS3Th9cmtTrmPzymHcZo2xjVAZMYnkKZYBLCouI7iK5GC3miZPwLvP4
         38JXW+b1mCmBbBN7amrAENL8JJTmGh8xjA8CAXqpPYkUty6LuUfASbxS7J78H3POVvxm
         l1Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=94KNNSgQrp9cQIM7M8IYuzIJOFEns/Tz2P1OpTss3IU=;
        b=RdDWCw3kddbUdlKS30m81ry63P3sjaQtViL+Md4RVdQX5O5BFFZ8BWl9F5BSSKZg6Q
         +/NPC2qNdOPZzwvVBwyJ6QovFAf32J107OMqmACwLaJcMOddy1Y2NKTitGG3SkupaClR
         p7uyT/jjPWLGujPRIMAdz6OPtE9ic9G1wdg12wz43RkjbcNFN3+UBpkR6D1i9z+XNgqX
         Zu4Af/XGiq/1VvKex2ly9jQ5e66YEiduErrz4ZahvPa6vz8m2hJxqYl8dMhJv4Dz/ThE
         GphRWb4B1o5rSvsvyNdYGnPs+POwpQKCvOcBN7UYLzetD4eggrdtyxeTCtpQn64jJ9kw
         oI3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVEk3tns;
       spf=pass (google.com: domain of 3plmfyaukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PlMFYAUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=94KNNSgQrp9cQIM7M8IYuzIJOFEns/Tz2P1OpTss3IU=;
        b=gCBadzuremIOb8N64hno/W+p+JGrtO+IFjjoSvKrjx2ocZTjEbswwj8T2UdHZbOql5
         HyqpU/EGpOtyJc+J/vpDVnx2dP9zTkhMyev6CqSC8NN5Ry0ntXH6cMTmDeaRDFoUOvki
         Cr0xzk94uGrkOzfnM9Vt8o5RxYar3HxfTBXnI+PASZHuRj+oAl86lDIjzDCAQp974SDl
         vNgTsqyW3NGVJ1AVKxrOrTZZUbptdNLYnoSsRpANpx1r6C11bUZr6pFupTcYn5kJMGNU
         ZhycloKMHbRUwhp9yS6f3eg2RHlkeG4T/kGKxs5Z4mDhzThntdux1emVDcOTChDPyf7F
         3iow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=94KNNSgQrp9cQIM7M8IYuzIJOFEns/Tz2P1OpTss3IU=;
        b=cLr6A1Moe2nIi7XQHMIpDQpFVK5gMu3JvXW+EHXnbxHURm4U62q65Bwm79FMc9ixSo
         TX1j3n8u57x6Olp4zELgKpaQTcnKwOWHIHnJUPGnGdn/UrboeB4xawXYewXktm9s3jJl
         0PPR7wub7ksv+KJETWrSDIHcHun9fi0YY7oBHJ6XLNJP4G1xvsbyhHip3psqvsOOGK5e
         WmA8CS74KJqHp3pkcm+McXwVsm7458xmvnZS+jMTk0IRhjnL+8OQt3xnqJm/3ZdauRvr
         PIeEotwmLbuRdYUsu38uJrJYS7C7H+1LkDWHCxF5fMOKpvzvB1SiVL+XmUagwuC7yG8w
         zahQ==
X-Gm-Message-State: AOAM530wxW5uM6VXMOzJg8pMjfQi5p6Au+TlD4+VKvGW+LyjF+wT+Ev1
	5m+zCd05V38sOS3Iao1dgfk=
X-Google-Smtp-Source: ABdhPJxs4i5kYCR/fQ9Ku5nUYCHlugAIBvD1Znl/RbF9WnrbATGXv/OaXC2q4iXXUAWHk867I61EWA==
X-Received: by 2002:a5d:6289:: with SMTP id k9mr25925014wru.200.1610961728185;
        Mon, 18 Jan 2021 01:22:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e608:: with SMTP id p8ls7793957wrm.2.gmail; Mon, 18 Jan
 2021 01:22:07 -0800 (PST)
X-Received: by 2002:adf:fa0f:: with SMTP id m15mr24843535wrr.300.1610961727215;
        Mon, 18 Jan 2021 01:22:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610961727; cv=none;
        d=google.com; s=arc-20160816;
        b=fb27b0+4YLgt9n5widPaL/J2NWcQWq5LAXzWdWq8pXfHFtf+B15m20+Q5czPdjM0GC
         Z7nl4/9LYzURaS5EPA9ZZFlvAaKcDD2I2vtmHH6VB6hntQ2iqy2Ah/rBfzNUBWH6hOiy
         91m5k6Onsps1/PrZKmJA4ZQXqceJqtr+vwjKTHAr2e1l/LEVgXaI6ZXj5Mdl/rza5Qbk
         vNGwXwyWSgNu64BYPcNpCvqNYVRWS5lmmv6u1ZybAsGwSp7IeyhwZNkvdh0aGE9hLleq
         V5aLg7WNSb3F7q4UZM6JGeVQh9fiuEE2+WwLfobe2jXI/Eu8VxNXoF7l3V78BT5m8upK
         1YHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IZxX31YwQJxY4qKXB8kaGSAyfVufijU5UZLnTc03xew=;
        b=iifEmdj/T/inLuV//PmgLH2LlZHT4BRgceJhIEbhJZg3HgiEHltoyRF7wvaZRz/gKc
         po2aWuuM7E9y4KK8owMsjXASmkTI7jA/lWXe2IMNMTMrvwPPBH0UOrts3IMF4q8x+tyE
         S0p2dKNbTvBqGk6Jo/aPRbu2eKmuzJZSV8mXJlAl4f5t7GgYOfGh20RxxZqALoFQkjtH
         X1xXbN7d+7ElOr3VTg4cksYdnm16zvo3drioxmjzqtVpor5Gh2mm6n4nF3mfCC5sf+UC
         XxfkELyhVmXhWazE1HiBwypm85d6YBhLZazkOGpasTBnQkNkJ2vODsHb47EoS+6qCFHm
         idSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVEk3tns;
       spf=pass (google.com: domain of 3plmfyaukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PlMFYAUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id s74si707184wme.0.2021.01.18.01.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 01:22:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3plmfyaukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v5so8010273wrr.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 01:22:07 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:adf:f60b:: with SMTP id t11mr25193199wrp.401.1610961726705;
 Mon, 18 Jan 2021 01:22:06 -0800 (PST)
Date: Mon, 18 Jan 2021 10:21:57 +0100
In-Reply-To: <20210118092159.145934-1-elver@google.com>
Message-Id: <20210118092159.145934-2-elver@google.com>
Mime-Version: 1.0
References: <20210118092159.145934-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 2/4] kfence, x86: add missing copyright and description header
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PVEk3tns;       spf=pass
 (google.com: domain of 3plmfyaukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PlMFYAUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

Add missing copyright and description header to KFENCE source file.

Signed-off-by: Marco Elver <elver@google.com>
---
If appropriate, to be squashed into:

	x86, kfence: enable KFENCE for x86
---
 arch/x86/include/asm/kfence.h | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index 2f3f877a7a5c..97bbb4a9083a 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -1,4 +1,9 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * x86 KFENCE support.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #ifndef _ASM_X86_KFENCE_H
 #define _ASM_X86_KFENCE_H
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118092159.145934-2-elver%40google.com.
