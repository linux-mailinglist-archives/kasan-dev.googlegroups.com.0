Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVGSWAAMGQENB65LQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E54AF2F9BD1
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:22:10 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id u9sf1892618wmj.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 01:22:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610961730; cv=pass;
        d=google.com; s=arc-20160816;
        b=WZMoCGGgwngMBXA8chyiqM+b4FTeM1JDR5XFVn+zg7uBKlsurZgHIwyQqChsqeXVQ3
         vvxOJ7ufl1YDtGkCj6kY8921QwcdGvtYZytg5rGynaOzGrY1M6gMG6vw/U5EX46bcGaj
         h1m8h7bBw7Pvj9QTGLaSE+K1WikC7nvtKm4mHe+PCdCnfWazq2KLEZESn9gONrKbuJ+E
         ft5FBsoXjKaKM/6pla7cPksgnHZPCkPSoQ8mwk3HL8RXcmqFq3r78gIxq4xAKOMUv+Ki
         +k15inSWoXPY6M517lAeIdVNRr03WpG5uf3PnssHXWX2Z12Zz+aAVifrU5BuhC8HNBMb
         GnlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=znQBRl3OD2xhlpq2Pv9+ZDnovXLlxeio51ZYTb0C1SA=;
        b=mXx+1Reuab1OLtc281QGydNwmYjJ4St5qd0JjBUsNike0TWWLDmoNk2LtD7CqICJZY
         QFfZKiEuF2Kph+WE6BNlC6DNJImtxTxjAefOpeZuUTbItCNlAKOBdjN8brdkjS2jmlzS
         +wG/L77N6sGoLV4SkP3hq+ofPwYODR1UXR/+aAh550u778mWK+U7IrSp0Xm/lGYxqW21
         uR5d0XCUzyjd398gUGJ0n/Nf6jmx2l2eUEHpZut1Pe/x4z66U/SlvZaIadfPv315w0Ov
         uu82TfcatKHX6T3rwDVrWcQz5702fcPQemE7WcyuduTplbs1UwPfX28HSHz1WpUYDR5B
         zbWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uXQQtcl2;
       spf=pass (google.com: domain of 3qvmfyaukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QVMFYAUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=znQBRl3OD2xhlpq2Pv9+ZDnovXLlxeio51ZYTb0C1SA=;
        b=h8aXnB3PTqfYDnwCpi/FRAPXYd9hVhdZUUVC9dKAjlQbv3FAioaRIld7al/cG9FB7o
         lFApqgw8+LOXQO406e7WD/mfUeha1MlG9aAbBIXfya4eqn9CwiqnQhwz7gXSTQTb5xoZ
         m6Dxm9nikR1W9eHjrT9Lp4WlqgdEjk265JOob+nY5Od/w3VGnQndhmjY+ZA2IX3GQVYj
         fPzGs7zkzc+qczFMjebJ4nNvhpeIG7vpiDvs+rw//4e9RVCOQYgXVqeeYp68t/m8A9Qm
         ji0K1+t2LmvlMZkpx8l9QFMXnEg0pozGU+n/IwE7gnWBsT9OrWSfBclILt/+T/fmWLsf
         lB6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=znQBRl3OD2xhlpq2Pv9+ZDnovXLlxeio51ZYTb0C1SA=;
        b=iCU+S2ZUgIOU4lIEw2Q0zcmo2T/op31Ua9f05LT7hbxquuDDYbb/V9iDq9ppmuz8a1
         LCJHWpWvihE98fM+USlVEMkEQ5zlJ3ZoA5LovY8VCwde67pumDOJB6ZoH1ylFdbcBfmq
         H0ErrL2Pip3vMHXin1VGbd1ZRjUraXA2B056z0CN3XFRPp0qG0QVb/S8+KCXmS301XHV
         7zOA2zQPaoJ1N5eFogHGhFkR5kIeaeIoLDx3VdCDNrx0CK7cwisxN9ELdJVZLfdsGy41
         ++WCSfNV26p3JptlP9ymeFQC+VOHX2dSHPFQwmkOTiK7KtAMXOMAAKKQjjvw0SrYbebi
         6EIg==
X-Gm-Message-State: AOAM530eD4MU2d6MRmZ7fOc94q+6vxKXx8CdI336nd64PTUynQ5irGbk
	XAZ4M69+6Ot7U0baiHmIAaI=
X-Google-Smtp-Source: ABdhPJwaIAGCMGtzLgdJCW6p4A1+gSHPSI0SydsMR1lAt8M6Z91NsF2GDENt6gHBLEmHiRJ3vWMf4g==
X-Received: by 2002:adf:e406:: with SMTP id g6mr25098205wrm.255.1610961730722;
        Mon, 18 Jan 2021 01:22:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c191:: with SMTP id y17ls1821727wmi.3.canary-gmail; Mon,
 18 Jan 2021 01:22:09 -0800 (PST)
X-Received: by 2002:a1c:5941:: with SMTP id n62mr19910115wmb.63.1610961729747;
        Mon, 18 Jan 2021 01:22:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610961729; cv=none;
        d=google.com; s=arc-20160816;
        b=0v30jtb7MAfMxc+WYYDKMvCwqARUbrI9H3Uvcsse3bCj8uopxuYNLK0GRtT2DWyRWj
         ZnXMbaAmufAvkofW34swm+AS6ZbN+yiWZImGw6gJYq7ridJKnXLHYMp5VCAIyvFzVxBD
         MYp4Fv5W8Npau7EouR/GXeqHWW6Ll/pDSKf55qNz+0T2qKFZg6MTcTvAdRK3tRouiSBI
         PeYbZsd12G1X6x0ec98IM3MP5DpVVunr/U73/9F/fE296DZNUykTxtBLir4vlqfRjftW
         n29mKJJKNJLrAl2bgJ5RFv5p0c+DHgbQHErWgrlHl+bctfAHWwlPh5zcLbwQnh9F3wU6
         vDSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hkWRLHOHbnA69ZqWFvUpIIVeHgC2CbanywSC7oN8uXE=;
        b=fO/KdPNZEOfd8Z+WJYiDF5Vn0pzmZy54ZKKjebAX1d2vcapu+Qg26Ogn27pJSjURO9
         oZyDjH0AVzM5aIU6ee2gLWoabMLXbgfMlt5BOdf5jWsibNLiOLxTolacxpHyNai9orCe
         x2u3o0pKBrvNRqGuOVeQO3gBNumCm/IiAz2cjDfAUteQjV+peTvg4lDS9JROtjqS92vn
         rsujITyC8t0sJZiYE7LrzvdgZywiXrP9JEtOZI/z8t5oTLLu4zlmMgttw1kcq59cCvK9
         m757pzQUtGFzaVZQRlrXdlDSd+Tc8V4UA6d/RY54MseQrydezB825w3svZaES3NNZM7M
         c3AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uXQQtcl2;
       spf=pass (google.com: domain of 3qvmfyaukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QVMFYAUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j133si339773wma.2.2021.01.18.01.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 01:22:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qvmfyaukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q2so8008246wrp.4
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 01:22:09 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:600c:19c7:: with SMTP id
 u7mr9181180wmq.122.1610961729366; Mon, 18 Jan 2021 01:22:09 -0800 (PST)
Date: Mon, 18 Jan 2021 10:21:58 +0100
In-Reply-To: <20210118092159.145934-1-elver@google.com>
Message-Id: <20210118092159.145934-3-elver@google.com>
Mime-Version: 1.0
References: <20210118092159.145934-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 3/4] kfence, arm64: add missing copyright and description header
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uXQQtcl2;       spf=pass
 (google.com: domain of 3qvmfyaukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QVMFYAUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

	arm64, kfence: enable KFENCE for ARM64
---
 arch/arm64/include/asm/kfence.h | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index 6c0afeeab635..d061176d57ea 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -1,4 +1,9 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * arm64 KFENCE support.
+ *
+ * Copyright (C) 2020, Google LLC.
+ */
 
 #ifndef __ASM_KFENCE_H
 #define __ASM_KFENCE_H
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118092159.145934-3-elver%40google.com.
