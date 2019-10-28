Return-Path: <kasan-dev+bncBAABBB5L3HWQKGQEFA2S55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 39C66E6AE3
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 03:42:17 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id l1sf3143295ywe.19
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Oct 2019 19:42:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572230536; cv=pass;
        d=google.com; s=arc-20160816;
        b=XrQznT/iz7nYrx58ztU3NSiECsO1ixSG7aF9ISEAQyZQEJ/uepb0CPtWzeBZ3JbVtG
         Y46igGjmGbBJm4prooAcILGf2TqkJty1wkeOnVNpxpgUVyIl8283bDg+SpgFWz+MrA5q
         YUmrAP5D4kEYBmzlT2nu4CaGkhCkss7scIn0OsmTyUKuY/0Gu7iegNuJ43IZC4uBHuPo
         rIlScgSOoScXD+lmpqpukqrmUPDcPzYdwdIUVwStnmyP/+r9sfXZ3x/WYKm2VLB1D5Mp
         zmuOThm+TJZRjepfPBhpgBywLq3xHfqjnIIM3FP2N+w85AV70rM8fYbpueqoXAZw5Laf
         SaSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FOa/LyoTMpixVqpSAX0HKpIXwWSVl+gs/+tfuHuhyAI=;
        b=iawtNYLSXfenlGRXBp5qYvG06UXw0qK3zCbA6RySQwlr/EHYPw0Q+Nc5bkCE074AYX
         iPWLv2AF/IJRVZRvwAPQ/LkgLtIFD8rlAZxDb5mSi50nSoM9Gx6BEFFunCCvh9JAHCxt
         Tj3zBqBTkLGN8SsvrG5/zl0YCRi+spGMPBo4mjgboj4l1O/UP7kv6oDL2wslV93s35ry
         VljzfzM1zlxfqlUlPhNWfDFG6QLfAprs+yVMEWM9VMTj946e5HUw1uu/NJwtpy5aKrAU
         hJ5oJW6PbjQbqr987bVpqGlppUF9CtvVk2H4vlRv2oYqCD20/6k59RsKaY+RkY+9W37q
         XDLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOa/LyoTMpixVqpSAX0HKpIXwWSVl+gs/+tfuHuhyAI=;
        b=bvO0JKDVyaFo6hNFHkRpKhafsTheg43c7UMBGfTH7KD4GuWbigLIG4Fh2JmIXUwlKB
         y9Qhe9llI3q+Ts1mcXpH2aCQh2x5kHwk6xLDSYXLm5X79PeiDxIFKocXSZqigdU7Mx11
         pVZajjzkPHLPIKZpF7s1K6I1jBmCY/Z0RWcn6v5xphPIC6kwvlBPBlBJnSlTnhyq7PKF
         G5YTd/8dlAoG8PJRopZlxFZZHgjjJX3QJb06f61rrCbzQ9qW1P4ThXm8jE/eAaX6dejy
         M5BKPjDQTcqCRerDWOHhEr0pDDbxN3EZP0e+rhmFWzTCqcW3wiLEqtMk6ppVnRbN3dfB
         bg+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOa/LyoTMpixVqpSAX0HKpIXwWSVl+gs/+tfuHuhyAI=;
        b=JqGfPopb6jU1nDFkuhQNEYIF3Xd+V3ObRSDn3XtZMqFYERSMxH8oozAWBebVx2WWMe
         MtXqHWN8JU8BpLuM2AR6hO0+yD4dLMJ7TQZ36N9OF9WJtC6ArwYK9YrC5sIE4+l9g9ZO
         vW5vL6CG4i20l5zZ4Rtncca5/aQqwKU4u2OaBNG43kP5UT5Xk9wsHcemGu23hn0McYL1
         RivP6MNYVDN/QXW5tfeXi4W5/3xrG4Y/XlcD8E7A6mtm4vgnytvZpJOJ5YAEwQOxzHmu
         B70GcOSVSKsoa516URiLU5+kfbpBaIZMOLpD1gpdp/Wreckq8awUq0qwdq7iEKjRvWbw
         rG6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV0y/UhkLlupNGH0tUR3WQLmmfmC9S9Jl5RwrTVs8Hp+8dDXlg+
	dFom/3Z/5cXowUptWi1G4F0=
X-Google-Smtp-Source: APXvYqy8PP833LFBDfi7kllPNEblbAJA74iyf1JebF+F3UcHXA9HA6nIuYdZeumrVYNucDjiwEhQlw==
X-Received: by 2002:a81:1dcb:: with SMTP id d194mr950268ywd.248.1572230535891;
        Sun, 27 Oct 2019 19:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e54:: with SMTP id j81ls2459613ybc.11.gmail; Sun, 27
 Oct 2019 19:42:15 -0700 (PDT)
X-Received: by 2002:a25:5346:: with SMTP id h67mr13090236ybb.365.1572230535532;
        Sun, 27 Oct 2019 19:42:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572230535; cv=none;
        d=google.com; s=arc-20160816;
        b=TzkHAi4tFh/UjfRIGfyQWpb9ailj/pU1N2o5J0N06rtA7RZbQmnE9hXbJqzPLAlvvE
         2l2PRCRNXbPB9MRARjR49OYnd4HBy1Xu1Jb8dV+Sp2OQLjZHztIHJL20JaZKFKCh5kdi
         xzhNY5Oqxy732fuziyurZuO4M8iEAzCWYgkg7aJiwPv8pZ5yRdVLy/CSSGR4FmpzdNMk
         fS70/40pMyvpsNo7lqAlZKf73G1HOgWXkzGZLycF2ptDJXHsKxm4AZ3kx1PQJwTK7rGh
         FbNWLbegI9kA9dgCVTgJKtp7kRyVjmd26p7cFIApkLbVfCi7Y8wRO0v0HOJQqb0z+FqU
         u/zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=yRjuma5UGlXgnJJhwq9b6CPNlwqZXPQmv0iTUFFsrQc=;
        b=nMmwU2uNShUPoRonwoCgOVXZPoXSdPWLlEFe/rsC93gJjW/O9iyafUtzxLgUtrniIM
         jQvv7sjUdnvOfDokBMywKc4AxPPwJMwTSPedMKCf7V0ZmrMCD/isQN/fqS244n5BWH6e
         6vLmPpyMtoFAb7Y6gYtaeisLYsjETpuu4Y1k1cjWXNJFLx/OD5l+KIYnnPKwIwOCvW7A
         F4WRkt61moRz3X/H8gUAw03aKGBf+i4Z62t1VHl4i2x/b3BAM+6gdoj12aF3APDMPtNq
         38EmMMhRrZGnZotniq1kpBL0oOQEVPwXDoVFGxTmXKLlbfhGCbxQDoI0J19Cozonj9eb
         Sr4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id d192si568024ywb.1.2019.10.27.19.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Oct 2019 19:42:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9S2OTh5087266;
	Mon, 28 Oct 2019 10:24:29 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Mon, 28 Oct 2019
 10:41:57 +0800
From: Nick Hu <nickhu@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <corbet@lwn.net>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <alankao@andestech.com>,
        <Anup.Patel@wdc.com>, <atish.patra@wdc.com>,
        <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <linux-mm@kvack.org>, <green.hu@gmail.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v4 3/3] kasan: Add riscv to KASAN documentation.
Date: Mon, 28 Oct 2019 10:41:01 +0800
Message-ID: <20191028024101.26655-4-nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <20191028024101.26655-1-nickhu@andestech.com>
References: <20191028024101.26655-1-nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9S2OTh5087266
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Add riscv to the KASAN documentation to mention that riscv
is supporting generic kasan now.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..34fbb7212cbc 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -21,8 +21,8 @@ global variables yet.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
+riscv architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191028024101.26655-4-nickhu%40andestech.com.
