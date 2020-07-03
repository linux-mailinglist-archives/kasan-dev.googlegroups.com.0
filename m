Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYHK7T3QKGQETZ2Y7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DAAE5213B3D
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 15:40:48 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id d11sf14144295wrw.12
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 06:40:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593783648; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNWgU10mO6z7bfsjciVYmqaclmKUdD225WVC8Qzz/vxps0sASn1sOOjKRO7viL/zjt
         xb1kAo4BaSy0N3TO+4l8iLfyqulovhwEVlN3TY2mVe8x7M00CtHD2AceUQX8WaNdFh8d
         mHVN90dgAVCSpAf6quua1grINUQwNhjvC3zMyDpbgsoRCSFOACjWiXy/9MSo+99pJRQ0
         +1AuyKA1i3NLY2JS19kEIAceDyrgA80qlTRUowmocTZ9XoXvk1aCG4gyNAheaxvfG6TJ
         Row/wMfzAhhrVd1Skxh1bJiVR+M4EuQFfyWRD3joei+D6IePHqgj99RQw6rFr/nJX70I
         D7CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=epLQv/njx+Y5a2qvKLUGvKyHH9OMcFSWqJjwTuFjO7Y=;
        b=rrW1e74dDvJDpsRGGerxBCfJXjqoV38MPdYpn7wJf2qI+/uzSYWBaddemOV7aYPARk
         rMyPBAqQBDDVysBE0WFM96pgyIl3FbKkRk1qurmSx8uo+p234/LWzL5lZnVTYi5y7kQ3
         6x/sDohS/duzXdJp/aLM9BW0sxSYwL6bjkgdeYSFhr8m6ZvGFQbC2Kz7xlZ2Zp3cPsaO
         67i8TpuyH7a9uyEZFyrGaHU0LDJJTCj1JEsQZeD/Qyc9M3iiXgDw3geVRRRt7MjB/0dl
         dntJkWC7oLJscDbSOicO/pI0L5yM0KkpLMWer+SqMsslUhZDnlJ41rlsuNd6//echuHd
         YwiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f3HS4AQx;
       spf=pass (google.com: domain of 3xzx_xgukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XzX_XgUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=epLQv/njx+Y5a2qvKLUGvKyHH9OMcFSWqJjwTuFjO7Y=;
        b=QNgTIpYE/FMiQoZDuJq0D/Za9Od9ZgMHuseIt7c8TT/M4zlz9O1/JtLzbf8PEjarES
         mW3CDQB2m4bx3+hZDeAxW8VraBNseTInWeWzhl++QN8X5g/POqlaEC0msmyqkiky7hk/
         EIDB4uXu8wT+kQA2c6W5P05QKmW3w9iNmNKN8okhyvwG3PmYvsh0bR8AHoPFI/ECW7f/
         czcFaDgxbk/HPukb8lreNh5jRMcTPQPMnJPTHHppeHmhgEPj/2PAokP2ypPkW+XUsnod
         ududeMh+KQ0ASw6HMxkiyfJ9MvE4xB9XkmJ2zbr5DWaEdUl2FnrQv20TMgA6aJXGRX8h
         e/3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=epLQv/njx+Y5a2qvKLUGvKyHH9OMcFSWqJjwTuFjO7Y=;
        b=dHZiGCmzBNdUDlmXNE66tKor3t8mDYu8MBI+7zAJp5yeZbWF6wVFWBVsCyn8zmoUUA
         Q9kZYDHgkbRB/op1xwDnlzXYRsw6QlO73FXRILyJI+wUKSwwUwKNj//Gv+vvIIJR9SlW
         0YsnDnPkbBX+mSp0BBQuSt7049unl5H8+pp6h8N7HvSIrLmAAaKWL6RBk97SAPE4ryn0
         e2XnpVIor3dBQLm/QZgyRHboZcnw7xNlIqhHyrZgMyXbYNZYx9ciwwmurxYNrfA/+rBB
         XUNq4tf4RoSlmYxJR8qIeKZTxODNgf7F7LO/o7mG0+VMjEdi13Awe0FhZKHGmw0o8RrO
         hHYg==
X-Gm-Message-State: AOAM532ADnlFglVufNsMogClFezS//DZZVYgirJ7ZysOXBNK1P/wI0kO
	tElSxxI/SVFxy+ZpgUYGsSo=
X-Google-Smtp-Source: ABdhPJyavgAIujgvJ9+rEnbuLA96k5y7RW1BEJy9Fw9SbLFnEMuNryhxJpjkIAf+4loczSHbPaCthw==
X-Received: by 2002:adf:f082:: with SMTP id n2mr38968178wro.326.1593783648642;
        Fri, 03 Jul 2020 06:40:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6507:: with SMTP id x7ls1394818wru.0.gmail; Fri, 03 Jul
 2020 06:40:48 -0700 (PDT)
X-Received: by 2002:adf:ecc8:: with SMTP id s8mr37441352wro.317.1593783648124;
        Fri, 03 Jul 2020 06:40:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593783648; cv=none;
        d=google.com; s=arc-20160816;
        b=XDE4jg2bFtbeq90/1wxqVpTXepFZ6EqYPBg25GeDBn5T49HXcrfMPxE5cM816H0N87
         N+mILInLk8OD3oMSfDO+Y4QQRKX9hQMt8bRPTYGXX3LoMScv0Nw4JlTLxN22QrOirwUb
         YkRIxxTvAUOUfJ24QPBlD0BNs8FWj6+ABlUD0QLBVG6U26XAHz2WlrYGQnBmjx8k0btJ
         t6A6DE2YSipmmUtLYqho9Hb8wfp2XgTYkckbgpOLbTpuHvX7+iQKfwd3QHxXEdr7mNvl
         ncg36GDAaLyr2G/1G1WN7XbgzZgZJ9BXLi6B3ItMoqHHO4/WHUgVmpvA/0aqjlMYzQcb
         BHdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3lMmHnjpBeXU7bC7LazFD6+XAe//tACHyc53+6mLoHk=;
        b=V/6E1pvpZ/fUy62Hsu4sXUTHDh0b/5NVaNvkNSy4rDE8tqZfAHH8MAddXDEjKpMHqI
         MvthUOlMxwXVN07k9/Trj2bFUZd8ZQx5yQmjP/1DKUro/QqeD+2kugOMn45VIp4GsTnA
         93YbaYZio0yf+B6+JkfTiszPeYZrRH1mxRfHYGVANjloKoh9YdcJUMTw6drPL/nnKdGX
         cSB+2LAyBD5FuuFgYYRA6JEsRf4LwH8GWzIdoQN3E1/HCcuRKji6GyNrG+TG3ss9qkj+
         MzJ5elqg4ycvhSetyC6a1nOv+4k8/sQqJKIePNf+3gBvrQduYXwchyRyGijv+S/7B7rm
         7Swg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f3HS4AQx;
       spf=pass (google.com: domain of 3xzx_xgukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XzX_XgUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y6si581004wrh.5.2020.07.03.06.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jul 2020 06:40:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xzx_xgukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g187so34969371wme.0
        for <kasan-dev@googlegroups.com>; Fri, 03 Jul 2020 06:40:48 -0700 (PDT)
X-Received: by 2002:a1c:6102:: with SMTP id v2mr37906503wmb.6.1593783647766;
 Fri, 03 Jul 2020 06:40:47 -0700 (PDT)
Date: Fri,  3 Jul 2020 15:40:30 +0200
In-Reply-To: <20200703134031.3298135-1-elver@google.com>
Message-Id: <20200703134031.3298135-2-elver@google.com>
Mime-Version: 1.0
References: <20200703134031.3298135-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.212.ge8ba1cc988-goog
Subject: [PATCH 2/3] objtool: Add atomic builtin TSAN instrumentation to
 uaccess whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f3HS4AQx;       spf=pass
 (google.com: domain of 3xzx_xgukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XzX_XgUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Adds the new TSAN functions that may be emitted for atomic builtins to
objtool's uaccess whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 50 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 5e0d70a89fb8..63d8b630c67a 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -528,6 +528,56 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_write4",
 	"__tsan_write8",
 	"__tsan_write16",
+	"__tsan_atomic8_load",
+	"__tsan_atomic16_load",
+	"__tsan_atomic32_load",
+	"__tsan_atomic64_load",
+	"__tsan_atomic8_store",
+	"__tsan_atomic16_store",
+	"__tsan_atomic32_store",
+	"__tsan_atomic64_store",
+	"__tsan_atomic8_exchange",
+	"__tsan_atomic16_exchange",
+	"__tsan_atomic32_exchange",
+	"__tsan_atomic64_exchange",
+	"__tsan_atomic8_fetch_add",
+	"__tsan_atomic16_fetch_add",
+	"__tsan_atomic32_fetch_add",
+	"__tsan_atomic64_fetch_add",
+	"__tsan_atomic8_fetch_sub",
+	"__tsan_atomic16_fetch_sub",
+	"__tsan_atomic32_fetch_sub",
+	"__tsan_atomic64_fetch_sub",
+	"__tsan_atomic8_fetch_and",
+	"__tsan_atomic16_fetch_and",
+	"__tsan_atomic32_fetch_and",
+	"__tsan_atomic64_fetch_and",
+	"__tsan_atomic8_fetch_or",
+	"__tsan_atomic16_fetch_or",
+	"__tsan_atomic32_fetch_or",
+	"__tsan_atomic64_fetch_or",
+	"__tsan_atomic8_fetch_xor",
+	"__tsan_atomic16_fetch_xor",
+	"__tsan_atomic32_fetch_xor",
+	"__tsan_atomic64_fetch_xor",
+	"__tsan_atomic8_fetch_nand",
+	"__tsan_atomic16_fetch_nand",
+	"__tsan_atomic32_fetch_nand",
+	"__tsan_atomic64_fetch_nand",
+	"__tsan_atomic8_compare_exchange_strong",
+	"__tsan_atomic16_compare_exchange_strong",
+	"__tsan_atomic32_compare_exchange_strong",
+	"__tsan_atomic64_compare_exchange_strong",
+	"__tsan_atomic8_compare_exchange_weak",
+	"__tsan_atomic16_compare_exchange_weak",
+	"__tsan_atomic32_compare_exchange_weak",
+	"__tsan_atomic64_compare_exchange_weak",
+	"__tsan_atomic8_compare_exchange_val",
+	"__tsan_atomic16_compare_exchange_val",
+	"__tsan_atomic32_compare_exchange_val",
+	"__tsan_atomic64_compare_exchange_val",
+	"__tsan_atomic_thread_fence",
+	"__tsan_atomic_signal_fence",
 	/* KCOV */
 	"write_comp_data",
 	"check_kcov_mode",
-- 
2.27.0.212.ge8ba1cc988-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200703134031.3298135-2-elver%40google.com.
