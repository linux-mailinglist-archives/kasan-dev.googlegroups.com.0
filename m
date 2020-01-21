Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOCTTYQKGQESYBVRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AAD08144189
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:05:37 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id t8sf995302lfc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:05:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579622737; cv=pass;
        d=google.com; s=arc-20160816;
        b=0RHDhohzVhOkuBRz4wbaJP6S59l+xS5ZkkGdCQLGGJzXfkrncV4RtR1jTjrZQYkyId
         pryg1Wf1Ai0mjIxt9L/8vtvaUd/iebmYZrcmSpjWWG2WXQVu/HlU46SikTWIWyd5uRBr
         pjMExXI5Pfs43YNcYuRIUoFICXmNPU1Fi4sQ1OtTdA4LwYcvmndK6WvtJuntNWJ7YSMM
         Jr7JO2yVjBfHvlDUicFmSQW2pUtcOVfvhAdl1LDZys/XB8vcbSiQqiQ/ZpEr0MgkDHYy
         ixPBKZXWJbQEVwh8fRqpPIGDa1+YUCHfc9mvEi841dk8auCgMmCK3cN7444rNzH+1ljB
         rM3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Y4ho3HouAGgDvbW9BrYB3oLUHPfQ+xvowCweQON1hUk=;
        b=sq5/n+5o49O+wjAjmiP6ECdW4nFdJt6eo2gPUeg3guBTeh66MZXMtRm/HBVyfSNj8d
         C6Kr8J6iiLLf261vE1c3QgQlJEmpfPhGVecVrrOauqrH7Ac9TsdkJoPDFqr8gReXXnEv
         j5fcYZVWU+WF97J5yYMG60CZlau+F2/ygFoaLOpBoZnd/FYcCUK2NE+3a7o2cb+RW0dU
         lxHMqV33Rg+pbIvBQjOC8MnLYaa4DGF5L8O9FPri4wintXMweI0M4ZtyZrxq2rE+C1Mm
         rl4wag/5/kuPcu/el9XdUrNlcO/v8oEB5dxZTzKj9JxdTpmUR8z5LAZk0xFhh88k2V7X
         NgoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BBeNCO/V";
       spf=pass (google.com: domain of 3tyenxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TyEnXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y4ho3HouAGgDvbW9BrYB3oLUHPfQ+xvowCweQON1hUk=;
        b=aIMv1cfQ5yVCatDuoV5kWyZGtX1vNyG9pYCBchdzbHq6DtMyKj/8buRnY6A+oDPBNZ
         oB3083roIFYasuHzeIIM7256/FNYnBM9ZZx16pWJkTgjjodRc5R8ZdYByhGZ7OS8U4d0
         N7RljHHg6wtHu7Hlv1U1wKTUVaMIkQmJfKTTcjM+vTd14fsjeobQh5hX2Frsbb2PaTPa
         ItzB29weMnxQkXIAZav9HwCYWkCIEd9YBCS5o9E6g1dnzP4gZjveuMlcxQeybsbDWx8N
         wwLpgSN33AIN9upBn/fcPMWKtgMt42jWzBxhM1ijChnB7veIQFFhOYJa11rpoi4InbKx
         x6Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y4ho3HouAGgDvbW9BrYB3oLUHPfQ+xvowCweQON1hUk=;
        b=osIsFy9BOzu9ko/tDNdZcqLqMavBdTMfen/1cdBkTrkIkvt6cJZpxguraM+oo4DEcQ
         kmnAhDgQHsGfiyUyb8Ii4J3R6TBRkitzPS99IbXjy23THCmj63PrEF9pi3KOBwxi1BcY
         KO7oVjOeZoKq/NNrDNkkMrOz1aQQ9Ra4Wl+fT05FnsPo1W5vyWuJP0/OF3Dr9BKKx2Qk
         JY7NRPtqLnpy0HnjYmtVwRuNefnV4XvOQGdV94tZfAByoIHa65/0oxJkxbGAJnJz03Ik
         IauWan6OAweWPfpIdZ0QH9jmiIelOeydg7G9mu7zFQT8BiNArqg7PMXzcfCSXwHq4PZu
         jiTg==
X-Gm-Message-State: APjAAAVuoMCZ/yA8am29cKq7+0euiYqvQnkd98xq+a5VM7G2RlzXPhg6
	t0IDfAj2RernuvmELF1At5o=
X-Google-Smtp-Source: APXvYqzo6UAy0wq74wG+LznnuIT0B9wK5xcaa+WhDDrv7Gn9enan2cBM26FBELjDNq5OLEu9Q3O79w==
X-Received: by 2002:a05:651c:1122:: with SMTP id e2mr12926675ljo.238.1579622737188;
        Tue, 21 Jan 2020 08:05:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4e7:: with SMTP id s7ls4825134ljm.10.gmail; Tue, 21 Jan
 2020 08:05:36 -0800 (PST)
X-Received: by 2002:a2e:7d01:: with SMTP id y1mr17248072ljc.100.1579622736348;
        Tue, 21 Jan 2020 08:05:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579622736; cv=none;
        d=google.com; s=arc-20160816;
        b=k9cla0ZxrdX+Q5n+rkrpzKGi9ulEopyArukwNu1EBvULbGNkym1kLaX//FDqtejiL5
         2SkXDrKXbwx9OIZa/QLSTVkha7tqJnY/UJ567xx30l+ztp98BpH1r4v1DLBB+10+ULT7
         2zc6qJ9FuSr92fECPBMnEUJ/nz+PDxnTNPv+amd89xag448G6vfNwcwvXYRag22RZWGv
         PWwinqv2XAfeYfjS949luT1zlWRM8ITiYV6w4f59iMPZRsL0ct7j8Qy7OJrGCxYDCF5R
         asctOcOaVPZdYC6I7ikN6Nmx/ko6hYW/mEvkKDRaYQJSoz/1h/X54jbOwqT6UrpF09FZ
         fhqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Elct5+lKhC9X7zT8nF9IWixwmqUVlFcvw9suDwdwDnE=;
        b=g+GySgAfgf1g7DSjxY9H2VL4uL58Ll9UJCq3DgjzZKkaxLZEU/i7sNNQtbxAdsX2ID
         OQiNYZ4eymcGosw/Lens3FKqBDqJnPc2io2ZUQu1PsQeErWCKlWKYT1oNKsG2FbPlx6M
         nl2AjH9aOlkeO8fh0C0HggyIvjygQkhZoWmC3MuE8OCg58/9VY2IyBCaaWM8/4A3THnn
         qmXCBLhwN8tgBA6vxnKsa8N40U+vi3rU2CnTIntKPXRSOu/7AdMQRXop3hgxAZB4RQF/
         U0lMqeNLiRxdy+WpfV1cAu6ZvAdppCW+QjwXTq858sXET6lB7whrWcA4ZLXGKeLLmUIT
         CwTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="BBeNCO/V";
       spf=pass (google.com: domain of 3tyenxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TyEnXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id u5si1568358lfm.0.2020.01.21.08.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:05:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tyenxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p5so525820wmc.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:05:36 -0800 (PST)
X-Received: by 2002:a05:6000:11c5:: with SMTP id i5mr6021320wrx.102.1579622735534;
 Tue, 21 Jan 2020 08:05:35 -0800 (PST)
Date: Tue, 21 Jan 2020 17:05:11 +0100
In-Reply-To: <20200121160512.70887-1-elver@google.com>
Message-Id: <20200121160512.70887-4-elver@google.com>
Mime-Version: 1.0
References: <20200121160512.70887-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 4/5] iov_iter: Use generic instrumented.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, dja@axtens.net, 
	christophe.leroy@c-s.fr, mpe@ellerman.id.au, mhiramat@kernel.org, 
	rostedt@goodmis.org, mingo@kernel.org, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, keescook@chromium.org, cyphar@cyphar.com, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="BBeNCO/V";       spf=pass
 (google.com: domain of 3tyenxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TyEnXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

This replaces the kasan instrumentation with generic instrumentation,
implicitly adding KCSAN instrumentation support.

For KASAN no functional change is intended.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use updated instrumented.h, removing post-hooks for user-copies.
---
 lib/iov_iter.c | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index fb29c02c6a3c..614b6999d2da 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -8,6 +8,7 @@
 #include <linux/splice.h>
 #include <net/checksum.h>
 #include <linux/scatterlist.h>
+#include <linux/instrumented.h>
 
 #define PIPE_PARANOIA /* for now */
 
@@ -138,7 +139,7 @@
 static int copyout(void __user *to, const void *from, size_t n)
 {
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = raw_copy_to_user(to, from, n);
 	}
 	return n;
@@ -147,7 +148,7 @@ static int copyout(void __user *to, const void *from, size_t n)
 static int copyin(void *to, const void __user *from, size_t n)
 {
 	if (access_ok(from, n)) {
-		kasan_check_write(to, n);
+		instrument_copy_from_user(to, from, n);
 		n = raw_copy_from_user(to, from, n);
 	}
 	return n;
@@ -639,7 +640,7 @@ EXPORT_SYMBOL(_copy_to_iter);
 static int copyout_mcsafe(void __user *to, const void *from, size_t n)
 {
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
+		instrument_copy_to_user(to, from, n);
 		n = copy_to_user_mcsafe((__force void *) to, from, n);
 	}
 	return n;
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-4-elver%40google.com.
