Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7OS3YQKGQEITPI5MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2BEC142D0C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:19:51 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id v24sf22052077edb.15
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:19:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579529991; cv=pass;
        d=google.com; s=arc-20160816;
        b=fe89+4BQte/EhmSd7sFOswnmM8SSYjRJVHJERpVcvZJ9TnfDLCb1x2KgzKBioASREn
         bkMwmRhsJyi6u64GlhpzC+Op+EIB70ytHKKpmg4N6glRwpTUW9ufB/MSSzVjJ569pLLH
         8GBaomtFjfIdRycd6XUI8zGyg41S89RAjG6NG4/rhzuLggWH82X9ImD3xGNh+clKoBnj
         G7b1kgyVVlzCushApVf2WKu6VieaMGGOEIX64UAVGEJXQgwiu0VPAhbl+gBtxOcbLEQo
         ihIH8hdrSHfW+uqxCpnpMdlnFOrh8lrASgvdg8VuWcWwjBvIIbegXIw0s0TfjAN8UxXP
         niEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UR/HTy1H++9h4A6PKLyvJMFy1Jk9o1vQsATAL/mc63g=;
        b=Fk00jn8yfVVsMqJ08IBjIftyCTCVU+NCfN8uVCFd6OvR+9vbF9PxCHqS38CnnO6BVq
         5a7yGlQvZnuHw7OT2yG3DzGotOKyH7calBeiAjZ0kAUq/ka/w/qzsRuyPTLLlZ2Atoc+
         bO6/rB8hlazN2Sns6m/AUGy4fA2pq+XgucMOtMgOKOCbkqloykU2sGXw3jiDM3djiS98
         JDIAq1ehWWimcu/o1l2bs+eWL8yCJjgQ8Gl7q8l2/7HERfBxXexak8jLgWdKs3NtQnYP
         Na+G3BwPT7OgZGAW4PJoc8TtCJDr487+26FxNpgvDwALEUrX6ZEzMCsE3w83v+OCcEuX
         iFYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fyHqklo6;
       spf=pass (google.com: domain of 3brclxgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BrclXgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UR/HTy1H++9h4A6PKLyvJMFy1Jk9o1vQsATAL/mc63g=;
        b=AHPJnRbmvP+I0gaaRx2uyTNKF9Xg7scjqHOBDLpnMfdUwzfIUCyUGKvza/AHTtkFRB
         SJ0c9C5xONkxMDCJA14YkJXll/lmKUjcQwDFHo/IXe25hnED/tVAyDtG3nRYWlNKjgYG
         H8amVmSJotM+3ma0gOgcopgWj7T/5XCef4MasbwLtHvIuWB+i9G9GyExnTGYRno/b26f
         QlWhVbeTt4/K6HVdlO70llRCuKs4oN2N+Xhe0Zxow1aRSV1XbWJ+0MYQALchi/zNsSrW
         f0a0/qYBmMdqGgkdJpWznPBDmNOvDsN/txpmwgDFiUd/X5MQO1F5a665cIfdcctp4+AP
         HarQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UR/HTy1H++9h4A6PKLyvJMFy1Jk9o1vQsATAL/mc63g=;
        b=THCnLJRkkBNIMju55A/IQ+P9NMvCi0NvYuvnyAH8POV539UJ+4ehTjDpGbQ7u1D73q
         oOy3NluSoJEk1lGHpeL1LmjtSQtOPl5R61hejnGFvB1+oDdfzrA+/edrDxQeg3896Jm/
         3QI3sZiKtQ5Qo/BAJd9qLEWEMMFYOSkEp6pQ7cT9L0B3FJlkY6u+4dGHYFLzS3Mf701Z
         JJe1naRb3ljFCPz14KVYIlQl33wtbRFI1hl9luONTJTOsuS/mHM9PKQ/QVlE4WQSXGXa
         qYXUqY8dFyAUJYzdDmJjn8tws2yjHItaqeZhjBcvMXhKcm2ouka5dbXv1vOM8yTw2LBb
         WTCg==
X-Gm-Message-State: APjAAAU7LNA9BpeVJQ4+YVj0R4YhZRpmcLGOQx1ZIiWw+xPE1MhF/YpR
	MijzgOnFVmAQnXBXFYsC1XY=
X-Google-Smtp-Source: APXvYqzhGxh3432H62RT9Xy+RDLO4jKIV3k0KGyCYhfclVNe7xiWR3DSrl5+XKnfqTYyDKkpupdC/A==
X-Received: by 2002:a50:d5c9:: with SMTP id g9mr17813778edj.131.1579529991523;
        Mon, 20 Jan 2020 06:19:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c0d1:: with SMTP id j17ls8115207edp.4.gmail; Mon, 20 Jan
 2020 06:19:50 -0800 (PST)
X-Received: by 2002:a50:93a2:: with SMTP id o31mr18109749eda.160.1579529990912;
        Mon, 20 Jan 2020 06:19:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579529990; cv=none;
        d=google.com; s=arc-20160816;
        b=D2Ww7N7oNHzJEhBmDJyjzQe/58U1ONBv63E8TvoDLYj/slmC7GecDo3MWrE4UzIXix
         pGQ3gMYCkTHT6loR+ZDaeobDoiK1Yy55TIYG4xEX9YTAZFnO4AFN9iJlgiQvCY8jFVCv
         3E5TKFoypT8tYal+cysiAo2ggvd/E1zFqlGABJsoLi7hML745HceYtuasTvyG8t/Of+D
         Dwn7kxfYrqC+vE2FTCc4jOb0fgsU9/iU7uNHWPyRZZoddvusliehqRffIcJHsMC5HujZ
         adw11fTdqeOLIy+chvmMjyWkZR7gPipteUrLYngsSCcwHrnD1KekBmbYtsIa65lQ7jmG
         EPWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=EjDI0Mf31vFhPpWjYi8Hep+KoV17mwptU+RbwnUr7FM=;
        b=yGbi06mybFXOLh9ydYjVGwuq4jqpKPr+xjqhT2lTUkqAQqbSgzBI8i7f4ukp4sJv9l
         loKwUHd5kOMCCj3Kl7AgC1BMZkHMga04I7kfykBnvhEK4IdYhF3brj9+uqUMlXBFVJJi
         nqaekcFZNWnjkU/vJ7EioOzKuTfu79He51xPbIRx8Q74g3Q90Cn2lMc6EV9cqd5qH2lh
         qQU7bQVlx189C975zZkKfKWHnx9JtANi11ChLGRr/PlhvDlQG5S4JqH/MLWsba9eQnqU
         zP21tdtkatWv/CZyeiKdDW/2vqO1zkz+kkaTsuHvjX0JaQr21rkvlwf4+pyvi0jUK3bt
         pSlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fyHqklo6;
       spf=pass (google.com: domain of 3brclxgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BrclXgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ba12si1390646edb.3.2020.01.20.06.19.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:19:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3brclxgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id k18so14245817wrw.9
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:19:50 -0800 (PST)
X-Received: by 2002:a5d:5403:: with SMTP id g3mr19279976wrv.302.1579529990515;
 Mon, 20 Jan 2020 06:19:50 -0800 (PST)
Date: Mon, 20 Jan 2020 15:19:26 +0100
In-Reply-To: <20200120141927.114373-1-elver@google.com>
Message-Id: <20200120141927.114373-4-elver@google.com>
Mime-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 4/5] iov_iter: Use generic instrumented.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, 
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au, 
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org, 
	christian.brauner@ubuntu.com, daniel@iogearbox.net, cyphar@cyphar.com, 
	keescook@chromium.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fyHqklo6;       spf=pass
 (google.com: domain of 3brclxgukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3BrclXgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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
 lib/iov_iter.c | 28 +++++++++++++++++++---------
 1 file changed, 19 insertions(+), 9 deletions(-)

diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index fb29c02c6a3c..f06f6f1dd686 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -8,6 +8,7 @@
 #include <linux/splice.h>
 #include <net/checksum.h>
 #include <linux/scatterlist.h>
+#include <linux/instrumented.h>
 
 #define PIPE_PARANOIA /* for now */
 
@@ -137,20 +138,26 @@
 
 static int copyout(void __user *to, const void *from, size_t n)
 {
+	size_t res = n;
+
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
-		n = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_pre(from, n);
+		res = raw_copy_to_user(to, from, n);
+		instrument_copy_to_user_post(from, n, res);
 	}
-	return n;
+	return res;
 }
 
 static int copyin(void *to, const void __user *from, size_t n)
 {
+	size_t res = n;
+
 	if (access_ok(from, n)) {
-		kasan_check_write(to, n);
-		n = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_pre(to, n);
+		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_post(to, n, res);
 	}
-	return n;
+	return res;
 }
 
 static size_t copy_page_to_iter_iovec(struct page *page, size_t offset, size_t bytes,
@@ -638,11 +645,14 @@ EXPORT_SYMBOL(_copy_to_iter);
 #ifdef CONFIG_ARCH_HAS_UACCESS_MCSAFE
 static int copyout_mcsafe(void __user *to, const void *from, size_t n)
 {
+	size_t res = n;
+
 	if (access_ok(to, n)) {
-		kasan_check_read(from, n);
-		n = copy_to_user_mcsafe((__force void *) to, from, n);
+		instrument_copy_to_user_pre(from, n);
+		res = copy_to_user_mcsafe((__force void *) to, from, n);
+		instrument_copy_to_user_post(from, n, res);
 	}
-	return n;
+	return res;
 }
 
 static unsigned long memcpy_mcsafe_to_page(struct page *page, size_t offset,
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120141927.114373-4-elver%40google.com.
