Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWW67L2QKGQEEGGPWTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C52E1D52F2
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:03:55 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id s188sf2006127pgc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555034; cv=pass;
        d=google.com; s=arc-20160816;
        b=frhzYm48wpvPHsJjY4dMY0Oh1ehKARq1o9XQL0zc7xZj1OHxwr647wz8XEL6XuEwNW
         6RuVjv0YN5PFg1d73WyuCDvX2nvpCNryurLxypzg8uKz4Myih2ZwS1IA+dcSJk3cVlia
         ED75rlXKIncCanY8MMNrr2Q1lIsFLdNU1eZemGObkuck9Rp8eJTuFzix0daE78jFa69Q
         TqU133amxMzrwj6w43rc/apGOp3MwPXAR9ArPgmjFxT5Pc4GYCZGSuG8OwnD0mXwIer9
         Sy0wrnryppNdSK+L+WwgRM7riORefBy2oxLCOqq7O7ayozHANVfHeKtM8y5E+Zq3lbKS
         UPvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Xa9vn43MwSqysuETNZt2/4F5IPsKxsbqPPn/d9i/vS0=;
        b=JmYgVKhxi8wUk5fGw+YdkQoEXZBW4AFFBP3qMPDSvw9IIN9WwlPX3nl4XNkwrQj+GU
         tpa0DQIC2oyYfjPwL73+v972spyHqtSE/5o/30yGiEOHPjvDMTIfLd1OVzPSP6D8Bby5
         ZDXiP2pIfPfSoyR9K4DwQHQkrjrWKXcxAVxsg+s2Dnghk0PGeicVaF6AqZkhNnGIQ1nO
         OeuLj5LDyENlXmEwzkBnWojhP8LCI85E10jVfpaS4lq9ksgolgtQkB1HJQP4oLcgPj2z
         Iclj1VFfYNfD6YI8p69tEJnEqvOzSCXeUsf6Fi6sHU0ORh9qLJZANqpnzxIXcIlQWzvv
         /PiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8KQpXCY;
       spf=pass (google.com: domain of 3wk--xgukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WK--XgUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xa9vn43MwSqysuETNZt2/4F5IPsKxsbqPPn/d9i/vS0=;
        b=cdKiaIN7GlFJis0hGPy2oRUTHpt7BGRy796d2X61wdfEIJ38OZYp/390kz7CdYth6G
         UnO3LE7DONApesZsIh1HGjQ5kFmNFImPoWln6ii6Qrufrk0rQ+EyGJkRrop3U45UqAD3
         qCv+0/3z+AjQPn0xKW1Oiv99uUE1QZI9VVU1R+ZR/kiZMBr9qFDGsmLjWToF8RV6uAGX
         47EfiFW7pivB+ha7ZncCZvr2T7Bt3ui9RUqFOrng7LORnr+Vl/3wWGDlO8E1T0ONxzl/
         H6EZWI9FYpLe+QLqzcdk0MxTJPiWwc6VKX2Ag/d0yDhkQacxvgYKbVgSq0qmT/S8gnrF
         XOtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xa9vn43MwSqysuETNZt2/4F5IPsKxsbqPPn/d9i/vS0=;
        b=XH00QKb9cXNcCz9iMDa2eFWjy1MnmPoJt/rmbHqtcM+o6PN5VQMEwAJ51ek4fhwxCb
         dUUu72wZVHd4anKxHKPsEMNB/5xMU1o9+n5l1+Qk5ETfZr/GDMH2xGNq/y532Dyl426i
         rIYovz4VB4AjcAnnqvQOi8w+Y2pIh+3eWGXXaUYLEm6Pe14SUsNKFVETT+KjA1VjnWJ1
         op/1TSgiL9a2DqqNJlhOWcmcWyAzQm+zcPKgaA47mKFgXt9E91vU88E9CaQK62Z+LlOx
         TMFnf3j8NYvG7ItAmZPNePQB69boTv03JoYWe1y17uc8tzk31NvPycOVaQsgR9SRkoxU
         J/kg==
X-Gm-Message-State: AOAM533o/uz19mXUTwnX1UwN2Zyh6tqTlWdrp82YSMWS2+BuF+QhYQtT
	HICqoOaEVBeJwEUEZaDRXzc=
X-Google-Smtp-Source: ABdhPJyWELfeKnFWpK64TunMC3GZXJ3gsUId44kOHHKX4gy2Q5jyMQ13fw4t0v+DqqBHOsnyGVFC4g==
X-Received: by 2002:a63:da4c:: with SMTP id l12mr3547761pgj.3.1589555034362;
        Fri, 15 May 2020 08:03:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:24c:: with SMTP id 70ls929912plc.2.gmail; Fri, 15
 May 2020 08:03:53 -0700 (PDT)
X-Received: by 2002:a17:902:8f8b:: with SMTP id z11mr4016573plo.208.1589555033771;
        Fri, 15 May 2020 08:03:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555033; cv=none;
        d=google.com; s=arc-20160816;
        b=0OcihbI2mGHwuh/6k8P0GCuWTmldNatxNlkvVgR3lvZ5oSPCuiIa9BQh3a+97xX+sH
         miSfY/TfHCaaYz59/+9i3kf66aq1Rx4KXNM7tT1mkzau7enA2LVLw3EdVS1kqZLKF5xP
         vd1ZcBCAsNwzG15G7yl+4ZjOq362gitGmC+jb6VkUqLB976b5OqyLhMRZK3YfoX/uDrs
         1ad44Fm/NN98Iz8AVGjnmhl/ecgXdOvI0xX/tH/Nh7jl/jMtKp4IDUTDZtgPPJPQcZbM
         EwUsMgDYX6jHBeuRjjuJB33GYswm+z3QoR8ZlIb3MlpUCf9Gz6zN4b9pZJ9rEi5ot4gK
         E1RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=p/SCTVw7StWX3LdYvyHEBQe+hUDMyY+dnWBb3b3gSe0=;
        b=C+55yh6PKxs2QXvDsGY4XEEPW//7zF6yoYo3gw6uqnSC7PgrQMaiGA3Z1mPvYuw5cf
         wjhISK7MQ2dWpf6Iyl4hF80yDhm2aMy+whP6cxjsAap6e4SpmKk45X3QeX01TlXsWErx
         vNdmxMRUg4dxPkuWjo8hJiGhYwoFRu6MZmtNSUL//kRPiygCreoeO1zqITfBk+qUAD9P
         RI2lXuZtmEAQWltYcwaktz8WkipxPSSYy7T3t+FDJ/T9z72KqjRAD+8XN1DS11boQe5T
         xjs7antTl7SpdglmkUHOp7ZBrHQfEheNT04+zcXw79tEwdrgJ04ZVp90/YP0PS9IB8Lf
         xlEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D8KQpXCY;
       spf=pass (google.com: domain of 3wk--xgukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WK--XgUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id kb2si158145pjb.1.2020.05.15.08.03.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wk--xgukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id s65so2704654qtd.21
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:53 -0700 (PDT)
X-Received: by 2002:a05:6214:7e1:: with SMTP id bp1mr3748671qvb.208.1589555032839;
 Fri, 15 May 2020 08:03:52 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:31 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-4-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 03/10] kcsan: Support distinguishing volatile accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D8KQpXCY;       spf=pass
 (google.com: domain of 3wk--xgukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WK--XgUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

In the kernel, volatile is used in various concurrent context, whether
in low-level synchronization primitives or for legacy reasons. If
supported by the compiler, we will assume that aligned volatile accesses
up to sizeof(long long) (matching compiletime_assert_rwonce_type()) are
atomic.

Recent versions Clang [1] (GCC tentative [2]) can instrument volatile
accesses differently. Add the option (required) to enable the
instrumentation, and provide the necessary runtime functions. None of
the updated compilers are widely available yet (Clang 11 will be the
first release to support the feature).

[1] https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
[2] https://gcc.gnu.org/pipermail/gcc-patches/2020-April/544452.html

This patch allows removing any explicit checks in primitives such as
READ_ONCE() and WRITE_ONCE().

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c    | 43 ++++++++++++++++++++++++++++++++++++++++++
 scripts/Makefile.kcsan |  5 ++++-
 2 files changed, 47 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index a73a66cf79df..15f67949d11e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -789,6 +789,49 @@ void __tsan_write_range(void *ptr, size_t size)
 }
 EXPORT_SYMBOL(__tsan_write_range);
 
+/*
+ * Use of explicit volatile is generally disallowed [1], however, volatile is
+ * still used in various concurrent context, whether in low-level
+ * synchronization primitives or for legacy reasons.
+ * [1] https://lwn.net/Articles/233479/
+ *
+ * We only consider volatile accesses atomic if they are aligned and would pass
+ * the size-check of compiletime_assert_rwonce_type().
+ */
+#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
+	void __tsan_volatile_read##size(void *ptr)                             \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
+	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
+		__alias(__tsan_volatile_read##size);                           \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
+	void __tsan_volatile_write##size(void *ptr)                            \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size,                                        \
+			     KCSAN_ACCESS_WRITE |                              \
+				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
+	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
+		__alias(__tsan_volatile_write##size);                          \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
+
+DEFINE_TSAN_VOLATILE_READ_WRITE(1);
+DEFINE_TSAN_VOLATILE_READ_WRITE(2);
+DEFINE_TSAN_VOLATILE_READ_WRITE(4);
+DEFINE_TSAN_VOLATILE_READ_WRITE(8);
+DEFINE_TSAN_VOLATILE_READ_WRITE(16);
+
 /*
  * The below are not required by KCSAN, but can still be emitted by the
  * compiler.
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 20337a7ecf54..c02662b30a7c 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -9,7 +9,10 @@ else
 cc-param = --param -$(1)
 endif
 
+# Most options here should be kept optional, to allow enabling more compilers
+# if the absence of some options still allows us to use KCSAN in most cases.
 CFLAGS_KCSAN := -fsanitize=thread \
-	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-4-elver%40google.com.
