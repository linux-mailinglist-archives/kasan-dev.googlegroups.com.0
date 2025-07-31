Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXNRVXCAMGQEUGBT3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 31309B1709F
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:51:58 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-451d3f03b74sf4428385e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:51:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962717; cv=pass;
        d=google.com; s=arc-20240605;
        b=YK8KtKYgc8bxy3Tuqj0fESQFhIxNnRBLyHAZqf3fGNq8M2DpGla0JWX2IpGBT+VQQp
         LVa0M+N9q7TrWAxzT5H2r3Xn2M5PblBJAj0MiN9KeQ/1v5n7UbShEmkOlRtDpM5Ry4ax
         Qogn4H5wUk7TKFvrrj32qmDnqmbT5WqF3BO5PbeIHw2dUi/D9BVrBvIrldQJQdYOuaht
         GPGsRxQSekT4OMb2p2k3roxw+wjDl4h8PfVSjrALji1GhFcg2/+D66TaEGQlvIs5aC2Q
         bOLowRc78vwZlmXnIrgk8nXGsFKMeNOpMqd+3EuqmpRXDlrQimHhXwd48jH6OI7csCF8
         Bydw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QAu1j4dmONO6kPMBNLekA4jSxmZkWYljeE5uG5WA19I=;
        fh=f/y6TnExXxv2m5c6KId008An0LFZPP/rNkz+4D4DnfI=;
        b=ZLyWQbAvBxSB6cPFVvSC2qHOWTtWlicksQv4TWmc/EYYin/eFBnyp54M6JC6oPrK5U
         NzZ1jH0yNMsAscaPx4cnwQRrn9BluoXpY+ZojxOZPUa+kxoYXOlkb2gj5n4mdb7vZM2f
         ZMtMBFI+S8UYPS4xVubMRHkQxIkIyCMyxgRUX1ThiuAyyRDEosb1AmaZ5pGGHXBIt+dt
         k2bJo7VuyA62TJcDvtdTev4ohmtILvHj9w+nNjJW21ANU0tYp7UTbPm1Y7sMd9dRcvKw
         c+geNFw/TV8HQ2oljVN86r+1zn/dZes/kvjdEdCkcksFlDpsaS/wH/PFUkxlA7YuQaIE
         CfjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="M5hD/4bu";
       spf=pass (google.com: domain of 32lilaaykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32liLaAYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962717; x=1754567517; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QAu1j4dmONO6kPMBNLekA4jSxmZkWYljeE5uG5WA19I=;
        b=QMl1ciXeKe0aPEakNubUpVeTZTIZMY/d4LsDLe0lczhWoxxPKlN04rAhNIK5XBZsnX
         cnatue5uA/rVNo18SVeJcnCV6Wj30C9TdJ60/p9f/w3vs77jzii09/FfiREnwnArPfiA
         LmiNJ1VBMOr++q8CkyQx7GxORFC7QNgdME5JUkWsIwIiW41RxO6mi7sf/NFYHChVP5mn
         +LSMq8FF4BgZii5TT7MJick+fzcjwbcwzy+Cn1lk7s0wl5htXzlYI9/LhkbZvoVZxYF/
         U06ksXeYK8mK2/OivntglcWEjir94OtWwyFfiKiE54YobMq8aP28CVn97Uk+Egw6BbUy
         15ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962717; x=1754567517;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QAu1j4dmONO6kPMBNLekA4jSxmZkWYljeE5uG5WA19I=;
        b=uk/Jb3rJQQfN2qixm4KQO2E3wh/D8dG9FdqNVC5RFRJ6zczkLTJo2oYPVI+Gqm7OD8
         je39Qnx+9JGDzHlRhT5LkHmj8zHQpx3XC20ouLgSxeY97Q0hv6KItUWXbmA4hctvxhFn
         rFvwDQRFcVLnnR5gkK1dzGpgjGpTTiXA5SXHW37oy8HilCSqAITlcokdh4btuVy1iYHV
         /uhzE2WvCgrJxU+OLHFH6tV2pq+xj59uUBY7GVKh7SjrZPcVVVgVlXKGHwqVVDQjYfGw
         5ii2SApYXmWAsYoNgMA5GI4Akbmuscmt+o7amZGnupkCWU43w/c+DQuWspJW6iTBOHmk
         fsPg==
X-Forwarded-Encrypted: i=2; AJvYcCUCWj5T974z9vMfVUuW5BpsTgHLWA0eXzflbJl/BMgoZ2zcRZpARfiooM6Y6PyMXrQoVifUCA==@lfdr.de
X-Gm-Message-State: AOJu0Ywfc+mXWy6NB89q3iufTh0c1xAIvc2YSJoS4GcCxONdL3Tu5zdt
	KliejdrJU0oWBBukT0GLykwZ8LLNom3szMNI9nvF/Fc7rusfFr1ZG+pu
X-Google-Smtp-Source: AGHT+IH7OpscD0T/fCB+3VdZvadpy+P6X3luyR9xxV4r5+s/PXjnXH0/gNTC/OZdWEO+ONb9Exujug==
X-Received: by 2002:a05:600c:c4a3:b0:450:6b55:cf91 with SMTP id 5b1f17b1804b1-45892b94d5emr60702365e9.6.1753962717585;
        Thu, 31 Jul 2025 04:51:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbyX5JmIVV5fL2eOWrU9+ZvtcZFMmKEP57gqTMzFkdKw==
Received: by 2002:a05:600c:3b98:b0:456:241d:50d1 with SMTP id
 5b1f17b1804b1-458a7e2907fls178905e9.1.-pod-prod-03-eu; Thu, 31 Jul 2025
 04:51:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPmqNl2+2EaNiNakLpDlAfewKTdQGM7tUVm7uJ6oFTEUsI8dMg21UbjQv7iVq0BJ5xIvt8OPMeTso=@googlegroups.com
X-Received: by 2002:a05:600c:3592:b0:458:a5f9:aa68 with SMTP id 5b1f17b1804b1-458a5f9ab77mr12460095e9.2.1753962715107;
        Thu, 31 Jul 2025 04:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962715; cv=none;
        d=google.com; s=arc-20240605;
        b=jt7PpiVF84+D+d2ayUdNVVx5HAGWMtjHQApysOir4cdESppDVJmMcmZHzin7Bnc9mT
         gyqC+Tc5qKz8TX3oK24sZXQuMWnoW0INY3fS4E5SPfhKYOru1Bo4OCciBHszX6MJsxBt
         tUxXC79YL91EloDEh2hTdNgWV4Jba3H7Ceu0aw0YZvFVyfFP5BbBe1RJzJCkHUkySVeS
         hylcn559SL4uPKgIb1/ik548FNbXGYk2tk5aTNTgEWSh8z7DLZrVwYEgE5u2e/7bVNAj
         ECGP0w36+fQFBZzLffiKwH5KMZmoc+sWBnYG/W22iU8kKtkStX+dOJdjE0lQedKiEJK+
         ivjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Gx/82C9/LmdN6I5VG5zleKCD5AaUcYE9gaKc5zZKlEM=;
        fh=gsqnlTwRzQc6FAJv+1xyb/2toNoh3We1R8L4dfBDJzc=;
        b=cDIJZQP6CTuyQNYoa05+NpTrC7CPxlgqFjsDDHVNDdbrMevbzBc6AYuuDg525B2Ry6
         HSP7udGSdLEDpc+6qo6mp8EyCDXc1DL2MjrNs0/qEKU5ruH3E3XVe4rhVpkxjiG+UDwG
         nuT/3RcOO6n6Y2t4ZugS34DF7cYMAhc+FnL5DqkwUc4ji1qQTA6rL2C8d5UuYQk0JlbP
         T6YUOSQFW1MNvxfhg6h3Fbyi9DpIjKABaEJzTrpem/3oDK6ntmijxPBsItaLRd0w5sMh
         uyiQAn/DVR/MGto87oVlnecULJDiBFLHj6G9UlzIWhxI+tDsS5wmoKdMjqYpd+1sbh2+
         nAZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="M5hD/4bu";
       spf=pass (google.com: domain of 32lilaaykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32liLaAYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4589ee09341si509235e9.2.2025.07.31.04.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32lilaaykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b836f17b50so168783f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUc5eFEa5zGjaFsCECnKhKnu36HfrziAFEAgX8+G7ROOL746RyWdUaUOhUDWiv43fldK26TuXe5gSE=@googlegroups.com
X-Received: from wrta8.prod.google.com ([2002:a5d:5088:0:b0:3b7:89f0:5c26])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:401f:b0:3b7:8832:fde6
 with SMTP id ffacd0b85a97d-3b794fb6807mr4958295f8f.13.1753962714695; Thu, 31
 Jul 2025 04:51:54 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:33 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-5-glider@google.com>
Subject: [PATCH v4 04/10] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="M5hD/4bu";       spf=pass
 (google.com: domain of 32lilaaykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32liLaAYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
are inserted by Clang when building with coverage guards.
These functions can be used to detect initialization order fiasco bugs
in the userspace, but it is fine for them to be no-ops in the kernel.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

---
v4:
 - Fix a compilation error reported by the kernel test robot <lkp@intel.com>

v3:
 - add Reviewed-by: Dmitry Vyukov

v2:
 - Address comments by Dmitry Vyukov:
   - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
 - Move this patch before the one introducing CONFIG_KCOV_UNIQUE,
   per Marco Elver's request.

Change-Id: I7f8eb690a3d96f7d122205e8f1cba8039f6a68eb

fixup asan_before

Change-Id: If653ba4f160414cafe65eee530b6b67e5b5b547c
---
 mm/kasan/generic.c | 24 ++++++++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 2 files changed, 26 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e76..b43ac17b7c926 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -238,6 +238,30 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
 }
 EXPORT_SYMBOL(__asan_unregister_globals);
 
+#if defined(CONFIG_KCOV_UNIQUE)
+/*
+ * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
+ * when the user requests building with coverage guards. In the userspace, these
+ * two functions can be used to detect initialization order fiasco bugs, but in
+ * the kernel they can be no-ops.
+ *
+ * There is an inconsistency between how Clang and GCC emit calls to this
+ * function, with Clang expecting the parameter to be i64, whereas GCC wants it
+ * to be const void *.
+ * We pick the latter option, because Clang does not care, and GCC prints a
+ * warning with -Wbuiltin-declaration-mismatch.
+ */
+void __asan_before_dynamic_init(const void *module_name)
+{
+}
+EXPORT_SYMBOL(__asan_before_dynamic_init);
+
+void __asan_after_dynamic_init(void)
+{
+}
+EXPORT_SYMBOL(__asan_after_dynamic_init);
+#endif
+
 #define DEFINE_ASAN_LOAD_STORE(size)					\
 	void __asan_load##size(void *addr)				\
 	{								\
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e649..d23fcac9e0c12 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
 
 void __asan_register_globals(void *globals, ssize_t size);
 void __asan_unregister_globals(void *globals, ssize_t size);
+void __asan_before_dynamic_init(const void *module_name);
+void __asan_after_dynamic_init(void);
 void __asan_handle_no_return(void);
 void __asan_alloca_poison(void *, ssize_t size);
 void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-5-glider%40google.com.
