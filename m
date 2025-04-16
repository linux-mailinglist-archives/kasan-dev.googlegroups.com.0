Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5XA7W7QMGQESNB3GIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD2ACA8B478
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30bf9ed6da1sf31345791fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793720; cv=pass;
        d=google.com; s=arc-20240605;
        b=E7+xJe0gl1S3dq17tn5mTRuk+z4bmamOKQykwfJn6lP7Aj8NyNDUu5plDwNseSGcIN
         bF8a9dOxx6ERWNuCelhgaZKHJSReAvaK4fmbDYyEpXoY4QdXNH5Ug5Oc9rWm9+5DPdbD
         TnCW2lWkUrHByks4ZbAsIlY7I48fNvHVCN6y8hWodzzp+qoB8StU740QLDHJyOB26EOi
         eu+nIahKh/mbdefBxLAnqOFGMA973DqwTFlAzPdBJsUnJ+ifkTtCyQMSVpE2btsIkiQE
         qzwbc2cUhUHYg49+BHfRkSfGAn3/KVuLSMWYVAF38BY6mz+7YM9Leku0NpaWVzpxkh1b
         CVYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gYIDKDbgm8acjl4d3qxD3OaQz8yp6dN5foQ2jqNMnVw=;
        fh=V7TsRk7DU/cku2xp3q7NpAnwI+TtYpVCVeTxBo2/kFI=;
        b=dXtA1XRi2cnxIAVOsbIzwYHYP7eh2CLvxx8YVUDQr6XVruhgGbGThF/ZqmLRjD6sSp
         7nEZbLuus1YpMZd90m1IdC8GGqEHQr0gnlbkCenCOykLXfmh7QpcCwMLEmqpJQMleFdC
         k0ngqLjbiFn0HPkue+wUKy3bDZd2gB0pQAar/V77TiWHFOPUIEej6zEXLd7SGLL/r4Fz
         O/QQ+0ijLpOUbdUzKa0pSHkccTcGAFyEIxkez4RqN4lYAl97AbW4+YL1rdEgPRgmLWLW
         l21JLneZMkjywZpuNYUYnwPNkfWJQtCnUfy29vs4KwO4v8mHmLAWdMuH6bzzR+pzAXSw
         +p9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s+UGLGTy;
       spf=pass (google.com: domain of 3dhd_zwykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dHD_ZwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793720; x=1745398520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gYIDKDbgm8acjl4d3qxD3OaQz8yp6dN5foQ2jqNMnVw=;
        b=kG8zzVZQSzgfKk9d14NbmwiYLYig5U/JBPrsZ5PZ332I0EsLydVMw4kUioj8mYh8/S
         uKyKNXb7ZrifErD8X2ww5kJkE7dL9iesEtnOVStYzhfdCSj4hKBvUYyfckzN6jSJnb8C
         5BSgNRSOH1h//Mt0st2j/AtTYQtviy0QQ6UwAbXj8vy8MKNlAZor6SCSDB9jLmgSGYJ1
         kI9GflfDumSXO3wBuL7HzH86ymrhW4qB2Dy79JTjCDTzrMZLn2XAO/NYm3oBe5OMTQpX
         t2cj4pVypKC7gW4MKDO74JBIDgw4FXsSkrOEf5gQbwiKTc7DU2p9fWx6Sttn8H0Z7ixr
         n94g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793720; x=1745398520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gYIDKDbgm8acjl4d3qxD3OaQz8yp6dN5foQ2jqNMnVw=;
        b=atkI/LDwCUegWA6QkQBPmyYNvmHyswq20NnDvgVaiI4s0iwa3FaNi88Pne6L6bm9iX
         68D6fKhoXGjSvB5rCaMdm+v+AC5CLrJn+RP6cFrHaoegun4mI+hCQpOKNJUmLDa4CdVe
         AZbwyP5fSrSCTzb/ncmtqV91tr0+SUVRH0OqHYlNadxytqys80j/5l+RwCgUXqwtqKo4
         DQvhb6X1xLny4Iv4TXV0oqp3YjBKohfAsGW1OzCBwc5jTgwKHJFJNXymp2pxzWa3LvLv
         xwLkM30ZtMHwT5P1iwckyOyLXKN3ks681MYazTVqHs7Obh5jRvnr59NGC6mp+684vend
         Zjcw==
X-Forwarded-Encrypted: i=2; AJvYcCWBd1cE650dXkKOxuZ54CNE/FaZ1RUB2gN2wQJRAdF/bCYQPa5x8EJyMzEc6qKkSt0Jyf505A==@lfdr.de
X-Gm-Message-State: AOJu0YyITXGEyFbRzjavdRK3KdvFtTGst7zNl7T2c1ltv5hw1vSOJ76S
	cLBV+RbnsQvZI2Tw+BeDNLHFk9VOTaRTiStY2Glwevr70vvDHhRy
X-Google-Smtp-Source: AGHT+IGTwn904K9vk0xMLb3Q4V/fVZfBfftAXh31XpylqA7ZxeuZYxX+Xdm6/9aTLe//4W7d1UDb+w==
X-Received: by 2002:a05:651c:19a0:b0:30d:e104:b796 with SMTP id 38308e7fff4ca-3107f738d86mr2778941fa.40.1744793719444;
        Wed, 16 Apr 2025 01:55:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIeaTDSbgm1jl1JRf2bkFx3Dvy9XS4c+sVu6uYK2+aUCg==
Received: by 2002:a2e:bcca:0:b0:30b:ef35:2d28 with SMTP id 38308e7fff4ca-30f4c7dfc8fls1047201fa.0.-pod-prod-02-eu;
 Wed, 16 Apr 2025 01:55:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQlaNilGGvyjmdxNLsACwWwk/VayXXFcdYK+vh+VapVAAVHo8XA0vni4luemSZvsI+2Hm0gjj8u20=@googlegroups.com
X-Received: by 2002:a05:6512:15a8:b0:545:271d:f8e with SMTP id 2adb3069b0e04-54d64aa9bc1mr256973e87.29.1744793716527;
        Wed, 16 Apr 2025 01:55:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793716; cv=none;
        d=google.com; s=arc-20240605;
        b=KmsvXewVxAtV//Wllz/tKckXlqhxkJU9xpsWXCtSjkimbuYt/jYPHMDWkcRjUl7JAl
         UQ0gkSZKm4JBO9y6Zcd21cQuQ7X9ESCEC6BkoudDWgAs2UfFIMgewjv/wUOP9Ovw+WlI
         Kc751Cd1e3riUeJ5BJgNNWvg5pYfglGRv0czZTPJitcyE2CAmYz63204PRvxFeEZ/Cpl
         daS8VPz3b2rcU1xDz/BPHtgMgCuRMCqVrKlbcVqeoSQXtScfhxnE+MhnnoCTGdN/irBj
         ekxvmGegqAyto2g0dr1w8Ue0l5FoHXP0M0xVS95hn2jEapgKHPyK/CbPgwh7FNh7Zuoz
         mNxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Zc2x1kjeEyidtKH2uktLTwpBYFAA28n/I/Yhs6L1K7g=;
        fh=UYkYNZimL5phwmuO3/AErXigD0gDbLohRZpROGF89RE=;
        b=B3eqVJP6klanE8j1foXtXB5Y9NlJLW4XxoQgiEN0pxH8fVi71BwoDMI5BcfimPlbHW
         No7p2O55jlRvgliuHg0pK0xuI5yCeKnKp0JjwK1uJvx19zAWuyaAB2H6jM+8+V/14GPh
         OLZAp9HwblvKXOlsEfdpxq7SHU2/4d6qA5ZKJpHAiRAkNDfaNdT6mOtWJHhNgPXznQGM
         GC5mX2457EiqlZxoX+jv06waRWqXOsQQbjM1vddOPZS9uR7ALb10gJ8NYtR/4QvBBapy
         yhdp4kQV79aImw3hysd5yGUdyvUnhUGs18VfrlTB+csBBZcIkcA9LpioX9pRoRz3PcQG
         mhAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=s+UGLGTy;
       spf=pass (google.com: domain of 3dhd_zwykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dHD_ZwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54d555bf687si184302e87.1.2025.04.16.01.55.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dhd_zwykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac28f255a36so516325166b.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUybnZnpvAwuj+7LyebNUw0Mxy6IBAIwGd+QkUG7SuWBrMODoYhKc1iJOB7Baax19lRFWoyoPf/vl8=@googlegroups.com
X-Received: from edro11.prod.google.com ([2002:aa7:d3cb:0:b0:5f4:b068:4902])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:5203:b0:5ed:89f0:27fd
 with SMTP id 4fb4d7f45d1cf-5f4b74b2309mr852670a12.19.1744793716020; Wed, 16
 Apr 2025 01:55:16 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:45 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-8-glider@google.com>
Subject: [PATCH 7/7] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=s+UGLGTy;       spf=pass
 (google.com: domain of 3dhd_zwykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dHD_ZwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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
---
 mm/kasan/generic.c | 18 ++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 2 files changed, 20 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e76..91067bb63666e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -238,6 +238,24 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
 }
 EXPORT_SYMBOL(__asan_unregister_globals);
 
+#if defined(CONFIG_KCOV_ENABLE_GUARDS)
+/*
+ * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
+ * when the user requests building with coverage guards. In the userspace, these
+ * two functions can be used to detect initialization order fiasco bugs, but in
+ * the kernel they can be no-ops.
+ */
+void __asan_before_dynamic_init(const char *module_name)
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
index 129178be5e649..c817c46b4fcd2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
 
 void __asan_register_globals(void *globals, ssize_t size);
 void __asan_unregister_globals(void *globals, ssize_t size);
+void __asan_before_dynamic_init(const char *module_name);
+void __asan_after_dynamic_init(void);
 void __asan_handle_no_return(void);
 void __asan_alloca_poison(void *, ssize_t size);
 void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-8-glider%40google.com.
