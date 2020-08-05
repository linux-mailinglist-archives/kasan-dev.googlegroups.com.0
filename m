Return-Path: <kasan-dev+bncBC6OLHHDVUOBBRHLVD4QKGQE75IXH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D61B23C495
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:29:58 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id ck13sf3927477pjb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:29:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601796; cv=pass;
        d=google.com; s=arc-20160816;
        b=B380OgiYSFvXdUaHQLDwqokmcSoezIR+wB1SmxJnWQLWDifbkqrDsn5h7vXkz4ZXAF
         WCdhCcTbxV+YdsVQoM0h9MyjnWAH/mba76fq9N8/j8nBpsgapf+lzoMgCQQNXGQrJ9da
         07EN7UQhQDpeuDYTK1ODWHKU6oeWTywPH4h+1nawrcpmo0g9JMk01veTI4rjXOyLKrkz
         eFOakghqeKFBdUNMolyjtORKtgFL4zoJ8B4rodnhF2I4AxqPIzb88yzoikcVvqEGO65z
         t3ezjtmFgQY33SyW2p9AH4eX+n/NO2PNOVd6BcpOK7QsYeSQNuqulWTpilg0Kect9C69
         p1qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=GfZqTtqnioCtvgJ12I4zrQZoXqp72SIOAnHu11BIQZk=;
        b=zVe0UsUQQRoYYL9OyzBOYVpLFTNjf5z4B1T0FjpCyaG5DVhO+MJ+IsiY6hUYZ9Zlbu
         TVIT1ePmpLLb5eiJxNo9vigSC9cV2kwrwXrQqByrkG1gmqLuA5RdhX8r4E7mWhyvZy7H
         en+jWZHq5CrWO4/4TkyQFnhxSAS241yAX9QbWakDe68dOB82CjpvCOQoXOYiCaW5WCEo
         B8+aJLDzI3HX08AveTXCZDan4Quqk1NOCtES8Cya/7NItqEBQEByGfG+wd505T+9ZA8w
         gtwDf/63W0pEzTzKw4eZtvHZ9gtPjXZgAlYeLzelzpQT9WQ7Sh8zo2Xk50kY8jIgky+v
         1B5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pafk7wW3;
       spf=pass (google.com: domain of 3wzuqxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3wzUqXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GfZqTtqnioCtvgJ12I4zrQZoXqp72SIOAnHu11BIQZk=;
        b=Al9UCjKbZwQBWmfWa0hlX+Vy99QbNvou8eoO2M+mHhApSwNMF9XhpIpshyYtv9gp+w
         jqgH0v/e1OwFYKzahL+RhAEoKR4+/Jd2eIwb2KEYzQVxRh1FNsyoVkhurWZjco8E74vP
         16YRTwYbk1QU6XPGtJCuF6LXRzIpD7hJU732/6EHCyTFKyxd+Rq217Q1M4oHoUIJptBI
         szztlDIFvGI9PY4SDcb653Gj1ewm9p8zcQZ+HU6NSk9jsaZ2cjOm8HyLrl0S9a7Tvx9Q
         4Kwx2qsSWKlRzXP287h4UlERndCRUnb7X1cJYJJhPT/zNyVEizNlMLVz8HTIb+K73/9A
         HHiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GfZqTtqnioCtvgJ12I4zrQZoXqp72SIOAnHu11BIQZk=;
        b=URsS63jqCJ2v7mxVbfu9XWTi31OTgXmff+SXkF/hn8eqDg98Isu1iGdz1hpi2rk7Gf
         TIOHnXyDeKoBSgn/mng9mOXhVNbeTwa5OL6wCaII3/s/k96CG9+P8ke8znIlJALU7HFg
         zu1zTL+tF4eqUj/oqMv2ay+kGY5XudX/uAjJ7XRmTDUau+7yRMi08a3stWmhTj8Y7gxH
         nz5XkDH+c7SQrIPzftUN5YcSLskm8GU7IJYFZsDUqNgNveatYSTxqCFq633gQqf3nt0s
         t5nZhgcq9Rkurt0b3cMKSoTQldaO+k6nNJUOlbU3ORQJ9k561vjbnYN7fgV38AmNoVRw
         Gt/A==
X-Gm-Message-State: AOAM530pNr4hBpC9h/b3R/QEVeZgsJAgaVyYFuADn7f/82d8aG+5prlo
	u8sKLwQsq/ygGyIhzMRS4b0=
X-Google-Smtp-Source: ABdhPJyMSj/kFHBwMmEfuJuXLukjR5NxWtHI73ZwKeT/AkjJAnIvSxpt2X9r9fS7t+VxUsshjOGFUg==
X-Received: by 2002:a63:2a96:: with SMTP id q144mr1129793pgq.87.1596601796528;
        Tue, 04 Aug 2020 21:29:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:142:: with SMTP id 60ls500682plb.9.gmail; Tue, 04
 Aug 2020 21:29:56 -0700 (PDT)
X-Received: by 2002:a17:90a:1387:: with SMTP id i7mr1408492pja.199.1596601796094;
        Tue, 04 Aug 2020 21:29:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601796; cv=none;
        d=google.com; s=arc-20160816;
        b=1BEXyYsmdUZzRENwIuiFD4V2I1tVm0A/kpBgZpfuEAY3sEoH0U9n0zqjCrBA1mLdnl
         +cHSKycgsxf5ILirOTpP3SjwQVmZLEeo/tJHy5O1qmKGpFCY2JhL2NJMV3EC2JfLFrfm
         ZYDj7TH7Tx0eDl2fIuqhI6JqFDgJTjkE5SONung8d0yr+qgW0rr89OccEqXemdvEaasO
         Ikf7iiz732dtnJpv5/uiU8NRlpYk62r3s932VguejXtq7w22/SZSS2eKnTWWoW8HRs0n
         oVBvvZfUVg7s4oL/vQl+jxgUf3yYWIJAs111/8M12+6jBf4L/GEFtufDgwStDi24oZh8
         gabA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mFQWzCkGaiFIpXpMkbbRXHow6YpRUyxsgQjGovY4KbU=;
        b=VqDf79sxAHZ/AY+7wGUoxzy6tExt98qogzzpTuZCDq160F01z3K9dVyOtXqvac2BSW
         hqJJsjHCFBJbjNtzyNYfaGeXVPG4aLD2ZtdQPUucVzaLHzXyO7ULPV9pFHokhI+adR/O
         HXIHEX0i9OT/S67+WaQtcbECjl+fU/h0gyHvyX1+uL9SncrWnS/Pwso+Y1qAnvg3xADx
         nK97pwfa/tD8A0yKQVI3EamroH6kIMmRB3kZC15Io7bnvdg3HzLpo/jfVyWbplVAxHUd
         qENfLwHZYGSsyRDHQSkSgAFh0jnhvmy0ijy6tRqbjGMLG1TpVHud885NUowUVRAbe9us
         3osg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pafk7wW3;
       spf=pass (google.com: domain of 3wzuqxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3wzUqXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id t75si38909pfc.3.2020.08.04.21.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:29:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wzuqxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id w11so29719866ybi.23
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:29:56 -0700 (PDT)
X-Received: by 2002:a25:3803:: with SMTP id f3mr1978981yba.470.1596601795228;
 Tue, 04 Aug 2020 21:29:55 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:36 -0700
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
Message-Id: <20200805042938.2961494-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 4/6] kasan: test: Make KASAN KUnit test comply with naming guidelines
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pafk7wW3;       spf=pass
 (google.com: domain of 3wzuqxwgkcdy52na58go8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3wzUqXwgKCdY52NA58GO8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

The proposed KUnit test naming guidelines[1] suggest naming KUnit test
modules [suite]_kunit (and hence test source files [suite]_kunit.c).

Rename test_kunit.c to kasan_kunit.c to comply with this, and be
consistent with other KUnit tests.

[1]: https://lore.kernel.org/linux-kselftest/20200702071416.1780522-1-davidgow@google.com/

Signed-off-by: David Gow <davidgow@google.com>
---
 lib/Makefile                        | 6 +++---
 lib/{test_kasan.c => kasan_kunit.c} | 0
 2 files changed, 3 insertions(+), 3 deletions(-)
 rename lib/{test_kasan.c => kasan_kunit.c} (100%)

diff --git a/lib/Makefile b/lib/Makefile
index adaebfac81c9..8a530bf7078c 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -60,9 +60,9 @@ CFLAGS_test_bitops.o += -Werror
 obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_HASH) += test_hash.o test_siphash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
-obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
-CFLAGS_test_kasan.o += -fno-builtin
-CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
+obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_kunit.o
+CFLAGS_kasan_kunit.o += -fno-builtin
+CFLAGS_kasan_kunit.o += $(call cc-disable-warning, vla)
 obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
diff --git a/lib/test_kasan.c b/lib/kasan_kunit.c
similarity index 100%
rename from lib/test_kasan.c
rename to lib/kasan_kunit.c
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-5-davidgow%40google.com.
