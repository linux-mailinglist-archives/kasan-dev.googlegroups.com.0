Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTVAVT6QKGQED67BFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC552AE2DE
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:31 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id w12sf28772iom.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046351; cv=pass;
        d=google.com; s=arc-20160816;
        b=sHsdQ/m5rrELlZF7HL7h9qu/j6HAPMIG7kCi615aIYVrqPE1p3fAW/7wFJGQQ0yEYr
         2sJThwfGq93hzAUxA4lO2Fbj8rjwRImDIm1cbraAmcv+V/2VULF13yyD6k9zg0QCIwd+
         bfR/ImrksOVJmxmwiQh6n8DY+qziDsmpYh8j0cF5n1Yp45LqmhafpE/y91juVUUdeY59
         SVnNErvLfK9Mo56CXzE3cEwpVtVJoy7PN8nQrLm8I+6I11Oef5OsMjSnlVcgq+lNI94p
         UzpF0Cc1aqe0AU5bjh8bNqk/7+gU0mD5NahJEZI6TyEq8xYeQg/UxVRlp3npJgNyUXH6
         Hmww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hnX7CELPt3lWjK2z+XkoveYe/y2jPd5j/ogRc8sKkkE=;
        b=YYplUjKw7OLyGbzx1iDu2sl0MhwO9zIX9lkZXGksG001fgmuXx80KbqEfYX9nbuMMf
         GEUY7dMGYBrKytkZdLY2EpjFX0+VJbKEaSraF6qfAOTCJ2uK5ivRHmBOzVaHPMA5ty9Z
         JxnsjRtCavOuc2+yJoFunjlI9N1FNLzUA9SYY+e3pkn2tEFU3H28cM6FvSYJzvZbHR2K
         cJwnd6VfxXbtifECX5yiebZlhDgsMy7YukI7BUS5ETZobVVC4hs2RkaUKAql3FNvd61V
         t/0/Getu8zJcJsIrPBnLkJFV3USat7tEeEPsAyIXWDXTEnM8NkvXg4iXrKEwUUlZUkZY
         P8sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XwoM493D;
       spf=pass (google.com: domain of 3thcrxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ThCrXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hnX7CELPt3lWjK2z+XkoveYe/y2jPd5j/ogRc8sKkkE=;
        b=oepZS0YCi34X/k31S1rYaCAVtpVrrDG0uUpMBxej5GH4UZCITZ0MXcYn1knSNV04wk
         7YIFSOo4d1lhed3+SuOMeKlVDAEjFvJf1jzyhHQ6/fTEMhRUt58bRnDmbvBe/Omu1aCE
         UzfPcwL0t7E6pBycE0v8vUyGW9P3c/BGAyBd4PlTDJa7njj5s8NF/AXkHFVbRlJXeL56
         3YJDb6BismCiJ5vpdSGrrb9JymA3PEJSQXqAw4PMF56rRBipg4BhZZOLmhQbYE2zD5sy
         UhXqgEH3C8thukjQRLibYmGYaOLcc1C6p5tt4LbNM88pJsIRunB13OBsrnuNdY2a7Ao5
         Pp+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hnX7CELPt3lWjK2z+XkoveYe/y2jPd5j/ogRc8sKkkE=;
        b=aJHfR4jiuyi8YUPBxgEfWOqwJEbW6qXni1c+2qfpGgrAdbpXBxZOvW4zkoOk1umDl2
         AC3edo1e/UIc0pT2gYwybkhr8ru6xULGJyOcDDaGF9bS7V47WSC1btHKu5CdsnHdG3Rd
         75LBpOX9oAEKz2ajZddE5+4/K1+KK88v+F0zM3cDAPHIrq1VNTIWVcZEw008kzEZtQw2
         2ZG33l98FASgsLDvk4zL2vVgsE0ydetR94xO/tSBE+/Dr1W928jWfBvEvMEg1muh13un
         ZDlLgwkgBo3hcTLKl4tqJUdF6Duyvt3ko5gaIw19mWWoIHSf6CWQ6kTjO50Be/o3UHRA
         sNng==
X-Gm-Message-State: AOAM5329KoE22YBpmGaqg5bd8ZONDrlhLPYn3ukESkTtSM+20FSnZSP0
	LIHI8q0crtlKcntV92o7SOs=
X-Google-Smtp-Source: ABdhPJwQuafnulZAn4N9KsoPQPiO5nAptTDhSuIuTQv9Y/pXy7kzT3b85Q7cFmaqa9rxOx2QFLxsow==
X-Received: by 2002:a02:70ce:: with SMTP id f197mr17614037jac.120.1605046350981;
        Tue, 10 Nov 2020 14:12:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c4c3:: with SMTP id h3ls1524007jaj.2.gmail; Tue, 10 Nov
 2020 14:12:30 -0800 (PST)
X-Received: by 2002:a05:6638:d7:: with SMTP id w23mr17775954jao.131.1605046350645;
        Tue, 10 Nov 2020 14:12:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046350; cv=none;
        d=google.com; s=arc-20160816;
        b=wxo0vfzUDrcwxFC5+PxvpyX89SrmEv1LU6WpXvsLkJMGY5nmhMqObvxuu8zWL41aw9
         kQuNhxvjooRDz6KDhm8MAAnfW+stgQDkknuLCMuY24VwMZjUQ2ewtkQApIMkGhcF8+Kk
         dtTsXTNgiqbyBaItkqoZtzT0L/4JJ/SjDdBIH8nLP0U/KNQoAKdYvWMoc0h7ievwPDLa
         wJuAuvVB5tf3Wrv6FUEVuqxkDpiRHFU9Dn1+glqyhhiPeHq6EzSXSAy+Z5i5fuZYfaV+
         MzzsWSTXTSR0NMepAfa9B7ZXwIAhEWVe5UOkc1j+cNkPLH8mmK4e97gODLceD8hs3JJw
         VOgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S5GVREd9VqHHCaX+FFNS+NOU5hd6lun6S29ewqSBNuk=;
        b=NTlmMuSVRHp23qLfnb4EK6N04ae8HjZ54Jtp5seMF2pSvIiUhIkvYJohKyuQFjrhSa
         nBu+JObR6JG3m9pNgYbBQgbMiqaLNFylKaPAzHx0F6m/k4JmGBpBn5Q6sexDY8CW+ef+
         dahgvD7MxkLifnYmSNRfv8MCI9LJpSmitu3ZN6u7htjtbcTVSdAl8P9NE3veheP/+Z1N
         c/g/FcbhCbKyekvC3wCYC7dx0WY6txS9zKsTWfpfbPVZYq/9JL4yZY21QkbRLKSP4cgH
         H7L+zBO9yrr1RB/0E1ari0WH3qN4uUuwh484oLpneBFClLk8PrbY7XCwznJEKDjtEpoS
         yrsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XwoM493D;
       spf=pass (google.com: domain of 3thcrxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ThCrXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id s11si17369iot.1.2020.11.10.14.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3thcrxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t19so8471005qta.21
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:30 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4142:: with SMTP id
 z2mr8829724qvp.48.1605046350079; Tue, 10 Nov 2020 14:12:30 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:32 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <b484d6cece68422a6cc5399dc7ceb69ecbdeeb22.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 35/44] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XwoM493D;       spf=pass
 (google.com: domain of 3thcrxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ThCrXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  9 +++++++++
 mm/kasan/kasan.h                | 26 ++++++++++++++++++++++++++
 2 files changed, 35 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cd61239bae8c..419bbace29d5 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -230,6 +230,15 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_enable_tagging()			mte_enable()
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b5b00bff358f..ae7def3b725b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -241,6 +241,32 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+#ifndef arch_enable_tagging
+#define arch_enable_tagging()
+#endif
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_init_tags(max_tag)			arch_init_tags(max_tag)
+#define hw_get_random_tag()			arch_get_random_tag()
+#define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b484d6cece68422a6cc5399dc7ceb69ecbdeeb22.1605046192.git.andreyknvl%40google.com.
