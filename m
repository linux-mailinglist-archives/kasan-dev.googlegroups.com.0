Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFEBSP6AKGQEV622KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8104F28C313
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:13 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id r10sf4448236vsq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535572; cv=pass;
        d=google.com; s=arc-20160816;
        b=wko9nk/HBl2QpQ7Pz8JAOQ9s/v3RBDzga0PFzcg8dS70Xjo3Nvjk1JJfPH6YxIQfuY
         Srz39ILqo6WnBCGHcup8Ay9NYIVAbygAc2WWL35tVjuZkGYMz7aszjKCe6KZwfjgrkMe
         dn605WnMjz76Ti1FBJZNxLpxiw5bSmVAAanr9KrOa4mjm4PAat8dZwnPRCSeyOSIztaD
         H1B+EERpcY814DW46pXaP2X/aRd9vKNHovdGq01IWorCOXeameUAzIQi7moFZoYDHagZ
         PPCjBFfwHefvJrWUdnVLjgdX2n3Nl4e5Kn9OxwgZvdRACCEP5J0pgrMpE/NkqgbMClkW
         oAHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=q5P2pwLnLjyktVZosej2SvCUrkZ78ZTinA+BUkx5DbU=;
        b=uJpfY4ZmvjBwVT+9lZ1AVT+Jk6D9kbjDueTfsfKZtUHKZIBr5CaXn1/NiMDMm4q9tk
         /mcdPrCRnUzdcbmfRV8Qxv9MvM5rgDyHvasGWZLP4JCmLGQoP3a4c4tSWJjBRpUMJZUO
         n42adkBKEKChhTMLR4XA6XfD+5x23CWURdXIWdEdzjq03lNFVKh3xjHV2KvzKV8GDhPk
         /7Vpww0RcPpD+nmkwR4agWumYBFHTRqkThwAL8tX4U5aWWT2xcBeuha2I3k+B3p6T2Vl
         ndAtYAccGEkhR7CzPr3VfeKmwoxSuilgdZn4fkz5yjMP3dGheyOOqLOSUEWwZm64ClZh
         OusA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P9NNpy9d;
       spf=pass (google.com: domain of 3k8cexwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3k8CEXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q5P2pwLnLjyktVZosej2SvCUrkZ78ZTinA+BUkx5DbU=;
        b=mzcEWtQeCJLQ2OUGjoisI8QuPmFUbnptVcH0xTVdaatPkXHDB+W/L+i8DzOsEuoGzs
         jhV/5e/p+3G23hT/N/IV94o4uKJzfBKfsvTTkkxfXXKgydPiFyreZ0oaTrMFU5P0BAO9
         QMy58xvL7z22EmBxJM2cJtVWf9u2G7EG+MRcEam1zy9q4WQAU6HclKl546mPo+q+pJlz
         te5/O2/SyGk2xtfcihI6ur7wdlMcEQ43GYrCqZp9YxL7jg5YlZb3Ay3A0kAY39h7WExB
         PLwoFx7ed2KYtoLr65INrrfXuNFDDz8u4bgyEL8Twzds02pINNyJ17R6yWwmuG0u5Sth
         h8pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q5P2pwLnLjyktVZosej2SvCUrkZ78ZTinA+BUkx5DbU=;
        b=sWrJPPftejYOlAGPRhcKleo3g1xU58IzL4oWpKzL5dbCRxDqH2D4abgQ6DFU2zZNAC
         83+pRLGAuNoduQ8k2EUNrXsSOX4VzJnYDjKhUk2txuwimAttLz/qfjrmJXredS+8pMXq
         u4Gjn2uIw2tblc+6PO1mmenMFmeii8X5fUbULGeBEOyVQTBcR87IHDp060QGFHY0tjDl
         fQVCLix9jzd/U9PLynHEGa58KDp4a1E7Hve0Pxsy9eTULkSXcKwiBAsCwnfMqIBgeYaK
         bRLWrTkpEJeSqYWq8r/9+4gttBzoFCe6FtsqOWO5MqLbpLiEzI8qclrK0TjxrFjhwg5a
         kRZg==
X-Gm-Message-State: AOAM5331nAPdfCYerMF1/1Yi33h3jLaAdRX2Q4bhdz8jSoNzMBNWzeZT
	rQno5wgqaHFySYJIiG279jE=
X-Google-Smtp-Source: ABdhPJzhVra99I4Cz9Tom8hOeBouqbgBHe1ruQCaxvHh6pZvTIWxWihzxYEbK9oagTNg9IRaMn3fbA==
X-Received: by 2002:a05:6102:237c:: with SMTP id o28mr14668339vsa.60.1602535572614;
        Mon, 12 Oct 2020 13:46:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e29a:: with SMTP id g26ls1063161vsf.6.gmail; Mon, 12 Oct
 2020 13:46:12 -0700 (PDT)
X-Received: by 2002:a67:ef1b:: with SMTP id j27mr10712412vsr.1.1602535572151;
        Mon, 12 Oct 2020 13:46:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535572; cv=none;
        d=google.com; s=arc-20160816;
        b=fpGMfojwQyR2//MXu1sb6Fx8aNWVU8qi8jntAt3nPAgygOV1Zu7TV2DDCkrH+Poetd
         IvnpC+BFmdFRQ/CGWMLQ4gsUuUcc8SPsGFgE+IvafCjUCjt2N9/CkNx5cl/Re0OqdUkA
         uaru24sdnfuUa/NSrDsmWFl8Y258SzWIBa06ah1Lzpib5Hg1Fr9RO/XdX6T1SNNp8BBb
         SahjXikLgpbnENQmOyxYZqIKkaRfLD7tXvmhhYsEuhCW5p+Knb4cpYrkF3s38PcoUurZ
         oLKucrdXYt+NjD7pxeJ6pwEqYWCdmJvGXGz+dY+unaA38u3guvPHzRqEt7Nxw3zCBW5r
         5FHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=l835kVUvCOUPQzymSXPKbaJ+1+IzaMSz+0eMBwoZxjg=;
        b=jKWSP//Gzlc1TJ1eOoa6rfGB8Ti10mwqwDSPJ3BAbUwyebfS6bnfkndr3r4nLMT5Hi
         1H5tuONxSzrVybgC9eLsD83u5QeCJ0Or01GSV/JRwaVyK07OYj/9LVUd72Esq/WUWkSK
         o8KztcxibFHhQ4GWgYhbxb2t+L5XNiDJSgnxpXspgjChV+voMUBdC/zxbpnkqW/f6XAI
         7jdQ9Mh3AwMJHtRhv3frZbbSrql+GyDSqZ1YDMW7opn3ZUklA4FIScF7TIaivQSdZO7R
         4iqjHvJsk+DSA6fEk56jkS+2CUOacUaz7TS6nE0aS3tNDVds18qqMteSOtuAUlJcNtcQ
         2JKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P9NNpy9d;
       spf=pass (google.com: domain of 3k8cexwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3k8CEXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id u25si1272170vkl.5.2020.10.12.13.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k8cexwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d22so3070348qtn.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:12 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b308:: with SMTP id
 s8mr27714655qve.31.1602535571727; Mon, 12 Oct 2020 13:46:11 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:39 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <d42cc8d9227bf37eb88a7068addacfee13b36104.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 33/40] kasan, x86, s390: update undef CONFIG_KASAN
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P9NNpy9d;       spf=pass
 (google.com: domain of 3k8cexwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3k8CEXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index 726e264410ff..2ac973983a8e 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d42cc8d9227bf37eb88a7068addacfee13b36104.1602535397.git.andreyknvl%40google.com.
