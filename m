Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIFP5T6AKGQEOXHWXKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D1529F510
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:30 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id b25sf3783492ybj.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999649; cv=pass;
        d=google.com; s=arc-20160816;
        b=oUR5myLwKTT02qgKjQOlY2uDYEUPU6NHFlfGFssDD3E11icbeyFru9lTAuepI1K9bK
         Zf8GwNp2m1ILyYxO3DiQHWjzy4zxoQ8/f1rD3gjDazeenovSoUrCwoc3hKWN6mJwXcgP
         SESN4d1ryxTgxmXcNVY44y5amp5rE7icg3FRi1Qj0v1QuiO1MnWLEWdqXkw2KUrdZCwZ
         f2Bv8aO9k+WgjXPU/VBmdSFO7lFYA+/HyetmQm17EENms9XDyJ6Z1QEKez+h71PX1xww
         89j2X06F7gYbxxKki74j+CE4gWfx1GBbpK3H0uhpfia50wNi5OdRRUdfQIOZ0I9EXxHN
         edDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=q8+l1aJGXYLoE9QvTbysGIWbRXIs8qJHF/8ou9Qb3Is=;
        b=qv/V7lee3LKnHbsbK1qcmZ3t8OFhvY8ZgTrtuUSXyWrLw1FdQhqIo3SmIvo6c7+TA6
         6ldU2ykVKtELX5hOEaXPGbY5tIKVvqFhtEVKHZkTGoWAzul8vI46pPq/Ltgo6cGU86AX
         5cf3EVwKpaAridpeN3BD5oTs3ZbfMGFbfVQWd0H2obLh0RXyWcCeEUhwvPmVZdU15cgx
         noG1wz24CMWDTdG+jxnD/VnDULo0IbUl5QCztU9j3sZfKNlrNTQRF5P8TE/yrjJ+UlOZ
         2tEatOB8tVJS5lNlyU19miCf2S5EN1zkIWh2HySlsKJbIr6E67g85VjTgoGroMEsSSMG
         uYpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uX8trozf;
       spf=pass (google.com: domain of 3obebxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3oBebXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q8+l1aJGXYLoE9QvTbysGIWbRXIs8qJHF/8ou9Qb3Is=;
        b=GEkGRL2VIz9UabeuT5QR0dHdul8ibmJyBxYJCaqc/go3e+QtYZodhZsJXEyjb5fXuA
         b3zRfejHQpSvCoeV+jRqsydyiGbN6mZybCDZORpIteI6RbMZof+8iSznR1uLn3VBa9gd
         lXhLOTjBs1aHInVEqG9PJd1+Z21hZb1tSESmrAy2cMMEgEWOAvKhusT0l6u9JLX6exs4
         jShGsiJcmZZnHcKPDJEfotR3Bztylai7Ha0uUvSqCaWqeVzeytckgZMNGq/Ij0sAGboa
         TU7pLb2AvxWz4SScyFNaCE5pX0a96q5v5R3IKXTTU79a2ujF3n5w0PdfYc/QwEeZSpv+
         xTcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q8+l1aJGXYLoE9QvTbysGIWbRXIs8qJHF/8ou9Qb3Is=;
        b=NTDaq7iWj0UTJ/YoL3q7kR1PGbajZHAxv3oEP3QRmFef2XRVkUpS9VEzuaYnKsGGgl
         GyaWcp7vKDeOeZ1yYIOddOaMah3N/fRJcoVOPARNo7ueKuh0GVmM8Zu1pXOwuwPG7V6d
         Nk1R9f1qtKry0Nokc8kw7+0fOI8Z16w5ggYmiSX3vCnPLLeLuXIQyNHQXEW8Iq6/dPBM
         Zjcc6RVYPnLYy5tmxyhpN8JFYYfy0PgLzXExDxiCtM58GZs3JTfgggt6+1vWXNP2rd3c
         j8nb/ocuHBkSj7YKFVoiEeTFTsSf+P7GFednsMQePxjzmcejpT1GNh8pKW8jBqmzAmst
         ofFA==
X-Gm-Message-State: AOAM530vQ2LGlHeqFTqO+cfwRntqtFKQGUbW2EMJAiH44mhnFIt2F7n5
	VhhupfMLrIeGOHYov13smSY=
X-Google-Smtp-Source: ABdhPJxAg9E83zdcT3SrjCmMVDDUa1tbvllPndEj9Iuhm8RxhYLVmS9wH1bghHz7p9/RdOINY0W/YQ==
X-Received: by 2002:a25:6089:: with SMTP id u131mr8470101ybb.456.1603999649034;
        Thu, 29 Oct 2020 12:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:84c4:: with SMTP id x4ls1814292ybm.6.gmail; Thu, 29 Oct
 2020 12:27:28 -0700 (PDT)
X-Received: by 2002:a25:ab84:: with SMTP id v4mr8512745ybi.313.1603999648532;
        Thu, 29 Oct 2020 12:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999648; cv=none;
        d=google.com; s=arc-20160816;
        b=aV9iFfFJWXqgWIUXbdhYxmGYbuOkUeO30Sm52j+eLIPPVuZXuWfQbxEAJcOdJcylS+
         H6yX4YEgqopzwcSKn7y9QNlj7LbJTbWgsNBVhPNf6dmfC8nmNYS/BVXIzd7y7D5AGw2X
         Z9SpLleIh2UserfEE1qLWGwuwYXC44TZOmeBHjWuPecZI1fdhrITa2GYK7zxE9Dm310b
         GRZr23lYqYt7IjbTJ9oppNHxwp8YV26q9L4p7JB9xCH0Dyjc7+8QP5L/4kWficX3kOXi
         jyBhwDUc/j5iPaWX6jG/pASN7fSrBwRlYidnwCgEznFna05iT+9+dVEClI/DNI2gRyZF
         TnPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NNmCWg3uUJkm97N9bODpJVOfWoCAwpfkACCfjKkMoC0=;
        b=vE3C9k0+9LLBeFmg20zWBGrsHOyOeW0kLmsQuas4x60jU8Xbqqnd117M4eJ6sYEfPo
         /EMlATpDrpPAWKUtj7ZCJqkTU83+QpAJjlO9WX5MSAXMhzZCG0BwcH8oDC75CK2rlBe4
         qbPmr/dc9/VuISAeDlKHgWjSLRD4+to2L136edYKrhAiw410eFGTuQB1xql5H4ia+ndA
         D0JH+4B+YPq2fLqP2dj+YSJy6lcIdbFwvPqxF4dgd8EJMuzB/R55SU8NOekxuAdA6E4m
         ZUG9LBH5+MJ82wpzjMBb53Qr8uYy4WN8KvbcKQeJZZ8RFem+wvmTFkOEUJX0czfUSabs
         vkbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uX8trozf;
       spf=pass (google.com: domain of 3obebxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3oBebXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id g36si234643ybj.5.2020.10.29.12.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3obebxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t4so2492511qtd.23
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:28 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1192:: with SMTP id
 t18mr5862530qvv.49.1603999648113; Thu, 29 Oct 2020 12:27:28 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:54 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <f8006477b50e3d77005046a83a067a295c680327.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 33/40] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=uX8trozf;       spf=pass
 (google.com: domain of 3obebxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3oBebXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
index 6d31f1b4c4d1..652decd6c4fc 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f8006477b50e3d77005046a83a067a295c680327.1603999489.git.andreyknvl%40google.com.
