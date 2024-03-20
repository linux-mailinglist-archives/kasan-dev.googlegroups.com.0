Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEXQ5KXQMGQECK227JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id A7FD4880F79
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:18:59 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2d45c064742sf65548061fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:18:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710929939; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJZeg+RFq5JWJNJ6CjnWd6j1m20TbKJiNGnj1Q3A6/4U+leg8ajDx1PD3B/Z20b45b
         0eCTzOyxzm01lZdcNcn64zqOjhGNBLtSZlRHSu/9jXV31LxbkQuyS/ldizex6Xy71+nZ
         nqJ7RexzirUwtPANv68dCA+ZKip4gbbhfTwldjfdxW7b0SsR8mFmWXMkjIk2umqGo+wR
         RrS01ijoRJ6N0/hv88yIBWFkYo8AE8Gf8NY6AWSPmWz0fsM3luw8MMEEXo8bwhKo7BNc
         zwaP6gIi56Rn2nCgfOfxLjzUeHfLQie+Fa3ACOZjz2TVTngjqmDkpz46k0uihV+y6dpR
         UjQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=Ed1qjG6HI7/vSYB1DOt1vfBFetLKR6AbZFZntJp2o6c=;
        fh=sLT2rQQqIkB0jAlgxws3mOBi3VoNu6UMS8xTOS/XADA=;
        b=Uunm3eRVchRHVw1axRMh19yhxPqIM8PWqteJlM1z6h+TzuEUJadu5gHtiMx5rk7uTS
         lj0nTeR3RKq0PzI1pahbPr0JgQ9/74B5+L8iQGYvNfqpNf36efX+IFz7HTu7iIxAscq2
         ESzAvIjuQnO2PyLfz8PdR/JDhx0wb2w9lSgcKKP08eG52uZ1i5yNr42Y+i3jlrftw2Vf
         z4Gkah6Uuyp9QGnupBT01HN8DqofremeTj4wfiNw1FleP9Fgj73rsZ2VPeBUI2Vfttrd
         m9DkpZ7KFM3toyemYkkUDp6HnDcC1AQMEt0DUuEht+AKulCOuqx8B//BPcNccAYAkyPU
         /44A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TJVXIpRE;
       spf=pass (google.com: domain of 3d7j6zqykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3D7j6ZQYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710929939; x=1711534739; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ed1qjG6HI7/vSYB1DOt1vfBFetLKR6AbZFZntJp2o6c=;
        b=Eo6SEpdU9N8YrrdO0+zVxvkr3zugQP07j8xmyp/tt8OFWVe61vG2Gzv1PHHOxBiev2
         c4/FZTHBfitD56LVXCA7l6d9k1M03nLF1wIOiSwNd+fcPJTma+EWxxnCf9h+ceP2ezDP
         k9W+TOUEsQ6RIx+wNn9mItIweCOqA77XuCj64rOo8jszBDMcbsgCZIfvG0s1JpDdcSJ7
         HHv2cjpnaakWFnhOKgvVbFsO6qWiYzeHHaiwlyy9a3WCjajAyFf/JWBQiSOprFydkDYR
         2ckKCycRMq1bwr2P9PIz0rDAswJfJronB5gcmHc6ZzOdrlrjbs452pnDsQ0KSbt9DSsm
         hziw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710929939; x=1711534739;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ed1qjG6HI7/vSYB1DOt1vfBFetLKR6AbZFZntJp2o6c=;
        b=HUUzkXMB/VgXVH8oRYaXXHNX/iVSwLajtRzAHYH9XreZ0T+Cd+nuUu0+mfKRIPITpx
         xE3H3aIAP9yFchc90vkQA6reWlous/s9TaG0f3rBycC5tyyENd81d4k7mmx58VVpEyLg
         jiunQFTP+RYCCzyd43xmcb50Ly2CyHAuGcJs3XiMfExCWexqaH7AgqxvVyLDnTdlylVs
         VHVFQ6aadlfjmUR7qpNJ+tEw+FgfPgOMjiEKTDuqopyLYPzX7XH+KnDtlTmeALWS9qSp
         FHZx1rEYE90WraQaaxvBtkrJuqxhKji9Tmpgs646x2k8RKxOfmKqIcr4wInpOg6qIqs9
         u63Q==
X-Forwarded-Encrypted: i=2; AJvYcCXWEUqzOlwid9HafomXmnLsHvsBjFf4EHsDxL5xazVZJlSW2mGflOXovS1nmemW/fRdMFd5AGHIs6xWs3FjTyh5igXlfjeKZA==
X-Gm-Message-State: AOJu0YxR8s4UEoQKKWvctWpXUU2bnxgfNklWCLNYNe9PFShhlwe9AsLz
	P0SXoMMeiRA12jd4c2oeIGL8cgLQ60HGXVTviYh8zjkAOKvPr+GQ
X-Google-Smtp-Source: AGHT+IHd+HBiA7/OXlxjcVddRoFkxtlMaEJK2Nkpien1Yf46fVHwDApyu+igxb70t4S7oZaTn/4p7Q==
X-Received: by 2002:a2e:9106:0:b0:2d2:3810:552 with SMTP id m6-20020a2e9106000000b002d238100552mr3207748ljg.53.1710929938480;
        Wed, 20 Mar 2024 03:18:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8197:0:b0:2d3:3a2f:99a0 with SMTP id e23-20020a2e8197000000b002d33a2f99a0ls540242ljg.0.-pod-prod-09-eu;
 Wed, 20 Mar 2024 03:18:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTT2fRZf0ouUYAGk4KWDopzSQK+jnLdHOtH7JdFxFbxERGjmuQSuvyzd0jgjYmDZ83fIWATjvPY/3hZggCqHWIBpIUNzLliB8wMg==
X-Received: by 2002:a2e:9106:0:b0:2d2:3810:552 with SMTP id m6-20020a2e9106000000b002d238100552mr3207690ljg.53.1710929936377;
        Wed, 20 Mar 2024 03:18:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710929936; cv=none;
        d=google.com; s=arc-20160816;
        b=kH/TeJQ4yGppxKFG2uQAFcYBJ4IytBPEs9yL/9HTor3aZDAZa/JY1Rw1aPjsTY0fnr
         mrEbaug6LByWZOKspzUzDqNTm/LGw4FhlptL97PyMpIdP5waXJ2w7RPeluE2KjEG4luS
         i/DAmxTvqfw061pwQtw3x2eT9B8S1YNdMp48bYOIsTW2mfKVQjxpEKUPrwXfXTyP0CAz
         GJTCPo27z08wRbEn6Xq1nsNDrynD2tcsCj/pke7VjwLiqVmX/ZyshQfb1Pv5OHXdJEb5
         qalKCeToEYYtMonZkzHSmw02VB81LMdJA+sTxQQyohXljqB6U7DOTaReWaHLzAt8IsL6
         3Npw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Pe97FWHITdYkiCtSSFDy2YJv9pSAbWKeZZSBy5Rk1y0=;
        fh=tRtJr3xQZcnC/64QgtQSsBCo3RUAUXWvehaw/PuGCgw=;
        b=WnqAyzMgO7EuJrdG+qWCieUMsoVAY7K3Ul731jKn0MhZpNol+vMRIS2iLxxCJSdPDe
         9iE8IA05ZSz9XlRBHxM18YVy51v23f01b2PmO9FIo+2Xb089JZdJU2SB+W0sTSKuh1oZ
         mxWkYoZ/9X8e37fJ7K6tOVLmrG3EAFRGo3j6n9RVG1LAtTD8H/UEGbJDkUHeU9z9ZGjf
         f73PSRqMDli0QnUbpsJqKoSUU5dexTATaMcgvjVI3JehwJzAjWRauyQeqbbzD09TcDAH
         LEbyrBD+s61RKcOREMh754WLE/sMfp28+inuj7OTrRSsCuXZzCLG/mUv4vJBU3Fhowna
         kD9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TJVXIpRE;
       spf=pass (google.com: domain of 3d7j6zqykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3D7j6ZQYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id d26-20020a2e96da000000b002d2b234958dsi795349ljj.5.2024.03.20.03.18.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 03:18:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d7j6zqykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-56b99ab60faso692144a12.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 03:18:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpFgVJ8krQFrDhGHSzauGW+PsU90K/sqMsazOWCPJiUnFibofBvgIAO3Mtpkuy9ZwC2piBlEmkM9lHBFQ5/VUGnTjPf1K6Q8X2dA==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a05:6402:3893:b0:568:a515:30e8 with SMTP id
 fd19-20020a056402389300b00568a51530e8mr77979edb.0.1710929935435; Wed, 20 Mar
 2024 03:18:55 -0700 (PDT)
Date: Wed, 20 Mar 2024 11:18:49 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240320101851.2589698-1-glider@google.com>
Subject: [PATCH v2 1/3] mm: kmsan: implement kmsan_memmove()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TJVXIpRE;       spf=pass
 (google.com: domain of 3d7j6zqykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3D7j6ZQYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Provide a hook that can be used by custom memcpy implementations to tell
KMSAN that the metadata needs to be copied. Without that, false positive
reports are possible in the cases where KMSAN fails to intercept memory
initialization.

Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
Suggested-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Signed-off-by: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
---
 include/linux/kmsan-checks.h | 15 +++++++++++++++
 mm/kmsan/hooks.c             | 11 +++++++++++
 2 files changed, 26 insertions(+)

diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index c4cae333deec5..e1082dc40abc2 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t size);
 void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 			size_t left);
 
+/**
+ * kmsan_memmove() - Notify KMSAN about a data copy within kernel.
+ * @to:   destination address in the kernel.
+ * @from: source address in the kernel.
+ * @size: number of bytes to copy.
+ *
+ * Invoked after non-instrumented version (e.g. implemented using assembly
+ * code) of memmove()/memcpy() is called, in order to copy KMSAN's metadata.
+ */
+void kmsan_memmove(void *to, const void *from, size_t to_copy);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -78,6 +89,10 @@ static inline void kmsan_copy_to_user(void __user *to, const void *from,
 {
 }
 
+static inline void kmsan_memmove(void *to, const void *from, size_t to_copy)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_CHECKS_H */
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692a..364f778ee226d 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -285,6 +285,17 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+void kmsan_memmove(void *to, const void *from, size_t size)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	kmsan_enter_runtime();
+	kmsan_internal_memmove_metadata(to, (void *)from, size);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_memmove);
+
 /* Helper function to check an URB. */
 void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240320101851.2589698-1-glider%40google.com.
