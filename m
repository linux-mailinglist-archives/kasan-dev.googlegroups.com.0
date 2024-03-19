Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL7642XQMGQEVVUYUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C2DB880275
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 17:37:04 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-221d2420209sf6125538fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 09:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710866223; cv=pass;
        d=google.com; s=arc-20160816;
        b=lp7eLkcvKinpQNJo0qH8TzWUyq3iwQh+JFDF1IYVgu+LD7GwBqwP4ady0HHZXDfakH
         O+BG845aXyGahV7+X9D2RgzvdDMsSUsP6JkoZiEmTD+mZzvZdlUZcZWwbhn8fSDb8gjY
         8d8VbK9Ri3zz1mzqlSyade20zbnzy6QQiUKxjXTTZsGnKYwjcZrra/neFBkMpiSCz1ur
         2ZnS+oQHknZdLkmghAdS4T0x+uFSsYVKlqGy4BnM0NiSqx2bAeWleBZCL5CxTZDrzyPO
         dxa56O4/lJmLHDu46A2jcRJLAoFaRNN3VSQAJQFjqE8mDlitZN1UNoNDRuzvhw5jFvnP
         qolg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=UbHS22GsE+gkxIf2OjbmTo3rS09e7PE8oMRVeYRrEYI=;
        fh=Cb017/RScmkc3rBOqWJ+9I65Z/czOvqn6Fe42RapZMs=;
        b=way8MIwbvwhiNOjWX/2bsw6gVNWObrN68NVgmKZMBqtmA7Fnf1w4dl2ZPErRIbNz7T
         J8LtE9T06i607knyfvDeYA4fNu1eU52DC3aOwHdBznWQevp/lIMTF0CDp3LzdSn0lEpq
         0pFgtGzJB8RtCFJLRJ9RRSmM49Z0TZHXoXxDMz5mYbgRRGcuyzCATn/4cwT+eKQlyrUJ
         delQauHq/4DpEv11vgtMJI7cYrjQaRC7kLVJHXJVML8BkvH8GVyIKf/8+A7DsH1PthMc
         +UiRt3g/5tOdbOAnCX1adFVKH0bv84/M2R/heJchwtAMHrsyDLwIUqF6/BmkTMrP0VMd
         oHvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=10O7YvMR;
       spf=pass (google.com: domain of 3lb_5zqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Lb_5ZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710866223; x=1711471023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UbHS22GsE+gkxIf2OjbmTo3rS09e7PE8oMRVeYRrEYI=;
        b=N2gY1FS1T4Aj+AevAgdaYcr3M6R+2hlYZSpcV3ryNjqJ75Xfg9WGbFLWRicTEcxB/8
         Uk6sx6o20brx093CJqvvQXAGD+L6JtoFOKVGHIM7q9Qa9v8jpM7JMtQMIFiShmixDm6o
         t1D604h1Xy3zsXkXOUORJHzNMPamEdH0yRvmafEKoxuDMI3JZdyl+Zt6M028M9wCsl3d
         Y/7g8BAiFNAuHK7BZXk91g/7uBiJwBDP7M/3sWESBTepuDPgUlOGaM+GwztSMr0Fb4er
         E0b1INM7SnW7v8AQ+erH1LMCCOmoJSLxUOTR0aiB7Qz0vanH5X171bTCDeaNkNk6PLzS
         vvXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710866223; x=1711471023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UbHS22GsE+gkxIf2OjbmTo3rS09e7PE8oMRVeYRrEYI=;
        b=bIFstJBABvsOLJjwNrL4jWljmf7X0ECFsvD4be4qsqm7rbg+RgNl/E38qjzt6WfNpD
         gXtaZpVM3HyM6qjjUB0sb2R2cyIBnh+FcyAxz4pRB2/gBYfUtiPJ+zbMpHOEVX0EaIFr
         nRKZGaXfmlcCXztYILtwXN8dcEca56oWvUkjG+gtuwmeGTarw4O2KYehsrdBFnOJrn8E
         dUUCiw9l3OWbdKytGGgwbE+KPsjn2/b5OozVB/oM9r6Z7EOjlfaItd12cez1p/bO11Hy
         VFm67efwXDJVhrYhzoAB0hTvfFSwBZnXw3g/t0Eyln5t66T2hJbLmhwV/Yuz5CKXw+rX
         pUaQ==
X-Forwarded-Encrypted: i=2; AJvYcCVsDeXpByACIBMjhvEAxaAAQr9PsUWKja/3G5vvFnFgI9KyiBtWqOIAz6XnBGXeTEjQ+fq6JH6iAuC14IVcyS7Ac0fRb+Ug+Q==
X-Gm-Message-State: AOJu0YwyXjeEmPULb6wm6iJ1gmWL+cbuRuNO7Tz8knozXw7upK3qGt2K
	4DugeXe9j5VQvxSlvWWW2OrbYuW/9b8PqcjXt/nuGctLgdxk6ihZ
X-Google-Smtp-Source: AGHT+IEIWxYFLT9u3ZldqfGSy0K3p0w1exezin6wrRN9ItUhd1NaUA/OlL03FsV9EcEBke8p4vNrVA==
X-Received: by 2002:a05:6870:15ca:b0:221:c7c2:925e with SMTP id k10-20020a05687015ca00b00221c7c2925emr17731829oad.15.1710866223157;
        Tue, 19 Mar 2024 09:37:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:548e:b0:222:5ca1:6a8b with SMTP id
 f14-20020a056870548e00b002225ca16a8bls948103oan.0.-pod-prod-02-us; Tue, 19
 Mar 2024 09:37:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4/UCDkg7Xa4j7sMfZ2jiKT/weVXT9LUg20Ibl0bZOWn2zBw6Sqot2gBKm+eTP1WxAF6qpgkPXlz01cPat5HjGDdLfxjIGdLc7tA==
X-Received: by 2002:a05:6359:3085:b0:17e:c7bb:43b5 with SMTP id rg5-20020a056359308500b0017ec7bb43b5mr9612859rwb.0.1710866222340;
        Tue, 19 Mar 2024 09:37:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710866222; cv=none;
        d=google.com; s=arc-20160816;
        b=th27UuDF9QyNnX6lkgq84bA3IF98tyOt2c8pzSGJ8Nx7SztZXBTIEdhQJtZKLdq99T
         oT9VgCKct5XLUnqyOOH1Tv6O7GPMXvh0GjZCXaCcJFNDTgi/tcW6CK3TC6DqsuFIQrbZ
         MKwLGxkr8x+h1SFSKFrupxPfzQeDKdpaDlho/wwj0U5Oz9wgDeb95DPFL7PxB+5wvsR6
         CbQGKtOhOwA0RFnu0oZjPt4FCovlxl644DPSHl3sYLo2LLAHmFDYEL9aOxfjxjEzKcl8
         bemODs21jOv8ZagKmi3fSCEuAiQlXOPLkRvmLWNO9etk5TXJk/f9SdWJWIpsQNhPNluP
         3+qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Pe97FWHITdYkiCtSSFDy2YJv9pSAbWKeZZSBy5Rk1y0=;
        fh=KRC+SNqOT5KBzH9NQLUV9xVMxAMQkCGyrsqN45wJPsQ=;
        b=Gk8YdTdhrR9FKKNyvzcrXp+rRCPsx8kkrX2/1lqR+jgwyCeb+BRjlsPSWXpqW/3hGa
         P306MeV1omxHEgGago4GgOcx2CiKa9xPhC8ln5XXhDn4Q9hD2GWFVnDqvbHLmzclopJe
         dfU0VvlWxxjjxmfEU/UkMdKV+8ZbI6dSoba5VWCcMofFprY3LrmwDJclk3Sk+RNg+Pgc
         cTuIyitAIw779YwOrkqihu8UPJyBVxCe7H63aAjmB8L6352cGSE3yfYYGkiWDgBa8Zq6
         YVd9CcGDjWheIcNRy4jP8WbjXyIQywHyG6X9KJwG8re3hIJTDYwUmC+w7/6p+Rigd5Jr
         P9mQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=10O7YvMR;
       spf=pass (google.com: domain of 3lb_5zqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Lb_5ZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id q13-20020a63e20d000000b005e5038c57c3si1397450pgh.4.2024.03.19.09.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 09:37:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lb_5zqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60cbba6f571so110797237b3.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 09:37:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVoZcwQ9KFZ7nVaVKQmqmThNSFOoSOyCiUzPv+ZEPbNrHV9cMaK5DJNqWBFPawgBbwurcJSnQtks07Xa+ZowYE6ZLFm6ym1fwwUYA==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a81:4941:0:b0:610:c60a:bd27 with SMTP id
 w62-20020a814941000000b00610c60abd27mr1741328ywa.0.1710866221483; Tue, 19 Mar
 2024 09:37:01 -0700 (PDT)
Date: Tue, 19 Mar 2024 17:36:54 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240319163656.2100766-1-glider@google.com>
Subject: [PATCH v1 1/3] mm: kmsan: implement kmsan_memmove()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=10O7YvMR;       spf=pass
 (google.com: domain of 3lb_5zqykccguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3Lb_5ZQYKCcguzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319163656.2100766-1-glider%40google.com.
