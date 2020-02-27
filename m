Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7VT4DZAKGQEGJ2TDEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A0E1728AD
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:27 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id w62sf659552ila.22
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832126; cv=pass;
        d=google.com; s=arc-20160816;
        b=YfmJ9hqIhD7LU7YsJV+urZJ6dvqzJ+3WmLpTyM4/G0iPFcuIvYXeC0EAlWTZpZPwmu
         Cb7rDWXxUxmioXVuFhyCo3Y3C9L00OQN7XLapaVO0o5ofqlCRfuCuLHMGaDNzIzcKckf
         FIjYoq4m6jmFguyKv8Erm/GScKbYSsQRAIWJxnzfIvPjogFcMpnlIr3MhqgcT5rXg0Mi
         HeJHHl+pQQvcxEwSfXPNM6hxTmR5RuPXP6ry3xBGaCneGcRN/GyWT4QYzUzRni9+mfbw
         78GsMRYfza1/R2MOI/+rz3Ya/vNCVttVGiSA5709lG4s11WruCFtt2A9w7VhpcXnMOsC
         2B1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JkNGVbimOv6V4OtSR+S8oCHINUyf1krBHpSnaVq8XXE=;
        b=nzRBFM58QCJN871GrY6DOBcxCxSheps3aQSkpwcIDlk+93fIXLSFB2ucyvWvMVYjDT
         +K3dUBkICHhccDKNyBsliq+FQjJCVAeZ37FF3hc6B5l8uMKXeMbfUU+NxzTBErWGFcpC
         9pKh7PHkclnw2TkNA0klJfuP96XWwOzkcFT9D9F4d3XAw0DL86coUw6OoiusZ14WomIi
         oL9u0X6hrhET6X3blkYErz3YSZGIYz12/ygg5FZVlac9CpsohdsQQidV1OXYWYI6A1Vw
         xyfWGr+KuU4WVsWBoxpKBW7r9aBRnh2XlkimPwAKYS5XBByBZl9a86GgBI7/g9vL+fTy
         /brA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U18RVdaW;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JkNGVbimOv6V4OtSR+S8oCHINUyf1krBHpSnaVq8XXE=;
        b=S5bXrOj62beMdt34YjAJpevNcAEmCxXh5Mv5jvqTkvWmFr/p3u7j5uMIoyRLeGJT0t
         utdaLL3M+tfMBlkfCYIy1/BLBX3hYOEa2/Q2oiqwdaVdZIngWcjxUyMb44EQH/5jDwoI
         E3y7BuL0bZhIs+a70zx98cXfTQ9hccCEG8L2aDS9GYOSDGAr7VVxT2muvIGFNfbki7VW
         H2CL9iaFb2T05EEw4tE6z+qO4S5LHaH2rlCDtcdC0K1N3uPfl5+vR4OsRBcyJ9pJDXL0
         eAzGuoQOOeAnqQrcY8FNWrK+pnqmL+Xph6qUHq52l6m8M2C/Hvel7p0OC9ixGl1if8H1
         WAMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JkNGVbimOv6V4OtSR+S8oCHINUyf1krBHpSnaVq8XXE=;
        b=nn1U4Kt4Oyc2j49mCLbhaJknZDUxym2stnuGDl5vZwSRORJNpTXXl7FToo+FBi2Vaj
         KA7UvVBwqMvcnMuzKTK5qhPZK+yC24rJTsFeU2f5UBrGq7n5ELtqHsOx33bmIGqWUV1z
         imaaqczJILSAjYxPYWHU4DVyFW/q7r+GIPspDooyxQKx1cgMCWpzWHNjhiahhdwG9BDR
         BQw/lKdgPJ48xPeER4hqD4w6SyuaoHKXWpJX79ywmUQp+wDTQyYxxh1b5P+f3QabgvWH
         Ft39eF4qaYlJXNyU47nKiRutXQ/hxtdfQB0UkPwtHiI51x1fEgxSsUtfQj3fdvN9gTQu
         vCnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWn56gtQvRXNII9n/BRr/JR1qUoMLu0iV87mO1EG465ebRIvrde
	t2S3JkTLLxh9dnI+osadB9w=
X-Google-Smtp-Source: APXvYqyPjfAOd6adxI5xfMs4Fo933tAdUCffL4aEBPjeWrLQCQS6qp3tm6PWgzEyPijPaEKNf042OQ==
X-Received: by 2002:a05:6602:150e:: with SMTP id g14mr696880iow.190.1582832126184;
        Thu, 27 Feb 2020 11:35:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9057:: with SMTP id v23ls127454ioq.5.gmail; Thu, 27 Feb
 2020 11:35:25 -0800 (PST)
X-Received: by 2002:a5e:a611:: with SMTP id q17mr499569ioi.281.1582832125907;
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832125; cv=none;
        d=google.com; s=arc-20160816;
        b=hQx7LK7IQkpsSUqVVzbxe9imtFvffRaygOcrzGLIVnEjhy1Pd66GvgWsuJBP3iawR7
         59E3yt+9X6xD7GinjLu2B4V9DAU3DClxmYvCHjyelSn4c6WUx9zxRUcJlQIZAiYnAZZp
         5Ck54XAx4gRjnxF5KdteuvL0T0AjC+zVrXT12mSLSkNQRPu7AKt9BCCpu4sYxBJd9Hps
         vLtu7Wwpfnz/yG9IIIcDbOtbcMZ8dHI11BpJvHIjWz7UonFGWPR+qkB7POxjWuI8p02I
         YHtvDROte7ncoFAXiRqiLsek0Q8L2T95v0mfbcvonp2iBFqU04bxH4WzTIDK5PRRW6iv
         ZMxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tZTI1WKOfKcUGuqkPLx5fh8/0duDs7Ezr+5qHoGz4tY=;
        b=VmWzB3cWl0PMj9UO+38MHpmZgQsP5Mpt3tkwTPnbDV079dNw6MrG4a471fvTVpGAb0
         7hrgwBMT4+FPYp8N4R4oSoaZe2T8ziMIXk33NDON7aufMZpUVt1AlaFTdn7174Uh9ug/
         v8i8U3NLV/B9q+J+9VgSTd5ecC0i82Bs69ssbvMdn3igIJAQhmMdfBT9sVFklohgyr79
         rVeTGV9rIpHHPXDCcEJsJ1o6IikvsvJjjPwahqBHFVjnQd0RcLHxFBNjgKEDqhH4uuGA
         EktYWEtliwEe1Zk4ro+pvaStiRw3LzPF20d4BK/bv0i34I/uXS++oKkhCIeQzT+NCEgi
         tDDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=U18RVdaW;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id r5si26188ilg.3.2020.02.27.11.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id o24so328349pfp.13
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:25 -0800 (PST)
X-Received: by 2002:a65:668c:: with SMTP id b12mr914117pgw.14.1582832125520;
        Thu, 27 Feb 2020 11:35:25 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id w11sm7478980pgh.5.2020.02.27.11.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:20 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v5 3/6] lkdtm/bugs: Add arithmetic overflow and array bounds checks
Date: Thu, 27 Feb 2020 11:35:13 -0800
Message-Id: <20200227193516.32566-4-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=U18RVdaW;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

Adds LKDTM tests for arithmetic overflow (both signed and unsigned),
as well as array bounds checking.

Signed-off-by: Kees Cook <keescook@chromium.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 3 files changed, 81 insertions(+)

diff --git a/drivers/misc/lkdtm/bugs.c b/drivers/misc/lkdtm/bugs.c
index de87693cf557..e4c61ffea35c 100644
--- a/drivers/misc/lkdtm/bugs.c
+++ b/drivers/misc/lkdtm/bugs.c
@@ -11,6 +11,7 @@
 #include <linux/sched/signal.h>
 #include <linux/sched/task_stack.h>
 #include <linux/uaccess.h>
+#include <linux/slab.h>
 
 #ifdef CONFIG_X86_32
 #include <asm/desc.h>
@@ -175,6 +176,80 @@ void lkdtm_HUNG_TASK(void)
 	schedule();
 }
 
+volatile unsigned int huge = INT_MAX - 2;
+volatile unsigned int ignored;
+
+void lkdtm_OVERFLOW_SIGNED(void)
+{
+	int value;
+
+	value = huge;
+	pr_info("Normal signed addition ...\n");
+	value += 1;
+	ignored = value;
+
+	pr_info("Overflowing signed addition ...\n");
+	value += 4;
+	ignored = value;
+}
+
+
+void lkdtm_OVERFLOW_UNSIGNED(void)
+{
+	unsigned int value;
+
+	value = huge;
+	pr_info("Normal unsigned addition ...\n");
+	value += 1;
+	ignored = value;
+
+	pr_info("Overflowing unsigned addition ...\n");
+	value += 4;
+	ignored = value;
+}
+
+/* Intentially using old-style flex array definition of 1 byte. */
+struct array_bounds_flex_array {
+	int one;
+	int two;
+	char data[1];
+};
+
+struct array_bounds {
+	int one;
+	int two;
+	char data[8];
+	int three;
+};
+
+void lkdtm_ARRAY_BOUNDS(void)
+{
+	struct array_bounds_flex_array *not_checked;
+	struct array_bounds *checked;
+	volatile int i;
+
+	not_checked = kmalloc(sizeof(*not_checked) * 2, GFP_KERNEL);
+	checked = kmalloc(sizeof(*checked) * 2, GFP_KERNEL);
+
+	pr_info("Array access within bounds ...\n");
+	/* For both, touch all bytes in the actual member size. */
+	for (i = 0; i < sizeof(checked->data); i++)
+		checked->data[i] = 'A';
+	/*
+	 * For the uninstrumented flex array member, also touch 1 byte
+	 * beyond to verify it is correctly uninstrumented.
+	 */
+	for (i = 0; i < sizeof(not_checked->data) + 1; i++)
+		not_checked->data[i] = 'A';
+
+	pr_info("Array access beyond bounds ...\n");
+	for (i = 0; i < sizeof(checked->data) + 1; i++)
+		checked->data[i] = 'B';
+
+	kfree(not_checked);
+	kfree(checked);
+}
+
 void lkdtm_CORRUPT_LIST_ADD(void)
 {
 	/*
diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
index ee0d6e721441..2e04719b503c 100644
--- a/drivers/misc/lkdtm/core.c
+++ b/drivers/misc/lkdtm/core.c
@@ -129,6 +129,9 @@ static const struct crashtype crashtypes[] = {
 	CRASHTYPE(HARDLOCKUP),
 	CRASHTYPE(SPINLOCKUP),
 	CRASHTYPE(HUNG_TASK),
+	CRASHTYPE(OVERFLOW_SIGNED),
+	CRASHTYPE(OVERFLOW_UNSIGNED),
+	CRASHTYPE(ARRAY_BOUNDS),
 	CRASHTYPE(EXEC_DATA),
 	CRASHTYPE(EXEC_STACK),
 	CRASHTYPE(EXEC_KMALLOC),
diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
index c56d23e37643..8391081c6f13 100644
--- a/drivers/misc/lkdtm/lkdtm.h
+++ b/drivers/misc/lkdtm/lkdtm.h
@@ -22,6 +22,9 @@ void lkdtm_SOFTLOCKUP(void);
 void lkdtm_HARDLOCKUP(void);
 void lkdtm_SPINLOCKUP(void);
 void lkdtm_HUNG_TASK(void);
+void lkdtm_OVERFLOW_SIGNED(void);
+void lkdtm_OVERFLOW_UNSIGNED(void);
+void lkdtm_ARRAY_BOUNDS(void);
 void lkdtm_CORRUPT_LIST_ADD(void);
 void lkdtm_CORRUPT_LIST_DEL(void);
 void lkdtm_CORRUPT_USER_DS(void);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-4-keescook%40chromium.org.
