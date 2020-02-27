Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOU64DZAKGQEEKDDIQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id BDD5F172800
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:31 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id j63sf736582ywj.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829370; cv=pass;
        d=google.com; s=arc-20160816;
        b=omdFeADZzbEnRz85njc0KaBp68EietKmiJm5i33E1xBIlRHRqEPAxCbJdsKNQtnoeX
         3QGtYx+kzZ0bDm1w4TUXzZoAgKuKTOV8g0TNdUd955Xdc1d59P2eLZ7oyseyA6t3PwHn
         aNwxTllzwHCOhik5RXcg1GJwe/1mwZtsuJTz85HTFmc0+YeNzBGrs5nfZKGpDk2QuNhN
         wHJZ8NKIS5HvKFLfEBmREqoy68TvbhRrXsMGjkmARxlUdU+CwCXGvkcrYE/WiT+qlSdw
         r1C4xq9GCxKuTeLdV4ZdcyTO+clhWA+XqMw2qQX+OJ2H3kwEKWwqlabhbj8CD58s2rzU
         tWvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+TuayEmVe9aDf5vKsAN3ZWzjHlC85V6pdFzG+CRnLOM=;
        b=bEQCS20qszuU+0mwoDFgX0+hsqmGu/8vSsOtexdToO6CoGZKm/fZR5J+ZOuiHZ5h6t
         O0IIe+LnTZZNowYdAqLh4Nie1xZbtlRnT/LPQRjPJvs7TNK64SzQUgi1G7ixlim3mxR2
         hmtahZOAbNbOnfw+rkHzDNsDFXTBhxv14EQjSCdc/vu1kCNh7hlOmq1gJk6D+XKEXWCr
         8LSTaSqsP2iU7PEt4q2LAcRDx+/WTo/8BphadrotPRkmj2J3TOL8DRW/IHfq7HkHVdqK
         rEZP48Vn4MVCC2sm2lKIK5hIclD7kHLB/1T/gOheR5LBmIp0SxU0ZrYH/kwPX2d+Y4KB
         iXbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GklqgiNX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+TuayEmVe9aDf5vKsAN3ZWzjHlC85V6pdFzG+CRnLOM=;
        b=DTYJSy8VogQvCGqkpSzCwXDzuqqW+NKeP7jHqL3WVOZTgEOEXUzCsya2dvu1KZfEu3
         alsEXjgBGkmWlCO5Ld2q9UcCXrgjU4Y3hRmkOxtZUkAGD3PvktUQNgv0bKE9ycjKxTxf
         /kMD4oyBi2urMBFVwzteVB6Jk9jweCNQIbOrw9FGtDhiRB6aMirAOfcG7DVrI1aeiR1l
         cRneOkeV2ECofcmz32+jPuGNCaUIJ2V2O07SE661Iivnv/qUVHAbNKzc7/QMDfxMsl+o
         KXhQjlmO+v2wgZfJ6wh+d1MivJGqwj2pWrUohI3uVDCRPNAr1LjcLNLtO1VmRZLZOTln
         J7pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+TuayEmVe9aDf5vKsAN3ZWzjHlC85V6pdFzG+CRnLOM=;
        b=sgwY3cw5n1LtNEbDkWzVAG/aEGIeFdeDd5YHLGtnGKqd3RmQSg0JFw/4uGivl3V6eL
         G+NfM+islnjEnW3jU8Gp9nrkmOsN1fXuSlvPt/X3FphdkGsG5iXXKzglq6CoKHpa/M1W
         jXrPDrV5SRih98JuVmmutVSGhA5BaRefNyB7NgpMVi1aHJz14iHVhxUDL0BwxlIhdLR4
         rZ+bGFs9rFM8yfWxRSpVU/ekgXFAo60P4xRIwGzJZROJ81NcHp8rxKadllOF6uV5bjqr
         byHP9GpdamrpYLOvbXCVGoigAQFm6dpEnSpOWMwmzxP7RNPY1dBfXvA6zDL6NIqm31Y3
         3zew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUbZ/4KMLr/Pe6DDH7G+Bst163CFp9fU40AW5r/Sfg6QqeVbRvT
	OAqzj2zfSfyqAT/dp2qwhxo=
X-Google-Smtp-Source: APXvYqzbJSYzYY8jnKiLLdpsi5DzAJFIwHQnlUR85KBWuTGl0Bjk0d9HxTOjXV96KpXGFQJMuzdYzg==
X-Received: by 2002:a81:4b42:: with SMTP id y63mr860417ywa.502.1582829370769;
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:984:: with SMTP id c4ls85192ybq.1.gmail; Thu, 27 Feb
 2020 10:49:30 -0800 (PST)
X-Received: by 2002:a25:9704:: with SMTP id d4mr56625ybo.137.1582829370391;
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829370; cv=none;
        d=google.com; s=arc-20160816;
        b=yE4pPJIYI+vYzMSbXZVIw75ISDPxsF/e+CW/WrNqPO7IMAvUDWqZbFtOMBt4AbraQg
         dwYr8gSHCfFJqyQMwsGWETQnqCgb+W18S1TLbejibEVPga3zFiUVu0w9wSdurOqkTkOg
         OFWWVyB2vCvEo/Fvi0t7rYtOjxyOBrFVzb9B+me4camJ9cSb8gUbY9tT0JtpZMsqfG8w
         VJpb2DeG5wdkFcgGvYu+7OnqwSgBIen5V5GtoskXrPTB30fRoSw/SgxzUUPHuUQhoHGm
         VpG+n5pC2MDyto/91AtDFWzL97XwkWWAN7ruqIFZ36IlypFOvhifOI1xmIk9sm/oqUHy
         IShA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tZTI1WKOfKcUGuqkPLx5fh8/0duDs7Ezr+5qHoGz4tY=;
        b=jOWm5sl41SJeD1fxyj7lk8WIdrhPNi/bSpP4oJKDHig2sfRRCC99MWmsu/EmPR+9g7
         rpVVV5BZ28te63Yv9+3CmXXdfqel9WXxpRifCeypOQ7En0zA9+qQXdfqmpDbSgneEbYk
         OhTok6qoTNq//J6OrWJObLe/qU7fECLlR/g6VVF7jGenp+EgD9iMkl8Qukyw+N4qPb/K
         D8fhRsIz7hra+4aYvzZaTymbAUC8im87H0u32UveFtie5V8rFhQoeR9Nu9z3Y6QVi2tA
         nDPZXeTJSykzwSgGKf4LKuGen2PtFWFEhcWWOI15Asalg/HgBUKvX+DSndhqMgZ3ERDH
         3Brg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GklqgiNX;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id i200si29280ywa.3.2020.02.27.10.49.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id q4so159822pls.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:30 -0800 (PST)
X-Received: by 2002:a17:90a:cb11:: with SMTP id z17mr366666pjt.122.1582829370031;
        Thu, 27 Feb 2020 10:49:30 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id r6sm8070816pfh.91.2020.02.27.10.49.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:26 -0800 (PST)
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
Subject: [PATCH v4 3/6] lkdtm/bugs: Add arithmetic overflow and array bounds checks
Date: Thu, 27 Feb 2020 10:49:18 -0800
Message-Id: <20200227184921.30215-4-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=GklqgiNX;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-4-keescook%40chromium.org.
