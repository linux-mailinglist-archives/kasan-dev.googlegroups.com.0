Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRFI3PXAKGQE6DMAFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id E20E7105944
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 19:15:33 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id d22sf1077220ual.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 10:15:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574360133; cv=pass;
        d=google.com; s=arc-20160816;
        b=dmAmDQbJLePGtQ4HJ3cyNMbPEO/ZHtDuggxjH22D3fSSvjq3Xs5UfFtDRt9rrZt34S
         x9Iim0RWJ9WYTUgDuE5J+lL87m+XOwU0miHFmHUqhZH8htQ5RgS2jlOoEFj2ktQu5Tbj
         +0WY7LhnDdPrqbtcoiDJmgyx04ICI6LJNPSQRnC3up2vozPql5hIMGpcEXu1GsNL4oeI
         rk2uyCiQvhhCNeeF7oiHTQSc8tZkRqrFwAwWANcucrgxiO4usIqhsbkaNniM9dfvvnAS
         Sdgw1O/Kp65bSDM/jhyOYS11O5V6gcMAmj/KMfXTSdYvTtuBE3C53jl2eGASJISJlcYJ
         uadQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=98nOAuJ4SHGmDua+JQAbBJ1qm24X4hY6pn0/27ZHcos=;
        b=ONUeQpKaNWXdYHlrkTBrWO9etWjMZDe6Jb/mWOsQweC+sYOQOPt/RBT1mosPW4iWK5
         2FhobToZS/r6lX0mYbg18donYp2sRYfJcceUZaywEb5ihbMhzaIfBPf2kwPjjV7M4e3A
         r01z4kgPELWvpaaSl4mIrO9A3fKo+NmGRkh1pkOFE3mOAnQecn88BUiJEsdiaGTmHd0+
         kskz7T4CPZj+i6SHPtZaC74gmMOGijcw3XrWJj4CrPyqCPkcYjZw6K/3hKaf1p8JWnFH
         YXxhpYbUp7w03114i8EHGamr+bDV3nX73vzT/h0fOz7vo4+CiM89bGzxigIFciT1uM+l
         PASw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AUOvfPWM;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98nOAuJ4SHGmDua+JQAbBJ1qm24X4hY6pn0/27ZHcos=;
        b=tmdnMFrl+6Khk2Ni22PpLK7Y0UAzZ3Z1nwDwq2dZbe9rsTeIVMzC6OeAXouWAC/Qwj
         /5daSQsvbQHtdModqCTbT3trg2OGkBN8oOM+VjrigbhL1Z5IDZR8V/Gte+aaEKKq1uZI
         Jt0xS4G8L/6MaYMWOxJiz4VdZ3oY/IzJqx17q4Bp3DSUMx4Eqx8+ppgY/NYCfK6WYO/U
         i67v2GbZlVkzK+lKngKDoXTdV+vLzpaNZSR7qJlN36W8iedGRpE/3S6aP6ONjIoe9N/E
         v7nxPunl8SiyNsp4Rxvjb7dcgyAL+TEuz4qZMdd2DwmxWBqMbVffKiSliuMfqb9JMpuZ
         HkxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=98nOAuJ4SHGmDua+JQAbBJ1qm24X4hY6pn0/27ZHcos=;
        b=MUD9hTYsPGxjaOumpVSULupfxG08ZsPQ//ulZl0KwO4Kn6KlGTQAyu/8sxHYq486pS
         G1wp1THIBmVsHL6g9tnkADFFWNvlh8TPjjaM3lkgkiXodgbhvV0UgTMXgssLbMWNyAKu
         yQtcPudYwWGDBJVgzVe2aUCt8fbrnHzdeCNp6oeLSCmDzPLD/4qWUIyiJ3eGoVKbQPlD
         hfsWDp9s2o9IaTscBAi9LpozvQi8m9snE+3TesmWV5ttzZriIPqCEfKPxHMbFc4ZwOH5
         IkudQbhg2APYdAWAtNZAgdqXj6TKKLSw6CSYW6nBFwePP13McPsyQ9XVAZru0yfuQ5Ko
         dUVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXpFNa6xo5emxyHRbxOzXmXqq0Djqb9zcqk5HlFpP47feSijx1E
	FQKgw98AvKHXonQYv4oh3+g=
X-Google-Smtp-Source: APXvYqwawa9Q/gUfuU65Qojq9kPbXSJuf/XOGansWOI3fzGQ6b/kmo8H9fSnOOXbGM+Uh1cDPm3Xyw==
X-Received: by 2002:ab0:608f:: with SMTP id i15mr6590513ual.20.1574360132810;
        Thu, 21 Nov 2019 10:15:32 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c116:: with SMTP id d22ls873190vsj.14.gmail; Thu, 21 Nov
 2019 10:15:32 -0800 (PST)
X-Received: by 2002:a67:ee49:: with SMTP id g9mr6928273vsp.105.1574360132490;
        Thu, 21 Nov 2019 10:15:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574360132; cv=none;
        d=google.com; s=arc-20160816;
        b=DgM0WnIAsVLrF37W2oMIR+Qu4gBvSlfz5rwBD9Fu5uSZdeuoXUUyLa3vHzh4VZFjrA
         yaAdK6okF/eoqYFNp/dKlYRpmgm8wbePPlDZrwOm24gO81gQ8qKa5uI1umU8AXDsHtTz
         79sd/HCOy8N/S1cVSO+YiDhNmv/fRXrmZUwV1FJBOSxxDOR2r3lQDARSfPlwyJXN2gP7
         PUbjaTSR1qUg2OyVukV+KDbwzgibtdGOuKS+E9yhMfGfSeuRd1rqmJnbVvTYnNX+iFbW
         3BLUmfqp6EZ7Hqn0d4ScVGdIgdnbZ58bg8QzANAD3j5bp+M0rnF20pH66HSeC72V0Xqg
         eFVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=0T61AzxnAvwa4rB+CZumfDDidufAJnp+U8GPCQMxTB4=;
        b=qn8+ccNcxdmxU1TzuSc6PyBiZ8R/rVHsnehR2CXVZi3DQuBYOZz8cw55s0KAqrERYB
         XuUKFkptjReYj0et8gbYrd457tfDjTy/c5n6gqNwpQR5HN1c1ZAOsf63LqXj2VT6vA0+
         4IH5vn6VhDgPml3l4NH7Nf7hNghQv2gBCU5aBfw72i+PrB27bQoSDehzao5zL0lLBa1C
         g0chvj6hRlQ3CdQcul2A3j+kveXEUvwAXksR2jCs1vxx221mXgJPgoUHlFud6xivydTP
         u4372k5uZpmkyfwoIKXcz+Dei4C6GSOsN+uCleYFBgdsrDgI2HrKdJ80gHMo+NuCEwQI
         D/6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AUOvfPWM;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id s197si173652vkd.5.2019.11.21.10.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 10:15:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id cq11so1846469pjb.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 10:15:32 -0800 (PST)
X-Received: by 2002:a17:90a:3d01:: with SMTP id h1mr13598717pjc.15.1574360131608;
        Thu, 21 Nov 2019 10:15:31 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o23sm3964733pgj.90.2019.11.21.10.15.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 10:15:28 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH v2 3/3] lkdtm/bugs: Add arithmetic overflow and array bounds checks
Date: Thu, 21 Nov 2019 10:15:19 -0800
Message-Id: <20191121181519.28637-4-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191121181519.28637-1-keescook@chromium.org>
References: <20191121181519.28637-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=AUOvfPWM;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1041
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
---
 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 3 files changed, 81 insertions(+)

diff --git a/drivers/misc/lkdtm/bugs.c b/drivers/misc/lkdtm/bugs.c
index 7284a22b1a09..8b4ef30f53c6 100644
--- a/drivers/misc/lkdtm/bugs.c
+++ b/drivers/misc/lkdtm/bugs.c
@@ -11,6 +11,7 @@
 #include <linux/sched/signal.h>
 #include <linux/sched/task_stack.h>
 #include <linux/uaccess.h>
+#include <linux/slab.h>
 
 struct lkdtm_list {
 	struct list_head node;
@@ -171,6 +172,80 @@ void lkdtm_HUNG_TASK(void)
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
+	int i;
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
index cbc4c9045a99..25879f7b0768 100644
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
index ab446e0bde97..2cd0c5031eea 100644
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
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191121181519.28637-4-keescook%40chromium.org.
