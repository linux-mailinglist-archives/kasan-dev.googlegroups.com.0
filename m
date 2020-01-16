Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRXW73YAKGQEKUF3XMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CA6513D172
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:24 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id f15sf11334059pgk.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137863; cv=pass;
        d=google.com; s=arc-20160816;
        b=GAYKRscI5T1GhnHynN2gwKJUgRht1IeS4lSl23wHp3rck0wPivQoYTutX/K5jLUX2t
         Xi46BmPNaGpGBieE8MdKM4mDGhAarA7oh3bPBQgY3AIU1BPXNWiN+YMKHXWeLkePnC+j
         PRXT9pBnFfgyBdK4WI0PEa9921ZN8iTZ338lsxLxeoM/GkOOOCPfiWiU1RlEEppBF1Bs
         Qtracg4iAcdX66ma6JkgJk75M3xaglurNORh//QpwrO4j91QpomVRW6QM0cqyLye1lbI
         ovGX2sH5bSg+nqJ4OEmZG6mg8vk1WZOYRN1XFsIrfJM4q5+AI2DbJgMDwyjHnaHT7zTq
         LCwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oLLpV0pgfLuRPn2FggwNXRfx5/el6NLvO1gL4Zc2YLA=;
        b=NWKZ9e0V3xo4QZN1LBlKy1PThy48qblLgdk+kWzxT2T/gzxnD5ZDN0lwGrLcvif+kU
         6kHpgykjQl1FwsDThj1F8We/kGXPijKSpPhtTDEksf40IfB0bauQYY4m1ts2aXVPaYQa
         1h3sZ6V38upH4z2IPThUImEHf3vlDGV+BFLUlcI1nae//rjv9nhCd+ZsW4uj7YU+R/W8
         rAV9s1Iv5isn1NdWw8tV7UreirpHSBLDUUtbRIzM+kZeWJPmBhHZaTpesEQUyzwKPnpl
         EeOIb2gXQddWQnMdeQ9RgCFhA651cMlxdjU8VdOgzDushMmAqm/abcHPTqLBnOfESjHa
         fJAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JhPSOz2w;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oLLpV0pgfLuRPn2FggwNXRfx5/el6NLvO1gL4Zc2YLA=;
        b=cU9dh914VsjquqWfq+8fIH0Od0L4OnFZJHid8aRNposbhruJO3Tm11Pyk2ArADFtA8
         ur53eYEc6hnWfe0cBYFagMgB3jLpZp55P771CzNjk508Kq1I7gcGuEMGtwlNFRPxvWu2
         0pf2QJfmQb4v3GD8yrB1CJKXSFDMR/Emn4OYydLplYolln9VdCshy5rWYVwe8JlOsxaI
         N5DKwF1IXvFORzumcC9H0G3xlcttX2NxhpJM7LxFmJFj6I8D0fcg+/oFO4Xa8J02Jooj
         F/+X5JiudC5P07bmRw+FqQf0ruv4Sc5y0hyhFYSPeC1ZRf0vo82LhY7QBBvjIPwyjXNK
         0ocA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oLLpV0pgfLuRPn2FggwNXRfx5/el6NLvO1gL4Zc2YLA=;
        b=FyJwrwhmjFQILJI5oeozAdjEZ4IfNWrYrnOCjgChjPWjwj2zcDvLQqHuE5MItRd3G3
         CHeUoqxCWzDZTzTHSrXsOd3u4R8jEb806Qrp02QqPP2S/fTXoouuSRYUJdWzyGJUAhVP
         PI2xSJ2/yQprmtYGpOp5BIcTSWq839Jn0ejTa58s8D4pNuG2JNyci4NvddjyR6viDhtw
         K84Gph7JNwcp1jvn7o78P0dBzGjRWmHuTSp6+f7+51zKw9JuKQ7nY5QizD2rEOHe1DCt
         7K1m8Edk6j/3W3SuEcnOakM+yXmfiMpGdSKpzu5CIxovSJjR+/iwh4IGGGIhdGW5DweS
         QaPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXswXaeiPApw379efRzUUG6cEosDyxWMs6guyeyItnP9bC8olyJ
	iTmsSFwo9IeKMR7RJ9OgLCw=
X-Google-Smtp-Source: APXvYqzB9ZShUlvbbK2trpJSa14l4EAv0guBozNTg3+4nVd9dDxSx6PLznecpep9U2C9LgdEUHIcpQ==
X-Received: by 2002:a17:902:8303:: with SMTP id bd3mr8350856plb.171.1579137862818;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:84d9:: with SMTP id x25ls6228769pfn.2.gmail; Wed, 15 Jan
 2020 17:24:22 -0800 (PST)
X-Received: by 2002:a63:2e07:: with SMTP id u7mr35980302pgu.295.1579137862409;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137862; cv=none;
        d=google.com; s=arc-20160816;
        b=DFct1jpXLim26tjw+n+8lQyCOnVGzgiC3kwTi0Fw8dP2EMp40W0+hUMDYTXf3NkHzo
         3Yqe7QITRvBfTux2jUVzEoCXVx39cBljlPW2Hyw+yhItYSM/bYREemgsQ2UXk4FohUyM
         1MeTToDVWRJOf+6oH2dY9G+iI8l/VHpavNoBFBZbZL0CSk+fAOyrDI5cpG3RI+MAR/RT
         +Snv9Qg2ev80NhH3yjTd12Kj6+cOTAOlGqV1xbFEIFWb485XD9WtuMKpjGr08c9ZS5nA
         XmE/G1F6x2X7xKxBVaHBgMOahBZTUMei4f4Adm67rPXGIoxNoB3y8bUGRZBrTm7H1inG
         KvJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZQ9IDbK60uG/o5/jdnQdHcQ/z86svExWfXh/mgZ1IxQ=;
        b=Jp/Pnf2iG8c/cTIfzuYO3mahG16UpggJiD8yjrCimSLZoH1Wsx1oF2yV0375KzaHW/
         4KAJgo680rTLc3/tK6JSukVe8Me/oFUHOEeRAggq3GXPpOemHHuJxvCA+qxpNyDjlpZ9
         4n3Xbkumukiahff1RaaaschgZNOEk7VDeNl74Cx7L2eet+ORuOP37Qw8I9Aqv+vnLYDR
         xNF0AxP8u05TZwmgXcjnFsNjtrrCn1fZDa/px0+E2RpDVDnLvEuTC5ZlX5qmjL+l+UB7
         KcRQLeScDGXJgVjqulHwAstmvScqCrEWGQAkG2HU0HlqakDC2NzA2sxWZzTHDgL4gk/5
         nrbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JhPSOz2w;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id c4si792132plr.4.2020.01.15.17.24.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id x6so9363782pfo.10
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:22 -0800 (PST)
X-Received: by 2002:a63:201d:: with SMTP id g29mr37572832pgg.427.1579137862140;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id q21sm22396012pff.105.2020.01.15.17.24.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:18 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
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
Subject: [PATCH v3 3/6] lkdtm/bugs: Add arithmetic overflow and array bounds checks
Date: Wed, 15 Jan 2020 17:23:18 -0800
Message-Id: <20200116012321.26254-4-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JhPSOz2w;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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
index a4fdad04809a..aeee2b1c7663 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-4-keescook%40chromium.org.
