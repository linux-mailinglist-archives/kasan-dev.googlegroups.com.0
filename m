Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBOX42GFAMGQECQEIE4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BB2E41C76C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:54:51 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m2-20020a05600c3b0200b0030cd1310631sf941962wms.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:54:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927290; cv=pass;
        d=google.com; s=arc-20160816;
        b=lER05RBnPixP2zLY4cCtclm3upIXakvtQ/rEEA5sIUFgEQTvw+mQIFsfR3lulZ5dRr
         0PNxIId8QA72NVxiw49hK0aKvKtinwTQzyG2yUll+tykzj5sHrThQl0Nf8k9NZGXXUDX
         iXpYxSvD7n0E6ehUtEHwULwpqv9rppTI0w8yS47LJ2+E+LPd2JNF0S5l7Dz7hHPgwOUN
         Z/IPNLQhyCu+bLHbdswVymqvXoY/68T97E4cKMlwVVLXD5cBa2dDJlbZJFeDlzV0amth
         WktcjWOy8eVmiacicGU1yjdumuNTuwfmoaLgqHI+/SNt708nbF2609Yud2JGfaOVyT/1
         5Srw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W664ZatHuJAMkQRf9wur9ZV7KMTbnMl3eYQLF7WfIrE=;
        b=iE5ibT+ucICwlCBW5sldI5BlZ5jyk7wpz2OgbqpDdQpTYpyjIMHxpAU/3/Vuo2AQ6n
         0mphg4XuuMuIhBG/tE5vesDDSN+3RjQKiTMLEF6qgGj1Um4PdJqxF9hPI07L0T3AM/s7
         rrrQOmm6MqQRy2rOCCljPpl8fWJ8ytT4+TO/j2/zx/z3217qCobAUa3+9xFEs033urXD
         eVYanbsAVtSNg3r/Wg1fkaUeSE293OSgVfQFtbG62mPrWd/0Nk7VzjSLJOq2TBfIYKXr
         0j4JcJFWYcJnAXsW5HRy+oNVrP5wvZAFCdbZgGi6I37omnvSTJUkeQmae0WlrzTD1oPY
         OYUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ZDK7Pvmk;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W664ZatHuJAMkQRf9wur9ZV7KMTbnMl3eYQLF7WfIrE=;
        b=c8ga3/3B+Rx5ydFf65PbvXUNJoiwG0k7xadg1oI9tTlN0CJjrnrn0F6NANAT5pSqn+
         nZ6+/wqwQ8kHwrpqqsrDO1m5xl04iCJSidDw4qZdUY9RgAbbRUsj80zcfF9yPkTz+in8
         0eZnXtgtO3nczVptFvXMZh+lUeTH+EHYVevQWctI6YSFz6RzUvet11zPFTVq2R79Mt1q
         tHe3qnyB9WBWVVMRdOsmJ0wxnrL7+Tp1pZQoXFbhSkEroBIlY0Kn6lLgREbZV3JkgH+b
         tKxEzhTpufE6Y72HSwWukMU6cIpjhGZBs0qS7IWcfHJjSL04CJfk33paadxSli+dajO0
         paBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W664ZatHuJAMkQRf9wur9ZV7KMTbnMl3eYQLF7WfIrE=;
        b=1B8iosm/xfWhjKvJ1NfztjQDb4fIGgK2FJqjTJAhFQ0gJ86USJ3I5A6heL8ZAN+/Td
         xWVJ71tifma2xwiHMuaq/6Fv3e7ie/plt3wX+VXBeR3hcMEyYKcMr96egQ9t2+3X/pbO
         fQv4i2J0ub3AnOVrh4aKljWFGndh84X+OItWSMTGt2vAl1FoGHz8RAqDUKJ03z5VUVYz
         zIED2V5qFlMcqPTD/XRmgIyAvqlrVLBqIHblRIxUbjBwvk+aE0AccetDc7kEIK2DYP3l
         TD9BPQqhNtqar5Uc7lAAeEznM9gWtZvhwKzybEl1JrcZ3ADZGtlITY0qN41Xu8znBh8u
         BYNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532X246UP4+Nm3tbsuycZHIOeZfQIGV2mU0M5vanMjGhEJHtL6EY
	cmf9EgCRPiYH73iQfJ2IcWI=
X-Google-Smtp-Source: ABdhPJy5re549Q4EETF//xm8V5AQfjc+PKcyrBJUWsurrUPT/YMlbmrEQMd/Bz/+9wPaMPJxwKd6DQ==
X-Received: by 2002:a7b:ce98:: with SMTP id q24mr365069wmj.33.1632927290827;
        Wed, 29 Sep 2021 07:54:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4646:: with SMTP id n6ls3342482wmo.3.canary-gmail;
 Wed, 29 Sep 2021 07:54:50 -0700 (PDT)
X-Received: by 2002:a7b:c74b:: with SMTP id w11mr361380wmk.21.1632927289949;
        Wed, 29 Sep 2021 07:54:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927289; cv=none;
        d=google.com; s=arc-20160816;
        b=0ssRxpztTqR7FQu8L/gOHJllGoGjO63GtT1Y7plVFK351wdVxJ6fXGJRFN9O+Ed/7/
         QqkC/f0vpcayCxXGm52Q0bXBLaE1n1OzfS2DTG85TtLufAjSYskCvmu8mWZPT9IQzxKM
         T+t1XPsK36qN+hu9Q/6gS0QiwjMZupJvadGyemUs2PXfUa2tKI0sM3P25pVkmGy5JgqR
         gaP8W/8DmfQ27VCIuQzH5HEiXD2i9e0LRfSW9UfaVVMPXmvA7hWmw/LcPu0Gil/HR4VI
         +aMCQSRDorhnvqyJI+JLSSNgpvV6NlrAo2TR5r0SqVld4keZLddb0WLik193oj5OuWJh
         pPgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KeLkiElzlzQvNNsdjcFFS61hMwkuiVlVaM0dpBDB2C8=;
        b=eeEWGJvT1I8V+fm31GRb4cnFt6UpRhaDmlzNJpnNZbsTnsub3muHmWwE1D26RmOY5d
         U5C5W7oBbPFJEmQh0BQTTIGwvhrBbVPY3q2E5kw3jzFfW8LzSmGEWuocGZ8DPOpqkqAn
         8arOTPt6TGX5NOr/W32fjdg1ONh1s0DZu50hWfWOE9nikNjMtzz44YlraA+geiSW/KPu
         T2i7uQvZ9eRFqn3jelfUN8J0M3Pj/Td02SeqkcBIzrQXsB3dPmG3RM8nf8LnRnDVpsoE
         crAKl71HeP8uSUP5abJ2jldTi1FgOTxyG8etRrwQ1p/PJzDUMjIE1+dHBIsyEO674KIe
         a4JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ZDK7Pvmk;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id g2si537389wmc.4.2021.09.29.07.54.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:54:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-lf1-f69.google.com (mail-lf1-f69.google.com [209.85.167.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 940243F4BE
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:54:49 +0000 (UTC)
Received: by mail-lf1-f69.google.com with SMTP id x29-20020ac259dd000000b003f950c726e1so2601240lfn.14
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:54:49 -0700 (PDT)
X-Received: by 2002:a05:6000:186a:: with SMTP id d10mr293242wri.113.1632927277902;
        Wed, 29 Sep 2021 07:54:37 -0700 (PDT)
X-Received: by 2002:a05:6000:186a:: with SMTP id d10mr293200wri.113.1632927277749;
        Wed, 29 Sep 2021 07:54:37 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id e8sm127119wrr.42.2021.09.29.07.54.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:54:37 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 03/10] asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
Date: Wed, 29 Sep 2021 16:51:06 +0200
Message-Id: <20210929145113.1935778-4-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=ZDK7Pvmk;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

In the following commits, riscv will almost use the generic versions of
pud_alloc_one and pud_free but an additional check is required since those
functions are only relevant when using at least a 4-level page table, which
will be determined at runtime on riscv.

So move the content of those functions into other functions that riscv
can use without duplicating code.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 include/asm-generic/pgalloc.h | 24 ++++++++++++++++++------
 1 file changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/asm-generic/pgalloc.h b/include/asm-generic/pgalloc.h
index 02932efad3ab..977bea16cf1b 100644
--- a/include/asm-generic/pgalloc.h
+++ b/include/asm-generic/pgalloc.h
@@ -147,6 +147,15 @@ static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
 
 #if CONFIG_PGTABLE_LEVELS > 3
 
+static inline pud_t *__pud_alloc_one(struct mm_struct *mm, unsigned long addr)
+{
+	gfp_t gfp = GFP_PGTABLE_USER;
+
+	if (mm == &init_mm)
+		gfp = GFP_PGTABLE_KERNEL;
+	return (pud_t *)get_zeroed_page(gfp);
+}
+
 #ifndef __HAVE_ARCH_PUD_ALLOC_ONE
 /**
  * pud_alloc_one - allocate a page for PUD-level page table
@@ -159,20 +168,23 @@ static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
  */
 static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
-	gfp_t gfp = GFP_PGTABLE_USER;
-
-	if (mm == &init_mm)
-		gfp = GFP_PGTABLE_KERNEL;
-	return (pud_t *)get_zeroed_page(gfp);
+	return __pud_alloc_one(mm, addr);
 }
 #endif
 
-static inline void pud_free(struct mm_struct *mm, pud_t *pud)
+static inline void __pud_free(struct mm_struct *mm, pud_t *pud)
 {
 	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
 	free_page((unsigned long)pud);
 }
 
+#ifndef __HAVE_ARCH_PUD_FREE
+static inline void pud_free(struct mm_struct *mm, pud_t *pud)
+{
+	__pud_free(mm, pud);
+}
+#endif
+
 #endif /* CONFIG_PGTABLE_LEVELS > 3 */
 
 #ifndef __HAVE_ARCH_PGD_FREE
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-4-alexandre.ghiti%40canonical.com.
