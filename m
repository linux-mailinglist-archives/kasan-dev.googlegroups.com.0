Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJV6XWBAMGQE2JZ73IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B7F633B3B4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:39 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id q23sf16039669oot.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814438; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HeYHoPfg8++KHWrd5wTOAV06jfmzXw5ovt/9CSXozNTYR48ujJkoL67kmiOu3319K
         yVe4BpQDZYVhnzSeEf97usw7O+J2GWwyEiSZXpsQEJ7WtOztOWjagh5aQejg5BIjS6HI
         FJv8t8u++hUH8IG0X591dYTU9C0gGW/tmVhsnVeKU7RApkBURwm5KyZk1jPgoewmmFT4
         E0CbWt6+WwRGgGSfIPD27aZtkfg/qy4w+tTtTSUbgb+y2GIbrqMxFNLUtI4Rsp1nwUIg
         cqJw3LzhL9CH38pKJMdDfBgP3vLTibSJz0uURFiECYeJFIpfsd7t66W+um1HpcTIKxw5
         6B7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z2hXmybzPBak1ZGbqSe42XNDbwye3Z3zjuLlIyE50gA=;
        b=MyxtYgmiNTLUe/vqBbDfM779k9qWFdlzZOLrXxy7aF8S4ekISlunFY7f7r1Wi6SyAf
         YZn5vwJRsTFf1rVhxlRbQ21Kk3XL6B5mAPHl22z+g4JclCbda/gGLuGYDo4ZMNxDw/+s
         CWgAe24dLKPzk+YgSZOv0EwE/Ydc63sKd+fRASV2vHbWL4llAgWMbfIf+3kgaEzQSOx8
         76N4i9cDxoRKuLOkP+xP9R1ne/69Ne7WnMYSRxV6Cr63ix1SIrkYllfBU3VgLw3yUwdp
         25lIapwKPtqfbaZY7eqDNixQqjbCOuilTltog11KLdnRPlO+Tn40rgw0YBWgtFw1aHeD
         o3Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z2hXmybzPBak1ZGbqSe42XNDbwye3Z3zjuLlIyE50gA=;
        b=oUw9G6E99NhlWqfXD+wbJj3RPd1WosMZ7FjYcO01Y5wSlY158/hKk1NWOQ7TX3miQf
         UJFzydjaPKHAn8zw1tXPHhclXi1NUY39k9I33tSdih/sBHMXRlx/Gk0ZGvx7Tgw0jj4f
         z6yjyUTM9v/txgCUiCaBmYEGaCZ9BNU7TOPWnqeEjUZERCgENZlYKO9cFKxjaZh3STwb
         vRYogasHqgxLj0dl+iEoLOKrR2C/HunWo0BWLWixYWJC0G+G/+c08Yp7Cqo/dbotkB+G
         9O3vVGaJk0f8makOLe1FmiOv24r1ASiDQ9dt9e/u4Gjl7l4JEWQbZ2sc/ROhOsQ9KizJ
         r/og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z2hXmybzPBak1ZGbqSe42XNDbwye3Z3zjuLlIyE50gA=;
        b=i94cqaRPYjr/TgnqAolkbqpkN6Z6k1EdouTxnMNkXPlasdlNjDhC+8+MmLoJWoD/BE
         NJri20QMhHs0fxVfMJsyIJbvOTO+UfkxnxOJwnDstRf5E+w9y7CMYZRG+yn3gQRKXUDS
         0XAL8EQbFBYJvwLCfqs7YbpjrfMACryx17xUlwFGT8+oeHBC4tdOAmngfT8u1GsJ9BN0
         /pGBUX6M1NyOf6UGdWY1dZ2PlIgfFr1QI4e3aaOdtB9lMzhvA+k6X2A6VGfST1Fp/N5S
         IydPkmKDPSrrwSoMnEE7PeCI0mzbb9Lm79GO5MQ2f8FzWNTiUGvZDc4J7tznMi24UZG0
         Acmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Z+SlMUr1uWjPW0W3rrtQRqG//a6bcOufsWob1n/YRx5umClFR
	qiRfEUWD7HdSFYQbM75jzA4=
X-Google-Smtp-Source: ABdhPJz5Rv/95cCBfrBiXGSquCoR/81vLT+NhGoJ3oOq0ACBie5YZHvVk1Ds685JBsJkTs1s6UhP4g==
X-Received: by 2002:aca:d608:: with SMTP id n8mr18553217oig.127.1615814438213;
        Mon, 15 Mar 2021 06:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d54d:: with SMTP id m74ls598923oig.11.gmail; Mon, 15 Mar
 2021 06:20:37 -0700 (PDT)
X-Received: by 2002:aca:1c18:: with SMTP id c24mr5745400oic.7.1615814437890;
        Mon, 15 Mar 2021 06:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814437; cv=none;
        d=google.com; s=arc-20160816;
        b=Ba2C1uqNXq66kcBR1P4/Rau7jIl6OUBi0AH+54V+JwYDyxgt7hTm4+4G1YyQ5Daman
         wW839M/SK8F8TOqRuFd7EnVZWiAV/EQ7yUFnqOdhtS7RoMeQZsu6OpV1zbQkTQny4c3i
         zOe91yiTzMOZiPFRTga4ruaJtTVUkQjqj/6Unr1mte1x1Zk/4lhxu3SkS4JazV4CrAyC
         LbQE2pL+OXup4ziiodN4wAl2he8KAuKC5EHJMEWY1XXe0VMARNjoB81t+Hj+92CWMDHc
         q4gIOwcFd8yzrOlHbxqQu4oAdL7GZ/Y3So99QO37TN33o2C4ngwY5Zbl5Xocq8WR7fOe
         H+Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WjA/D/j2uujoyj1qbB7tk/Evdiq/flAsV6eMkmYGi3A=;
        b=OJRXqRip/gNxdCPZ8D/A+e1Tt/6jOinrZEGw73tqx9KpayVSuKfTtKSEYKm63UCj+x
         ohV1k5iDGxwtyERhqadpPAeCsR/VQzpTgcpIoIIeXDqz5kOjj1Fb6PY2Bngcf2sN9t7p
         IHDjGa3EqoaidAD22OgLNPm/N6ECKgAx3IWfrM2u8KsDudqsBsxmzz1j9oaJrUblNLiX
         xCTMDtmRe+b0L4jiEOfc6fop+2bz38OClfnUZYFa12nB1WYpaaLxTI+vEaA5tMihJhnM
         ldjC4r3owptxbmy/djXbGaxY36878/MXIB7dFSjurj8msZuxDFTKa4ooZV8NpVuLHKMd
         8X6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w16si315785oov.0.2021.03.15.06.20.37
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A6D5F12FC;
	Mon, 15 Mar 2021 06:20:37 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C2A4A3F792;
	Mon, 15 Mar 2021 06:20:35 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v16 4/9] kasan: Add report for async mode
Date: Mon, 15 Mar 2021 13:20:14 +0000
Message-Id: <20210315132019.33202-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/kasan.h      | 16 ++++++++++++++++
 mm/kasan/report.c     | 17 ++++++++++++++++-
 3 files changed, 38 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 8b3b99d659b7..b1678a61e6a7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -393,6 +393,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+void kasan_report_async(void);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 9d97b104c3b0..56b155ddaf30 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,17 +7,33 @@
 #include <linux/stackdepot.h>
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 #include <linux/static_key.h>
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+extern bool kasan_flag_async __ro_after_init;
+
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return static_branch_unlikely(&kasan_flag_stacktrace);
 }
+
+static inline bool kasan_async_mode_enabled(void)
+{
+	return kasan_flag_async;
+}
 #else
+
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return true;
 }
+
+static inline bool kasan_async_mode_enabled(void)
+{
+	return false;
+}
+
 #endif
 
 extern bool kasan_flag_panic __ro_after_init;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 87b271206163..8b0843a2cdd7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -87,7 +87,8 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+	if (!kasan_async_mode_enabled())
+		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
@@ -360,6 +361,20 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags, (unsigned long)object);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	pr_err("\n");
+	dump_stack();
+	end_report(&flags, 0);
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-5-vincenzo.frascino%40arm.com.
