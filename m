Return-Path: <kasan-dev+bncBC7OBJGL2MHBB57RZT5QKGQE5WKH7FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E343327CF65
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:39:04 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id y7sf3548555pjt.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:39:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386743; cv=pass;
        d=google.com; s=arc-20160816;
        b=cPdJIITQO8JZQ1qhFWyBjO6QVWnBnr8JNtZ+OqZsRBz3o382vk6puUL90p7j+8hhmV
         vosT8CifR6XgMOlG/Cd/DrVbYplWMX3hCDDbFJ+0qKb/RrZZJeHmoBBBSUreqXwUS62e
         6DbOMPSMZ0GzApGDA0wNRuLIjckpEDeY2EagpJcnLSUkd+MSnF6yXi7IYPFKfBn8ad6X
         X0NOSJCgsdavcrqPQ1jOOqasMSD7VerKulR/i8WCSXCu5N50zehdWIgb5JI8f0lat9db
         XlQLEMu9aiH7P4wT64k8t7BcuBVBG8vqgKG5exh5ko+e6W1TMRcPKrN9wt9toKIQE6i7
         WTPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=cakYW0b/d/Frq7g61fkzpmhewnmvaK8v7bpX4Uv+Z3A=;
        b=LI4DA0cQCkBQlxzmKA4adMe64PPzHRTgTMsRJPKWD1laV1Acq/qudFGz4b9HiQwnkZ
         59zoNZX1DIjNTh6a7SOhsaoxX2B2Dxpq0KhSiCWOP+WvY4tbNuPbbrzi/8InkemgUBZj
         rvKBAPjaol89CANo5Uhb0zpc/++bVmIQ+4cWT8zbidlr2KBBLgEaxRa4SL6DvoxlcYWG
         8VdJjIOuluvI64yGqQD71BwN+OohRNqRcAAPys8eKCp36KCd0Bgd874BOJXvR8N1pJqQ
         BOfouDLiT4JpNwO9CHvfE02NrnYYGpK8TA3TCzdrX0XOYtxlkXabXsAqpMTtyKoenuL0
         csxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UOSBvRZB;
       spf=pass (google.com: domain of 39thzxwukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39ThzXwUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cakYW0b/d/Frq7g61fkzpmhewnmvaK8v7bpX4Uv+Z3A=;
        b=gF85XZAkZoIO54wMNzaNGFEJETtxzav4mW9vfkaRP75he4ryqu2R+u0SqNwTDlPsV/
         S2ew5GMEm+vmwoN553QRRrBIPtOTOsUBMBERx1PFUusYIndkOp1TSCKtcETdveqUlLDL
         liyO6stmJsS+jJIuIQhb6gnVXKage3Kx91phk0L6m/fq3Mbn/CAfnLRi4UKNb0hC5U+X
         nRP1tpkVS+y6hadjyjOzXHJwGCWUBqSFvQJTa2KAqG0XVjkRn5W7l4Sqj5eHsv/Gjc+Q
         7rBEGjxAf0iPDCmhBSSBWt8a8CNsYAqwC0JcecSphO387T9Z88DPJRUxvNN8oAQ3DCPk
         hlYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cakYW0b/d/Frq7g61fkzpmhewnmvaK8v7bpX4Uv+Z3A=;
        b=Tah7oBG6jtM6z3Y9Gjlvp9yp5vv2Ti8+phNB+y9s/EDZ5UHra4IKZjYmF8JsCYfJMf
         ftPsDmaaXw190HGyyF5mJD+mQo9Q+9VNrw0uKtCTOlBxAEBC9c9uBJIEnzQpXqjQRx7c
         /mo2eEeygJknqlOxA9bOEyZySdI/y0ItrohrOIPXeWRA/NOErZGng0fFUweT+/6KG9Nv
         /MkQFQGwjP2tpxWhkz1/0UBR7UZPho/6vq4FpWVn1R0DiHASWiaJ6i9cES58Ndpgu7uu
         43K2X1ovgtbM1nAsHFVlj/qAPrvZh7/tYywq1BY5YzV4fh/0yGM3Fr79JJw1bMzsXU5O
         IJ8w==
X-Gm-Message-State: AOAM532NwQ/Ud3Mdaa+q+B4Akp1Q2+CWR0ngvi0SBSAhUI0jA1auSkY4
	vunp22452j38BlODfuquTfM=
X-Google-Smtp-Source: ABdhPJyz/4hzkQo+rVoGR4RaUgNYF8hsjnyCgm4vbgdcROnnvq8Qd5f2zjt6AHMEFKwYD40d4vfL9Q==
X-Received: by 2002:a63:801:: with SMTP id 1mr3395222pgi.48.1601386743396;
        Tue, 29 Sep 2020 06:39:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e303:: with SMTP id x3ls1440620pjy.2.gmail; Tue, 29
 Sep 2020 06:39:02 -0700 (PDT)
X-Received: by 2002:a17:90a:f0d5:: with SMTP id fa21mr4041532pjb.77.1601386742737;
        Tue, 29 Sep 2020 06:39:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386742; cv=none;
        d=google.com; s=arc-20160816;
        b=AuAVTrfzDMRDRuyOk3QCy1pXd60zb5IS3ePGW68EYVdlVcZ1Iu2gFcJiR34uSvHf48
         63L++gb7pSmxETNHyRagig4vDnZyKcmpRaI9C571yDEVVDsQz/sFmLHeStKm1Kh8NPIy
         L2rTXY05y+H9NiWRbIofOvsB9/Bhk6Tszai36ZWLCPg+wN1I2TNZhRPMXQmxCrfNzPN0
         9HBO458MRzyeLLrgomvrxxgRJ1VlM16KaMUnfrlWgnYtJt0oPtmyN3DESc7ZwX0Dp7m5
         CbegE9Sm/5cKUp24z9tqRw7Sh4cZuW8q633tbVb9BjAqT/xPLdcix2FVHanklJbVQhAt
         n1Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vVOlNt/WCejDp1JOCEsvSSdVHILjJnc43Mcb0PKSl94=;
        b=uCTSGc3jkdOKoQ50UH44CuMjt5jdYi2jcO7X7IXrnf04N4EW3KJDV+NmtLBABGrXIF
         jIynAs5VWlbfMyjgiz9Anb4GiU7onwZy71o5nXUzwVQ3EDz0gvfECMgm6rdB3k+03DKU
         eeZkF5HAGLDF3usI6bsHtc/DsrjFz3d44P5tBNC28kMlTiP1JtP4i4PU6nz0EMnQGlj9
         FgVVee963AURCap7y0q/MF1DR8hOvhuhBHEfL4yC2jicqrEsrmIbYBVtw8MfQw0Fro84
         m2Kcdj3iD2T2TGXyJsC7ijJUR+ZWbFVDL513AsZ3TD2cvetS3E+ppP5rNG1useWYwm2F
         WhMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UOSBvRZB;
       spf=pass (google.com: domain of 39thzxwukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39ThzXwUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id j16si324356pgj.1.2020.09.29.06.39.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:39:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39thzxwukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id a16so2988831qtj.7
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:39:02 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:f6c4:: with SMTP id d4mr4373033qvo.41.1601386741788;
 Tue, 29 Sep 2020 06:39:01 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:11 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-9-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 08/11] kfence, lockdep: make KFENCE compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UOSBvRZB;       spf=pass
 (google.com: domain of 39thzxwukctywdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39ThzXwUKCTYWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Lockdep checks that dynamic key registration is only performed on keys
that are not static objects. With KFENCE, it is possible that such a
dynamically allocated key is a KFENCE object which may, however, be
allocated from a static memory pool (if HAVE_ARCH_KFENCE_STATIC_POOL).

Therefore, ignore KFENCE-allocated objects in static_obj().

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/locking/lockdep.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 54b74fabf40c..0cf5d5ecbd31 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -38,6 +38,7 @@
 #include <linux/seq_file.h>
 #include <linux/spinlock.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/interrupt.h>
 #include <linux/stacktrace.h>
 #include <linux/debug_locks.h>
@@ -755,6 +756,13 @@ static int static_obj(const void *obj)
 	if (arch_is_kernel_initmem_freed(addr))
 		return 0;
 
+	/*
+	 * KFENCE objects may be allocated from a static memory pool, but are
+	 * not actually static objects.
+	 */
+	if (is_kfence_address(obj))
+		return 0;
+
 	/*
 	 * static variable?
 	 */
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-9-elver%40google.com.
