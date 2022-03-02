Return-Path: <kasan-dev+bncBAABBZN372IAMGQELAS6S5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A98704CAA99
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:40:06 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id g13-20020a056512118d00b00445ade9f7fbsf898222lfr.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:40:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239206; cv=pass;
        d=google.com; s=arc-20160816;
        b=FkyZe1/YXQF5kyBXsKfH7sWeDE67IAW+XEzWiKtpvcxjv07fP/9dNfdKGtvR8+O//n
         +aO7qnNp6hSdxdaIqYnM1tNxultd31B308xAzDXoHg5h3vNdLRVvr83N17Y0epjIEOX2
         2BecTLIjjncd96wxACXjX4JWYhipSHt4/M6+Cv96aAOYxm/Ge5g/t/cJipDkWRv2lSZA
         LHAutwdnlW4HcBu1pc4LTHM180DOKX6hwYLVM44msJtgi4S+Ug7MUP3Br+fhOqrNMBqH
         4fhCBIqjcXhPRRO2OZlt1jZvsvJQS5881Y56m9sqvMtQQr3j+vJLeHBT1zevZ/Z6Byca
         5kpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NoRCYSp55PoTqRuFYPpizi0GfmkO6MrH2l1kGZSl5Lc=;
        b=rklDdpPPia3XC+v7bp4eDuMI9qzKfRCEOQ0NHlw70JALopj8iA4euTMVGZveqT6EKA
         nTfRl9li+J/7fwsO/U+ugYlARKPoIMq57OSmEZRg/H/gSk82KUtPqkgNxT3O23ng4HMC
         iicWq8W8vQQsC/SaL/uG6V2UylJhlUVwp0CPrm+LVdc+OTPlRThipiwD0fXjXrHh0L3T
         8FLzpNaFPkVcKrt5RTCSjSiKyWVmyOoPqEhCkkhPFFPVuWKPZzHPn5yfUzRob4mLgIs+
         1uEU0Xrs2qXEXqjd3O5x8GjWlX45ixDeAncwuI2mY7CN+HP8IpUZR2ctIhN6JC6jdirg
         Q/aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=THIJtJGD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NoRCYSp55PoTqRuFYPpizi0GfmkO6MrH2l1kGZSl5Lc=;
        b=jUzpdA9bC1kXE6a6J/uSuHCJG9kq4UQt+Xaq2uCjDX31crOpUz+9cp0BizA/Wvs7vx
         1HIAOdBfVv6kDyS48AMH4Of1GzxSwK8nf9Mhidr+L7I7lJY1hGPYxRuNf52e/9th7qck
         Ts8EKy1buGKGHaV37Pdvb0p44JLWqYD2QqVrze3fFNTJT8l9My2iIOZoyWnbhHVEpqDV
         e4b9gjKK25aDHh6z+1/EpXbhXTB7uxRzznVMPyzeiaS7xJI4XtICkXcgC5HCMiNXasae
         VMI/qMVJx1dtRWeSNlSy9o2HEie6Dkbwayb6fWy5Wm/5yxB90TfPt6Qj+gjXmt3/xQxI
         EuuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NoRCYSp55PoTqRuFYPpizi0GfmkO6MrH2l1kGZSl5Lc=;
        b=4FthHR5c8Lby6Bkx1bkQZ4lB7K2aomOACaxsueC9L0huZx5JRSmTd4qYJ0zpwXYEXm
         MUfqFGnVvFb3SrZ+kmPZwKIuDEC2j/2UGO8wLlqin6bPXjvoid47OrzmkjrvZbqeRxwH
         XJbexEzkHGP6pxSIeeux3oAxHmBXZ6iAPSumVyUW0Ov7YEjiCittckrIubLJf4HIcv8W
         MIMLRr7WlY64EMwQKJ+1Hz7Rzp/EJLWVS/9CjLEG4vFt1vwVXDSw8WCInnBXpmvhJ8YT
         xOGgpfA9Q3X6+w49M9nBzVyrUb+7dWAUD8vkjuf7SxTEyW0+1F8J4AtxKu4eFHIOTDPO
         hBlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aRuf+70uPzgKUKVtq+Yc8Gm5T30+26VU0TA1zSBOWU79TY1Ex
	gap9EaUTc3IybJOr/g5xAJc=
X-Google-Smtp-Source: ABdhPJztNRoKGVIMFyj0SczN5FzTJUvV8qkPqxv3V2A2KpgpfMcvo7i2O9pYXTgxmWwe07X3BDEsgw==
X-Received: by 2002:a05:6512:ac3:b0:443:d3e3:db0a with SMTP id n3-20020a0565120ac300b00443d3e3db0amr19456647lfu.298.1646239206026;
        Wed, 02 Mar 2022 08:40:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls487037lfb.0.gmail; Wed, 02 Mar 2022
 08:40:05 -0800 (PST)
X-Received: by 2002:ac2:5de4:0:b0:443:5b80:d4c4 with SMTP id z4-20020ac25de4000000b004435b80d4c4mr18814183lfq.373.1646239205084;
        Wed, 02 Mar 2022 08:40:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239205; cv=none;
        d=google.com; s=arc-20160816;
        b=Quuf5001YeSFAJCwDG7rF/G+GRLuD/0sbIZRx1+zc2gtVAAM3SXjAJCuqABJMtpE0u
         Ibto+81+T+OlgA7OO4zo6ezixYBSB1EUGkDb2gtnKYjlLIygIcFACXlBTNWsColN5+IK
         VL5cJ+2EpoVysnm3lq7r979hmxrPEe+Uh7qAylDi/9ZwDasvWzfiknXkjWLWpNdutdBI
         3crSqws5iMQHjyCtF1A6/bonT23JU+z57Pb4+vRoCOLYHVtBFN2XhrLKg8hLKtkLeSg0
         8JAeU2tC2poiomEUgduJOnIV8PClDswk9toCIuFu6ZHxsn7/jiM4e6/dtKPVL/pxoUrQ
         KNOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EfvBgrtiG9LxjqkuYus7pXkmugj62NhRZroC7mYbdoA=;
        b=kg2chDzpcjeqaS6DuCcaJpOPo8jj1H87fUoz5L584sFXSfQ8u25eykQAGzvwZtZrty
         qrGCRgoWskhunceMC6bmwKv1u2z+xkGbNctf25ottdn2MdzE1Ga+7f+Wffhy5aacs7EM
         xa7ZYwqYAzBup+DR/dpk6YpJCvVw0I87baq58+gYQMEZXzFP46YSLz3mvYjuwdWgFbn7
         VSlpXjsPyNBiBrutbudE2+K8JUFjy9r5icsC0wjXtCX4/F/jH+mWs+f+fpJIC0G7Htos
         ny2WAcgRFSC9i5pbAYj43Z+uNgC+kLZSdi+4BnWDaL9BuxHb6eSjiBrLufWIMJKWn9s9
         qulw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=THIJtJGD;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id q188-20020a2e2ac5000000b002463e4271a7si873566ljq.6.2022.03.02.08.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:40:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 22/22] kasan: disable LOCKDEP when printing reports
Date: Wed,  2 Mar 2022 17:36:42 +0100
Message-Id: <c48a2a3288200b07e1788b77365c2f02784cfeb4.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=THIJtJGD;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

If LOCKDEP detects a bug while KASAN is printing a report and if
panic_on_warn is set, KASAN will not be able to finish.
Disable LOCKDEP while KASAN is printing a report.

See https://bugzilla.kernel.org/show_bug.cgi?id=202115 for an example
of the issue.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c9bfffe931b4..199d77cce21a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -13,6 +13,7 @@
 #include <linux/ftrace.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
+#include <linux/lockdep.h>
 #include <linux/mm.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
@@ -148,6 +149,8 @@ static void start_report(unsigned long *flags, bool sync)
 	disable_trace_on_warning();
 	/* Update status of the currently running KASAN test. */
 	update_kunit_status(sync);
+	/* Do not allow LOCKDEP mangling KASAN reports. */
+	lockdep_off();
 	/* Make sure we don't end up in loop. */
 	kasan_disable_current();
 	spin_lock_irqsave(&report_lock, *flags);
@@ -160,12 +163,13 @@ static void end_report(unsigned long *flags, void *addr)
 		trace_error_report_end(ERROR_DETECTOR_KASAN,
 				       (unsigned long)addr);
 	pr_err("==================================================================\n");
-	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
 	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		panic("panic_on_warn set ...\n");
 	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
+	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
+	lockdep_on();
 	kasan_enable_current();
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c48a2a3288200b07e1788b77365c2f02784cfeb4.1646237226.git.andreyknvl%40google.com.
