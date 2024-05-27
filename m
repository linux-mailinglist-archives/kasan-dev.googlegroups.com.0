Return-Path: <kasan-dev+bncBAABB44I2OZAMGQEFEUZUOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C3448D0970
	for <lists+kasan-dev@lfdr.de>; Mon, 27 May 2024 19:35:49 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-529618910casf2573625e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 May 2024 10:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716831348; cv=pass;
        d=google.com; s=arc-20160816;
        b=gdUraLoKROa5QiV/PBjhSIOZqAhWgFnV8+M3VcziQp7Z0GOgud9AJLQK2Ep4+4DaW+
         XOkb1wPc1jjE+wT6kJ/egblOSzo5rKHKrsbRMY+wRJI9OfYhTG4tzHUgp4d68qxhQLb4
         nqw0wSGKNwqoWMnj4B2eMtoxTWL4cjVf1ArkOIxpgvNI9NYJhBimjbXbC1b0DxLPNqOp
         +ZYCOkT+siQzoIlLSmaeqx19zDW5vd0JlfMILTon2YQwRZN3Cxeukaa6QkAHF7M6/bYV
         xz5au3dSpQC1ni0NRQVJ1N/KankNpGeDuP0Rao6iY0t8nlpAJw01HBUyXaO3rsFnBVvv
         Bjhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pBIVmo2md39AiK5MPIfC26SIvufmbucyQ+vskSdex3M=;
        fh=ikPi8PhIlsNjjYQiU5sheUiuUsWL9Dm93oAg4e/4PU4=;
        b=zthksslTiFXUcwxMYaLGayspqYZY/hiCiOG4fG67J86fr3z+QIY8I9L0s/HdwFffKK
         /nZbIRfBxdkIQqFcHw1+u7qRkHf4pUejhliNryu9GWUiiJNG1vaCeTie6jIvv0Kn5shv
         np/e5UfElZhdwHwawWR0Uj+hL46hTLDHr07E+b97QP2HH05RD+XYAEpIwAxgNq5IiAhK
         uAjBO/pxfXRHIQxoJanNnLjR4TBzM/S3mxylrcQG2rVZozWHJXCfCZ5LhLwYPlOMvvVf
         WhJE6dq9R6jg81OeUcf1p3NjgjJptaqTVjpVp/CjU3lPDq4+xyrqu8odxyfdYswmuPjB
         dfQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="fc/XjUnZ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716831348; x=1717436148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pBIVmo2md39AiK5MPIfC26SIvufmbucyQ+vskSdex3M=;
        b=Oo2QIUfWRz39wH62jqr47HP/tBVAQKmh2QHJaGSNN/YUfEb2HAyPiZXTaXvztXXS9P
         62usf52NKaOyFR0vWQTqYHligP+BRjixKShV3DuSqupLpCTnD1GsLfRKpIq9VW56C6Es
         XbuHF24s6WnZf2xsgCtD8ca7DQZAoJ2+dge+/iOwDxFP3SHyktr7nV80uGLeyjlO5m5Q
         X/PtRiqpJAJ/X+pY6mRlS/kwlhRpa/Bf9le6t4iKX9akbXeZB/7EGvpQymW/xxl7HUO0
         LxxZc0i4AcatLXmUhwpXr2CrBLelR999AO62Qa6ekbklpfSfkoYPiXXNi4q72kjK/OPq
         tFUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716831348; x=1717436148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pBIVmo2md39AiK5MPIfC26SIvufmbucyQ+vskSdex3M=;
        b=XpjF11HzhhHDEZUE5Nbk8Y5rKkwVqZB7TQkfOkIgaSy8eDJj7DlrBiD2wA7XX/1KsT
         h5Or4+Ynxf/HbsmLJferUj+flM0MNl+tXSRLUlqtbIJ+Ag6Z3FRtaY3HQAtQpx5Cm93h
         yNQGaZjLKJJ6Q0LWUqOWAuJ3T/kkY1mUoDUEZDIV4uD2DA3O9zrPpYaUv2MP1+ZCaKsj
         aZIMNxXwpTXkalgABCpyx6CoF8S3Y1PQT3ASLqTE//K4/Ndsy98aF79yTU3hCSnIWtJH
         buC8CPXZ9OrjspPK8t2y6a0xN6E5+/o3cJcAtKiFT7Z54BhDLOUwzR/Vsuz7FtJU9+kz
         1p2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVT5bE8Zp5se8ZLV1H9dsKGEvk56LR5Wb4p56jDqmqWZjKwAt0FdPQE+tNW3ZTWzjuN1IpfTzSbV+29KrG924iABX6C2k/eA==
X-Gm-Message-State: AOJu0YwCyNM1gzQw2WmuDofIhHprEquLnkIQrkItYN6RNRNjJVMC6mDw
	FQ2wY/FssYNx3yWb2S3JQmbO3Lz2sqPbqDKjQQP6qKlfw3mnBh8H
X-Google-Smtp-Source: AGHT+IEVWMSuqqvTg5kDW/sy6Lt3hitpuc21trVjMq8hCYZWxppn7gjYHgCLCwpR9JT77A44Gn+Y4A==
X-Received: by 2002:a05:6512:454:b0:529:b697:a0d6 with SMTP id 2adb3069b0e04-529b697a37cmr818664e87.8.1716831347329;
        Mon, 27 May 2024 10:35:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:370e:b0:578:61d9:9aa6 with SMTP id
 4fb4d7f45d1cf-57861d9a19cls1041497a12.1.-pod-prod-06-eu; Mon, 27 May 2024
 10:35:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXH9v4KhcwAOmDedR0fho4NRgi6ykGaQkypKhvSRSrLn0OXWLMXmNToXwvevaF5tTgFG6N0Wrb2dS5oz6vwkZwWK+y5MT24wjgs8A==
X-Received: by 2002:a17:907:c84:b0:a59:c28a:7eb4 with SMTP id a640c23a62f3a-a62646d76b0mr482461766b.44.1716831345624;
        Mon, 27 May 2024 10:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716831345; cv=none;
        d=google.com; s=arc-20160816;
        b=kGlBJG9CINsdet9VEmwWvxKofPldcbTGqrmoU/7ycttk26vMP8Ko0sPg4V6R38FmvN
         hAQxZda4UIaJJkvaLANcDepaoZEitNPA5ZqTRgIMdaLKcR3N4WJZ1uD5WIo81X8rB+gR
         PT9ROZgXBznN1bpeWWcyZodePSJSlpdErA3nqQpDLZaRV2ErT82z8/ffzZFGjMRnPdCj
         vAdv32etCmfyyX0TMBydzaQxt36B0JPS3KK5Jq8gFSI3KQGoec/uo+9DE3AFNCBuB8jL
         9JQR/NME5WfzH1w02vzJSKZhgOa7xagBSryze+DNjOTsti5efk+Cxm4G7p3wzqGO5RMs
         OinQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pEWfxwCTmdixhELCn7XIjki2dS3F2Sosog69ucpgf7U=;
        fh=rkraikRHCFJTluuheplx+qlwCP3SJZSDkdhgtMGwXno=;
        b=OG0/5UzrwlFhJ2NbonBOf2mBjowOxaqevscaKRZfaY7tGJcH0JoXaO4xoNs4FTNAwV
         TqzIIWVfBQjEXCd9dCzIGHOc5PMP0K0Li8gN3E+Q4a7sZ51926wQU1Gl+IbRtEjZt6G7
         609Gv/10j7HZS3J86DpC8q8ic2eiiHbpp+dM5ztcxTdrFyE7LKJtyroO74QpW4bP6HSe
         /D6w3N3BbFDXUzfnPCcEP6kqaOJ/4XqNkMwBvXteNDY4wzMpLexevqEMofOgg3er5+ax
         5BKqbSNO4si4fNSxLgbsxwXmlvC49O4hj72gwzmpMgMW8tP2NzP8wCrvkTP2Bl7Tcy1L
         Ocpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="fc/XjUnZ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta1.migadu.com (out-180.mta1.migadu.com. [95.215.58.180])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a626c0e2eadsi19219166b.0.2024.05.27.10.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 May 2024 10:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.180 as permitted sender) client-ip=95.215.58.180;
X-Envelope-To: stern@rowland.harvard.edu
X-Envelope-To: gregkh@linuxfoundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: penguin-kernel@i-love.sakura.ne.jp
X-Envelope-To: tj@kernel.org
X-Envelope-To: linux-usb@vger.kernel.org
X-Envelope-To: linux-kernel@vger.kernel.org
X-Envelope-To: stable@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Tejun Heo <tj@kernel.org>,
	linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Subject: [PATCH v3] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
Date: Mon, 27 May 2024 19:35:38 +0200
Message-Id: <20240527173538.4989-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="fc/XjUnZ";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.180 as
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

From: Andrey Konovalov <andreyknvl@gmail.com>

After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH
workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
interrupts enabled.

Thus, the remote coverage collection section in usb_giveback_urb_bh()->
__usb_hcd_giveback_urb() might be interrupted, and the interrupt handler
might invoke __usb_hcd_giveback_urb() again.

This breaks KCOV, as it does not support nested remote coverage collection
sections within the same context (neither in task nor in softirq).

Update kcov_remote_start/stop_usb_softirq() to disable interrupts for the
duration of the coverage collection section to avoid nested sections in
the softirq context (in addition to such in the task context, which are
already handled).

Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Closes: https://lore.kernel.org/linux-usb/0f4d1964-7397-485b-bc48-11c01e2fcbca@I-love.SAKURA.ne.jp/
Closes: https://syzkaller.appspot.com/bug?extid=0438378d6f157baae1a2
Suggested-by: Alan Stern <stern@rowland.harvard.edu>
Fixes: 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH workqueue")
Cc: stable@vger.kernel.org
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

Changes v2->v3:

- Cc: stable@vger.kernel.org.
---
 drivers/usb/core/hcd.c | 12 ++++++-----
 include/linux/kcov.h   | 47 ++++++++++++++++++++++++++++++++++--------
 2 files changed, 45 insertions(+), 14 deletions(-)

diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
index c0e005670d67..fb1aa0d4fc28 100644
--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1623,6 +1623,7 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	struct usb_hcd *hcd = bus_to_hcd(urb->dev->bus);
 	struct usb_anchor *anchor = urb->anchor;
 	int status = urb->unlinked;
+	unsigned long flags;
 
 	urb->hcpriv = NULL;
 	if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
@@ -1640,13 +1641,14 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	/* pass ownership to the completion handler */
 	urb->status = status;
 	/*
-	 * This function can be called in task context inside another remote
-	 * coverage collection section, but kcov doesn't support that kind of
-	 * recursion yet. Only collect coverage in softirq context for now.
+	 * Only collect coverage in the softirq context and disable interrupts
+	 * to avoid scenarios with nested remote coverage collection sections
+	 * that KCOV does not support.
+	 * See the comment next to kcov_remote_start_usb_softirq() for details.
 	 */
-	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
+	flags = kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	kcov_remote_stop_softirq();
+	kcov_remote_stop_softirq(flags);
 
 	usb_anchor_resume_wakeups(anchor);
 	atomic_dec(&urb->use_count);
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index b851ba415e03..1068a7318d89 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -55,21 +55,47 @@ static inline void kcov_remote_start_usb(u64 id)
 
 /*
  * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
- * work around for kcov's lack of nested remote coverage sections support in
- * task context. Adding support for nested sections is tracked in:
- * https://bugzilla.kernel.org/show_bug.cgi?id=210337
+ * workaround for KCOV's lack of nested remote coverage sections support.
+ *
+ * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi?id=210337.
+ *
+ * kcov_remote_start_usb_softirq():
+ *
+ * 1. Only collects coverage when called in the softirq context. This allows
+ *    avoiding nested remote coverage collection sections in the task context.
+ *    For example, USB/IP calls usb_hcd_giveback_urb() in the task context
+ *    within an existing remote coverage collection section. Thus, KCOV should
+ *    not attempt to start collecting coverage within the coverage collection
+ *    section in __usb_hcd_giveback_urb() in this case.
+ *
+ * 2. Disables interrupts for the duration of the coverage collection section.
+ *    This allows avoiding nested remote coverage collection sections in the
+ *    softirq context (a softirq might occur during the execution of a work in
+ *    the BH workqueue, which runs with in_serving_softirq() > 0).
+ *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
+ *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
+ *    the middle of its remote coverage collection section, and the interrupt
+ *    handler might invoke __usb_hcd_giveback_urb() again.
  */
 
-static inline void kcov_remote_start_usb_softirq(u64 id)
+static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
 {
-	if (in_serving_softirq())
+	unsigned long flags = 0;
+
+	if (in_serving_softirq()) {
+		local_irq_save(flags);
 		kcov_remote_start_usb(id);
+	}
+
+	return flags;
 }
 
-static inline void kcov_remote_stop_softirq(void)
+static inline void kcov_remote_stop_softirq(unsigned long flags)
 {
-	if (in_serving_softirq())
+	if (in_serving_softirq()) {
 		kcov_remote_stop();
+		local_irq_restore(flags);
+	}
 }
 
 #ifdef CONFIG_64BIT
@@ -103,8 +129,11 @@ static inline u64 kcov_common_handle(void)
 }
 static inline void kcov_remote_start_common(u64 id) {}
 static inline void kcov_remote_start_usb(u64 id) {}
-static inline void kcov_remote_start_usb_softirq(u64 id) {}
-static inline void kcov_remote_stop_softirq(void) {}
+static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
+{
+	return 0;
+}
+static inline void kcov_remote_stop_softirq(unsigned long flags) {}
 
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240527173538.4989-1-andrey.konovalov%40linux.dev.
