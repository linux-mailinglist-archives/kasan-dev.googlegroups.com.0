Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTUH2P7QKGQEW4M5A7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id ADFA22EB3BA
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 20:53:50 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 4sf74628wmj.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 11:53:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609876430; cv=pass;
        d=google.com; s=arc-20160816;
        b=v+BjUEPjZwyW5T+XmntlQU7BL3fncm2ZAE19Unwy7TQvebEnEkUQZobq11J7FQPTnw
         a2bsQvf41AWJhLvZKJD83wOm0ZEoC425y6GAadzfQdVeIuMLPTCsAteID55chHlrrAr3
         xyy8VRy6rH8hhlFTCergDfxmmIuBYavuVY6i/hg78HMw1Y8i0gxuLM0sCECBoMatdl7i
         IIU6xZq+14Wf3F+z2mcbD1YzQOL9pC3vEJV0hCrKmxK40kFZICdHwRB7aO32vbIpI21V
         4v5AEZUM+SZufBmNw4uHgzVwFOBv7RDZXpzZA05hHwWiLZie4t7YDXNgYzZd5826Wzxg
         Ojqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=UYsTDDkXODMBRvWdcXSecGLJDCiJ7HMhlzZgsgdY1hI=;
        b=mvlrHs8Aw1QgeF0YWGmR3FwgFnjOm0Q05gOPmBufB9xqUea/V4Up3kJoS6+MU70Pvu
         1wzNZfY6FoPXGwz841FnKQKej2VNSY8Xg52l1LGTGCUIDp3aWnY7gPJ69b23vSNAojkr
         EQGUBtpFVwUZR9uXhIDKlSr3eIh46TFDW20OnEzhcJH3LKms+UHGSB/zapPMOpbSnGwZ
         zKQiQhfewkBW2514eespCDAl14BGUPdsRSQM9xjZU2HoVdI19RTh/C46NFxmfPeKUi8F
         dbh5IgqZfrlMLDlMFaH8gJQN73ftMbzSIFB9p51tSfZT+Oa+LJZX8Y9A2rZAhdivnMo2
         zIYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWm5A0AP;
       spf=pass (google.com: domain of 3zcp0xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3zcP0XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UYsTDDkXODMBRvWdcXSecGLJDCiJ7HMhlzZgsgdY1hI=;
        b=b0FGSlGVHoN3IJPTBZGalqPPSENwyaGnGnYGy3pdvCMIrZAKHbwlsBYry4aqIPBKVO
         Zxpxx4njOzjQJ48hq85qPaI1YAG2EuxvOOA3Wn+OLR75qikrJtwdNR9QueLwk12zaGuf
         1QYk7yyGEcC6Is6SFKOisvRNN0kllfI6IvlkXywcx5csofs26O1LBW6e0wQJOO7/i0ro
         cJzpk9kolqdKYiTOuo6ehDdbFEQmOHl46hlhHgitUzEuHyMoxCZP5KeL+WSgOtgO0YnH
         TelxLwIRT84ScQJ3lqS2/1pVu5joEmBOLr9fILhg/N9q/NOulenWHvFQ6MBOHbgiWOwn
         aAdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UYsTDDkXODMBRvWdcXSecGLJDCiJ7HMhlzZgsgdY1hI=;
        b=dxCQUzmNB0iMkVnA01Zoeo/iq6GD9SF6Cd37gFQng8R+UNUKWvbVOobP0l9YpUxrkf
         gkVUfPrH/BtezY2q5z3UNbcgqd1jMas3Y6z/kJTMVK5iNIcwWlzNQ251TLehfW1906MU
         3FRXjp7uZvF2zvNffr/9RhQbJWDH1Ihu/WOZG9fmyRQEKEIp1QYXfb77mpmXQO+t4ACX
         2d81zqUS0/xTJzvb5aetH8buhc8ppm9+XQ3foUkOHwSdvXLRVdPxvIQ0ql6rdsT+fXJq
         R2Sn/6AcQFdUIqZN2k22ALid7ej7+UHxi2/ZMsrG/+u/aMHGG2aW/rsqGg0VLYskKnVN
         YFBg==
X-Gm-Message-State: AOAM533AlkPNGHwacOnkXsOR7JewJj/XIvUFitwldcvt4voGlj3kxrNp
	tRo5pvEmQ237lIKX+1iCrpQ=
X-Google-Smtp-Source: ABdhPJxOu+oSQzlL3WD2v2CdAYUtsmYmIfqSnaZsFTEa4ViWQ/0RNSKOOBECa2fqxuSx2ouYzUtvXQ==
X-Received: by 2002:a5d:4dc6:: with SMTP id f6mr1127570wru.336.1609876430515;
        Tue, 05 Jan 2021 11:53:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbd5:: with SMTP id n21ls314867wmi.3.gmail; Tue, 05 Jan
 2021 11:53:49 -0800 (PST)
X-Received: by 2002:a7b:c773:: with SMTP id x19mr611319wmk.127.1609876429818;
        Tue, 05 Jan 2021 11:53:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609876429; cv=none;
        d=google.com; s=arc-20160816;
        b=drrO63VaWinS03mtr9E9I/UP3Gp3KOa3ZVv7X62OjNO8lI68rIO24XUZye/aUJTrIX
         MmCQx0R3251N9qw4HOxrmuAXPL1AQ+tIkTN/70TpVW+L/QrukxxlXjjwFx7C4YjrkFyR
         U8q/nSDCRKBKt7AjAFcxnGZkrch7tnzDwKZQbFfBjXnwiWtwihswTs54WxwDOSb7ERDc
         SEg1eRS/L+uoFWcA1SSXWR1q+sIeNj8tf2ihERbIlid4tP5z69HX00LsZhjpmwTdzPQ1
         fw5R250FKIl42MI6NLgNfwuhFaTiMAjx5sYdaMjKOJ8Kxe8xsly/KAqVUPAubchgO5s6
         jOnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=ToKZZMMFz2dd/gf3h/vSB+5EZJff08Hd9cEbaiMy84Y=;
        b=jbKxBbfja6IKfecMuk1ZSlf45ru31JM74iU1jWcSZY2nBKv1ZhOY3Vb0+cPwb9xUM/
         TTxZbyRsXRKinjwNfMMgqwzjSpk/nEPez7sPUH3IwVPk4Dv3JG5ttp+h86y5pRA6MUFR
         KxtSrihCFjudTE3LPmMGGv7mulWy8Qwg3d+mSs5Jn1g1J6nm0AltPngyBUQvBTYY6Fi3
         QrtFOdoGgqOYl2vU7xLAs+8/R1lR28zDme2I8tLXlgdtRk54HGkb4Z8eSMvpQxdtX4xW
         WG7s/zdX4THQfzlsV3TX5a/pPX4Ae1zPQfKqPf9ot7PeKqjlWA+6nY/IHALjCG2FoQw/
         G01g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWm5A0AP;
       spf=pass (google.com: domain of 3zcp0xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3zcP0XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e16si17724wrn.1.2021.01.05.11.53.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 11:53:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zcp0xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id o12so286616wrq.13
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 11:53:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f6c9:: with SMTP id
 y9mr1090609wrp.121.1609876429392; Tue, 05 Jan 2021 11:53:49 -0800 (PST)
Date: Tue,  5 Jan 2021 20:53:42 +0100
Message-Id: <aeb430c5bb90b0ccdf1ec302c70831c1a47b9c45.1609876340.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH] kcov, usb: hide in_serving_softirq checks in __usb_hcd_giveback_urb
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CWm5A0AP;       spf=pass
 (google.com: domain of 3zcp0xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3zcP0XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Done opencode in_serving_softirq() checks in in_serving_softirq() to avoid
cluttering the code, hide them in kcov helpers instead.

Fixes: aee9ddb1d371 ("kcov, usb: only collect coverage from __usb_hcd_giveback_urb in softirq")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 drivers/usb/core/hcd.c |  8 +++-----
 include/linux/kcov.h   | 21 +++++++++++++++++++++
 2 files changed, 24 insertions(+), 5 deletions(-)

diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
index 60886a7464c3..ad5a0f405a75 100644
--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1649,14 +1649,12 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	urb->status = status;
 	/*
 	 * This function can be called in task context inside another remote
-	 * coverage collection section, but KCOV doesn't support that kind of
+	 * coverage collection section, but kcov doesn't support that kind of
 	 * recursion yet. Only collect coverage in softirq context for now.
 	 */
-	if (in_serving_softirq())
-		kcov_remote_start_usb((u64)urb->dev->bus->busnum);
+	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	if (in_serving_softirq())
-		kcov_remote_stop();
+	kcov_remote_stop_softirq();
 
 	usb_anchor_resume_wakeups(anchor);
 	atomic_dec(&urb->use_count);
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index a10e84707d82..4e3037dc1204 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -52,6 +52,25 @@ static inline void kcov_remote_start_usb(u64 id)
 	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id));
 }
 
+/*
+ * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
+ * work around for kcov's lack of nested remote coverage sections support in
+ * task context. Adding suport for nested sections is tracked in:
+ * https://bugzilla.kernel.org/show_bug.cgi?id=210337
+ */
+
+static inline void kcov_remote_start_usb_softirq(u64 id)
+{
+	if (in_serving_softirq())
+		kcov_remote_start_usb(id);
+}
+
+static inline void kcov_remote_stop_softirq(void)
+{
+	if (in_serving_softirq())
+		kcov_remote_stop();
+}
+
 #else
 
 static inline void kcov_task_init(struct task_struct *t) {}
@@ -66,6 +85,8 @@ static inline u64 kcov_common_handle(void)
 }
 static inline void kcov_remote_start_common(u64 id) {}
 static inline void kcov_remote_start_usb(u64 id) {}
+static inline void kcov_remote_start_usb_softirq(u64 id) {}
+static inline void kcov_remote_stop_softirq(void) {}
 
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aeb430c5bb90b0ccdf1ec302c70831c1a47b9c45.1609876340.git.andreyknvl%40google.com.
