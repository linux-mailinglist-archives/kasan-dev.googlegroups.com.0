Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4HA3T7QKGQE2FTRXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E10402ED3D4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 17:01:52 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id dv25sf2559148ejb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 08:01:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610035312; cv=pass;
        d=google.com; s=arc-20160816;
        b=lmuynjW3fPgrEAddDwPAuii13aRkk0NZkNnvUYmKDlEHN+1jPx14AQV+LWu5VZOpIG
         57RX6ym8KoXvxNcecOxSA+t0M98yPB0o7AN1xQ+4Ysm2Bag9RdTQYKAwwqET4NTYk0BL
         E+aTsqOR3CufSfkJgyc63Uv44YXFLCinRPgNOyvNzT4bL7jiczlzjD/M3qT8hPLVGJVO
         vCGXXAL0HQ+XuL4ZFkqXdVd+hpsxlGdPkUxTedn11+J+cqRJ7oxEIii/wpzelhadOV+U
         tkti9184LlG9aLnUlfxfbGPM4SvkRekPYt/APOtFYgNZNlY7V8/YtmJvj6rPItuXHPiU
         CmuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=GCmlSwZNyDHoDjLb+9QDimJifeBLJdA+9jyH9lEAo6g=;
        b=SmMB2M1w+Hceji6clmdvta3hb/Ii1W5kDmgijejuMYslzGulXrNffj8Gq3rxfe+FUa
         2mUi/p8zDIePodjBGQ5QV4Yh0IUfbtrxPJwAxLsA64ek1J8oDwFgOgr3zREBvpqofVkF
         nN9/k9Q3uZc36xdNSpeWYbiN0sKi2jDZ21k1XJl3VHPDklEtTcdY9zmCOwQYjyS7rSnL
         +Q06+7b9l14TSQTQnFfTFev3asTTHUJe+qhEVlIMJUW+KUamhAvWT4GjDgDG7yOeptYn
         Sh5x+D8KLp/q1++LbB80Qpd37eYs434G3sS1y/trJEqPLfvLKHYrGPNpUnIOIRaOvwrt
         FhVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V2dITOA4;
       spf=pass (google.com: domain of 3bjd3xwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bjD3XwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GCmlSwZNyDHoDjLb+9QDimJifeBLJdA+9jyH9lEAo6g=;
        b=FL1NKfjrM5kYf/5mQeiNh94PL/8On9rsWBOv7M1Umb4rnjO8WAJpS1uisjTuscEMjr
         nAB+FLXsk4MIy4+PxyNdoy0JnINX78Mp7WWsjWxoFx3Dk71SQUUMFOYXxtlDOK8nZCFS
         Y7BZybXQqS+brOYroVTRnIhL4n4bXWvVOq3Fl4FCBAnbs+kL4Luzk+iOCgjREKJdrWzh
         QkfzWB1Qlc/QRhrv3MtofvBONZOzhLeVrWNbVkkygLUyd2QaoHT1QP+HZGzmvFYKZLS0
         ifBatfoZyUC9WgsYo9yEUkQ18Zvnbz+voCf+6n896PNlP0SV/GCrdWv+w5p095QtxBN7
         Rfeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GCmlSwZNyDHoDjLb+9QDimJifeBLJdA+9jyH9lEAo6g=;
        b=oOqRfhiPhuzZC/PIsUthJCUz5asCwukyKXcYTYoP52jYNpXTFbsJmzq2jlTjFUNhlJ
         HlMHguNAoyJxACxiKs6GZagDRdfTW71qulWJ9/FuS5LrPmCBkLNW6THKKvnR9TQBezv9
         Kx5D577HoE5RFUKTfbxUaD5YwNrWoAWEhaVGtITxmhOiB3U6OsBnRpArSRlc1zsxhPfZ
         ldy0RLFoA8jVHdD+EUSMZdgrVol40a13Mhgw0WKqSHVxfSX7YjTinv0+xuyoQg0f5mf3
         jaYuTpVP765EfNagcNB/mshO4qxHHiJZZKOfHj/04HTOBQs3Jf9kRMbIwYmOg4r5qIMt
         MfqQ==
X-Gm-Message-State: AOAM531bbQXo3v23hj1XcbFp53fpBpDayxWh9fFGaSCQdGnt2DVybyg7
	t7pflR06cPIQmSTiArNEU5Q=
X-Google-Smtp-Source: ABdhPJxeVC3Xy5bS53gfoFXyXJFX/2Rzgj53SGW+zuec21NtlkFU7nASN1+IY7IqeUEibQSxAHRr8A==
X-Received: by 2002:a17:906:2499:: with SMTP id e25mr6795388ejb.446.1610035312668;
        Thu, 07 Jan 2021 08:01:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1432:: with SMTP id c18ls3875881edx.0.gmail; Thu,
 07 Jan 2021 08:01:51 -0800 (PST)
X-Received: by 2002:a05:6402:379:: with SMTP id s25mr2246583edw.367.1610035311710;
        Thu, 07 Jan 2021 08:01:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610035311; cv=none;
        d=google.com; s=arc-20160816;
        b=s1B1eeaI/IUVoUOk0p/V0p16jNt3vKo9eIS1gHCeRHZfVQpsLJAN2O8FC8rRhi3cyz
         MHrruJFoGijixNMWvGcRlv7ICWDNA+37BHeGJa+M6sTq7X49n+jFl5SWmEZfi9/Ty6zC
         yhSo1DG0P3JP0HEqtq+MxQOFT73oygaJa1vnXVqqSZ8PwkdSFIIDJBvDVn0LyOsMv4Pz
         YiLbV+XWCd1dXiKGV9xZIGR4LlyErBHrxcdqugG+nPPdlBEsX4YIkLSyW5pgu55BR+/T
         A8b1xeILKVh7Px3rPrgKjHmVHaB2t6ggap6FaZHMsloTEflOFWP64hYf/atTTxF16ebH
         HLnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=cIq2VE7GHy/A2isTfDsjFX2FggL4BJiiCnO6T+jBwiM=;
        b=Vun+djJFLwcDmUaPz7vJEj442TepBzY76BEx1dwicfKkPcUAfSDjvkuvV1Jn7VNR8i
         G2YV8xAuL/FWKvLTYWcBMHW9Ak1qC7TihyjYSTlOi7WqGsIaSrazEjJPe3x9fYUhAo2l
         uJmNpoeLn2vj4lwUdXdGOiUA0ozgEG+WTvUJJOULz741Fv6oxsHLU3JLH9YnbnRmHqXe
         BcsHXUYwLP+KSvp7JfRscA0GPUFxBuC2nYqYlCDWg+zVHW7Rp2fq0SUHQKsMiaEsE0Vj
         GWzojwcc278Y0pR7OklrxLnQXZesn/5CUQlFRZ/5vSZ9T2G0AjobUICzv4HQvGp2My3c
         ITdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V2dITOA4;
       spf=pass (google.com: domain of 3bjd3xwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bjD3XwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f26si300300ejx.0.2021.01.07.08.01.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Jan 2021 08:01:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bjd3xwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w8so2815966wrv.18
        for <kasan-dev@googlegroups.com>; Thu, 07 Jan 2021 08:01:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2c89:: with SMTP id
 s131mr1458471wms.0.1610035310903; Thu, 07 Jan 2021 08:01:50 -0800 (PST)
Date: Thu,  7 Jan 2021 17:01:44 +0100
Message-Id: <04978189d40307e979be61c458f4944b61134198.1610035117.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH v2] kcov, usb: hide in_serving_softirq checks in __usb_hcd_giveback_urb
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V2dITOA4;       spf=pass
 (google.com: domain of 3bjd3xwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3bjD3XwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

Done opencode in_serving_softirq() checks in __usb_hcd_giveback_urb() to
avoid cluttering the code, hide them in kcov helpers instead.

Fixes: aee9ddb1d371 ("kcov, usb: only collect coverage from __usb_hcd_giveback_urb in softirq")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---

Changes v1->v2:
- Fix a typo in the commit description and in a comment in the patch.

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
index a10e84707d82..18306ef8ad5a 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -52,6 +52,25 @@ static inline void kcov_remote_start_usb(u64 id)
 	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id));
 }
 
+/*
+ * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
+ * workaround for kcov's lack of nested remote coverage sections support in
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/04978189d40307e979be61c458f4944b61134198.1610035117.git.andreyknvl%40google.com.
