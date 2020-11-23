Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE4U6H6QKGQELFDGOYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 778942C1989
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 00:47:32 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id cu18sf14010436qvb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 15:47:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606175251; cv=pass;
        d=google.com; s=arc-20160816;
        b=kwPEBGOikTFg8G6nMy0eCOWhLpBitfi2nVl2bNwCrt6DVtBqGaF/M35ysGrs+IgML0
         5cZHLuVCUWwTwCSmPtIqU2Qj0mMKDIzSuW0MEQki3zmIxwXz4Mzzyft29mJKQpY980B4
         Qehesk4crO+HKczqNWhkfGHnKUsC2oH6/O7iTnKlqtVonRHZR4g4fmVEqJiCNFYrZTCB
         7TSCgBqQhwch9GmVM3fxUX3o2RADx4Iu5kgRLgs0p4Uy6n9MKJKs25+Pqt6H2coDUoDB
         BOisM59x6cwcrdLnzKBdSvHnvZsJjJqTDJLGfacgYnUpEzmhLGEch2ILnOgVo/BbmZE+
         9E4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=D4n6+iKp12ey/j0OAtj1zJkMPcN1yOYVvOZEFsQLJ8A=;
        b=q960ocz3zpUXuU7nnJQFiSmxpWfjvxi7Aas86mOCO0URI6x+Y85Sa77oHZpX+oNSDR
         e5lpgjIM8oBW5JRxAXSt1k+VnU0uW1XBhVCB3ZT5UmaMm5ccUzo7CynP/ZY/g/rZS5nH
         QtAE5wOCa5/9FhC4uNNlpfB2PND9UE/bS0xz7x/jO3qQPg25pvCJ6Q75nI9zBMk0Mca2
         ohyDD6+ulJIv/JP6SxRHHopRWMxqMx6HQQNNRQCr3XI0e3yt0sc74mCxlF/RHazKQBcX
         aX6XNMsNMbMTNigjThHFrhu6IYczMNMtmY8yg8zFOS3AKv0HA31/AhB1OeNcIQfWo9J1
         jBiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVO7kq0B;
       spf=pass (google.com: domain of 3ekq8xwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ekq8XwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4n6+iKp12ey/j0OAtj1zJkMPcN1yOYVvOZEFsQLJ8A=;
        b=SFSz1l4235mp5HMiqRcmzDPGwvsLwXC/67bw3+7Cn7fBGZXhTkgr+YxifhzdgFc/aP
         aYcGfrl3xO350XHQeO18Dba4lmW/fC5md3Q8ljdndLB6bJP212ne+fTkyfZgHTyNQbxn
         6WsDZpzjiSWUU6FKTk4NaWZSaoWsQZfqAtopIUMTIH4WedET8PmPNv9U6AenppeZkOXE
         yX/8yR2oMAPk2J2AUj8VKUXnoYz4Koo7YuQNK76YFUjAmIYbEHk56cq0YE5qXSEGU7l7
         4LEI5e1G6a2c1/bzESUeYU0SuR15RsB0AY8kXoLHn+MSm1AdsZMgCpWSIfdflUKb8P1Q
         WGtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D4n6+iKp12ey/j0OAtj1zJkMPcN1yOYVvOZEFsQLJ8A=;
        b=Y0v6vGS7G5gjjjyA8rGFvurqBLKda+75cLs9pAWlpXUAg/YSJiOFx9NlQju41KMKxU
         +xJ8poIJNDZTout2Z4yS6aBpF9cIZ+UD9WCLW1Jhc3CLl4Il8UHieVfaoWavPBvqdk1p
         JNvL5WoRRHQjTk4eNYddt5jBEHh/DJGy7svTjUodQ/xovpY0Fs50Lnq5vd1khW3+2rsd
         UIGVRQxu1uhNvFMOGixfGr29dosqCMgdJStvuWNkMPL4YY6ioB8Y48onefR8puza/cBV
         t9ll2wN2UKYu2P00TjucieGuclW+8NxCU503yhIhTNoVwdBLjJYghGDDwif+vzgY/RwM
         aM4A==
X-Gm-Message-State: AOAM5317FRZgT8sbF9rEqn4DX0z9Z6z2OWPsYtQ2+QDYB/eDbP0Xfhio
	gGUycj5WMLm88nTAcfyz4K4=
X-Google-Smtp-Source: ABdhPJzgmQhPSmU1NAULp+K05XmPLwK7pQr+SSNCBfRuLWqvIZNCDAur5sDfFtJMVvNw8e4aWzrx1w==
X-Received: by 2002:a05:6214:20a7:: with SMTP id 7mr1991643qvd.59.1606175251510;
        Mon, 23 Nov 2020 15:47:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:556e:: with SMTP id w14ls1441192qvy.0.gmail; Mon, 23 Nov
 2020 15:47:31 -0800 (PST)
X-Received: by 2002:a05:6214:4e5:: with SMTP id cl5mr2049724qvb.42.1606175250999;
        Mon, 23 Nov 2020 15:47:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606175250; cv=none;
        d=google.com; s=arc-20160816;
        b=lvBpaOIRrsXgNi9fLyVx+ufvO8+wWokt54nN/KQ+MtC1ctw4DT2QlTn2sK+ZfzNu5R
         iAXcdiVhBvG1ikCmwS4q77SeFCqnr84Le+pQMKMmhG6vxWzRNfw7ytX2VGTazCMXRWRY
         KhN7Ha6JK64GmLGRWMeRkadCvtF5SDLaYS45vU6NdJo2Uwf65rG2KEKFHGkmM0BaeTO0
         1+qoVrvCNxCF43ddYdYca5y3DqwscXa7bLStZb4loZL6GYfgmPbEZ47fZTvv24a2hHSt
         TxIjxUzmEK1iiwcQ68UpbwEGvduUOEZBpnivekoOP0KVLitbenfKzir0mc1Jl5P12U63
         QopQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=ascgbhXbYRQvyEEAQc3awfc5IanY2cScWjvfywd41uw=;
        b=Lz+Xtxr3ibFeCF6ha31OtOrvll4j+nvzjqnpRsnsI9KMlonEcvmEbYC0L9YnOOM7J3
         dpVAYyn0HfdSuKYLS5s80qXbyNP7dhMC3H9TJXIU1A+/AbBbt9wxMGvGU1fDE2MoKJRc
         dQ537YeD4icI9KphSslNPvsElfrlxeRB7NqfZMarpFud8unc8SpR2Th7/GJ0Eg8CjxbZ
         gtGk33AuieUHZpiO/pZYEx/p4zXIH2NRycYXw+8vFF+KqXqg9hbc6lKva0ZxVng80bIS
         3bs4FDLjgKuXv3Ixd6C0oYcqhVj0U4Url/iRkFRQYUL8ZBnw6LFVPknNFmLev6/xR9cO
         gv8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVO7kq0B;
       spf=pass (google.com: domain of 3ekq8xwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ekq8XwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h185si350396qke.7.2020.11.23.15.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 15:47:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ekq8xwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id e142so25176611ybf.16
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 15:47:30 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:4095:: with SMTP id
 n143mr3145444yba.106.1606175250569; Mon, 23 Nov 2020 15:47:30 -0800 (PST)
Date: Tue, 24 Nov 2020 00:47:25 +0100
Message-Id: <d7035335fdfe7493067fbf7d677db57807a42d5d.1606175031.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH v5] kcov, usb: only collect coverage from __usb_hcd_giveback_urb
 in softirq
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Shuah Khan <shuah@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Nazime Hande Harputluoglu <handeharput@gmail.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NVO7kq0B;       spf=pass
 (google.com: domain of 3ekq8xwokczs5i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Ekq8XwoKCZs5I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
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

Currently there's a kcov remote coverage collection section in
__usb_hcd_giveback_urb(). Initially that section was added based on the
assumption that usb_hcd_giveback_urb() can only be called in interrupt
context as indicated by a comment before it. This is what happens when
syzkaller is fuzzing the USB stack via the dummy_hcd driver.

As it turns out, it's actually valid to call usb_hcd_giveback_urb() in task
context, provided that the caller turned off the interrupts; USB/IP does
exactly that. This can lead to a nested KCOV remote coverage collection
sections both trying to collect coverage in task context. This isn't
supported by kcov, and leads to a WARNING.

Change __usb_hcd_giveback_urb() to only call kcov_remote_*() callbacks
when it's being executed in a softirq. To avoid calling
in_serving_softirq() directly in the driver code, add a couple of new kcov
wrappers.

As the result of this change, the coverage from USB/IP related
usb_hcd_giveback_urb() calls won't be collected, but the WARNING is fixed.

A potential future improvement would be to support nested remote coverage
collection sections, but this patch doesn't address that.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Marco Elver <elver@google.com>
---

Changes in v5:
- Don't call in_serving_softirq() in USB driver code directly, do that
  via kcov wrappers.

---
 drivers/usb/core/hcd.c |  9 +++++++--
 include/linux/kcov.h   | 21 +++++++++++++++++++++
 2 files changed, 28 insertions(+), 2 deletions(-)

diff --git a/drivers/usb/core/hcd.c b/drivers/usb/core/hcd.c
index 2c6b9578a7d3..7bafd01e05fb 100644
--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1646,9 +1646,14 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 
 	/* pass ownership to the completion handler */
 	urb->status = status;
-	kcov_remote_start_usb((u64)urb->dev->bus->busnum);
+	/*
+	 * This function can be called in task context inside another remote
+	 * coverage collection section, but kcov doesn't support that kind of
+	 * recursion yet. Only collect coverage in softirq context for now.
+	 */
+	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	kcov_remote_stop();
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d7035335fdfe7493067fbf7d677db57807a42d5d.1606175031.git.andreyknvl%40google.com.
