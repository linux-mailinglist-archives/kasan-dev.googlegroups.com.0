Return-Path: <kasan-dev+bncBAABB6EOWSZAMGQETSODJWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 807D08CB4D0
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 22:43:37 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2e2035036f5sf122347631fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 13:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716324217; cv=pass;
        d=google.com; s=arc-20160816;
        b=p3r5Qa0KaNwUXoe+qRl+GCzjNtmWySDH66Kw8ye6bsk/F4k48qZ6tJB32imDvQywiu
         KaOysO3jxoeWGbcGFW1pCMMXZ+TTk2ufVnY5mnap/MNO306mECzqjRDeNaiHit+58bZI
         z6uPARPEazHfaIjDmSr0I7aYou1Ji6pNT1aEWTaTcjHUZ/XW5MArBkAAzy9vdNkha5AR
         ZrkHKcP++nOovNoU9aaBvwXL8IRv9GWTwqwEr8KKRpYHqP3KkzEfDavaX3kfBDTR3+Nw
         wIH3/4tSD036FWZnfgKmnJp7FOEBP3E32M9+wenpwS5COuLhCfBir13yxTtJxKpaTCeQ
         I9qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Of2cEbeMtD9Hlg/pioJiZ2acSyiXuBWBlX7ZiMMnkMQ=;
        fh=26YVEWvwuBXRD2uJjBT3voC8R7fANdmdDGnYKggOukw=;
        b=Yck4QSK5nSuZdFCFSxzqozZa9AFSLGtElHm7gDpViVYZDZwEaEC06JB27dXjrxZzZe
         7SS4WWUk8tbB/D9fihuJBRC8ZEAu1KqNEKXd3rbR6bEPa1+++RFva1YaXO/iJ5RBnppR
         JFdgLPRpL2E+HuRdPCynBeiCUsrghE7xYTJzGLQV06BEINXK33gWX9yNQEokbSYV1JCa
         X/2hOjNoei4+/ZGV8sWquZSKznESwiLbJeheT4OVPHGwmY51k8yIxkWX8CkbDB7VbWtv
         98H/q/92oXzF79BKivk4eRIg48VWj4d/PMVTmKBls/ReAV8yubwWBMI0CKLQdrv2IJQK
         ldzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ElXeTZh+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716324217; x=1716929017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Of2cEbeMtD9Hlg/pioJiZ2acSyiXuBWBlX7ZiMMnkMQ=;
        b=uXH6XG2GiDTXipOMNpJoIhI/FsH5M0ufiY+9G41e8zeIxh1qUh3vjon9OxKSzvRtZy
         xMub5c1N4H87rDn1ROTu4xHC1Kdw5rF9bZUFlcgiiE15xXop+01jCKWoIsZjD0TUIqof
         ss9bYURMrUvnZK0VaMuVVV5q6QI/9D9pGYiuxsU21g9US+7Cu5KkpZNXlDWy2GrB3S4Y
         OT8CA0Kxn6mTuLWbOWY+exk33Jybms9sIXqPp9AYHYi/u6sDaEaCZDSZaJ7AOjPg3PAb
         VA48/QNuExaa+gvkHXa27cePxuzhdWim9hVPxB2mkW5c8T2HutYQJSxTAzqYgOxXLJLE
         gkJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716324217; x=1716929017;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Of2cEbeMtD9Hlg/pioJiZ2acSyiXuBWBlX7ZiMMnkMQ=;
        b=IOnCw4YP8puNZDyiMWa85fJ5hQwD4aeeK+cVMtqSEikWkE2AEQMyWPk7EAgpaskbIs
         CrFTvEvcSokNh5VZ+bjOMTyuX15HBl/1/09vH2/OdnLPjYiIiPkLsGt9EmKZaVdXU0ej
         qvmpzUhf0KITvlufxL7l3QNpDJkkLI/lAFdVAEOQJytWPz6j9LPS4x00kIr31lawatMb
         E1+LU981zr2mbIfu+IEPzpiurQ5aI9KAqgWsbXO8rCOQd0dR65rgYcWSYkdmSIvWWk83
         i/t7tTUxPhjlU5xJhhjy2efuBOtt3uRBRRDOI/saSl6D+4kgtHlamQAYU14IlyCpBG7h
         sY3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVL7WSQCIC9gtxAlpDO/5xRx3CtFzbBjTENPjGvuhTqcGeUebowSpu0c5uCAYbeqVc8t93uZEK97jH7bymKwOBk1svXdFEyQ==
X-Gm-Message-State: AOJu0YwL3wm7kd8ZWEJUhU+0jzAZbeqERzXzHNGMOd/nkvNgq3WUOvgx
	6MveLm9N0X/+YtDZmzsyZNjpxe1PsXHBqE1YB+rWN8qQ+ii2Z2ej
X-Google-Smtp-Source: AGHT+IG5G/xfJsl8ZLb/ytnHTaPBTl8X4zIvLipqEmC60pq0zgPrW8/4JtcdzMZk6Uz8eOO9G0Wk2g==
X-Received: by 2002:a2e:9497:0:b0:2e5:59a:591b with SMTP id 38308e7fff4ca-2e56ea3aeb1mr272982101fa.0.1716324216355;
        Tue, 21 May 2024 13:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e48:0:b0:2e2:9c50:c4f8 with SMTP id 38308e7fff4ca-2e4b5818536ls2165021fa.0.-pod-prod-08-eu;
 Tue, 21 May 2024 13:43:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7QSmkl4SARZeSSPk5qEqLo9QTMUbQqQvt9VtpGIZOG8uXd+sWO4VhKwttiAK3dxtnCga2RkXabnJb9mpoprPXw8GhKAYgowps1w==
X-Received: by 2002:a05:6512:2252:b0:51c:cc1b:a8f6 with SMTP id 2adb3069b0e04-5240b650098mr11865507e87.20.1716324214497;
        Tue, 21 May 2024 13:43:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716324214; cv=none;
        d=google.com; s=arc-20160816;
        b=ERTsUsz4Xf4YNHMkW5gLzRoF+sd4Ft2NFLkTXdXEzRg64HlQFBPPEyq3EUqv/l8Jsd
         3uGJAIxQ4rm72b0sM6XD3i2LHYY3l9GXFBUD4k+lr7amxkqqGwUEnGtER0n0U1d2lIds
         LFuQd7FNspppe2PIC6fYm6oPiQq9fBcROdk6bgsaz8YntN6+GR863Tj4oNwBcFukOmtx
         yBr2eQtNl/HIwSvW/dLz6vUpU1KHp3DtzC2lfTfdhAJd28dX1IDOO83R2oU5CfiL642t
         V3YfPakbiBT6Nl5lgKptIoUVPBeLXn1IYi/nXjbvsnTAD2yiHzUNB6PaLyaVsKoymUG/
         mcEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Bef2r7PmAPGGh3unVAHDRXktGwmTTWv6IxMkhLqqDqQ=;
        fh=vzUw7PUiCZFQ+9TOy7Fqic/NTmihsgiz7wHWl8OdU2Q=;
        b=OINfhP+YGA7kaMH1kXLhJoAQuHyr4nAMSLf1MhPSPCuPrRE5RyPLnnZI+MppNfL9OC
         u1FU+DxVm2flH0YwqYVdgMIHi8Ap9f0EhFjgBtgJJHEfP3yVnjpgpgH/VarxgxGhP6uu
         qeA2BGmQ6iEGt6mbEnXNoRHiyySsAGNTiTl5u83Rw5QuzKE9qz67Qg0JpsJsI5VpCsFy
         yO6a8C9EEWHwWHK2KMBjLr2H3eYGDRWtjG969HkgAS7pGT4I6wIIxjLJrPh/H51UntB+
         PsBHYPM/hpmZ+w/nOxkquCqo6bTf75oVvp/1TtB1aOXMBx2R8d/SfyZCMXpjy5P6/QKW
         4x9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ElXeTZh+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta1.migadu.com (out-174.mta1.migadu.com. [2001:41d0:203:375::ae])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-521f38d9213si701648e87.12.2024.05.21.13.43.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 May 2024 13:43:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ae as permitted sender) client-ip=2001:41d0:203:375::ae;
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
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
Date: Tue, 21 May 2024 22:43:24 +0200
Message-Id: <20240521204324.479972-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ElXeTZh+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

Changes v1->v2:

- Fix compiler error when CONFIG_KCOV=n.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240521204324.479972-1-andrey.konovalov%40linux.dev.
