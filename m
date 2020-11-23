Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2EV6H6QKGQEMRWFAZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 677942C1998
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 00:51:06 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id s18sf5314098pfc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 15:51:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606175465; cv=pass;
        d=google.com; s=arc-20160816;
        b=DtGugaDCsyqSd0mu1e34+NXrxqoQjS1A+l8mAs1s4Wix7GM/laDQqYq7WSBUFU8BJw
         HwuHu0l1Gx28bpC59rYoE6AtZpgPVTqCHp68wGahghXtv03jiVqyJHyeHtm0IBKM7Vsv
         o8wbbT+aEJTj4H7+5ilzrANcoyzcmVjwRa/OTJFbm7i8rUafFPehJSP48X9Nu0OxGYw5
         jKuncCRftD9uLmMCYz66Jkk4o+0lpPy+9bMxdzGmWG+LpRjdk0ZJThipZ/GcwHTSUHsk
         d5bwLZn5RJYnNvmu0kAM5M0TT2Jv2DqmZgv4/WlaFyuleu5ehPZrTknZTPDknOyK31my
         qOPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=C6AKSLC3UogFMviXgyEgNKVsyKx7123K6CJm8t7ahYY=;
        b=pn5ob2BfDM5D4qZURV1K/JIneRV4PPWfSYAuCjC4J9IX2D1hPfh1UuS4wRDEDm+SiR
         W+y+CwHiihbIuE1p5027ONd9ij+5ZG4+xRxc2tXDQYuON0Zc/UBFFq8FNk0qD8XEATnJ
         iZmLECX2OwmGGI0OTlaYci5LnKQEEEsLKE07ggFWqCyUfPpjtCAryMULZptxD29OEVDZ
         8iPJ5NPL2ruZkyRsBu/SsgmpEGa3st5bYyG7OPLnkPYNaqtsr5BpGOJypEk2dyripeBJ
         vffkVjh0wDSCSBzFjSaWEIgOV4XOcNfqipYig42E4NgOIP2UQH8A860jc7xJIcHlU811
         gNig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hy5xhvJu;
       spf=pass (google.com: domain of 350q8xwokcxiqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=350q8XwoKCXIQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C6AKSLC3UogFMviXgyEgNKVsyKx7123K6CJm8t7ahYY=;
        b=iaZUFXbRsyl7c9HQqV/KX3p0oGx3YORnAvvtmH+651vnYIFS4tGnxL1f7yeuP/Nhl0
         m38p3QhEFrL+imA41KBuND80LBH3QnClnOqIwvLvYPoTGHuzVeXbzMbBbroBtDJcCcE7
         /KIeJKCcA38tLXBE39W929D4JogCabq+d3brkR/OH+VsxyGilCSBHHudACPlbpuG/jP3
         vzEnPi5lXaFnakLR3kUbfPNjEduGKOONdDXBG711G2J9XCWwRgYSp0OUXKSUfGC46M8R
         lRH/kYVEtN+zIYsh6fz8NwUqoPy2tdTBgzOQljfv/6wiAzVvHfg4NPCfsOhH7ezIwNrd
         09fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C6AKSLC3UogFMviXgyEgNKVsyKx7123K6CJm8t7ahYY=;
        b=DGprWYVXx3d6TFgm825tOl1ZB0xhTRwk+s0LCydLamP+5tkNv0Y992OLFR46Cu1RO1
         f6CMpT3qH0MBK5wtYXKPvdGOEYsIkyOD3Rrjik58ShfYV9QB19upl88PZgX0O/ZdkIBS
         pusGkE1fOfP092k5kusTu3dfhdf4zKlQohUP2aEDuaGWIRtSDpU1DyWP0QkkkZ38HN6j
         2tGTxCMrCAS+ma89mHTRZOny4IMHWSGtzk9xXROilAEXCoHYli8MF2YJf5LN5kcou59Z
         BgmKPsrD7Jn/cPE9xlwLZu63I/FxeKSHRJ5jgYQAG0cS1r6WxD7OadX0fRUv+EU0P50c
         eryw==
X-Gm-Message-State: AOAM532LTeLDb7pznuqtyk9Fn9RUWAqe78Rt2x5qi0wINEXGPmza+0Rk
	DYK3fkony5z0/qy/MzOBfl4=
X-Google-Smtp-Source: ABdhPJxE8AmnGSUXFeGBXgBomk1QW037ia/d/aBO8BWCBil5o7YDPUM/aJ/0d+XPuP4RJCKbr9wGBQ==
X-Received: by 2002:a17:90b:e87:: with SMTP id fv7mr1527842pjb.207.1606175465087;
        Mon, 23 Nov 2020 15:51:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad98:: with SMTP id s24ls511449pjq.0.canary-gmail;
 Mon, 23 Nov 2020 15:51:04 -0800 (PST)
X-Received: by 2002:a17:902:9a8e:b029:d8:d989:4f80 with SMTP id w14-20020a1709029a8eb02900d8d9894f80mr1602075plp.32.1606175464597;
        Mon, 23 Nov 2020 15:51:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606175464; cv=none;
        d=google.com; s=arc-20160816;
        b=mzzpL+c9KD9chiawDZsstT9v7gt+vSu1mCRvbpY1j24AWX3Ue5KWXQ7QFYxgPrgamP
         efYq/FpNLlKS1/4Wez7cbZGzsXl6MhzSGNbKIEylGuPbEMaitq1LNbFbGmTr0C2ces9d
         myTsFAOIFTfzOAx5XVha4Boqmvg+hComeAjfQJPTtp+yMXfVppB4RrhO7fHCkseum6E4
         Ftn/jYPAD+9ZPL+7uRoPRKT578yyCYs8Bk8mz0cmbo6ExyEQNvkPFHy3Jt8m+KAy+how
         B3pgd17rD7s0SzEGYn7O5HdhWyDaOzQpdCiYqu8us1H6V1abRnmudG7xAsPkjPMToTdZ
         G/2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=53LKNClv9WjrnexN7IY+lrSioJLLdaMg3EsJwltsJf8=;
        b=uUqNwE4qgtCE9BD70ZyjBVbe1OZHZSC45HTWkhw4Og/Y9t/YUE8ncfcrkCsHeRDU5t
         7jUjUc3pM0MTURS23z81QGMXBkEtIY90p/wX8+xqHv6rLSUT4wcisyFjilbBf63EF4i7
         dlo2/DMV2j9G79EcpteMo3EbHrOa2eUPZIHnPFYIBibJT+4HHMv5b74ZObLY9OTuymtg
         oDbLCx3FdE9FiTvWY8tHB2vRovPxrADJIo+4n+DvdafZm42L+m8hirnl0qz+E9gBB5cr
         /9SaGb/SucqIXIdz4oUpqjse5w8z1QILctIAHAfE04ot6s+h0wV5wa+dQBVMvmzH8Mnk
         a52Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hy5xhvJu;
       spf=pass (google.com: domain of 350q8xwokcxiqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=350q8XwoKCXIQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id v17si72442pjr.2.2020.11.23.15.51.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 15:51:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 350q8xwokcxiqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id o16so779094qvq.4
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 15:51:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:924:: with SMTP id
 dk4mr2031501qvb.19.1606175463697; Mon, 23 Nov 2020 15:51:03 -0800 (PST)
Date: Tue, 24 Nov 2020 00:50:52 +0100
Message-Id: <f8114050f8d65aa0bc801318b1db532d9f432447.1606175386.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH v4] kcov, usbip: collect coverage from vhci_rx_loop
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shuah Khan <shuah@kernel.org>
Cc: linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Nazime Hande Harputluoglu <handeharput@gmail.com>, 
	Nazime Hande Harputluoglu <handeharputlu@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hy5xhvJu;       spf=pass
 (google.com: domain of 350q8xwokcxiqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=350q8XwoKCXIQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

From: Nazime Hande Harputluoglu <handeharputlu@google.com>

Add kcov_remote_start()/kcov_remote_stop() annotations to the
vhci_rx_loop() function, which is responsible for parsing USB/IP packets
coming into USB/IP client.

Since vhci_rx_loop() threads are spawned per vhci_hcd device instance, the
common kcov handle is used for kcov_remote_start()/stop() annotations
(see Documentation/dev-tools/kcov.rst for details). As the result kcov
can now be used to collect coverage from vhci_rx_loop() threads.

Signed-off-by: Nazime Hande Harputluoglu <handeharputlu@google.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---

Changes in v4:
- Add USB/IP specific wrappers around kcov functions to avoid having a lot
  of ifdef CONFIG_KCOV in the USB/IP code.

---
 drivers/usb/usbip/usbip_common.h | 29 +++++++++++++++++++++++++++++
 drivers/usb/usbip/vhci_rx.c      |  2 ++
 drivers/usb/usbip/vhci_sysfs.c   |  1 +
 3 files changed, 32 insertions(+)

diff --git a/drivers/usb/usbip/usbip_common.h b/drivers/usb/usbip/usbip_common.h
index 8be857a4fa13..d60ce17d3dd2 100644
--- a/drivers/usb/usbip/usbip_common.h
+++ b/drivers/usb/usbip/usbip_common.h
@@ -277,6 +277,10 @@ struct usbip_device {
 		void (*reset)(struct usbip_device *);
 		void (*unusable)(struct usbip_device *);
 	} eh_ops;
+
+#ifdef CONFIG_KCOV
+	u64 kcov_handle;
+#endif
 };
 
 #define kthread_get_run(threadfn, data, namefmt, ...)			   \
@@ -337,4 +341,29 @@ static inline int interface_to_devnum(struct usb_interface *interface)
 	return udev->devnum;
 }
 
+#ifdef CONFIG_KCOV
+
+static inline void usbip_kcov_handle_init(struct usbip_device *ud)
+{
+	ud->kcov_handle = kcov_common_handle();
+}
+
+static inline void usbip_kcov_remote_start(struct usbip_device *ud)
+{
+	kcov_remote_start_common(ud->kcov_handle);
+}
+
+static inline void usbip_kcov_remote_stop(void)
+{
+	kcov_remote_stop();
+}
+
+#else /* CONFIG_KCOV */
+
+static inline void usbip_kcov_handle_init(struct usbip_device *ud) { }
+static inline void usbip_kcov_remote_start(struct usbip_device *ud) { }
+static inline void usbip_kcov_remote_stop(void) { }
+
+#endif /* CONFIG_KCOV */
+
 #endif /* __USBIP_COMMON_H */
diff --git a/drivers/usb/usbip/vhci_rx.c b/drivers/usb/usbip/vhci_rx.c
index 266024cbb64f..7f2d1c241559 100644
--- a/drivers/usb/usbip/vhci_rx.c
+++ b/drivers/usb/usbip/vhci_rx.c
@@ -261,7 +261,9 @@ int vhci_rx_loop(void *data)
 		if (usbip_event_happened(ud))
 			break;
 
+		usbip_kcov_remote_start(ud);
 		vhci_rx_pdu(ud);
+		usbip_kcov_remote_stop();
 	}
 
 	return 0;
diff --git a/drivers/usb/usbip/vhci_sysfs.c b/drivers/usb/usbip/vhci_sysfs.c
index be37aec250c2..96e5371dc335 100644
--- a/drivers/usb/usbip/vhci_sysfs.c
+++ b/drivers/usb/usbip/vhci_sysfs.c
@@ -383,6 +383,7 @@ static ssize_t attach_store(struct device *dev, struct device_attribute *attr,
 	vdev->ud.sockfd     = sockfd;
 	vdev->ud.tcp_socket = socket;
 	vdev->ud.status     = VDEV_ST_NOTASSIGNED;
+	usbip_kcov_handle_init(&vdev->ud);
 
 	spin_unlock(&vdev->ud.lock);
 	spin_unlock_irqrestore(&vhci->lock, flags);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f8114050f8d65aa0bc801318b1db532d9f432447.1606175386.git.andreyknvl%40google.com.
