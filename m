Return-Path: <kasan-dev+bncBAABBHH2TO2QMGQEED62RYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D5A6093EB2E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 04:23:26 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ef2b0417cdsf28874691fa.3
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 19:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722219806; cv=pass;
        d=google.com; s=arc-20160816;
        b=ToemZcenvTHCk7lYW2pJLSt7K31hGkZq3XQEUEUnVmu84me7itGORH7Pfhkb35Yucz
         o2ObZ4TTo/WzKRn2/CPPJRtnT1HgcwSHxzRjPeryof2NsU+Yad4oVZ3USrzDr433PLe4
         Ja353qf62rgRUuAyUk2SzKVDwoadUpqFgFWobqzfdqLEqY0yQ1u5E5XUZooTjpPCLdVD
         Wbkfw2uBT0dULhB8oOGdhKEJGPSwgxGZlZOwwJpMGWI7q0E3ejhe5OVYFqkUs/koE79d
         WtyntfXMbTR806nW9H628YthIODhQj6ns1/Wwv5GXJjPjUD84eETvg7gctRYq5toTY7B
         oTJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZVlTKNF7sYnjLmHV2e2uabKp4HACvYaEYKViH6XVtw8=;
        fh=4qDe6Ui84ailbNoKgz39+AtxQMqSKx55w+rcxFqEPnI=;
        b=dZIy3eM8YgD0n4l5MsctNMtmsHWNC++utb3PVrkaJS0dfWZdm2rxvDmcHa0vfUEsIL
         S41MWzexaZkZ8OQVDQaZf+/Wj0rf85uPtuZfopUar/TQuDte2bbnsmV4IJP7kg71p+8Z
         yfmdoUDDErvPYNoICGdszmqfymo3o1QfpzKkTkWsoCNpA/BW+BDRq+wfkNlpIvRrCe53
         SXRswOiS9T92w94LNPgInn16btXYudOmWpfV9Z64M8Hn4c+nUhdQ5qKdshyCtjMKAhjz
         mY5+D4grb/1JFexYbB3H0vySEQtGwms+xZZickBg4QDVVcarx1vxN0dZHWQuEqTSzOym
         7fcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qdROVfdd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722219806; x=1722824606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZVlTKNF7sYnjLmHV2e2uabKp4HACvYaEYKViH6XVtw8=;
        b=oejA6vIuTla3W9H9cRjhukyy5BUaWTyLh7WE3RzBqUxMkXD9pKRtAQjSwsx9PJz+pk
         1jB8jzG5LxBKiMizsOikRDYHAFxC+fSPQDK3KPNcXX8S5NYIKBQXfnDZWGH9lvTQlQi4
         O6TkUyYvmENemNLNeb/wAi9FudDZghsus1iccmPeoSreOJe/9D2/3sk+0/h2Xd2KIRmK
         ryD77Qfes2n/gNI0syGc0L60BFMQoRR8VQhu2t2gPrWMvsGa1DOhx3plVoJS/fj5laFE
         RIxdYTciAIohsiNdx78mzAvpAtmSmzQMjz3tlbLH0YMY/kaWLgvK8H2vT2Fm0FQhXD0Y
         R/pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722219806; x=1722824606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZVlTKNF7sYnjLmHV2e2uabKp4HACvYaEYKViH6XVtw8=;
        b=g2pPxHMlSENhf51lwiy8AW6mHTY5DoX275akH+IV1n4xMl7byYOEzJzgA9xNI3AGDP
         H8lb97a0IEXC72lUakQ72q6B7PvNLKRMX9GtoaV/HO3ayJr/6bmUHrA4Qu2YwdncoeI7
         WPzdT4xOjcSWZf8sh1M7h3XRZen5/P5OPwfSW2xwothBpIpzA9NId/RfpRYRhK2UZ7nX
         np/kW8L2fSZ7I80DFMe/zE/1giCiN/wt2VlRY19wrhkoNdFyuUaTCOGvfOTewDJFpQpo
         rnmHnNh5/dKaGb85PkZeGdu5AaCtHt90j1iOFe5H+1PbC448bsI0beVGbV2JvlB3EGiH
         UfaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtsGcd2UFrQugCXEZkMRfpK8CuF8kXZu/HnacFbtRidsYfHjhc2nTJOawtcePFiSjOgOiTmA==@lfdr.de
X-Gm-Message-State: AOJu0YzJ9l7QVf3BBWuAsSfpRdzonhu3AObmzgNItGIgcKwuD7QayXDD
	tfaoJNUcsirf6hVzYZvWxFG/5zQ/XpgFUM59ZjPC6Ziz4JWxLR0I
X-Google-Smtp-Source: AGHT+IFpbsI1H1CEFgRpdw4c8T2fJTmU4S0w1D3Kg4Ewq2Rt0RE6Cvh0aQghmEMCcLHn32cuw8oEkA==
X-Received: by 2002:a2e:b055:0:b0:2f0:1a44:cdea with SMTP id 38308e7fff4ca-2f12edd604cmr37103121fa.26.1722219804628;
        Sun, 28 Jul 2024 19:23:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc10:0:b0:2ee:8477:7703 with SMTP id 38308e7fff4ca-2f03aa45b4fls18772911fa.1.-pod-prod-02-eu;
 Sun, 28 Jul 2024 19:23:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8GfWeLvCamjYO/f85EhPW5PpfayYE4eNx2EphENED+6n3AEMm/v5ZHIrLxPdITgdCzXR+229WI8s=@googlegroups.com
X-Received: by 2002:a05:6512:3056:b0:52c:cd4f:b95b with SMTP id 2adb3069b0e04-5309b27a467mr4258031e87.22.1722219802756;
        Sun, 28 Jul 2024 19:23:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722219802; cv=none;
        d=google.com; s=arc-20160816;
        b=uyNX8n3LM6/YH7m8UIJkGPvhFLmUnZzH5e7h9dNDB8VQXaCqOjjlaLLvlktKjKjD1G
         NGJWpeP/kYhRC44wGG8WZA7gXG0sjgNcTQKQChLO8a99ttteEpi4corQWSMfo1AiOInt
         AkNEAXdkDcIjtI9Gl6jl3UjdP33WKvJ/YsPVL+KvFAsCgQEM1srguRTkZEZZDPExclsx
         /G/pocwM3cgk2AoEGA/0zuFj2QM7TLXc9cO/aLgJYvtvnWB5bhbDGsLATbLZ8lCYQn75
         meQXwtE9khePbjeV8DWlLiTfrfCqCMFwJPWfd8Z39d6EC6GseuEDH/7+vhWDUsv2zXOx
         W3Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gCwEWY47GPr6v18PXrGNgbZC2X9ZT/ev75yXbrOMQ20=;
        fh=EmjPc6wjj5GFMzgqDVftkPqIeLajXn3fJBkulHVKlPc=;
        b=wP2q7hMQYQVep4k9OQGIhDTrg73qtBCP5FJdsZ0gKJylFhuuqIPpxwyXo1Dc/nwIos
         a+RojuKunYenG2ieg12i1tnAaxzuiDvG4XFYtEyyPe1Gy29sFDTBfLLXHvwITJD1C1gB
         Ivi5jcUDG+C6Uu1VAgjHdTddIhyRghivI0lyiKbgjTNJcx6oPs1yCuUYT0ucnLR06dKT
         Nkdx9frZwtBmNIifKk8vVspMu2AfY/HTQpC8vguFL2V3m0YVoDEazCU2mHswQm67YbDN
         MffE3wi0sSWb0TUsHbWyogSAkhniym6m1GPkke4nUCz3bHVNshF6VjbMRKCtrAE+/AW3
         y9EA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qdROVfdd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta1.migadu.com (out-183.mta1.migadu.com. [95.215.58.183])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5b8b9bbsi180377e87.1.2024.07.28.19.23.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Jul 2024 19:23:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as permitted sender) client-ip=95.215.58.183;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Marcello Sylvester Bauer <sylv@sylv.io>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com,
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com,
	stable@vger.kernel.org
Subject: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in softirq context
Date: Mon, 29 Jul 2024 04:23:16 +0200
Message-Id: <20240729022316.92219-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qdROVfdd;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.183 as
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

Commit a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer
scheduler") switched dummy_hcd to use hrtimer and made the timer's
callback be executed in the hardirq context.

With that change, __usb_hcd_giveback_urb now gets executed in the hardirq
context, which causes problems for KCOV and KMSAN.

One problem is that KCOV now is unable to collect coverage from
the USB code that gets executed from the dummy_hcd's timer callback,
as KCOV cannot collect coverage in the hardirq context.

Another problem is that the dummy_hcd hrtimer might get triggered in the
middle of a softirq with KCOV remote coverage collection enabled, and that
causes a WARNING in KCOV, as reported by syzbot. (I sent a separate patch
to shut down this WARNING, but that doesn't fix the other two issues.)

Finally, KMSAN appears to ignore tracking memory copying operations
that happen in the hardirq context, which causes false positive
kernel-infoleaks, as reported by syzbot.

Change the hrtimer in dummy_hcd to execute the callback in the softirq
context.

Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=2388cdaeb6b10f0c13ac
Reported-by: syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=17ca2339e34a1d863aad
Fixes: a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer scheduler")
Cc: stable@vger.kernel.org
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

Marcello, would this change be acceptable for your use case?

If we wanted to keep the hardirq hrtimer, we would need teach KCOV to
collect coverage in the hardirq context (or disable it, which would be
unfortunate) and also fix whatever is wrong with KMSAN, but all that
requires some work.
---
 drivers/usb/gadget/udc/dummy_hcd.c | 14 ++++++++------
 1 file changed, 8 insertions(+), 6 deletions(-)

diff --git a/drivers/usb/gadget/udc/dummy_hcd.c b/drivers/usb/gadget/udc/dummy_hcd.c
index f37b0d8386c1a..ff7bee78bcc49 100644
--- a/drivers/usb/gadget/udc/dummy_hcd.c
+++ b/drivers/usb/gadget/udc/dummy_hcd.c
@@ -1304,7 +1304,8 @@ static int dummy_urb_enqueue(
 
 	/* kick the scheduler, it'll do the rest */
 	if (!hrtimer_active(&dum_hcd->timer))
-		hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS), HRTIMER_MODE_REL);
+		hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
+				HRTIMER_MODE_REL_SOFT);
 
  done:
 	spin_unlock_irqrestore(&dum_hcd->dum->lock, flags);
@@ -1325,7 +1326,7 @@ static int dummy_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
 	rc = usb_hcd_check_unlink_urb(hcd, urb, status);
 	if (!rc && dum_hcd->rh_state != DUMMY_RH_RUNNING &&
 			!list_empty(&dum_hcd->urbp_list))
-		hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL);
+		hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL_SOFT);
 
 	spin_unlock_irqrestore(&dum_hcd->dum->lock, flags);
 	return rc;
@@ -1995,7 +1996,8 @@ static enum hrtimer_restart dummy_timer(struct hrtimer *t)
 		dum_hcd->udev = NULL;
 	} else if (dum_hcd->rh_state == DUMMY_RH_RUNNING) {
 		/* want a 1 msec delay here */
-		hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS), HRTIMER_MODE_REL);
+		hrtimer_start(&dum_hcd->timer, ns_to_ktime(DUMMY_TIMER_INT_NSECS),
+				HRTIMER_MODE_REL_SOFT);
 	}
 
 	spin_unlock_irqrestore(&dum->lock, flags);
@@ -2389,7 +2391,7 @@ static int dummy_bus_resume(struct usb_hcd *hcd)
 		dum_hcd->rh_state = DUMMY_RH_RUNNING;
 		set_link_state(dum_hcd);
 		if (!list_empty(&dum_hcd->urbp_list))
-			hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL);
+			hrtimer_start(&dum_hcd->timer, ns_to_ktime(0), HRTIMER_MODE_REL_SOFT);
 		hcd->state = HC_STATE_RUNNING;
 	}
 	spin_unlock_irq(&dum_hcd->dum->lock);
@@ -2467,7 +2469,7 @@ static DEVICE_ATTR_RO(urbs);
 
 static int dummy_start_ss(struct dummy_hcd *dum_hcd)
 {
-	hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
+	hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
 	dum_hcd->timer.function = dummy_timer;
 	dum_hcd->rh_state = DUMMY_RH_RUNNING;
 	dum_hcd->stream_en_ep = 0;
@@ -2497,7 +2499,7 @@ static int dummy_start(struct usb_hcd *hcd)
 		return dummy_start_ss(dum_hcd);
 
 	spin_lock_init(&dum_hcd->dum->lock);
-	hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
+	hrtimer_init(&dum_hcd->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_SOFT);
 	dum_hcd->timer.function = dummy_timer;
 	dum_hcd->rh_state = DUMMY_RH_RUNNING;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729022316.92219-1-andrey.konovalov%40linux.dev.
