Return-Path: <kasan-dev+bncBAABBWXQ323AMGQEIKYT44I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F1B4096ADE8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 03:31:07 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5334d43c562sf169804e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 18:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725413467; cv=pass;
        d=google.com; s=arc-20240605;
        b=DRGn/ktop6JeQJfzzCIqpNZVhnfhukhHPpq5l76K346Z3Hr7gKDpGoOd0/gkp+lBHw
         8djgrEITmHJF7wLlAr/gvcpU+WVcJAqKEDMzT/QSfW2j2cuCz42YhY2fR/uBipM7UIoG
         T5tNcqrjb5XPLW8Qv6Xei548wwFwjqYxn3NpStwPFdwguOaUNlzeQJOWSy7oP513WYoe
         Bg0MO3zfrNConD4z0HKbavmtXkxtUmGy7NzR5KU1yHQ4nrqfLvARy+960A7cK0kNYC1+
         gB0yOxyQCKwdpr+1AjtdCJZX9EsQrpz/zMZWIuTsbnWwCr28TcWd+wlwi3f1zmevi9iq
         TUDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=o1UR/FB+mkahZt959qbHCmkQBKEAOYkhD4QPQ13vT94=;
        fh=bdcAGRRGxez+U/uN/G3TDT0pIsFDH2ehfSYdsr5ha94=;
        b=kcmHH1mAH0PkRg4lUAEZG65izS9nTLSusg9GvBoRj5xmTX8xybRaKz+cpquN670VrD
         wvZcl+J7QmOp6m6At0reIrph9lTDIh9iSBgkLxyJ9tqLNoEywzZaCGGq39DgKlVjhQsp
         flZH6yU9nTz4d6/zyYfcTxxiATWXP8EPXBjK+DuMPs2lZREGvgTU1eV4NjF0XD3/pLW9
         cXNuOQa/s/iThJAcZpY82XT9mH63OTedVRrvU/LFh6lvH/b2hg3z96Nk9o+oT50mjgOh
         xic9/5RFx66GKiRrrGQxRhkwvQDfUYOBZ6N4DonCAzEqwLc2e72W0SGWzGqxRt38UzxI
         pu/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KUlzZgiJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725413467; x=1726018267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o1UR/FB+mkahZt959qbHCmkQBKEAOYkhD4QPQ13vT94=;
        b=AWBdtT7A6K8ivSIxGi06Zu3QzGhJlMUMclkTV10pR0+Wq+pJsb2HjHJiLBz8JTYi0V
         s2xkpArrR9XD+TmBkx6sBN7GMkrVaMmAENMVWz3f8bUhlJrdX5sIyrM1oKiaSApin4tj
         liMx1phCV5IxXPMIQpNODk3gyg9QEzc0ugH97LMAbEBitBtNRLrGBP4Lvje6E71OJTVe
         frA46Wc7oMLcIdXY/AwJlMMjuoWdlqKBzQnuVzP7toKsVToGnVaoS1r28veE+81EbJqf
         hiYV+5zJVXehLu7oKNVjAyEX69PgLgUzCvMxCeAxucexUwK5UWFwGEJuVT1EebTIg38M
         ADbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725413467; x=1726018267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o1UR/FB+mkahZt959qbHCmkQBKEAOYkhD4QPQ13vT94=;
        b=Cne35Ckw/bXNDmagj/dKdUFiAbypIlOMkj1CAo56+A09bekvgm7hsrhWzjzF7243YC
         XBL4kp4woT2PkSTX8lrrb/MDmMIoBIuhpB7o9F+1lyrKyT5YUNW3rdf8mmXzzDvPf8FD
         cv8XBZ1fQa5htrpcQ56ALNJ8rN7v5g96MEp6rXP+YG13ziTZ0Z4nESsTxpjFHaWRIJpr
         b22scuxBHlWdlzd06e284G5s+bCYmALJccOtI+jVqQXbXdkOYWqEUTu6TMalZUQHAt8U
         dJi8NLc006Wl4xcn5uUUYXWXe5kHCHSl/ucZQgnwR2UHE2OefTSgwB/jFE2GDP2sDlCd
         NZmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZIPNeRk0GEytvGZw4M6kaixL32fWo+F2F5bsOJ/hRU3MLTXOAMCvipQ1QeEbA05+RrW4QkA==@lfdr.de
X-Gm-Message-State: AOJu0YwL1oCEgBrFTe60G8Evj0WJ5lEFwBPkFm8Z3GX+2eJQ82e9hxkn
	oHPK2rK0ohulPJXipv+9MfTEUq0IgHZQqJXm21HTJ8tN9EKPxRn+
X-Google-Smtp-Source: AGHT+IFX9g5YiqGp4T7wL22Ybc7DWtFzC6dUC1q8imvslyedcLA/znIpeTxnx15vhkXSwBvcO/raCw==
X-Received: by 2002:a05:6512:108f:b0:52c:ad70:6feb with SMTP id 2adb3069b0e04-5356778bc21mr96163e87.20.1725413466411;
        Tue, 03 Sep 2024 18:31:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8f:b0:533:4886:850a with SMTP id
 2adb3069b0e04-5353d813255ls119427e87.2.-pod-prod-00-eu; Tue, 03 Sep 2024
 18:31:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUKtOXIIJwpvAnnu8hjhjcEhk8Y8VEMiI2QJ69jt7+DLNQqv7Rl6FTOMUCC9jznns4KNSXnv2HZJcw=@googlegroups.com
X-Received: by 2002:a05:6512:1110:b0:533:426a:d52f with SMTP id 2adb3069b0e04-5356778d5f2mr143625e87.11.1725413464440;
        Tue, 03 Sep 2024 18:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725413464; cv=none;
        d=google.com; s=arc-20240605;
        b=ISxKZBgr5Un9kl48++n1jeewMr+N/ONbupheS1dXqa0Bj6uhSzJL0AmaGPUnqKBOMy
         qIVO4avAKyv0Fziatx030078MzDcyLjFdsfciot7nHUpU8ziCP/t7RbWEp2tdrtp3KB9
         rBnDFrGmyzR7HEJtUzHAOxgeMDU+Czx13zw+42sjTLk1vc1ijldY3qYfXyb+j3U9ccLk
         D6zpwvRogyA5rZk8nMUyAcejOHmO2er72jMMgh+RL3gQYVMibeAONANoZhw1+SEHbMFx
         WMIEAoWJ2aOQm9xE/bmhDo96qTyc7DpttpRu6z0kKuch7yvMd5v1ZNrgoJvXlpxAQuQt
         NnFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=WL9bEn+qeDafnFmH2mu2935t12N8fCu85vsLBSg/BdU=;
        fh=Lr36PwTFHKduRAzN23dY3xi99YoABDbn2m0xoUZGH8M=;
        b=WqZbW9sb62acusZN2nygqTqhQrWqc3lSonGGPNAdVsdHKW4wUgM3JIDzrzV83bLJTl
         QJaoRIh2eNJN2t3HfOv9z6EgHcenEtNwUP50Tbbv0m6jGyj8m5lT5sXya8ePpsmyRXXj
         Ndssu9AR6U1l69RANJCI/YPiAQD52C6kcvP3fzm+yo240wv5kXfLIjEflWMEsKKRBMel
         C/Oh0dOQx8oMbDPIiFICU5AWtzW7QZjowlcqIRIWpx7c/rCA4SEP9x+auTJZYhH7HKc7
         TtTeWz13LEmUoDN3HLmiXUWs4fgtNubEh7RRGdySBtJw5lFJCbTLmVImAxIRaO/FTb1s
         wjFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KUlzZgiJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5354081d8ebsi250219e87.13.2024.09.03.18.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2024 18:31:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Alan Stern <stern@rowland.harvard.edu>,
	Marcello Sylvester Bauer <sylv@sylv.io>,
	linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com,
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com,
	syzbot+c793a7eca38803212c61@syzkaller.appspotmail.com,
	syzbot+1e6e0b916b211bee1bd6@syzkaller.appspotmail.com,
	kernel test robot <oliver.sang@intel.com>,
	stable@vger.kernel.org
Subject: [PATCH RESEND] usb: gadget: dummy_hcd: execute hrtimer callback in softirq context
Date: Wed,  4 Sep 2024 03:30:51 +0200
Message-Id: <20240904013051.4409-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KUlzZgiJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as
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
Reported-by: syzbot+c793a7eca38803212c61@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=c793a7eca38803212c61
Reported-by: syzbot+1e6e0b916b211bee1bd6@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=1e6e0b916b211bee1bd6
Reported-by: kernel test robot <oliver.sang@intel.com>
Closes: https://lore.kernel.org/oe-lkp/202406141323.413a90d2-lkp@intel.com
Fixes: a7f3813e589f ("usb: gadget: dummy_hcd: Switch to hrtimer transfer scheduler")
Cc: stable@vger.kernel.org
Acked-by: Marcello Sylvester Bauer <sylv@sylv.io>
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

No difference to v1 except a few more tags.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240904013051.4409-1-andrey.konovalov%40linux.dev.
