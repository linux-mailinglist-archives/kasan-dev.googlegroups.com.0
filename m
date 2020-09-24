Return-Path: <kasan-dev+bncBDGPTM5BQUDRBIFVWD5QKGQE2GZW4LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 1380627677B
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:03:46 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id cp1sf1296676plb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:03:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920224; cv=pass;
        d=google.com; s=arc-20160816;
        b=IPBCIyrwWkcaF8B2SOLYu0nLWeHE4+ldUPYr6lDMKBXS6pek6Irw54Zcj4cUHyjf0B
         X+mLmnPhTsFSrkTTZdnSkaaD+IokYl0H9el4VACbYDdq0/gkCxn3KvGP/6pvpNNUKle7
         ThO5ndER2qSEPCk77dasw7CYOHprDXf58lDAi+lZJBQ2xOD7fg3Y+6j+7Ez3Kw/wt1RI
         /h+2Kd7kfnGwLTNRobXcShSRSuyUjKByS/yvkjAYtSJCKKpGTk0g44lLl8kNFbe/Z1jT
         jHFFlCUB9NTxCVqRCD0VlSrtLuJ/tT4j1hugPqaOPa+djdMyANHjxCOy8quVJA5abjmC
         zeog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4GZBVtYWRHRZiTlYNEljZuNxgnj4UkFNF7CXaDGvsCg=;
        b=mDUHKSY9tH6pvqO69gupBVog4i0dbNkzaFIwq7r7VvezTsIAwaYnE4Ji9u94zmAAIF
         /V3kpraWm5tuBtAltfFg93hSNUJWl3uVPYHEio2JjSV/mmZL+6sPXDO2Z4shgcdlaxqw
         Mekf0xLqzZJcQipTyIh+m9t7mIOSlWxILicIFUF5NNviFQHWHX+Jks0r8UxEgjidSheH
         ywos0k8OSmnJN4nXAKEPAdt7cOOX+o2CD5shLCoP6MAM+RBzq0M0XPVA5HC6ZSfSXMRz
         jvketSvGyahVURXV8Bw8/LN9pYgjK2zdGm75kurBnW6W30OG/mm+P3By4Wbhfg33pKI5
         IMLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="KvhTLfP/";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4GZBVtYWRHRZiTlYNEljZuNxgnj4UkFNF7CXaDGvsCg=;
        b=lDEY5vc4P6ajRcXi798J2zFDRrX6mdvukRpSUiPzmpAN2p9Ngv8rbfl2bp7/TBYwTg
         k53uWDgXd1Z6MBQaURTBm4ppUSsfKXKcUCktOlBM+rkx6kPDluyFzNWNlJFTrZrG7G7Z
         lThmQOaH+NlqGMndlDkBOmdMb9nkWEHFboeipUXuCZ+hUQ0NzEKi8VuqOU7bbWQ7TjBV
         oJGexn25h0AumouRq6iQMiuYorF724PCj6Sn139pC0CvM0KDr8Sr1GNR0aarHXZqKK7j
         KUUzgTlG+cNokWF0k6s35j7ipW4r/wsvHJd6LSaDzQM9il+soWfLRkj1uCbNqBXNZOOs
         OjPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4GZBVtYWRHRZiTlYNEljZuNxgnj4UkFNF7CXaDGvsCg=;
        b=QBdeqrSpJJfG+YKud1DmWyWcbYfkok0R7+7P4sEaQgm1vhjGS2UJal/8Losk6vVVAI
         L8ctPlUnHg+Iq2mC/OTp9iGDfd2HzLP+/98dtQvOIeamYeN23j7T5O+ZmaSeFXWUccTO
         p3NcX0NmKr1+iPI7YRKzLBAZr86S8n62KEHbPcZiaFg9U4rb5TU8N0n/8MA+quGSYEZo
         fyvYo4ABbA0wjCSDW+OI+5ew7tf1Fiikb94Mf4U4ljnvrDu1U6kFpgqotEQIUWlzxoCw
         aMVD2Op4RFHUyGD17sHhelAjt7YFVjoa992KIgnEPzAH1B3MnejATT98UWzA8aDZzAII
         lQ1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531H7g5vyKNKTjrtrF0RcBo/EcThbXeDJOyCsyHbi9x7kwaqLSKK
	dGdiqU+iDXuVss76IQbRSJI=
X-Google-Smtp-Source: ABdhPJwTX0ptxbZxdrz2TjJk36XqTJeWZ7OFLGQ/7l/tilUV2Kc1cPVxu68t4rZ30jKMG2vxHB8ByQ==
X-Received: by 2002:aa7:908b:0:b029:142:2501:34ee with SMTP id i11-20020aa7908b0000b0290142250134eemr2635809pfa.71.1600920224513;
        Wed, 23 Sep 2020 21:03:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4812:: with SMTP id kn18ls831708pjb.0.gmail; Wed, 23
 Sep 2020 21:03:44 -0700 (PDT)
X-Received: by 2002:a17:90a:ea08:: with SMTP id w8mr2287884pjy.124.1600920223972;
        Wed, 23 Sep 2020 21:03:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920223; cv=none;
        d=google.com; s=arc-20160816;
        b=BtXGuRXbGqTkAGxnADSlh33tXMpDcXlCGDeB1tsmR/v8TC8+N4rNpRwWAL9iia2Y30
         +72LNxqAQNgwD/opYbsMcsTkMTj2v32+xgbh/SyaAGeUB/dHUvwoY0c5B3LEtUTPQ+dG
         /3SzVZwqd+ZTWHyshzhgcAZ1kU2gLK9X9iMd9/FD0Hjt8RoOxXjCrVLocWBGUHOvffB/
         p9b/xPzMDGN5XGPG5Wc1McD9+akLRt0BS2LTm1nKQY/Cccqtsa/a73f5/WkzWNSz6scn
         MaIWzx4It8vgGn+syQ70L3uG8Bd5NUomRBlJPWAmb3KCIwQ1yIKoR30oxsZskk/vWzVf
         ltnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dMII3+0XheNBeDRCJOnd6NRZNf7iDHcFRVLV7dSXF+k=;
        b=FQsVtNX5cbbhYJsIdHf9w3JPIJVVZD7qWqP9dbAi2U++AKykYgxeG9iPVfyDj/UdRK
         MoUW3+1xIRy7g9DQWxJjAYykpSqykqfZQPfOBrT0BVsbNRfMwWbenyNxuiMQ4DhPD7FF
         BFvaxwJ5AWUUbFNv38H/yzxKjY6lmQt2DSUM+8rLhidk+i7cGKAww1RpFAPzEneqk/2s
         C12oPkDJ19w/KOF4jyXyP/Yk57HVJmx0d/jmRrHZxzfAroaHSVuGoVY6xMmnodDKE3bu
         jBkfe7CyDv4ZOdhe9Ac7yq1fEW6GuAVof4vVULFukDIgS/wetsUjHscPo35lFfhczkZe
         sKPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="KvhTLfP/";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id mm16si138577pjb.2.2020.09.23.21.03.43
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:03:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 031d0cc632804df7b22e8a729a49ec48-20200924
X-UUID: 031d0cc632804df7b22e8a729a49ec48-20200924
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1673301738; Thu, 24 Sep 2020 12:03:41 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:03:38 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:03:37 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner
	<tglx@linutronix.de>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 1/6] timer: kasan: record timer stack
Date: Thu, 24 Sep 2020 12:03:35 +0800
Message-ID: <20200924040335.30934-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="KvhTLfP/";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

When analyze use-after-free or double-free issue, recording the timer
stacks is helpful to preserve usage history which potentially gives
a hint about the affected code.

Record the most recent two timer init calls in KASAN which are printed
on failure in the KASAN report.

For timers it has turned out to be useful to record the stack trace
of the timer init call. Because if the UAF root cause is in timer init,
then user can see KASAN report to get where it is registered and find
out the root cause. It don't need to enable DEBUG_OBJECTS_TIMERS,
but they have a chance to find out the root cause.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Thomas Gleixner <tglx@linutronix.de>
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: John Stultz <john.stultz@linaro.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Stephen Boyd <sboyd@kernel.org>
---

v2:
- Thanks for Marco and Thomas suggestion.
- Remove unnecessary code and fix commit log
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack.

---
 kernel/time/timer.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/time/timer.c b/kernel/time/timer.c
index a16764b0116e..1ed8f8aca7f5 100644
--- a/kernel/time/timer.c
+++ b/kernel/time/timer.c
@@ -796,6 +796,9 @@ static void do_init_timer(struct timer_list *timer,
 	timer->function = func;
 	timer->flags = flags | raw_smp_processor_id();
 	lockdep_init_map(&timer->lockdep_map, name, key, 0);
+
+	/* record the timer stack in order to print it in KASAN report */
+	kasan_record_aux_stack(timer);
 }
 
 /**
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040335.30934-1-walter-zh.wu%40mediatek.com.
