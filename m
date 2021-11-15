Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWWBZCGAMGQEPPXCNKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AE843450092
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 09:56:58 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id g3-20020a056402424300b003e2981e1edbsf13465488edb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 00:56:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636966618; cv=pass;
        d=google.com; s=arc-20160816;
        b=SvUSOII6V8FiTD9Pkz37jQzX3sqvrA58kpW5Kd6AxeGIj6KMcgyv8R5tldpYhFqfCm
         NDE2KnPP6EMeyEKGFo76WTWc5uEI6d9Gh1p37TvZxUCz6bhbLWI5kK+OkUFxlScS6j4L
         FXisSSwWrO1+5FJgviLMm5lqG7y0VKDiorWyf2EVZQVG2ImEtWUKgqD155ORdwKEFlSd
         g6rS5uVmnyDbjocNoZqWGOAS87Y5EA61N9qpQIEjDDnG9qP2GMy8JjEpIxTJX2ctbbD1
         I/nmMRKfy4YTTe6WLagAAeFTkAqu9WAPSgyLOLYxXpwbAnB7NLmDJrDuNydjwI3Ms/RF
         ePoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=rjTZ13bk9ysmTbgRRfk2CrvwcA0BedC2dLfNo8X7fp4=;
        b=Ki/LrmEYTJKBaGtrlu9v+m8Gqaft8WS2JKztBk6s/gX+7SeYjb4oI51IsN/gspU/K4
         gn1iCi0p52btEmuRKFy2k2Z9O4Rm5ExHswdEtNMerxfdH3u1O8Se1kn1xTHOXH9qbrNB
         0XjB0TaL0kS441O3MzxVe9Oh2RoQTkgaICQ6u6vUpRfxhEYZusVmOTjHzfVgYtJI6wyH
         d1Ub2E++VqgAKGM9LdCUBquBhhDlzqAyDUTLFL4sNceHL+Kstz3A0mXlg1Bp5/VwfSse
         UN6jQvj+uLw7u/V928FSPiTKwR1w3A5Dj/hWmn6tOScvn3tK40OuCHdad+3bWPHuEYPS
         WEmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IBr/z4EK";
       spf=pass (google.com: domain of 32ccsyqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32CCSYQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rjTZ13bk9ysmTbgRRfk2CrvwcA0BedC2dLfNo8X7fp4=;
        b=QNEdeRhUO9xVNW6SdPMiIrPrgoW7wCe03FL/3r4WYrbMezAd/2AEbBdguA9zvBVUN/
         sEn15OEY/jHKPo5J4dXcFXD5xUVKjQw61jJ0GWV023VjBZYS3bFq3rtYJph97fruTCto
         KVutbAcMIaqzpnuIcH28/AKZcX32UjoIxxuYHHj1wvEPzQI6FB/rXqK+jyWzkM6+QeDH
         AvQx/k7BbM4RDxHqOZ3rMMQJWcjI9oCWyC84RLECz1PKANMZjh+gpDz7tp1lMrm/Ong4
         STB5sCotBCOcGvjC9ZE+VEBfBJ/9iMNlbMwpcuGza910IsqVXbX19L7p5SseZhScg2F1
         sH7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rjTZ13bk9ysmTbgRRfk2CrvwcA0BedC2dLfNo8X7fp4=;
        b=owsJh65LW3jtSAqfAXSo9c48SAHwmCRdQ6n14Fium6UVORC6rasHQgsagm9gDA+8h9
         P3uBihI3F/536MErK7YWEU59YfPqhSIctZmc0g0RWkGGogpa5/wfCMhT/RKw/83sffFh
         TrWf5++ZdJ0qVb7DeGKaVsCBMks1STYeXqWK4jspdMR2a9ljYXA+41IHvzWRIVSHYAUL
         7vgD3xDR0Yb5id8fgCtM6DvrynxlB5I+bGLClFteY8ZVqhLEPFGvqtk9zby4CHFYsGf9
         gcsk8IHmzPMtjUrqplJXUGQg6+EKJdf05t2Odscp1Q+kp460XBMDuomOI/QJauEekTvu
         Hn/w==
X-Gm-Message-State: AOAM531IRFIRPhH2PUKtgDaeeprhATKxZa4EM7Gttc6CbHen4ivVCV5C
	ISH9D+O7rFi4wxoNCutPaRI=
X-Google-Smtp-Source: ABdhPJxZn7nNppjvi08+yKsDk53ky2YcU32zjB4nSUV5+0hB+wWTDzwzpo5vpNgFT+h9bujeP3y5Jg==
X-Received: by 2002:a17:907:3e0c:: with SMTP id hp12mr46941459ejc.293.1636966618448;
        Mon, 15 Nov 2021 00:56:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d10:: with SMTP id gn16ls5262645ejc.5.gmail; Mon, 15
 Nov 2021 00:56:57 -0800 (PST)
X-Received: by 2002:a17:906:9f20:: with SMTP id fy32mr50281775ejc.459.1636966617494;
        Mon, 15 Nov 2021 00:56:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636966617; cv=none;
        d=google.com; s=arc-20160816;
        b=Rhw01jEJOdo+QeR4vF6Du0cut4Gnv20UBADKg6V6OFXazW/i8ZnPAv7wZGsPbvh7VT
         PWsEJKYt7iz/HafIdmdUYoqGLQdH2fHMmiCVzYeh1e+0gJpZdxCadA7RUVswA0GZG7a3
         iJuI+dejvueVBFMBFhvkhsOKMc3gvBNu5riXAkL3GybVUJIPq1H7Q8piqu2BJGojVH7Z
         N0P58qCVosIt7/hXOrwTtipMHtlLriFR2nDEp7S3eVda6aT2Qlj8VBBiiA/6DZ7p5Yy/
         l9hyRRKUnACj0OgR01A/y3V0oefQO7yvyAOasmPoxjk9HQSehwDAqlgsU7z0Ph7/Q5S0
         B8vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KoIGQMcPDNQgf+l0n0SpbMR7KXGkG+Y/GyFEGlGCO3o=;
        b=UQzLh1OMtM1Cz8iLa1rhFHBi51xQabd6j7/ZEifid93JS/3mcZtP7J9sYZUszz1CLB
         vKU5Ju0rHe3nGb3jStcqb1u261A17MPwzG4uHhOeo2UUTcxLLkiO7pq26ECU+8L8waTT
         8q8515ZQjLYpqLaoFfNJdxAJIypSZ9JIfg+m6nNpxTtBGOkMzufjTZclcvLENd5AFEPZ
         XWB9VHh6byy0ceLEJela8FfVIKSwjlQkLi2dpipkukV2bda1qd4+6Z/e15hcnVNlGiCH
         McdUbPs07Q4HKZ0Iivc3cMdbU//uheWljf7WP9rueKHGYPpdXeXxhS773cDprmlIZjEt
         FxkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IBr/z4EK";
       spf=pass (google.com: domain of 32ccsyqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32CCSYQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id fl21si1085865ejc.0.2021.11.15.00.56.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 00:56:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 32ccsyqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m18-20020a05600c3b1200b0033283ea5facso3215219wms.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 00:56:57 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6385:6bd0:4ede:d8c6])
 (user=elver job=sendgmr) by 2002:a05:600c:1d1b:: with SMTP id
 l27mr470410wms.1.1636966616454; Mon, 15 Nov 2021 00:56:56 -0800 (PST)
Date: Mon, 15 Nov 2021 09:56:30 +0100
Message-Id: <20211115085630.1756817-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc1.387.gb447b232ab-goog
Subject: [PATCH] panic: use error_report_end tracepoint on warnings
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Petr Mladek <pmladek@suse.com>, Luis Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>, 
	Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, John Ogness <john.ogness@linutronix.de>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Alexander Popov <alex.popov@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="IBr/z4EK";       spf=pass
 (google.com: domain of 32ccsyqukcxuxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32CCSYQUKCXUXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Introduce the error detector "warning" to the error_report event and use
the error_report_end tracepoint at the end of a warning report.

This allows in-kernel tests but also userspace to more easily determine
if a warning occurred without polling kernel logs.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/trace/events/error_report.h | 8 +++++---
 kernel/panic.c                      | 2 ++
 2 files changed, 7 insertions(+), 3 deletions(-)

diff --git a/include/trace/events/error_report.h b/include/trace/events/error_report.h
index 96f64bf218b2..ed0164f8e79c 100644
--- a/include/trace/events/error_report.h
+++ b/include/trace/events/error_report.h
@@ -17,14 +17,16 @@
 
 enum error_detector {
 	ERROR_DETECTOR_KFENCE,
-	ERROR_DETECTOR_KASAN
+	ERROR_DETECTOR_KASAN,
+	ERROR_DETECTOR_WARN
 };
 
 #endif /* __ERROR_REPORT_DECLARE_TRACE_ENUMS_ONCE_ONLY */
 
-#define error_detector_list	\
+#define error_detector_list			\
 	EM(ERROR_DETECTOR_KFENCE, "kfence")	\
-	EMe(ERROR_DETECTOR_KASAN, "kasan")
+	EM(ERROR_DETECTOR_KASAN, "kasan")	\
+	EMe(ERROR_DETECTOR_WARN, "warning")
 /* Always end the list with an EMe. */
 
 #undef EM
diff --git a/kernel/panic.c b/kernel/panic.c
index cefd7d82366f..8e299cae1615 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -32,6 +32,7 @@
 #include <linux/bug.h>
 #include <linux/ratelimit.h>
 #include <linux/debugfs.h>
+#include <trace/events/error_report.h>
 #include <asm/sections.h>
 
 #define PANIC_TIMER_STEP 100
@@ -609,6 +610,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	print_irqtrace_events(current);
 
 	print_oops_end_marker();
+	trace_error_report_end(ERROR_DETECTOR_WARN, (unsigned long)caller);
 
 	/* Just a warning, don't kill lockdep. */
 	add_taint(taint, LOCKDEP_STILL_OK);
-- 
2.34.0.rc1.387.gb447b232ab-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211115085630.1756817-1-elver%40google.com.
