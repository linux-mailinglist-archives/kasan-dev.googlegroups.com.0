Return-Path: <kasan-dev+bncBDY7XDHKR4OBBAGWXSDAMGQECN5THGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id EB1993ADE32
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:48:17 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id 5-20020ac859450000b029024ba4a903ccsf1201872qtz.6
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:48:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624189696; cv=pass;
        d=google.com; s=arc-20160816;
        b=ob9pHjTNZCggVcplbzhbQJqUrYcDjL5sfy0meqAyV+4LvBhMc5+e0XsLoOXxjl1vsC
         KBdHypQQzXnPUDWORon7lh4+fkq1ZW6W/9SxQYJfERqbFrISk+FX70yEI10cgsAJNfTy
         0fMiL14MfVM4Og00JxpiSRiXV9CE0u00E6RMMIIYqigELEREA2jJfQgRxkeVQtyxkYhu
         dvn27+2aEsDIR++sVHku7qKqYVtmUvjjgYUyItBdZA1wiiWEHRtUXxc3GkGeJKzWHxOk
         wbASASFuykZDP/bBH2bsKF9USwQ4Qw//aPQj/tykOrRXX/+hlLK5GgsQLzRdC/9mk0kn
         ZSIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1xJxAq+f5JTDZNg60ZzdeeS3i4DTtPs+/GUpx+/2xes=;
        b=oaMaHmu5nQ8c61W5NBcApunpp1AtkGjAoW7MKvziHytJmotqg1y6vZNic3L3XCmvEg
         2Lkt/f1UYhksohQeILAPEJoOEU/rg6JPXd3HpOqLVonYQF0W/I/X21I6bNCWtH5fXIEt
         45cQmHC/Jsv7Oz0JEgAmtHcqpa76UEM1/zr6VjnlJ+bQjOo7xy9P5uxiXmLMUwVWH9dw
         wCYH8Lgdg7FnK5tU6SMzRtpJLfCvH/c4T4xU5pOhM0AZRJss5t5vjz8u8ZSH+osbzDKI
         5CKIbo47zFeK8OAsnYDC02BK/RlAw8PbH/gAMejMDRUqVfR95gdzrkwYzwkEG7D6c1DF
         Ne0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1xJxAq+f5JTDZNg60ZzdeeS3i4DTtPs+/GUpx+/2xes=;
        b=DSASWSFM0EEOyX3c3TrA3EXY/N9B5H17Du47DYRnK8YjW5aNROT0Zo5U5oVvUG75JU
         ADWJvNeZHvdyy7jZbvo/pR/Oiz8cUScEEUGP4k9BI5XjBCrra/jWtLxYDJ2DugC0zuh5
         DBA58ezUptKfQBppABzF0NjyhcMnfzh4KTo/60J25mkTtzA+npdAQWDQxtpwgRSE0DoT
         DnGzqXNS/9iWEJz/yE94MqMHBSm6Sp3qg2d4nwOzszEzbQXg7UmjAQd/ZjulNbHkHsN4
         UKe9aYYhDOtjUZRmxAylLd+En1Ukm5ZcLF/qE4/3Y8yLqlgf4C7XDLGhgSLYPmaxAJcu
         0TrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1xJxAq+f5JTDZNg60ZzdeeS3i4DTtPs+/GUpx+/2xes=;
        b=gSQV0J9Tvm4gqiX0B5xVUD57O/dNGo66vpn9/VB6Ii4WuVclUuSsMMht6KE5BFymKh
         Ixn1oTIDCoVRTPFI2pfY3FbjEdt2RYfNTqk5spf/edA6nRDsFZgcBwOrHF6D7y5Io+VQ
         DA20KLofyk6EQNmJUe+Z5JD2YBRPDYluObVDAaxaYg1402WTmgLMOevYj9lW/YdqouAa
         HOjfXM+dH8YMFXqg31kLQJ0FTxlZwJM1UXpekKXT2RgDTYZ/CSdK/Z6kaG7BO27vaWn4
         s5d6eHhrSPL2gL4/+3QTqcY/+Kd6BJHRP9RL3WNdtx+4WYnl2KkGiGVZXjyPCav50s/l
         gutg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lhplEA0CMa6VpDpqwVE+dCtYpUfceMTF7oF3lJwcTE2EVgZr+
	BQbCOz8KmTaUZ3lZwzaxU7I=
X-Google-Smtp-Source: ABdhPJyu2W1ga7wa0bkFZCP0WNMJKnRcn9DqfAHOyw0qW/VvGXjJ5BPrVsIIVmJ/nw7myskcIVogkA==
X-Received: by 2002:a25:b225:: with SMTP id i37mr24355287ybj.120.1624189696703;
        Sun, 20 Jun 2021 04:48:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:497:: with SMTP id 145ls7589107ybe.11.gmail; Sun, 20 Jun
 2021 04:48:16 -0700 (PDT)
X-Received: by 2002:a25:aae2:: with SMTP id t89mr26100357ybi.302.1624189696285;
        Sun, 20 Jun 2021 04:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624189696; cv=none;
        d=google.com; s=arc-20160816;
        b=gk3B2KBad/7LGs2GMaGA2jC3fHu2uzk+Uxk9FIbh85KWhkOHAz043jFJ/v7RFHeXMI
         0CgIBCoXrkvMEkkPAm/EL0TxmpIlox3eym+hsZQ88NPcISw3B5VoeBnpJkKCLkga18Jj
         LZiHNrz+Q6DIxQmvlgsNnG6c813/0MbpbYR5UW3E50aIikLaKUhS4EiRRr9pr5Ms1HWx
         g2nxA+qPB6X7VluwtzePLiwlkOl8NO6ixswYC0SuY81BfLjeY7My9R66xSGch2ZpkFmv
         W8vz3ogjTZbXfcB/gb1YcMLg71OXouE+8fGgto+b56024uk94Rr+LV2v4PeV+smvTjRt
         IUyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=rz2InlAbffT/WZtCvFC84HB+WD0ok7M/gTk6Q3JWz1k=;
        b=Us4adSMVNf1OKMnbSdQgml+jnsKxJFWlRPWhWxw0aNVhAiD0DpWl6T40hixLqV1YS4
         YBJF/UfEPb4EyPFCGSg1h+NdN9kK13L4gsy36qAYIJcXah8HLRv/xW3k1y9XNyWTTvG1
         fUgRUc39KQg/FNENwj129Nb9d3bjMVyh7VPxa8u9gVtn48i7htu1yOiDxqkSJLrZyjA1
         Lrw9sL/ID4W4F0dO2g52ST3xY1nvcUKI0yyNZib0IHMPUiA4WWuSPUrPSZeWkgJVrOIq
         5w7CoJVaMSxWbzKKgpJObIJw1IJoN3waDVzZrNPGJeQijvo4hZ5Nb7yT1rzmvbY2Pn5v
         Zbsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id o78si536104yba.2.2021.06.20.04.48.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4ad91dac93454e12a7fff2379ad760e2-20210620
X-UUID: 4ad91dac93454e12a7fff2379ad760e2-20210620
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1014899775; Sun, 20 Jun 2021 19:48:12 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 20 Jun 2021 19:48:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 20 Jun 2021 19:48:11 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 3/3] kasan: add memory corruption identification support for hardware tag-based mode
Date: Sun, 20 Jun 2021 19:47:56 +0800
Message-ID: <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

Add memory corruption identification support for hardware tag-based
mode. We store one old free pointer tag and free backtrace.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/Kconfig.kasan | 2 +-
 mm/kasan/kasan.h  | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 6f5d48832139..2cc25792bc2f 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -157,7 +157,7 @@ config KASAN_STACK
 
 config KASAN_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-	depends on KASAN_SW_TAGS
+	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
 	help
 	  This option enables best-effort identification of bug type
 	  (use-after-free or out-of-bounds) at the cost of increased
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b0fc9a1eb7e3..d6f982b8a84e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210620114756.31304-4-Kuan-Ying.Lee%40mediatek.com.
