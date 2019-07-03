Return-Path: <kasan-dev+bncBDEKVJM7XAHRB2VM6TUAKGQEPHT5HRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 404E75EDF1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 22:56:11 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id z10sf1559072wru.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 13:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562187371; cv=pass;
        d=google.com; s=arc-20160816;
        b=D6Dr1YiIpkhuxLP8CDBpMvrmMdx6PvEQdzHrAbovQP/aZvevttocCCe9OQ5Z9siqrY
         x/r/kj3MUJZRq5IZg+7SH2lx+ZzYm1Sxk6zE4ot2HIB80zFmr/M+K0HIDII2hzlTUqAR
         xdn7yASlmrZhQjMwO/t+OGoaQsVAIHGTuKQEUmiuPZCRRy+ZfR0HMGMB4IJCmWaN8+dy
         /6ezr00fkdWWMWrnXqkvjQru/zXr3dOd4EAtloi9FvVwGpVz/bnMN+eS7S/xjd3GLSaP
         aaP6s93fmIhLI/UQqd+cFT/G2U3NJvohuesptNe8t85nLFnHWUN9K3+D67HK/C/91ar0
         xZ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KQbL7H1Ba+d0fVhNqq3jJT6GbguCauh5LyDk3iBAeS4=;
        b=utVZpwwZW/iL3Qit6FSO8uDPuygrT2/nUBxols7/Tcwt11iarsyC3/OIJU48mRSJk/
         F2qMpVK9CGLmUaa28BAHAyeLbZ90JqnWc3cCnpx6gfPskFxwiueDa5uVVsBBycs4Fmu1
         6I4jDLOXCxnv2nZzTBQH7EJp25r7WRQO/Db8UmMKHPGLpWOmhILwEBlMGTUmNnmWF3K6
         b9ngIAdckNoSi062C+BjaK/SrotWu12dM/DvM86mijOLGGgdPF13eUTcJPeMn2pVDijb
         2NaQafqwWN2UJOgugqfJmTM6gD0txFqE+MavBzzSsY226gxbCS7fJrt2H5n9pjmH2J5m
         OHJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQbL7H1Ba+d0fVhNqq3jJT6GbguCauh5LyDk3iBAeS4=;
        b=bbtjQsewUYjsVq5CxWfGFbdF6PPYNoAuobskJjJBzzNEzvpDlXdtgX48+fqaq/A40h
         Hezv2skBomEfp9QfwrkPtXNp8qqGEIMiN8427g9AVeIpb1mIz9XbhZVS/EKVY8WJ73kp
         F337IOCF0PDRlAXl/6MddZedHJe2s+0mWyw6Q/jTAtZHNM1t81RDZimxWJG51EK6c8ds
         mhR3bBo74wRozMDxf8R+zgDicqdYL2xI6wbifNtQn8q8/1IZfoxeB1/UFcvp2Y7VRLry
         qZSTqwosnsOPDoAjshULfWbjkNX7UKv5iJRRZbpSUzGa1i+VWFCtRZCqD1gLD8Mz/38Q
         OcQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQbL7H1Ba+d0fVhNqq3jJT6GbguCauh5LyDk3iBAeS4=;
        b=lJkSChOPJ53Y1atLCulAacPzuOTvRrtxNvi9zfI8c4qtFr3dATCnwXQ0ujQjpjyI1t
         7W503xiOBL8xNuPS3XrlHG8dCJ5f5bS1uMyvP/z6jeI+FBBHd/g+PW4U0EeWNF4FTyDe
         VWxa2t7qJYdGI9jPQSk5aYs6ayuJ6WwnLtwUIRJB9gzxZfhy4o92HgOOBVjDK4hlVgTR
         ccUd925mBh7azBy6USxobrymDhOrAbiHkLo7xjSB43+HfKsNzNVaU6cps25EcgguHVuV
         iVRjrjOtP3vOTPx85KESCjia9VS1Bou0N4Gql37lw9LVdAwP/BLhb/8OpFV1+b8h5oTJ
         irRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXZA0wXJE9sjMy7J94+ZNPrNe4XQ9HZ5bGRqoaAePI00ifj0GLX
	nmc1GLzfE+fgkKnrTiH99qM=
X-Google-Smtp-Source: APXvYqyNU83fXwmtvUCy2GTD/XTQJd4aYZpm0aigw32QCB53+0fQmpEIBBXA+Lz1jNYhi5DNupn1tA==
X-Received: by 2002:a5d:5303:: with SMTP id e3mr29893269wrv.239.1562187371009;
        Wed, 03 Jul 2019 13:56:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c05a:: with SMTP id u26ls1054053wmc.4.canary-gmail; Wed,
 03 Jul 2019 13:56:10 -0700 (PDT)
X-Received: by 2002:a1c:f001:: with SMTP id a1mr9748714wmb.130.1562187370212;
        Wed, 03 Jul 2019 13:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562187370; cv=none;
        d=google.com; s=arc-20160816;
        b=LhzIsqvAPCTuBtRpCiDc8kTIXzlENAunK02R2GluI9BPZKIIEFVA37r545hLGa0O9s
         KY3M6G85Zkb7Su1SduPUFBaQN6QQerxe1z+Q2Xk5UYKnXru2qfy+jrFOWjZxuTqw3eho
         C58D7WZtsJiDNmRIMg5SbR2zPBDpoBYY8eaOVeelqMQGijYjjujjYpk0d92jhC/B1j0k
         tDvT/ePHxR5yL868O0Kq4FiYCT+6tCVeRm0Es0paJpm14dhX6VhILK1g2iRNrF3cnhIk
         JCscEEvYt4dm5j9XGypH8XSGLlR9Lwl5MQh9o4nlDpedXiZ+BE5dHb2e8iPGeDABIezy
         CPGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=OtpgfvAyzmDa6+kr7jhqubHmTmGSXxzmZ/gclzKmhEg=;
        b=smmIC5K6BRMEP4qSSl49D0erbgNWSYCU3Hmg8z4mklviiTIpWky59hO47SEBLvULEa
         bhe7cCYQ6+7IPxFsyMLVLGGNTXjXoqLUYacPEPhRmb6k+JVSj80XUl5qyrDk6ulVdqew
         SE6/+SQ2Pxze7TfvrZpdRgGq9NoQr35jFgXarqJQLqf2+ewK4M9Lsjl5OQwzYPsrtR9x
         JN7wDga3EZlYZHIDmz23qI0UpuqUN4hG5NH5jlDcYZAHwUWikvGEQeOF/KdOM6klJryf
         HvbnoI8l0zKrrvIu0CEK4y06HO1CFJN3PJiSZzSAbnWT40StBiEDbPksu1QzewuhMLpz
         nM9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id a1si336327wmb.2.2019.07.03.13.56.10
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 13:56:10 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue010 [212.227.15.129]) with ESMTPA (Nemesis) id
 1MqbDs-1iMWxP2do8-00masw; Wed, 03 Jul 2019 22:56:03 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Abbott Liu <liuwenliang@huawei.com>,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	Linus Walleij <linus.walleij@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	Michal Marek <michal.lkml@markovi.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will@kernel.org>,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH 2/3] kasan: disable CONFIG_KASAN_STACK with clang on arm32
Date: Wed,  3 Jul 2019 22:54:37 +0200
Message-Id: <20190703205527.955320-2-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
In-Reply-To: <20190703205527.955320-1-arnd@arndb.de>
References: <20190703205527.955320-1-arnd@arndb.de>
MIME-Version: 1.0
X-Provags-ID: V03:K1:dVu6TB6bK7PiXC0nWCBWTtH4+VmEpXav81wxunH7qxb9O8LK6xY
 9t1OBqgcoNKISokDJOGEmpsK9Olw4WiYxv3R4Yk0VHCPHCwbE5CfGGDvCGKORzYaTcZzpMZ
 m0fJ4OWUu8fhsgmIFep0j6SXmG5L3NTwAgbpxGDx8Qj04BISYNu2I01zggQ4J9AyAUBAt5n
 camESeoPyJjNiAUdUlgtA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:BtQ+/a+4hxk=:BXsO/jIoni0w1uZ5xMb/V6
 h3BmSvC14FIsrbv1u2lvwtgR132tDDF864k1Mm0/o1613vabZUA4IFS/P8E4jRRI6wzptV5lM
 jniEHTkB7qHeV/3lCntpeY7GYB4gr9Vvv+AKKRatXz3x21fZBGm2/fGSYXAXY+ZYcmSlQRb0Z
 3uc+P/LLZG12LdSV4N+0Jdl/ijlnTXia0VndfpbgkK0UMbzs9GaMSjIuFE72esecJiyh9QXlC
 jNr2Bequ/b5BgqDk6YfU+QnZsfElwGyaURabVnt6B5C4Ohxqk07JXMFYf1RDOphcRy1RG3a7g
 cX1kSgnBkWa6c7lXaA5Hp4HJ+c0RNNy3WS5G15hdnR29brBeN7LGOMTBv+bUvZj2fKB9A8rcd
 xDU4aHuOfToN3Mi0jKRBJbkqfK4pL2GQiLvrctVa9OboD57iyUbUJJQxSc64DPWyyv/TwAWg+
 4rlCQYskxhnYiA1upHe0T38dZpE4V+pDZ9UUdpPEEC+JaKy0Z7hPP3gDh8UQUk7wDeMlx43Ma
 Nj2f2RvuW0zBufN7CCC1gzXZZ7yj6LKcva/a4KeZ+T9LAHp/QTc4vBkJmaBeQePNHF7pDF9ty
 lgByqBiJ5vNeyY0IYOTYOX5SjHBdj73WL+AOjE6+yMAAfu05z4cLAPM2ewhkYRfsv/UNbfGFL
 1jdoMMETbefmQEsOxl2/ok8E/gLyIPPUwGrnjqGFE8jZCT2/J0FOdGzP9k7kfPWx7NIPnmgMn
 vIN90lJ0ZDhmHtW8bJnYoKFXqd3tUJdj5FcRRA==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

The CONFIG_KASAN_STACK symbol tells us whether we should be using the
asan-stack=1 parameter. On clang-8, this causes explosive kernel stack
frame growth, so it is currently disabled, hopefully to be turned back
on when a future clang version is fixed. Examples include

drivers/media/dvb-frontends/mb86a20s.c:1942:12: error: stack frame size of 4128 bytes in function
drivers/net/wireless/atmel/atmel.c:1307:5: error: stack frame size of 4928 bytes in function 'atmel_open'
drivers/gpu/drm/nouveau/nvkm/subdev/fb/ramgk104.c:1521:1: error: stack frame size of 5440 bytes in function
drivers/media/i2c/mt9t112.c:670:12: error: stack frame size of 9344 bytes in function 'mt9t112_init_camera'
drivers/video/fbdev/omap2/omapfb/displays/panel-tpo-td028ttec1.c:185:12: error: stack frame size of 10048 bytes

For the 32-bit ARM build, the logic I introduced earlier does
not work because $(CFLAGS_KASAN_SHADOW) is empty, and we don't add
those flags.

Moving the asan-stack= parameter down fixes this. No idea of any
of the other parameters should also be moved though.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 scripts/Makefile.kasan | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 6410bd22fe38..fc57fcf49722 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -26,10 +26,11 @@ else
 	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
 	 $(call cc-param,asan-globals=1) \
 	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
 	 $(call cc-param,asan-instrument-allocas=1)
 endif
 
+CFLAGS_KASAN += $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK))
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190703205527.955320-2-arnd%40arndb.de.
For more options, visit https://groups.google.com/d/optout.
