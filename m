Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPX6RSMQMGQEBVS755I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FC815B9E15
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:35 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf5624688ljj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254335; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5JDpBnP/0C4eyWZQgzBC5VdlfMElv8DnI6AEdftTyo/Rlsg+UyDt8m76+rmwKK44s
         lq7zVqRN37OOsoFxVxRoGlpBMEU6cNYQMDk2TeTbe3+azlzeOkVWPXnEkMB/ZzH7blSt
         bng40WoEi0Fz1QmuRxL+nb72WtBT+1Fr/v6CHBHHzbuhxVJBwGt6eTmXOOLDw48IzXc6
         /jhLhNbnTgAzTlvNdvcy8leBUcsK1MwSYnkyWuvdc44syL+Vfy11gpJpHHLurJxWCDTy
         xMaiqOTP5vV9AS0ziLEvqyLE/GMcDkSoeQiJ0Kcbk/S/WCUXnX97s6zZmLKdZXhZqnNV
         vTvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Zs+4LaXZefoKgKMWmeqxJ7T63PAC0+TumMwiNjf6cDY=;
        b=m0mvK+r3Uywint8CLIcCWvz4ZOc46Zgqz1rQSM3kC3IkVIqxqMGylxE+6MwKMXLro6
         CdtXb90tU5JduVMGiL84tcZ8CCbgnavpdIoBVqfNloKfmoZZaE9EKhbeITayfAWBT59n
         W50tVfCNmes9q4L42Zcc7WLJtuuNWwKroLkizq+Rq2fWR7/F9N5EvfLx6Npi39+lZNgV
         xxFw1BdSoeNogKed51YsCMooYs+HTJlnQMutxHt58j9k8EgsjWanA3FAwdvcsfY/BGQo
         vJ6jGbSjXuDPDs6qUS+lvtVzVRFfu6dP7ygsHHT4zSlGfe/IDxR5GitIa6CnSJtOE2+f
         jHSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ThD5yyzH;
       spf=pass (google.com: domain of 3pt8jywykcwgmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3PT8jYwYKCWgMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Zs+4LaXZefoKgKMWmeqxJ7T63PAC0+TumMwiNjf6cDY=;
        b=WHnHcKlbR7wMSEU3oaucwOwzhxCb2V8zg9iNm2yrOg7XyjmI9lF/OETnTUcB6xzq/Y
         tV8KAkVv2HvPCidGTfDcfpzrD6U5kRH/vv2vqkJd2pQeCunxNKSWbS2Pnyc7iuYeyN+/
         hvX36kXqs5xqpa8iIF5mEl6jYczgShDPW7umPQcG7JcIGLe48/qxNtjljerWTVCmpxX+
         7mKAYQMP1/WPrOm2Ih2Q5Wow1ktkVJkOvsT/Ka2hXx8dss392wT0q9Hj/+GZDnOivbQp
         uqeLvlPL8Mdx0KrywlLE1Cd3Ku5Mfenw2r0n1WiDg5yfgDSNVkH3dtW1AfprWMIJsYt2
         nEAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Zs+4LaXZefoKgKMWmeqxJ7T63PAC0+TumMwiNjf6cDY=;
        b=Uz/TsF+ykaOSJ0GSuYLkl9Tu9tSteTLJdhYj1gcLUjRkoQ8yYro/TW+ElsYzme3M7p
         GEySSQaBU4P04cxM0whlqKB/CIXb+Ql2AqSNg1UWNPLBwwyYdQUHWmtiXYORHIrHriXE
         OIBcv85IvlRFlWAno0NtJveh/8dpw98vJXf9xVhElZBdOEBmwvkIEU49P34S7TE3oHAs
         O2vB0D7UO3ZYzWnPB1NNpL+uyzIBd8Y7zyBKaf3BAQB7YW3UJqZYDG5t2iixAnkPaETh
         GMZDEicbPr4OAq9Q9kqFUeM0eG1fe8IRi+h+VuJPJodDqpBSCq1w9QLtpdK30qk+OsYR
         d/7A==
X-Gm-Message-State: ACrzQf0Tq3ABYUoZdoIHVvQoVWtl4gpxTRzdaTuCn5dMhgiSglN8saVi
	1GbR79FC9KsS3D4Zry8uRDo=
X-Google-Smtp-Source: AMsMyM7NwjgontB3rmrhAjIlcV63T5R7/DVaFH/n/PVO2KndEy4y1SIGVee/leKmW6G9jaKLPMkFGQ==
X-Received: by 2002:a2e:3809:0:b0:26b:e124:4d43 with SMTP id f9-20020a2e3809000000b0026be1244d43mr60818lja.398.1663254335077;
        Thu, 15 Sep 2022 08:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:210e:b0:48b:2227:7787 with SMTP id
 q14-20020a056512210e00b0048b22277787ls1228896lfr.3.-pod-prod-gmail; Thu, 15
 Sep 2022 08:05:33 -0700 (PDT)
X-Received: by 2002:a05:6512:2201:b0:492:f874:39fa with SMTP id h1-20020a056512220100b00492f87439famr105367lfu.365.1663254333728;
        Thu, 15 Sep 2022 08:05:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254333; cv=none;
        d=google.com; s=arc-20160816;
        b=WygXs9JP1w/ovuVcxsaTd5vFfsyC3axk5dR12u9wYcVJpeHdc7nEtAHnK5DZI5PpcL
         dXClaaObBQ/YCCVQ4oi0rK4DTGGfj4uxksrgznWqEZCDawXaoxP3inwUx0oetzw+pB7+
         CQrAEpvDEGAxOUcPhIo9aUjxxyQYzDN5gapJHvu2kd9G8A7M8yXcLF/z/C+I7q2MD0eZ
         4TbF6kBF6b0mgRHvj4LQOhgbYAjm5BOjqrMUpbe/q9cemUBBCS7fH1gMw2+FeZoCcpno
         e2AY9nqSHo8a7rZeAH1TJ21viKTu1Nng1vsADVq4njk8tzYFClkWvopIKmzl545mKgcI
         jx5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZKRhstpgJFHnwQb7wa4PSp1fP2zpnAEklrA/+6U+C6A=;
        b=eZ1tgKyPVyCDi7ydAD/lO1JjnRANE7GX+rcj6xRDVNeWdws0YgaRvqaEAsZAFxG4j9
         nrrQ9yHl7vIF54FrUYBj2iXCM/83dEi0Zf10kqwb/yFmDkJ2kmdx1VGdTM8yBGQGsUmX
         aYB69ERLAXuvOSq5EMSd0FBa96ZiV3y6HKFCSCZAklWUnYZlzSaYimvAH+snYzO3IRuY
         1j7l9yaSWYHO6e3yTIIMOhVQcylZRM2Hk7nPmZryoCo1hIQtl9xAPuJH+39W9KdJ580O
         JPxpWiTwynTHSQYquLHJQqYgg5s/xPoFA1miaGypzbM/XGODz42kaqq8ZPNLnKpkkdGN
         KfHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ThD5yyzH;
       spf=pass (google.com: domain of 3pt8jywykcwgmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3PT8jYwYKCWgMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 14-20020a2eb94e000000b0026bea510aadsi505975ljs.3.2022.09.15.08.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pt8jywykcwgmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x5-20020a05640226c500b00451ec193793so8530168edd.16
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:3509:b0:452:20c7:5a95 with SMTP id
 b9-20020a056402350900b0045220c75a95mr237534edd.427.1663254333337; Thu, 15 Sep
 2022 08:05:33 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:54 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-21-glider@google.com>
Subject: [PATCH v7 20/43] Input: libps2: mark data received in __ps2_command()
 as initialized
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ThD5yyzH;       spf=pass
 (google.com: domain of 3pt8jywykcwgmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3PT8jYwYKCWgMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN does not know that the device initializes certain bytes in
ps2dev->cmdbuf. Call kmsan_unpoison_memory() to explicitly mark them as
initialized.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I2d26f6baa45271d37320d3f4a528c39cb7e545f0
---
 drivers/input/serio/libps2.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/drivers/input/serio/libps2.c b/drivers/input/serio/libps2.c
index 250e213cc80c6..3e19344eda93c 100644
--- a/drivers/input/serio/libps2.c
+++ b/drivers/input/serio/libps2.c
@@ -12,6 +12,7 @@
 #include <linux/sched.h>
 #include <linux/interrupt.h>
 #include <linux/input.h>
+#include <linux/kmsan-checks.h>
 #include <linux/serio.h>
 #include <linux/i8042.h>
 #include <linux/libps2.h>
@@ -294,9 +295,11 @@ int __ps2_command(struct ps2dev *ps2dev, u8 *param, unsigned int command)
 
 	serio_pause_rx(ps2dev->serio);
 
-	if (param)
+	if (param) {
 		for (i = 0; i < receive; i++)
 			param[i] = ps2dev->cmdbuf[(receive - 1) - i];
+		kmsan_unpoison_memory(param, receive);
+	}
 
 	if (ps2dev->cmdcnt &&
 	    (command != PS2_CMD_RESET_BAT || ps2dev->cmdcnt != 1)) {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-21-glider%40google.com.
