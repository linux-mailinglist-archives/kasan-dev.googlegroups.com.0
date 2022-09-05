Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVOV26MAMGQEF5SN6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 38EE75AD262
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:58 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id k6-20020a2e9206000000b00267a6d3f0e4sf2790584ljg.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380757; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5Ggk+4Q6wWMdxPgg+foYMd3L/vijysmfKjKHDXIOqwU0/sO8z+k+X5UQir2g/15Rd
         rvkOjmP4EpST9TGnXj44h+pXafRl589jjyop75xias+NTIUK4PC3xXjp28mno59qJtoV
         Zp56L797G5IzGMIBWppFqSRTRohR1YgU/LmkfcRW8mWEpNclyt70l6wliA6bqRAeB3iH
         HP4fadbVZqeVbA//RXjk37X7XAhENtsL0JwNFj8kpqjYSvNCisddKARPC5ZMJN6Px5A7
         ARYv/jgOF7jsHWj3IFj/XVS4HE8P1kl9aBLMtSYSseZtYMiXU/ybTWD7u0kkFVJZCSvv
         J9jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dBxEJenFzhBNAzC3ur6pUgqCP0mW7t27PxbvOpzP+tc=;
        b=HUkgOUNDHAppyNs353qtVViSOSyPdPeIaxXgprBlNYSRc6Q6AGVUO4TqoAUhhlrI+H
         KCuIR+4+TU8k/5AWC8fnXJaFNfOHiRbLMwHPZS+AD/Uze8l+KjqRLFBR1xeuc+xPbBut
         ef43EdVMCWuw6agxWwD08D/GHKypBmK27ASNmcxzJMGIm/zVj+SZVmh1hJORZQI2hOMH
         no0IY0lntM4Jz/uYuOTYGnUHM17vnAHtBUF/nvKz/0UuAX2NU6/CvRrNJLnwyTJUXNhq
         pQvBcpeTIV1C6utIC0DtjGoZ3CGisEYqVPXYd8ldfXTB9+/cNzu04jW1qMLYpVmJUckh
         T7Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xc6WWErx;
       spf=pass (google.com: domain of 30-ovywykcsache9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30-oVYwYKCSACHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=dBxEJenFzhBNAzC3ur6pUgqCP0mW7t27PxbvOpzP+tc=;
        b=frMpmKQYRXYTbv7AXscziMasFNtwZDlcpMigiiiEquW186oXHvrbzVj3oookUsY6PZ
         v8rFPhTFaWNpUuTsKBktdCXoQ3GcXEG0z/hAT4as4ZsnXu9cFYw7mAPvm/l0DrlF/KPD
         gAGkI0vyG55WDScyIzVZyeNqEmqnInW9SBOv8ilnchWOvfYSyWBsNPJIOhVl7AKYMP8o
         BAgFmkirfdMBXZZg+1lbxudV2sboNQltCueEfHX2G+96Qbkpco2pW+ymaAkZdFSmIvoo
         +uwrYsfS1whYBQcXF/lzmXG5tfYqeIPKe0Htsemsdu214O1uIsnU9HnB9z9U51Kpjlxm
         UMXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=dBxEJenFzhBNAzC3ur6pUgqCP0mW7t27PxbvOpzP+tc=;
        b=Guj1QQT1OqvcAefz78ViVjYg3Gbc0OJWhAqtfE2slEWOrUmUl9sNHAIyPxfeBfQTlW
         Lp3gazit5RX/X4LBPBPqfiC3LnvyHetm4gIJ/BGgpaOGY8i6rHm4l6aQzJ6e/GRcPTCh
         hmEqeVKaUFtE7jooHIaSD8xa9WFM8XX0skTl9eXd7jduqH5ko9PdL1LvihD0XiainGUD
         +/3SYZFPoWj2mNnh7frAZ0IBEPRHsZ/ueVzf8A56N4bWeJUCsLxX/PMPA4T0LkGyaXU8
         CKMtHmUvBO1qdlYlFmLzsUa9ennBm3fBoWe1GuLJuOtUnnIBZ34NPFN1jimJ46wPfwhm
         NUWQ==
X-Gm-Message-State: ACgBeo1l3jTcYpL6FEb2m5w+HulugT5NWP+Y/PiyBpHEja8SssWL+Lnf
	BXoOTcziawADn2SewKqVKyE=
X-Google-Smtp-Source: AA6agR7n6pYuLg6OXzSBxgEELrhFNE8h/pK0ngwTgx9mEoRQaRlLTrDb4sWFFN9FnSm203xPY8ql7Q==
X-Received: by 2002:a2e:940b:0:b0:268:fa1c:106f with SMTP id i11-20020a2e940b000000b00268fa1c106fmr3705401ljh.101.1662380757726;
        Mon, 05 Sep 2022 05:25:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls4746288lfo.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:55 -0700 (PDT)
X-Received: by 2002:a05:6512:220b:b0:494:ac99:dfb7 with SMTP id h11-20020a056512220b00b00494ac99dfb7mr4592454lfu.572.1662380755813;
        Mon, 05 Sep 2022 05:25:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380755; cv=none;
        d=google.com; s=arc-20160816;
        b=kvfFCEC1Y+x3FCpg/B1Xy/8d6M5W8dXoiYVfl1WcVp5hGY0ZoILsDpYYto3ck6E2Ml
         F6iOvrOBeSYmM4bfZMYnZAP9tcTJr/1FQknskb12k8a1qAgtVm4axKmdzH/PX/4mrPp2
         gkyfPBIl9c49FuWszJke64SBIDeqZiKPscJF8hQQox2i3gyrny8MtY3oRM9xWk5lRS09
         e9BdzkArKDFI7Iz0XKFK1337ckfXs0YNLOINqE8Flmxr3qyq15c6BSZXJNZe/J4Y+p1A
         IB6fMhsR+BagjS1aciRLh4xoMW5BDU9iZFoHnuf1E3PoZoMt1vweEwHF7ZBEvPs7ThNk
         PRkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZKRhstpgJFHnwQb7wa4PSp1fP2zpnAEklrA/+6U+C6A=;
        b=pODqWF8bG40NcLITivefv2qyH8ywVA3Hjul25dwSnwYuEao+ew+51gJkwCA1NWFj7Q
         ksp5AtHrPRDz2lKQd0m363hkEEKf06hvG8FjrrjjjS5O7KNZ/Py0oZeW1D3lf42SRe0A
         oIOb6rtytUDdQ5AvWMGG8c6Gvzrgs48Y/ZlwFszXXXYD7RZWxNOdzRes7x7cuhTOGNRg
         a8auaS2cmYR33+dwrt+rTwLWt9/Kry+iv+0Jk9bZRWdF++STKQ9d0a9BiRDTe40uu4Gh
         e6dSvpnBKhnAprsKv7zn+kR2UDUjldr1YcKKnD0d8m5m0MqS1jVQn0BLqVOH8MCtMWOJ
         iEnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xc6WWErx;
       spf=pass (google.com: domain of 30-ovywykcsache9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30-oVYwYKCSACHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n17-20020a05651203f100b00492e3b3fd98si367504lfq.8.2022.09.05.05.25.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30-ovywykcsache9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r11-20020a05640251cb00b004484ec7e3a4so5724583edd.8
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:55 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:b15:b0:741:8ae4:f79d with SMTP id
 h21-20020a1709070b1500b007418ae4f79dmr25370696ejl.247.1662380755352; Mon, 05
 Sep 2022 05:25:55 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:29 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-22-glider@google.com>
Subject: [PATCH v6 21/44] Input: libps2: mark data received in __ps2_command()
 as initialized
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xc6WWErx;       spf=pass
 (google.com: domain of 30-ovywykcsache9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30-oVYwYKCSACHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-22-glider%40google.com.
