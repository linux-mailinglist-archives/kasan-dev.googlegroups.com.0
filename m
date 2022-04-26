Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRODUCJQMGQE763N66Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 514A7510407
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:58 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id c11-20020a056512104b00b00471f86be758sf4029237lfb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991558; cv=pass;
        d=google.com; s=arc-20160816;
        b=vj1DvYglCKY8tHG/7psmeLkm8hZRxwjn93NrQku9esRLBtlIOUzhoxMPclf1Jj0nLa
         hV/Y3+xs3vKUKEIOYFDJQwapDge4GhXYyD/qewppQjphCUg4xm1BXnVQEpdNVgu5/YUp
         KBZ8GdpLzdXFOzOuVzOEdXOIkjvhBFeSRHNBBS15jM+vDKrS7N7BPKWpiuDt3XLNc/AQ
         sF1Qr8Xv5M+xm8DY+IKJdxln+mL1obx+qVQYY0dhwpYQaqquZ0ZotcEUjdZ9ETQ07bo1
         Nj0VlTxLjmYpe7jm93vxttoEL8e0p+sF+dx2PuR1Mg4WISvo6I2j6SdlwtKWROFz0IFv
         n6+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=uNlH8kvmRz84voOiCPtA89gqs55X/Rxgzh2M4FUss7g=;
        b=mchDhg1FuXHL+4TVwH7jo2mgVpEn/mGCVvM22ncJsWi9VYjhLot5xnOXIiLckL57PO
         WKJaPbEF9wqtrOLhlh8zjg71MrGW7GeTRWYRYq3SFPLUAR5sPx3lcbUQeOj3t547ZlGa
         mEmN9DfRPnyY46aOj48etly/MhcO12+YTLjSA2tTJWi0oP9mVIJbdeq2xNMnHpqg4YYd
         dgdrFL/wzZvOWp+V2zoayBB4h49IKOVOGGqL1W9EyxownSA7Jh34LCMJcKWvk1mKDUF9
         GurWm9mhElfrbLiFn+b+Kvcb1cwliT+880ac2o4X+FR/WDfSH+g0tbaT4pLS33RXlOb9
         jiTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XHfBp7Cl;
       spf=pass (google.com: domain of 3xcfoygykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3xCFoYgYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uNlH8kvmRz84voOiCPtA89gqs55X/Rxgzh2M4FUss7g=;
        b=CSgcYPktcQAhArPbOs+ma8k4iyinT9aSX5TaUpkq9OCwQLdzLljLjwG0dv/jrLJDet
         mw9dfpfXrerRFZizvPNyTqbLbmbi9WvMP5ZfWtOoy3CJxLrMom38UoEjxJX2v/Nbfn2R
         yd+2Wc6oTMYZkylfTfmUOdCcgJT6WEthyM4YiYBqaXAjwqZkv0NEDaolr8jSjbzhTvZ8
         MrkF3MBnpZvz8KeCwfi+rICN3cTFttGtOv0Yg7TWLJGPTAZdZj0w3z4J/+7O8W7oWn1M
         62c6WCTpUpEgh5WnGo7FP8wk9uNuo/WXMzeQavBW4PvfJFDlTNoIOfI3hUZrkowQQaEY
         t/Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uNlH8kvmRz84voOiCPtA89gqs55X/Rxgzh2M4FUss7g=;
        b=3PBgADwoKnwodrSvCCeylZ7IJ+Mb5tURPMZpK4PcG7DVpn7wGK3MSBj51UEtlRQtcg
         nyiZI/TqOJUFK1IXPyRWseNkRHi4uX/Wl8BsovOmssgxpr/UXwn8ezWFOI48favc1f5W
         qKYhbhz7meXaNV/tZffj5ZCJM6gfLHoBAhkuDwxRk1Aqce7FAdbXx5EvIkt3RjCOXAHo
         R/Z1kLBtk3WyQv4mJi04hI45HriJgnqJrLciyKqqcn6u/zLQIAUNKEiV+VttWo1J+4XI
         kfc2NNwiU0Prn5DVxRIEyYvAzpAkDfv9ewXg+mptyUAn02IFMN/g73q1hpfRYd83DQP8
         X0uA==
X-Gm-Message-State: AOAM5306kl/EmAq5xKQ0Um4nxBBmpOlef4zxaRAm8nngytHNgggh6Shh
	ckCnmLfx0vqoeMRw4XrL9o4=
X-Google-Smtp-Source: ABdhPJwf6OMDtZO/CMKiptqD6OKjyv7C7AEN1X4GzjV7ov/T83WS1QYw+pqXhnk4YV5CAnqVY3pjEg==
X-Received: by 2002:a2e:8798:0:b0:24f:12ec:5268 with SMTP id n24-20020a2e8798000000b0024f12ec5268mr6138556lji.367.1650991557813;
        Tue, 26 Apr 2022 09:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2082835lfb.1.gmail; Tue, 26 Apr 2022
 09:45:56 -0700 (PDT)
X-Received: by 2002:a05:6512:304a:b0:472:d34:dbdf with SMTP id b10-20020a056512304a00b004720d34dbdfmr6405010lfb.554.1650991556786;
        Tue, 26 Apr 2022 09:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991556; cv=none;
        d=google.com; s=arc-20160816;
        b=b+04WHiIGwFdS1KB/Dt22LB+Fewp5jPmyPfgBOldwIv6YmLDJzGClQA9tPjQSsbOm3
         3Mam44gYWY2GoKk9Oi6knVzmsgsC2Zoih+8wrFYKtJGueagSWFXVpffvigT4/PD0yiD6
         FWgnuwNeZEo983Ry2kX/Ej401k7c+yh9jN2YY0wvtDhh1qzTOMV1XUURCxHV3QguxBEu
         g+xDwNYCSzgg+kJMj0j1NwEIsJd7zaK4UMCVqxaF6uiuxpqG5hkFGkI4y0fvToeiPcEr
         kybJZOZkARtfpxW/vlOSe1uE3622le4IH3nexmmF42RfCNMI3BuHezYUpqqETPFH3Tlp
         Anmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Fx98fFr6n4NVKGBzav2AZaWX3VRzhlrRB+7m3pCHiSE=;
        b=Hb3lRbgbVxU4ZFz3uVE28qBRZ2nHiayy8AgNK/13CU/atdU3BR6hCQOn+vI2fTHCn6
         S/HSzZ7Kg3etxyQUduRelGKQp74Vx8o4cZOn/PrVcaXAMqW0lr0Em9PWnpw/EhISZDiZ
         T0NrjkVsqfVEdVSCyWFl/S8Q1ZiIaVGIPI1oJwFzBQaSOgbuo+4iYBV0al3ff6Ko7IiU
         WcvF/Qt39Xtl5EnPfCkwp9wEQzelc/K+KuY0nieI+PoxqChj0PFR8UJlYEXVW+T4H+vC
         HGYm2rbt/hwBlEiyC3TEv1ZHVy9JE2Y9neHEiAyA6SJkk0FaJyqfiNxrRWrWW2uidEz7
         seQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XHfBp7Cl;
       spf=pass (google.com: domain of 3xcfoygykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3xCFoYgYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id h20-20020a2e3a14000000b0024f1cf9b1b0si103038lja.4.2022.04.26.09.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xcfoygykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sh14-20020a1709076e8e00b006f3b7adb9ffso1015274ejc.16
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:56 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:34d2:b0:423:e6c4:3e9 with SMTP id
 w18-20020a05640234d200b00423e6c403e9mr26328332edc.372.1650991556120; Tue, 26
 Apr 2022 09:45:56 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:06 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-38-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 37/46] x86: kmsan: make READ_ONCE_TASK_STACK() return
 initialized values
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XHfBp7Cl;       spf=pass
 (google.com: domain of 3xcfoygykccenspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3xCFoYgYKCcEnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
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

To avoid false positives, assume that reading from the task stack
always produces initialized values.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I9e2350bf3e88688dd83537e12a23456480141997
---
 arch/x86/include/asm/unwind.h | 23 ++++++++++++-----------
 1 file changed, 12 insertions(+), 11 deletions(-)

diff --git a/arch/x86/include/asm/unwind.h b/arch/x86/include/asm/unwind.h
index 7cede4dc21f00..87acc90875b74 100644
--- a/arch/x86/include/asm/unwind.h
+++ b/arch/x86/include/asm/unwind.h
@@ -128,18 +128,19 @@ unsigned long unwind_recover_ret_addr(struct unwind_state *state,
 }
 
 /*
- * This disables KASAN checking when reading a value from another task's stack,
- * since the other task could be running on another CPU and could have poisoned
- * the stack in the meantime.
+ * This disables KASAN/KMSAN checking when reading a value from another task's
+ * stack, since the other task could be running on another CPU and could have
+ * poisoned the stack in the meantime. Frame pointers are uninitialized by
+ * default, so for KMSAN we mark the return value initialized unconditionally.
  */
-#define READ_ONCE_TASK_STACK(task, x)			\
-({							\
-	unsigned long val;				\
-	if (task == current)				\
-		val = READ_ONCE(x);			\
-	else						\
-		val = READ_ONCE_NOCHECK(x);		\
-	val;						\
+#define READ_ONCE_TASK_STACK(task, x)				\
+({								\
+	unsigned long val;					\
+	if (task == current && !IS_ENABLED(CONFIG_KMSAN))	\
+		val = READ_ONCE(x);				\
+	else							\
+		val = READ_ONCE_NOCHECK(x);			\
+	val;							\
 })
 
 static inline bool task_on_another_cpu(struct task_struct *task)
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-38-glider%40google.com.
