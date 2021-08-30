Return-Path: <kasan-dev+bncBDGIV3UHVAGBBTVJWSEQMGQETOQO7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id F0B473FBAE8
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:48 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id j135-20020a1c238d000000b002e87aa95b5asf9547789wmj.4
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344398; cv=pass;
        d=google.com; s=arc-20160816;
        b=YLOtzyybJghKIypfIKVkX/yGS/PbAqvkX1TVWDVY0gBsEOs+RaztZajCW4H8zXjB9V
         y+3kn6PItdaE9QJx8o6Xo7ELZGLtOvZkTTzah2WsxK9wtdnaJ7Mn7UoiG0/Ax7UilEXc
         ph5tqfzAfpHNNvjOlv84B+4GuMIg469vrPQrD+N/R6TB/w2ie8EsTOxjypUGY+iLsZ1l
         ESqTD+IEJF3jDGSprk3fWeouilYJxwQaqepFE44WmH/2ZRCQVOiDH3lc2tT7KoReCj2a
         9tzT41TZzJoU8/EoDn1fhOJom3c9RgNgrma6xyim8mZUl+O1FFG8b/YhHxGYr6KTpQRd
         hpRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vW30BiSzDGXUxNtxbDfwWc2dz9DAYtUx/VSdJcOUdbE=;
        b=ggYEGd9bfBY55s7kyXlTFqjIF8uhT+MEh1NEiEjCRwHq6Xb7FF6FxZUzwmydKNluzE
         QgfNQCFkGaBjniwrjm9IF4NJBN0QqI4yoY8f9EYa7spNnte9KoDsBGJQLLqN4VdBGgR+
         Itn40EP3JwQC4CNOUZ16u5C/dH4YUfVAGOcE9yalRPhZO35Nr3DBlWO25V/PLS+rxfez
         Jljp4GnvrsUT4qgdZ9S5GMBNei1Ixoy5vSF8Kyz0WzDPcRqlBWkvy/+mwcnyaTMD9gGE
         rUJ5WozEtcYqWdQF7X1bVu8ZLjU6d/ZnoZFNb6C+7Hqrs99YaD9Z58165D0xMAf4ksUq
         HcUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=QOxAok9p;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vW30BiSzDGXUxNtxbDfwWc2dz9DAYtUx/VSdJcOUdbE=;
        b=PFiAVXs98AZnUU1D7UBavrIV6Dpm7VLq5QT0dGWtItFH4VgKrnQFQePB3pTkMZkaQ0
         JqBRXEEUptX2Q4w4IyZZD7nMFgdYQ3JGHApfcAxkAZzEkrfgLKIfmXmB8xuDmzd3C2Dr
         IxqPE8S9T0payZvf3jzNe5vB6Y0lkXAToB331T1vbM1ZNNBuN/nbpl0MnU2eZZQr0qCU
         YZgkucyHpKDO0s2CSe1/mn/gSGh9EUacEdhHakneKPJu4n4bPkJb6U5yPCE5n4I6HXeM
         82DiOb/c2noKexRFZiDSqRWZENmeZb2ql3AIHxcmrmqTcVL/0f450tkWAjaRd0xZaiBX
         tqSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vW30BiSzDGXUxNtxbDfwWc2dz9DAYtUx/VSdJcOUdbE=;
        b=lyVR+LN4JxPwfsbndzIoec1ewS05SFVj3jda0DhLlgI6eA9YrdqvhzeWXLaXnSdPEu
         NyiMrvrpjq36jkeDlOqtL4tiFhdXnW/axnHC95KYJF5fUQDWfBYTCbamqhNO3hRrITyb
         1dFHx8/2uBj33IegPnm1An2Jo8J/swLW4S8Jnk04r7jEJbwbmvJkqAG4H/QQMhC5KJIK
         rA/Tw/1QeShT0x/fx0jCwbNaK3stqI11yR+oSr8Om43ae+s0YpbF26O9vHhd3PIiV4Bv
         tlXYOJZ1xikN6MqEQRqm5USTLUAxd63MIAM8G2q7lpQK/veTFp8K9q1/+0DERgzxL7MH
         GHDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rfKvldUpw6NHdcQjs9ubJk620SK2NaOEDz8R6AFCZQ+7P7zr3
	XTklG3f2fhX/xw1fyvf8Ecc=
X-Google-Smtp-Source: ABdhPJx+2hNbf0p4xlZ+3TMW0DaKJ9tE4MYOI+NV6DYYdRALhoEMQtQCLSZB/IIOebc7eCNxpGxPng==
X-Received: by 2002:adf:c10e:: with SMTP id r14mr9201585wre.313.1630344398751;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c3:: with SMTP id g3ls57107wmk.0.gmail; Mon, 30 Aug
 2021 10:26:38 -0700 (PDT)
X-Received: by 2002:a1c:7c12:: with SMTP id x18mr163118wmc.114.1630344397954;
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344397; cv=none;
        d=google.com; s=arc-20160816;
        b=W7ZtYauqEbqz2eLZfGpU8R6Z/cNFGcigM99mu3NCquyCmrNjiStTAjPD7U8ayX5/ut
         McvQRumTNwEfOEZVBu0Q54xC0ZeFqeshBs9OBL/h+LUgatXi/Vv2FcN2iU1AuOqHXqOU
         Bct+w69yB6YtiK8OC15pO4xP8Dnc6tVYvE6V9lF1nuIV4rjcB9AWdOOsXgkk8/UOZkSU
         ugLAIeCZh5gLBK+n9z3x7IfntbXfuZZuS+QjEgbNANc4fLL6dQBIkfBlO5sbvEfMGp5r
         P8hQsrYw1AD8/GTLOIxNPqixEoJtcXXLXsTW5YaOoqem7qJeHh8yv+ksXVUcSdQsq9XE
         opeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=zdeGlaxloU7A7puzQDSmxwaKz/GLtfH48l9XOoOH/4I=;
        b=Dsu3RfJnhBTe/3l4oDEpefubjxpATAmlBBxmN5xxOcZ/k8MFLRPfHMu+eLY9ivb+fx
         FqS0IsT9xe9djHAE8mZIa4QjKyGW9Krta/F7u6hi9x8w+eGv2V8cFWfLpuLfJUWvfu1i
         hBH2Z+RlZUW6j9s3ZDYHuDTr6kRYnYhqHsbx8SC8embZ4I5Qq5bS1FiJvwNSAWttik/P
         R80o2ZMgSD3ji14q+gmV8dhj0o2cYaGeGOnjWwvU3Lhkfi1KldQca4LXphTaAMGdrYjo
         yq3bvqXYkvAYDA2IZmrY3gIfa3gKIx4h920Cxk7/addQcdDIDJvQY8VM3QPTJbsMMQVu
         RYkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=QOxAok9p;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id u2si1089771wro.0.2021.08.30.10.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 3/5] kcov: Allocate per-CPU memory on the relevant node.
Date: Mon, 30 Aug 2021 19:26:25 +0200
Message-Id: <20210830172627.267989-4-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=QOxAok9p;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

During boot kcov allocates per-CPU memory which is used later if remote/
softirq processing is enabled.

Allocate the per-CPU memory on the CPU local node to avoid cross node
memory access.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/kcov.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13e..4f910231d99a2 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -1034,8 +1034,8 @@ static int __init kcov_init(void)
 	int cpu;
 
 	for_each_possible_cpu(cpu) {
-		void *area = vmalloc(CONFIG_KCOV_IRQ_AREA_SIZE *
-				sizeof(unsigned long));
+		void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
+				sizeof(unsigned long), cpu_to_node(cpu));
 		if (!area)
 			return -ENOMEM;
 		per_cpu_ptr(&kcov_percpu_data, cpu)->irq_area = area;
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-4-bigeasy%40linutronix.de.
