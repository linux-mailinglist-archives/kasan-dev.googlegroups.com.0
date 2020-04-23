Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEXQQ32QKGQE7OXD24A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A70F41B5FCB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 17:45:24 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d22sf4918931pll.7
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 08:45:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587656723; cv=pass;
        d=google.com; s=arc-20160816;
        b=dcyhKb8XY2gvbEdcTEzx0u2bx4D4IMG8lS2di5+lj8v7cRp09L8iQyxJ4gpdk2iboT
         gXxAEqdfG1VffOR/oKzcOuTBkemkFzWvMkPyqlP4M+uF4LxAL8byudrWkpXdkDcouWpo
         8dqeS6XH5M+30m7+hrC6uOnpMlNVVLj5RCEHRiCM4VnKsrPiiuVDHpbIEcWKtkeJQXVo
         3VWg9iv1vsN0mTi3BYwztV47NN5OPcmYvWCfuzHntzuGqIxy/UXy24iNAMoBevPFv7zV
         0/Br01WkGODXS2A9q4qmw1XcpiESFO9cnvjifoj7KCzjsQIDpBOBPzgWUhgAI3+P4qHT
         82YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uSTF9hPOkdogZFlljEb1eOUeJGsyWJgCgm4t+drYjLo=;
        b=Q6Ex/uRYz0oi+fmUOUzziDYdHfvWEbZvfTjTMx52MqYyF6mKpz779DPkFc4WeslJJy
         gPE/nE/84tCCK8Dm06YU8KfnHtNEGEzaEoUAwhQZbr6HnDrYJyXRwiX0+LF1lYmgB+aW
         +4szkhknKKwW0AuqMtjXFbpQUv16MOWhI/1RzU4KiMG32csTR6JJxnENWdtQYnpS5hNk
         VwfVGAUi+7w60K+M0L9w7Ij+cieHRcYPiY7iMhIBewnU5aeo7s2ovG/h5vr2SOvBcCfT
         Nbnm+aTFd55PZJNnadZmHNXMoIftIw53efZrEfjAFhzTZ9MJ3BtW2rDq11sjHkhkR2qQ
         V1Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IqBvaW2G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uSTF9hPOkdogZFlljEb1eOUeJGsyWJgCgm4t+drYjLo=;
        b=V9zOcjBV83mExtqPoH/Q3RSZdGQxzK2Yr+ynnK6zgqvwFk8Lo1MkZwY+7SMrnkKnNa
         ZhwO0bIK7MC5MxI8IRXMnssnzjaYj49bclXbCuES1Jyb2YiGDQAE9oT9E4vgta7rNdcp
         K0oaNs1NHbQZx+C+pOY5BhetmDykYhTQJC5fMUyGPHnAdpld8V8xDwDxGOh9LIfvFK5J
         YDI+CJ/yIWiKWQCzOp8e+JuObWNIEaNc4uFzQL3GwxXRctyP7KTFzbzxcUL0kMxF3a5O
         VNoss68O6hCSwlH4GZGtuc7w5jCk2GfI+YcMiJzKzizCLyINGk14XGDmMiZaiGMKUelz
         e0fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uSTF9hPOkdogZFlljEb1eOUeJGsyWJgCgm4t+drYjLo=;
        b=nP73nZ6AJoVwCE6oF+Fu1pAO1ZIzH6lM4JbY9r1192MSVIP5dQ2ptp2T5cLAQaUDyj
         GM7OW63odQd8R3srsLcpX4k/vdnl5S5uFhJ6REINxfe4zQwdekFGuy4dJ0RGztfDWmFm
         d1LosvvZtntEJ+re9e/nrM3oS7+iEoFF8EV2TewKlFWgwQLTIPJY+QzEmXIVHRfZN1Lj
         6EsxmlMZySvlMlelzwg++7uZil5TJvW76F2ZvY1+W1NhorX1/sTbJGsnG0T+CppYPshX
         nsQCx7rDvUysHwR5TNoLO+QlXX8S+jP6D6sdKcZMXhBGqBa4XuGksAo+k7M937TkSL/j
         e9Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYA4zuYNav0LnqnMNuffclx6J0wZLIoiEhIWbB0jiTuVYtn2Q60
	IKRAA0IGqjsTs0y1aX26SVw=
X-Google-Smtp-Source: APiQypJKyH0TjQkFvHqe1ElhSWzSMPppJ7H8mOCKdbHgit7eY8xRDR5sKwd8gArQ2ugLiaVmOwg97w==
X-Received: by 2002:a63:5724:: with SMTP id l36mr4532921pgb.317.1587656723021;
        Thu, 23 Apr 2020 08:45:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7053:: with SMTP id a19ls1308226pgn.2.gmail; Thu, 23 Apr
 2020 08:45:22 -0700 (PDT)
X-Received: by 2002:aa7:819a:: with SMTP id g26mr4393199pfi.193.1587656722604;
        Thu, 23 Apr 2020 08:45:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587656722; cv=none;
        d=google.com; s=arc-20160816;
        b=iTASZ6vDcbLYJq94K5p3+hxRTfyrWxxMuRxVj+w2qKpfJkYYlVK9yVSW89kECM01UB
         Hq25aKunXiVHSGll6qaAkOBxN2cNDhoC+Gj+hGK93p6wnY3bzseQDkAL1OjSiZ40rbmM
         8je2yV3A7/zTlyBSWCZ0zx9tPhtLgI6tkqKjU1MVJCvsa0VR5hw2G466B+zuteItDlrr
         LUwJdBc8rag0khwHf7iDafRWe+dVsP+Bo2jD0uZSdpKNRsWzRgGPzj7r03tUwP3bOEDL
         bn1TazUGTcvhFkx02rv30Z+mjSA5IR/A68kzki0b7IHsN9O30ZMSaqL54XI471jDIT0e
         Y4PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+SloOzgks90oP9C6mvgapac7rntE6LuQE/iY+UvGdqE=;
        b=HMxXOF7b14PmFxzSc2GePBLkdtV5dQeiR8OybgFR8n54zTPCaEo4KjoSKMoslzubEk
         iIiUbZT3QFEjvF9fkyLP582VHKObPVAhkdZl6kQNonWbvXDzqXQkGsUvb6hF3i2/OA7h
         5LFJqgvoiCMP8iHiw7oH4vk08mKSROMT7wQaAErhjpT0FcVCRrSviRv1gV2Mm62Qr5zi
         5PI7ZqKTAarDbHrAULf9lZHOSJuvKoTJBkjqRi1BNxdHgELUejlEkcmAdEmRuqCpwcmc
         WxTVVoMxgQF3MsK3lHFTYQFFt1VWLc6+swsKhAETXC9lFDsQAsE1G/WMi1kkd4OMQUJ0
         M8/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IqBvaW2G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id j132si193045pgc.2.2020.04.23.08.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 08:45:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id s18so407662pgl.12
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 08:45:22 -0700 (PDT)
X-Received: by 2002:aa7:9f0a:: with SMTP id g10mr4217244pfr.109.1587656722363;
        Thu, 23 Apr 2020 08:45:22 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-7979-720a-9390-aec6.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:7979:720a:9390:aec6])
        by smtp.gmail.com with ESMTPSA id z6sm2200624pgg.39.2020.04.23.08.45.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Apr 2020 08:45:21 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Cc: dvyukov@google.com,
	christophe.leroy@c-s.fr,
	Daniel Axtens <dja@axtens.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>
Subject: [PATCH v3 3/3] kasan: initialise array in kasan_memcmp test
Date: Fri, 24 Apr 2020 01:45:03 +1000
Message-Id: <20200423154503.5103-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200423154503.5103-1-dja@axtens.net>
References: <20200423154503.5103-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=IqBvaW2G;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

memcmp may bail out before accessing all the memory if the buffers
contain differing bytes. kasan_memcmp calls memcmp with a stack array.
Stack variables are not necessarily initialised (in the absence of a
compiler plugin, at least). Sometimes this causes the memcpy to bail
early thus fail to trigger kasan.

Make sure the array initialised to zero in the code.

No other test is dependent on the contents of an array on the stack.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 939f395a5392..7700097842c8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -638,7 +638,7 @@ static noinline void __init kasan_memcmp(void)
 {
 	char *ptr;
 	size_t size = 24;
-	int arr[9];
+	int arr[9] = {};
 
 	pr_info("out-of-bounds in memcmp\n");
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423154503.5103-4-dja%40axtens.net.
