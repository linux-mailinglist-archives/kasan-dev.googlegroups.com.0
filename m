Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJWNTGRAMGQEUAIRWGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D31056ECB3B
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 13:23:19 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3f173bd0d1bsf26759965e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 04:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682335399; cv=pass;
        d=google.com; s=arc-20160816;
        b=VwdN0auKA+u9VZRahr4I9vly/1wsyfPKboifu5guzBrTy4TDKzhZvBJIiyDL4rHv+f
         TxvkTCJ66nHBGQ4t5gSL7iWyftWsRkBIBxWuiN7cqb9EBHwV8ollJ41EnkNCitHrTGO/
         pmtE7nPOd/BYDg6dm3Lth/E15L5vcA/QjP8n8JMfSKY9WOHXgfymp4X4d7/5+DNTFRcI
         vAtnIWpBWU05gAZIRL/Z67a2t0Y5TDDK551+RxLIjGZ9jWrcYeBYE156H2VE/wO/Iuui
         jqwhlbamcrFcMgDnPcMG6LpNQndfacxBDb4O/SNMe1ucTboH7hisOLpOruv8MTE4eM+j
         bibA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=1R6mksUyTyeDKcXe30h+ZqYXk7TS6xaHY+Ia2nUPhc0=;
        b=xSFQnLGWVFXqOujdeS1XkS4xyUlWnwdQkudhboeewraiCpLZ+xMXtSm0AeBtNS+8v0
         tUsg1F0IxRdl2hif0SInPNwzWoR6jKB7NRHVwbgVrW7SB4Nv71jFwmGAGx8kHRj4vvqF
         aMAhqscMYao1goSXZ/JCvoT52wv4se7PElppczEKbGmu960wLZ87S1gqNMUckPTZnliq
         AiL26Ume2pNF2ZItvGCtQ/vzAfv7UkxpifPbSCAVNnTgHBiBwyHkTtIGnENaG+78OFmF
         RPIOFHk/lRJjZO3oEd0tm4UDR9EEtarDl3RnQeTMV23Lnq3U9bM9U0te0/WVvOQ9ZOM5
         +/Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mxilGFIr;
       spf=pass (google.com: domain of 3pwzgzaykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pWZGZAYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682335399; x=1684927399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1R6mksUyTyeDKcXe30h+ZqYXk7TS6xaHY+Ia2nUPhc0=;
        b=floi/E1aFpdWENd6WtCnyLkLzOfubwlEsZmkutACl0J1DbRVfQRDkuZJndsze3vOHV
         NlQLB2999HLywt2J0tL0te7CM6maembH28Z3trijb28Xc/i+GwxlSbDVrJy/Zh1Dsqm9
         S0b3H6jeCNKoBE/n6FFNQzD+rmSdh1N6iGkQam4vDog4ZS75sNfNnBiQ1gOUJwfHPLow
         u3Nltkq8MiZ1XF2gdr/AHIt3M1hWMxgV/Foi4dEY5jQmOo7NM+/ghjUvoTU34OFn3Mbe
         zYp5/YrS0LlZz5r5NIkaL4XcxkrogYmMQRfcEkVAPH24eEx5Z8Elk+gDecoIi5EK/EFF
         NgkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682335399; x=1684927399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1R6mksUyTyeDKcXe30h+ZqYXk7TS6xaHY+Ia2nUPhc0=;
        b=FiuupFhGD7hI+c+P5dnIBSHRkjd0k9UBgTC5/dUbHfFx5uFpgXP9TKh0OjVVdMDoUD
         ZWcyhLejzPAkyFeWJ7piGs2p8sVwqTQy57E4OJwf1tI07unC3V9u9+RMsMuO00N/PSNq
         cHXnhh8val40Fq4WWB+BDfY049rOGpNd05cHB6ChEzxGaXIBax700R6UP0oqeUlycEfM
         /mYHXvdP7DgRBqGsTSqDuGJADMx6KfgDB2Wt9Vh8oyvQr8eTq9OZOY0bxRFfr+E1JanJ
         gwj2tM7SwrcJ0aNaQWY3+P6jHo8b726VfVMlgEKLQhY8iST7oqs1I9xBT3rMmGyGE3nC
         hdMw==
X-Gm-Message-State: AAQBX9f0myq4XVprkWq9VZDD503dZqHIGhtyTU+in6c6Z9FdTVPnYGyV
	s0/P5HEyk7iub1aNpQEIjZE=
X-Google-Smtp-Source: AKy350Yqi+ZgRHeRn99COrLuGHcX+VQfjR1bHt6fSjQ4Xo3xSYQUpGb1Ssmy9UPE7412tyLqe5XllQ==
X-Received: by 2002:a7b:c5d3:0:b0:3f1:70a1:fa91 with SMTP id n19-20020a7bc5d3000000b003f170a1fa91mr1986706wmk.4.1682335399107;
        Mon, 24 Apr 2023 04:23:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5e90:0:b0:2f8:4432:9c7e with SMTP id ck16-20020a5d5e90000000b002f844329c7els763573wrb.3.-pod-prod-gmail;
 Mon, 24 Apr 2023 04:23:17 -0700 (PDT)
X-Received: by 2002:adf:dc4b:0:b0:2f0:442a:2d45 with SMTP id m11-20020adfdc4b000000b002f0442a2d45mr8449681wrj.57.1682335397880;
        Mon, 24 Apr 2023 04:23:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682335397; cv=none;
        d=google.com; s=arc-20160816;
        b=vyNDXW4wJtsaK+izDAKd+X2UCs/yFRbImSq73er7c/Btk4O7yxY32ML3SRAUiYO60g
         K4ms3MXQbrRpLuwZd+ioakgZRxfdUHzZ3zv8ADjoxVmA1pS6R5fetPZ7wuWOUUrvxbCH
         GQ7D2YsTRegt+TzSbA150JeOjRFMmsTqrHaLCKR14oOAyDHVyZ7AKh1XDxxkMbBMaMQR
         BdKc8ie6Cb0T3BGqpdCHI3YSNfls1T3a7+p1AuTefdpZlzJMgYaUBYD2A4igkvVKo8bp
         UIWvk9Wc2Mnd7TQW3K/swgp0GEx0eHlqCaSofwNTtSXga6ArHD78rmWmTQqH+lwrHo8r
         NsAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=klWy9eDeY9DLyh7eLsNz2mZGZzQpgILthmxtoxhfJPs=;
        b=KA+8M57zm85gluPy+tni0wv/eC+sN7NMydKXTwMvNbQbcLO8H8sqBvSrn84qIazqkD
         8wltku1GLlSTvnF3Kn8xf4I83SWEEbkzDrJe1C9hpk9lEXeJ5Gt730la98FCldby1ktX
         j5d1+mS7TGOeLDgEsgeF8MFoGpTtdi2iE4mug7qMZKdlTbkvWi93manPcIdxSNukWX4D
         Q5HLPyuJpMKp9pWVerUSRyzgF/64WLNC58OICIKKG6EpFRrQV1oQl0f8aYM1dMYr0g2+
         bqbSussGXTX+JUfPEXiHN/EjpAvpByFXWKWKO+HQciVNPM7ExLxaR9CcQ6Epq3OOYWHC
         hIsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mxilGFIr;
       spf=pass (google.com: domain of 3pwzgzaykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pWZGZAYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id d13-20020a05600c34cd00b003f173302d8bsi550471wmq.1.2023.04.24.04.23.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Apr 2023 04:23:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pwzgzaykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-94a355c9028so443117166b.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Apr 2023 04:23:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:ae04:112a:7904:fef5])
 (user=glider job=sendgmr) by 2002:a17:906:eb1a:b0:94f:c72:1de0 with SMTP id
 mb26-20020a170906eb1a00b0094f0c721de0mr3297825ejb.14.1682335397499; Mon, 24
 Apr 2023 04:23:17 -0700 (PDT)
Date: Mon, 24 Apr 2023 13:23:13 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.634.g4ca3ef3211-goog
Message-ID: <20230424112313.3408363-1-glider@google.com>
Subject: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, andy@kernel.org, ndesaulniers@google.com, 
	nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=mxilGFIr;       spf=pass
 (google.com: domain of 3pwzgzaykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pWZGZAYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
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

lib/string.c is built with -ffreestanding, which prevents the compiler
from replacing certain functions with calls to their library versions.

On the other hand, this also prevents Clang and GCC from instrumenting
calls to memcpy() when building with KASAN, KCSAN or KMSAN:
 - KASAN normally replaces memcpy() with __asan_memcpy() with the
   additional cc-param,asan-kernel-mem-intrinsic-prefix=1;
 - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
   __msan_memcpy() by default.

To let the tools catch memory accesses from strlcpy/strlcat, replace
the calls to memcpy() with __builtin_memcpy(), which KASAN, KCSAN and
KMSAN are able to replace even in -ffreestanding mode.

This preserves the behavior in normal builds (__builtin_memcpy() ends up
being replaced with memcpy()), and does not introduce new instrumentation
in unwanted places, as strlcpy/strlcat are already instrumented.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/
---
 lib/string.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/string.c b/lib/string.c
index 3d55ef8901068..be26623953d2e 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -110,7 +110,7 @@ size_t strlcpy(char *dest, const char *src, size_t size)
 
 	if (size) {
 		size_t len = (ret >= size) ? size - 1 : ret;
-		memcpy(dest, src, len);
+		__builtin_memcpy(dest, src, len);
 		dest[len] = '\0';
 	}
 	return ret;
@@ -260,7 +260,7 @@ size_t strlcat(char *dest, const char *src, size_t count)
 	count -= dsize;
 	if (len >= count)
 		len = count-1;
-	memcpy(dest, src, len);
+	__builtin_memcpy(dest, src, len);
 	dest[len] = 0;
 	return res;
 }
-- 
2.40.0.634.g4ca3ef3211-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230424112313.3408363-1-glider%40google.com.
