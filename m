Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFO4OMAMGQEVLXYL6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5076B5B0B95
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:39:09 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id e2-20020adfc842000000b0022861d95e63sf3341040wrh.14
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:39:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572349; cv=pass;
        d=google.com; s=arc-20160816;
        b=s8yLUs3obU3PsJxjoPCK5f4AN0Dl2dbsjfNWt9ZQOynUVFrockk9tze6ZTLakhcBon
         WAM5T9efrGFwDjEg/D6fAotU+AdJMeieJG/GIQJlzG6U3YBmRTZpWUWKrqjMkTft1JvZ
         ynwlUWl4Ijhm8Gq9+4NyYTCUidIFUud5suWsWOxrjI3umwL4yE431BzPp/4n/I3Ne9XR
         9J0y309CXylUOzV9MTDXhJ0jLaoRmPmUtcoSSnDHzBJkEetFL9Td5xaThqZWOgL+VoJJ
         ZdcRw2LiuOVkDICMeuAwJt/eujhaA6V2wX1FXPBBGhkYBOZPn0OBIMaR14Y0P7kNgDo3
         0cXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=yvNtPFz0OTlVS2p3Qb8NPedoOEhB4m1QD3crJWuCW/4=;
        b=oEfUoFuoE5Y9x/x3tS20O8TKlxY/y4NmgQMAPQnxmfqwZsrLksSWLHWpjU4Yjp2Pd0
         BOtGEjZKmmQv9KbpxEXjePDt4BOyzlYE+SrpEnYhnvX6CesL2ThrdE/5BlH1LikLVShI
         scxHgOthpcQXl8zLd24oC2xAHdKpdNV5OsfPXti7n7Mz9A6Y2C2WG7wgWSEvUlmdkYKE
         hTBAh13smYgN6gLu/9JJiTtIbCslxTdBiin4+On3Q7Pg5K+u2L6RAwDkh/c8G45oOO89
         o/5Ev7Rg5cHeNR4cz/93RfQOnOnPbqpXYZVLqBtcK4j5K5+8VlHRvnOZd/YV6rTvxt2L
         8a3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j8sE6fYT;
       spf=pass (google.com: domain of 3o9cyywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3O9cYYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=yvNtPFz0OTlVS2p3Qb8NPedoOEhB4m1QD3crJWuCW/4=;
        b=gvhbNxRWwhsATd6hpgn0BnPzmzfxRmoA2+ZfG5gOcdDFD/oTqv0xmB1mr643fAhprl
         pnSpg3TY5/h+eVxCbSYbDltw4/fbQpRcBqdfzEzR6Am89OcNYF1wQ5rTsBpDtEhXyiWj
         vC1dh9rb2tpbCAiS330ITYegSuEQ6u8g/T8GKaPrErBxPEMTWTG1wrZhv5HMfO+33Uj2
         ltrchmaIAOgBq4ClU8ABCfY0I6WCXMH/8B8TeffypuvbteYMl0C8CH7ZI4LHIql6x5JP
         oARpCIIIBapMvJsvc7F7JRhs8TyzJGR/sDkBUGgIGUBlNiI08ZiRbmstW0y1P6+9ZcU6
         90sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=yvNtPFz0OTlVS2p3Qb8NPedoOEhB4m1QD3crJWuCW/4=;
        b=xRqmPIBn2KKmESmDW8DSbxituAknKiFndDQ8Kg6LLhutwD31XqYa+yDjKwhu65FWNO
         EVa3Htfl2DMLqIfR8aBYVJ5IChsvDCIE9V1IWADxaweywZsO93jGsyirDf1nJRZT6/8w
         NNOzJiZgpJIZMjnVT844BLLK2N72OfxlviCbAfm0v0/AFVfpJbw1QOu4OKiGColq9Hj6
         SQQNco/1ywjbf+I5ug2aEuUC41UkWnajt6YI+GCIfXbeRdS+8kk6bGxlpI368U24WXi8
         smDjvHKU68dNFFrqPv9Ju412eSEZ5YbI/W0M3y/l3SKjNlbruM69pGQaVUAuvSSJXH7N
         JvHQ==
X-Gm-Message-State: ACgBeo1cT4Ia4W58YzMIJ0nK13a27pQD+9XPETePMyH6HlqmF+nhleZV
	HvCWMgKiMbcFBnu4Bzdv4rc=
X-Google-Smtp-Source: AA6agR7h2T3s/xEEMMMGFPO8Sn1AIjFsCVCx2xcyhQobQy9XAwdaYoJPEtPmw4/nplBADYYdsF3elA==
X-Received: by 2002:a05:6000:1d84:b0:224:f447:b1a7 with SMTP id bk4-20020a0560001d8400b00224f447b1a7mr2705427wrb.688.1662572348824;
        Wed, 07 Sep 2022 10:39:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls3257257wrt.1.-pod-prod-gmail;
 Wed, 07 Sep 2022 10:39:07 -0700 (PDT)
X-Received: by 2002:a05:6000:2a5:b0:228:d970:bb5a with SMTP id l5-20020a05600002a500b00228d970bb5amr2928244wry.74.1662572347557;
        Wed, 07 Sep 2022 10:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572347; cv=none;
        d=google.com; s=arc-20160816;
        b=gqJnOiAxGdihwbubp99TtRx3C0xDzjmT9jx8fgK6LQaEs0Hzy2OuJ21Sa4ifxIizyM
         +v+UCJ5gQ6TN3hQjo6og9UWw8yxjUJRhqqIdqr6UPjbYOcPxos+x1sMI1TrrurZDVuz3
         NDncCsOxcbDtzyK7w93NK4MX+qTEaan/9k/sbwpsH3cGqO+LemmKRhweAC1/FErvgawC
         BiK67HRQ1/KZyGFTxzRdpxRaQfoWjXMkBlYGBhL9lzw3XLus4FFsKCPa+495rea+zbdU
         T7rcH0bG5qlTVnSbo7rh6P+9kHG8qMcR7BatFWLg6W/p0YgcnExnMkvxzJvjX34zvBV7
         nV/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=sHsT3YDwhM+0jjwjlaGB8MngokRR5HRxbTTGftCU/LU=;
        b=hebPaXrrpenvhNmYwmjFp3/8dLEv0gG4C1HY0gufmtTD1SdXU4Z3yURbAwwhwewypg
         YUoKJ9O/kBtssj5LCA9CJiMdM2FN/8LM7ZoBWOT5kmyU2iXpqpRqKt3dxYipCixj6czg
         95kqrEGWYTmax6H0ZMFDvqlLNidvU/HAcjrDv7rvv4ptZjJQ4Y5aej4pQkIDPGo0x+LB
         b4ZZMlZX9jSo5W1g5Ga0Mv7OheVB2fYA2zdaI3u2i6Pqy9myF0UEzB9iOLpQ1NxmZ7yh
         2y0TJ1RhFMf3RbLTeH7JZZLiQwJEN4hXKFtHqBJAgoa9G0csSV9Yr9CmoUH+mBORUNmb
         Z0Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j8sE6fYT;
       spf=pass (google.com: domain of 3o9cyywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3O9cYYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003a66dd18895si247743wmz.4.2022.09.07.10.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o9cyywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s17-20020a056402521100b0044ee4ec88c0so3159848edd.14
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:39:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:ba52:c371:837f:3864])
 (user=elver job=sendgmr) by 2002:a05:6402:d06:b0:440:3e9d:77d with SMTP id
 eb6-20020a0564020d0600b004403e9d077dmr3852449edb.286.1662572347297; Wed, 07
 Sep 2022 10:39:07 -0700 (PDT)
Date: Wed,  7 Sep 2022 19:39:02 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220907173903.2268161-1-elver@google.com>
Subject: [PATCH 1/2] kcsan: Instrument memcpy/memset/memmove with newer Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=j8sE6fYT;       spf=pass
 (google.com: domain of 3o9cyywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3O9cYYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

With Clang version 16+, -fsanitize=thread will turn
memcpy/memset/memmove calls in instrumented functions into
__tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.

Add these functions to the core KCSAN runtime, so that we (a) catch data
races with mem* functions, and (b) won't run into linker errors with
such newer compilers.

Cc: stable@vger.kernel.org # v5.10+
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 27 +++++++++++++++++++++++++++
 1 file changed, 27 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index fe12dfe254ec..66ef48aa86e0 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -18,6 +18,7 @@
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/sched.h>
+#include <linux/string.h>
 #include <linux/uaccess.h>
 
 #include "encoding.h"
@@ -1308,3 +1309,29 @@ noinline void __tsan_atomic_signal_fence(int memorder)
 	}
 }
 EXPORT_SYMBOL(__tsan_atomic_signal_fence);
+
+void *__tsan_memset(void *s, int c, size_t count);
+noinline void *__tsan_memset(void *s, int c, size_t count)
+{
+	check_access(s, count, KCSAN_ACCESS_WRITE, _RET_IP_);
+	return __memset(s, c, count);
+}
+EXPORT_SYMBOL(__tsan_memset);
+
+void *__tsan_memmove(void *dst, const void *src, size_t len);
+noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
+{
+	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, len, 0, _RET_IP_);
+	return __memmove(dst, src, len);
+}
+EXPORT_SYMBOL(__tsan_memmove);
+
+void *__tsan_memcpy(void *dst, const void *src, size_t len);
+noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
+{
+	check_access(dst, len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, len, 0, _RET_IP_);
+	return __memcpy(dst, src, len);
+}
+EXPORT_SYMBOL(__tsan_memcpy);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907173903.2268161-1-elver%40google.com.
