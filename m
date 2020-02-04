Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6Q43YQKGQESGGGCOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CEDB5151F3F
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 18:21:36 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id q130sf27431946ywh.11
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 09:21:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580836895; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuBOvKdUeQAz+VWtt1qhMbzQC4uyrJcpbsEFxeUipah8k70KRPj3q798ffkozLsY6A
         /6CGScMd7XqWaavnRr2pVesSKDFNvg85wuKEdzqZPBr6AO0Bdsd0OKFKXHhj+B8qrlen
         0mZMpylts4DhtcQytnrD7RxrhJ5M1tIgckh8S9C8J8EMRJEbmtxAWzbCCHNfqUH8QjKM
         RvODWtIwIL31tEjjegqROCD98mvUZ3c9nSzTaWHiHQ/QmUcJ+QEcNVab45K2qESj4T2x
         ANQS7BGEPvqjGf16wpYQT5CBt5E3MZXXFJiMf8mjQKGQaY6hQ0jU8DlEOIRF87+DkKT0
         tVIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=jvFBAKUHkgqauUoOu1xruRmdaA9gIKXDeVIF0kN0J94=;
        b=FqcORQBgPgMtO6xyPw3d9qe0TUnGbd1u5YSs4J6lJbSXpFJhAvXtGKfFt65jBo/H7i
         xCiBk6vlYN2CsA++vUJxWaVmH8WSVVyitUcfUIZpkFWjue61ErJSmbTHvlMQcjT4lOC9
         J3hGxPpm6RGRc23TnI4lFu3N6pjBtehuZkOq/z4wci66Lu3w3YLMh5QYwT9JcCS/78Px
         ytRuX+MJ/7gITVPhZe/YNHEefyUZoKP9ioXXp+hzbJt4auEOLGOX/Asn6mtFhn5n+Kz8
         nOyDskmw7lcnX5A2AAK39gLcaxFI59kDh+pL7qJx+i98IQvcNiOVTN3Cj4IHUebUooL2
         dDUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQ0ZB6uu;
       spf=pass (google.com: domain of 3hqg5xgukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3Hqg5XgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jvFBAKUHkgqauUoOu1xruRmdaA9gIKXDeVIF0kN0J94=;
        b=mMHVVxUGdOD/a8nFSlpdpgy03DOY5czQn5wk8U1P3B4fWYGGNi3kS/c05tiYbHqZEo
         QtcdGVVAXdezW3XJ9x5i41urz97p6qN8U62w2lqkBpWxEcsBAXEAz0moyRG9MpjDA405
         5TjLepu5v/GI1fZRRwXtntlIu1I72DJIGvw/udQo94ziutYhOLubG93X68lKtQi8gNwe
         aKx5rIzhtKqTq02no/mYGpzVbh+kgv+MKvQVT5scVuH8K95mHSfTPHYaKua3GB8tO/q7
         kaJR83SBZZ4bK7uSuwPl6jvM25+QA6Ap83jKohyCqNLxwfg+J8ng12aFz5B9/4QXYVPG
         0+sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jvFBAKUHkgqauUoOu1xruRmdaA9gIKXDeVIF0kN0J94=;
        b=o6+IGszD1Bt2s04olvMdJyjFtqYY2vHnilTRLnLiIoQ6vRFteQi+d+FaHJOSPHB74e
         OdBbTFvYzLST8YYVtYsrTzC2/G6FszwFJkb+zGGy3Uun0xZBrZWqyDgLnznRgBmP/IgH
         P5unowkGdl3MF6uHTrlp0Y9EqpRxDEz1oVrWbIo9oO7w9OIn4+PHlBoAIm2sBSYKZI+E
         v1PNqBlHHsgnqHuRWbu/tKQTF70CAn1tRFEO9dmt9HLV0OFfEYuJjiWhjmqLmyoTuNgu
         4mqWTFWMLHmaF74c/XdA2t9beqOIGjFZsnCCU2lcdLN/O9l+12Uob5dZSKpk+eRlGCzt
         mEdA==
X-Gm-Message-State: APjAAAUBIT0oxjMKv8mhwSrGnPsC7cIWDpDGvaa1D51uj3vMLIOHfNCL
	HN48urTnRnQEeEGIqSLA60U=
X-Google-Smtp-Source: APXvYqyfjxHHCdjLkb04QckpDgmuiLcuw/ijFmqhldHIvXzCg8cJCOP+DqhVaofJ+uSEgtKY8Z4gdA==
X-Received: by 2002:a81:8a81:: with SMTP id a123mr6854976ywg.2.1580836895563;
        Tue, 04 Feb 2020 09:21:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca8c:: with SMTP id a134ls880912ybg.0.gmail; Tue, 04 Feb
 2020 09:21:35 -0800 (PST)
X-Received: by 2002:a25:3b90:: with SMTP id i138mr25710863yba.163.1580836895176;
        Tue, 04 Feb 2020 09:21:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580836895; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJtULqJJPY1nFlCgtaxgVnpjHrT9vPmtMTJpXa07uOcnSxUz1qrs+T6jtYtUkYskSo
         jiQaaxJBe6JJh8PROK7Jb8LVYoASsA3Otr4MLxHoPa2b0On9eOREFuGGGTaeMjSzPWds
         l4mciSlCS8ub3ql5sQA1FeMbgjyW4lNRp5FUg+Gau0QHUW4uhbVjx0DjHFy9dHDpDBwf
         kj++iTXAn+zqYvPZhE4JWe+sVunKY4sbzNlTFgOvOcmkWS9ti6R8xduzayoEk9LKtQcq
         gu0A/74QedyRjWqIuJl+1DbTjLBvshnDp7v3xAcnnDgB4NTZidvc8B3JdiMGR+Qh85tU
         4gCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=P5Zl9LQYe0TwoSBlL27JA/OuhbAcWy+b13rTN8vanpc=;
        b=myoluDh0poucoPHnauWuM0jr/ot2VQtNBgDNICd3AthRL0XfK8WkILw7RQnSlaae8j
         /8wHeXgUv9tFbXuiLrfLrVFiWulNlzf2Vh6rU29zdsi8IZgZFi7KXIfKfRlJB/njCSIV
         VZAuXiFyBZj3C42pf1DsAZTvdNdHxGKNuhqtRiHsc4v7RQ0m7dX3iHlkKT8V1npY1oOx
         5WhrzPw7SUKescyyWjzAUlA39Vw8GcLEFMCEPSdynBjA08yV/M5/HtVipisR7vJ30kiz
         Er6jvJOCGCiLd822hO5UNyfMxzWaUWMGvNsQnAQR8A1bsJPuRLa1V7cMKSueVAaHSNEp
         SgQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQ0ZB6uu;
       spf=pass (google.com: domain of 3hqg5xgukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3Hqg5XgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x94a.google.com (mail-ua1-x94a.google.com. [2607:f8b0:4864:20::94a])
        by gmr-mx.google.com with ESMTPS id v64si1382622ywa.4.2020.02.04.09.21.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 09:21:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hqg5xgukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) client-ip=2607:f8b0:4864:20::94a;
Received: by mail-ua1-x94a.google.com with SMTP id f15so5104461uap.4
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 09:21:35 -0800 (PST)
X-Received: by 2002:a1f:db81:: with SMTP id s123mr17780179vkg.45.1580836894663;
 Tue, 04 Feb 2020 09:21:34 -0800 (PST)
Date: Tue,  4 Feb 2020 18:21:11 +0100
In-Reply-To: <20200204172112.234455-1-elver@google.com>
Message-Id: <20200204172112.234455-2-elver@google.com>
Mime-Version: 1.0
References: <20200204172112.234455-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 2/3] kcsan: Clarify Kconfig option KCSAN_IGNORE_ATOMICS
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QQ0ZB6uu;       spf=pass
 (google.com: domain of 3hqg5xgukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3Hqg5XgUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Clarify difference between options KCSAN_IGNORE_ATOMICS and
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC in help text.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Update help text to mention alignment w.r.t. previous option.
---
 lib/Kconfig.kcsan | 16 +++++++++++++---
 1 file changed, 13 insertions(+), 3 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 66126853dab02..020ac63e43617 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -132,8 +132,18 @@ config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
 	help
-	  If enabled, never instruments marked atomic accesses. This results in
-	  not reporting data races where one access is atomic and the other is
-	  a plain access.
+	  Never instrument marked atomic accesses. This option can be used for
+	  additional filtering. Conflicting marked atomic reads and plain
+	  writes will never be reported as a data race, however, will cause
+	  plain reads and marked writes to result in "unknown origin" reports.
+	  If combined with CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n, data
+	  races where at least one access is marked atomic will never be
+	  reported.
+
+	  Similar to KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, but including unaligned
+	  accesses, conflicting marked atomic reads and plain writes will not
+	  be reported as data races; however, unlike that option, data races
+	  due to two conflicting plain writes will be reported (aligned and
+	  unaligned, if CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n).
 
 endif # KCSAN
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204172112.234455-2-elver%40google.com.
