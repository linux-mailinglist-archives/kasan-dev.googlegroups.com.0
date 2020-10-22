Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO62YX6AKGQE3Y3DQZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 33343295D5D
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 13:30:04 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id dd7sf807277qvb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 04:30:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603366203; cv=pass;
        d=google.com; s=arc-20160816;
        b=nUo5EmcLFtH6MUveL31MKDJc1797wc8vDXJoLOvxqO/1llnDhffcHyWf5/vVR9YN3l
         KRwFvlAWjwMH0sCObS2ylB3kSOz080/ymNVoJy+e3zk8Ot+cX27w+bu5sDzcXhysWacc
         FxhqL5ROL3wSq2jsElZbFexxwCk7Ozv/tg+m0m8PCPsBrBfY8JZr1fYK7ZGxzlt+G3m+
         ysufSR4xHurimGvM/K0A/w27YGcrL1b08CEBMsXoMgxm/HPTIcRFHLHbyjnVGV+rgYpu
         yKxNbV5yhEnJQEQM34i+6aveqeZmShawUaL4X4xLhEJ4rfk4+jEI1fXkLPHG5IoK6DPN
         97Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=PmI3jTYpBH8KiL3AJY+kMoRlYD7RTf+sel30mecCKME=;
        b=fbOThDInZYf6FB9JeZic8cRd54yxGNOGL6hfodr27qAst51gBZBtGn9Nylr3PM7ek/
         33cepu81QozusgHBKT+U+OUt5QBL+BGHvowthHZ0GWOcfSp8NKq9MNyth9DbtYUBPvIX
         dvG30kAcaCqBOEubhIrZ4T0uwgYrnzFyLkdtQnDOhhNUacUOCBF9RGI62Gwnu3qdknqE
         Zj4Ayt98JQWgcBJwZ+s9VAMIIHu6sZXW3vhg9p3Nfi/EXdGHaxp56GWeu2itRcIjLYMo
         J9U/l7AHIA+rzqM2m38Kt1c/eZk4J8Kg7UPqfl48zJgaQgEFcH1CbKBrATbFLKgC89H6
         Wmfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EmL8KR1E;
       spf=pass (google.com: domain of 3om2rxwukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Om2RXwUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PmI3jTYpBH8KiL3AJY+kMoRlYD7RTf+sel30mecCKME=;
        b=CoFygCuRI7ZQbK1aZLJrBbri0ODu09zCYZzAVoDf0uRAim4CWGOwdn7dM0gTA6w4z4
         nW8XOw6M+7V2uUXN32NA2QL6hYJuqgxHMM0qoo4GcU17BQRj+VXa3w4nk2ITqfHidN0H
         o5lFfMeRQW4baFG93Qkf29GrvIufkMlDqIdzxafDu5bqQdcQYRdiDIe6mYbLZSk/CA4C
         1Hb5WsBfgYnTCn4lfWyZIv6EkmDraWVUSh7joVp2PJlonnBdskwGX6SEYpqFTUq6TCXy
         FKNOb09+kak1uwOvK6krsNBnQvegwwzgr/FbonQczHNP017RR5JCterp2CJk41XspyUE
         bE6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PmI3jTYpBH8KiL3AJY+kMoRlYD7RTf+sel30mecCKME=;
        b=DOfyOl/hP0GHUl5derqU22re9yHOle0upUctMeMHPMY/U4JNf6y5MAPU6bwj+6lbcw
         /yCc0sh3r0TTM3LmK3w7CW9DAKZQqOnUYKQKugmWuYvQGlkg5nUToQ/rZfT5xx87mjjw
         WNolR/Y3ZyuGUJR9tea0idrpn1IAf6q890U+KfHst3PGu+dUuJ2SCIU/4Q5S+wA0spwM
         kE3JrpMGggx+P9gKgWe8qzhwgfivk4hEeCZKeuOIKlYhSXi6JlWk0awneNY+RRjHg/C9
         pfrg3hkPkMarewFvMp+/wLBot+KFlqrgvIpha1Llr3ZR0qD0f3Qh6b6YaE433yAP0ZAV
         BlhA==
X-Gm-Message-State: AOAM5309NpsCeukpr4zPd9i3M5yR3kjTQhOTOtF4QgyT+zrHAo9zWn05
	awcTf/0GqOxH36GMv5+qgMU=
X-Google-Smtp-Source: ABdhPJwZqLtD99KPj8TtNb/hxvhVSOYacYp7BkcuJc0lK3b1mFqFWp1fxNHpDDEDjHLT5PimA11V9Q==
X-Received: by 2002:ad4:55ea:: with SMTP id bu10mr1923089qvb.28.1603366203107;
        Thu, 22 Oct 2020 04:30:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:efd2:: with SMTP id a18ls395816qvt.3.gmail; Thu, 22 Oct
 2020 04:30:02 -0700 (PDT)
X-Received: by 2002:a0c:9ccc:: with SMTP id j12mr1863826qvf.29.1603366202668;
        Thu, 22 Oct 2020 04:30:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603366202; cv=none;
        d=google.com; s=arc-20160816;
        b=XxluJq6m08j2R3PeJAsRWRw57F9Mzx4yEiyaE/SsgdPHPzwqPrrJcxpqI/cmCs4FV7
         63xf6N+l7IZLefDx904NTl3qq2bMHSxntn+jCxxG4xdk46AbItgIay51sm37qZM2Lyms
         2hjkrx5ZmSErKjL/nTszX5efUblvnaif6qcFKHlFfAHwRz6lo68r0Xeag259ED0ExNU4
         vsxLrP+Ty0wYrmw7563Rt4GReawaG97PFdKb2jz7H+hxbeHRV5M/rQNNAauWN3oESxrm
         keBHtIJDLWePE4nUsRgccyRzIzDtq2zRsimSkx0H9qpv9CMDcHA2sfYTE6ale3n3vNqj
         z9gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=g50aig4WnJQhcCcuXsue/eYMQH3ofUeze+geEk++93U=;
        b=KNZqDVHhhn/TcrmUG9gnRegknS89Q/dXpV+FhWdcYG821c9Ukrhh8Xmye/hLqJ+uJc
         t3xdYvygugXIcSX2Q6VNtHGZz/PN209wIhxuvL6TS6pDdkpBAq2el7hVG4qUetupuD/x
         5hlW4t5qm6ioPyN3BLUkPjBQ4pd98Hy0ZgRY7sog40/nY1ShcAYTNIbBVrUhLynxy73m
         9uzwxkbmgzJVuO0IVWZP8nckf1Rykjazlyd8oPfELxfwNGW/x/bCarzTFmBMIzGXx/Go
         WmjnUQ2aWbEhbTu8ukAEIoCztgWY/AAwiyrxqUDgB0mykPSXBzbsED/EnpQG2KkZPQVr
         Tc9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EmL8KR1E;
       spf=pass (google.com: domain of 3om2rxwukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Om2RXwUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id r40si96905qte.5.2020.10.22.04.30.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 04:30:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3om2rxwukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id z16so770772qkg.15
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 04:30:02 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4e0a:: with SMTP id dl10mr1790315qvb.41.1603366202277;
 Thu, 22 Oct 2020 04:30:02 -0700 (PDT)
Date: Thu, 22 Oct 2020 13:29:56 +0200
Message-Id: <20201022112956.2356757-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH] kcsan: Never set up watchpoints on NULL pointers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EmL8KR1E;       spf=pass
 (google.com: domain of 3om2rxwukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3Om2RXwUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

Avoid setting up watchpoints on NULL pointers, as otherwise we would
crash inside the KCSAN runtime (when checking for value changes) instead
of the instrumented code.

Because that may be confusing, skip any address less than PAGE_SIZE.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/encoding.h | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index f03562aaf2eb..64b3c0f2a685 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -48,7 +48,11 @@
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-	return size <= MAX_ENCODABLE_SIZE;
+	/*
+	 * While we can encode addrs<PAGE_SIZE, avoid crashing with a NULL
+	 * pointer deref inside KCSAN.
+	 */
+	return addr >= PAGE_SIZE && size <= MAX_ENCODABLE_SIZE;
 }
 
 static inline long
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201022112956.2356757-1-elver%40google.com.
