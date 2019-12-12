Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSEJY3XQKGQEPZUE6HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 691DD11C112
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:07:36 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id z10sf272548wrt.21
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 16:07:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576109256; cv=pass;
        d=google.com; s=arc-20160816;
        b=CyjIv6eRS3Z0N83Qb12skr2kME/F6+fZ8oxlvGXU9joHsNu05tSGEvjuaTzw1Ikqeo
         fWZz1w8rlmHwQ+3rezDW84ODOHPsvkf8g2RfbGPXBc2muw6ze9jJJQARcbRvTksg/qQs
         l866b7t03QpCbhK6GZ+TOdR0kccWH8N5L2DJrNe/vsE00aky3FwCK7ycLe8hFEpW87e2
         TU8Q49WGqziDsVjPul2fXxvIVJGoTYGz8+QQcVj12Nh3UPhgHeTDLdlnbV+TALTInnTW
         FoPtQY3OYiQqR12ZPn+9p5FbPPkTXBJy3nToCkTgVdr4GJwV2VMQK1nGZufiurLQh1wD
         PycQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Hkbxq81+wYs0xpa+ZbSYa6ccXWgDJc7ssQ8qjw4OxxY=;
        b=Q4S6ljYhcGKn3xA+qViqChnzEUgH6b3sK/XSe2OjPz0eX+6K6E/SlYIakv5LvSabm+
         9h2y7/L4np2fW2/TyXOGmm/lFr/vSP1V/PGj7RYddpGIeUB4MGBhh72Bx/QU7e4kAZ+z
         4DnPpnvf9GKzt0Ji0b3dpHTYO2v0kahRU7DmYb0nre0TJ5hVt8pgKgkpgoYaH11uKfQ/
         IUkjt5l9XQQNcIQRHK5TCqZ0YP3VpsHjJq/R0UBxccMyVpVXEqU/hW7KOm3WUEvJeTVY
         NCttvPHa44jGgeVw5/Co6FwBilu5aZXH2XLzXnZC1HE3wKs9V5ddgiNWw9pz9f1/cmEr
         0QXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nflDkvqb;
       spf=pass (google.com: domain of 3xotxxqukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xoTxXQUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Hkbxq81+wYs0xpa+ZbSYa6ccXWgDJc7ssQ8qjw4OxxY=;
        b=rlfGHQqwr51fnd7XxxQLdaalUTrx6yTFEwUalR4MKl7eVG07056OQ+jIjH8Z8il8xd
         VkOd3gB4ECn7Z8IKCQx1he9KPKiD9Xu3jYPuJmV1fkFqAV2aW6mLfDBXfjkEjpt5IHrO
         79rzGMEvSJNXs+6rzlqXL5jRqSbTzaHe9CHgAutUGRl81HV8v4VasMXv6pSuFPAFPyMV
         vEUmNo+D1b0IJPhc7PsKmfCeK8U9DSQCnf5dfWuh2v/BlnFL+mdBtl0t0Hgb+ayqkM48
         1BUhrKd+dGRVAkP1jTmAm9dg4MIjjIY3o7DIYUwnOeZockMZmebMv4gXFhupLqkxAMC1
         nTaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hkbxq81+wYs0xpa+ZbSYa6ccXWgDJc7ssQ8qjw4OxxY=;
        b=ocQE6xkenjXHoQ0e3FWiFtl2XWqsV81/4aztnCJoLIg3JEGSmqJ/kmN7dZrS0XZn86
         loLI2+8H1XODTb3TNgSXVEr5LyQ2RKFL3HRCVeSas80gFx5esRfVm+W4jnQEN4DvAqcK
         3sNgrnWoCLtygy3athkfGvs6WeHOthJkBdhE7LceqjPoQIuXIOqXMonqB9SPs6YMVEsR
         0li1SCzNfA/JD4x2o8KXuafB88rBql8NBt8f7m8MKKGa+WFi1w+VNW/8PkG9OGGxuSc8
         K3wccpXWQR0LeBvG5kXZP4foc0RDRrcBUPEfrf9CkLuGz1yyLBcTVD2lJZ/M6E8QIRlN
         zPDg==
X-Gm-Message-State: APjAAAWsyg2p7rdnT6sKF6sLpyuY8HKt6eTavSRmljGyAgLqRuVooUSy
	2dimU+/S5lZYBQAfvCDgZxs=
X-Google-Smtp-Source: APXvYqx0f4YYFE2ADWdSI8FSdrKbXneLKn57atm72VrtXN9as5TjX8BjOGOr3zYEA0QnxU2CyUAcFA==
X-Received: by 2002:a1c:4c5:: with SMTP id 188mr2829714wme.82.1576109256073;
        Wed, 11 Dec 2019 16:07:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6650:: with SMTP id f16ls1553303wrw.4.gmail; Wed, 11 Dec
 2019 16:07:35 -0800 (PST)
X-Received: by 2002:adf:dd8a:: with SMTP id x10mr2708903wrl.117.1576109255458;
        Wed, 11 Dec 2019 16:07:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576109255; cv=none;
        d=google.com; s=arc-20160816;
        b=cWOo0fxlzW0ggtdE0vilzrXAMS7LMpLfuS4wnu6PGUkHLcvxqa0mni1c1FngojF52t
         L1Xml8M2SiS9tqWqQQIqeaRit24fJr6H+FJ7jQLBNQ8BjiQYej3p1zxaDEJP3KBNFm88
         zPFfHOz5FEeOS051KVMeVSvqsTmhtR3kqhFH43br6soKNLLt8H+6VFho0arqCMxEDvvg
         UoJj1SWrOJYPNBXq3uDX9+2uolKc5tEiYYRWL9UMMHwV5KqQMb4u4PeW9DmHBNoKzz/T
         aV+nPmXBvbbyCQMXtZ4OP//qOcHuwYCjvHsbbLwaPZhIovFlFfS6uJx2lCjSBE6E9u8B
         y+rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=+h6zMTJd2eON2xkPbR4jSlI/q1iX/u3EoAW/W4Wdsws=;
        b=zDLPWzC9fV800tsGOo5M0QXTEWjeY4KdgouyAWG2OwO/r6EZP2tpaChiAOwsmkIi1h
         iiN8K8/+Z0mlLLHNc8hYQOV8uJWKpgeUfh173nzIMOsdWS+0DD72DKlR5bhN1JzGaLV5
         BUfnPzLIdq5d0i4e6Rw0BaIoEQZjXy1aaZLtutENaspcYDiHQvly8u5GUGzegPlY0vcw
         ykaqyXu+rs2srf7y2jNQcFpFG9hoZ8yXqON52QFzqvAqT/hYLw6/yCHtji1NXeV8Mks/
         x8LsjPPQuVf73rmNxwygUZLn5Ees0w+F+5voWFTJNgbbMRoUTqV8xuRnYWnWb4Gs6MLK
         ZYyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nflDkvqb;
       spf=pass (google.com: domain of 3xotxxqukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xoTxXQUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 80si89074wme.4.2019.12.11.16.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 16:07:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xotxxqukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so273702wrm.23
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 16:07:35 -0800 (PST)
X-Received: by 2002:adf:f311:: with SMTP id i17mr2688986wro.81.1576109254697;
 Wed, 11 Dec 2019 16:07:34 -0800 (PST)
Date: Thu, 12 Dec 2019 01:07:08 +0100
Message-Id: <20191212000709.166889-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.525.g8f36a354ae-goog
Subject: [PATCH -rcu/kcsan 1/2] kcsan: Document static blacklisting options
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: torvalds@linux-foundation.org, paulmck@kernel.org, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, tglx@linutronix.de, 
	akpm@linux-foundation.org, stern@rowland.harvard.edu, dvyukov@google.com, 
	mark.rutland@arm.com, parri.andrea@gmail.com, edumazet@google.com, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nflDkvqb;       spf=pass
 (google.com: domain of 3xotxxqukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xoTxXQUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Updates the section on "Selective analysis", listing all available
options to blacklist reporting data races for: specific accesses,
functions, compilation units, and entire directories.

These options should provide adequate control for maintainers to opt out
of KCSAN analysis at varying levels of granularity. It is hoped to
provide the required control to reflect preferences for handling data
races across the kernel.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst | 24 +++++++++++++++++-------
 1 file changed, 17 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index a6f4f92df2fa..65a0be513b7d 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -101,18 +101,28 @@ instrumentation or e.g. DMA accesses.
 Selective analysis
 ~~~~~~~~~~~~~~~~~~
 
-To disable KCSAN data race detection for an entire subsystem, add to the
-respective ``Makefile``::
+It may be desirable to disable data race detection for specific accesses,
+functions, compilation units, or entire subsystems.  For static blacklisting,
+the below options are available:
 
-    KCSAN_SANITIZE := n
+* KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
+  any data races due to accesses in ``expr`` should be ignored and resulting
+  behaviour when encountering a data race is deemed safe.
+
+* Disabling data race detection for entire functions can be accomplished by
+  using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
+  ``__always_inline`` functions). To dynamically control for which functions
+  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
 
-To disable KCSAN on a per-file basis, add to the ``Makefile``::
+* To disable data race detection for a particular compilation unit, add to the
+  ``Makefile``::
 
     KCSAN_SANITIZE_file.o := n
 
-KCSAN also understands the ``data_race(expr)`` annotation, which tells KCSAN
-that any data races due to accesses in ``expr`` should be ignored and resulting
-behaviour when encountering a data race is deemed safe.
+* To disable data race detection for all compilation units listed in a
+  ``Makefile``, add to the respective ``Makefile``::
+
+    KCSAN_SANITIZE := n
 
 debugfs
 ~~~~~~~
-- 
2.24.0.525.g8f36a354ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212000709.166889-1-elver%40google.com.
