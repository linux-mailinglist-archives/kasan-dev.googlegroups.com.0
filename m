Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSUGSKOAMGQEO7ZHWEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BCFF63A550
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 10:45:47 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id s1-20020adfa281000000b00241f7467851sf1702576wra.17
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 01:45:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669628747; cv=pass;
        d=google.com; s=arc-20160816;
        b=HvFCIViFs926RfLnAaCRO4jobDUenuBJXP4gaqgxP1JgS6O8GwGc2xAGZsO27kgc8C
         2vS4g+OPJTxlm26GpelIWOzCHJBr3KRa4O9e2JokbMEv/MsyQuMezzy/AAAYGCVvVlXA
         9TjQXkhpryT1LTiU8y+sTKTrb3o6raoxK4I5PpsvajwEPVB40W9uAiOcIbpB+K4OZd6T
         x//7tcyI/cXC6QbkV2L1WG66UAhqjzCiTUx6YyYTaq5N2JJ5Q0FAAYL6gOh9x2kN7Krc
         PoHq+whMcYxbhO/ds8w40c7xFKaemu7CbUP+RfoT7M31CzQFhdtRh6XH6xEABjNW6yBL
         odEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=DbzD/3r359PSylOAKFOdNGoHPmNK9HzpGXAgR/KOWdI=;
        b=wPmgotd3asgiIy63L1p/vydiVT6/HzE991Y5f7bmgw0Tw2Q+mfF43L6tFu3Pgb6Xlu
         ieZpnbih+sGJ90LA6pNRAtdQ3+QVks/czaZ4Xdxb5izJS8/imeJI9ACZsxy1ovUNaRV9
         2bJFZN9oQgjzWPZK3RLNPIBIHKOi0KWvVnicNFwOvkBQnOEoq+lyI++Vicd8DKQ5E/+G
         o4Ufq8C5Y9Ssc0YcBdmIgF5PB4Fy+DYxTb2mkMzjQVVMCEx+jcokd8BAeGRjvyMJwjWs
         QECAHvAxNaQkbEy4Wfo9ZQlomOHdZNJ4/5g8jGnD79/yMwvigTMu9KU+a/u1bKBlhDLk
         0BJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s6w1xbIf;
       spf=pass (google.com: domain of 3syoeywykcyqotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3SYOEYwYKCYQotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DbzD/3r359PSylOAKFOdNGoHPmNK9HzpGXAgR/KOWdI=;
        b=rLd2AR17YcmKKr05Se9cm8TXbLP0UZ6PXqAZsclb3jj7tyooOZw0JgsZzGUrmawW1b
         zw21wQh07gR2jIV2IZ4NXzY1lKj5sPay2IjpL6mS221AmG73CD0xLV2qAT8EEoVyU89X
         2wJFs+Xfz8WTNozmuc4ri1/2RSW9KjGxRcZbpK+wB/Ij6Px1N4NOjo2AIJQWcJnPBq2+
         5yiECM6xMwCRfXZi+D2j9cMiBx4nMTGTgStXiiY285o9gRDXHG2ZAAVJJUFOh15W3IrP
         r6Brra/7M+dH/AJo2gcJ1f6esf3vPJhuDQkHIRCTOXXiA2iByp4J7xWeEMaFPIi/MnbK
         4erw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DbzD/3r359PSylOAKFOdNGoHPmNK9HzpGXAgR/KOWdI=;
        b=H3VOICaU6rr9eVu1Dvxy8v/CiaJo85WRmZuSpTghOKl/xp0SXEmvtcsfuJgXdrVO2H
         DHAaONUlWiqyeZ5igzc8KLwqHUeZPASQcNPKkQug6edLip63LmYvSL3PSJpS/b5pQlka
         gj2VUKwjih7/EZ7HfAMLg4NGLU6kmD+OJWBroOMCOItHW+5/QJg86iIcAcsB25RXBEE4
         ispwI/g1TZY2VMDF6HiQXKF2HTa56XpIO5aGt1Xdg3YJKPgaKdKmcmj/CEIHMQfl2C0i
         Cl01+hG2M3Yjjl3s7x7iOhkITtv/00iB5AuR95YqFOiRBN6z82iC1XBblMWTKSum4jRD
         d+SA==
X-Gm-Message-State: ANoB5pnjcOkRCWTNzZbj2IFUHfLR9WLc5TrC6oCnzXuNXI7BOwQfQGFy
	WgYS+vAjKwrZjHjhD2x40Os=
X-Google-Smtp-Source: AA0mqf5jovZgO0jSSkPH/gYpKVMrzkozbpuo+rT9GH/bHT+KB5N4mTA5PXKw4xOYxFkaYC8h6nQTVA==
X-Received: by 2002:a05:6000:683:b0:241:dac7:5282 with SMTP id bo3-20020a056000068300b00241dac75282mr21128198wrb.135.1669628746903;
        Mon, 28 Nov 2022 01:45:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2cc9:b0:3cf:d483:5d93 with SMTP id
 l9-20020a05600c2cc900b003cfd4835d93ls1589628wmc.0.-pod-preprod-gmail; Mon, 28
 Nov 2022 01:45:45 -0800 (PST)
X-Received: by 2002:a5d:6343:0:b0:242:143f:1d2e with SMTP id b3-20020a5d6343000000b00242143f1d2emr3218787wrw.391.1669628745930;
        Mon, 28 Nov 2022 01:45:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669628745; cv=none;
        d=google.com; s=arc-20160816;
        b=b58jpkl1uf9mQVSE8PzHquRyG5gvbKjsAUP1fwHX2wqC2w1n8xasseMk7Yj23c8E1M
         3+fqqgz2tmzDB+MQkwXaeWgWHGeBAnENwVPvxLx54TpucNAQJTjipM9YmEx/5GernGtG
         CsdHagWf7HyOG4eoFBrVxo/Q8UfO1pRjA9fb2pxDIDQAadr10xiTRCHQYJ1Mmoi+0/tP
         ukHkSGoIigZ/j4iUykmwWJTxW9yvkJI47AyKKbR+LIyK+4nWGZaJJkOkCBHZnBukyBYm
         HwtW2rblWRC4XQUu/qea0M9d4I4O2jbGcADdH0V95uZqchDNMit+ADou7Zq2ESq3mwS8
         tivA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=rXoOet1Rb1vO+RV0XEBtCtgaydxMI/engJANIwuECRQ=;
        b=EMXdz33eYln2AmE839ZuAww79S665pJnOhPAYBwr9z4VhHqgv33caVX0uVupKEId+9
         1Lc2boiernhTmFtCJ/NpByHvRGbwdJme797ZWJpjRciP6fD/1C+p570IJyzLuhsDXBAS
         +1tr3BKQuc8G9bu1aCgAeb9BPdrcgJoNj3TgqgrR+OYIZpjXZei5A43rwFJkDbg8lgrE
         2O56Zv9uVvIRxdzcGzXoSdwV3tE3mpSv3KGR4hlMjH31rV085W9zvvPqVgKo+B7lmvyM
         3scMuxvzcNyBtY6BYSWnu5j9n999IiTzo17+FTw2fn58Pfjbsxc09x/I03ZwH3H+z+x2
         rfxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s6w1xbIf;
       spf=pass (google.com: domain of 3syoeywykcyqotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3SYOEYwYKCYQotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ay2-20020a05600c1e0200b003cf567af88esi765866wmb.0.2022.11.28.01.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 01:45:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3syoeywykcyqotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id j9-20020a05640211c900b004698365dc84so6197968edw.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 01:45:45 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:dc07:26e3:1eb7:b279])
 (user=glider job=sendgmr) by 2002:aa7:de08:0:b0:46a:e4e0:8407 with SMTP id
 h8-20020aa7de08000000b0046ae4e08407mr10060697edv.36.1669628745543; Mon, 28
 Nov 2022 01:45:45 -0800 (PST)
Date: Mon, 28 Nov 2022 10:45:40 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.584.g0f3c55d4c2-goog
Message-ID: <20221128094541.2645890-1-glider@google.com>
Subject: [PATCH 1/2] lockdep: allow instrumenting lockdep.c with KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	peterz@infradead.org, mingo@redhat.com, will@kernel.org, elver@google.com, 
	dvyukov@google.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Eric Biggers <ebiggers@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=s6w1xbIf;       spf=pass
 (google.com: domain of 3syoeywykcyqotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3SYOEYwYKCYQotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
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

Lockdep and KMSAN used to play badly together, causing deadlocks when
KMSAN instrumentation of lockdep.c called lockdep functions recursively.

Looks like this is no more the case, and a kernel can run (yet slower)
with both KMSAN and lockdep enabled.
This patch should fix false positives on wq_head->lock->dep_map, which
KMSAN used to consider uninitialized because of lockdep.c not being
instrumented.

Link: https://lore.kernel.org/lkml/Y3b9AAEKp2Vr3e6O@sol.localdomain/
Reported-by: Eric Biggers <ebiggers@kernel.org>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 kernel/locking/Makefile | 1 -
 1 file changed, 1 deletion(-)

diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index ea925731fa40f..0db4093d17b8a 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -7,7 +7,6 @@ obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
 # Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
-KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
-- 
2.38.1.584.g0f3c55d4c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221128094541.2645890-1-glider%40google.com.
