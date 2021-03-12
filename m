Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPHTVWBAMGQEG5YNVZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B6C0338FEA
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:25:01 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id o11sf7967974lfo.12
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:25:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559101; cv=pass;
        d=google.com; s=arc-20160816;
        b=joAOZsN+7CXMWXrOPhvw9IweM3QQJqFLlWN3XqkNsqMpbsl8VKNd1XDghypxr4SnM7
         9wby3wbtM9ROUvQz1SKFzpIf64BO9wS+AviEzWd2eZYGgdDv5kwLA7Xc75r15Xns2ssk
         CDfcUbO5ZXXIdfd3tWnSZx60ABYvN0WkzJxmx5DKTniR/Jlyvt1yaGnGtl1ZWs+tps5M
         i4Lnm9fNRJ6JXjBfXZ3DT/wrxlshhSfTBUKrtoL/vc88t4e1nuDf7PFOJFx2jTPDkrEK
         1AFv84yt857XefhGPwGktCIZBjVsHIYIhvMlYncudrXYCBlaVODjgGOm6T89QBmYSnmn
         IfDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=NkalEToFiEElym7Xaz3S1QyMgIr5S07ag4iMnXdy/MM=;
        b=nNUdskW5PTTlelCokAMHkzNGcxILkLHSsMpQnXj9zXEan+1y30w2m6ek3AxypaZob0
         osDoKE9qXrzN4ydWFOaM1GEuQ7BfLz/D3D1ZF0SsnVHl5edB5lH31KXitogxqBnCAqhv
         J6/PHdpNmHlikxZ2MFEUG/Ut1qZvPdrBYc28Qn/Q7ArH4ps38HlgFB4Q1Yd4AxwU07Ge
         wWWgjXkzn/r6z6ncO0+GnJj/yyJkAD8eoMcgeLftzv7iVIgkB25cx1MiRM5pn4WrkDZA
         2QBbQD29LCi/tgUGfu58Sch5qO+nnlC4K1ZNAsbvRPTy2pH1dQZSl4qD6FktEumXJRyw
         rHhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rC5oeVOt;
       spf=pass (google.com: domain of 3u3llyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3u3lLYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NkalEToFiEElym7Xaz3S1QyMgIr5S07ag4iMnXdy/MM=;
        b=ETEj9h7NI/YaVZ2DhATsH1kdCsDZT4bd7NOh+qvAXRXIMsu1miAOBFsKMcWsYuDad9
         Gd6pUHu8QeGYRvfbt+dzymwqCw6ea42Pm1RQcJTUL2ZeWlo+unoXSUDbci+7uoKp3Hse
         L7tbD/9G0v5JD2b7S9fO+fSdn7Qvuns5UQmq6sEeYwo6bCp9CR2gS66hYihvaLKKlr08
         J6SUqZmqL6JoBWvxx8ggpUCUo5PevnO+NkiamGukLb9r9/dWT6jnF9KU8yvUzDZxhidN
         y15cHep+iCb2i3fa92bcFKzhr8ywMwFDPPnGqWNiiQAbf/M8r8mfj5VMpsqMVIex8wsP
         +org==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NkalEToFiEElym7Xaz3S1QyMgIr5S07ag4iMnXdy/MM=;
        b=s+xWqkN0V4YUWE09OKB4UvHnr/U5YApLtmU7tujvdN1n0oG1u03UrsFs7Vr857xB/b
         H40ZIrtoP5E5JBtDlRt8oUuXpv4OYjYzhfbdQP1PdqpFyaYhfIe59bcyCe7IDNdNS24d
         m9JhJNZY/hOFz6BKPfIDtygsoITn6cbdBdMdC927DrK9LkVe5ksCKOi+DqOUv2QWw9i1
         glbE7Hf3IBbEuHgGygB6Tl7/BM0/dWa6tNBO4notaK/e8mmSuFO+sFZGAtPENt1Qh2rb
         5w2UAcqhm7f00ruQu7wlqmf7pxr2eFaDdY3tIGPQ4huyuoHGRlxFxWKeIhir3aIGs0Bw
         WGRw==
X-Gm-Message-State: AOAM532QDnjiGqn0QnLxBUdDS2sclcJ8kfgFH8rNk4pfkzQCm9mSKQLc
	1aXZ1j4Q7bF8C7Inz1shAgo=
X-Google-Smtp-Source: ABdhPJzfwaYw2TVH/xZvPl//VyS0fOkvzDEwt86Etdnz5AgrzXjy22ANalwB5jvXSxw4r+Pj7DbKbA==
X-Received: by 2002:ac2:5fa2:: with SMTP id s2mr5402933lfe.486.1615559101199;
        Fri, 12 Mar 2021 06:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3504832lfu.3.gmail; Fri,
 12 Mar 2021 06:25:00 -0800 (PST)
X-Received: by 2002:a05:6512:12c2:: with SMTP id p2mr5365346lfg.339.1615559100183;
        Fri, 12 Mar 2021 06:25:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559100; cv=none;
        d=google.com; s=arc-20160816;
        b=rKG7pcLLITKsnHTFoEYYGOHBlx4HL7UxrRnY4mUeRnrvt8zhVfzrHS5th4UD3v0O7/
         ifARcPPxjZx2R8XHsTNyLMtHkbmMjWpITU7A/D1KAeRW9Vw1exPGfSI5kXW8WbPxCul0
         esq70iAQ9nr4sgPv6+4nWLqzWGcqI0CPeKp8GmfcR2BIPJKzXrDGsV4YSbAgNmwIdzbE
         jlkLDpgaYYw+cWlOgtYdrVM4oTVt3c5Gd1LYEsZ7RgQXDsx30grKrwgH1LhHaNjfnA2v
         a6nd/PR7mYmUsxJ8kfrzvQNyjUni8dKjtnxf9esudWf3plFwov92Wr2r5efhYzfrzM7e
         rTgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ygfy34R30Ir5P43bAuVWD7PsEpaVeYrJUsfKdxJOhKs=;
        b=WH5hUpBtSpUUCwfuAMUmuIdSDRAhhz3crKT8lR0LoMZJRQEfhFP7Z6oQ2UP+y7hRiD
         8lHKPg/nS1RTrUBJshxS7MRmjwhK8cLNE8PqP9A3kg8eG9w1E+VxxM3G2LqQJdcP0hXe
         8YYpbqeZnX+DMf3nB/5b2QZWZ3+c6Ut49Q+Sr46YV8QSokzoMANI+AYbFSu2LpbFHgel
         /pmBtXfPHzEY9jpVYvsJDhxsbIteebzLagPD1pr/rXEYrAYkcLvspjfZmMmSaBWZsHhF
         fyVYUZ8y1n2ZnPsM1b7F1tlXWjMnbwiyheHepxvFuQqOQmH3QDdJj75RyfzjnddykQeN
         uUFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rC5oeVOt;
       spf=pass (google.com: domain of 3u3llyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3u3lLYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id x41si158776lfu.10.2021.03.12.06.25.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:25:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3u3llyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y9so2106404wma.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:25:00 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a1c:5416:: with SMTP id
 i22mr13379263wmb.146.1615559099696; Fri, 12 Mar 2021 06:24:59 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:33 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <4531ba5f3eca61f6aade863c136778cc8c807a64.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 10/11] kasan: docs: update ignoring accesses section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rC5oeVOt;       spf=pass
 (google.com: domain of 3u3llyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3u3lLYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Ignoring accesses" section in KASAN documentation:

- Mention __no_sanitize_address/noinstr.
- Mention kasan_disable/enable_current().
- Mention kasan_reset_tag()/page_kasan_tag_reset().
- Readability and punctuation clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes in v1->v2:
- Mention __no_sanitize_address/noinstr.
- Reword the whole section to make it clear which method works for which
  mode.
---
 Documentation/dev-tools/kasan.rst | 34 +++++++++++++++++++++++++++----
 1 file changed, 30 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index d0c1796122df..5749c14b38d0 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -368,12 +368,18 @@ Ignoring accesses
 ~~~~~~~~~~~~~~~~~
 
 Software KASAN modes use compiler instrumentation to insert validity checks.
-Such instrumentation might be incompatible with some part of the kernel, and
-therefore needs to be disabled. To disable instrumentation for specific files
-or directories, add a line similar to the following to the respective kernel
+Such instrumentation might be incompatible with some parts of the kernel, and
+therefore needs to be disabled.
+
+Other parts of the kernel might access metadata for allocated objects.
+Normally, KASAN detects and reports such accesses, but in some cases (e.g.,
+in memory allocators), these accesses are valid.
+
+For software KASAN modes, to disable instrumentation for a specific file or
+directory, add a ``KASAN_SANITIZE`` annotation to the respective kernel
 Makefile:
 
-- For a single file (e.g. main.o)::
+- For a single file (e.g., main.o)::
 
     KASAN_SANITIZE_main.o := n
 
@@ -381,6 +387,26 @@ Makefile:
 
     KASAN_SANITIZE := n
 
+For software KASAN modes, to disable instrumentation on a per-function basis,
+use the KASAN-specific ``__no_sanitize_address`` function attribute or the
+generic ``noinstr`` one.
+
+Note that disabling compiler instrumentation (either on a per-file or a
+per-function basis) makes KASAN ignore the accesses that happen directly in
+that code for software KASAN modes. It does not help when the accesses happen
+indirectly (through calls to instrumented functions) or with the hardware
+tag-based mode that does not use compiler instrumentation.
+
+For software KASAN modes, to disable KASAN reports in a part of the kernel code
+for the current task, annotate this part of the code with a
+``kasan_disable_current()``/``kasan_enable_current()`` section. This also
+disables the reports for indirect accesses that happen through function calls.
+
+For tag-based KASAN modes (include the hardware one), to disable access
+checking, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``. Note that
+temporarily disabling access checking via ``page_kasan_tag_reset()`` requires
+saving and restoring the per-page KASAN tag via
+``page_kasan_tag``/``page_kasan_tag_set``.
 
 Tests
 ~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4531ba5f3eca61f6aade863c136778cc8c807a64.1615559068.git.andreyknvl%40google.com.
