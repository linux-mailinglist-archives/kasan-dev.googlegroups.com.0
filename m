Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVW67L2QKGQEHCIX6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 568851D52ED
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:03:52 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id w15sf2834305ybp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555031; cv=pass;
        d=google.com; s=arc-20160816;
        b=eZYat3yaeFg+l4b37Xe1Y4q/Eq5auTiyMDS6b6iViG8GdYWFFzNrKEmvPLK3CLBHsw
         F3cfz8qsvMUYGSraj0BTveJbaXxbj3d/VMiGH3RscGNlAr8dbp13IBaLwae/L6roPyNQ
         a6m+Z/PSQKpC4O7tlLfQjp5qGKBbXTSZ36i7dewSt/O/iLohypHJk9AM99E+1RDC4wFx
         lwAiMbd7DUYSE9IT5yAhJ/7EvXekUwQmUQzgcS1wBTCqSFOBS8AHKsJGqnWlXDiSwTiR
         IyodheNlXZbr3PY2oI1qG9/aI3Lvvvj1GP0IPt+p70wadZf69U15O1PKlL/n28B6hSbb
         bhkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SuyHc6WA1GRvKR8yDl0kDNUh8PrnJx+RlJmny347jQY=;
        b=MHG68mS3EbCIPiXdPaqOVSyIc95nKVIhVWzp1zDUWW9VgwP/jrQbk0rlkbZSRFSuV3
         POac6HSzGOMLXI6LP101P53pLkdy0PZZDeH4GFJb3VKuRcScd6pIjfFH8drigfN0N38x
         i/RoJo0AA2ogqvNV/DEpIxnIXF1ckMuJg7Jbdf8BbKIFW6angaPpHtngadqWKrsA1xcd
         9jMCGdOZRpuIuThQ9KzEYhtBMXSZe4diTHUVdWbz4SQGqTpfVNY8/MiFfWtZlpFDcPIq
         /yxoBqLMmjVdZGEdtM0Qd+CnYNahR5YrgAG2QQChzix/JDcEIOsqpEVAxgCgeBA0ib7X
         Tawg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nsQ711Ia;
       spf=pass (google.com: domain of 3vq--xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Vq--XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SuyHc6WA1GRvKR8yDl0kDNUh8PrnJx+RlJmny347jQY=;
        b=dMJKtWawAbHlu6S4mzo41GPGR9B/wwXztEIk/6DXoYfJqcUrMCwrR+pGeiJAyLiUm7
         PlxRisPlQkhimYgr7EX1bw8WDjPHcBKt6w4ocUFgXl2R/HgQK9dA4kt/ak2fDbX8Cyin
         iQgaN4d0PB/xeqaCBkldggU8C+kiGEqjDIAzfKYNvOUQ4ejQ1guCIPNv5J4++SFjVv3p
         wtbvf76pkjJgErNC2GOa1YcDDnellXrltb/vIZ4hwzOW+9duNGeKUVQ1Gjt42BQ/Jj93
         gwjppX4dHtgn0qEZx0YjYFzmMHYU0fxlVXpcR6HWvHEM6zrVoDp5LFoJ0yRoHeuq9lmM
         OP9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SuyHc6WA1GRvKR8yDl0kDNUh8PrnJx+RlJmny347jQY=;
        b=ck3UI5NrhsFOrkpMknjhyGn4NSzMG/dPmLTaz8aTpOw6Oz8RqRV/9m5EyuNw8Gr6vj
         OfFrcq9v1xnNMIWzLa+VVlzMH816GYspV0oB6DO98mnhclDZMrVZ0RpAHEQbTHGP3gD6
         8tByxqIEmTx5UEpxq1Ur6H89C40Ug2r0wzdKK4Q1c2xEFdcDxhjvkSAZ0WJkppbFmNH/
         EMxUQ71HlOLqrFbY3wkKE3UPI12MQVjDPgJFAOAE7f03AQIzKjYe+alo8D5PNrx66XSa
         mc1uiq4yrVQkNSWpALeRqvqKjxYCTUZ+709rqUN2wDL7dy9uMCDk1sFR5A1MGNN/BvXt
         ZPIA==
X-Gm-Message-State: AOAM53236MjFmBkpBYRjYzg566paFTpUaQZQl3oAL94+AT7ec6pRxTix
	CzSfyFJn7Eizfl1ijzkM4yA=
X-Google-Smtp-Source: ABdhPJwgXTMR1JKFY9roGnsXn2edpEenHEKieVmIvao/0Qot0+X7wPf6Gsez8xxUOZHJ7X1BOKIssA==
X-Received: by 2002:a5b:49:: with SMTP id e9mr6752543ybp.447.1589555031099;
        Fri, 15 May 2020 08:03:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c751:: with SMTP id w78ls985893ybe.4.gmail; Fri, 15 May
 2020 08:03:50 -0700 (PDT)
X-Received: by 2002:a25:af4d:: with SMTP id c13mr6494854ybj.217.1589555030693;
        Fri, 15 May 2020 08:03:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555030; cv=none;
        d=google.com; s=arc-20160816;
        b=xR0OKSXuuzxr/RA3IpjwGgLJExJjIGEpD+sTOlvOLkSaSycC3Fqrtr/dQB/uG8/GDZ
         AjYi8Z5Svlgihty31P8Dy86S7dbptN4lMFe8z+vgpHEQmkROoOf3eKArbqi6L95AK0vI
         X+d0QJAc5r/9VjKuz12IniNV7sNs7Jg7nZtZvC8q6JttnNLPHhZJRtjxr4wOGMH/DmOu
         ZqF53rRfO5KTuDIZNg/0V86jTWTr2x2EpBxlYo8q7pj6DatZM7VaqJBRlo3t+SvPPj7f
         viEKAu3hlyLmYah2+qdYq+onZROGxC9/6xHA+6athvqh9rcH50iQwlDPt/ldYd/1KusW
         zUhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=COp0SyeTFByf68VoAMfHccz/8jBHCco/jZeKm/gYFRA=;
        b=NzU9b5sQDYCNn+7kozYcr/9WeNHFYdN6elXVsQFAwyLGIzrOGTgvl3xPmBjE48j9NX
         TwAMc3UuCzmskIzdEgRzwiKBy7nLypVNOOUS847fJ4S1seWE9cSW4HLK4i1BRzZbZa4i
         BoNar7xP7+rfPIhdHMwl4P2Wh/VDZ5R+/J4scDGoMqVQhFFz8BbU5EoAOKUci6optuB6
         vLiMg/Wzsp5sWjvuIV+32luePgOO6LGzebNvhbfKwYKlWDsLDSz0lSiYC2m3iSJr6YGg
         Oj0caYvRsFEzFaIKPWzSIesQWfhQjMZDJhKlAyxPq1pXG5JxS6nutUrdgPSgukDVEy1W
         SWcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nsQ711Ia;
       spf=pass (google.com: domain of 3vq--xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Vq--XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id p85si152884ybg.4.2020.05.15.08.03.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vq--xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id n22so2724789qtp.15
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:50 -0700 (PDT)
X-Received: by 2002:a05:6214:3ee:: with SMTP id cf14mr4069665qvb.128.1589555030260;
 Fri, 15 May 2020 08:03:50 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:30 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-3-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 02/10] kcsan: Avoid inserting __tsan_func_entry/exit if possible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nsQ711Ia;       spf=pass
 (google.com: domain of 3vq--xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Vq--XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

To avoid inserting  __tsan_func_{entry,exit}, add option if supported by
compiler. Currently only Clang can be told to not emit calls to these
functions. It is safe to not emit these, since KCSAN does not rely on
them.

Note that, if we disable __tsan_func_{entry,exit}(), we need to disable
tail-call optimization in sanitized compilation units, as otherwise we
may skip frames in the stack trace; in particular when the tail called
function is one of the KCSAN's runtime functions, and a report is
generated, might we miss the function where the actual access occurred.
Since __tsan_func_{entry,exit}() insertion effectively disabled
tail-call optimization, there should be no observable change. [This was
caught and confirmed with kcsan-test & UNWINDER_ORC.]

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index caf1111a28ae..20337a7ecf54 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -1,6 +1,15 @@
 # SPDX-License-Identifier: GPL-2.0
 ifdef CONFIG_KCSAN
 
-CFLAGS_KCSAN := -fsanitize=thread
+# GCC and Clang accept backend options differently. Do not wrap in cc-option,
+# because Clang accepts "--param" even if it is unused.
+ifdef CONFIG_CC_IS_CLANG
+cc-param = -mllvm -$(1)
+else
+cc-param = --param -$(1)
+endif
+
+CFLAGS_KCSAN := -fsanitize=thread \
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-3-elver%40google.com.
