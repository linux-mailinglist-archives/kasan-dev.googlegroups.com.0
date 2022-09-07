Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5O4OMAMGQES66AHKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id A3B525B0B96
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:39:12 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id bn39-20020a05651c17a700b0026309143eeesf4719313ljb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:39:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572352; cv=pass;
        d=google.com; s=arc-20160816;
        b=XJz8wxJgMf0K4GBWCZgSdhh7hMQfDQQz1KbWqu2MR9IBqr3qqprxUTdeRizVrEB9Yy
         tL++Ay8uAZJZuK0eNrXcZnl2KWvyWg1SawukVNFSxYGMW7u8DQIvKyQDQ74Lkx5iLwOa
         MH8I01LIizW1pIo+41Xk8AX0Zd6n+BOC1sHeJ5Q7let4oaUhykHm/2E3ig5bo7B3a/3S
         dabsZHl6QACS6Il3qjtZTMEZdFBYHRtx02UabWZn3OsIdGHTT3LhESmybGwdmu4UnS6u
         TWVICn1Mefze0WsaRVIrX2h3RuJ07LnCO4NVh9bhlTlUfvOOb22hO/pxCzLZU8Q5WgY+
         Gk8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jTcH/cUGdEi+Ht+joB82sfn6JfSuVPaD5iCyku+6erY=;
        b=WYm82GquodV36CcLiQ+0GdGfCt/AVhklD7ZGyQgZ8CuMAdF9ObLc3JLlkBuO7PNcAL
         VOXm9zd0c/XB6RCcFfBV9EiV6DJ5FYSQm1/o7cWBIxXEQu6bs+EnwO/3RvmX4S4lpeJH
         v9/mCBV6EpKG4OnmNoSxiAS/mbHei4E7R2nVxt0q1Ro0bbVG4ZhOUCwgjNAQpDtvRkCF
         8MTmSSj3jYnVzGtdeFZlXhw6I5B5E9Z7xNd+7DOs9QAKiezcielBYhpdgVh9B49fheMU
         7SdevW5LHwUDdkRvo7pojC3OZmnpUM67fn+BRsgHPfpq4p1/TaYbYd5384dhor9R93MZ
         jxLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dko2SfaL;
       spf=pass (google.com: domain of 3pdcyywukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3PdcYYwUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=jTcH/cUGdEi+Ht+joB82sfn6JfSuVPaD5iCyku+6erY=;
        b=XbTBb18wyNoH/gKWii7h5YF8u6AMZsqugpAj+4cICVB5Ma4NnQjlRRaOyhpLvsTpYq
         cm/MCT2qFVXG7watueLaOjrGQZxR4FTRNvr1fcUIvW40OaSUG+Dq4vjsB8qjaFTd8X+8
         IVWIQNL3pjnwpvoS2k5zBpvtqcU3YdfD3zkTbtTqq7Dpou6Mn1rldDTcnTCzUhDPFyzJ
         +rr3K82QfcaWY8MTUqjC2e/ZXakjIRaiLZ9Xd+lAASyU3Oyf13dBz9hcjpdZcZTw1eSr
         v9pDfpFvAYgd0AHN0P9XUWRsk5osSrIyb4BLDIY7IzWkWUxjk70B9B+2rQKbAJVIUrPW
         QwbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=jTcH/cUGdEi+Ht+joB82sfn6JfSuVPaD5iCyku+6erY=;
        b=CahlRFMSmCAc7ulwy1W7tv4PRwu6ntRcXcbYZqq+AwU29x7cK+Pz7k3LNMEc5+uE8O
         DCGhzsdMKZk/sK4iOx2tnGAt7KTWfpXTJwnDiFyXgAdU/9IJiFiqKAnFiC4zm56HT67R
         9twzQ7OcuEirAc9z1MWdCCC2OVhxHymSd3/tYKMuagfThqGpkbqsWi8UESrTnrQImDm+
         kObfGp+4OLftrtkqCpAD4eGN9IUW6NB+GL+KWPpCSR2Nfl4MftGdrXxse7S/YRXNiIeG
         bmfWaWzYElHDipChdmHpnvoXZHGcu/LvCfXBDX815GacW3zMshdBQldd99gk2yOuwmhf
         nNNw==
X-Gm-Message-State: ACgBeo0ZE5htXZXvi0qadw/UKKG2UuN+LqQbqcRoaHljm653Kf9VbLAN
	KMenrZI4DLWjo3803Q2pLxM=
X-Google-Smtp-Source: AA6agR6k7ZsS9ncYfpqGzCqffCwnzX+opGK7yOfvYPT6SaZjichkdEoj9l3VctPovDHIa+Ul2kmJuA==
X-Received: by 2002:a05:6512:110f:b0:494:a534:981d with SMTP id l15-20020a056512110f00b00494a534981dmr1574518lfg.376.1662572351888;
        Wed, 07 Sep 2022 10:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ec7:0:b0:261:ccd8:c60 with SMTP id h7-20020a2e9ec7000000b00261ccd80c60ls30115ljk.10.-pod-prod-gmail;
 Wed, 07 Sep 2022 10:39:10 -0700 (PDT)
X-Received: by 2002:a2e:81d3:0:b0:26a:612b:ffc4 with SMTP id s19-20020a2e81d3000000b0026a612bffc4mr1233212ljg.301.1662572350235;
        Wed, 07 Sep 2022 10:39:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572350; cv=none;
        d=google.com; s=arc-20160816;
        b=qQBGMq3hZO8lzLySBC6PDsc4CyPUIGBKIxpEJHUDyZRCjFIrPgKcbkdHWopwwyEN+P
         AJ9h+84wXx7C34hRM2hSsDAfB69eELa1CeIDoF1CkSM4BqYgYSMLqoHIdB9t20/PJIx8
         Vtz7eX4GQPWd0szf4gFtF98lz6avWQspfTf4aPCa3jQ86LcXqSROwxOhCWfQzDtz4P74
         E7u/m4MPhHmWcH3Wvbd4/fA5u4WlnendTEz/hpkVP3MpqAJYMAiIBgKhb75ZLtJEBSng
         e6pKl2zGw2O3ARAQnHe7rMOHKNxP3vH//Y0+KQScUDRyNV6pbGi7bLUHv4Z4/VN13Iqa
         87Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BmEi8gIwQcUUQptKaHcLNwXSjRU/vHM6B2OOTGvVDXE=;
        b=rR9d42qWzI1dRb1x6Z8Q9PRgWMwad9cR5CJ9V2OoAT0MvKGgA3X71JVNYFZM3UBcaH
         NrHDxm0Vfx4am9ZuwCI39TYJ0tVW3TsMcAzIZS9p9c0qTUED9ud6oPcRCMlnLHulSDKl
         AU9m/jPmnREDvcwHmC/vFXnm+hE7gEApQ4gN1N125PJO7mi87BRTZvQIQqj5QBXpV8r/
         qzLGJl6UdUTkf3j/VPbgqYQp1eP6GCJUxTShmzG5wlUYUAC8/63OgD7JFkQH0PWgOdw2
         wb7i3N6RFrvm0FU9tBEIuCQ1BqLjqiejboJ5y+ZzVdeO93+R/9CHXwtkPXdIprhws/5p
         m9pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dko2SfaL;
       spf=pass (google.com: domain of 3pdcyywukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3PdcYYwUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id v8-20020a2ea608000000b0026ac5bc6d39si202019ljp.7.2022.09.07.10.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:39:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pdcyywukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fso4758500ljj.14
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:39:10 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:ba52:c371:837f:3864])
 (user=elver job=sendgmr) by 2002:ac2:5ece:0:b0:497:acb3:a6f5 with SMTP id
 d14-20020ac25ece000000b00497acb3a6f5mr554128lfq.112.1662572349920; Wed, 07
 Sep 2022 10:39:09 -0700 (PDT)
Date: Wed,  7 Sep 2022 19:39:03 +0200
In-Reply-To: <20220907173903.2268161-1-elver@google.com>
Mime-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220907173903.2268161-2-elver@google.com>
Subject: [PATCH 2/2] objtool, kcsan: Add volatile read/write instrumentation
 to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dko2SfaL;       spf=pass
 (google.com: domain of 3pdcyywukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3PdcYYwUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Adds KCSAN's volatile barrier instrumentation to objtool's uaccess
whitelist.

Recent kernel change have shown that this was missing from the uaccess
whitelist (since the first upstreamed version of KCSAN):

  mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e55fdf952a3a..67afdce3421f 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -999,6 +999,16 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_read_write4",
 	"__tsan_read_write8",
 	"__tsan_read_write16",
+	"__tsan_volatile_read1",
+	"__tsan_volatile_read2",
+	"__tsan_volatile_read4",
+	"__tsan_volatile_read8",
+	"__tsan_volatile_read16",
+	"__tsan_volatile_write1",
+	"__tsan_volatile_write2",
+	"__tsan_volatile_write4",
+	"__tsan_volatile_write8",
+	"__tsan_volatile_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907173903.2268161-2-elver%40google.com.
