Return-Path: <kasan-dev+bncBCU73AEHRQBBBPNNYWPAMGQEC7ZWBVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 55CA767B6B9
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 17:20:15 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-15fbd6c0385sf6459275fac.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 08:20:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674663614; cv=pass;
        d=google.com; s=arc-20160816;
        b=grSUZvvwB7ik3yZafqLwfIudsygf92/S1Ueykr9i63tl3yvFuB5ZeIigYsoovNZGoI
         82z0ZwQgHHYPGVcP9M7DkVOmRsOVrlHJ4IvV5y0XLHCS3ZANURvYG9XDkLRZBO4JD/NC
         /2lASuv5g8UZiKxsVC32hKVMa5KgEl+LmYuQQRHuWIv9VLQ6GG/W6CqM/OM3skDlaVoX
         +kStGT0GPoKRSHmvSnZ5aqoGtZ37EGbG/haXRfRAlXd1Z75SREGBJpC0zr8sv5ZbxKMc
         XmL/FAQvlJwe1BkAwX2SxdJnn29Ie4bRCDHeSHYf9neCaCNK9rrVBPKy/yX6Zz1cC++l
         VVQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=23ZHi1nRivK19jAbGy5zDE/O7U+mzPu1NDhCuFrJpj4=;
        b=VaQ3XtY4WOqLnNnLTdW2Gq49c6sp569lHhljOMfPgwp/8ujoYMlL+BowEpZTwQNnS7
         OyO1se6K43taKykXsLGnS9KxjhauAyR6D7hk2es2LNt6nsRNdjwLnD/Zw25ffgyB0cLM
         h0HgojCAdFP6KqemVKWEnNtQZHljoLDA3bo5/F/ETSrMhT9FpgOaasG2FJB3sQSr9X5+
         nP9iKRIVeFg4rb5voSymZ11WQKmsK6eEJsuQriH7iLZlBsjd34j8sKAl9MR26EgC75VB
         BImvs7U8zizFMxUjaZO9NhUQrgToF5roTypD0WnSFmnO3C7plqeP9CsyawdMrVk6mylG
         dtJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ktz/=5w=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kTz/=5W=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=23ZHi1nRivK19jAbGy5zDE/O7U+mzPu1NDhCuFrJpj4=;
        b=spDTZkSkXG0l8dGxcsyDXhdTomDAsV1xdvmke90MCvguVDJK18ZHand5fNvsauG5aP
         ejnaC6SXyHct+91f2Iit8xtKHuCNm+MEGT/5uC/TDuS4QPFxlbVkkZIk1AqO50ubD5rc
         T16mbnuY58IQtzpK/++gYz3MBSWbrBQGLtoGi7J5yv9TvqO+JWuH1MmoB9IpH2aMQ5tL
         2/FrSCWI12YiuC701L7By7g2vzuwSq4udfWAk6YPrWK9FBiG3RRzrcacXfZXVB56SDF3
         DBd4YYc/ZXxqNN4euoMCtq9sHR8cVwZ5iyUe4/UAoyy4XoeR/U9NUTBNRFbP4TQldivv
         6nSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=23ZHi1nRivK19jAbGy5zDE/O7U+mzPu1NDhCuFrJpj4=;
        b=Xj4LAyzHP+naltqinEBuAOX1BX6KNbVyscUOgT9HLiyHf5Mcv51v6NEDBSWJsejvjg
         omAFEntJ9xidNDqrr6xCcIBY8Z69nlo0f/Ummh3/4UC0W5FSammL3MJTQtGo+LAh4/35
         vjikCnl44OEfifyCUYY0JL7AfwBtDForqJovFzXUloEbpZ0AMo5dQJqwYbKk3bvHat2S
         h6sTWlizqnMrqzYQFGqt9hM6paEQ3ywDCJDLkIPD2btcMAseN189eS0hshyzPxeflCDU
         o6/P/kcCjb+Gy5utbmK2i42MemtoBJBCZihIhRJcdOIYaApkp3OCL2htPN6wJh38Cnoh
         9AmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr3RU4EYxso+kadMWIoe/VSoju/SCdemAv2mseSnweZOD/SiALl
	DZaAS2AgroiYU+Vrdp/itOw=
X-Google-Smtp-Source: AMrXdXuvFE3Vfa23P2s7NqlWoCko37b6icO1Q4wDOabqRnqsF8o05OUlv68sNI7+Tp2dHgakuQey8g==
X-Received: by 2002:a54:438e:0:b0:35a:8a2b:e900 with SMTP id u14-20020a54438e000000b0035a8a2be900mr1611165oiv.140.1674663613892;
        Wed, 25 Jan 2023 08:20:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e82f:0:b0:4fd:e348:4f39 with SMTP id d15-20020a4ae82f000000b004fde3484f39ls977230ood.6.-pod-prod-gmail;
 Wed, 25 Jan 2023 08:20:13 -0800 (PST)
X-Received: by 2002:a4a:e4c6:0:b0:4f2:b25b:574 with SMTP id w6-20020a4ae4c6000000b004f2b25b0574mr12575502oov.2.1674663613390;
        Wed, 25 Jan 2023 08:20:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674663613; cv=none;
        d=google.com; s=arc-20160816;
        b=kZBCJ2H/1LmdKrPEos7uUHEfXie593TigRJB2pesPUD9DFnrayPkpomBFL/LCTlooV
         aQo26j44GhW/ovFt0QH2ceUKN9Qdan81P5oi79JDhoRom3630CujqE7xm6ZLC/dFYzPC
         aybIEFCNNmirqTe9SY9wiONBsYoeuOesCQm1dmYkvtpFOCBtaz5Efv+OymZjzKw2yUfT
         4meOpbNb2flmP9XppMZXmzt227iDKlWOUvhLitNKi6v8osKjZgpyRMICEIt9cV/HtsgP
         V0hpwosbIiv/P7RfW48zgg8i3uQxCwF8MHgm9bVoC4VKw1IS/qE3gH6fRwlmYvNfCKM1
         ap7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id;
        bh=nMn9Ilyy+cSX/OjwZf2VfJcnLecNkaaOVTEoME9LXHU=;
        b=d0yxudYPdcRFOTInQpE95ln+5/4KJ8sfrewCMyWXTYm4uNTaupfh3CkpVgi4k+ud1a
         HAreGsuSWejZ7HIZoSH/tBFALjzY1q+LvcqeCnAIrMYH89y7mvnaFto+qY/p80VjiYxO
         JpMHKPzGUonQugEfs+od4d/O7K1xOycTKyuM0+42nAxMfSVw9um+qlPZi+3u4YjHBi2J
         KsNx2cBvRrwKJmUPql+usQtE2Tw6/7gIFl/XjuFKUkUZ9TbVqhgS9TQckYLHSNKi/+kF
         NlSasl7+QFHgyokvwYVJQVjdMONAI2OU7sNgVMJGxweN92CYjWiVmOwbRbZ0uzgBmuAP
         3x1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ktz/=5w=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kTz/=5W=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c184-20020a4a05c1000000b004f52827c8b8si429136ooc.2.2023.01.25.08.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Jan 2023 08:20:13 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ktz/=5w=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 19B8361540;
	Wed, 25 Jan 2023 16:20:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 49755C433B0;
	Wed, 25 Jan 2023 16:20:12 +0000 (UTC)
Received: from rostedt by gandalf.local.home with local (Exim 4.96)
	(envelope-from <rostedt@goodmis.org>)
	id 1pKiVP-004Mtc-0i;
	Wed, 25 Jan 2023 11:20:11 -0500
Message-ID: <20230125162011.031705664@goodmis.org>
User-Agent: quilt/0.66
Date: Wed, 25 Jan 2023 11:18:31 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: linux-kernel@vger.kernel.org
Cc: Masami Hiramatsu <mhiramat@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com,
 Randy Dunlap <rdunlap@infradead.org>
Subject: [for-linus][PATCH 07/11] lib: Kconfig: fix spellos
References: <20230125161824.332648375@goodmis.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ktz/=5w=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=kTz/=5W=goodmis.org=rostedt@kernel.org"
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

From: Randy Dunlap <rdunlap@infradead.org>

Fix spelling in lib/ Kconfig files.
(reported by codespell)

Link: https://lkml.kernel.org/r/20230124181655.16269-1-rdunlap@infradead.org

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Steven Rostedt (Google) <rostedt@goodmis.org>
---
 lib/Kconfig.debug | 2 +-
 lib/Kconfig.kcsan | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 881c3f84e88a..6426dbf99c12 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1917,7 +1917,7 @@ config FUNCTION_ERROR_INJECTION
 	help
 	  Add fault injections into various functions that are annotated with
 	  ALLOW_ERROR_INJECTION() in the kernel. BPF may also modify the return
-	  value of theses functions. This is useful to test error paths of code.
+	  value of these functions. This is useful to test error paths of code.
 
 	  If unsure, say N
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 375575a5a0e3..4dedd61e5192 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -194,7 +194,7 @@ config KCSAN_WEAK_MEMORY
 	  Enable support for modeling a subset of weak memory, which allows
 	  detecting a subset of data races due to missing memory barriers.
 
-	  Depends on KCSAN_STRICT, because the options strenghtening certain
+	  Depends on KCSAN_STRICT, because the options strengthening certain
 	  plain accesses by default (depending on !KCSAN_STRICT) reduce the
 	  ability to detect any data races invoving reordered accesses, in
 	  particular reordered writes.
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125162011.031705664%40goodmis.org.
