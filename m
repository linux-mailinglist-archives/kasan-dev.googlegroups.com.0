Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUX77OMAMGQEXB3O3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E7CD5B575C
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 11:45:56 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id q16-20020a1cf310000000b003a626026ed1sf2718271wmq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 02:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662975955; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAFc3paiyaH2mVjO51PmtzhVDcbZRyj6z0kC8J9NYxE8dAU9NOcJ89lN6U91mqUO0e
         /nKVbJSiaypGwrN7c0XxM69NoEZ2IwjB96kmsn5oEMXi9gggeeWU9V0zg69NUId+B1v6
         WS+NeB3iCpUfGC3SVgIdhMoRQ6eQaxvH4yhNQSTFJxrWNarzWVcCIYMjul8fIvzFOX8L
         Hbx7OS+0U0zQq0wLtU/VLgsC0cWJCIhjzp/oT0rkXy1DWky7Bfj3/UG/N/MqUj14lDgX
         d5JT/tP4ClwrfNb07ViFrVkeIznQlaCSxCjHVmpRvJgrIiHc7Tf4ncp0dkTIWwajDs04
         c/jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=f87+nqURnyDRSJeIL86At5Yh4mkBOcy8FgcdYUzlO/I=;
        b=gZrBG/BEdWwQg9LEmuvil9bxEhUhw83pE2tAEONzGe5+99gSZIFpVyCj5VKS8guap5
         n7ZrLRfBLuOBgWWxisXNd0q3CdmQjo12rYPX1nFGXlIZ1CZvLMygTs7noJEvpT9fOyaB
         EqaZZDmeCOnn2RgN6PoBbGBUdac7xkcLmAOgyFE7U2W+53WqjmZ3mnaNPgLtOXNGssU/
         Q3RCT/ZlNYEj1BGFFMZrf/vlYXjWW/cXJLKWD/CAJhZkzVQSH/3zFepVIF3/ielJTPYV
         y/7rtrl3eZFEh1fUxdc5PNRvJS4mLcvj1p0IujBjWAb6Qvv1Qkja2kUy+4BBExnDmBTq
         pmwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mzaREv75;
       spf=pass (google.com: domain of 30f8eywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30f8eYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=f87+nqURnyDRSJeIL86At5Yh4mkBOcy8FgcdYUzlO/I=;
        b=p8ggiaaupd0NbPTUADLQwkPcy0Mcc9OjQeQ4VLmVKzbelDzmootB6WTUZUkwT2JD2j
         4eFLbPEcKTfzF4tQxcb/D+s3AtPr3tFVLyfK8vkJ8x02sHiNrWrpxhRfNb8OCm3M2iR4
         ta+rpBokhThxfW7TIAFHiDFAW+HfBcKoW9GP9Br0KCnjZtoNfcLP/1WXnm9bLZp28UrM
         /PKCI1/XKttcOZ0kSGQaBD5HPnZRj6S+7GJ3bhuW57OXb2LCp29qit0XI6GChT2f1xLJ
         oyEyIbP219k54+cJSckevekJmOJTk0KarwSEam04g7vKlU7E+fypHeSdbpmzYoen07aT
         wEQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=f87+nqURnyDRSJeIL86At5Yh4mkBOcy8FgcdYUzlO/I=;
        b=P7K0KC+VIPdql9+eYyg20adojrKeuy7qgQcoPz7M/Wkxt8JpykB9c/Gpcz7UippUde
         UzOCRR8iESDaKbenG/ncsnvORb6UO3E0n/MIXjJK/dwwsbodsNs4bvAJ5G4CYBYFsSKt
         lsfzDzw5t3oUWkJaaKLIIAl1ZxgOJICiYtVxpX7Q2sKrRQOf4brYyjpxCeo2bQ+WDXPf
         X1WccpvISTPQkP2dfTGd9v+rwAW+BjbnJiez3pGIKF1hpLKCwc87QA3zzm6vFlpdUDRR
         IjwESLogdFhmsW0PeLkjS4pYekCuLGSN1nsXTjscemPcGUMl4hBOy9QP0gLKVJgEYUXF
         OVUw==
X-Gm-Message-State: ACgBeo3rDpajMWQe3/Bl0uGSrzdOBcmzUISzmJqs6FZWgzWs+tYixCeF
	wQuapnpI3TymFn2A6kx9IVM=
X-Google-Smtp-Source: AA6agR7HqZWctJuNO/eRJILtQ9Vb0VsziFbws0QDI/lwvgmf1u1ZQc5lexS63CyKX8ndDrfwbClWQg==
X-Received: by 2002:a05:6000:50a:b0:225:210c:a7e4 with SMTP id a10-20020a056000050a00b00225210ca7e4mr14330935wrf.704.1662975955121;
        Mon, 12 Sep 2022 02:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f718:0:b0:3a8:583c:54ed with SMTP id v24-20020a1cf718000000b003a8583c54edls3602434wmh.2.-pod-prod-gmail;
 Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
X-Received: by 2002:a05:600c:4e89:b0:3b4:8648:c4e1 with SMTP id f9-20020a05600c4e8900b003b48648c4e1mr3065119wmq.26.1662975953884;
        Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662975953; cv=none;
        d=google.com; s=arc-20160816;
        b=faBlLLtQ54fv8D5nMscrvnPO7QyjWM5ah8Eo7UXgMBP+9etJQb5Zz+Vf6a3jJSQQG1
         4UhdaaY3X4/OU7EswiEbU5JHPXcLGct7nQwXVEJgXjXDI2dU8DIowkXPKGKG9ARaaCRi
         7s9LgD6AsfSdMJWDSkD/pcfSGbBa38CaNOmRI+FkNSf3zXICV8q3SDB0CPEJHBGBetps
         fd+ZLbSkcOXwYdqskibxliFH3I5w5XjYF7U9DsuS2f1IDve1HKz4V8/KZfNKfzGFDjZf
         FxdTTVriKOKYpXbm+4YWm2j56HWRA1RgxTwTJpFJE017jFGiYC+JBbrn/CAskm3Xas4K
         a77A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uClVApymgkgK7fH66RPqLcCXsTpVvQDUaMyIyH9j81w=;
        b=E7vOnkJWh/hXRQ2bu7uWhuspLvWFSBTF95UmDBY3iXt52N0Qj8irAKWEPC9u7d99It
         fMkog373MqKQcgLhcL2LkmMPcabi2OuSlerFn66rETxEl2kC+Di+prx8i69Zue8/k94W
         j3TJez72tqbCfM5NKGHhKTljEVZhDxSMxgsPZnkC6x55b3TjTbAEEyHjdSXhdg4t8mjW
         5h+9LR9Um9C9/pWbOWV2FcmYfwxoHnen85iuxwYzv9GiVn0P+V6NLL3k53230WTAR7Wt
         A9VoX5OUizLnCYKGuBispwuzqMILD3lRJG8njiqWnda3NxplwXYP+J6SoEwNHAJ8R//9
         nC4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mzaREv75;
       spf=pass (google.com: domain of 30f8eywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30f8eYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id u14-20020a056000038e00b0022918d21a6esi190306wrf.3.2022.09.12.02.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30f8eywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id q18-20020a056402519200b0043dd2ff50feso5702690edd.9
        for <kasan-dev@googlegroups.com>; Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6402:4011:b0:44e:b8b5:f52e with SMTP id
 d17-20020a056402401100b0044eb8b5f52emr21439836eda.352.1662975953684; Mon, 12
 Sep 2022 02:45:53 -0700 (PDT)
Date: Mon, 12 Sep 2022 11:45:41 +0200
In-Reply-To: <20220912094541.929856-1-elver@google.com>
Mime-Version: 1.0
References: <20220912094541.929856-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220912094541.929856-2-elver@google.com>
Subject: [PATCH v3 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mzaREv75;       spf=pass
 (google.com: domain of 30f8eywukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=30f8eYwUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Adds KCSAN's volatile instrumentation to objtool's uaccess whitelist.

Recent kernel change have shown that this was missing from the uaccess
whitelist (since the first upstreamed version of KCSAN):

  mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Fix commit message.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220912094541.929856-2-elver%40google.com.
