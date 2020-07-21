Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTEH3P4AKGQEF3HBDKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B90A1227D00
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:37 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id g18sf9799637otj.12
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327436; cv=pass;
        d=google.com; s=arc-20160816;
        b=uugxe3c73PZtNFHm9l6P37P58H0EWU49QRasOp3kTVpMe0jj/mQUa5Q2qAwRURfdzt
         yjdi03PkEDchhQqMF3WXE+vHlizbg1PpWufUZXX1EWWVc/uuZ4Sps3oMLHLr2hqBapPO
         HJH8e04rSxOeH9gceCUvHD+ulEVg1AhMUUafHecQa5eo15jOC3ZE05MYAu70a9xhYKMV
         aNOFW/JSQKCCQqyqsd1TDxLXHkejD2XYvCNxjMt/IWzOtUOlMoHUd2nqbIlAUKNGMrUl
         HKv2TcmwAQTVyS25BuKd7LWj3V48XeCN4+FWrWVHV5TDaVbhSnYs/A7CurTHIOysbaI7
         Ka9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UgLoI9pJCV7gFsZuRPUds7fctJpu3qetr5IFx95lcl8=;
        b=yAjkDiWUvUCU2XLamfMi4Et7VDDDOll46y/+7pQtBJTBnV2LVyKoMA9DWsRbsPUgvI
         gQcEr6wJ7nVvUalJHlsfWCAfrN0dzbQAzcTJLBQf+NAFw/jQTGYSM87i/RHociRr54An
         uRPyCKyXBdfmMHVB/I3JAefGX/9CjNyXJWiiXAcK5se3TpIX4yk9XiraLOHvUlSkIOnw
         pgCFZYS12QCappbMtvqvXhkVXT+jdQ6FZD6poZt19VPwG0DZXQqstiOwMe7AQrDwvAan
         iwMEDOhqXbM+qEuT1GqknddoDz6R4+NSaPIlZSHRAHqKTALNnxg+sxpC4x0zyANF6O9I
         cd5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aftcNk8G;
       spf=pass (google.com: domain of 3y8mwxwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3y8MWXwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgLoI9pJCV7gFsZuRPUds7fctJpu3qetr5IFx95lcl8=;
        b=ZZOrTcBEhYAY+oawLXcdJErpcGPdNMnsqvGMd1YF853bzFKM9fZoJp9E4WkUHfhGBd
         h00vnbsjbT1j4lLS9cfXxQu+64XhPkWCp/MMmNgzE10pG/GUqmmAj4FdNmuEHqypnPSc
         WiEM30tryv1ncdIvYx88mAcUAF4fGilCwPBkkjMZzeh7spt/b869eIbnzv3VHwRkK28k
         tKT9rfz8z1Vh2qsoYs9j0txTm9FkKR+eVeOJEvSmp0OTRAcQ5Y2EsK/tR2mA+WppRkne
         krMK+ZtuZ0dHUS1WJ8OuFMi8ksObVgZuL3phnkIgo1Y48ibOUr56AcvbUwKQZCH/iQKw
         0maQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgLoI9pJCV7gFsZuRPUds7fctJpu3qetr5IFx95lcl8=;
        b=qMhqrZ9ta/5hmPEA+xqH4YNFXKC8HHyPrayy6Ru5158l1nBSrnaNONL/o7dzV4lny5
         ncG7W1jpm0QlUBSxftacLmfWoftZ4tKz+AGFsimRxY7FVnZXdpRR4iyzGjzfjD68Xikh
         mSywdYdN7UnoxpWcdN3xwKePvqcUqvr755wBhWfKU6ms9sSI0DDaVF2i+tESIM++ljnP
         FIMc/ka5zxriCnbiJWSS8ZaQuVO10UpDUy8tfwtVuo9vyZOmaeKLoNebK33FT6pygO52
         96zTXkI9nqJo7wjbH8jZ0LopUQ2KSWbxB3ZQbjTuztUyKMtzzNLdtqdVRbvHoPIgbXpa
         i5rA==
X-Gm-Message-State: AOAM532QAEy0Rz6EXqUiWfcYgt43ovm0uz1VvIjOE1TkZMMEcztuAGJ3
	BahhBBzI5gm9wKCRFJKcn8k=
X-Google-Smtp-Source: ABdhPJyGhRJQ9RTmiWz8rFxPPKKKmkO6uFBRisNcoEBpLdXcJ3VzQ93vAD/U2lmzLBNU9Cu3LEh5RQ==
X-Received: by 2002:a4a:b6c5:: with SMTP id w5mr2806054ooo.89.1595327436284;
        Tue, 21 Jul 2020 03:30:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:370c:: with SMTP id r12ls975301oor.11.gmail; Tue, 21 Jul
 2020 03:30:35 -0700 (PDT)
X-Received: by 2002:a4a:2209:: with SMTP id f9mr23284489ooa.43.1595327435921;
        Tue, 21 Jul 2020 03:30:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327435; cv=none;
        d=google.com; s=arc-20160816;
        b=eJKo5zYJKCYbLRpKverckkGSitayhNXYzmW1PcoshS4PiG+24JiR54zvEljeqxdNzF
         C7ENK7sQqyoMBPcCQx/MGfa8ED1wwmJ7q7LsfHJCGE/T+Z9H7eIxWZKnqdM2Gy6yRgLi
         iV0cJUAEJ+dQmo5RI9p9oKqj4tD+r4RF6SUNhI4kr6wi8RYwPNpHYfRo3g2ouMtUy7mZ
         MCe2pB1rqTVuy2XAwjFi7+fLjF96GueUO92U4L2EKKlaQqR75cF0ty8ZIarz1Vr6boQW
         QJVg2wtCPTGMmsIv7I0tAFWyl05oDhSQy5wfrzUZOzCE+hhSabtmEAc4S4UQ0kC82/hu
         Liww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cPjmWgpWaY+rWzHjnAp20s8iFiM+s5JoLN5MYOTYnFA=;
        b=ib0Yb13y1qp4RYRAZbfN1hNojEK5VpQGM6Pww+7mOgcCpb08vR3ewO8faRzQRZ0MEO
         uasilLjZH3sju4Rad1oqIobKU9p6yjoZg2avrwCOVWDvQQZFEqL3h2NF2Zzbv/pe3drO
         quiYY4QyKWuY2XQRzUltrZhddUljxVDAS2Y02EURV8mgQHF1ujyG681SGupNEZRfktn7
         uo1ozB4sXxlRG9V8Hh+dbknwB6p333jyrdgdE6G96lqi5cwEPWzuN07WLCnWzVWjgfXD
         KCYUDxfig9IeIalLGTwwfJGnz7JTWhFeZRX2Jo5TG//EhaK74yAX2hKmoFXdHjQSDcGt
         rvLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aftcNk8G;
       spf=pass (google.com: domain of 3y8mwxwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3y8MWXwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id l6si929687oib.5.2020.07.21.03.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y8mwxwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d27so25104669ybe.20
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:35 -0700 (PDT)
X-Received: by 2002:a25:a088:: with SMTP id y8mr29898149ybh.253.1595327435352;
 Tue, 21 Jul 2020 03:30:35 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:10 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-3-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 2/8] objtool, kcsan: Add __tsan_read_write to uaccess whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aftcNk8G;       spf=pass
 (google.com: domain of 3y8mwxwukcawqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3y8MWXwUKCawQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Adds the new __tsan_read_write compound instrumentation to objtool's
uaccess whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 63d8b630c67a..38d82e705c93 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -528,6 +528,11 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_write4",
 	"__tsan_write8",
 	"__tsan_write16",
+	"__tsan_read_write1",
+	"__tsan_read_write2",
+	"__tsan_read_write4",
+	"__tsan_read_write8",
+	"__tsan_read_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-3-elver%40google.com.
