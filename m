Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7OEUKBAMGQEYGJFA5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84A73333A44
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:42:06 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id q5sf12502262iot.9
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:42:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372925; cv=pass;
        d=google.com; s=arc-20160816;
        b=GqSplloNcdyQ/Ped4XCev7nLCpQoF2gnJ8FjOvInf+9GaGk7KDJ1Ohr2ihVpqBAYj6
         m0ynEPy1m9hTKLjGSvwmYqiQi8E8TQ5U0GH5XBpuPFFWaO9ZIHG0diXygSol7q7cQd6n
         cw0STxPeRykFxDV4XOHFYNojqWdAh2NLrjYbH8RfSEXH+VVdRMEZfBmeM2QRCJFYMsEM
         S271cOjzr7jFaEfQ6jTTuLWzl908Pft2MGmmCVLQv3dCz4Fy7qG4FpFgBCkj5/OerW7Z
         XJ0JsUjT5VHxMoTCbKALY5UdWGMLb2s2W/KFHTaIV2+q7RupNSk+uMeEWvrD8qilMW43
         +GJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xXYmHZpzmmUeE53h+Hb7J8ZEyUQAU0MdqSYlvTG9vZ4=;
        b=HyAp77/HMbUHIC1ubHPiZp2+Gkpp4198+QAo3BpNNSViUppnx3U0PWdbeGx/TqZm4O
         pkP5+ZIYSAmsU7KbO2wMn57cnWf5Y7ZQgYEVRFwcy3yzG5f9gKpfjjezzqFOElLsotab
         xtzi07dmPzx8dON5pQtYNt1fYnhvWRliQ4cjo60r1WjhtXX3hhsXVgEhtLPlvPAMkvMb
         zStURWNmB96N1xcOXPUApZrrToCc4/akzm2yrWhesKwIc0AOW0whm7JpdsQWs/8l0n0D
         GMtsoxKbBLDhpHHmr9AWYLvr+URKIGdJ5qZEnopF8mSbjLO8QKf6nqD9S0Adqd65hOqD
         Qt6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9prmAM1;
       spf=pass (google.com: domain of 3fkjiyaukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3fKJIYAUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xXYmHZpzmmUeE53h+Hb7J8ZEyUQAU0MdqSYlvTG9vZ4=;
        b=KA8mPFM1n1gi5m1i7E6908E6OF7s0DQNpmXh6C2IsQ9PlusDiQk9blsFyPD6l5K7SS
         dRKMzpT+FURqRL7hS2YSGPSNc7eKUb8BMY+kFR+Hs6VUK25K2+0VMDXlKpcitfj4mc9A
         j+pL0nX7PflHi1TJG3aEpLag+idV8cSVXfepgp8MnD9JAnL36BrfRMwj4bUVhiLqEGZQ
         Jj8RuD+1L359aqiSfPmyuMgVjOpo4D5ofTi5ZtTfbXxepFK+6mKoNAmQZvCmBWf6tkf+
         KwxEIvJs4/lIkQX/1QNlvUI8yzxDg4BoLjMt5I+3lrYtbvl4SWvNLibS0v3K/kXLSJ33
         ssSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xXYmHZpzmmUeE53h+Hb7J8ZEyUQAU0MdqSYlvTG9vZ4=;
        b=haAr/zkVaeTK21eDyu4QpZxVRMKR2yVtT6viIJGjHvFpNGPP8R4a8mmTgWozFllYau
         eoHo3n1z8GawKckBMDqmoebEIvj/xxtjL2wVWfXBrFbEJFJ+6tS0joyrLyTj8sCyzWlc
         BVQ+v7oyDeZoGkKKLupDwwE2j7hCOghxP6GidfTVqRwddmFOvMEfWb74hpBofBu9QNRx
         Ck8U5qJstey0JwjaFtKtkeQJmOgz4FtRCTK1DrVKKnQ7F5VNPuhyjXNejk4ukEfCFnxO
         olMy35Ql0JHrhiKQbF4RNzCUpMIiK879HLTP4D3y9FEBaDrskeAoWYDx9JygKmCZ668t
         3RpA==
X-Gm-Message-State: AOAM530i2LoXnJjTepUtdaafwmPjs44GipT2mYo2CvNA+9I32qsucb9+
	87n7gx+5TCRf3CqzYd5xZtg=
X-Google-Smtp-Source: ABdhPJwSezqtPDtbrwU+EduTNv6K/iPElCy8yoDPpN/yf7Azufxwg42FJLY8sYzuS6zNb/l3cFvNaA==
X-Received: by 2002:a05:6e02:1bca:: with SMTP id x10mr1945721ilv.71.1615372925605;
        Wed, 10 Mar 2021 02:42:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da52:: with SMTP id p18ls398759ilq.11.gmail; Wed, 10 Mar
 2021 02:42:05 -0800 (PST)
X-Received: by 2002:a92:194a:: with SMTP id e10mr2100035ilm.213.1615372925231;
        Wed, 10 Mar 2021 02:42:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372925; cv=none;
        d=google.com; s=arc-20160816;
        b=HCSVZLxQabxlwvUM4Wc9g84WS9B1U2a4Ot8pbHdJcr0uuwerwBb5kWqCs2D9fxmOTs
         hL9tAsqavWqqoMHZY6hX5IljddoMWCokkkVjlMWI4xBnfLmHx00xb2bWMYohAdb26ynw
         HuucGjzxUQiacxLU2XqIUkAOnog7WSFv5FgPxpgiD8bNo/FHKB6GkRNO9r4MMWYjK0os
         zlGN0ldRjn83oRUQ5IXHC5kXmsVHREJopxFneYKxoZ4Av0ApSloWlAZELf1/uy8ZXlQo
         Z4hlK4ZIvR6hK3AITUuJccFpYbPUYBszkFTZ4fgBQHEttvi/0UkVARhzNShatt+U4/A0
         Df7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=4oqgRNZGjKcuPrToE+ulENN9iboOssrjKjo3aJMrJ9Q=;
        b=b1nIdUskBHOQM10ZHLZjtL8scy1UtzlVDqA4p8/CUyxHmytJPue2OCr8p/DcrNGwNM
         gueH35Jar2tOurhpLRmfxVSblWaBrGxpbXiH3/ALY6npDGQBlVDLNjHjaFje71pK0WQU
         rS86nAmru8YRxjxbxF3mp64yPMFvAzRksqvzZhCa1AAGKBpqq9GtXWUQiBHqJmlYmuaM
         4arfd38ygW0LHlsqWtNI01XAfK5dYbepmG0vwsBqV2LStwODFKOEvDfshebmFvMC2wqh
         JEiys9YAD/JnRdI5gBeuf56j/DSy1G3OqperliuJKHfBsCSvE11shFHm9Ae919Dlohk6
         Suww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9prmAM1;
       spf=pass (google.com: domain of 3fkjiyaukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3fKJIYAUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id p17si261616ilm.3.2021.03.10.02.42.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:42:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fkjiyaukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k92so8763026qva.20
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:42:05 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a05:6214:c27:: with SMTP id
 a7mr2084546qvd.54.1615372924678; Wed, 10 Mar 2021 02:42:04 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:37 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-7-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 6/8] perf/core: Add breakpoint information to siginfo
 on SIGTRAP
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s9prmAM1;       spf=pass
 (google.com: domain of 3fkjiyaukcesryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3fKJIYAUKCesRYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

Encode information from breakpoint attributes into siginfo_t, which
helps disambiguate which breakpoint fired.

Note, providing the event fd may be unreliable, since the event may have
been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
triggering and the signal being delivered to user space.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add comment about si_perf==0.
---
 kernel/events/core.c | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index e70c411b0b16..aa47e111435e 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6336,6 +6336,22 @@ static void perf_sigtrap(struct perf_event *event)
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;
 	info.si_errno = event->attr.type;
+
+	switch (event->attr.type) {
+	case PERF_TYPE_BREAKPOINT:
+		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
+		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
+		break;
+	default:
+		/*
+		 * No additional info set (si_perf == 0).
+		 *
+		 * Adding new cases for event types to set si_perf to a
+		 * non-constant value must ensure that si_perf != 0.
+		 */
+		break;
+	}
+
 	force_sig_info(&info);
 }
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-7-elver%40google.com.
