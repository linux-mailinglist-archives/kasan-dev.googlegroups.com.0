Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIUO3ONQMGQE244CF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D842362E9B7
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:31 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id d2-20020a056e020be200b00300ecc7e0d4sf2281319ilu.5
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728610; cv=pass;
        d=google.com; s=arc-20160816;
        b=U8r4WR+tDS07lKF4Ho/s+vYAarT7ecEH9LmKRJWpf5Wgg1QR1zt8MzCmQeUg4hhqoV
         iYuUtQuQppMKjfknSJO/m1e0m02AO3hwQI1Z9duBL8jajRxZVWLv+hcvrALYZzTtcmc0
         yYhHb1juGWDD7goIUwoZ+Bg5QPWBv53LdrSojTdh5Swgdek8Hsr4BioHijef9xoV4fUo
         QyhAn6R/PFFVkmI/ekT+cewY6n/KjNFiPcx9cUR7s+BbZiO6Lnt4Rl5MXczx3P2SMzzP
         MDxD3PEO/yf62pRrtzAMSX+hcU52iS8ram/ZGDWDlyc6/XWOQNl4givw0Fc018ouAF+I
         o+AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T9GYzCETn5GK//016nHSXPbw/QzB4ctfa0IB9DnAa4Q=;
        b=RUXCgeiFcgI0E+kyx7T8XfR160eGHHp4c85lrhgQXQ6ulozkqBDR4r7dcDKS1oa3Cr
         b45yjTZLjLsdEFadOAIT8HA8SpzXauaCzknY/9FY1/bPKqF/Nrp/q2tpiNuNBP7lMNZI
         YmeHWXRnhIvzDg86LGdUwSGQWQpV88AOXrntUGAOBq2tUgOC66xHzqod3q3ufSFMdvRU
         yACqb8lLyiNHlshFaIA4iexcZuW2o5MjRTvMqvyly9z8vBfnSsHDN1HCJXyMBKVtT0m2
         TxlA/7F0eOece9cOOpoFTr2MypsbaD8kG2jMCvZW87lZnDeKeVd+q+a9L40WBw/le53O
         CJZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=dLZRKPT5;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T9GYzCETn5GK//016nHSXPbw/QzB4ctfa0IB9DnAa4Q=;
        b=bCjTPrgtiWIGuyfT+U1wJqAderS4vQy7I18Eq8LAjTlfEmuzTPMUyE5xilV/oGB1ir
         SDnFgrlMXqnzhlMQS/yfVeM30kQ9EEUaz8EZgNXNpMXZsRjg2XvH42lbyAU4qrxh3hyB
         MvKgrkKmoL6tshZld+lnSms0q4APKL7vn/iHlzediDjr4qLQAQKy3VdXPL7LIM3fIp2c
         N98qvHHM1wOANE84MB6lGsI+8otAFwZBx6GvpPkU+fO3ogsk26ol6X3swxvddiaEp3yr
         MMqhWaKNEsjOvQUJENAEDXliqx+coGwI6VOeycUZKuBguvYZOOu60+xTozeQdLg0qTmh
         ITjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T9GYzCETn5GK//016nHSXPbw/QzB4ctfa0IB9DnAa4Q=;
        b=qdcjFwc59MA9j2SgrMc5VVLde1btryWLMpngg7/zDqq7dUD88d7kl5LaFcCOHrj4Dr
         mWMo8cB0QrHr8QEDrOMsYENucKgEyAXrxz8bJJCpR5ERqm6PQOzRqOJq+IqzVk+jFu24
         +CZBDW51o2/GQLw/1V5jFx/3zMWqplx3dXKg37MYbWw0zeQrXmrQegB1Ik3B2JOHglOl
         4cuNKHSc6ZDVCq1BD7HX8YRichEiSbyzS5ZFJjxN41iOlLzdR2jBemb4uEXxyPq/CarI
         muQEAev3WFFQhjR6dn1UTwVh/uTJ7qFHqLDEjLBHs6emni9xjvngCeohvODsxRPgRSvQ
         wAQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pk4DBKtdgWdxzk7Uht+y+/0VsSbDFjWnX8XnB3rLmKU4EqPBiGL
	TOyL79/R4OoquUSl0Nan1Jw=
X-Google-Smtp-Source: AA0mqf6sBzs1HYKnJNPxja5WD7LcOZY2rwVQz/3tznNg36dTNmQb/ZciFxNYhkVm8CIKPB5df8zYiw==
X-Received: by 2002:a02:ca45:0:b0:363:a4ae:5a80 with SMTP id i5-20020a02ca45000000b00363a4ae5a80mr2197726jal.105.1668728610808;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a82:0:b0:375:19d7:7919 with SMTP id w124-20020a022a82000000b0037519d77919ls638320jaw.8.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:43:30 -0800 (PST)
X-Received: by 2002:a02:334d:0:b0:376:22fe:5e7c with SMTP id k13-20020a02334d000000b0037622fe5e7cmr2118357jak.126.1668728610356;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728610; cv=none;
        d=google.com; s=arc-20160816;
        b=TMQxODsHcwUpHTdXrP5ODjAxWtLw0NeBu5cYHGECRc8FGZ0MwN2bapNMskwI8qK8JN
         SjYOIKFOnI4dRc9UhgQnn1S4dVcpWgY1pD5XLePuzMq1xAWowCEVmTwdg3yYBnuXKs0F
         Npki56n+kWpV3nnxsQHAyjBBd0YZeG0aSdR8PyvERCgqvIAV0Bet1uBCsSwRfzOYMqCY
         d1kOWwo1jolatjX8xu4Z5y6k7H6ZJeZ8rwPr726tldJHxM0Y9rswS5E8MInLhHWRtmLo
         cR5Qi+egrqzobrWqxy8EskoOWecw04OXYYZP/6Xx7TkBhdAhYZpWntAvikmARVRNYmWN
         TBog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oZAyTYmNqDqjhiVXCbn/iUUPGOe7A4x1iLp5SSq3M+Y=;
        b=aF7dRdaCpYn6oyC+E63+8r2ALAJUQIaKvRX9qwT5+SVZQUmJFpTXtLIOVYJUufo2pl
         n6NdVtDL8hBOkSmox8VasdKpNNVWG1yk9bfB2/IBfdZbZU30UnDzh2zehP57pQm/U0fZ
         23qi5VO+gWQTlEpwMcZ9bp3foKTJrXK0fSTYs0b2S+9HCbjK/iTGndK6PAz5ngeRMaFp
         Zq+h3ONkodEDN2ixgSQPdLXPHBy2OX6zZoWN5awnr+9EeEWIwomSgWYFeQOQIxum1Vg+
         Jn7bcShc2rj1Vi64bLVfnO9oUKoN4YSCvQXDSkVCRa5u+TZKq34q0tb1jFPCpN4nyGuO
         DLKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=dLZRKPT5;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id t22-20020a02ab96000000b003752c8d2694si103595jan.5.2022.11.17.15.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d20so3065240plr.10
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:30 -0800 (PST)
X-Received: by 2002:a17:903:1c2:b0:182:631a:ef28 with SMTP id e2-20020a17090301c200b00182631aef28mr4854752plh.46.1668728609730;
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id t15-20020a1709027fcf00b00186a8085382sm777889plb.43.2022.11.17.15.43.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v3 1/6] panic: Separate sysctl logic from CONFIG_SMP
Date: Thu, 17 Nov 2022 15:43:21 -0800
Message-Id: <20221117234328.594699-1-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1240; h=from:subject; bh=MYCrkHw9R8LxDYIRQQdTTq6YEsTSsq26SRgNezbmUEc=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdsccw0YheOkdHY6sLAGx2i/EwJzpirGYe5KFf1J2 O3NKspCJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHAAKCRCJcvTf3G3AJjQmD/ 9UudpK/LjYQqgT+uDSinOff7b8X/IOatcfoEVeqxjwXnW5g1w8/uvDchyE3AXUMKMSqUL9wlcA2YXY 9FsQwXAM9SiZxvpzbNCULf1J9dLOyGZpct/rt6MSKpGwRSboVh0q5IKCPpt527XqaY7ei1zE4MGiam 4eFnNJQKnOeU1nSKPj5C9V3FwStWVScAeP+eeWYhLytRpj+AVZ65/N4hdvCBK+rdV6a4k8uvS2o1bc VPNDgNxBbJIEn99M4tO00reM1b8JeS0x3kiCpL01KE2rYCeYC3Y5qFbAz1yj7TQZuDivhvVAgEXYTZ NDMeu733A70XHkm9eLHey8Sxdt+a59iiTDijcBqgOsjqMI67Xdt+mVA4MezxNn8c7TDJMukp7vYHgX 7w30Ut4mulgDUtaSbDBIDC4K8BJ8oInCdVm95U2j9U02tg0CltGRlNZXtdr66ydcPFz+lJUS53O9w4 bwCG83c270M7bk/bmJBKGbtETZLb2agP21esArCedrmGjWFHD9oKCEguHLI18J99mQ0kXvsA7yGkjq /Shb8v/SxobU3/gQ+OIl1a/paUZr1PmFr9F9y6PQ5NUfzucIpmrys6aUhc29wrFnuH1aiuyTroVlhx BkC9tCUjIlr2fuDrSQdTWWKaCmXp0MpZ8IUofmDmVX3pbG53VF2v2STqkKTA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=dLZRKPT5;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

In preparation for adding more sysctls directly in kernel/panic.c, split
CONFIG_SMP from the logic that adds sysctls.

Cc: Petr Mladek <pmladek@suse.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 kernel/panic.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/kernel/panic.c b/kernel/panic.c
index da323209f583..d843d036651e 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -75,8 +75,9 @@ ATOMIC_NOTIFIER_HEAD(panic_notifier_list);
 
 EXPORT_SYMBOL(panic_notifier_list);
 
-#if defined(CONFIG_SMP) && defined(CONFIG_SYSCTL)
+#ifdef CONFIG_SYSCTL
 static struct ctl_table kern_panic_table[] = {
+#ifdef CONFIG_SMP
 	{
 		.procname       = "oops_all_cpu_backtrace",
 		.data           = &sysctl_oops_all_cpu_backtrace,
@@ -86,6 +87,7 @@ static struct ctl_table kern_panic_table[] = {
 		.extra1         = SYSCTL_ZERO,
 		.extra2         = SYSCTL_ONE,
 	},
+#endif
 	{ }
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-1-keescook%40chromium.org.
