Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBR6SYOKAMGQEWWU565A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C943453647F
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 17:07:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id b2-20020a0565120b8200b00477a4532448sf2071468lfv.22
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 08:07:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653664072; cv=pass;
        d=google.com; s=arc-20160816;
        b=PFIUoZcVh4xOClq1fGg71fCDeM3Jr3ooYtR55HdRVNLgF86QUvrpAA3khHxpM80jcG
         g2s3+fd7gApcsMJvBJtYqVBKw6hxrszp781z7689ZDv/3w1+1zMhQ4NhJ8uWgpZ0w8WR
         TWWtTxNT/sbp6KgZS8CSjXoC3nzQ+MaQawZfFsx43H7Et3CyiFiWU02N5BRtJm9MUzgo
         nUUt8KBmL7BFeFLnPKN0WLIrr78UOLZhwAeoNf0x44ZQPxgtYAZsk92FKbI5yI2bmctQ
         iDVL06H84zGNhRphO3btJIpJghZUTvK3+wQ8FG2Og+bXv3qJTxjj4xtGQZFU7+qYfNf5
         50DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=lg+SMpYLzORIwwISuhI06eG61GCfE51gkeqom1juMVA=;
        b=R/bCAMVxb3VxV7iqXP4CMq7T+abC3UxqgjtbldO6H8qujujgJTfSKvSiRL2yCWpE8R
         zjJH0Dv13KmThlIZpbcxgoOdfrh7caHdmd9HUgSVNhhYTvwP2OTPgc0FGpeilsWB3OuN
         Pa7x1NwrOv9vDm6XG1x783UQxDea32pRRll31lxBt+fem/k+8RtMKxd6mUa3cOqLga+L
         nqV4tq8GHRvo6Ya6dHSI8T/WGfQvKJoYGC7pe7n2WsD1hoTiqg9Pr+kFAmt9feBW5C00
         VAiK1xu62PO+bWqXET9r5Ao0Y2+bLdsdThKV7BDxL2Z9PwfHQ/wxAH6Km2/24JDLc9Ot
         QTqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=iyKxM3us;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lg+SMpYLzORIwwISuhI06eG61GCfE51gkeqom1juMVA=;
        b=DcB3oW42BVZ2RpfAWHvac/8606DHJm6zvwtE3dLCHRBMGY/3R74GQG43pZIJVQXqT5
         V72O8HCuacqea5Oz43sXL/Kr1YvDeMapDaz4opEUWjYEUF7TzrfdRlwifruEQ0YwojMW
         loV5NGtwKnVOIXzgY5M3guXA7voaicwsumAF8jWEtQZG/clu6wJ7SaI+K2trFVERby0w
         rSHuU1jwq5pJSk4jG9S7RBlyhxqZvtvRvFZGG3jQQq7fdEb0MPq/vjz2TiRtfVjF1372
         48H2uWkXJ27YIvAquE0FWXKaDC9DfnW8zIbitcSgDh0yTzjGkZ6BnIADaIiqy3Kx72ml
         iTaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lg+SMpYLzORIwwISuhI06eG61GCfE51gkeqom1juMVA=;
        b=Wsd5v2VoBBANBF18mamnOJfh/jTNVMA9SZEf+5TmPZNWdukkREt6bLJV4r1YzhtBYH
         3wQMuhAyB/JLo485U47HFnj8kwbpo0sixcMSubAvxnCLIbGo95AJEpQ2lvs2rO/LgbgQ
         37hyjiTfOpFz+U35MbGQIdphnLgM5/ei0QFTucmDuY+Ov2BdViL6wuAmTiJ7ouACWhaG
         WckPLWfPOcWnJojn4WLMj92G+OwUT9s+s28XaSCGKlQKjbtXTC5x1YvgKdWh1jfTpjXm
         Vph13yQK4i7gPTVFkTIwqiKdI+SgIWhcXpk3AFA2nYjNX2ENBZGN3Zgm9lHOvVWphLsm
         HUGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Hc/21J6AZDgXbpr2oH+9PEcBmkSNFeBsFwtPafNpGEaSPeyEM
	y3o3L2wQFuTKdjbvnkEFtyY=
X-Google-Smtp-Source: ABdhPJwmwBAv6eYR8wossDj6G8A/d7LsuTkQrKAKnZNE5vveGydGko7u51JTjsrSujbLDVvPHlBpXA==
X-Received: by 2002:a2e:a7c2:0:b0:253:de67:6ad5 with SMTP id x2-20020a2ea7c2000000b00253de676ad5mr21335391ljp.519.1653664072235;
        Fri, 27 May 2022 08:07:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls1440468lfu.0.gmail; Fri, 27 May 2022
 08:07:50 -0700 (PDT)
X-Received: by 2002:a05:6512:711:b0:478:8d0c:df93 with SMTP id b17-20020a056512071100b004788d0cdf93mr12970492lfs.507.1653664070331;
        Fri, 27 May 2022 08:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653664070; cv=none;
        d=google.com; s=arc-20160816;
        b=LQ9trG364UKD5f2018WC9KP63CFUfNsfkRRKlX/4mNS+X6hJlMM5f1IPmWrv+2f7xS
         BxhaAK8tLOPdluCZ5LxWawY8C7ga8TQ/cX+xJMCj9CdlehHw1VpaQNB5KfpSOPk/7+JQ
         txtIcK+pOfsgNDf5CDjmPdgf3wyrjVfyRD6f7f8jvXAZwHAw5ov1KG2B9v0TLG6Ns9V5
         wCQcEKZDNKQkPt9MjwJDyaIjgRYKoGKqCgEZtY+Xop3ZFHcIeQA0RRL1pNjfWUEF5e3v
         zEuGgZGm4xEMl375xy+wmuuX+QorRAFttCqjlI7kD+tdrS6yfa6PSPmDi/PQaelBInPW
         NFHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OHVPhUSj+8Sy9n8xF/GHpPM9wlJLJWPSeBMUVUf5Iwc=;
        b=ddLRKCKXBJRiz/IC6NLhuS4c99aXhffnLokbNOuH3ySKYzsu4N3V7j3fo9fKK8PCsE
         Fv0ToA+v6mavVeaxSkzQidhM/ZlLuC0i3UgW1mWwyAqz/RgOIpZcMGM5kFUbLv6l3l+9
         Zom9GWJXhGAfC8iCUFLfNukU2VGMZ6km8YPBXPpeKgkLMf0POM8BXVCz4X7fw8wKyc1z
         jPt90TQCvVpn7/zUrjREmDA1wx6uLTZg8cIHvdGEvOrQ2sv5issezApr9OmwGQlOtdmy
         Z6CI+dPR2QpU8bURnBkxM4a04CqryPJ0iyJ4CjVSP5R8wb2rgjSE0gniWGmIvl0yhJmn
         GUxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=iyKxM3us;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id h2-20020a2ea482000000b0024e33a076e7si226003lji.2.2022.05.27.08.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 08:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nubZ5-0065E4-Ce;
	Fri, 27 May 2022 17:07:47 +0200
From: Johannes Berg <johannes@sipsolutions.net>
To: rcu@vger.kernel.org
Cc: kasan-dev@googlegroups.com,
	Johannes Berg <johannes.berg@intel.com>
Subject: [PATCH] rcu: tiny: record kvfree_call_rcu() call stack for KASAN
Date: Fri, 27 May 2022 17:07:45 +0200
Message-Id: <20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=iyKxM3us;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

From: Johannes Berg <johannes.berg@intel.com>

When running KASAN with Tiny RCU (e.g. under ARCH=um, where
a working KASAN patch is now available), we don't get any
information on the original kfree_rcu() (or similar) caller
when a problem is reported, as Tiny RCU doesn't record this.

Add the recording, which required pulling kvfree_call_rcu()
out of line for the KASAN case since the recording function
(kasan_record_aux_stack_noalloc) is neither exported, nor
can we include kasan.h into rcutiny.h.

without KASAN, the patch has no size impact (ARCH=um kernel):
    text       data         bss         dec        hex    filename
 6151515    4423154    33148520    43723189    29b29b5    linux
 6151515    4423154    33148520    43723189    29b29b5    linux + patch

with KASAN, the impact on my build was minimal:
    text       data         bss         dec        hex    filename
13915539    7388050    33282304    54585893    340ea25    linux
13911266    7392114    33282304    54585684    340e954    linux + patch
   -4273      +4064         +-0        -209

Signed-off-by: Johannes Berg <johannes.berg@intel.com>
---
 include/linux/rcutiny.h | 11 ++++++++++-
 kernel/rcu/tiny.c       | 14 ++++++++++++++
 2 files changed, 24 insertions(+), 1 deletion(-)

diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
index 5fed476f977f..d84e13f2c384 100644
--- a/include/linux/rcutiny.h
+++ b/include/linux/rcutiny.h
@@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
  */
 extern void kvfree(const void *addr);
 
-static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 {
 	if (head) {
 		call_rcu(head, func);
@@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 	kvfree((void *) func);
 }
 
+#ifdef CONFIG_KASAN_GENERIC
+void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
+#else
+static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+{
+	__kvfree_call_rcu(head, func);
+}
+#endif
+
 void rcu_qs(void);
 
 static inline void rcu_softirq_qs(void)
diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
index 340b3f8b090d..58ff3721d975 100644
--- a/kernel/rcu/tiny.c
+++ b/kernel/rcu/tiny.c
@@ -217,6 +217,20 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
 }
 EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
 
+#ifdef CONFIG_KASAN_GENERIC
+void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+{
+	if (head) {
+		void *ptr = (void *) head - (unsigned long) func;
+
+		kasan_record_aux_stack_noalloc(ptr);
+	}
+
+	__kvfree_call_rcu(head, func);
+}
+EXPORT_SYMBOL_GPL(kvfree_call_rcu);
+#endif
+
 void __init rcu_init(void)
 {
 	open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf%40changeid.
