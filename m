Return-Path: <kasan-dev+bncBCYPXT7N6MFRBJEMX2OQMGQEK4JTDQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 72BE3659FE5
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Dec 2022 01:45:25 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-45c1b233dd7sf243033487b3.20
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Dec 2022 16:45:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672447524; cv=pass;
        d=google.com; s=arc-20160816;
        b=ABK8XwTlF/vd6Bu4Ya2OSuRiAV0Io1+inZeKroDVeDjKmVPm+VEnEoifQWEoNp1+br
         VpGHGPJWnm9W4A88bkBC6nNwu5a88dmNiBssnj90CRTzFz9L1ZjBfNfvvcxHQ6+TmreM
         VK0InJ4AgWzousGr3cj1Ggc/I5vd2I3bwAr3yNX9kIswNJ9amLndyz0rbb1J82C2pB9O
         kmC6UM1eqF9Be0Xi025lVvMteUlIMtc2AR8HnfUV3rbaqM/W/kRylqaAOljQqTLx1Hlt
         sW3adqH5JOVixYzrFHwneiIXQ54qzvNz90kwD1XvpcM/TYE2MVRhp7rMCxREgbXAIL2p
         nsKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=7XxBhxNIkvRFJwWnnqb4Y0tVdOg5Sq0p2ynVXBoySGY=;
        b=zROKBLxp2CFDuc44pRuhv/RpJWnA1gbYrFZE4QX/LYoyTVCKgiz5LmBvwC0YlYfBwA
         8ya6TrR5+sNquJ/mcYrVvFRuxFKqpJVGBugoHmMD/Sdw19T1SLHAQcCMOQQVx1mwpzHB
         04o2dit5MklLHLDz+pocev99+43oOIAAGTRtBlSW+BRWrYvQPH+JrVA4fOMgQ8B1zDCa
         Nhv8JSfZSw9t+AFmFBPLod5lpsZp2lEnj03eKmrZlDv84CiwP57SNlAAHTDmxE0xfO9m
         9y+HaA6AAsjhHNtHhQRFMvSsI3ki2X/z1dl4qhZOGJJW+RaeVpe0hOvec13ILV4sEoki
         fdbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Vao5WWjd;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7XxBhxNIkvRFJwWnnqb4Y0tVdOg5Sq0p2ynVXBoySGY=;
        b=kki2kXTLJwCcDLpLhuj+sRN1ZkYdSJb/kDCwCBBCk58NF7bK1GYkLft6appjLf7x/z
         wyYX4/BevBIvrcsJoNThXps6VQ/FWRFFOn1VZWNLgJkUSLLsZVWbMu4wL8eQk8mAySlL
         1E39GPvGxhGsIxMlAsmJbQqHLZmZL8My4aa7HnE/K485MacizkCCXvAAvQZYtiQHMmAA
         uAihDupvTueSNi4u+3a88TXoSSQ0SR67hvZBC2QYRHP4jExIPNFuG9iN9xwONY1vBiGk
         EjHwMONAhkFBLGCjuX8+AHzAzpczCKy3Q3tb6M77fmps1FvUCkV4STiIqhO6YQ8huiDh
         Z2Mg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7XxBhxNIkvRFJwWnnqb4Y0tVdOg5Sq0p2ynVXBoySGY=;
        b=QM2tMnEnzlqs+n+6FPRfTzs97oxpg5d1ukXdUGxCrF8qC4+N/jqkK7AMXdm/+IJUT3
         znxpSefDcQshEVlG/Ojb5DkXi1n++Cdma9QKPDuyR2S6YqtZeHambjrIZikKVt+trdeY
         DN+FMnNBn1kcOx7Qrx0JfgapK4DfD8cPIYc2kck+RGCJVHAMBj49cuJaeD1ck0y/746R
         TcsSyyDroo6i+VvJJUNGNhh8tb+Czp5QLC28SXWwVaTPf/cStaxCt5jQq1tjp0aiqki6
         ZlK7GSyOoXumaU4Nh5w9tWWI40K3Bv5r1a3YHCiRe7BAlpIoXThdNlLeZMTdukuI+w6o
         etLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=7XxBhxNIkvRFJwWnnqb4Y0tVdOg5Sq0p2ynVXBoySGY=;
        b=wCFHPtSQ8lJow66L9K553ovrIHbgymE6sJDAT/YX05em/84iSznvTdkJqU8KzyO/b/
         NGHxbtelHM8yECsLGdFqXY9KlSt5u2Q/XoKCjakPQK8E9mltvBvfyfoy0qv3wBELFxwB
         hjy5anpsLzqnMC3s0ozixuORXdXzJ+7VQDa4RzFPUGPwcuOfvcTfHzIJe1G+UPqvWSSs
         dS98osLkBSV9lAW2R2kWmUgwnzoiYbbxivg19fTNXM6F/DYMab7FZm2/JnB7E7ZNCEPF
         S1d8E2GA+/eMA208ewWLE0Sry5yBfgBhT17TwfPpHhQMM/cBLqpPz3MAdVU6fnwdgPcv
         BgYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqA4bwInWRl/Usmcmzy0Q2mf0Oibita1S8nq0jwt9zpQ9kjGBnC
	vvDKb1c+pqJOhEfBKNOVQAg=
X-Google-Smtp-Source: AMrXdXvGP5zCvcsu6j9XDVSfEoUuj2oC3cz/8IvQo0xzq9GcyCJ4vYgWODvUf373GGabrcq3cBhqYA==
X-Received: by 2002:a25:7343:0:b0:763:d4ea:a43e with SMTP id o64-20020a257343000000b00763d4eaa43emr3482416ybc.401.1672447524201;
        Fri, 30 Dec 2022 16:45:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:fc9:b0:36a:2cc6:5e7e with SMTP id
 dg9-20020a05690c0fc900b0036a2cc65e7els8917698ywb.7.-pod-prod-gmail; Fri, 30
 Dec 2022 16:45:23 -0800 (PST)
X-Received: by 2002:a0d:cc05:0:b0:3a0:336d:2b76 with SMTP id o5-20020a0dcc05000000b003a0336d2b76mr34513324ywd.12.1672447523607;
        Fri, 30 Dec 2022 16:45:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672447523; cv=none;
        d=google.com; s=arc-20160816;
        b=P7imunnDhzgAnjALqrbpTgBwgRix1mNBapEkb4d7ZKstqD4fYw31Kqj5rNSJzGWf1Y
         ZbI4rd10aqgSI/KqC46Ip9lBaz+MvfpErj+Qm8GE/mbAejRJrGawdy2pUGwFMx5rcBNS
         puRiJ3c51ZqcyR7I4RrrWJgKg8RMPOe2rhYu/64kIPeO9r48if2tQ2UYz3YfGiqA5HH8
         0S+B5z0z8kCXUKcBSs8darJLKQXjU8NAVXI+Rql2SFa8PQg03bGAS2hiucCQkEZiTn/3
         zwSHzRb7r7mJA3nOLpyBEXMLYwoBKobOtaNDQxXL56cv5IVkeNa6hRGYEG3Bva5aHSZ3
         tZQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=rdAX1tY2lgADZc9s6/5hpXkndV7lITnERV5/PWeUdiA=;
        b=Lzhfe6sn4vxNHE5bhGt+q4yC0E5f2W7VW22dD738OKtqsgOd04QOoCl/GM8PzhK3tb
         pLtyeOlRSP7mUfxb791G2yBttwDg7SC0jaa3eZx6wmWQCB8aaP120AAOPZkpuAqrv5Yw
         zd31XOD9fioLbBAiaQeC1ekXkmiM2itJaLinB39NuOSeK1QSMGLy1TsRzCjEzXDiKW3H
         tVwbgAJKGa4NIje4HfZNky7VJAPZqp5C/ZsrW9LFBwaYeazGH71Oc0G0k1rE6rnkkTeu
         O+CZAH+4NROHezj5amENyvT7hXY2yPZs9s8nxsLA9258oZ33hyGJwqNbLRqVqRIvTgo1
         Qn7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Vao5WWjd;
       spf=pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id bp8-20020a05690c068800b003e0d1cdbb77si2078021ywb.3.2022.12.30.16.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Dec 2022 16:45:23 -0800 (PST)
Received-SPF: pass (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id v23so23880138pju.3
        for <kasan-dev@googlegroups.com>; Fri, 30 Dec 2022 16:45:23 -0800 (PST)
X-Received: by 2002:a17:902:c948:b0:188:c395:1756 with SMTP id i8-20020a170902c94800b00188c3951756mr47555051pla.41.1672447522835;
        Fri, 30 Dec 2022 16:45:22 -0800 (PST)
Received: from octofox.hsd1.ca.comcast.net ([2601:641:401:1d20:499d:36bb:724c:bd6e])
        by smtp.gmail.com with ESMTPSA id e7-20020a17090301c700b00186c3af9644sm15573030plh.273.2022.12.30.16.45.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Dec 2022 16:45:22 -0800 (PST)
From: Max Filippov <jcmvbkbc@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH v2] kcsan: test: don't put the expect array on the stack
Date: Fri, 30 Dec 2022 16:45:14 -0800
Message-Id: <20221231004514.317809-1-jcmvbkbc@gmail.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: jcmvbkbc@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Vao5WWjd;       spf=pass
 (google.com: domain of jcmvbkbc@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=jcmvbkbc@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Size of the 'expect' array in the __report_matches is 1536 bytes, which
is exactly the default frame size warning limit of the xtensa
architecture.
As a result allmodconfig xtensa kernel builds with the gcc that does not
support the compiler plugins (which otherwise would push the said
warning limit to 2K) fail with the following message:

  kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes
    is larger than 1536 bytes

Fix it by dynamically alocating the 'expect' array.

Signed-off-by: Max Filippov <jcmvbkbc@gmail.com>
---
Changes v1->v2:
- add WARN_ON in case of kmalloc failure

 kernel/kcsan/kcsan_test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dcec1b743c69..a60c561724be 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -159,7 +159,7 @@ static bool __report_matches(const struct expect_report *r)
 	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
 	bool ret = false;
 	unsigned long flags;
-	typeof(observed.lines) expect;
+	typeof(*observed.lines) *expect;
 	const char *end;
 	char *cur;
 	int i;
@@ -168,6 +168,10 @@ static bool __report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
+	expect = kmalloc(sizeof(observed.lines), GFP_KERNEL);
+	if (WARN_ON(!expect))
+		return false;
+
 	/* Generate expected report contents. */
 
 	/* Title */
@@ -253,6 +257,7 @@ static bool __report_matches(const struct expect_report *r)
 		strstr(observed.lines[2], expect[1])));
 out:
 	spin_unlock_irqrestore(&observed.lock, flags);
+	kfree(expect);
 	return ret;
 }
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221231004514.317809-1-jcmvbkbc%40gmail.com.
