Return-Path: <kasan-dev+bncBCLI747UVAFRBCF3Y6MQMGQE223XH3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 879485EADBE
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 19:12:42 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id e14-20020a6b500e000000b006a13488a320sf4216851iob.12
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 10:12:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664212361; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zd97rGP9aOxxt0DrXo/Pu9cbIETkRDtIVNU0XwGt9AY6zuWdBFCxmElaXGbUPqQKfE
         FDcip6F9uJzVwSvCEbsdw4pEd+PvWwEQM2d6dezCrA3+pxZAAL3jLEBU9dzUVvPvCeBx
         lxJ20nyVCpFl5xJP6BsUmHBrf/7h+BZPdDmoSlkSnb/75362IB9dDzHjHcEW+tl0ZOLf
         Cp8BP7OEe1Dvlv0Q22PKOGUfrxBS3iwOkYw8+SJ3pqtn4ppr29/9LBjD6S2m1Fd4vmrj
         ivH9yNyLu9V9cd7lYzgBb3SKoqeiq1h/olNO3JSd9kOWRl7IVk+mi9JuHJ/iecXeCMyT
         /apA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=dzSfDRe0TiajDNg7XQpdZQBDRgUknOTRNW6bzFuHk68=;
        b=pIWWXTlMVTkbJmLWPQ9fdN/bgp6jc/jJUwotJtj7cfrZDlpvYEKglTGNVT1oajYKma
         Un0o32VeuqIC6Wxznke4bnU78c0KmGq1en5FjntRBAmfJHrea3vgRHJ18Fo27x8qD2Km
         fGvIZEhgHhEB9I0nFllJg7JK5cf/6tTMYcsxxynJDALcQ5coNdp8FRQTBEpRhF8SbgsF
         3rjWv/1R8bSWidMUDJf6tm7ctphVaDDrB7i29K0izECzvvYdRCIl2bkoNGDY+yO20O49
         hvtcWNFJQxW1UXbMcgYJM5fOlzU+sif2VjGG6kPKFHv0v0mX6ylvISSZuGdp79RdGy/W
         eyDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Mb3tRMyy;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date;
        bh=dzSfDRe0TiajDNg7XQpdZQBDRgUknOTRNW6bzFuHk68=;
        b=O0DTqsxRF73VF8rKo89qfdcsC65cpk7lcmYnWhAWsO2G2TFyLGy2XIjecHcFBViJMk
         iG8WMjA7giLhc33rSDEzklnuSmJbv4p8bCI0IvoIUL3LYDpRrgpz0BsfbuaWgigDfhlm
         pN+tbCOIxGkZ4h0tsWGvYwwbG3tyqkKmavImbT87aImnMzwjRW3yZqD0yA3qqStCVYN2
         7eUOZ8PV/PBO84AcxikjFtdoquqM7cY9qeSD/zsOAttTftBc3wmJFeoV5iTNv2whCmRU
         jXroRPmZme8fhsi8Fd3I+uXrHW6R8jxCYRfda92shr7Af3dtMUGyBKpey5DGJ7jMVAlN
         xPuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date;
        bh=dzSfDRe0TiajDNg7XQpdZQBDRgUknOTRNW6bzFuHk68=;
        b=uQ+CiKCAurqb4QvX2ySMQ1OO7aJIiCUmuwv1GXss2vJFIBlUYUpQH4aOHDjhyqPT7D
         QJTu0QhyYH1+jqsxnBcH8+ODW61e+gYcXqOf+Lit/HXZmHbUoYEoJfAchdhMyCAsNMn1
         BiDvvDeSVLWWySNlVZnhsOTnIgPDfWfGLTki2QNaLz3+/OOwDCvUuGtYgdJOavj2goQL
         wM1u8CraPtgHBAQ4gY0QJZgyQ4nDHN0umHqciUbjpFKNw1CeGJW0Vq6/fegw8BFn8Ro7
         8eO6nzQYjKABftqPsb8enOCC0FoDKXVcJdt9RTNS1l4omo5ZdKSXWdl0gvQayOJ51sNI
         AFyw==
X-Gm-Message-State: ACrzQf2v3sMkksKqZXCven6CfbFe+oo1PWcQImxSNGXV7dVwsRR43kJT
	txIlJXTY+gsJdpG5gquHktE=
X-Google-Smtp-Source: AMsMyM7suLQH1R+f9DggWRranwNIn1wHP9Z0GrKlnUkpeiGnbU37ENGiTuPfnyCKf5EOOxrBCffu+Q==
X-Received: by 2002:a5d:8913:0:b0:6a4:71b5:8036 with SMTP id b19-20020a5d8913000000b006a471b58036mr4403257ion.171.1664212360119;
        Mon, 26 Sep 2022 10:12:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:93cb:0:b0:358:37ef:358 with SMTP id z69-20020a0293cb000000b0035837ef0358ls5156556jah.7.-pod-prod-gmail;
 Mon, 26 Sep 2022 10:12:39 -0700 (PDT)
X-Received: by 2002:a05:6638:2496:b0:35a:36ca:b188 with SMTP id x22-20020a056638249600b0035a36cab188mr11861502jat.257.1664212359777;
        Mon, 26 Sep 2022 10:12:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664212359; cv=none;
        d=google.com; s=arc-20160816;
        b=YrA/PKSt32uOoz+471RZ4SsmHcAvJCzUjgpyqP5tQ234bupYjg7W5/WjpxSVHJcYje
         FqI7/dGver5MSHkdKAej6rJV3cdhDdeB1mEWniMBRjSWAttYIP8wbColAVEPEu2kuxUW
         cynmSrlzkqWFo9y+Hnt92mTEGMNVaKnbmh0KKhCK8aoq32BcLxsnevJtHyU/J9e9hP69
         1d+JeF9Z4B3w6QobWyu7FM1qT6oYB3IU/qWevrqC7QJ/4fepkF3W0SJA4kxiR1x6DO05
         1K3NpGSfLAySZgz62hezPLf/FakO7CKLcZY9YcySq+dcixScRXtWj0QbnvpEEt2zCnBd
         2IEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kCHSeunwpNZ65UHz6B65TlyJBUnIW68s8YAvcdZcpz4=;
        b=OuQ/x2YicMh7u+cwoioICWBDdgDwPV2PXfUSJFWFvXB3vl/y4/RU8iWpfjfT/UJ22O
         lAR3lOTp14UFoaNuEl+95TZO3ELPYrKeZy28pVQYSdt2KKeRLRmq6NVC9665TUYh81vt
         wWBTf12vJZOEoDQYG4CGYrGCeS2DloDv54NqO2ERvp/qJzOUZbv0MgOB5sfGz55TBnq5
         ImXzVV00rcYfpgINy8+E8uWR0rR4l6u1CfOq4XhqBhm0X0QeY9w90Py09LYRb8TMaUby
         zJMYL/B5iUsngN0mgce/jh5yWQkU+BySyIqq5143N7lYaF+t7Dv8uLyjCrStwr43xhVH
         ++hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Mb3tRMyy;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id u4-20020a02c044000000b0035b443cf6b7si463292jam.3.2022.09.26.10.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 10:12:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 24041CE1266;
	Mon, 26 Sep 2022 17:12:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 11EBBC433D6;
	Mon, 26 Sep 2022 17:12:33 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 74130d56 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Sep 2022 17:12:32 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH] kfence: use better stack hash seed
Date: Mon, 26 Sep 2022 19:12:23 +0200
Message-Id: <20220926171223.1483213-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=Mb3tRMyy;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

As of [1], the RNG will have incorporated both a cycle counter value and
RDRAND, in addition to various other environmental noise. Therefore,
using get_random_u32() will supply a stronger seed than simply using
random_get_entropy(). N.B.: random_get_entropy() should be considered an
internal API of random.c and not generally consumed.

[1] https://git.kernel.org/crng/random/c/c6c739b0

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 mm/kfence/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c252081b11df..239b1b4b094f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -864,7 +864,7 @@ static void kfence_init_enable(void)
 
 void __init kfence_init(void)
 {
-	stack_hash_seed = (u32)random_get_entropy();
+	stack_hash_seed = get_random_u32();
 
 	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
 	if (!kfence_sample_interval)
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220926171223.1483213-1-Jason%40zx2c4.com.
