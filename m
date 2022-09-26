Return-Path: <kasan-dev+bncBCLI747UVAFRBRFUZCMQMGQEIWFWVBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B91A85EB326
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:31:49 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id b25-20020a4a9bd9000000b0047679132f18sf976716ook.21
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 14:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664227908; cv=pass;
        d=google.com; s=arc-20160816;
        b=c7Yk+aYqItz9fl0v9IBwvHgfJ9qSlYnjlak9HyXQC/YD9PUhWf1qXdqfpsimib3K++
         zK+3KKTcIM1Rd4ToxZh6Vw3McjTELlJmHkKYfeZD+u+JUhb7eseuVJIFYrwmeCDV6q1G
         cQ4A5czQw5YfwSg8so6p0Op3I1El01mi2Pz5d5MfctZ9pcSGJHeOIbUwpZVrcXWH9ltO
         93wVd8kcziorcFZUgn/uSbZx0cAZI+cK0+Ecahy1Uil1Ioel3X0z+zBRJnr4S0F9Dudk
         hchmrHaik6ji4YZR1K3YppeTwBxsBXMOMP4ldgFI76vJWmQZz9W9yT4fIhn+sSDd9QUA
         qtpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=sCTSZaaI9sOuDBuhEbgjVciWGf6EqMhBCTNOmeObg2A=;
        b=lWe82zVa2/jl34uF6xgMzOqgqrl7ur24v5hsXccrC3M3922i4bcLewvGhUFIoeekoY
         QmQme0hqA91LrtKSAibE4T563pzIl08NFY6XEub+qG2G5hWOhC4BWKxKwNPcwVAo1X5N
         sSpM6FsHPlo1uCecI1quLwWT+7Dd3a3bbN8Eoc6hh45EeTp/IgE+RuTb/Ua8MnduAoDP
         UUHJdxW7Iae4nhgJz4M3KOG4jyXwwQsCy3aaA1iZQCQZZjcZc7xt3iCarBrzL3BUBSU4
         BVkYfTmLXyZY42nYyQ+T7EFsrkUbvuRnJ7d310Vexbak9pdnEOSxqy/2gfnvWgAfAmRO
         StEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZejhL1fX;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date;
        bh=sCTSZaaI9sOuDBuhEbgjVciWGf6EqMhBCTNOmeObg2A=;
        b=jhZmfbS+4+nIoNAsWoQBkVl48BpHLfXk3OvBjF75c9Uv9QFCZUx+nASuvTwlCQOPKq
         mtKc0ykuq09/6xoqaDH/IdNrKuL90x8MvZot7SbeHMfN4S89POOJW8JPgpaNMVcdHBRT
         ZNOajvHhOzUUVkYBX6v+ao+J+u+muYqfqcNMD0FtnnvLAxU2ZVgTNCDwOv+Nn75yf3zg
         4OyGrEm4HA+VkC7Qq6KP08PZamINZQ5Z3ykl3XTMIhYFWcAGw+6/IedNtVZiNbT4MvkT
         QVS8BZp/fd7H3qdqFLzT5t9fMETOcUC3Ff6WNe67KFe1pVpwqWjPYtlhne/DpvODWf9L
         MXPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date;
        bh=sCTSZaaI9sOuDBuhEbgjVciWGf6EqMhBCTNOmeObg2A=;
        b=gk8SDnoIzb0BwYnvWXJC85AwCu8m2vAcMEmPescX0506Qgf78EuJUv44uCZwnzJWa3
         FczunNMyG2JgR0I8+IJh1mW6EWNuNKN/LHNHXVMZVR3OWP5BGPKr5ZJRPNbYR4+uC6m5
         nJonpcKeUJCK0q7wOMoHzjfYSNUXpeB5k4BiktoXL1C2MykUGwNsJsOJ/+lr7keT4VUq
         9bON1JXLMefLNTVi0/c5HOCIS5r7mUDlsnjvhie0C/0MkzHXm4x6tsmXgyWRCbtuiQsR
         jelQVgNTuSzChPSeVkYd5GaVt2T9amecSnMiy65aMWZfPPLzmZMqvAnnXHfR/dT9WOr/
         Ajig==
X-Gm-Message-State: ACrzQf0p8WshgvAjrRHXDxGaLCD73Y0rlpz/pRmE5ZKDWv7pL0fVfBhz
	RYSK7sYcw21YXdDH9wOxHmc=
X-Google-Smtp-Source: AMsMyM5Rx/1vi5XTLyApac4eETLjFPxTSVyFS0FGbNtzheRJrEdhvS2dGnWv4ktD4d6ZkAh5dUWQNQ==
X-Received: by 2002:a05:6870:c5a4:b0:131:6edd:3955 with SMTP id ba36-20020a056870c5a400b001316edd3955mr428600oab.96.1664227908708;
        Mon, 26 Sep 2022 14:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:68d:b0:351:10b5:2e7b with SMTP id
 k13-20020a056808068d00b0035110b52e7bls161832oig.11.-pod-prod-gmail; Mon, 26
 Sep 2022 14:31:48 -0700 (PDT)
X-Received: by 2002:a05:6808:1b2a:b0:350:e5c0:59f9 with SMTP id bx42-20020a0568081b2a00b00350e5c059f9mr360451oib.189.1664227908226;
        Mon, 26 Sep 2022 14:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664227908; cv=none;
        d=google.com; s=arc-20160816;
        b=QLggcI0IIxE3csdRujSXsi9RsmqJQRRI78hK6+whmj0LzgqdS8k9P9CiGlfVyPcFJg
         8SIPLgtWNSO20iIF6DgWzXCgnOIEsJXmHpcs+kG+5fD7I1oOQn+oRvLjazNA3ZFQkAOH
         tHIKabUTHKKYqMb8UQEa7JTNTSZ0UkKegi0b7PlIiCgMMiEawPUmAsoravs9bGl8Vuod
         /QPnEJ0MBffq7S2RC9q3Gmq6ppuJY87SB6t4ks1AKa0qF28yY8kb4xzUmUojUv8AasW4
         cSaldUI2cjH7CVO9NrNTRnKgkMtpkaO7tmyNapE5SKAHHCjMfUxnJ4GEnSXqeRoglWeG
         jIhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JLbf48vjMlZ56ruPBS9/QkT83yj7vuavaEds8C6XntY=;
        b=g0DG9urwpyTEPzWsoLCXHyoV6SbN208rCyrvaSOBlbJ7xFLwYncNDy4baYCjNpAmaL
         eEaHKKXRKLS8yRzSl7DujW25GP2YBM1tIH4aColl9vCihvwDo+da0o2RO9xS8siKW4eO
         yxqiZ8ySM0QYOM3BmI2/9AM2ilf0QYqxrZcUoloQAU2KRNKqcmv/e+8KggA66Zm/w4Ca
         p7x/SneosBWoPOqT5cAIqPOElCsyHqOQUT6ruc7nm0Ui790MTeQn1ts1cZ/PaSfk2tLg
         TSSHSzn8MygzdQKLjAzkX8yMJxBBVuxv/QiJVjmmMF+VkE/uvBO9t0s4XSrnFfyrfWNT
         ys4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=ZejhL1fX;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g16-20020a4ad310000000b00476406eaa8fsi545514oos.0.2022.09.26.14.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 14:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CE2606145A;
	Mon, 26 Sep 2022 21:31:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 75A9EC433C1;
	Mon, 26 Sep 2022 21:31:46 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 0b02cf89 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Sep 2022 21:31:44 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>
Subject: [PATCH v2 2/2] kfence: use better stack hash seed
Date: Mon, 26 Sep 2022 23:31:30 +0200
Message-Id: <20220926213130.1508261-2-Jason@zx2c4.com>
In-Reply-To: <20220926213130.1508261-1-Jason@zx2c4.com>
References: <20220926213130.1508261-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=ZejhL1fX;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
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

As of the prior commit, the RNG will have incorporated both a cycle
counter value and RDRAND, in addition to various other environmental
noise. Therefore, using get_random_u32() will supply a stronger seed
than simply using random_get_entropy(). N.B.: random_get_entropy()
should be considered an internal API of random.c and not generally
consumed.

Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220926213130.1508261-2-Jason%40zx2c4.com.
