Return-Path: <kasan-dev+bncBAABBB4IR2KAMGQEVN5GAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4663B52A036
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 13:16:24 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id w23-20020aa7da57000000b0042acd76347bsf471185eds.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 04:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652786184; cv=pass;
        d=google.com; s=arc-20160816;
        b=oX+4t1A3v7rEq5agAQxqgwT4eRAC9xgCw2mWt9A6NvrH/7uUcJI6kk9GyIfzFipuv0
         rOVKTSmQspMObM9My5WxuO5Q0C7SeIWliNAaflMhbxtqI8UHUmNdptyrbxA6t/xvg1Gh
         6pOLFetUHssrHGQ+j0EGKy/7y0aR8xuOMbJZdCEr3Jc8eov3ZcifK//NGp1UYEModxCo
         PMu+y76phyj61OAcJbE+iKUxa9xkTUJOACgQzWH5sNdnr7mf/5RSnRjoBNqBjd1tURkr
         u07aaDp8X6KcxF53FhDptrQ5PJ5hRNFDPMYXy8uvBv1kVRVu+V6lSzaS7Ukx+Pv6n9Q+
         KttA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xMOieLz9G2gOPRpvSHVjX0ySTnnZRXsch33BX3gE1ww=;
        b=DZEAI3EYglZqyycCDT+8safYrZHHIKYAuV6NeeVTCsa6sduJ7VOHvgf+E/w/el9mjQ
         oRPwlGZZCUf9QYpBNYxO6p5F/Uxd1O2GNKOCPUjNGMDi3xEQFPOoU3QPRSxqmsNgNluk
         AsI1uFNjj+QuDzcA3brkq43jyZJS9T90mbObb/eRS1F07xVqqCvZz+tmZ99y9KDicrz3
         O6R6CmHs/gcUSq2+XWTbW3w700wkzR7fF/IbGLMfq5BtpiGXs0Gnv204XDRSjOduT+W6
         Qm5aHEMkqY6aVFPrNvEY75b3DmrCCjKHy++U6kNTFvIYY6SkwAQ4JRxwid2B/GxX7DU2
         LH/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kp7PzIji;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xMOieLz9G2gOPRpvSHVjX0ySTnnZRXsch33BX3gE1ww=;
        b=POsF3/QhJP6QI0aBCs8s2pyJvg59+LIDQYOsoMEoQcOgup1O9XpqTWHbxYWwrJhZgk
         aWo4+3HaeWTRHMs3vZzgR6mtW2Uy5BzJ93YuL0twYk/xa6D/XZ8/a4ggIP0K9/tKREjh
         dmK+UsF1lhcsw9Z3ay5lNWqUV7gOEDMDZTYFm6OIBH/6DDdgffU8HQ3W/+z+vN3HI8Kn
         DRDlrtm6ADc5DloFuSCsZJ9tvhJR6FvtfgTxADJaVTLVQ69ZrNvCzsD+SU1eSl0tR5P0
         OvMPui8IyFZJvwpocGCINM27leR8oHTgvkJfKlhiQ8nlT1Jmv1ORltq6WxJJX7cRoheK
         +0ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xMOieLz9G2gOPRpvSHVjX0ySTnnZRXsch33BX3gE1ww=;
        b=2Yf6yR0+V/XEw37YYJTkfjc4rYAktRhHQjNvjxPjRXVcieNa4qRB7n1syoA48Pzz8I
         v6ruVI1P5QaqW7B3WLD/+IegOhsGYbeLg/I4Gak1xp4RpwoERB59zzCor37EVLiB3nVB
         uTwQjvzFRCva5YbbrU2oEjLZ3JYpMS43QghT1g7pf5nCSQAE/zSzrTi/bGEm/6F0Q0fA
         OfPf1GLP716AwqQeqKv9SOMtNeetwWNOXmclAyEzRcsZY6dx4Rb/Jwwu18rNNnYHWABD
         D/2ctvVVh1ZtSxP0VPJ4jjChg//aqe07SuVHtIcBIGloIkSHWEEDXpjKx3MH/2/q/bF6
         oHug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323yG9aGUIb59cL4woe3+6qXjmI3VTWJ1tsxHrNIvdyWquBFNRG
	/mlN61MUEQ160vtVhInwisg=
X-Google-Smtp-Source: ABdhPJz6fviHS4++KpB3Gtm+HLzX3v41bCc5ZwJiNm6IsaZtzSBFNVoxSwgKhFHUNZgvWPP0CE2wog==
X-Received: by 2002:a17:907:9623:b0:6fe:1c07:f363 with SMTP id gb35-20020a170907962300b006fe1c07f363mr13658548ejc.255.1652786183822;
        Tue, 17 May 2022 04:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:98e9:b0:6fe:40aa:f8c5 with SMTP id
 ke9-20020a17090798e900b006fe40aaf8c5ls751555ejc.7.gmail; Tue, 17 May 2022
 04:16:23 -0700 (PDT)
X-Received: by 2002:a05:651c:1055:b0:250:9c36:eb1c with SMTP id x21-20020a05651c105500b002509c36eb1cmr14336040ljm.276.1652786182936;
        Tue, 17 May 2022 04:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652786182; cv=none;
        d=google.com; s=arc-20160816;
        b=GqlYTbbSIQ+J4TR+lB33inesFsugXNoFnR/SzLotQz3qUWLyuC3OIjEHVKw3iWqvWd
         lB5MuZs+1kzSeEJJEtF6XH5bweaVNRql3uAbZUNNWgMn4Hkrqx9eRDQ/6yw2dqvJleDs
         /fBc4/87Hr6CjT+1j74QwDpvNeDheskrunzhoGAdymI+ZpgQ97hm46bvtCVP5DDK1Lfe
         urDnjiRUUWgj6H97ifj0EqsDYo79d8LSgaqn4DyDNz+GgbyYxlcZUDYt48yYr3taGXUu
         2LWm6413s+nIElKEnhZTBolDtOTv9+nN0SGPFRX8HkahPfdRF+3awKRg3F5kR/4ROA29
         zPiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GFXG0AL6zVxDtCvLO8G/I3Q+cbj8L0rmDOvKuJnP0cQ=;
        b=mpeGCbRPjj+7963Cfa4jBUXyy3ComR7iwqhjgecucjr00VqgrMc+B8Z2q7/fN8HVP2
         qCmj9dMEIJQTWi4o5YwRHp7DdctbxZ3TtLNpFNuL2YH+7E4OmSezXqh5ZGFSPoUOV+wr
         Pg3uShGZ/e73/iWpDgljt8RZPq7zPhCdkRdpT1VLrMLU72Lu42WWrHz6xH2moO779/M0
         /XGsEmdy9vA6fnjkPxa0uC4Okjvr7uqJUJUdFCzjHwvhB6rHI7ylcvbRdil/MkZlBPyy
         ByJK0WIjUv3e+b/0Mx/+skZXaXGILenrxmVn7z1J5S4CtQBb1Lt4a2eLErHZoFZKuuuj
         tjTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kp7PzIji;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id u11-20020a2e91cb000000b0024f304af5b0si636785ljg.7.2022.05.17.04.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 17 May 2022 04:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
To: glider@google.com
Cc: elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH] mm/kfence: print disabling or re-enabling message
Date: Tue, 17 May 2022 19:15:51 +0800
Message-Id: <20220517111551.4077061-1-liu.yun@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kp7PzIji;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:aacc:: as
 permitted sender) smtp.mailfrom=liu.yun@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

From: Jackie Liu <liuyun01@kylinos.cn>

By printing information, we can friendly prompt the status change
information of kfence by dmesg.

Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
---
 mm/kfence/core.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 11a954763be9..beb552089b67 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -67,8 +67,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 	if (ret < 0)
 		return ret;
 
-	if (!num) /* Using 0 to indicate KFENCE is disabled. */
+	if (!num) {
+		/* Using 0 to indicate KFENCE is disabled. */
 		WRITE_ONCE(kfence_enabled, false);
+		pr_info("KFENCE is disabled.\n");
+	}
 
 	*((unsigned long *)kp->arg) = num;
 
@@ -874,6 +877,7 @@ static int kfence_enable_late(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	pr_info("KFENCE is re-enabled.\n");
 	return 0;
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517111551.4077061-1-liu.yun%40linux.dev.
