Return-Path: <kasan-dev+bncBAABBO4GSGKAMGQEMJAV47Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF1452AF62
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 02:52:12 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id k5-20020a05600c0b4500b003941ca130f9sf292890wmr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 17:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652835131; cv=pass;
        d=google.com; s=arc-20160816;
        b=poXuDmXufISy3uqFbYK7QVX8FALfLgZenuvj0tPUbmhF2iYWvBXZdGR0QBXm2ptvSV
         o27Tsi0eyw2knQvmfNAtEA9KpIjbq0Nh4/NkPT7R6q0RqWs0zE9o0nQdnpLkUXggJtwC
         cl+ZA3ce01Ke2VIC5bd2biOM92SnkgWaHouyIrjdVzKUujnK7IErkINTJMEEtu27PBUd
         /tXMpaGj9HrHyNFcIJRItvmsfsn6CrDFB0f6TSvkLdQBajjYZPwU/6+KLtlUsZRRx1Ke
         u32Y2tspBJf6firj4QRYz8dacAzC4o/1UUeffovEe6F0JLiTsvsi10uzGj0+DHnpXjyC
         FGNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=0YqqT20l2F5e4McvUQsYUYFs6ymji2s4gRlOpycwtiI=;
        b=MlaNs04+XpNJJP9KgfAjswlbRNYz8BN0PY0rrGW9ZAMFIgjHIggskqrZKBj6KpzhHc
         rhYDYQCKf2Zfh1ypXUVIYG1e1KpRok77hbGmPgS0OSijU8UJEsRw38Ou/hF3zFathRhb
         pBU4VGp+daDutxGIUf5AdUkIuVg7xEzvpGcNRr1F560LEJWAdby5WBMNRWu8Lm0KmL5T
         QLkSI09vFeMEX9N3UQ7Zq8MSgYefcoz1kmixKddsb1ir8fwp9IaI+RrPT+QNmctxB7iv
         aWwm8oGMMTxtQ7LPnc32aRJ+z9FF2eIw41W1TuL9PSVLYkC5xtessL1Gpx7C9p7Wg772
         YFpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZLKHuiaR;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0YqqT20l2F5e4McvUQsYUYFs6ymji2s4gRlOpycwtiI=;
        b=emhy9Ys4iGGdCcrS7vuccjSvenhKSQB9Fsq1Hgyd3Bt04On4+Z6ZFHlEGYJcIbu17Z
         W9uOyKw6ERYc8PpSOdpdIWva14okZEnSkJdEQJWDZ1JgAFMK6lSqw3cT3e9c1OyWOhNG
         OLfdr2b1vMe1EFn5OE0Eb3aknureKSub5ugfSpHIkh+ntYqeaBoVqheFocd04WPrDzxq
         2thmhITJvvNY/7KKMKOcxP02zt5RAshqrP2s78nrciLNzL0ZgXSc5C43UbAdPwJGye8X
         lU5kAl9B+if35femrTtbcfSwnMFbpZ2YrKlSzx8XFpCEnLjTudeaK8Du3ZtAA2AMg0sf
         Yvng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0YqqT20l2F5e4McvUQsYUYFs6ymji2s4gRlOpycwtiI=;
        b=cBLCl3EL/HIfSPZ7c0Wi7vIEIIYeV93/9iGHFZrcxxHYsVxXmyLnoeWi4vZ36lNaIl
         0HeO2RWgjiCaTzDmGLqsguRX40KFgvELBj16IbTd8if6aScVL3R5O9ltcLTF3NTQU1R2
         YJMO9YnPMLUnRhLlir2WuHhpeotyo1zqZBx6z05i/POeIS1qDt8pjmtoC0JBVvfZBURQ
         BFuC5ovyXMokWcuudRKC6ZhX4bS7pldpoDznl19NZBHWqai/JoMpvDbAwiduFKtL161M
         kOFMqRHBT2wBf7surNH2yOdAOb3saUvUPosU540pIXxGTEmgTw3W/plVOfnQRxwlLAPE
         BAJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SxNvotLtrsO7Pduo8TDR4xhIMQVGS2w+x6DygLvGHAWj6FDsr
	gRjYTPDbUl9JcfdJ9biVnyg=
X-Google-Smtp-Source: ABdhPJzbZ8AYmFdUHOiLy0eQOr/Z1zovZ/eCPFOmHrActARQeKCzkpeTp7XR/AKywo64lEhz3EI1Pw==
X-Received: by 2002:adf:fb0d:0:b0:20d:97e:17ce with SMTP id c13-20020adffb0d000000b0020d097e17cemr10279648wrr.585.1652835131713;
        Tue, 17 May 2022 17:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els5134841wrz.1.gmail; Tue, 17 May 2022
 17:52:11 -0700 (PDT)
X-Received: by 2002:a5d:64ea:0:b0:20c:5ca3:a0de with SMTP id g10-20020a5d64ea000000b0020c5ca3a0demr21465459wri.308.1652835131161;
        Tue, 17 May 2022 17:52:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652835131; cv=none;
        d=google.com; s=arc-20160816;
        b=XUooyEk5s0II19AI9oBzt4Y5XIVKlqf3OxNW+pNvPg7oIFrZyZRctCmwc6JWVon5eU
         kR6mA6cOHHXjMtToGn+3jp9+3VB89uKh82N4uJABIADABZjoijN/DMq5sbem0rF5dHy+
         iFsotSK7LHa8+WYvdlK0n0GY7EqUwbjdXqLUAtQ6R+isIXtsiAd8Y/nrMFJ1xleYInzN
         xiFy1ndwjonyCBdqbtBhNCtB8KXmUhDJ5PBwXupXYhg0u7oXMOzRMM/GRK+inEDz9tMS
         uAzAukMxHjnVVOyV+8u5g0MSLBugqY+6vjjqUTHLL/6TIpNESrDPl8gkWBcvVfvb71sz
         CoRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pqfn+Mn0DYWU3NSDwIhdEh/eAd5JYvU0926dCbu4dhw=;
        b=R4hGathNx6Fq6d6DoqNXrGfI06wDLDslDe1FdYTpQdHp0D87UTctv31DA5UVAwkFLR
         17cMAHdx0bi4Vx98m6jigVSSgmRyImD6vnADVDEWNUSItQl49PjUOyz2Df0m98bcAY+n
         q7fu4MsykANyhHa8RgQ6OdsydxRnn/Qz1JZnno9JDnWNscplQKkCG5edJf71MSdUex5r
         +V+g9lh0BC46IIBYmcowUQjWgfM6TrfjrnNKYYlPHkvLu7m+yQwm3VlHkfw0DQuVIGPT
         pb+a6cznFTXBsI+ZVb2QOQ6SjtQpVyzvqvlBmwFcxvaeCen6RHsVn49DjYYD7pSTeUB1
         TcRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZLKHuiaR;
       spf=pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=liu.yun@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id v17-20020a05600c215100b0038e70fa4e56si251145wml.3.2022.05.17.17.52.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 17 May 2022 17:52:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Jackie Liu <liu.yun@linux.dev>
To: elver@google.com
Cc: glider@google.com,
	liu.yun@linux.dev,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v2] mm/kfence: print disabling or re-enabling message
Date: Wed, 18 May 2022 08:52:00 +0800
Message-Id: <20220518005200.4150246-1-liu.yun@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: liu.yun@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZLKHuiaR;       spf=pass
 (google.com: domain of liu.yun@linux.dev designates 2001:41d0:2:267:: as
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
information of kfence by dmesg and record by syslog.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>
---
 v1->v2:
   fixup by Marco Elver <elver@google.com>

 mm/kfence/core.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 11a954763be9..de5bcf2609fe 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -67,8 +67,12 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 	if (ret < 0)
 		return ret;
 
-	if (!num) /* Using 0 to indicate KFENCE is disabled. */
+	/* Using 0 to indicate KFENCE is disabled. */
+	if (!num) {
+		if (READ_ONCE(kfence_enabled))
+			pr_info("disabled\n");
 		WRITE_ONCE(kfence_enabled, false);
+	}
 
 	*((unsigned long *)kp->arg) = num;
 
@@ -874,6 +878,7 @@ static int kfence_enable_late(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	pr_info("re-enabled\n");
 	return 0;
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518005200.4150246-1-liu.yun%40linux.dev.
