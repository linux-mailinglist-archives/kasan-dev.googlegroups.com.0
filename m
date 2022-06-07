Return-Path: <kasan-dev+bncBAABBI4N7OKAMGQEO3C2URA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B248853F485
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jun 2022 05:31:48 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id q5-20020acaf205000000b0032c2eeaafafsf9624112oih.22
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jun 2022 20:31:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654572707; cv=pass;
        d=google.com; s=arc-20160816;
        b=uJiBC1YXF6Hi0z9f+BWXdYQI8NgFIO4rlYCPrDPCDVW9OQHPORnuBtG8hQXK+YgAdT
         h2Lfn2rr/feS5gFtTMS71UfkqujydS5CAR+aXBDqQdVSdNCCFaqsFadViIJogTUuvjjx
         9WFkdRegA/rcP3KwC9gjV6LdeXfmXywvOhwKHOJ/Ll4u2T07SghcJfLAhk0NfiLCKqdN
         cz929eGC1EPrtcCRjjqjanplSC2BomOeiDN0P1In2FssoYCB4s3NCYhcNn0pbYVlh4J5
         KBdxmujFIZIuRcITLvqdVUjh+qLfFK7KAcaqpOLGczCGNbdZjdLI4tGeUthK74H1F1rm
         micQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=0oXF5dT/MlYQSiJgs0epNdYEsLQzv1VbOP+xmxuCNmk=;
        b=BZo8JXFK6Oi2kMawpi32XW0plO1u73k9xe2pzqPE7xmmm+Nlpc3y+YjdE7fa8Rqq4N
         43qpccFlve1uGgWzDOAclsUVHNE54TCn+VdGF5xSf8VMhN7tPP3NkrGStFGQutOLMo7u
         NQ2deFI0r9WgP4dWt0E9E1xgGI+uvJezcYOGe1IojKEKurwD0EDDBach71ZPwZ0InFSa
         YyWMm+gk1Wl51kLP0bpmimpAcRhfI8p127xoZfeomjxvKtOwzHijvBrB9/OM8P+NZ+q5
         H1mXa9SQac+2fjGCi3AQg+3thBf7tQRxw7xlqfDs+WgB9D2lCPjMgQ2rllxH9+SAadAW
         5SZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of kunyu@nfschina.com designates 124.16.136.209 as permitted sender) smtp.mailfrom=kunyu@nfschina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0oXF5dT/MlYQSiJgs0epNdYEsLQzv1VbOP+xmxuCNmk=;
        b=NmrDO1SOWUiMA6w6jrTnm5xIUy9qMmK0vhHDmbOZcy5KpcxSCo205mGrNLFdrBtxPC
         9GV/KAyz5QC33MfqE0KIet5Z1YCNR5xYx6gOxHvX5WFxgW0pSPkSNIeMQ5k7sWwsWy0k
         0Hmo02CgGG/DfhJjUAaL6RP1Kq9xqTVdVglBzD31vLF8AdbSg8I8brGDDyRmpF+IijFU
         anqgjJFJXFkq7Xg6ZsoCFHrjquHTpNy94BoLOjJ7+88+kd/i4bKtM3dSw7SisbeZZjZs
         r3WX6XwyXM+rIM/RH5LxSoVlPWqOn1pOm2kBKxuTpPI/ZFhuIO2P8KP0J1GQm7hZv0v9
         3Wsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0oXF5dT/MlYQSiJgs0epNdYEsLQzv1VbOP+xmxuCNmk=;
        b=e36q2x//PxiLF6NbWILDdco+oMfIswejiTtc6e+bkvPPdi9D2y3Twjq6/YvTjF9eDl
         0xoovmTogGkEwemmfyPEU5eyUGx5yZl2c2pozHTh+Srma+AEJji5RcMbU3ImeeNu/n+4
         JDr+30CFA97eOScEUVE1RMJ6KYH2zM+I81FEzNwBtH8fBddqQqaadBO1BUuYfNA8kwHB
         l4SLRQQT4iSwmGMTOCNpboGX9RtAtl7qHk7VyslQti5SHCxFHsMCzuUmqmR8NXvbFn6l
         Wb7i9rZDnXUJn16RRLHQJO5bxeLlYRkSBWBcYrasmW8kfKUYUfexrRroooJ3TX6fsFqP
         Kf5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330rif5kiudPkPR6ECg/nU7rw8+ycLqOzcaiT/sWh5eismSfZVf
	9tTg+bnNSYOLDbeQS0Lh5O0=
X-Google-Smtp-Source: ABdhPJw5bWlO1RTyEquVR9810CA6MM0beL/WsgSg8dOOtuRZCI9KTILurZ0+A5gKYcKOEx1jpEGjPw==
X-Received: by 2002:a05:6808:d50:b0:328:c9e6:3c52 with SMTP id w16-20020a0568080d5000b00328c9e63c52mr15238571oik.231.1654572707421;
        Mon, 06 Jun 2022 20:31:47 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7a08:b0:f5:e876:9aa3 with SMTP id
 hf8-20020a0568707a0800b000f5e8769aa3ls4453390oab.1.gmail; Mon, 06 Jun 2022
 20:31:46 -0700 (PDT)
X-Received: by 2002:a05:6870:4584:b0:fb:6b97:b5bf with SMTP id y4-20020a056870458400b000fb6b97b5bfmr3004638oao.109.1654572706812;
        Mon, 06 Jun 2022 20:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654572706; cv=none;
        d=google.com; s=arc-20160816;
        b=sKwUxeS6ae58tEqSfFn6SJXGRWzuX8ZPqTOG47muBUOHXoVPdEpNBM5QENN30BJOr6
         +vzsWmOvC6N4CIlhqdNHqadhVp737jyDKSBq9Hk8XqNXrsmhTzFaNs4B9uGJ5Z/CVD5/
         lswJlej5vBmrN48Od/YMwnLsr9RrG90VLAxBQ4bjbS3XhGD/xCHxhZAuX3Jj3zw+9XEf
         HZjerdFZV94voaX3m0e2zsaIkNc2MMjoQfJUW0ysnCAs0jg+l0k5r1LL8QumtbOqLSQ8
         HHGViBSkC2F/Lcekuzs5Wxa9LYYnJoC93iEgu0zBtDqcz1NT0zLKs+Cej+6tQpGMFeKj
         EdSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=Vtrr+02ofV5Z9gPNp0Tbi3jRl4uRBmgkF4ORpJNdQ+o=;
        b=yCJ3mlT95//7gGL7PMKJwRFUDwlrnvIsIS9lwFgXE2kheE934axETYNU8VqwVMxbbv
         /D0R+IexSVghzfs6njHeIzt+8WkTsEsf+hk/1pUaYvAu1stt7xQpqv5l0fHDLjRglFzu
         vUGZbdPx0jGWAg/WK4QEcjCOY5bh1ZAWUmzgAMOFlTgyDS7IaBghorcPypk1HnS1Glj2
         6IpYkgdckYff1gFMCutuKQucAV9Aw7+zgr0QL52kNrkxFgq2xAuehcUPNCGZ1qgcSDE8
         FA1bfo0ZUbtBxuCk8qjGuGazWSspfUU9pB5OQWlOSJhm9tjjBcwnLdrrI4DlujUXiXMH
         vrbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of kunyu@nfschina.com designates 124.16.136.209 as permitted sender) smtp.mailfrom=kunyu@nfschina.com
Received: from mail.nfschina.com (mail.nfschina.com. [124.16.136.209])
        by gmr-mx.google.com with ESMTP id ay13-20020a056808300d00b0032b08d1cffbsi1516342oib.1.2022.06.06.20.31.45
        for <kasan-dev@googlegroups.com>;
        Mon, 06 Jun 2022 20:31:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of kunyu@nfschina.com designates 124.16.136.209 as permitted sender) client-ip=124.16.136.209;
Received: from localhost (unknown [127.0.0.1])
	by mail.nfschina.com (Postfix) with ESMTP id 0B8461E80D74;
	Tue,  7 Jun 2022 11:31:27 +0800 (CST)
X-Virus-Scanned: amavisd-new at test.com
Received: from mail.nfschina.com ([127.0.0.1])
	by localhost (mail.nfschina.com [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id VxJoDDgVzgzL; Tue,  7 Jun 2022 11:31:24 +0800 (CST)
Received: from localhost.localdomain (unknown [219.141.250.2])
	(Authenticated sender: kunyu@nfschina.com)
	by mail.nfschina.com (Postfix) with ESMTPA id 261341E80D55;
	Tue,  7 Jun 2022 11:31:24 +0800 (CST)
From: Li kunyu <kunyu@nfschina.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com
Cc: linux@armlinux.org.uk,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Li kunyu <kunyu@nfschina.com>
Subject: [PATCH] arm: create_mapping function to remove unused return values
Date: Tue,  7 Jun 2022 11:31:22 +0800
Message-Id: <20220607033122.256388-1-kunyu@nfschina.com>
X-Mailer: git-send-email 2.18.2
X-Original-Sender: kunyu@nfschina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of kunyu@nfschina.com designates
 124.16.136.209 as permitted sender) smtp.mailfrom=kunyu@nfschina.com
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

Change the return value to void to reduce eax register execution.

Signed-off-by: Li kunyu <kunyu@nfschina.com>
---
 arch/arm/mm/kasan_init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..db2068329985 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -187,7 +187,7 @@ static void __init clear_pgds(unsigned long start,
 		pmd_clear(pmd_off_k(start));
 }
 
-static int __init create_mapping(void *start, void *end)
+static void __init create_mapping(void *start, void *end)
 {
 	void *shadow_start, *shadow_end;
 
@@ -199,7 +199,6 @@ static int __init create_mapping(void *start, void *end)
 
 	kasan_pgd_populate((unsigned long)shadow_start & PAGE_MASK,
 			   PAGE_ALIGN((unsigned long)shadow_end), false);
-	return 0;
 }
 
 void __init kasan_init(void)
-- 
2.18.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220607033122.256388-1-kunyu%40nfschina.com.
