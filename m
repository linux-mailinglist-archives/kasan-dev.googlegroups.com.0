Return-Path: <kasan-dev+bncBAABBTGS5OUQMGQE53XV5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 449EC7D8BBA
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 00:33:50 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2c51ca27f71sf14971491fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 15:33:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698359629; cv=pass;
        d=google.com; s=arc-20160816;
        b=dequA5u2h3QxoYeYlf2Wlks/0qhBpg2MbhyjQKFSS7ft+0b+RM6LgPwNU9HVyAknCJ
         FaIJLGBbdEBTxS8VylN0+pckrL4qQjVS2fjxKPMYRNCIsCRlQkcGYDy/mJMcGsLJcjz4
         s3vpVleNez9M7uRUukoIC1Aro2655xxFnzylmKHWhjEVht8R+Eam74LglPBb76/BUEon
         +pVh50A2gcHJyNKXJsFys0vhXGzb5zIJ3LOvjunB2nABuZyyyaQe99v/7nkOWUqY7m6c
         XuVM9J+INJatwqdN4MoiLtJZ291ZBHEXSXwpK6YWTTRd4Fjt4qm7FqqUgfvHfQC4Pdp1
         ve1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9vHwjNvGGgLAasoQTRCovLdp7a1UmimMfExiOeMyIL4=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=FxPShx9QoiNr9OmBKXX/MBkV1pxmynyptq4Bn1oL3i7z0rg/gq84TErIyoeM2FPAiE
         1tcn5PdN28TpgqCr8dspp65zbkgxt7wJ8sZG1QheRvQb2Cvoh+w1MmW5B/JG5dudEusv
         JvsMpLc0P0nsrf0BcHv5lcOZLvqj0eK8kCyBpDsIwhu24HHqITNPcUKJM6z5IcZ1Lnb1
         JXbYOc9znIpQbh7F/knYL6qSwrLmNaDlwDaSDcoVSLL2u2sAuk2RXwPrs+hOjJML9qzk
         gLb8Vo5arZ97QwUq0U2/WWE8/vAliPqnJeZkSCsJCP3fYBQUlAxP1kJF1rmjPbgFiTrm
         xJVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DockHeTS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698359629; x=1698964429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9vHwjNvGGgLAasoQTRCovLdp7a1UmimMfExiOeMyIL4=;
        b=FZZWZbNPw4R0z39JDDJIwKqU0a5W0z8u0XZ9qAiqVd6Xjo1LHAiklNwUZ7QLsmrH/s
         C4XpjHT7KTQwwQ7KAF292XpNjdzxIo8BCDOPVBIC5rwmPsCCs+FMg5R3uQIc0ycvq9y4
         DdKX5mDnIxGUCBQDnHaiS4dN0bw+OdQIW8E8IBgaovvA7d+zYnR36vcskA9+Hvsgvt3U
         t0ZXZSNqFuquPDO8gpn4PfRU22Ul2KutRyon7D/W5fFMj1WHor329vmB0wtzh9m0XV/5
         QJY3KqQ5I8ZzSF7WeCNnB9TOdQ+/1LM7iI9WLBEG7AwphU2/X7CGv7e4Aa6SpOB73Uo3
         0tlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698359629; x=1698964429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9vHwjNvGGgLAasoQTRCovLdp7a1UmimMfExiOeMyIL4=;
        b=TSXdj5ZrzvBbxb6/IwsiVQg4w4l6BdmvuQ0UkwnjzMeIwEGrKYsAdyzuAWFEC7sEBE
         HptR6oO8NVfTuoCAcqNztxlvQOa/BgAsayWoDIX1g+cn5+KDk89pC/zRhy0IfY/c2UWS
         9TJi1IcA9UpMrcv15k2bFLtmMk0ycWrabs+b2Yu/Zv+PAEWjESp2V44b5ZbywwFzvd3t
         hSs0EN9PRj+baMQX1qub/bcFRRPMj/duUOGh+9r8NMX8VJ0uFtYBQ7bBHt2BkN5R3IST
         AJRbuQqxLjnYD33HXTT9hHZ0pIVqiCuIjQ+z8xYS2p2dBoyQ3rQPFdt1q8A0c3DBtRcA
         QUxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzsUSyvDcpwCxu92kQPRuIEeajGlTBUv3G+CX8TRhhmwryqiglN
	gi5m6L/rfsDUWeySz5H2LQw=
X-Google-Smtp-Source: AGHT+IHvWxPE33+gK+BKCeekWA8U3XZxGFXtqmUUu7QGBpzw4zWxThp6/RLLV4BiP7O8O4U61azoWg==
X-Received: by 2002:a2e:9e05:0:b0:2c5:380:7bff with SMTP id e5-20020a2e9e05000000b002c503807bffmr596900ljk.25.1698359628465;
        Thu, 26 Oct 2023 15:33:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a21:b0:2bf:f477:1991 with SMTP id
 by33-20020a05651c1a2100b002bff4771991ls262193ljb.2.-pod-prod-01-eu; Thu, 26
 Oct 2023 15:33:46 -0700 (PDT)
X-Received: by 2002:a05:651c:2124:b0:2c5:3490:9bbc with SMTP id a36-20020a05651c212400b002c534909bbcmr779457ljq.26.1698359626350;
        Thu, 26 Oct 2023 15:33:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698359626; cv=none;
        d=google.com; s=arc-20160816;
        b=wKxANqW5HtSOQyIlWoDBsYHDeYPA+Cj9sW9edpaP6HqETiWC0B9T6JPC/KUo6ikgvL
         MWeT1efAJ8zEUnYIqeZbXIvrCpLiG0DKd50CNVL13Sbm/YM9GSVi1gES8UTpkKEWR4Px
         sABMhWZ+JTsnUH+60hOzZoMfd6HFK39eZOAGUx/x4rOul+FUi6O81fo2+kftR3EmnB7Q
         Ceui2NMjxoVXQFpmeYAy5K4LGOJUjgAsLyPhYJZ4jSL4F2PHXZbSf6R3/psDKJet6+OR
         +sp1s+jHZrUre4OFg1xgqQV5YxkVFwkkdF7FoRi0FQU3AdCLzIqWe80ALiIjp3beq5Bi
         qBTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7wiIXHVKZViLnzrPPkXa8K3V9xAsF9dc3+hDNlwl8Us=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=cWVfPETVg0QYCwJxbRdKoYZV/RBDAsOJmgxGlTqv3Tz314hzKRDpwJlFAs9inkg2xA
         LBTiWZztTKr4Ic0eMpwpYvU2CrTa2gCVwYsuOSCwFXQvmE/sSdXtX547VZhuacXdJDWB
         2sbUWpmuDoI2wSV/r4msY7CfktVKwqnfE/ouaM8WaRkZlqqP8zAy4z6pyMnX2Bg6zdiT
         CFAN4metVWxBO1bCM7NeVmOSiEqo1er0FSIu43wtW/XiOXflIl6SQds/xWEJM6cDlbDi
         4oayMaG0haFfMNDXlFsUiunJVqB7zhq5qXzGVY/vlmD2VF3HXZiinK55Me4H0LWDfUCn
         dhQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DockHeTS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id a12-20020a2e860c000000b002b9d5a29ef7si13363lji.4.2023.10.26.15.33.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 15:33:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] fix for "lib/stackdepot: allow users to evict stack traces"
Date: Fri, 27 Oct 2023 00:33:40 +0200
Message-Id: <20231026223340.333159-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DockHeTS;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Commit "lib/stackdepot: allow users to evict stack traces" adds another
user for depot_fetch_stack, which holds a write lock. Thus, we need to
update the lockdep annotation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3a8f045696fd..cf707ff32d7d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -388,7 +388,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
 	struct stack_record *stack;
 
-	lockdep_assert_held_read(&pool_rwlock);
+	lockdep_assert_held(&pool_rwlock);
 
 	if (parts.pool_index > pools_num) {
 		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231026223340.333159-1-andrey.konovalov%40linux.dev.
