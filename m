Return-Path: <kasan-dev+bncBAABB3POZSIAMGQEQYLQK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C18A4BD61F
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 07:55:42 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id cg14-20020a05621413ce00b0042c2706a4besf16163169qvb.23
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Feb 2022 22:55:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645426541; cv=pass;
        d=google.com; s=arc-20160816;
        b=bseKaxxRfWEc0PvDAr/qTVt7WuhAmvHI4B7RlHf5cPZhQNTRfR3k49wq3Gi8v9E9BC
         kzKQhF9ko9HcBQbc3yynAdJDKpTK3jVKoJLo/zLFjie3Mt98I5affwH0O0FwacTVxuoP
         0fhs0vcirFxL5pnVln7BoB0QeGQ3ZE/83J0eP08kHYL6qCkf5DcyoO4P4oAW1GzW19Yz
         T0yqe2rVLNqQOS2W6xVStWIQ2zdQumbwq4T8i/xI2//ITrN40tjKedhq/cI7c9fRXbz8
         gd71AphEUjfn1TdjfCF2ty8OndAR6yin1jNdx9i7ARtyr5TzOEPiea8SRRIxXTfvg3cb
         nhkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:message-id
         :date:subject:cc:to:from:sender:dkim-signature;
        bh=nMbtn962bJyODTJ60nMePYv0vJMX/g6tFUaUMuEAtIE=;
        b=hsHTJwF3g/TULZaZCd1hrC6Bt4UZ9qPco8RKhNw8xc4ovCK5FyIZ7GLpewuj7kCqjQ
         7NCDIvknYgC/gFvp0aU5Astt2X8oSVxYiAItlsdzSPrhPAfNY8/sDDWAROv/DLanNMZJ
         9O+1o2Dw3QoK5+SAu33e800DTiH54mPzRUo/XI+3lsTtbxod2YzYN0B7ivVqZ4eZhhPc
         +8OKD5ZoUOEY6s+JbiyghCj8QRvWzPfo+S2uSCxoE/ieKy8S/DgKKStB2DUOKtDqj0GG
         bA008evKOGhvE1znvK2HYe7W/VMCSsMRSXNlh9B5MPRQBFlEA1h43/x9161db6EoJtZ8
         BERg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tangmeng@uniontech.com designates 54.243.244.52 as permitted sender) smtp.mailfrom=tangmeng@uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version:feedback-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nMbtn962bJyODTJ60nMePYv0vJMX/g6tFUaUMuEAtIE=;
        b=ig7vAOgFN8IPDb3nG/c/oNToaaQfy1hz0y3TM7JLlLfxJl7VVwkzs+IVg1JPTCCrd+
         BrHt+IHAX7zSIPaq9doGCLI/qUOVP9IMby0X2Jn2v9VKhjvJzepg2u45m1gkY7OzzT8+
         mKdZnCdKycZWcx3JAZT6B9bZEHqgVdR34J+YejJbIX6nwnCev+udVpKrr0TBGFu2kqeT
         JxQog2dui80lH8WJaxAYFounyMzWVGrfiGl+i/gHFhngnCmRAZC8OivjWlyVX+esbEAp
         hLA5Vop5iX7SrY2AZIcl1vBW4lUIw7dC+TQF4qTrmIP5nPEGhDTcGFOreqyXRxDpuaGD
         ooiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nMbtn962bJyODTJ60nMePYv0vJMX/g6tFUaUMuEAtIE=;
        b=PyNmUts5rSnrlU9j2FluQaIpXQh6YRy2Uf2sdT48spJ9OJoxSyi0jLLeYh770I5nzC
         eMeGOkrPYy8//+qHHIagec70gyVAc3dp2vlAnSZIjVIGYFGPU6jpp4dMJ18vCyWLewba
         nWYwINrxWhq9tbaJbM3JrSmz5qxugqWf33aW+OVgIdVsW8d9kHM9Ipe4pAXUDzn3BPPs
         1q9KxIlz1a7cewMSa3kBwM9Q5XqcsnKtI8JV7y/2VmgDvZ85xaQivFDZYN8PruXA3k0u
         EPqrKmwwt5XzM3YD/mVDZOyFhKvo4IoF7wsflvj/COeEDr6ZlJR4zgf9mWTcWTpckXE/
         Vx4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZoguAEV08r6h1ltaRKTkEowiPIxRPXFjmvigT8bkgv2zgXJWu
	jxmzfZZOqvfE8+PnNOykWks=
X-Google-Smtp-Source: ABdhPJzg/yRMNdqrhAW+wb/9rAR5vi7WBvS/WKdTpwAkfSLSuIk2l/F2fLWRRWlYPyTXV7MYNqAFwQ==
X-Received: by 2002:a37:9c4e:0:b0:5f1:83d1:4397 with SMTP id f75-20020a379c4e000000b005f183d14397mr11634878qke.738.1645426541512;
        Sun, 20 Feb 2022 22:55:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6844:0:b0:648:d7e3:5c5c with SMTP id d65-20020a376844000000b00648d7e35c5cls1267577qkc.1.gmail;
 Sun, 20 Feb 2022 22:55:41 -0800 (PST)
X-Received: by 2002:a37:b4c6:0:b0:508:b101:75b9 with SMTP id d189-20020a37b4c6000000b00508b10175b9mr11268428qkf.550.1645426541059;
        Sun, 20 Feb 2022 22:55:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645426541; cv=none;
        d=google.com; s=arc-20160816;
        b=i1k5ISLzq1NG0tmcV5vwUzvAZ9/3vLGq2cxces6Hn2N9lv1g7eduULoHe4s/E3IGG6
         /LpL10DO8Gm5OD6cxFyEH8suQExY+ays8rBytytqArkC6Lbz6D+wYtwTPDIfLMm+jH/H
         N+zE1lwM3fVeBnRHlIuF5zIG7eDtWt7ETiPAwhwhNHNjR/rsPWfOLpLV6+AHxUdh28RN
         iljKOMn8MgPoeMNi30CNHRAhaGafC+eGcy1N3KgWoub9rmfZslQyO++uervlpAd6jxOh
         f9EZm/v8XZKQff05r/PPwbz81Pj13MU0gFdj6MbwGKf5k/zEPIWiUf9Q1iLrB+UDtj5q
         PBCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from;
        bh=23BDarXGc3zWt+8fCLt/rgyue53x4WcnMLvriOdY5bI=;
        b=nXW7R995q0FWADl+HrhFtUzkMoqAFQuNwsJhg/byNow/Av9cCjmHmVxtUcA0aqP2zf
         JUWBYdoAcMGuIy1x7KZj5joUXVrQuRc2dXUz5fSlLF/+Lq7UPfv0c/JQWS9mv/AIazMN
         Y5V6UPOvqpabfVQhh98ul3Z+M7s+1fQIWAKeqQwa3ZkBpTpixO8nukt5XFea6zVM7YQf
         MOxQPeMDHyj9CaEAJ3h+KI3YW1SgPS0V2kvAoLu3WiyKggN4rtDRv4Dy0w2JV/5AEOTy
         9/8FAglWRwX5VoJlrZSigdQVfdNKLNLeo8KWvlyiBm1MrRtZWwmK8ZduNdetrq3wFGkD
         xGqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tangmeng@uniontech.com designates 54.243.244.52 as permitted sender) smtp.mailfrom=tangmeng@uniontech.com
Received: from smtpbguseast3.qq.com (smtpbguseast3.qq.com. [54.243.244.52])
        by gmr-mx.google.com with ESMTPS id s16si1059242qtx.5.2022.02.20.22.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Feb 2022 22:55:40 -0800 (PST)
Received-SPF: pass (google.com: domain of tangmeng@uniontech.com designates 54.243.244.52 as permitted sender) client-ip=54.243.244.52;
X-QQ-mid: bizesmtp89t1645426532tkwhdq7x
Received: from localhost.localdomain (unknown [58.240.82.166])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Mon, 21 Feb 2022 14:55:26 +0800 (CST)
X-QQ-SSF: 01400000002000B0F000000A0000000
X-QQ-FEAT: XwMLFaztUQjhkiiuaJsef5Cm/q6HS4HdYRPGwY/yYJmHM8mNIjyPoqlroTkWH
	dU5IsXirHH7tS71PLBjkT0pEqN92+O9NIEbTqBduOfepbqjl5+URvJg3/cLnSLazLNcyfXK
	OC2oTa4aiQv6CszZc+/5992H1c2ePcsMcpCOxCU75HzTe5JeAaggM2XrlLeq94GHPDs3mUJ
	gEnN0xCMGy+LfeCOH7PNVOAn/18IQRH/TSJ989XwMMMS01RAJtQ4GZyWmWF05/T8L9JROq5
	1CIX5FV95IqEU/TktCeWY9AmM3pGUgQK3naRsiXXrqSWYttB0J2m3iNmCOnuNk4IbICwViR
	E1XPqKVU4EaN5+L4exbyzKtDEH4A+lMN6kEesBFTrdHB/NOUfg=
X-QQ-GoodBg: 1
From: tangmeng <tangmeng@uniontech.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	tangmeng <tangmeng@uniontech.com>
Subject: [PATCH] mm/kfence: remove unnecessary CONFIG_KFENCE option
Date: Mon, 21 Feb 2022 14:55:25 +0800
Message-Id: <20220221065525.21344-1-tangmeng@uniontech.com>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtp:uniontech.com:qybgforeign:qybgforeign1
X-QQ-Bgrelay: 1
X-Original-Sender: tangmeng@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tangmeng@uniontech.com designates 54.243.244.52 as
 permitted sender) smtp.mailfrom=tangmeng@uniontech.com
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

In mm/Makefile has:
obj-$(CONFIG_KFENCE) += kfence/

So that we don't need 'obj-$(CONFIG_KFENCE) :=' in mm/kfence/Makefile,
delete it from mm/kfence/Makefile.

Signed-off-by: tangmeng <tangmeng@uniontech.com>
---
 mm/kfence/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index 6872cd5e5390..0bb95728a784 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -1,6 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
 
-obj-$(CONFIG_KFENCE) := core.o report.o
+obj-y := core.o report.o
 
 CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
 obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
-- 
2.20.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221065525.21344-1-tangmeng%40uniontech.com.
