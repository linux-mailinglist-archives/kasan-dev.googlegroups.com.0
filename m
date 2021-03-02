Return-Path: <kasan-dev+bncBAABBCV266AQMGQEZSUWZGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E96732966D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 07:37:00 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id j3sf11252099pgb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Mar 2021 22:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614667019; cv=pass;
        d=google.com; s=arc-20160816;
        b=hg86WwmjFTH8TLZ1BkbvwUXuUHbherXSNY3J1VbjzpVo36LGeOr+DCUbB42UsU789+
         c8ZdmSrnrXFAjgvegpIgE9X/CE5UatXp354yzR8r0gEu66hnl03LC6t/8AOEIUaMyyh7
         WbnUt1UXDIoI5JBKmzOyt26F9uT1+vKfeTVt40qX4ZsoMOOcEGHLKi9ldMVewAMD22u7
         Oq8XlrjbSYt3hBe7+3zfsz9Q4UaQeL0NBJMLxw9p82kHL0D/T6FYwmpmEAZtGY2v4Fdj
         UGGGCoPfy+RJQnVH/pJeh4zx7XPSqbTITU1fg20ODtU9Tyin/3xIkUxQtGFFCA7P1Yz5
         YObg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=uDaC1rS2MmGvvqRBbF1TVc4oELvVQAOOSQthLeiZbHM=;
        b=myrNBNr+X40CdvSIIqIYF1UbFPfCMA7WMe1T8+vLQCt5lb1LZ/jFdKhAOAmbYVsoZa
         kwN563Vv/c8Ufm8s264iygRnsc6vfdBENBv+H3mc4WbL7NUN5Wx7za6rSIocWzOaHJPZ
         msPm+xeQDn4BVuJDjF/CiryrOTl0I0gu/ogdMyU/PxChK9CSGcewbWxunYN86iGpFsiZ
         Va9NzGx7dsnjss2Ct6L5PHrO794+AtuBIBOY2qc+VfhB1zjj+X2gyRmNi3HEwxbng1us
         D7vZsTnoud0slHEEGl1oXxfb1DeBwJWLWvUo0SW3nJPE0s56MuV3gq1x0b8qZSBK/kLw
         Amnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uDaC1rS2MmGvvqRBbF1TVc4oELvVQAOOSQthLeiZbHM=;
        b=kHopLeMP25JrUlqkcoKK9Dr6kL5Z4x3JGPaWCRJbsp+8lH2Wzyh1dLzStY/SOyMvck
         CoTnqPbs0o2zr8OJ8CPCo8lUCMgcn4lo0aACTRcqwQ5tohgNBcoDVGjTwhTNA74tKs91
         T4jx9/ztIURSQ5Lg2lnXmWYrlxgKEvXyh6xHJC9ni04FV2ylRPYAQeIGMNKd3HWDDYzp
         mU2q3B3fzdfWeUk50l1c80zWuhtfZovK2bY7AfUDikeZEE+vsx5waSgw0oFRnqnnzWhZ
         S3DOZC0ztj3nprxns4g3YWzBQiniX/GHtzqSRrUaWvlEus+z1fEbr85INyi3znwUogXR
         N5Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uDaC1rS2MmGvvqRBbF1TVc4oELvVQAOOSQthLeiZbHM=;
        b=Aih0KZXt/SoeztpOYywjZ9zmF6CSj2ceGTOOptzPzb6oNIKfoV1NNAgSvvJX4GFGEZ
         /qnDFpt7fwmdeIa3wjGyOtTVOX7IEEK1bcxakVJIfY3VOU47Rusc7fj0DJX9tNW3rJLX
         WJ785ZkIf12VhiZ1oRtHGrQ3eTcQQ8V289yWRtrWaaP7fhR11SHCmDdRPPB0ouHKsz8f
         88ew+y4Y+7HwrOB2LzTQ3nS/Dn54NmILyd2I0kM605QrawpK0D1BgK9j3ry56zfd2wbL
         TO1XoBfIOMsjOzvGCdwtty4noRmxFY3zHcLzPpR8sDIw5r4E+Md8m76wsyGCwe4p14xi
         4vvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n8T5bBsHOMZvpnfeQkm6DwxZuuaky7GqFhm9SzKyiUxTxk4le
	7992AU9qsaRLRlo5HCC1xO8=
X-Google-Smtp-Source: ABdhPJwjqD7x3kAzirfAAPfKZfvd5O+ehlg9ukONFpbabKMALpGVdfYoVxwBHvUeiISI/prHxIQAwA==
X-Received: by 2002:a62:5e02:0:b029:1ed:8bee:6132 with SMTP id s2-20020a625e020000b02901ed8bee6132mr2076050pfb.48.1614667019054;
        Mon, 01 Mar 2021 22:36:59 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6902:: with SMTP id j2ls3189781plk.10.gmail; Mon, 01
 Mar 2021 22:36:58 -0800 (PST)
X-Received: by 2002:a17:90a:2b4a:: with SMTP id y10mr2806037pjc.143.1614667018349;
        Mon, 01 Mar 2021 22:36:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614667018; cv=none;
        d=google.com; s=arc-20160816;
        b=LXTfPaiNOGF98gqQ2bvmrMtgdzepRmUU3w5EmVFTVkED4U66ZhqGHP+S8V5GcV/84H
         gmBYiJUpqGGnDrOtKWcc0ttxhV4I5vzPzSOLJwP+lMY8xWcYE0b2AcshFkbSTazLE5uu
         tAb7rnflPSQULx2afdgSHf2A+LNXGApUOhGbp4RkkYoJ31oUuVTvzTataPjSfKexfBHA
         xuNjVOcBglHksz40+ifMXWcvFs+GA46x3dwzvj3sWK2FBXmmM8sbZROXkqy+fQ8V5NlT
         9X/d+0r97GLMwlGqPKKslwLV3FwTIDjxhF0wNO6S7Bo/wiOqx982WuPHW+AQDgGKUh1J
         ji6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=o1y0YMwUSDYfC/cqQpdRgqS/n9cJ3rIg6ipQjJWwWdQ=;
        b=cvltLg7dudRAgVloe0PuRqHOG9wpZvE3xelKAtWeBaDgO4hR8flqcoFeV5C2yxBycT
         3I4wjOLhRqWq8E7qZ7Vnbx0f03fl2QfOsRo8uJxCHBTFnL7sNUU0d28lmSUbzUkGoYbJ
         k9ru6j81pj2+A64bYi0n2JMhGqpmL0sLu1ihFHJj9t2goIZZ3ksGV5NLHVqBjaxgCZmQ
         +e8JYO9+b0ErwPg3f4Ypx3FNo+C74EfxO4I36aeUYbrc+/qPSOjZ1PMrl7A/0LqWBqHc
         vu+Q/SDhmEfqRcZoj1H7yOV2BWzl4rFH8KluUFOjRru1u/ChUCXjydYvVFJqfR3HIC/x
         b2TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out4436.biz.mail.alibaba.com (out4436.biz.mail.alibaba.com. [47.88.44.36])
        by gmr-mx.google.com with ESMTPS id x1si281894plm.5.2021.03.01.22.36.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Mar 2021 22:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.88.44.36 as permitted sender) client-ip=47.88.44.36;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R111e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04423;MF=jiapeng.chong@linux.alibaba.com;NM=1;PH=DS;RN=11;SR=0;TI=SMTPD_---0UQ3dCZ5_1614667009;
Received: from j63c13417.sqa.eu95.tbsite.net(mailfrom:jiapeng.chong@linux.alibaba.com fp:SMTPD_---0UQ3dCZ5_1614667009)
          by smtp.aliyun-inc.com(127.0.0.1);
          Tue, 02 Mar 2021 14:36:53 +0800
From: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
To: ryabinin.a.a@gmail.com
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
Subject: [PATCH] riscv: kasan: remove unneeded semicolon
Date: Tue,  2 Mar 2021 14:36:48 +0800
Message-Id: <1614667008-22640-1-git-send-email-jiapeng.chong@linux.alibaba.com>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: jiapeng.chong@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.88.44.36
 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

Fix the following coccicheck warnings:

./arch/riscv/mm/kasan_init.c:217:2-3: Unneeded semicolon.

Reported-by: Abaci Robot <abaci@linux.alibaba.com>
Signed-off-by: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 3fc18f4..e202cdb 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -214,7 +214,7 @@ void __init kasan_init(void)
 			break;
 
 		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
-	};
+	}
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1614667008-22640-1-git-send-email-jiapeng.chong%40linux.alibaba.com.
