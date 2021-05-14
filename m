Return-Path: <kasan-dev+bncBAABBIUF7KCAMGQEF55HPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94835380AF6
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 16:01:07 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id z14-20020a170903018eb02900eed5c11984sf13637934plg.16
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 07:01:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621000866; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsnkLrNSKcwJWBYvxIyxMgRcDkcvTXyAhnxJ6KIWy3xtB7V8hMRnkkDW46TzGAMw5l
         +hQU6H3ZH/C2soscbeOVfT3/ylZqX6e3VmS+3PKBN2lqEenzpGL74Q4VjsYfwy3wrTsw
         IfgssBonUnxNMhue3N/Z6vj7UPGffFhEIZb9W1fE6+M+SQZ3YGsBMCfbBGJQ4kyIm7k1
         ZbUDmuKhRbuYCdn08wTA+B912LX6+b4EH+jCu7QfXIrviyhgTMDLrKrDZzfuv9sx8G2J
         MeqySSvnj2jW7eaNBB3ZfhAAuVQpAoNPSW343ckEhL0IFWgj3A1gT83UAU7vnJNuEeMo
         Y/SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4kHTaw566FGUPYmqh6TaSYRm6l66e/iHUTkPcQkupOY=;
        b=nSmkIc5dLDKwLo1qDe2380XWMv7PrnXEjw3mwBJzx9WnKxYf8HZwOOPS5i6yUeYkQn
         WXB6i/vevgM7vHqK/ljDq12aVrhQXMLGrdFYDf98BfVcgA8ChguBn47Wkli3TVRA/iSM
         T+eE/3NThyoIrU0ClXP6IfKQZcNEdG2+CfHIzwnD2VBqVs8Vw9KQLxrhpbVh94dajy5k
         K62XPhg2mQLPeAHvlYRelkhyw1EzPtu419TbhevEgvyojZCsQsOUKjojdpeK/cho2rvt
         BOx1CYnpVzcSnz057IjFbsZjE+H52sc2euXFs6h4zXFLVPYMv6ANXs9TArXviGorrrmN
         pVCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="DJxi/6vL";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4kHTaw566FGUPYmqh6TaSYRm6l66e/iHUTkPcQkupOY=;
        b=PzyQQQZCvP8shuV4kpCrsl/6aE4Hz4oOFJOe45mE8PF1qpRWwqRO92/X811GNZ4Z3i
         +5MXM3uZuI8+Tf+T+KDLb4P2U92sAFBz2lsZ/4Uy4LvC6bbXuDRoW1WEjsFlwTE72Rqd
         QVBMhOqshAW6nHjZ7YFUTBl+UGfDaybJ4kQ6WIrTBIrsoSbuLqd9W4Xgq77X/4pEYVF1
         SZtxsz3fWMWeoHEzR+K+mhhgu1zf021BO1eKEB8v7HT5QR7m6JJLh1shXRQJznRpy6uM
         D5fFab9tTxb/5V5lQk1fWOZPEPaV9ZmfE9CQLWelCZMOiJyidAp2gf7vV2GldaiIuyJ5
         DS5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4kHTaw566FGUPYmqh6TaSYRm6l66e/iHUTkPcQkupOY=;
        b=MqW11Qs8yOYpJ261CtzQIQGh0MOFXrzWrZIXs6fbuF0MczxtY8sSBpj1E4eHvXuorX
         3Ok+PpSS4GnrLqIUt+p3tNJyuH2SjrwXvCtHsmayucjNadQpXUHzcozAN+GvIUQfkOVx
         Kw3h4A2hh6/BWEc+KuJXTs6Q5rRZkF87iNB3+SpX9WwdXwYfKrScc/9nuiLk9iRlz6TL
         8lae95mgo+AXrdqrsm15jFZCY840nUs8TjYDQv6XvM2X1+BbDrElcLcvMdE+6K1BaFqf
         tFbDmNiuF07Xw03RtmCe7zn+b1AbVeS12HsaSf2GKykHoE6JnrbYstYk5QIX7t7LxIqV
         ZtWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bkU2EKpB/xgzMS+bLEA2/94bcxl2NJpXAhoKsOEan3KbDhX9P
	IG7UXZlw0Ufq4wYYgZoXOeE=
X-Google-Smtp-Source: ABdhPJw9M9h9HHA3von4JSGDKQ1OZibqJEP7w7G6aCOg3ex90DmE+OqAUcMda+sc0Pgt9+KILKvvyA==
X-Received: by 2002:a65:4689:: with SMTP id h9mr9800466pgr.347.1621000866100;
        Fri, 14 May 2021 07:01:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb4c:: with SMTP id iq12ls5624243pjb.3.gmail; Fri,
 14 May 2021 07:01:05 -0700 (PDT)
X-Received: by 2002:a17:902:8c97:b029:ee:f8c1:7bbe with SMTP id t23-20020a1709028c97b02900eef8c17bbemr46076368plo.8.1621000865627;
        Fri, 14 May 2021 07:01:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621000865; cv=none;
        d=google.com; s=arc-20160816;
        b=zLusimw6Vdcbt+5m7LjVfOh9nyT/kOI8c1kAFDOXyJdYLBG9oQahJnNgHIYK9qJiKE
         VYx8XMb47evDMd5388zMjbLWbY3FmOsboVlA2ix0A7ol9Rlm5pr3sWmiKg+mm3/wEvdo
         k/WCLJhMb76E58d2QKkr2zqtdZew5GSRcefUTZNxIdHBRnKtnLVvss2A4BMXw2Hm7iD+
         NH0XQu/U29kedrAO08awu7sbItO+8P+DYnnICmuYU6HAZogdstMPS0w9kqCG6A7rJd9p
         gtIM7HK8YR64Xh4VMvA7wgcHp1bgxhHDW3Nl8GvItnzi4m+whhbfjCLYrJcY/Y9cGScr
         eGqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LyHlpW2UlOKG0QIogMUPiiTW9+pWu5cPlFoocFtCwuA=;
        b=nXWrALZZSZsma8qvug8m9MLeJ5Wf06rWZBZITa3iKa5/jRx8PGGPw/6I5IHwhskhS2
         tDXxQaWPKbxGrXqz91Rm9muUsQJCbZ5LuVj+/8qWNEDP0xxYtewlX8wDaRqlScsZb8t/
         tqRPiGwaQac01BVJDOTkJy/QJAwnd1Li9G8xsDINcdqRh194pNyzIKG6+BxAe3u0G9CA
         BjP6rL22DLBik4AJi64PfPMt46M6frKQ0tr8W8H9DLJQ97BJiJ02MGwUt8BI2rcFT0O2
         mdEs/piKTeAKKCvQNAJ74UZ42LPUK5OvUG2emv9y7kTi/i1Cn6O6v7FibNB83FJC/Xr+
         Rf0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="DJxi/6vL";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ep1si624972pjb.2.2021.05.14.07.01.05
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 07:01:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5158561461;
	Fri, 14 May 2021 14:01:03 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Marco Elver <elver@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] kcsan: fix debugfs initcall return type
Date: Fri, 14 May 2021 16:00:08 +0200
Message-Id: <20210514140015.2944744-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="DJxi/6vL";       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

clang points out that an initcall funciton should return an 'int':

kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
late_initcall(kcsan_debugfs_init);
~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
 #define late_initcall(fn)               __define_initcall(fn, 7)

Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 kernel/kcsan/debugfs.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index c1dd02f3be8b..e65de172ccf7 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -266,9 +266,10 @@ static const struct file_operations debugfs_ops =
 	.release = single_release
 };
 
-static void __init kcsan_debugfs_init(void)
+static int __init kcsan_debugfs_init(void)
 {
 	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
+	return 0;
 }
 
 late_initcall(kcsan_debugfs_init);
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210514140015.2944744-1-arnd%40kernel.org.
