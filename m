Return-Path: <kasan-dev+bncBD4NDKWHQYDRBZU4VTTAKGQE66Q6CRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 903E611D5A
	for <lists+kasan-dev@lfdr.de>; Thu,  2 May 2019 17:36:06 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id x6sf2295002wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 08:36:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556811366; cv=pass;
        d=google.com; s=arc-20160816;
        b=K2Sv2eiCgbla3HrprZDUcsWms1R1yJqUDkyiUzzgfH6XsfAB5hSSXSoG3ZELC53IGX
         kVVr+1Rvf1ImEXLqEs+jb8WA6Ui1+OSW9+3okqVy3QQYf/v6q/Kj+dVQXRtp+AgRZvtk
         wAMgRGOGlKTdmfx0Tddhc8y7kNj15qX6EfnEFAh3h1ERPQHfXzfSR6vmC8MgIxPKBVHo
         LtKMLcUyXUtBWnIfBv/1rxODY2WTZZkslptIN0cZXjq2BjS4FGWM72aumx+UpfIRAWTW
         FjQ251vQo/ylaNmfjLHzxe/79iwm/KZ8j7FNtu2gyd1XWQ85236M2LDfPCrBBDVS2WwD
         MiVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=G2PC4fhEjeL5VigaHj7rFbvJd/WR4Y+jiYvwtvGmJNo=;
        b=vKFGAuGDnaKWhipCrOK/XQORy/n43EasGx7I5m9mg1ArtkJOkbS9KfoM5WrYjZRJrP
         xBdqIWQgT7DDYWqKm2kghNn97zzVGBxXt1MV8AWj5c3rhBektSf0CdwfT4a+t5I/HQry
         rDzpsMRrIiin1fm531TrdP1kXJa3Q8ZrCduHKXfA7f6IKeyKVm8sLKL9rAskYix3RlSs
         VT/tIYrOGZn7e5a9jK9ZO1r70u0RokhFMqy6pPmNz3CI5542nQQgOwl8qdLdaQ19REUU
         meAOvx8JlSg09SKI2roGdzDrJ6OKfMp5N7s7om3ygwaOAmLsuJT/by2+lLU66053sE1X
         Iu+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=J04pm3ui;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G2PC4fhEjeL5VigaHj7rFbvJd/WR4Y+jiYvwtvGmJNo=;
        b=I79CSTU3YzR4oPXOkHB3WDWxvtnWUIo92CcxYSf3wr99MX+VZifrdbM137YU4gE9Pq
         1EbTscAWrP1hr3teROqLjtbEjD30np1dylAzSmbRTDO8qAewcEUXcP3+TIIoknIZj9W3
         /BgttwC7U6DcWfP5s1cQlbBQG+kTZk5A6fh0dq7ivH4kqWSRklpY95PLe573qdABmKTK
         qChOYMiX1aQ9lboFQQ52rCNlsAov6mArd6yXw+39e5PZIFzO90s3pjfy9NYv9wxZTPKd
         nfw6oqsqujdfwgdpxNFCsBDtuPEpHG0l0SutcimAdZu3bKFYVl/Qs5xSyhQoDOxs9aPy
         2xqQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G2PC4fhEjeL5VigaHj7rFbvJd/WR4Y+jiYvwtvGmJNo=;
        b=ZVggsDjARakYcS/wEN2lZ+UZ2Fadr97dFqaL5EEerfJ/Hd08OwVCWg4gw9BJ+A1MIi
         sZtOrNGWPbP12zJ51FXJSlJy/PSftgesWbxzYbAvRyLfbOK0ePVrXw90aBLUVsYKCNs4
         0tzcLnkTy2nnbk4LxmKFx5K0NxRD38x9wpNcxsh/VLopMC6WqFFihzkQoUAZMZeOhsRq
         BM1tXhX4o/R0hnq/+frFI0tVau+cHcJYnABsJRzO8SjU5qn/9q1PcExl1IShdKBDKE+G
         vEgndzv+aAgqfXDrcyzEWbCCfH0bAy1N4EVZW/ycSGiuEjJPjumUjitduti7WF+9oRaP
         jcQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G2PC4fhEjeL5VigaHj7rFbvJd/WR4Y+jiYvwtvGmJNo=;
        b=t7dVsbha3FLou9QzAYOXnS0bMEPfiCBUJgCkCgS0t5EvS+DRwRdQE26WCtCp94kTSY
         A1PDnGXAup1iHtZiWBrDcfUe2tGo2iWStJH9gWk19uIkYxLRZ0oLitlFO/GnivrloWiD
         GjjQlaFjVUirUK8+RmlI68zIE8NXxhesfOWVZ8btGZlIvDSsV7gr4gOe3P8wX3RkqFyO
         HaNiLnmTYEVcdSZe5AOieXzescrJC5/p+0ng5WP4zs/yb6/5sCanx0BKl/t5uLye74hB
         4ym8UxHnxvpdAzYRebhnPx2zl1P4PsCfjvLaQciVkMy22Z8JWGvL24XoDEQxMO0MWZ5x
         w61A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW6i2sxc3/yHnGBbLoIBcj3deT2/gt8xTJ6AqIGqDkAf2eGWuPS
	Gni9rdMzV5RjO2DhNlKv4jM=
X-Google-Smtp-Source: APXvYqz2SQaZChibkAq73nKPXGtECiZGek4XE1/ERXaSR0vAKmc377gwSiAKEVM2y7dHxqyXGPS6DQ==
X-Received: by 2002:a1c:a950:: with SMTP id s77mr2734811wme.143.1556811366297;
        Thu, 02 May 2019 08:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:61c9:: with SMTP id q9ls647929wrv.8.gmail; Thu, 02 May
 2019 08:36:05 -0700 (PDT)
X-Received: by 2002:a5d:4951:: with SMTP id r17mr3424136wrs.257.1556811365907;
        Thu, 02 May 2019 08:36:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556811365; cv=none;
        d=google.com; s=arc-20160816;
        b=AfAoU04olsbYMQOcoIf3bs2t6vRtb/ixnJhx+U35s6VBqE5+Ce4y/x1StK96rHJT7e
         ZkjnZlt28EXCUkzMUJpxGJW1vtJz/jT4T1m+KvihRklfe34GZ9ZucK+RmVKDhwaYxVet
         4+ZGttI63hO48TumZ4Pa0SzxVC0PG0OQbE5rB6MnH7Q1KhsJdqmFSz1cqdG59MAAl8By
         lCsh8mH3xyDRsNB7mK/J/qE/X8PXDIfam91jP4bqlH5S1YuzlWoXidPOVRsNi4Nm9XXu
         ixoe16WHhXZkGO7i7DdqTbD6apbas89eGzV2nmV8e1fnDsBuyODN62l+10AcGmQL+/d5
         hJtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=IeCbek7GxN78jmKl6HDSULctY9a079sA8sLhO9KSXCE=;
        b=lhJcvrr1RwiSnJKmOd/jWYKLzuw2VgVY07lf6gZ9XBX6+8HFaIoXDdENPT2ICnnbLa
         SpU4uZhxFjzthenaE9M/ZMMsTY0sGEVhEnXgT0T1sz/3vCZYTIjY6N9jJ9jKdhBUUWhw
         4bHHQKQ0JMV837FYSMAeeG7wSgDMDtB4m4uR06YjSVV17mPzwoKdZX9rQhrqH2NcMJmx
         ALWYHQ8V4gnZolxzZ+Aw86kKjpssUgPto9E2HS16N64IUBT2tY3o8jkuAM3KgL1WMICa
         F4KsY5QqdgO8vIxftWXWyMT6zMDMDR/AL1dGrsad3aQH4keTIIBk/DbcP6HyTdOocy+j
         9RVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=J04pm3ui;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id t1si391683wmh.0.2019.05.02.08.36.05
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 08:36:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id a8so2531009edx.3;
        Thu, 02 May 2019 08:36:05 -0700 (PDT)
X-Received: by 2002:a50:be01:: with SMTP id a1mr3094467edi.12.1556811365468;
        Thu, 02 May 2019 08:36:05 -0700 (PDT)
Received: from localhost.localdomain ([2a01:4f9:2b:2b84::2])
        by smtp.gmail.com with ESMTPSA id e18sm7386693ejf.77.2019.05.02.08.36.04
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 08:36:04 -0700 (PDT)
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	clang-built-linux@googlegroups.com,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: [PATCH] kasan: Zero initialize tag in __kasan_kmalloc
Date: Thu,  2 May 2019 08:35:38 -0700
Message-Id: <20190502153538.2326-1-natechancellor@gmail.com>
X-Mailer: git-send-email 2.21.0
MIME-Version: 1.0
X-Patchwork-Bot: notify
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=J04pm3ui;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
warns:

mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
used here [-Wuninitialized]
        kasan_unpoison_shadow(set_tag(object, tag), size);
                                              ^~~

set_tag ignores tag in this configuration but clang doesn't realize it
at this point in its pipeline, as it points to arch_kasan_set_tag as
being the point where it is used, which will later be expanded to
(void *)(object) without a use of tag. Just zero initialize tag, as it
removes this warning and doesn't change the meaning of the code.

Link: https://github.com/ClangBuiltLinux/linux/issues/465
Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 36afcf64e016..4c5af68f2a8b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -464,7 +464,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag;
+	u8 tag = 0;
 
 	if (gfpflags_allow_blocking(flags))
 		quarantine_reduce();
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190502153538.2326-1-natechancellor%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
