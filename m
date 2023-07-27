Return-Path: <kasan-dev+bncBAABBZUKQ6TAMGQET74NQRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FF92764346
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 03:16:24 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-d1ebc896bd7sf331176276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690420583; cv=pass;
        d=google.com; s=arc-20160816;
        b=iiZzM3CHr57tPzHVxu3PYO2RMvwxk8KW1xB4oYToY/d/AfX3FOsByspXpRqSLPetA/
         xs4QDLyOiJC0Aw6+WY+Wo4wz5o+jz29j5xtJwc20DNJW/khMRLpC7GiwlWpJqK9GQEzY
         a/rsE4lLhzrGw0X0bS0WGkKPRnNpLvTVa59LE5Xgs3BqCfUCJ/ZtA1MbNJnw/xAjK8/W
         kKXktRWXcnJal9jc+l+e1s7wkvnwTOyESKjszY4wNcT8psMwzBWUfCYOyGmP9EK5Jpkb
         4iFS0LZ/r3F67aBq46eHwvHhX6ZG2v9nbzHfWnxinzeIBPByrWVg8T55Us6YyRW+u5lM
         M2Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kVjkvBPET2haSIc1T2Dr44XMuxLLdrcUOi1ElkB+jXM=;
        fh=p+2efxOrsjtKfHqLXl2Yl/PWOJT0MqeZo5k3po+L8gM=;
        b=kkXCrCNiK9EXu4ekEK+bGDrnLihCGB359D2+vSfFUukkqGlirEK3aYj/qsDP/iP+4Y
         qtYWSn5VwwFyHphpqJYjeR0bqLiOV01yWay5WF5jAdPukxatxp+S//X/fK6J25ox7BQ4
         iLWejzEpPBFtP7otXy/FokLUQdJ/YR//sREi/1p96KkAY04kvmLxMZXlGKKfn8Q/tQF8
         A8PEfWFb44z9MzoafEx6HKDMitE1W27ENob0cMkzLbsrslqjx67AKFbGb+NuGp73edIk
         2tK5llosZMjIZXKlicF+UboVN8oawCH2JyuYUcQvYPYM0JBghzwkY7kriXshT090K1NA
         iLPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690420583; x=1691025383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kVjkvBPET2haSIc1T2Dr44XMuxLLdrcUOi1ElkB+jXM=;
        b=SkvFW2SoqFsR4QsBkzGbSZpSsdmbmOoFTy6lRYGpbrAkbUlRxO8/swhUgg8KBpvamf
         SR5U0HbIVWa4PUJRdaauHk/9m6SyfGyvBLRo8KrZyt+L/DVYZ4wvY0mDMy1F+is2hqVU
         jZ/zadC7rBXNY0vXAYk+IaUlNp7rXqUk7ynoC7+UqtQYJtH8We1f6lsWNkhJui7NyImN
         ejZvMaWHyyLKb38tmOqNLYgQ2OEjxik31Y7Cnn6yrCe4u3NPENTde8Zz03Xaw9JuG6Xx
         g1E938okoQMH8mo9NRiOdas6U8CmzLSvmjwQ/TegLny2vBHxnnXIht8/43BF5cHmlOo1
         AkEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690420583; x=1691025383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kVjkvBPET2haSIc1T2Dr44XMuxLLdrcUOi1ElkB+jXM=;
        b=g0Gfk46jcWsfCirkxUwOfpncdrKswAax6g6B0PLu5ulzK//22DATfFtTXtySJ9RaI1
         Dr9omN4pGE06kDP33YAaLN78s1yc4KqVewZrVcmGl77rWoKy8FqluGbpQ/FRfw2c1Xj2
         FELP8uyYlO5WEidFtCwnnn+BIUx7GEz1X0ZXIiQBQwdKPVSXwt+kc7Y1b/5HCTMIEbt5
         nAIjvUGeGGsPQO1hLhSF+Bs/jTtE8GiWXGztDDuZeU5woxplpcj0fzyOccQlkqXt+5Gv
         b2AcklaWOVo198mSW2sby+GEm55RI8jeW8xicqmxoirwNCpOWGD2CqkcGuPRjTwcVEJx
         Pz3A==
X-Gm-Message-State: ABy/qLZ+iepyqrIgHHToOIt280WZXgsTHPC4gC5nHgQvteDryAHI5tFb
	gD19Nv2lbAmPl/O/UaNIZBE=
X-Google-Smtp-Source: APBJJlHhWOYkJTgME4SS2ycQQp5gd6DzIzubBdqAHZq2mZ1hDIlEQJ2N55Uvwy+28PRDU5peOv6xzQ==
X-Received: by 2002:a5b:90e:0:b0:d0d:d99d:1b8b with SMTP id a14-20020a5b090e000000b00d0dd99d1b8bmr2979944ybq.39.1690420583124;
        Wed, 26 Jul 2023 18:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:154d:b0:ce6:7e45:dca6 with SMTP id
 r13-20020a056902154d00b00ce67e45dca6ls198392ybu.1.-pod-prod-03-us; Wed, 26
 Jul 2023 18:16:22 -0700 (PDT)
X-Received: by 2002:a81:678b:0:b0:56d:2afa:5801 with SMTP id b133-20020a81678b000000b0056d2afa5801mr3758120ywc.46.1690420582356;
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690420582; cv=none;
        d=google.com; s=arc-20160816;
        b=Zr5aaQSbHioo86b2gLzLyzEULaSygSEMx2pxkj0n1HsryVGOwgj/UpBBRe7esETu32
         dSvfr191NH958hWiXIYy1iUrrOmW2yWkx0fXoHNsO+RPEL68LvRX6e0N867DYSNLUpPh
         q/fKz4hPIsuCNeUSURx1nMh3enq+Sbw+WN1Qadg5YW2wzuA+y/YDUYwZvL5QHR33XKKD
         j/Wh7DlKbSAKxOlXo/e3ZTnfOCFknqTcY1RDKudDG9mxY3iqCfFKyL9Ow9pzOBzCHhoi
         Hqw2lw1jf3NY8jNQmnoY3E7Hx4joZEQYQH7AXPoKzm1JboRIl4W0Qy/bM5y+hvjv6+G2
         78DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Qr170MEKVVrnU+3V9UPTmGiI7GCaB3XFhNvWhXebk90=;
        fh=v9wYe9VT0TbAN61FdyevhEThUjofuva2Dd+9j50U/es=;
        b=rlVIsZJYbKlp6vTZR0JcBN2W9Cncg1WGo/DCvtZalcbkC+O1AdiGfDuhPN+1UXXktc
         +xkgylHRUNMnuSsq+S4gcET57FFeRj8S1XAKlaE1iEZ/4WdzUezu7fazrlcMLq87I1aP
         P0NLPJQ+tGFmc5pcMvzRc72DZJtDKBOLFMahaU2ge1nYr4OGp1ZRvl4lcXQ1dVi/Wgg5
         q6yvrVjpyf/hiiGE0HpFlMjFJcCIVQsAwGEflNK1p802Ds3zD+EGjRFFJLlF8J07K7BC
         fBPMQZYzs0PmtBvQ4toYMrEKWFi2Ro+9s9nPXe5F8AeezCfu0a1WEjc8u3UsZH7whOyq
         Czjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id fl17-20020a05690c339100b005835c0a3992si31812ywb.4.2023.07.26.18.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemm600020.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4RBCS81PHgzNmcJ;
	Thu, 27 Jul 2023 09:12:56 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Thu, 27 Jul 2023 09:16:18 +0800
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
	<wangkefeng.wang@huawei.com>, <sunnanyong@huawei.com>, ZhangPeng
	<zhangpeng362@huawei.com>
Subject: [PATCH 1/3] mm: kmsan: use helper function page_size()
Date: Thu, 27 Jul 2023 09:16:10 +0800
Message-ID: <20230727011612.2721843-2-zhangpeng362@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20230727011612.2721843-1-zhangpeng362@huawei.com>
References: <20230727011612.2721843-1-zhangpeng362@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: zhangpeng362@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Zhang <zhangpeng362@huawei.com>
Reply-To: Peng Zhang <zhangpeng362@huawei.com>
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

From: ZhangPeng <zhangpeng362@huawei.com>

Use function page_size() to improve code readability. No functional
modification involved.

Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
---
 mm/kmsan/hooks.c  | 2 +-
 mm/kmsan/shadow.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index ec0da72e65aa..4e3c3e60ba97 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -117,7 +117,7 @@ void kmsan_kfree_large(const void *ptr)
 	page = virt_to_head_page((void *)ptr);
 	KMSAN_WARN_ON(ptr != page_address(page));
 	kmsan_internal_poison_memory((void *)ptr,
-				     PAGE_SIZE << compound_order(page),
+				     page_size(page),
 				     GFP_KERNEL,
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b8bb95eea5e3..c7de991f6d7f 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -210,7 +210,7 @@ void kmsan_free_page(struct page *page, unsigned int order)
 		return;
 	kmsan_enter_runtime();
 	kmsan_internal_poison_memory(page_address(page),
-				     PAGE_SIZE << compound_order(page),
+				     page_size(page),
 				     GFP_KERNEL,
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230727011612.2721843-2-zhangpeng362%40huawei.com.
