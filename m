Return-Path: <kasan-dev+bncBAABBRXFQCIQMGQECRM45KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 888324CB542
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Mar 2022 04:15:20 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id v127-20020a622f85000000b004f3dfd386e8sf2371885pfv.16
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 19:15:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646277319; cv=pass;
        d=google.com; s=arc-20160816;
        b=nsmd9+HJ//s6yrFvNdDbWKFiQ9fE1dOYQdq0/u+dE5bqabRgle/p1k+yKTBU4M6Nmi
         huSQWR1/NGSJHW2XHV9+NTcsNUYM7rtJHPODAYJ9UxIkQykvQmcNUdzgLTWEHFyd8Gr9
         YxAo5R96ms/xxDCnwKJfXq0/epkoB6VbsyyicZtpu/FM/iYjD10RmvgyMonLknog8ijE
         Wiv3e4DCldcRDvtgfIWK9WWYJ3KaenPRvyvA+6ex/4mdSDUJD2qhJIVPZIddcmXpbYKe
         AwV4eWheyFMSZ0C244f1jzl+oUnHlLzddZxi68DcDF6/7ARs1ug6s3BepaqKCmEYfajz
         D9sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8gZgbl2nw6rwZ+lAkueS4SXTUaNvH1j14DQoqPC7EPM=;
        b=eXy8O8nD1WAGAy83lTuybprAhTCbWicgG67x3WhYEVa9X2G7tEbbLQZEiU6ihvSdpX
         MxllT0i5nZfqsSZloApbZKv/uAbUcCdnlE5tDDlsb7AStm7qeTu75I3H6AIcJKakvFfa
         EbGS4W8tH7ocTP/VAjKPg1sfVQ9cDoiQLkCNbWiiLWhNwCnCUZdyYGl5nf836RSqqtvw
         jk7VgfMymdLgqG38o2VsRmB1k5f1qmKFFyV2f/v/DH3RPl78v9D2iNEjOI+kjTfSahip
         yFeRQZ6eZVJN4ZQ6kSdkB13eZf9IYboQP/JcNKjd7BZuxZl7cehVCHHQioKh05JXbrT9
         tEeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8gZgbl2nw6rwZ+lAkueS4SXTUaNvH1j14DQoqPC7EPM=;
        b=ryCRObZxdUqv2nfV2TyE/o3AKM5egiFdLSmMUhDCtaqTXEz+0Gr+Xc4uqBCPztyKDg
         tqct+eOukKKMcb0d7ZF1ldv9s66hZZpeAENWlr4YGPRsx3GvsqEWD+tZ5XMGcK7xE/Z7
         7brN9CEq9G+qMFzD+dXIxUxvSPeea+BPjQlQi3zVvQ6fbZAlof/3+EPvL2msSF6KfHTg
         j/O3uRZZE91yumFzdLMNUh+WDXHKz5F7tH/qsin1JfwUk7CbFVjnb79mTtrlMJe7Wqhn
         accon4kK5qQLhuLp1Re9AG1KeAox0A9lEFHUFBfwD0FbH14IZFza5B0HdyD9WCCzn2Vu
         n3sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8gZgbl2nw6rwZ+lAkueS4SXTUaNvH1j14DQoqPC7EPM=;
        b=pjvAuYRjZLSw9zMNWm5utiY6I055sTTtrS2Ur/LVT4k82eAXzzXaJhLq52rqHwZdMy
         5SuuSHbbARPcjHKtMhr0FTs7RIPU4FLLySiiOg3532CQ2RlcxXlFU0wRzcrZd8dmZNT+
         1iNPOqf7IKdZrrHUwkCyumiP5rgYU7TLOq78Gr3PTN7L44Zivco0spuQIibSOFLC8f7m
         qxiIqLzoD0JSL4eFuyX/JvSE/RI0ek6bnobRYwF2Xw/lS0WjNpwL1fP2TRgyAg4zB2Fy
         nHuLUjvJnUV/qr3G0Quco8w+SoOPqssV9lg8gLTfL+Ql9VwQPOsbDXVd3c69i+kXdScz
         WNNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tehxdwq0zY1MXbqMReJoCht7LHKDYo06B2LDj7itYbZg9AJg9
	mC1JVnyVDB6P4RwZbp0VPPE=
X-Google-Smtp-Source: ABdhPJx4Klx8335DFUFGPLmmsYN/6qfLYGMhKXUa4noVjeCe+nFts5f8WPfXl4hNG50sGNhJ4tA2Xw==
X-Received: by 2002:a63:6201:0:b0:372:d3d1:a684 with SMTP id w1-20020a636201000000b00372d3d1a684mr28422284pgb.523.1646277318931;
        Wed, 02 Mar 2022 19:15:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:450d:0:b0:34e:5e5d:84db with SMTP id n13-20020a65450d000000b0034e5e5d84dbls479115pgq.7.gmail;
 Wed, 02 Mar 2022 19:15:18 -0800 (PST)
X-Received: by 2002:a63:7d5d:0:b0:34c:17:6174 with SMTP id m29-20020a637d5d000000b0034c00176174mr25178612pgn.133.1646277318131;
        Wed, 02 Mar 2022 19:15:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646277318; cv=none;
        d=google.com; s=arc-20160816;
        b=r3oWBAGxFASIjSxk5QIlKv1fUr8K7Wh56MMZR4SwmhKQKbF0NIQGphTmpP4yiqqXq+
         yJRiU8d/1BGcAc1QNS58wIGv3sgScD66PFcf8m94UEdLLCyq8pSY8hHcxvrOKxYGhVLK
         oK5qlC7481hpcZ4gyL9JrkNenfgfTe78jyTr4RkC2pfci7st4NCDJ56ba5BJJKIgL08o
         R0xFvQfMIC86RUWwlNWsT9mLtccTR3MrU4NhOwKjyZOms/DQdby99KktVVserhCzrpNC
         LQ3kYzAFep3ZSDvECP6YQkRF+c4DfqGEcvCg0YD1ME5wmkwWEUdKJsfXRywwjZgT85Lf
         RWgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=+nktFMqBOuPmhd71Wom9B2aD6CzsyplNxR1u378XOkk=;
        b=dpFaZ8h0OyJNvgZuGJHbeaZh4enMkDi1mCj7K5jGAYEl7m9RI9dmtzai1DY1aqHiuz
         tONl4DYXKlPl/rdYZpX0I7mMkLFRIPrtAwhEo7dDkGsaBsA5mrM7yTtTmf61qmHecTDR
         CPBgCWgqCL+bNmSra2OFcbeeNiZobH2JrFrHTcKXG6sGE8E36f2ZxUn1Q46wjTLnMXbK
         K7bh3R1afLsRodnT0Nz/YrCIb9KvJxDYWY6NAIAz/7mAmM7EDqVZ8TiUMrVe+VgLY9oY
         SdFzMF8IcCwoUvujXngbiJ8ZqiFgzOFPQMtaAvI/rlfsuglMfizoH957qxrO6fyLgxu8
         xVLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-42.freemail.mail.aliyun.com (out30-42.freemail.mail.aliyun.com. [115.124.30.42])
        by gmr-mx.google.com with ESMTPS id jx5-20020a17090b46c500b001bede07ed67si299800pjb.1.2022.03.02.19.15.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Mar 2022 19:15:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) client-ip=115.124.30.42;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R931e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04357;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V650kF3_1646277305;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V650kF3_1646277305)
          by smtp.aliyun-inc.com(127.0.0.1);
          Thu, 03 Mar 2022 11:15:14 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 0/2] Alloc kfence_pool after system startup
Date: Thu,  3 Mar 2022 11:15:03 +0800
Message-Id: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

KFENCE aims at production environments, but it does not allow enabling
after system startup because kfence_pool only alloc pages from memblock.
Consider the following production scene:
At first, for performance considerations, production machines do not
enable KFENCE.
However, after running for a while, the kernel is suspected to have
memory errors. (e.g., a sibling machine crashed.)
So other production machines need to enable KFENCE, but it's hard for
them to reboot.

The 1st patch allows re-enabling KFENCE if the pool is already
allocated from memblock.

The 2nd patch applies the main part.

Tianchen Ding (2):
  kfence: Allow re-enabling KFENCE after system startup
  kfence: Alloc kfence_pool after system startup

 mm/kfence/core.c | 106 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 87 insertions(+), 19 deletions(-)

-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220303031505.28495-1-dtcccc%40linux.alibaba.com.
