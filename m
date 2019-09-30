Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBKXKY7WAKGQEC5OFN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 83758C2096
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:29:30 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id h12sf6187559eda.19
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569846570; cv=pass;
        d=google.com; s=arc-20160816;
        b=PxiCRmu/xKQFCnl83s+uU2pLEXVFV9T5kQdbgqZTRcfboAuFcEkiPg9+2MxipTL9Mf
         YowMPrY+eiGl7Te9rQph6LNtB/yo0L4o0cgemeQGSkRh626SHmRcKQFHWtFNH0CV6A61
         u7NJBQKApNsdbR4A7lbK6gxCzQxIC18B5imwuBWo1xemZPuv/nzAeSSCSsSS7aVu+LRt
         dk3lGf5f2Aej7A1OL3byXl7ptadbmHXVmjBREv0XK6FsfaOcmRsNfDoFCC7uU/slowV+
         jQQw9doK1h1cPJ3JbUqW5lgs4Ttj25EVBxNAGflQuLjQP7FBS8D7tDXaHs5a4bDPDT5J
         P8vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BRkEFKOtLSBB9V2OyRl9SLECujfgDUQ9Pj3TAeWNePo=;
        b=amweDKJlqJDOX8L42B5OCW1bYXwFEGkysHKClH11fMaftnYXm2BUbT1nbOPiYLplw1
         MxNLl/PCmyq0fhnf7S432lWZI5M/HpBdbiJ0Ix/t78Ht+UJhaHqATEi5bY5Yj8zXDEc4
         esBqvLuWffAekrwWFLfecsrSqBPk+yDX/gyzDPtxVz/mrfBjykbQbadlPnMlRz8liokX
         AjXmtW29U9Ct1xRsZXPcUi4cKDq2e6YYNuz3VYKMz3cHpEQseplqpOB8H1ewH95yiguO
         sv5e8Kc2ri5Pb21UwiYCMDf3rkTLAqxskzI/QjIj0g4Qp6yIy+fdzv044u46T1rHsP5C
         J+ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BRkEFKOtLSBB9V2OyRl9SLECujfgDUQ9Pj3TAeWNePo=;
        b=b3s/0IEx6wf89SFaVX2l7Ua+bLM+PbsjGQi4CHixW9Il0hK2WqxlmUpFq+n3MRzTml
         k6afv5l61yLqWTH21lPaH5lACWbpfrJZi9ZxmIkz+6nPh5VwY/+ByPtyfKiLIwQsVLpo
         iCExbFSNjhVrbWsb1VGe6h1Yr5cPvfi97SH9eA89REvjTBCaAOAn15ZG8yQfX2lqMxAz
         SgTd0VkH3NoOHwwZe5+ezVCVDeX6jLP5q8UhU9JVCFcYTb5G2VftSlbq+lxVned+EnPV
         V0+iTvqg0wpT0eIeZJWjcvBGXxipBX3vouZtPJW+R5O9FU1V/T6H1ExLjW5B+BmpIeZB
         VsAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BRkEFKOtLSBB9V2OyRl9SLECujfgDUQ9Pj3TAeWNePo=;
        b=mYbTgOv7b8VtxGsqyiPu6t/BQY6FkKJckZfOSfT8g7AW91ypjrDWd/fUY7e2ouyJ8e
         HnfA2xCi5GXMwl7BNp/QvyDqzJ5Hy/ZMWZ758z6R/+5PEcgPklFxMmP4c/ekwlqqzg94
         +1hmqt67dII8SoBOUu60gxklrG6x8VcraA5Ju2Gs1e+DQjsV20LCGtbBukjzIoMqLFxi
         Xwqiz0eBrmcEgJ2URJHZQ+q8gazd2BGbB1eg7mlHbuvqE4s+GYL9H2CPfDPrtwyBeFsL
         Wyq/q1sif/6KVZ4Zbtnb12Yabrww19C+Al99zt92WZoH+WXw01TUH8aBMkzYQQP0C/xj
         7hlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUG/XhDGLu4YAS2XyvWl6VkkS9X1Mdcgo8r1lO9GDbRS4WejUK7
	y3IC5psdQOpvf4xkdOykaxA=
X-Google-Smtp-Source: APXvYqzLNbs+9xIyMyaUwx3PpaGvWY4EFnIB9r6W/H9UUzpYT6ckWQCIRDiDxiDkwI/W1UXrMfaQ1A==
X-Received: by 2002:a17:906:c7d4:: with SMTP id dc20mr19087655ejb.235.1569846570135;
        Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:a51:: with SMTP id bt17ls2093674edb.8.gmail; Mon,
 30 Sep 2019 05:29:29 -0700 (PDT)
X-Received: by 2002:a05:6402:17ad:: with SMTP id j13mr19384553edy.212.1569846569578;
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569846569; cv=none;
        d=google.com; s=arc-20160816;
        b=mzi5nkYUZvQ4sIAYFN7wdcWlXAq08PXSd5y4ND1BmmzCk9X4NIBC6ajnfQdkRlhfLL
         p7FQ+nnSauCDmIU7jyRXjubA2xKCfoFvubipyC9V+drSkXSnSbUF8kkjV4E4OMFSZ338
         EPYeZFZxIHrzhH3EO3IDcqvxbNHLYWCY+nrWNcbRU6jjHSuRm1VKM2vyqWiVnxAmtN4P
         qdunL/hAaXJOhq4BfL/mIZ+nID6D7YrexqeOTDo1cSh2inBtVhz3ZoJt5dysOITuDAJZ
         umqmZM9XPr3yJ4jz8mYj0xPUCWn759v0LICvQGmEajJR8mCVEnGbQAVA+sklnc2UMqmP
         Fu9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=QD5rwo5y+88KtlNE0EreB05PfjU3/C0/4dotbfzsQ3E=;
        b=VgMda75pTNZtsID9d7lo3HXj7EuqRRvBm8zLqAN3YxOyR8g0xCsSMscoz+ndTFMxmY
         pGnokFfgWz8i9YirOt8Yy5yYGwIO9Q3ndToqWW2fKiXruWhBeAWs+dXPpQefZxtmUTCl
         auSOta28H01WOOU3hkR1diltEKtmQl1+6V/gyK+MDtLqt5N5Wei2HehYng/1S8DdYNL4
         YvH0yuVFuWiuv+bAWgnahn0oNeYm/JMWcrbhnQls/vVMCSVXEUh8WSaQP94rnNDUL8sQ
         vjVvIa3SBwDjH/Ww/F+7kbGkZ6vSbEMUVJy/NkCaN6XFsd5cS2RWJGr44sYrfZra6ClU
         JxSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id d27si885579ejt.1.2019.09.30.05.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id E8F55B01F;
	Mon, 30 Sep 2019 12:29:28 +0000 (UTC)
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Kirill A. Shutemov" <kirill@shutemov.name>,
	Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 0/3] followups to debug_pagealloc improvements through page_owner
Date: Mon, 30 Sep 2019 14:29:13 +0200
Message-Id: <20190930122916.14969-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Changes since v1 [3]:

- Kirill suggested further decoupling of freeing stack capture from KASAN and
  debug_pagealloc. Also the stackdepot handle is now only allocated in page_ext
  when actually used (it was simpler than I initially thought). As that was a
  large change, I've dropped Reviewed-by from Andrey Ryabinin.
- More minor changes suggested by Kirill.

These are followups to [1] which made it to Linus meanwhile. Patches 1 and 3
are based on Kirill's review, patch 2 on KASAN request [2]. It would be nice
if all of this made it to 5.4 with [1] already there (or at least Patch 1).

[1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/
[2] https://lore.kernel.org/linux-arm-kernel/20190911083921.4158-1-walter-zh.wu@mediatek.com/
[3] https://lore.kernel.org/r/20190925143056.25853-1-vbabka%40suse.cz

Vlastimil Babka (3):
  mm, page_owner: fix off-by-one error in __set_page_owner_handle()
  mm, page_owner: decouple freeing stack trace from debug_pagealloc
  mm, page_owner: rename flag indicating that page is allocated

 .../admin-guide/kernel-parameters.txt         |   8 ++
 Documentation/dev-tools/kasan.rst             |   3 +
 include/linux/page_ext.h                      |  10 +-
 include/linux/page_owner.h                    |   1 +
 mm/page_ext.c                                 |  24 ++--
 mm/page_owner.c                               | 117 ++++++++++++------
 6 files changed, 109 insertions(+), 54 deletions(-)

-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190930122916.14969-1-vbabka%40suse.cz.
