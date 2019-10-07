Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB24F5TWAKGQEUQEC5LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C1667CDE14
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 11:18:35 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id k67sf3066659wmf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570439915; cv=pass;
        d=google.com; s=arc-20160816;
        b=Av+AHXxONN+a/W+OfnaZZ4OLKOdp87DvVBurcveCdt75pjVj22loSUI2V9YIq48udG
         /k282MphCUJvZK8JoyAB/EqkD7xREUWg/fi03Xs1bA6CgO6iLTQ8v2LWlMb3OsIMfTWX
         LBaxHVhojqgkjqqC84nNalupQCOAItW5GVzkePaUrH6IQ2zrgOtPa44zmVOumcq6sEPF
         HR6+Q2/13Ko+tx/GC/OdFJRAQLpcCneRiyQbtOi1sZd8G+8O3Paw/g9OQ6pP/0bGRk3T
         HlThXd4bm2jHh2+x73+beQg1+EAOQJXKap6zeTVE6xt+WMP223ujT/elkI0c0OHnfnGG
         4JKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=RwbIiFNsg98KP04H6ophlMMCqeLqljg/gSKDv4v1OU0=;
        b=guBt74Z+ljhuKOFp6jfeTHBedGO35i8GA5jN25bgbp7ueAZBqioNVrT5cKw6F6Omy/
         DQMHQoICh3Twgso/9ILx/aArd8+PLhQeHb/6hz/nxQZiyjTyu6e+Jb7SKH9X3XVmegV3
         V+0qx59lBVAYpDWaLnyggvoo0njUAQ3CIPc+MELFKv/hbFVk4bvdvq4VNqvT2B/y3w06
         +tW9IgPQdtXqzVZaqntn8iyT6D7RZHZmY+E4oyLA7ver1gSWYdZlLuUVcfcc59sCw6oC
         ztEEkEnjHkB0l/VyMs3DyxujhWdEr6DarRexwOXQN3uktcRoqx51wI5TBXLqG0eV0xFz
         k97Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RwbIiFNsg98KP04H6ophlMMCqeLqljg/gSKDv4v1OU0=;
        b=iAWoInjRMcLTJgNjJnKQ6QGH6+ZV5N4JdaHTl0sYtuPwmLc5aK2ZI+z+Kgf9l6AQnE
         RtHawzKmZB2PAFjNsb7zfCHdS8Lyy9n4GcnoTw/7A2FxUPcT22Y/D6TjUyTAIHDiIW+m
         +5fihBv+snHP07ArmSkQMcltvwN4kCoZun4NN1kmi/6S+wPqobi5MAsi2eTteoUpeMqR
         suhemnCkffipA7V3oYHMMiKQLxCPuqdhk5C0mR50PBXUkD+V/ebq2l/GpCFlhJhQfWnX
         XcUZ0QOAcaRglepPHC/U89CzrE+8wxaWTy5BAZAPEMnqP2H6vkG7siXJ8Q8+eSq5Fks7
         Rg5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RwbIiFNsg98KP04H6ophlMMCqeLqljg/gSKDv4v1OU0=;
        b=Fn+pef6PprMxZTFizCJYU59ELUHw2U6hLznE1HgNrGSyfQTg0hGpqFq74A1bizI46u
         nQr5af1xDz2ykWekX2gT/UPOEfRdC1rkn9dJ82mdQk33q1bkpObmUd6+pCelIIduRv0Z
         PuQJzXLuAY+dEZP14tjvLcQStDJJfP/LGUgcOGXinlJGcc+640JR5QVOVtSnEvVQmwsL
         Sp+q8vMUIHgksn3LK7p9IzQwp9Fst0GuLx88LR/7lpPpTsVpdW0x6Syuf6OHSJKLEdJE
         MqMF5x/XSPYDLZKLk/yHxJm3c83QG+ZlS3tg8t3zenSHSx2/KkP7dbASUfRV70T/K9ks
         wszg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWXuwA3BaMXnuHkj3vS77csjUZblve9R9eGPuKBc3Tbvnrdg/S4
	F7FVLRWVtyMB+CgEKz0pntY=
X-Google-Smtp-Source: APXvYqwV1uTHLeniUA6DsoIKt6iFUxsk5inPmlTk/j0P1ZoK9CEtkLCFn0RBrKeksX24cNf2suwBRQ==
X-Received: by 2002:a5d:4491:: with SMTP id j17mr20694623wrq.257.1570439915472;
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e90e:: with SMTP id f14ls5129931wrm.7.gmail; Mon, 07 Oct
 2019 02:18:34 -0700 (PDT)
X-Received: by 2002:adf:ce86:: with SMTP id r6mr21744459wrn.57.1570439914977;
        Mon, 07 Oct 2019 02:18:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570439914; cv=none;
        d=google.com; s=arc-20160816;
        b=gsiCNrnXMCbEeij01Mm3ZeQ+WdmUOn4s461cmjXGuZsqCn9/tCfFf0Byc0LYsCMyG0
         nKjk0cVxvaWIWITHRYw29L7YTl8jdQ4gTx53lVctniwwx2ltaWnCHTCWKBd/Hx+6ocFw
         Vb+ixop+44UIjlWs3rIthvT4O6/mWA7bAySewBKi0ffmoeT/L6GvAnyhVe4+zfO/7N2h
         wutOTrjG2Gs0ATX6OW7BPTVgO+fJ4CRcQfh+hAihASS1IrWSORt2dFQ61TVlsW+0nj3t
         JuVEnOWj+b/qDtxUu4joFFiI9jdkyR3M/8G0KfSVFFdwC/U9r7zFp2mj6RQlwh7t9G74
         U+SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=iqntT2ETOdXebAp2pSEULsJqvQPIcIK/5npAx5Lefag=;
        b=V7tqgWZRwQf2/TUB7cXyZOl/WJI3jj7FguR5a9c4jJLh674oWTlVk5mWgDk5BP2bGE
         +aRv1hUZGQAmPOw7knfltq8XQVzb8l5t7Z1uxNtlfnNqOvumUA9YkIifbl/cDfHnfB+6
         j4S6d9vL5zNle5TLAhTpFAxFSdJvg9/3j/lBPCkJbVz1l9hfawaM1MhbNzYdYZS18AHC
         Y0G7bVif8GS7MGh+d68O9nFIgWPOmz9Dq53vs9H2E9n1XN8JZpB+hR8bKjMn0rvpWDFH
         uKrjkVh7ahE27x5HHHFhHrO3YiUG5M5/fFBeS9Tr/4ZSAbUt5vmnuCeeF/qRv2X04Nbf
         tqDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id u15si900192wmc.1.2019.10.07.02.18.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 02:18:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 417FCAE37;
	Mon,  7 Oct 2019 09:18:34 +0000 (UTC)
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
Subject: [PATCH v3 0/3] followups to debug_pagealloc improvements through page_owner
Date: Mon,  7 Oct 2019 11:18:05 +0200
Message-Id: <20191007091808.7096-1-vbabka@suse.cz>
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

Changes since v2 [3]:

- Qian Cai suggested that the extra boot option and page_ext ops is unnecessary
  for a debugging option, unless somebody really complains about the overhead,
  with numbers. So patch 2 is greatly simplified.

These are followups to [1] which made it to Linus meanwhile. Patches 1 and 3
are based on Kirill's review, patch 2 on KASAN request [2]. It would be nice
if all of this made it to 5.4 with [1] already there (or at least Patch 1).

[1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/
[2] https://lore.kernel.org/linux-arm-kernel/20190911083921.4158-1-walter-zh.wu@mediatek.com/
[3] https://lore.kernel.org/linux-mm/20190930122916.14969-1-vbabka@suse.cz/

Vlastimil Babka (3):
  mm, page_owner: fix off-by-one error in __set_page_owner_handle()
  mm, page_owner: decouple freeing stack trace from debug_pagealloc
  mm, page_owner: rename flag indicating that page is allocated

 Documentation/dev-tools/kasan.rst |  3 ++
 include/linux/page_ext.h          | 10 +++++-
 mm/page_ext.c                     | 23 +++++--------
 mm/page_owner.c                   | 55 +++++++++++--------------------
 4 files changed, 41 insertions(+), 50 deletions(-)

-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191007091808.7096-1-vbabka%40suse.cz.
