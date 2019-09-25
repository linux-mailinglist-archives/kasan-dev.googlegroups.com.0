Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHUVXWAKGQEAN7OIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C6A09BE004
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:20 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id o8sf2292047wmc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421880; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pl7Zvg92WJXy4xcU0JeEhYrZIRqWzdhV/Wy0eZa4gTGYpQfa/0jnkVbP7oOODnNh0N
         PHQVJ5TU/HW2RETzld/vv2f22GfMneCOfvIqqozX7MNUEigezy3xDEmP+CrNKRzz37kG
         9NsqllHMkPMyDqI2ERy2qMiYdLomFzRhhI299BGizcpf3UDaki5FosAPk3UHakbsGzoH
         hQ8Lib2Smb5+UGnOzgDiRV3RMnlY+BLOnphBOiW23IFbJVXWEIA6na4IT25CjFI+B9pj
         3K2q9zI7ACLBsLcQpK6FkFiaN/Gcjl8A+eZCsMs53ZtBdCItFzhPeTNePJqCKNUAGGI0
         WJaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=37e3IRTF+FAuhOCfu2iXFVSmNyiEAknLexb+zcQWG/g=;
        b=uRSi8KfPQ76+7l8IiB3g/Xx/BSMNNcG/8DXYUWw52W38LKnerGD06FPf+SpZRsUplj
         3Jfh3ogdmtAe+PCkGFAV3/HMrmxugWCL63SczZfooUJpBzIjCYxU0BkMOD0IaAOiLL71
         cR7VQ5x/ZiSk9/ioDjvvlfqSHPvzgwIcXAOyy2R2BfQa4BmjaKQqsbJ0QUEogxlt1xLz
         4Fqo1t0taQrUVqYyck2uQeIh6Q23qw94sos+QFcLp7J3QVlrbzfZ+A8Uqeeseswt5Xhu
         /d1HtDSMGxz3KHLJrnOIccD5hf+tQK7vMd9BGfNJxljQCJFwSpILmUHkoCpe0G/PGSYH
         21NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=37e3IRTF+FAuhOCfu2iXFVSmNyiEAknLexb+zcQWG/g=;
        b=lVh1eakD5o10I52KOxiQU6Kce+ZSN4eZG7KvIcUHBZYaQngfcbfFcCuMJgLMCqcU7E
         vFxNRMZxe8ARmvdr96plChgisKsIv4UVGhzybNImbuFDBbd4aifJXzQcd0S559T+NjYo
         XYVThL+/Adhew4Bb3hxKo28Ep7QVppsN0OcrgoO2dAgqF5tet+oleoU1oU4ZTOYboJZC
         GHY0uyzvT07GwDmyVD4UwD5GalvG5aNzt2SIdMyOdTr1e+DdOksZg8tpGs/t4O7YRW08
         XTLEC/NjueOiLftYrzPERqtM5+rfsWouDEEy91nwPhNK3YvaoYYEOhS4EpOz4mj9KbG4
         LCyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=37e3IRTF+FAuhOCfu2iXFVSmNyiEAknLexb+zcQWG/g=;
        b=kFC/oJ9kda/2ISJtrI7u5hBdeqybIMBba7BTduPx0DRc3xZ4GqeIES21ILPA2p3QHj
         A1GZlDqwoU6PBKAHgQ4yx6v5VBlWC1GRYyN7+k6AJJXyZzH7rh+s1nHGpcsMuj7kqWtO
         9U71lQGrjhtYiA1iN63KZXCW7SynEvBDbRC6KCfSG1Ve5CY2EPyuYBMnHy6+v8mwtcVN
         XR9Huir/FPUryqVyVdCJwjo055iJD1OsaLjyeSfb4zgn1j5bv2w2N/6X0DijwuSjvJmk
         1EvGXJEH/xasCv8pUqSKU70UQ/1zcA3P+uYuXTWoi4ju5PhNVULztz4fTKsPzLHIjEO/
         S/+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWzrTgJzkyn/Sa6waBXGeZrUsQ++huya1Zo84UOZ3nXFSfAKQwt
	UuKfLZCwTK22IbkVj0fD7vE=
X-Google-Smtp-Source: APXvYqxRlf1HyruV58HIaDbnPTQY9HY66Y+1r1+Aq3CczFaCB37LXRDTdY6Wircajjy1xiOAAsvo6w==
X-Received: by 2002:a5d:570a:: with SMTP id a10mr9232022wrv.136.1569421880511;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:828e:: with SMTP id 14ls2301408wrc.7.gmail; Wed, 25 Sep
 2019 07:31:19 -0700 (PDT)
X-Received: by 2002:adf:e9ce:: with SMTP id l14mr10312652wrn.264.1569421879820;
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421879; cv=none;
        d=google.com; s=arc-20160816;
        b=AIzmaavX5TNp9USBChEaj6JwKXTahrm4k4kB6csGTBZkmBRzLgDIYbYWME+VCkz9nb
         g38dYNlPMzHj8uZz41rx9Qz0aQMtSGRtZ70/XXDWKvjLBKGBi4gNq8bT+tyIfMQJ5XaH
         LsurhxOGQ02POCXcHbhCFW6cNE65vr42i7LiU6P5hpwc2MQnosmWpuuj4BgsYh+7TsQB
         /+VgsJqrKLU9ro7WY9FejGzS1uYs9pDpWtJWvz/eIJo4jaQsC9wWQMYKkY25e2jyuP/Y
         xQddXVfglF6aigiJB1XOa031+ASspzN9lRVhKCqMXvf4Dp4SPB9hRxMtEihRFbyDWzFj
         GvTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=JWiXi6QsLfAXvpxYYsutxFI2MiZqoFa7+RlJrAi0DtQ=;
        b=cEPnNWSbMYVWPsMho0ob8d33wHpeHJMKaz8vUyBwc3r04A0x8fS6kG/ixMa/64zYS4
         xVh49/g4Ey/4XWOwPoFyozFjQrW772tJNJEThG3YBDQZZVHEjRx+29Z6aD5UsjeXMHmD
         2CI2JPiTEHafy07fhMU47zVxFyKK68/YeXAPVPlCXJIaI+lf4WRw3BWUdcA+lD4Yu0JR
         AQverxBLvxDUfuFmkCKwQaW0FB3dmXlo8AfTwmFi90DjUFLhT1RrkL9fVhYjkrRhczfb
         LMWAEmFgBacxES/bFE3wep8gnSO1vtEUa5bGCcw2fOnQ6MF+bsubvq3zLMYQcIlbNAnC
         7MNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id 5si337308wmf.1.2019.09.25.07.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id F15E2B044;
	Wed, 25 Sep 2019 14:31:18 +0000 (UTC)
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
Subject: [PATCH 0/3] followups to debug_pagealloc improvements through page_owner
Date: Wed, 25 Sep 2019 16:30:49 +0200
Message-Id: <20190925143056.25853-1-vbabka@suse.cz>
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

These are followups to [1] which made it to Linus meanwhile. Patches 1 and 3
are based on Kirill's review, patch 2 on KASAN request [2]. It would be nice
if all of this made it to 5.4 with [1] already there (or at least Patch 1).

[1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/
[2] https://lore.kernel.org/linux-arm-kernel/20190911083921.4158-1-walter-zh.wu@mediatek.com/

Vlastimil Babka (3):
  mm, page_owner: fix off-by-one error in __set_page_owner_handle()
  mm, debug, kasan: save and dump freeing stack trace for kasan
  mm, page_owner: rename flag indicating that page is allocated

 Documentation/dev-tools/kasan.rst |  4 +++
 include/linux/page_ext.h          | 10 +++++-
 mm/Kconfig.debug                  |  4 +++
 mm/page_ext.c                     | 23 +++++-------
 mm/page_owner.c                   | 58 +++++++++++++++++--------------
 5 files changed, 57 insertions(+), 42 deletions(-)

-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-1-vbabka%40suse.cz.
