Return-Path: <kasan-dev+bncBAABB7URRCWAMGQEUHBJX5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C233E819224
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:19:59 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-336599bf7b8sf31716f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:19:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020799; cv=pass;
        d=google.com; s=arc-20160816;
        b=jgs1ehxnvMPPEvWyIWOJCzSUMtSIp7GTVNMP/xLr1w8+InT6z/nVYQxa51Sz2bwjru
         O6LvC99ri8dYeEoJva6M9RdWs3cyjtdLIpXHy90UsRap79Du+KB7IEk7ea/lGWDQ/eJb
         r+bqTN00+54wFt4ZChjekF3Wd7qqHK+XEvo/B3ICXe//RmMqexcD7si4av2+FejmvhFd
         2Ipsuij7O5XeaC0AkwsYpdf7p8G39efvfD9NrxV/i41EBrzrTJWpeLKvl7X+LIVRPm3i
         NlBv/VleAwJAXsIvo6Wx19kukr4pbNj0cAXsZJap3KqejdhVHNkAEL2U1NaYUgUOtOlU
         l2DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6u/WwomIofLaMQU4eZ0diz0azGoyhrg9ekXKmAwgNaI=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=DTCYBfP9iB0x4TL3mn/abubplOnyp7dqsZNd6IJQ+zg+nCfrnJk0rTwKrnWmbGf8w2
         9B8706FQmUbMoE9CKpnuFOqpnsjDUZA0AnFwEQ+yVtAg0mo10aNzkkU8Q8oxh2uE1JRu
         m4tCQ3gA9IQO49q3gBckJSp6aPfrs9/83LC13I9sQdiJgWcd8nDo+zXIJpwJLMi2GLg5
         djqz9Cm+Sbn7L+6tqHWpfem1gnOdjgC7fW1FBGd2XFUvE9hgGwr3j6q7Ej7Ra6E8/21V
         mVUtg1EDsoYiDl3NH8bW3w0YZRlJt8Bl8jNkYDa1otdAZLrwmg3kNxrebZJAsUGiqyaZ
         WHNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wLCvb7tP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020799; x=1703625599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6u/WwomIofLaMQU4eZ0diz0azGoyhrg9ekXKmAwgNaI=;
        b=Haw5h4dMSLA6OM5hn7zfyXmZjfLCHcMQ0UCNuqZ7FUufnRRtZ+8Q7OBJsy20F3ejB2
         r//5PCrlGkNZKz0YNWKSnBLdnrT61P8EUQOMcU/mP94BJxccU1XREtFTio/KaxiIMDAC
         bzl9N67u4iN4HM07h3j/4X66Z4/ppK1+YlrysGrEQ1jaABF4Z2gjvHfpgrOcAHnVW9zh
         8/QmtHT30AL7vY2HW6F1cYhiUjU4MTPpW6OoOgNq2PiNE9aJNgArRGmzFqNu63ntbB4g
         2R4Al/Fpcuj0AOh6XFp7vPEqKAxGHaDFbkmxfljTuLdLDUrllzwlAipdGF4FZlhYCMNQ
         YydA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020799; x=1703625599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6u/WwomIofLaMQU4eZ0diz0azGoyhrg9ekXKmAwgNaI=;
        b=UR9uVb+efnRgovesVruXyHiTV3dBUmEHe3ujCDff2fedgPplxQU4HcpqRmqwJsfheb
         VegKDpjXuCaxofvvIkJZzJ572MGG8wPTP4MWnrQSeAd4tNTbiStGDWW5K60pfTBWOT2G
         nrlUCWRfXBUFj7NAkpFhJQ1ivF7oPcTwy/8goYiQgWI75hPm2CYhq0SqCVUEgKhylAFf
         7Y5vwweCLluDMdyuqPdiL66vR8rCUxR9/bhc5rekIigMj3oMU2q/7gCitvA+xbay64Ve
         qGgTt2fqY3dQaHHJegDX4ZrGCeTpqYGZt5/tEAN623ZHz855lGAvm8enK9MsWqpoD++X
         eaPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxN6KDhm8WUG6bKOdqlYEOcfAL+KBS2DrZmD9j2Rhb0sPKBOP4g
	L8F1bj51gkdE+h7b+Ao8sno=
X-Google-Smtp-Source: AGHT+IFME7rznHI2VPTwlJi3RIAEKXqXB1aVJ1K8zEHLrZSiHBb1vFRPD97ZPgF6pxCuterRRxQXxA==
X-Received: by 2002:a05:600c:294b:b0:40c:25d1:ca29 with SMTP id n11-20020a05600c294b00b0040c25d1ca29mr956572wmd.173.1703020798843;
        Tue, 19 Dec 2023 13:19:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1695:b0:40c:39ea:db6a with SMTP id
 k21-20020a05600c169500b0040c39eadb6als21885wmn.2.-pod-prod-00-eu-canary; Tue,
 19 Dec 2023 13:19:57 -0800 (PST)
X-Received: by 2002:a05:600c:2483:b0:40c:53bb:71d9 with SMTP id 3-20020a05600c248300b0040c53bb71d9mr859014wms.111.1703020797066;
        Tue, 19 Dec 2023 13:19:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020797; cv=none;
        d=google.com; s=arc-20160816;
        b=HqIplNOz3AV/YOoNShgasmViVm9w0OcyWaata9DyYWUsJiah8uO4MNn71BvHk8N6XZ
         +xqQCXQTCBxtXOiGgaCzFRRLydvBeCWMVyGmGv9h+22QZUYZYVnkvzTn2njHrCZ5TX76
         YtAI21EygQuYIk0z29FD275U23GGB+4ZbD/L3GLZcR8uug+Fv3orFUnUQyZK6CrC3eFW
         qboviNo4zKui4VZah+A11ccvCOAE3y4BeRzfQ3t97hIIC1WrKaC5h6v0uRV49XCENQlj
         fn3xtM7K3RfatZYRvXrN4OKoteqmehbkfVRbiMoR2fjGnyW8uiNJ+Z7VGHgUHfxS5WAZ
         6N+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=edMpd9BGEGYDrNpVSYxtSqq0y4QzGBIBITzoL+fELBg=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=ciRxglQy9UE799OQGLGDuCYJDX8a7uvDf5ZNiJOYa72Kg0T60Y3VzwVdxn0zXj4X4G
         cDp/fOLdmHhEnkiaxT5Sx8+ty7F/aXrLVMi0hHsqiXBUqBLkJjVf/Cll3iZig6Mb2SRV
         3sg3lYrSZAZnsAJRkj1NeRgm9feRpGXuuaZJn7OWWVqqQdhM/6wzt/pZvbVbqD9AkoDJ
         TCPDB1frVSVlwTa3+dZJ5HID8/BVJl21aJCoOIL0bli5PMkdvzSVlZ3b9zK1lfnaejIP
         w58CBIWTgPGFS0vTyP4BxQPjVDjQib8vIUDd2wdxkSuXZ9Cz0eIi4WdEr0bjnlXyDlh4
         0MIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wLCvb7tP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id az27-20020a05600c601b00b0040c69a269fesi129508wmb.2.2023.12.19.13.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 13:19:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
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
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 mm 0/4] lib/stackdepot, kasan: fixes for stack eviction series
Date: Tue, 19 Dec 2023 22:19:49 +0100
Message-Id: <cover.1703020707.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wLCvb7tP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

A few fixes for the stack depot eviction series.

Changes v2->v3:
- Use raw spinlock instead of spinlock to avoid issues on RT kernels.

Changes v1->v2:
- Add Fixes tags.
- Use per-object spinlock for protecting aux stack handles instead of a
  global one.

Andrey Konovalov (4):
  lib/stackdepot: add printk_deferred_enter/exit guards
  kasan: handle concurrent kasan_record_aux_stack calls
  kasan: memset free track in qlink_free
  lib/stackdepot: fix comment in include/linux/stackdepot.h

 include/linux/stackdepot.h |  2 --
 lib/stackdepot.c           |  9 +++++++++
 mm/kasan/generic.c         | 32 +++++++++++++++++++++++++++++---
 mm/kasan/kasan.h           |  8 ++++++++
 mm/kasan/quarantine.c      |  2 +-
 5 files changed, 47 insertions(+), 6 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1703020707.git.andreyknvl%40google.com.
