Return-Path: <kasan-dev+bncBDKPDS4R5ECRB3PH76IQMGQEVQ7MVSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D504E85E3
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:19:42 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id j8-20020ad454c8000000b0044111c17099sf9075722qvx.0
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Mar 2022 22:19:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648358381; cv=pass;
        d=google.com; s=arc-20160816;
        b=xGkXm54SQEPVPcXXXSg7k7jHg95cW99e8ciVy6GDaS7ovRiOjDxedQBl+Jqgx1co2u
         TACuHpmG8tSv5rZ7GvbspYOP6rvTeuuoc3sZwcwtrMprm/2EnEwYhmfy6bLtxT4qxLoE
         EGZN3M+yrMqDpC7oE/l/G1LLPnChXnHNfsRBrIfCtHI7xOKmcFKaruMWb8O91hpElpso
         LSFLhxZKUYI3cnTc1HlsetM8ymkiLexaiz/WCPrX4Rc3+/uD+ADn6vcD/byF1WTeDWJS
         gpSnbbNbhsBrx1uQ7+S/9W4GG1sUclxGI1Wa/woH26YUXLEtRqriKiBs2jefXVZLwYum
         PrOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=46Is7Pudbg8EEsD1/ch6hBbh0yMmIGzgXOiUGoya820=;
        b=qJnLx28meqG/FppSO1zyjKymmpQ/n2ytTJS2KhDRQs8GlyYpxyP0dSYzMVuZ85sX8H
         gCjeznM3KqD0wrdIgWbUkX/CQtrdApv9HqWgeTq+Dj/fg6whAlKxKQVapMi/gyjHw8en
         YHR2Aynqg2X9xYUEJN/OWArv/jqmBIYTUnSgMC0sGrDsG5qoEW+VRxBvBqhOvMvK5/19
         H/NIe2TAt9WNs7HmUQo/vYlI90Fz5DRreQDoWkWJs0QzMglaNBgTcf1hC4GOuWvqlnQ3
         gAg3x3lz3IxynMd+psNfBZgCd6VB7m44wXFNtThzXa7nwU+v5y0exlXdCx/S7na93QSy
         7eAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=LmvEja9m;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=46Is7Pudbg8EEsD1/ch6hBbh0yMmIGzgXOiUGoya820=;
        b=NODjjRdls/AUQO+SfaVaScrbvSjsnJTXRMNfywqwvLMJokr+kHmdOtAOHQziUzMHNc
         8lqOJyqn3nqzbZlkVw5Vr6Arcxgt7E2uq5dHQu19wzhCBNjXTE2TQsxyfOYUR9IZw/vX
         qv276+g1SyPn8IO8ekv9pYJ5KUN0Cjv2JHkxE9+a8e8QodRW9BejrJWVlILxdxb7jYgF
         DPhChgY75l0DohVwslSFNoYeumSnsngmZpKo34Y2809fg1o0mCVsQR9uqjt7ItGekAcc
         ODGozx9PkD6q6d3UczGvYwwhBDhovWQEUTu/LBtdj5kVfqtkVQgZ+YWL51KqgruROSR+
         ucGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=46Is7Pudbg8EEsD1/ch6hBbh0yMmIGzgXOiUGoya820=;
        b=QbRRRJH++NqoQlQYrg7zZkjZlzk1HF3GcP+zaueYGHKIaaCVkX6g+hyPQy0pCdnfyf
         l6uhkCHfV9OiWH2L+giFg3RqLMGiB+sYmv41IWJ6imTHUws77b6bAPsceCxcCcf+3DOf
         C6vtYyoi9+tnYiMr387cSoDAVVU2GyVeDH+CgpNKbBqn4XtYj5KyHlfWsYNv0pMP2oZv
         8WWEtmdkfjL2sCxqp87uuSZRB7GedwZ7ubyd/iZ5I6EEWTh4NB79ytOeJdJ1pYY/9B1I
         OuQ/E6lZHSf6IUeBmSAp5YrZuElo5OGFNUxei+oalj6r2hHaINoDRSwQHfJ730BUULO+
         QJ9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53314xkYC13c0wDJbH/G3FHZk2yivrw+pHJEWGdjP+KHTuUYZ1Fe
	45/sNvToat+8Y+abzb8eyxk=
X-Google-Smtp-Source: ABdhPJw7END4tpMeY/Fp2NW2VB+VNhCcw66Sbh7UoKb0A/u5ZSPRq4GlK0M9yZYuCA7V5h2ksBoRaA==
X-Received: by 2002:a05:6214:d0b:b0:440:fc38:9503 with SMTP id 11-20020a0562140d0b00b00440fc389503mr15940403qvh.13.1648358381721;
        Sat, 26 Mar 2022 22:19:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:27e8:b0:441:216a:2707 with SMTP id
 jt8-20020a05621427e800b00441216a2707ls4505725qvb.0.gmail; Sat, 26 Mar 2022
 22:19:41 -0700 (PDT)
X-Received: by 2002:a05:6214:1c8e:b0:432:4f21:aedb with SMTP id ib14-20020a0562141c8e00b004324f21aedbmr15334452qvb.74.1648358381328;
        Sat, 26 Mar 2022 22:19:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648358381; cv=none;
        d=google.com; s=arc-20160816;
        b=HZqF6UcuxF2YQmO74d8Ir4SghfFrsfJyhEwekJHCeVf3WbaHP7InzBy7kZcW21wleA
         yG29SpXE3qFgoi9DaVJEaOyEpspr7pRW8NFVZKEmPeSooWBigLYOmeE1XnhPzxszfRtn
         4d1peKWHbI3txiKg/igVMoFfCrg/fhPMqXhe/9soS5w/PkSKXAQ4nMAPX0TWG0bY2+4o
         roQHJ3ie2+Ksusg4Wzm02oTzrRpWEnt8CsFcz9g9PNcXeqxAmp3DB/tzvctXZ9eeDPPo
         XdDt+XXnTfNYlM0AlDzuhKmOTSW4lOHCu4vELMOOLm11ojIwr/R8unCGjBB7zJnv+tXE
         wf3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZjNFjTqwpOuk0OmVp2LI3cxltEk8fTUHQ4QbOFB4vvk=;
        b=GME8h7SMq2ImV0zR9ZSapulyKlghNnlRopBNgXJhKTdYwoxWMNERPZsUY4S+YinVMl
         zR9iIDwb5b1BdHVBMpkGnKtgp9rV0kVD1IygN6lL3Q6bciQbd/yxVqInfDLWNOHHE8fk
         QzJ4lMSn9hHjCftjR3CXvrJZcM/aT9FK7sL+ivPH2PHAd3depEvAzNRzmCizZCUwv8vU
         UxwV/Aye0tgcEjCCOp62/eWvdO8gtpLmAh4T8U2xjwBleoilKyiEVA52S/iml3Sk8MRL
         rp7TnidqI5LRTiff3OQ3V43Q+55b1aMOHid6d1QVX/9uRzgW++ZepKJe3pxYSKNiy202
         oMbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=LmvEja9m;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 81-20020a370954000000b0067b0ea8c5f7si459416qkj.1.2022.03.26.22.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Mar 2022 22:19:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id w4so12068739ply.13
        for <kasan-dev@googlegroups.com>; Sat, 26 Mar 2022 22:19:41 -0700 (PDT)
X-Received: by 2002:a17:902:c94c:b0:154:58e4:6f5a with SMTP id i12-20020a170902c94c00b0015458e46f5amr20586217pla.142.1648358380557;
        Sat, 26 Mar 2022 22:19:40 -0700 (PDT)
Received: from localhost.localdomain ([139.177.225.239])
        by smtp.gmail.com with ESMTPSA id m18-20020a056a00081200b004faeae3a291sm11115940pfk.26.2022.03.26.22.19.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Mar 2022 22:19:40 -0700 (PDT)
From: Muchun Song <songmuchun@bytedance.com>
To: torvalds@linux-foundation.org,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	cl@linux.com,
	penberg@kernel.org,
	rientjes@google.com,
	iamjoonsoo.kim@lge.com,
	vbabka@suse.cz,
	roman.gushchin@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>,
	syzbot+f8c45ccc7d5d45fc5965@syzkaller.appspotmail.com
Subject: [PATCH 1/2] mm: kfence: fix missing objcg housekeeping for SLAB
Date: Sun, 27 Mar 2022 13:18:52 +0800
Message-Id: <20220327051853.57647-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.32.0 (Apple Git-132)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=LmvEja9m;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

The objcg is not cleared and put for kfence object when it is freed, which
could lead to memory leak for struct obj_cgroup and wrong statistics of
NR_SLAB_RECLAIMABLE_B or NR_SLAB_UNRECLAIMABLE_B.  Since the last freed
object's objcg is not cleared, mem_cgroup_from_obj() could return the wrong
memcg when this kfence object, which is not charged to any objcgs, is
reallocated to other users.  A real word issue [1] is caused by this bug.

[1] https://groups.google.com/g/syzkaller-bugs/c/BBQFy2QraoY/m/HtBd5gbyAQAJ
Reported-by: syzbot+f8c45ccc7d5d45fc5965@syzkaller.appspotmail.com
Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/slab.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/slab.c b/mm/slab.c
index d9dec7a8fd79..b04e40078bdf 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3422,6 +3422,7 @@ static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 
 	if (is_kfence_address(objp)) {
 		kmemleak_free_recursive(objp, cachep->flags);
+		memcg_slab_free_hook(cachep, &objp, 1);
 		__kfence_free(objp);
 		return;
 	}
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220327051853.57647-1-songmuchun%40bytedance.com.
