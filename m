Return-Path: <kasan-dev+bncBDY7XDHKR4OBB4EJ72DQMGQEKFFKD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 264153D6D0E
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 06:00:50 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 30-20020a9d0da10000b02904cd320591a0sf6671125ots.18
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jul 2021 21:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627358449; cv=pass;
        d=google.com; s=arc-20160816;
        b=PmvswYzD5mbY4ze32FHX2v38EBNbLSE/NF6G8lRfvP+BpA3D2GBxlej73IJxwhmRc+
         cBmTYIKc611wMPlGFpw5FeH3GkTjFGG4tUq676u51GPvF4pHZZyXhC6vzxKgVTVQ3G5F
         MfDTs6BkA2Wtj1iqGCckPxqsyuSNcGLHbtZjUnKYSRqRVZgEzmAwLMVtxvU6LqU13TyO
         mSqd1NGw5MCCY/qLR/EBCL1arjZsJRumKWw0rY4S9HuoSZXoczf+oKdX8Cvq/alLnAhU
         Mx5Bvy2TYf5LfZK+LtggJXUCvmzyCASrm6gzBrSwePUXamXD2QN2fIkf2AYpRXrZ8RNr
         tVCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=brPyTQoCtphh2IdHMLBTKa4j9sDo9mWjm+qlqvhtDpc=;
        b=nNVFDCnvHm+UTdZQoG7xIkIJ41Xa8YihQDjMP8+ijWWVJlVhNtzsSz+vykHgZ0hWyL
         L84e4l6RwVI7CKtD7nNdgQNsQivcTa2lOUAJQRgvH1K3B5qiDvkuKC+fifxuBiGJZyPB
         8KeUu6JG5ky2ApRdJ2lYiYi6jLBOFAod2UOxSqCxl9LGiJ27p11TKRwGaQV0sIy/wko0
         MbL0rXdiDNbBrQI4S8QiBbaeKBHMaWNtrKD+hM5cNiTJi9CX4er+t1NyuXqBGs6QVuIO
         0lynFsmVRiI2+ou+6TSrudyqZuZ2JawOjXPJ4l/PsOhAoSZ9H1zmG50q8utmfugJQBjb
         Cs+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=brPyTQoCtphh2IdHMLBTKa4j9sDo9mWjm+qlqvhtDpc=;
        b=G4wgb/paOevzi1rI8G9wII/F7PB33syC/35QwhESzdKkT4/ZUImu88pBgym0QuLm3j
         pmq/Qlhlt7RTJ/3JjXRa6eEYoXFbe5L1amHCvXU7LshgWUvv8S/xeQaJGIJ5f+DjgyLm
         3ar2JX2Vm8rhDN0zaE5ifKDccCUdFzteSnNbmPwcLaQ/u1+mT/IUV6eNnC0oBpAXlY6d
         hP2ixY0jI7ZKCWerQaVO99maCVBwk41ukknszhDL8SxQg1hfspkkDE7VRoaFvm/okriX
         I0bFoLKFdjMdwIux9KyWUO4jMlbBpxjwZ72KqLWV63cVZ75PpjV5YCgaZI6hUjEuHURH
         NfxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=brPyTQoCtphh2IdHMLBTKa4j9sDo9mWjm+qlqvhtDpc=;
        b=U8HjChe8HYBtPSP/BwPmXbO9eb/5zhGbnkxDPiXjtNHdMWW08Oj9wPPvKeXERweNFI
         AMcmKN5P6HpLPRfHKNIAGK7AQdWpmjYi1F8F20fTW7GkVWKRUnbt7G14aerg6YfalLrI
         v/nnQCIS124rjmVVkJ81QZSX6+/fGcSttJF0tbyg+um3PjjzpVxBjDigxPWDg1h3BPeV
         RfTfWf5PTUrXoPkjD95HupL+tO2NJqHzqCPQOfMbJhHjq2mohgSAauEDcmjH9GUkvch4
         DRYCPcaFsFH30WydDyUaesik4XbrB9qj5ehh+42pR+r3SyT9o/m4fphs9NJMDotG0HRb
         W62g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ejUvSr8SmkteCua35fAjrUyoM/OwThwIs3b/UGJEaiRNrtO2B
	VHFiRxEYUvYNEedgsF+eT2o=
X-Google-Smtp-Source: ABdhPJwpSpR0u0ZaYLOISIFMs76wufjkfp2yGd59Fm85mMr0QPes1+IB7b835SXmbyu/EnkM5KNanQ==
X-Received: by 2002:a05:6830:1be2:: with SMTP id k2mr13651576otb.285.1627358448834;
        Mon, 26 Jul 2021 21:00:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2a05:: with SMTP id y5ls6386368otu.2.gmail; Mon, 26
 Jul 2021 21:00:48 -0700 (PDT)
X-Received: by 2002:a05:6830:1184:: with SMTP id u4mr13587299otq.29.1627358448516;
        Mon, 26 Jul 2021 21:00:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627358448; cv=none;
        d=google.com; s=arc-20160816;
        b=ha7t0CJUQ2oANgqDMkdbIhSZ0YHukMVtnSAWsfkreFLL02CKEtKWSzmI4jVfCHjT+6
         iXcmcOnhlFypZOOM7Px3Tsvk40gRTQwRhKdCtGhAJFU5Vu/MLbsA1Q1R7oe0xozZ3lmX
         1M1RZX99fOyiEog9JQEr9dl1JOBzd1RmrDINfovW3LRo2w8pyfTyUEOjzPiZ3pomGMAZ
         XuXSVHfJ9F2gkiEhxZUm9A16h9JSBzY2TgKPvQCzctIVNne7k5Aedbako6ZJAGHHCZ4m
         RQWmCNPqZmoLxY/bhvF2jYNiiCzz5y46QhrfXe+/JJq45RdUATGxuiGTgxCIgzBRc+q7
         Q+Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=nvNuYRg2tKD5Xgst/LIHbRSZyigbwYj4FMUxHCFOaaA=;
        b=oJC0d257Ma88QBznVA4zcwvxFxL/T6tvUclaYloSQ4lYbtO/5AvCJCtX3Qnu9nd5Lh
         05e3Q0gANdHKi/bGv4EMbMOhR8B7nuLc6b6SdYk/T8jJIp7jz9dtmYGzPlryTD+xQT1G
         ZZRehuwh4O7fv0rRF3Vcin7/Sk+46gPFAfxkNy+Ab0ed6dlhCKwJA/JyrCP1jFWF04rx
         48xJUK/ynFaTxTxjUJTIGWsJ6xhakOH3Yg0tY1HMNaYrLJMDW+DcyX626Up1bfoAKQud
         nrrpuNdMNQr6zMp9Ep4WfY3l07AUbpZ1STRjrZW2tQ8i+Xpq9kWYsKOLRH0MsGLnrfQm
         yN7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id g9si125170ots.5.2021.07.26.21.00.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Jul 2021 21:00:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2868be320d224ebcaaf0616153f5ab04-20210727
X-UUID: 2868be320d224ebcaaf0616153f5ab04-20210727
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 532556123; Tue, 27 Jul 2021 12:00:42 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 27 Jul 2021 12:00:40 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 27 Jul 2021 12:00:40 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 0/2] kasan, mm: reset tag when access metadata
Date: Tue, 27 Jul 2021 12:00:19 +0800
Message-ID: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

With hardware tag-based kasan enabled, we reset the tag
when we access metadata to avoid from false alarm.

Kuan-Ying Lee (2):
  kasan, mm: reset tag when access metadata
  kasan, mm: reset tag for hex dump address

 mm/kmemleak.c | 6 +++---
 mm/slub.c     | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-1-Kuan-Ying.Lee%40mediatek.com.
