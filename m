Return-Path: <kasan-dev+bncBDGPTM5BQUDRBJ4VZH2QKGQEBMOBKPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 405B21C676F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 07:27:04 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id j4sf468377oot.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 22:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588742823; cv=pass;
        d=google.com; s=arc-20160816;
        b=TxKtEiZSm5zGWg2RPb9bfdzntUAALaiYipfM9vtstQghGw4Bfo5CnJtMFiHjYZ1w3q
         irlGl5AWLmq6FFlkEEn0lYLm/jPQi/H6sku8AcqwqEUZ5rRAQuiMoO/R6GyOGTvEhdoO
         YuxG1qLJkVY/1ffndeUr+LYUTWvrUQSfhCXRnWEg8OLPzcTOfPVNwnSUMNra/xV+azmu
         kbquO5AbIS/mGZchyuoUc0SjXPAUHIRNlhMWPHsZ7J7UaIA1YUV24DrmkmbobNBtimtv
         OHCS0xVxAQHusdWfGYuifRbJmnQVI8uFHiXMynTJCHiKMOFIsJxwB4v45N0wtRwlljNC
         1pUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=no7YSWTbp9Dah+tUvhiyVGYMdwn4skaquX6J6fpu7yo=;
        b=nvBq5U3t8YZFtCiK04xznqHebqrMWsdYGzW2jCpKhVdVNuuWRB0r1dbex/AUyvh68F
         Lqmh92an0W0QnIjsqul5R0KlNvqzuL7XCgc5FFIDZ9QU19QoyhLiqU4YAsgMnZNKpuLF
         d7EW+/q16zwhT+ZJDB6vuBvhqTFl1EKqQaXuywuGRHvByrMSSBecSGFkobfbqiXNlmKq
         /o0oe2bed8OSqV8ov2YOPE5eJCIaVW4zvPAvkPg+lWW1KEO5BnTK63oUiOb2EmfNTSCm
         qwVHNcxf7mxxN4OM/oFw3YTogeJaWl9RMReANQfmahViHdScWdNiJfpWEIPcF7Wc+vLB
         i4Sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FbLP9Zbn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=no7YSWTbp9Dah+tUvhiyVGYMdwn4skaquX6J6fpu7yo=;
        b=CgVRqLHdWVu+TrjLUqoOzlAnWluHjyxL6qTxt/C+/X2SXIznytlW65pBiZ6pjE7Xzt
         QE2/zgrLkXYeT4g8dRjbHqs/FPOEV9HElIH586JQH8VkpszHsqnqtcVp+WkjIDGHqcPC
         aSR0D3Rwz9xlQoo34kZk5nEa7QwSxs1kvtWCypUa8JqXZl17sI9wUUU9qO03EEBX4BBC
         7JMH3PDQv5atQZ9nG+sRaS0vr3Yev1gFbVpfMrGor/Qsyh3AyPthh+61Nh7VpmLWDlAG
         mHENGV4rcVCjlly8pBWtOnu+4HGa8spNIpQeGlhMAyJdh9BJT4Ht6pkyI2zFmfnYmf5l
         0mmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=no7YSWTbp9Dah+tUvhiyVGYMdwn4skaquX6J6fpu7yo=;
        b=TRBXOQXyGgQria87JKsqFCOVjOBp2744Fm3seTHnpn1lTdeGRkDNCbUWf5z1cCvcci
         vWVOfjsAOBkew3pQulMsj+thQ526/Xm5dsX94simnqGq5EOIo1tTomJJkX4990B9L9gr
         UFG1fMJh+EkFlcRmGLDELAYC49asuIruAWMXAAvrp48ndOYGIw1NV/pflhdvjZFKlM4A
         3P3omUph7mMalzmGnJ2A+zIvaSK+vXJ2FGJHrRPVax67YHfodSPNamB8bcQy1X0onTIW
         NW9N+wS/6McYVXJ0kH1bCm69kKxabx1BCLIaeoMneVEIqHzrfsEZg5wLASBsJsy7eokf
         tdeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub5jSEPL4k0m6EeR4ZjyFNgznF4cMSypi9kw1oQG+q5VsBe45oe
	ytH4uFt2F2rvyNZu99D33Ow=
X-Google-Smtp-Source: APiQypLa+Iednh8hBA3RWVrRKYCKHKtI909nVccVyWovrcJlsf557MR/VmuizdYg49Z00Q3ko5NvSQ==
X-Received: by 2002:a4a:c3c9:: with SMTP id e9mr5964725ooq.51.1588742823239;
        Tue, 05 May 2020 22:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:108e:: with SMTP id y14ls126748oto.9.gmail; Tue, 05
 May 2020 22:27:03 -0700 (PDT)
X-Received: by 2002:a9d:6016:: with SMTP id h22mr5527827otj.206.1588742822932;
        Tue, 05 May 2020 22:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588742822; cv=none;
        d=google.com; s=arc-20160816;
        b=lksUaTymMyYQDXP9vcYqllpAULMbFTej6wj6k6i6L2EXj49GUSYZsxePsVG8bRkpDw
         85Bbr+Ya09TeivULCKF2CaBeGAW9ylphKj3gRlbmuSv30XXuG57zePCGEaDLd2Iycswh
         mggPODIOiKAy+EBGKx4cMPlJ8G+XSNGIIwtHOHp0g8Dlnq2/qaHbCKASWZo0ue4kVpVB
         tdoaZXqMa2VbU8MHg0KcF5rOhVC0DPj/JiwzB5ssWcHRf4rsU+Y8yWqo0JgMuNZRYQps
         lIl023CMIsAvKvv2KfnlZAz6oKCBpsD5I1Kt1Fnh23GiUVzUXnnl+ZwLFF2py5zUMwe6
         CYIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GyIzn8Fjf5emeqtXboCK49Lm5jVHGDGdEVCXXCPcZZs=;
        b=Y1dkLTefAhSGTss38ZqwoVJAnJHUpPQ0h1ggDQxcZKnfMhECUXN+OxADxq4qsEZvTQ
         lmm8iyyjjILwz1bhTbq9hH37aNOZ79kj5l4sE7QB7/MS9qPrFUwLGNY9dpfYec6MI7Zs
         fJlPC3HPMlk/8fig8EAlMSaNzobWFuK5RnAyfpdOsHV+/zZI8Rw9Isph9XCN0ep/DrkT
         cVTEcUTsXHM1F+EtzwuRpEBtpo+6HrSBuCJStz3xEEZ3JfUn+d7GkmLH3xugQlD+TGVq
         BwA1hm4ZM8qCd0BaTe1/GV0Dbo51e/NcDtJ8CG7hgjrSQelMcLHMvG1JxYPn9rxUuOZE
         Kojw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FbLP9Zbn;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id w11si90569ooc.0.2020.05.05.22.27.02
        for <kasan-dev@googlegroups.com>;
        Tue, 05 May 2020 22:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a5bb50585ca341fa900c46b565d606fa-20200506
X-UUID: a5bb50585ca341fa900c46b565d606fa-20200506
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 810855708; Wed, 06 May 2020 13:26:57 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 13:26:55 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 13:26:55 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 3/3] kasan: add KASAN_RCU_STACK_RECORD documentation
Date: Wed, 6 May 2020 13:26:55 +0800
Message-ID: <20200506052655.14639-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=FbLP9Zbn;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

This adds the documentation for the KASAN_RCU_STACK_RECORD config option.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
 1 file changed, 21 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..368ff0dad0d7 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,24 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_KASAN_RCU_STACK_RECORD
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+With CONFIG_KASAN_RCU_STACK_RECORD, when call_rcu() is called, it will
+store the call_rcu() call stack into slub alloc meta-data. The goal
+is to print call_rcu() information in KASAN report. It is helpful for
+use-after-free or double free memory issue.
+
+Record first and last call_rcu() call stack and print two call_rcu()
+call stack in KASAN report.
+
+This option doesn't increase the cost of memory consumption, we add two
+call_rcu() call stack into struct kasan_alloc_meta and size is 8 bytes.
+Remove the free track from struct kasan_alloc_meta and size is 8 bytes.
+So we don't enlarge the slub meta-data size.
+
+This option is only suitable for generic KASAN. Because the free track
+is stored in freed object. so free track is valid information only when
+it exists in the quarantine. If the slub object is in-use state, then
+KASAN report doesn't print call_rcu() free track information.
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052655.14639-1-walter-zh.wu%40mediatek.com.
