Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW64QD6QKGQEI4PYQQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 234712A2F27
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:48 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id u13sf14471090ybk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333147; cv=pass;
        d=google.com; s=arc-20160816;
        b=R4+t0ZBlYBcKFBzIo/jsDwJ4gfZKXj4aDeoiWFI6DRp/uG/LfVc2PiWFYh/9rJ/tYj
         Ju/6lNqhcz3LaBlns6rifqWtI8+N5kKogeIm3tVCppciueiyRKbX5aBxYfvrc+9D69Df
         Z6/erRp50y46RMepmwCMfjGLMsg9/x/8Fj0wxY7zFdnP8gQrYPIj3/lqfYi/fnYTPiBy
         FFbVsO8mGY+K0HXR0xqehuWpjJK9Y6glro5/rNhSiZxPL3n7mD9fIQEjI/K4cqqiNDwX
         7JQDCcp+Dq/d3SA5X51uR+m8AVJHFWTychTorosVFH5wBFzRLrYZyiMBTlHOZDuXdB0a
         3cMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=j2PFurGlhTW7uZw9Mry3iRA0ncfk94qVv8pclA5HjWQ=;
        b=Wmqw2npoWFFUD9Th1CrD0Sc+jSj+wtPk8qmkP5tJZm7nzlv9/sj0zwtbcWQ544YUEd
         gJigleBeJIV/gDm6APC2qiYuU3z1dssEr7SMf6Aj1y5ncvZtn6r/eylLtNEYNdMr0oUy
         c4xa83uedQ+kmeJ55rEdfDQ1QMfnB8f74n0HlwjlX/XNJNLrgShRWC36tbmWZoImUQwo
         4IJhcVA+ZfoV8lk28cgFyHGHFGwnKGtkhU/dx2vkxb/ON24KimEzWEn/qG099MnjzuMC
         sVTq/aDXEbK2MrbFLT/so/Bkv0tImPVgIp0nr81Kt4TqeI9+qWVCn6SU8OHD+jWjKnqw
         QF4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B+b74HQO;
       spf=pass (google.com: domain of 3wi6gxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Wi6gXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j2PFurGlhTW7uZw9Mry3iRA0ncfk94qVv8pclA5HjWQ=;
        b=VIKpDiRpPL+FIln1zjD9gPlW7/gY89bhcJ/kUIYzmaADtIEyEvJF1l2GF1zGz5gtZX
         gX8KzLAkc8Qk5A/gTW06nLIEKGeCKRXFuACeTbcXgDhdkpWFgAS+sYWppvRe2PVLJcpf
         k/xEaoC14MsEv8FxCHDykc4++eQB0D1hZLYRHW723kUwpxIur2/D4vkIHuUMcVzHDBWJ
         RMU1VI4yYnd/tHY4eTR+sbT085LLMioFEaZeH97LeYnb2CKhaw/YCh3nQFiwizWW/UA/
         R2NDaZQr5FV/ZNUEudKLJjyDkvSpCbCdQ50WyyVX+GjzrrIs61p0rm1I/UWwN24pZWIM
         wJDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j2PFurGlhTW7uZw9Mry3iRA0ncfk94qVv8pclA5HjWQ=;
        b=paUdNNNS9RzbDCxvDbzk05dQZUq5aeekzNfVhLYE4ykXAAEEQTVCYa3NBwJaam6yS/
         jNRYpIxTR6+DpXbGLJDXCCqzTJWN5UE+6tIVRpiotB2V6qZ3JwFJuvWr0ZXPyrGCUSdC
         BOvhtFCOmf4t+M5edn1QneJd3YygPGEjf5squbIER+JYTxYgSejagVj/KSxKcgdt8wyJ
         abbCNT6kdcluP7UnrK8wqtIUGB5aojyGRLNnc05+f1fgInFLcmNBMW8CYyf7wnZkIW/D
         +HR0NmXuc2yh8f1HHxmt96KA+kq3KAVYIbJjtU3Myn+jkJXcNHkw/V2k7bp84y15BSwW
         ylbg==
X-Gm-Message-State: AOAM5310ZTSSuV8oJYx3y0oQeINBISlwGAz7pC4uHr76ipc/qB0Dk4ud
	rPVtcxNOM06QLKOkE9K8PMQ=
X-Google-Smtp-Source: ABdhPJyru28f29d0c1yxMHT6HogsdP/zSKFd0Ez4D18R7lHCx5drRzKX6W5baQ1beZux8igErfcGUw==
X-Received: by 2002:a05:6902:52b:: with SMTP id y11mr21299451ybs.508.1604333147171;
        Mon, 02 Nov 2020 08:05:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a268:: with SMTP id b95ls6857812ybi.10.gmail; Mon, 02
 Nov 2020 08:05:46 -0800 (PST)
X-Received: by 2002:a25:360b:: with SMTP id d11mr22338780yba.218.1604333146773;
        Mon, 02 Nov 2020 08:05:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333146; cv=none;
        d=google.com; s=arc-20160816;
        b=Ht4uoNhWFgu5m0nkX9lLdnL/W+UPjUrKQB6M/4eIxbdKDXPgRCXJ9kMrPpqUazzw1f
         4vOOwkGVzUpsvWGgC2nQGNQkiK/QwdbBaK1JR5h9pOUv2KNpRT29FdKwOD+e8jed2NFy
         o8mJbfM/JjSNURA7Vf+6H2fgGQ9GKbbB8qcfVhcDX6pNQkDZr5aB/ZWMdXYWY1pidBzw
         xNOXXnBaj8QAfCKMFMRyGx/1Z0w5Qqf7/REWo48u+/gEfTLt8kC3TZhgykOrSJBPkWKM
         eK23LHMcw9hzpuMcKCB/LH7jlBk1InPtVExE5QU2wUhTHfnUCfC6p2oDD2z9Oycn/ZHZ
         o8uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=E7M1YMbMIR4yMAYd8ymzpiiG9f9KaGeAaRDscMDAbI8=;
        b=BQNz/S3Ayt7FNm1Gwubl2I/1OMACv2sOUFj4v4rb3jYFQRnqkDXBZ1cg5nQGhdJjSx
         wQ6+DjMQEYHCjDplnK5iRUR1zoSMnNz91MtmFhjXNvXrzuSSCthr4swYpeJF1+9l0/jz
         QlgponkHHxYmdzUwNwlqOaZJEX8sUpaxDh0yzli5h8OV6WVL3TZwNXwV9GjprhbNL67h
         6IXX7j6La0XKyqi2WtKjkeQmcYEq/9C0voKDNOEZOOjLWVSnAHZcbUfn5BwFjP/tWlBz
         3ADugwtmZX5lgpYrwEgZjvS8YZF7Y7qdE7FI40FzU4aLwdrkhIwzGbUZiCFDLfYqEp1Y
         Rs3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B+b74HQO;
       spf=pass (google.com: domain of 3wi6gxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Wi6gXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id e184si719552ybe.0.2020.11.02.08.05.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wi6gxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v4so8476716qvr.19
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f70e:: with SMTP id
 w14mr23027576qvn.10.1604333146336; Mon, 02 Nov 2020 08:05:46 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:13 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <adfb51f61d93c78ca37d6238d4a435e755b30e43.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 33/41] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B+b74HQO;       spf=pass
 (google.com: domain of 3wi6gxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Wi6gXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e3cd6a3d2b23..618e69d12f61 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/adfb51f61d93c78ca37d6238d4a435e755b30e43.1604333009.git.andreyknvl%40google.com.
