Return-Path: <kasan-dev+bncBDY7XDHKR4OBB66VXSDAMGQERO4DKOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32BDF3ADE31
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:48:13 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id t6-20020ac80dc60000b029024e988e8277sf12248399qti.23
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:48:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624189692; cv=pass;
        d=google.com; s=arc-20160816;
        b=oUjeG8GDuW0ain7Gsx6UbUKOlpaw4pWUdHfiLYBaCf0eWHT5Y2jQmrz7cuCG4x+f+6
         wqYviYnCLeKqs45hD+BxNLekjy95NTfLWH73MU+QGiAg/md3t+UJ4IlT5HrEl/hA8kAF
         BPIJVYCjuqa8qs7GYqkvpepGTLUXvC8ahx0BeAKi3B22uvrheYAiFXBQgMF+tI2jqT9c
         H1stFSL0Mqp4e6IUbRbINVwszgUUC+ICxw+JluwpQ7qj60MQ6A8NaaRfjPzhh3fueOys
         1sTOuzd6uG3RYYpJBirD0e8+/lWPiS40opruvMgxgwbWsdONeHIPZ+5E5jK7CYhCnP9y
         s0vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hDdsafoZp+yrW0Cb1qfq4xuwJkOD7MVD0WkXHFjR700=;
        b=c/KMney8gdcajgNXHJfnEqr6MX/niVa6Mvt20HoKFN6mhY7yQDFWuAHSbBGJACBwiJ
         QyVgQ3dCCNLkfGstwLTAJqT6RwyXaQ8vWsN8T1UgIpaGQddXjLtV/w0yflorXBvFJ/Pu
         o4vJzrfAljxIfBxPLMbwt25hgKhA2J1Pb66bhEa4swegqBsFFNPjDkGo3U2pLz20prd+
         ec7n4pOwemuurTCVt4SdloUIZYnVyWXzYK2R6AqsZdFakPSGVjrnXnYqB3R5tgKcCNJJ
         aQmMaB7S7NXOGVufNNonfLmJ4i48l/BggB7azAjPoarvWkuJaUo/SL9zW6Oj4GQ91TuD
         NUVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hDdsafoZp+yrW0Cb1qfq4xuwJkOD7MVD0WkXHFjR700=;
        b=Zq2Idm61IWCaAorvk7YSwpBorhl1vmfHhQ/PkEObK11n9qZhh64b3NOJ5uiIMe6/EV
         sUh0k4RLpbNv/9NY25SGodpvjZw/Tbsf8Kfmn9PNilEq7nM4jBCu9EzrXEH0gGE/1tAv
         nojTYFjVVkw8NuSNniMbBMqiZ8OYLzOjMoXzG+2/DVf0pR6kybQScuNGh9Hf3y4y/2kJ
         DSEzzhTwtzeZStYUl5jxLfqwOsS+n9nlGceroThihvg6r7YT11pmR1Pu4rin7ztDwtU1
         LlgRLUpIy7TU1PnRaiCfVtyrT4jbgfm4NPFK7x1Pj+Gn0Scub+I4zUZAG9zwagF9zhGM
         XIew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hDdsafoZp+yrW0Cb1qfq4xuwJkOD7MVD0WkXHFjR700=;
        b=syu/Yb3wHzr08DS3ObmP1uWPB473su3GIj33AClOG3rLBxAOys+RPYApI5g/z6HVUZ
         GMs/+bTpTitsddLJNA74HFwCnpLngkdOUSZSvlPL89VCrwCgNYQQ7ok8zyDd+7eLf++j
         RKzLvDMeCSTjVOlXRRNnpn0aOGWPQhYwOd46juDT4UdLCp/+UcGO3IhWtF0sri68pVj5
         yZfGbOXyl/T/P8JH6wpX9mSz91iiTLGOXns+z9dygCP/i5siNxkT7Puq3azoX3/mbdnR
         cMKLNp2DA+zlOGjfFGUNqP9+m3xsulQOdvF+dtNEtUvpELijg5NIgk23stt7ZbHdvzq9
         Y1Rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RxATjRYnYSawTbWo5IZ2W/Qk9rdeLwOUM382LnKSs4bz3573f
	PtbrHL94AgRaKDsllwBh+4c=
X-Google-Smtp-Source: ABdhPJzQnDOEAuOwZL5I6vNTgSkFAajRmPanSF5ji468UEyz7e+GuGl8UqnAWrzs+qoIGJb/Zzo7Eg==
X-Received: by 2002:a25:bec2:: with SMTP id k2mr26769426ybm.234.1624189692063;
        Sun, 20 Jun 2021 04:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9307:: with SMTP id f7ls7588386ybo.10.gmail; Sun, 20 Jun
 2021 04:48:11 -0700 (PDT)
X-Received: by 2002:a25:8889:: with SMTP id d9mr26682577ybl.355.1624189691611;
        Sun, 20 Jun 2021 04:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624189691; cv=none;
        d=google.com; s=arc-20160816;
        b=DQGD5jIKw20wBH9j5QPVDd/TEUObKqcm3QyWYvb1AqpJUeLeAx1KsGISnrPwdwlLIF
         CstoZ88cKcK6RNDyiKTKekaKz0GPpwAflPTF9/sjZvmCqMpUNrf3gvX66XMM29EOjP9Z
         pF7f6zuyPBLVmDVI0mcKCkEnzUA0ZEkw/DQlWnvwS1pZv94I/8BKjwMxqKum3XWw6abN
         qH7GEVbDzcLQKL6XlFZ+X/16TtDEBU//6d9X6ls10OAJBNroUEKYLRgCEVhBzlUbBDmr
         HGSUpWyYnU38gMDTt6b+LT2iR72UyDQYQe1PCsuSa625CovO/TA2FBg/hiksknU8yL6R
         GpDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=OwPIkLrPBXy8FI39vVYI/5/35uoW4ETEoruxC4AMFTo=;
        b=AWFmh8K83XxLSjFjG2fmF+1diGwP5D5HoN3JGH50A2cCgBahIVp4kIXChOV4KQ8YfB
         WcOTXsI8+wENHvsVFFwCVVVvJBMP3tHUckOMPtzLE6B3vpN1KAguNfWl7H/RIdS9t+kH
         5H5YpvoW3MViWisWVHqJ6jTstB4+Q9+k5kzA1xOEML9ziIyGtZCUVpKraIHuIb/7MaVC
         iYhtYzJIZZuN27XQT64Rw1Rk0vt/b7wu7x8RaSoqu97vDECwL7ivEg6ijjNSVHEcYgRQ
         bSACtGEpEPVX5tejEG3KLAjLZvgJgR4f5ze6rS0FvkrTlk2h/0iUCcqryz1uLDb/Xept
         jxpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id o78si536043yba.2.2021.06.20.04.48.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ea194ffd70634a5f858ebec10db9e1cf-20210620
X-UUID: ea194ffd70634a5f858ebec10db9e1cf-20210620
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1529141064; Sun, 20 Jun 2021 19:48:06 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sun, 20 Jun 2021 19:48:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 20 Jun 2021 19:48:05 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 0/3] kasan: add memory corruption identification support for hw tag-based kasan
Date: Sun, 20 Jun 2021 19:47:53 +0800
Message-ID: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
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

Add memory corruption identification for hardware tag-based KASAN mode.

Changes since v3:
 - Preserve Copyright from hw_tags.c/sw_tags.c and
   report_sw_tags.c/report_hw_tags.c
 - Make non-trivial change in kasan sw tag-based mode

Changes since v2:
 - Thanks for Marco's Suggestion
 - Rename the CONFIG_KASAN_SW_TAGS_IDENTIFY
 - Integrate tag-based kasan common part
 - Rebase to latest linux-next

Kuan-Ying Lee (3):
  kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to
    CONFIG_KASAN_TAGS_IDENTIFY
  kasan: integrate the common part of two KASAN tag-based modes
  kasan: add memory corruption identification support for hardware
    tag-based mode

 lib/Kconfig.kasan         |  4 +--
 mm/kasan/Makefile         |  4 +--
 mm/kasan/hw_tags.c        | 22 ---------------
 mm/kasan/kasan.h          |  4 +--
 mm/kasan/report_hw_tags.c |  6 +---
 mm/kasan/report_sw_tags.c | 46 +-----------------------------
 mm/kasan/report_tags.h    | 55 ++++++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 59 +++++++++++++++++++++++++++++++++++++++
 9 files changed, 122 insertions(+), 119 deletions(-)
 create mode 100644 mm/kasan/report_tags.h
 create mode 100644 mm/kasan/tags.c

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210620114756.31304-1-Kuan-Ying.Lee%40mediatek.com.
