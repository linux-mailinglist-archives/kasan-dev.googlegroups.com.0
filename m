Return-Path: <kasan-dev+bncBAABBZ4KQ6TAMGQEMLMHIVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C481764345
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jul 2023 03:16:24 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-63d0b65ae89sf3380686d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jul 2023 18:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690420583; cv=pass;
        d=google.com; s=arc-20160816;
        b=w6MKDCWCUGp2QC0gP9o3WpS1WI1jhWEkCtGM0zaM+r6B/39vU4XMGCt1jHE5BXp0tr
         YueFKjXkG79Gr/v6ZxRHwSZOboMxkIGHVaKmnkoc1FKOGiAjsdim2wdEEJwTYkhJue2A
         j90sYnFQrm6qqH4Yj8gUMksETy60Uyytm0XKqQMARM6oYGBhUGq9tsuIC7uwLekwOujo
         lnS5r+spS2ir9Apybf7V2jl1BVEAYP3cu4zlOkGaG6QSXcabmPOB1lRphl0zMEmyUGiF
         Bolb93BhP0LtHguI8p6b3TGr7j+71b14s1/+83isvnLnTxK3OFx7l1mgcvklCt9E5zrs
         pJbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=vlEQTCi+pggSbdVIKTiaWZSh4roJ0jvXutA8Un9Qv94=;
        fh=p+2efxOrsjtKfHqLXl2Yl/PWOJT0MqeZo5k3po+L8gM=;
        b=xXFBwfsp7vTx0t6mTJLBcRm3PacDhx73mWZ0xPx94nUA/x/JcCyGVzzJheJz2emhMP
         dWdUCPk4m7bsoyfs0cwRhbQ9dImcjN8I5IVI2IF+LeSfC9UMRC0ANDV9iFa7nzZ0ShLI
         4CcPi+4+CwtNfQ5/UKyMsECGqkvF316lQYbjJ2Mmw3JOG3Jan3vBsGPcTOP2QwTw+4+3
         hPV8xCutcvZgjnk+fHASds7k9SyoHOpu7TV6ki+CkhmA347NcDtIjyK/WXoV2MSPczPn
         th8vy+rEeBbWt4646iEqCbCFmvXHOjIkAn4/NSeq+IlXwHQbqbm4WXSMzzkpLGlF0DMJ
         2BOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690420583; x=1691025383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vlEQTCi+pggSbdVIKTiaWZSh4roJ0jvXutA8Un9Qv94=;
        b=QkyKm2nx9arhHPWk4S06FJ8YI/A9y2kBHa+zIZHLRGbkACcIWDVHX8HgYz17/Tq/XW
         s+89pcERYJ5qiX/d9nB8P1GSEYttWQitpKgfi0bI28kev+zYN44ym2GydtcrvC828MWu
         ru9prs0TiefzJFjLtYkqdbUcyZsiTVdJQedn7PNAUlLZJn6Kueu39ez6NePOkgbc76V3
         wx5E3v83ooBwDwQ1UC5sV8V/UWe2PWYVB9kd5VhH4CzBFtFr8GQqiIt09jGrVLHT3+Zu
         54hemCq/QNBIRPrj5rL7AWq/YNAhQgpeK1jFzi7VHbBzscBzQnuYM3YJKyFFkH2Yp5HT
         K7bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690420583; x=1691025383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vlEQTCi+pggSbdVIKTiaWZSh4roJ0jvXutA8Un9Qv94=;
        b=G3WvSiG/eShqskPV4aThY7/EWprYiMbwfH+0QA28yKF8ADkhTvvkKrS9GheZzBUk1W
         9uxSwBXoaDS8ArpgUxt6qUj2bDh3AXObkK5SE26ESSNG27CBOOtNuusuhpgq5lCeQ02U
         NdHr+/HLYg4GEinCOw4lmooUB7i8/iCvc/r+SVXKauDnKPqZtFFkb4qcOjCn1k0gquuS
         pRpapKlrBGpn0g73f+mmxoCkDru8DV29rpFQVnhVfi8InBQeFBvy1jXmimTUvcG6iJJl
         COGFU1C8aIfdnMyBcsdP9xoDmIirhHN3mAKHGHmo6p6srIYHOQNgImZqJm6yW1eAIpVQ
         SKOw==
X-Gm-Message-State: ABy/qLbkATCNgtaazp/yckl4cCn3DChXS17LBS2kHahpZ/v4rqKbxlRe
	LyJgDt6puWZtQQ5p7xBFwac=
X-Google-Smtp-Source: APBJJlG2jKYRn/FyURZ+mKk2GBiEUMGlATsQ9xxZ6/pBXLF7gVMc1Z5bc38MpEfSpcKVaJry3s7cjw==
X-Received: by 2002:a0c:ca8a:0:b0:635:ea31:521a with SMTP id a10-20020a0cca8a000000b00635ea31521amr1719853qvk.7.1690420583292;
        Wed, 26 Jul 2023 18:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:de10:0:b0:63d:184c:ad0f with SMTP id t16-20020a0cde10000000b0063d184cad0fls216949qvk.1.-pod-prod-00-us;
 Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
X-Received: by 2002:ad4:5ce2:0:b0:623:5c93:77eb with SMTP id iv2-20020ad45ce2000000b006235c9377ebmr1816098qvb.13.1690420582692;
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690420582; cv=none;
        d=google.com; s=arc-20160816;
        b=eWs/ybxsWerpSGcJohh7qXMMry9+lrAhPM8KvW7PVZp1n7NeXxT0yGajhTzg5Peg+E
         b1PZfYY1RkDdCATE56iZMEE0yt/sWPvgDUKJMIClcfyQFwyJtdQl/b0OWUQ3ALAv7oSi
         zHkULSn58kQO8xeU3cA0AZ+iHFCyQl26VcxNYezuZ6uEq/sPlBcM+sg1FUdCt7IMaHZS
         9LLMzImHL5V9vH/cgHX2y9jVeNctCg4p9c8NsowFGi3NT3tObTYqKKn7Ge5dXgN7h7WJ
         7XrZ5H9auFHnfcKAiHjWZ7nh3Jt7zOLerFPr1bTjLm5EWbJJgMo1goD7CLPxTcJZD4+P
         frwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=1lhmM7kpbx7lw98lDuPTbeB3T810RA3LO8pc9Vx4A2c=;
        fh=v9wYe9VT0TbAN61FdyevhEThUjofuva2Dd+9j50U/es=;
        b=mtO7YqCgJrL4EWRrxPtMucz6HHMesBAfe5HaReUAqVVGVMLKdISn88mSbKGs+d2QTm
         yfkDMO3dZFqflwCYZtICj+P6QJct5jDwxMwpdKs0Iu+J7mdUljGcFByI1XTvaEIpMuB3
         7PNDlsgm8AMEQ5t8ZWWaQ40nHhgvRXY7KznWbHxQI+0f2L7SDmJS7OmiF3zamk4IzPkT
         m/3ZuFuiAewpH+JddRCuVyPa0AcNi/PJ74+oP8AdgJO2WGGbD0aMNwLCg6YMuOHq8loN
         lzY8KNOCLiuJMzZ4Fx/+YNO1oYWjqFbKQ4CmWuZI0E2WFoamQsp6c1R6L6nkSicybY7S
         RdvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id og7-20020a056214428700b0063d2253bb8esi9897qvb.2.2023.07.26.18.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jul 2023 18:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemm600020.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4RBCSH3h7lztRk7;
	Thu, 27 Jul 2023 09:13:03 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Thu, 27 Jul 2023 09:16:17 +0800
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>, <akpm@linux-foundation.org>,
	<wangkefeng.wang@huawei.com>, <sunnanyong@huawei.com>, ZhangPeng
	<zhangpeng362@huawei.com>
Subject: [PATCH 0/3] minor cleanups for kmsan
Date: Thu, 27 Jul 2023 09:16:09 +0800
Message-ID: <20230727011612.2721843-1-zhangpeng362@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: zhangpeng362@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangpeng362@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=zhangpeng362@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Zhang <zhangpeng362@huawei.com>
Reply-To: Peng Zhang <zhangpeng362@huawei.com>
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

From: ZhangPeng <zhangpeng362@huawei.com>

Use helper function and macros to improve code readability. No
functional modification involved.

ZhangPeng (3):
  mm: kmsan: use helper function page_size()
  mm: kmsan: use helper macro offset_in_page()
  mm: kmsan: use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN

 mm/kmsan/hooks.c  | 4 ++--
 mm/kmsan/shadow.c | 8 ++++----
 2 files changed, 6 insertions(+), 6 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230727011612.2721843-1-zhangpeng362%40huawei.com.
