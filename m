Return-Path: <kasan-dev+bncBCRKFI7J2AJRBI4VTCEQMGQEO55TMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 24E863F718C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:17:25 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id g73-20020a379d4c000000b003d3ed03ca28sf16275151qke.23
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883044; cv=pass;
        d=google.com; s=arc-20160816;
        b=rq1nEEFtfpnuXO2LPcHibZnm9ZCC0KnQ/VzB/99tkjh4jvzcwZDTCar6Bk78lyIzdi
         U2/45mdfYsN3RU4hUeacsAQMoXez24fcacgKnyKZajgQj5LyRP5bZARt5/cwZZZbZwcj
         HKem6neavqczeFNg9hqu5pLTGr3LB4h7iWtAEcN4nUl8M/SbBKhfq301uY8zP9gFb/i7
         L+RE0S6ZnwKUEacT6hiY2/trwU6P91B+1nI4fGDKb1+z2rAUv9Wii+QDlaiog/9k6p6d
         5Cwxf5WwyMNwHlcF3y91PlAVpL47jMaqSFbCKvySQQ94NbEUzAd2HkvxSOQdSDQjKGZ7
         xQVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=y+SgLBqguq7kBaTtsKkAYS/iIeYmwft3uDI0CRPGs9I=;
        b=CyDCM5sgZRqg89lk8lxFEViS8zGvH2Ipe8p1lreFoZouTwW0I3k75WnWoAzxKnAwtk
         Kc7TKxp0adSxBP+KdLqk6ndAezOkhPgnfJANd889YUcTHfvfjafL/RX3yM3W1FhVmsUM
         DjzOc70taPCBOmMDRZryQt1/JZ1dkc7wfI4wWm8TdJZLr9hh04wwyt8SPrXMOKgdYFjf
         gdA8eCPj2UonlAsMFK5GjolPb20F65Yx9mN0YfHFp+9HX+ryI5o0A6gkQiUZV9XPGfYK
         RfiWH6euzfRTuyfo/7YH5YSLZFj+aycKj3+Cf5t/HUijca8Y0DxDI+qp9NOjW48AiRHg
         apaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y+SgLBqguq7kBaTtsKkAYS/iIeYmwft3uDI0CRPGs9I=;
        b=E50rzWwmfbE/YLIQUzK2rRSXoAkIaYR/N2j/2mserEvwZH4mSco2g54IbtkN9zAxog
         ow0cYxsa37wKD8KhNuerfASGr4XoWBjfc7cDvX9BvTGx+5Wii5fGlQHpO4jlR1dyN87B
         nfaYGd8nsJ5uFv+kUQtw30mIgHpk8U+L8PkdOwoEvYqKM1YokUVT/RTTk7ladLkzdRF9
         XQuxXDff2ExC2jZ30SA0IGXjqNg1i4y3Zw/FMUqOwbO4fOPx+NS/KoezO+Ig/GUr+d/T
         s+BUSNFBMJQG55PNK8VPFu7XRJHIIII0juufq3UkRAPGHs7afQBDaU49mekGcKQiblNb
         tnWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y+SgLBqguq7kBaTtsKkAYS/iIeYmwft3uDI0CRPGs9I=;
        b=EuR0iI/QEyTsuekzDJdIQaaiqDAWpTVi5TJIXPNgpqjBnW79WJw6yRyQXkaTgRJyya
         oAehk9gl1wOvtPIMZIVZX1zd+mF8LxfOXAo+Pu26MhEyoj6VSfhmYe0SjM1gFrpirxKX
         aZsS1tsMBt/Y2+TLmpAP/j9Us3xYYLkLGgL4kd9VZXS//kC5daYvbd3Euq88AhCuKIxu
         0jOmdUf7U49l6dbZHxsNfkjDL6ZDOtJMkc0mIwftZXrc+1I3f/8NLnSBdPyL83eQce+N
         D4FFugOIoJeT9rLAa6i1YXp1KS9+E9orng1+E3PunMxRn0eHg860A/EJca3/692xcfNx
         416g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wqDBb+uOuo4Qv8QZ9pc+c5I5bL0kR/GvTlR7y6ht7QnSXdMvV
	3JKRD0NbAYk4q2NeHQsaLhE=
X-Google-Smtp-Source: ABdhPJxPLa+dMaMSK9TJLa8rQfOZKhMcai0TGSCDRSgLl6JwJj4su8BgtijwHu9bIuggi1U+sxsNDw==
X-Received: by 2002:ac8:5442:: with SMTP id d2mr26255296qtq.176.1629883044070;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2699:: with SMTP id c25ls843618qkp.0.gmail; Wed, 25
 Aug 2021 02:17:23 -0700 (PDT)
X-Received: by 2002:a05:620a:13cc:: with SMTP id g12mr29898125qkl.277.1629883043601;
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883043; cv=none;
        d=google.com; s=arc-20160816;
        b=VOPn3E/Joj2faXabmWKvHAYiKTjjQ1Cm4qe1XvSJ7meDngHk6DpX6WRlH8Sq1YxUqg
         FquK/L8AA9sfVFXPnJ3KU52ZmP0jRtjRSiAe5hIs1aJMrgLn4rJLEx7F0DqQcCY38DFX
         tB+iw8pb6KfHYfdJlMcylAhJBZJer4nPQIuKSlzaMJxO6RE/cQbHdE/w8RxkurhS7jhM
         aaIMTKupnWJHnm5zgrDq3DxgILTOsZ4wmwzddN11F8e+P/SkFJocTqlUlnJKBCyZ+6qR
         ID7W2EcfNs72rvQ3/StyQgnmWHdtiIktluNPi1Defes1zptVRIVSYq9IW8/bV9kJiaOO
         xaWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=clP+mUPYTuOlo56YQ0SYnLs1R6FBZ6qtuz6ZMArme7g=;
        b=f64INpPDqPhoQitzGuAXOyiTGHngfqUAl+tYC9thtQh0+OS8OSMYQAMiakk/8Luodc
         D+yFb/UGAhn1OudA1ndWdjdUeev3+uV5xqedjIicvy+8geLO+/ZcHTAj04sTmsZHZIVY
         tkEQCiVDk7QMMx8RlewfhzJGF7JcDfk/8hD83LCK8ARqGQvMS5NrTgFMOEfs7mJ6hwZO
         vhLoLGM4gaUieHv+/SWqSvj7+c94eu8m/vygnMT8KaK1QJgWLUVvLE9c+EALwGZoxWtt
         ujmALuYAHREBq+Bswb4Xi93qOL20EQl8q1SsUD+9N+v7ISd9rTNIHCH2uGnJrBa3PFWK
         tPRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id g18si668321qto.2.2021.08.25.02.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GvgMz2S67zYrNx;
	Wed, 25 Aug 2021 17:16:47 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:20 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:20 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH 0/4] ARM: Support KFENCE feature
Date: Wed, 25 Aug 2021 17:21:12 +0800
Message-ID: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

The patch 1~3 is to support KFENCE feature on ARM. 

NOTE: 
The context of patch2/3 changes in arch/arm/mm/fault.c is based on link[1],
which make some refactor and cleanup about page fault.

kfence_test is not useful when kfence is not enabled, skip kfence test
when kfence not enabled in patch4.

I tested the kfence_test on ARM QEMU with or without ARM_LPAE and all passed.

[1] https://lore.kernel.org/linux-arm-kernel/20210610123556.171328-1-wangkefeng.wang@huawei.com/

Kefeng Wang (4):
  ARM: mm: Provide set_memory_valid()
  ARM: mm: Provide is_write_fault()
  ARM: Support KFENCE for ARM
  mm: kfence: Only load kfence_test when kfence is enabled

 arch/arm/Kconfig                  |  1 +
 arch/arm/include/asm/kfence.h     | 52 +++++++++++++++++++++++++++++++
 arch/arm/include/asm/set_memory.h |  5 +++
 arch/arm/mm/fault.c               | 16 ++++++++--
 arch/arm/mm/pageattr.c            | 41 ++++++++++++++++++------
 include/linux/kfence.h            |  2 ++
 mm/kfence/core.c                  |  8 +++++
 mm/kfence/kfence_test.c           |  2 ++
 8 files changed, 114 insertions(+), 13 deletions(-)
 create mode 100644 arch/arm/include/asm/kfence.h

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-1-wangkefeng.wang%40huawei.com.
