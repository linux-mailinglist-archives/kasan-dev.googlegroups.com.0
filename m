Return-Path: <kasan-dev+bncBAABB6FBXCHQMGQEJ74V3ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 32726497770
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:37:46 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id c22-20020a056602335600b006101beff8bcsf2303998ioz.23
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jan 2022 18:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642991864; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQr0WSi2v8SIzCHFevk+36ylTTICxuV0M2TSXBWA/UaZipO3HyTBrK68JLEBYKHl86
         RRjdJtgAxn7FpcYmmW/C901MrQV16cmxPEXCdspb7tbxWL7WF+yKNsGelRaZKIOa7RFS
         alR2fSVtSZ/MQKDEcvIAS99MZJXngn1P3I2inrQejk+RX/vzK1iaEMU8LsG5XEuEtNxm
         8AK6X12liDz1jxPh5xzFCla9SdNrd/IzHgLeWzdU+S/DGHQ9+tx4yZuGC42huqszNOXf
         ajjr/PsAZStgwEif7gy4tXF1ezQtz8n75s62ewDWBKqjb0PZ0y4D0w8ZrBOe5RG/6Qpd
         W0hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=uPOBZIxAlD7PxJLnvPJSKgqtUv03I9zaY8/HMxCmv/I=;
        b=pYotznnGv3PGXw08BI3dOnvPdGmPqrT5MRLR8r+RBYLaHE7lYoqq1K2aFQc9RrNTRk
         qoLzgxr2HjClKJHbXZqQY9IOZylMvd9II/9+ufS5RNyokrqcrSbnsmT1gyFgVq6hJJ9B
         nXJ6p9w4RpNBK4UEc5m9TmZO+pGl5nYBYkZxAAZ1QXGcnJN/MdNc3a0Dx4y9go0+3Mx8
         spCGw2iTil2j/3t62L0qzDNlGNI+YjCWdOQfyuyrvkhMUpfuFKs3f0m/MmtvdrGmhBkO
         3uHTqNziJzHws2FKq3MYNn5wNIcUyfKGSarEnnbRmlc/IrF9r2m/69CuLPSklyJahKC2
         kicA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uPOBZIxAlD7PxJLnvPJSKgqtUv03I9zaY8/HMxCmv/I=;
        b=gA/zKh6m9sM0Rukmoh1G/Qeq1BifHDrUBdd7CD2XO9DDcMykhvxiljPEj52kke5EZ8
         m5SNb1CcUrPOYSNu09PMDHoNlqn2YCmS/OlMhkdHhLYGzgb0Oee+Ei+2ntTUV5WZLPv0
         FOSks19Yw0jTxufK588G48LKAgkKPfHi1lITSdGNpE5GWYjWdw6BJtarpQhCiNInR2Tp
         Lul76+/YyrW4HxolrortjOexahVV4uwF6nGmgnSR+BF9TcqqN1HCgfoPMM+7JaB8Bgcn
         FOUfhNtp9sk79jEj+A5jSkz1opTlzSoCsMCc6LQRAHwCROKgnekFb+iCelSTEeg61mHR
         0HRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uPOBZIxAlD7PxJLnvPJSKgqtUv03I9zaY8/HMxCmv/I=;
        b=HmgAu03vGuZRgNuLDRWuOxVjGID2bOgpoe7jqSw75u0v//IgedycJdtdUhNEhIDAQR
         chdmxNENVp1BvpYL+pH0ECAI7LMMqNLM1IKjpyZQ7fHxHWD0IW0+LQJ314XfyGGUaWIa
         5L4F+T1tY4EOl4ZFWRTuGVNXpZVpbxZvx5yHhqE/BnYAV5FS48yRqNSyUBFv2EMzeTqU
         p7ZTEodcwu9XF0qAI00GyLbz9PRXquLqXHP6AY207qmKjjd82lId55yVkSq/w1AJyEro
         99ZUiYm5085OPOAzPXuinec7vU25Ky1eO18rclvzRNiC11Miei95qTi/FEij9LB6hbds
         BHrA==
X-Gm-Message-State: AOAM533QYJKq8SyicE3CEkjnkcCtWiu8LmCe1+A0pgaiNBG1/7S8vFX3
	MLHEWkSXNK4XCix80PE5u3Q=
X-Google-Smtp-Source: ABdhPJyNM6RIWJNgYGIWEEu77cZm0q2VPJ3Nyocg1YeUAjnM+FkLwlfgv8PQNMIVzKmvFUz6jKzn/g==
X-Received: by 2002:a05:6638:372a:: with SMTP id k42mr5806342jav.51.1642991864608;
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2165:: with SMTP id s5ls2515692ilv.3.gmail; Sun, 23
 Jan 2022 18:37:44 -0800 (PST)
X-Received: by 2002:a05:6e02:20cd:: with SMTP id 13mr7454598ilq.108.1642991864282;
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642991864; cv=none;
        d=google.com; s=arc-20160816;
        b=Phhtfo8RnEVY66WdanAXDt5GlGdxO9B+INyaS1ZzPa11kA+3e0/O8yT4Z2RoEH4bVY
         ZAGGEifUx96S4xwbXYH9uyqo3ygnK16dPf5BHkYvW41rWtfcZtWjPXpus4F0h3sr+XWN
         mS4S3qR4Bx9MQFcGpmuzaFONm6Mgk120z4OEZHVWgtwbdRQlKNaOD0zg6CsoFUsugPLP
         /7t3JCzXBjHq3Su2k2WlNiwg+V3YQDCtDX15v7lc3ezr1UnSihmkrF0Ap2vlbwGdYrPz
         GFsAmzRW5JYqSuRuUSl46hi1bkEvEHG5D/xGy8gFyjZnqeZuIdcx94SBMMFgBQubnzvT
         /xzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=6ndR8G1ZRhRAXwH1ytG+zBHjd9c1Ghfm8QLuq/V5Ng4=;
        b=l9odCKIt1xUv8DV5xsfo7RUYa+XqQwq9/fpVBm92mumJ/NWE/X1788/pqfZBac7mLc
         kBt3sy1vY7OUrVCsLoFwU5gHIzO3/kyI1cvgKtAxFTl3YPBxi21+0uXohTGKzqZmDK4O
         Pq3A5BRMT1FRNEcRMFLNwsx0RgdXQ/O0jJWVOJb2TBZkmAPl6M+EFjSCzHYf0B81v85v
         /cg73HhQdVTOwM23UpZVs33VR7k8XVUsJayHmOifzDc1nLacLUe1nQsCh3yjYN6XAva6
         Hmmu+VyWaOyWSAL3G3IUJqywpKXef7Zr1F/r+JcXM8whqpJ+QvSSKK3TCk72KfkLOhx+
         pO6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id n9si868322ilk.1.2022.01.23.18.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jan 2022 18:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi500016.china.huawei.com (unknown [172.30.72.53])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4JhvDt076lz1FCm2;
	Mon, 24 Jan 2022 10:33:49 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500016.china.huawei.com (7.221.188.220) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:41 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:40 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH RFC 0/3] Add a module parameter to adjust kfence objects
Date: Mon, 24 Jan 2022 02:52:02 +0000
Message-ID: <20220124025205.329752-1-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
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

This series make KFENCE to be more convenient to adjust parameters in
not only debug process but also production situations. In different
production and development stage, the demands of memory and CPU
limitations for KFENCE is quite different. In order to satisfy these
demands with a uniform kernel release, dynamically adjust KFENCE
parameters is needed.

Signed-off-by: Peng Liu <liupeng256@huawei.com>

Peng Liu (3):
  kfence: Add a module parameter to adjust kfence objects
  kfence: Optimize branches prediction when sample interval is zero
  kfence: Make test case compatible with run time set sample interval

 Documentation/dev-tools/kfence.rst |  14 ++--
 include/linux/kfence.h             |  10 ++-
 mm/kfence/core.c                   | 113 ++++++++++++++++++++++++-----
 mm/kfence/kfence.h                 |   2 +-
 mm/kfence/kfence_test.c            |  10 +--
 5 files changed, 116 insertions(+), 33 deletions(-)

-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220124025205.329752-1-liupeng256%40huawei.com.
