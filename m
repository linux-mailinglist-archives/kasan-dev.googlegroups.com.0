Return-Path: <kasan-dev+bncBAABB6VBXCHQMGQEU3FB2PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ABB9D497772
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:37:47 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id x11-20020aa7918b000000b004bd70cde509sf8380427pfa.9
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Jan 2022 18:37:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642991866; cv=pass;
        d=google.com; s=arc-20160816;
        b=OUr252vGjIxwSx5ygJKXmbDUE7ibe51MXzYvwq5gZN4QCmHr2zqsbyAN63nzIxgk62
         +ihKsMaLeYmkV8uCZD8M6C3j1InHU+gvi+UzjyIAB5oE2gmay1iclOnzzayyaJCJC2/8
         hDW21W8oeixowey6sbv8uUTy68fKXZ+PFVlL5NrBj0xL+830tqf2Ylcm8K8jirrPfe/o
         sBzuwtIckifTDuPK1FZu7gLB8SzS0PNuKOvbp/X0hJCYLxqF8K8tFed0+Hw+Gq1eAmlW
         jmBnurg5/sa8huMr62h8VdvnZfcNm/gnlNDrfFso49S02Bt+wAgXy6fTjswEmdKZn9rK
         OErw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YsNlnJjaMCZtvzn0YrMdVh6J0LUWaORPOGGMyZ6bex8=;
        b=aqnrf7zBs5Ap6ntX0BcmZDDQxIl71gL0FcJBtXdra9srHnr/VctpwB2p05zsYPXLam
         zk9L3Zco/5j+SKz5Iu0Mn+ReGAvI4DnXEjKUPufo/RO50gGNv/Iom4oHhUhaRJMudsrs
         Bxnw6VJPQfmBHN50VjNOtV0TUaJhwvqyOw1h8B7JUHXMlQRUDY4ceKfK7bs/cruxLcLf
         +dNssDo7qJnbz7I9SeckzQWHm1bT4l24ZoRQgs86Dvs0DL+6u2cTZpxi1AFJTvb1KL7T
         6PC9cDzj0umL/4Z9KvnVvLPosvYdtNGHWrAIob24rFN5eTmar6MugUdaUCHXHq1VQ786
         ghGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YsNlnJjaMCZtvzn0YrMdVh6J0LUWaORPOGGMyZ6bex8=;
        b=X3RawSMoYnzkue/eFGn74avUT2gRcvc9XvkjvNbidNqacsc0+bX35MYXY1h2qhiLTz
         O5p9CMg5EM6ucPWuOjLmvw4UISeihj6xBsaDHIcBwTdhDnqhaRRGyd4FIQLyHNr/FGz8
         saptQDTdzaI/o0m0jiJHL4Dy8NrsW3PvfJvO2NcrCUNXDcLqCvR08a1WpMQGeWgNmLpy
         9+qc9PERcFNxzSs1c3N9KSx6OY8GNaRE8WXzzwTRIZCtllMU76hiNwHILtA35d+tHqSK
         +OPyQ8agLgH5EblQAWxWO5b+OfpLbI5djCQcgzZxlI98nPnJhNiNcOHQg780DKAFQnT0
         QZnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YsNlnJjaMCZtvzn0YrMdVh6J0LUWaORPOGGMyZ6bex8=;
        b=g2ejNxHabxN3ppItLY2x7e72DdYNL7zYQ12UGl+jv1Ho1st7UU7h38D2AXldmaGQYp
         Kw2z/noZxU1vyQ764FPnd+vHkbUyaTpGA6GfPAaF8Vymd1bGWuib2wSbA5BLGMie12cJ
         rkF+sHOV2H3FCQuke1fATSXDo/CbCInckCYbgu0JwW6aJF3RXSdUsrlfHFiMyOUcxgZ4
         zjGJxRrJTyQfa3jNC34zbKsq/9PHRGmJM2kGQ6E/xjwlosEv1KhihdLqkyXQoCFRO7JV
         2MXT4J33fG5qv1Z357txGMCchS4+A8tMcpBhj+PL6BC6gmahIl6N8HC3Pn93L+RtP58r
         qcng==
X-Gm-Message-State: AOAM533QQPCbbSOC7ap95XyYkk1y4uhKvZYZ9XKryHDJ5Kx1NwpwabJz
	KuTKomYoii7nKlwjpta2yfU=
X-Google-Smtp-Source: ABdhPJwVqXdqXV53tZpb5C892iJy6s+yztKHouaqASG5d317P81izp4XqSa72Bsc4sN4Eo/sAcnWUw==
X-Received: by 2002:a17:902:9343:b0:148:a2e7:fb5f with SMTP id g3-20020a170902934300b00148a2e7fb5fmr13577048plp.160.1642991866321;
        Sun, 23 Jan 2022 18:37:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a94:: with SMTP id b20ls6081173pfl.9.gmail; Sun, 23
 Jan 2022 18:37:45 -0800 (PST)
X-Received: by 2002:a05:6a00:1a08:b0:4c1:9f31:6d18 with SMTP id g8-20020a056a001a0800b004c19f316d18mr12261789pfv.0.1642991865705;
        Sun, 23 Jan 2022 18:37:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642991865; cv=none;
        d=google.com; s=arc-20160816;
        b=KlW1N6ezibkY4rcG3io98yPVrAKQ+Q1ghAw9Ljq3gj8+mI2+mT9/044kJmCyQCN9v9
         QNnl0TF1HkGyHgmrkp2EvLTsNEYcxkF785vADegrgeUXz5zN5RWo3zS+FtNDZ3vaKChm
         R55LWgDOO8/79o/og8Qa3qPvUAtrz+edXpPrPzv5SPtzDfAnMhrbLP+wxlOtyDZQzJsn
         qZ5Gjl39W5oCf7qaxQjtZzG+VyxRJOG5xPEgkGQo2ibVHga/fEynC8xCC3A7EJuhEMxj
         +9t5xPxmYl+nSghY5DvReWgVIJYOdmQXFlRzvBofciCPBRVGv5IsCcnIWraPwTbtbg4L
         QdiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=3g+MPf0IwUa/f2agonMpS0G5IPjK9URyioB0BTuRp2k=;
        b=GoDcBckeclKiaY44G63gnT8i9A0+Jv69obrEi08QEO1AN5Fc0FRLiDjUW+3yraiJu9
         MRNIDnwHlyHDwh7KW30URGENotK8VUHk8y4GGL9/2MhNj1o0DT8/HVjRfLA7718B3f66
         mIMdI2/PP0NPQFEeQ+1j8nBF2Ehl5clpOcFmnZhJ8SEzhfPYQH6W4yhLW2W1pFueFxTk
         us9IV3gowq6ddyTJD6vFREOAVwY/4DyP/tsxkh6zlGgkfOY1xLOH4/ue9PkSkU/OI5Mx
         zQudfGn5k4ejcT9dfLhIjbBGySQWjxpq7u2AdjbtNg7VVBT907MVekTmnyFb9DrtiGMh
         RHeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id k13si587189plk.10.2022.01.23.18.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 23 Jan 2022 18:37:45 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from kwepemi500013.china.huawei.com (unknown [172.30.72.54])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4JhvG070gtz8wTb;
	Mon, 24 Jan 2022 10:34:48 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500013.china.huawei.com (7.221.188.120) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:43 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 10:37:42 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <glider@google.com>, <elver@google.com>, <dvyukov@google.com>,
	<corbet@lwn.net>, <sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <linaro-mm-sig@lists.linaro.org>,
	<linux-mm@kvack.org>, <liupeng256@huawei.com>
Subject: [PATCH RFC 2/3] kfence: Optimize branches prediction when sample interval is zero
Date: Mon, 24 Jan 2022 02:52:04 +0000
Message-ID: <20220124025205.329752-3-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
In-Reply-To: <20220124025205.329752-1-liupeng256@huawei.com>
References: <20220124025205.329752-1-liupeng256@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.189 as
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

In order to release a uniform kernel with KFENCE, it is good to
compile it with CONFIG_KFENCE_SAMPLE_INTERVAL = 0. For a group of
produtions who don't want to use KFENCE, they can use kernel just
as original vesion without KFENCE. For KFENCE users, they can open
it by setting the kernel boot parameter kfence.sample_interval.
Hence, set KFENCE sample interval default to zero is convenient.

The current KFENCE is supportted to adjust sample interval via the
kernel boot parameter. However, branches prediction in kfence_alloc
is not good for situation with CONFIG_KFENCE_SAMPLE_INTERVAL = 0
and boot parameter kfence.sample_interval != 0, which is because
the current kfence_alloc is likely to return NULL when
CONFIG_KFENCE_SAMPLE_INTERVAL = 0. To optimize branches prediction
in this situation, kfence_enabled will check firstly.

Signed-off-by: Peng Liu <liupeng256@huawei.com>
---
 include/linux/kfence.h | 5 ++++-
 mm/kfence/core.c       | 2 +-
 2 files changed, 5 insertions(+), 2 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index aec4f6b247b5..bf91b76b87ee 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -17,6 +17,7 @@
 #include <linux/atomic.h>
 #include <linux/static_key.h>
 
+extern bool kfence_enabled;
 extern unsigned long kfence_num_objects;
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
@@ -115,7 +116,9 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
-#if defined(CONFIG_KFENCE_STATIC_KEYS) || CONFIG_KFENCE_SAMPLE_INTERVAL == 0
+	if (!kfence_enabled)
+		return NULL;
+#if defined(CONFIG_KFENCE_STATIC_KEYS)
 	if (!static_branch_unlikely(&kfence_allocation_key))
 		return NULL;
 #else
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4655bcc0306e..2301923182b8 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -48,7 +48,7 @@
 
 /* === Data ================================================================= */
 
-static bool kfence_enabled __read_mostly;
+bool kfence_enabled __read_mostly;
 
 static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
 
-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220124025205.329752-3-liupeng256%40huawei.com.
