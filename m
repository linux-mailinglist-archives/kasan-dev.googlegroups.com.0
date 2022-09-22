Return-Path: <kasan-dev+bncBCKYTRUVTMKBBUX5WCMQMGQE3XCHN3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B4625E6037
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 12:54:11 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id k126-20020a253d84000000b0068bb342010dsf7975095yba.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 03:54:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663844050; cv=pass;
        d=google.com; s=arc-20160816;
        b=X+gnUf4xtSzs+guseK6Quba2xMPx8/+F5TXc+6Ntql/HBm6jRqyQd616Cx44imw/O6
         L9sOXHg8TXPiyIq/jrJKjWbVpUG8cegBRP2V4w2BEALKWtGDKxd6/GjIwe9b8WIQ+gBx
         jzEdDLCfyDTvuKgnr9oq5/SUcSdiWmG82PCNowLV1AXOKMwYbU58w+ZMGK/styIYJg5k
         /fhokvYejRW//9BvQgDh/0PnHfYHc9OpBaSpnND5JOk+9hWan/HNPhaGWVDjkXzRfbWg
         oG3nY7un411PE2xZiKF3IHzWkcuXg2dIlh25WEQcYvHFOFJ6RfB8MXPVIMaLBYXGWYrZ
         oMMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=5x+SEZnWSOAPbROpQeS4OnRGUyT3ZC3te8t7dNbkFAA=;
        b=H3qUswiOhtVM2J56q2cCwj0XnBrayXfuFPn8lJ0SINObR6IJoWj2ZSELD9SzijPUd3
         WflZ5C4wyggh9fJYA/AhX8FYSJGO2FvjOaV3JEMuGXFAdL5CHNdgcgxS+VsQql6HPgOz
         5peG8jsuGOKm8CPK6KLXOFvCZOe4NHyhkAQ+Ch/IhJ1A1LZVfyvUJUBjb2P3f2qRcXaR
         bvN1aPJnDZScArNRDeMDxd4hFfrhaqOg6IWH2xlYj3jf5ACXHTFlDtdNH6T9V7mMHaBF
         3r29cLC5Mn7d/51vgWJd6XgYrvQFYaKryk8Rj2sZvLcD8ynBHr1FXFptVvzWlGKbGXEB
         w/gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date;
        bh=5x+SEZnWSOAPbROpQeS4OnRGUyT3ZC3te8t7dNbkFAA=;
        b=CIEf5uKDp9qeiHI5I07iMvwqErl8aSyuPikeCFTZKQDjFEDdNeN7OfNt/TwbF0gYS4
         +GzbjniiNlV1XMCK6jQYSS2b+FieImrZcSOwAkPOH9t30uCKx9kwHJxlmN9pypyD5bHS
         Vvi24SY86VXs8CzDYclZW+qx2e4gE76Moc1NVgvEuh4lKRrps8+9PRW8cPRbQ/fECi8t
         94OSStJiGP6V5WQqxcfPWyQEMMRhgGTC5dWLOL92ptYppEMWzC1maoSfDrm8NC0i9TTj
         QMWpvM+S5FEp1MPBYReJjdmZaHqAVFNcLUJSTulm/LkQSSi2vxZDzIgulf8p9rN1eVJ2
         bf1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date;
        bh=5x+SEZnWSOAPbROpQeS4OnRGUyT3ZC3te8t7dNbkFAA=;
        b=REqcfaM5ITXSKRMLZlf1J1wRvA0ZpniOxqadInkg3DlBb9Yi0+YMrBNDKDU+i5HpJ8
         CMuMUBU16f7p22mnMLZzXN2kHBIjbjHZOr/1xnajHSy2fy0YjP32goy+fbASIklngGnh
         tkcTqk+kUAEBvHSIaj+2Vl/LWfT9ZJ3yWEiwdWHUNqAMzVSUceYYeHcX1SOGB+Ok7gE0
         UfDv1LO5jHOJHMrG8VGj8fMunogSMtPToiZzM7xqhazoWWyYp03ncMmVMKstVS1xiqR3
         rzlLZYLbVFfOswzKwz50FMvYfJCs4GQWOE4ZeUAwTskrVXPYh8yBRwVITuuFXkwXlFhZ
         1ytw==
X-Gm-Message-State: ACrzQf0MRNmxZQFLyLJxMTI2jIl0Jx8VNtKr2A7VFCD8/xqwN85vpuPv
	GceU5fH1mSGHA2HaQk5oOmo=
X-Google-Smtp-Source: AMsMyM6RouvTif/w/7MIBU8Lp8k6epUjlMReUfpf0MLW6XX6ft7TiRM2ngfN8N79uJ12+QOSmhy8xg==
X-Received: by 2002:a0d:eb07:0:b0:349:d2f4:2d06 with SMTP id u7-20020a0deb07000000b00349d2f42d06mr2448802ywe.99.1663844050354;
        Thu, 22 Sep 2022 03:54:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b108:0:b0:6b0:b7:747a with SMTP id g8-20020a25b108000000b006b000b7747als7453385ybj.2.-pod-prod-gmail;
 Thu, 22 Sep 2022 03:54:09 -0700 (PDT)
X-Received: by 2002:a25:ac91:0:b0:6a8:d8c9:2ef1 with SMTP id x17-20020a25ac91000000b006a8d8c92ef1mr2713923ybi.526.1663844049719;
        Thu, 22 Sep 2022 03:54:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663844049; cv=none;
        d=google.com; s=arc-20160816;
        b=K6HyMsBIT+RSauwbkQhDU1OCkDFrOFjgVh2g4hwYEaWRlQ6qbT/407YbSbBAW5YtFr
         0/8AbzeAqOUeEIVjY6tBCGo3VbLidViZJXd5NvWEYrIHNHrcQZTEmR+GXESlYF/Lm6EH
         u/Kd2KQ8laYkfk27OdV1gVJ0zT4376N28Ivtc96hdoP0Axu4Smu4+ww+SQO3geFKz1wM
         H1i9UMDjrNJeUoVr8ccEWeQkPfuCWjAJx7I+HEjZGIjhwK5W98iDiiUdZsJKmF2fcrCN
         o8tktzUGBPeOQOraoRF4Mun55ddZeWTvyc8qUM/WbATb0+uQFphvea+mNUN+19i9U/0Z
         gmqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=LE5NsBj2MwcRieVcM5Tnlsp98cGgeZZykMgLQCgjACo=;
        b=grc6sR9UJK032N8DTXykEvuYo3xk5ZNbkJ9ddhwpcCrTFzAaTiZ+H4kW/ZBFtwZPs9
         2vTUGhQmxkjjKLj5uaLsd8giL7iTy86uuI8OralYAZ/kaiAOFFrDfYqH1Ild5ymLpVaT
         ph8MsHc2geHAHmjQIc0aBB8UpN5GSMiYbpGDxarfOhkY5WyYRzxphVnPYXLjSX4nPrWg
         g3vEcmvONKLvp29V8dOoshP8CJWVdaDA1arO0euVf0i2JTiW65znN0XfukVwIwWeZvAN
         hr7UyCSQYQ4IkZsjxH65nnehPeZayatu2Y/5Q2sMsjodvfMjUvBmXeQPVbWp4V0wveyQ
         tQaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id bp1-20020a05690c068100b00330253b8e8asi546243ywb.0.2022.09.22.03.54.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Sep 2022 03:54:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4MYBtN48lnzHqKQ;
	Thu, 22 Sep 2022 18:51:56 +0800 (CST)
Received: from dggpemm500013.china.huawei.com (7.185.36.172) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 22 Sep 2022 18:54:06 +0800
Received: from ubuntu1804.huawei.com (10.67.175.36) by
 dggpemm500013.china.huawei.com (7.185.36.172) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 22 Sep 2022 18:54:06 +0800
From: "'Chen Zhongjin' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: <liu3101@purdue.edu>, <bigeasy@linutronix.de>, <nogikh@google.com>,
	<elver@google.com>, <akpm@linux-foundation.org>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <chenzhongjin@huawei.com>
Subject: [PATCH -next] kcov: Switch to use list_for_each_entry() helper
Date: Thu, 22 Sep 2022 18:50:25 +0800
Message-ID: <20220922105025.119941-1-chenzhongjin@huawei.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.175.36]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500013.china.huawei.com (7.185.36.172)
X-CFilter-Loop: Reflected
X-Original-Sender: chenzhongjin@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Chen Zhongjin <chenzhongjin@huawei.com>
Reply-To: Chen Zhongjin <chenzhongjin@huawei.com>
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

Use list_for_each_entry() helper instead of list_for_each() and
list_entry() to simplify code a bit.

Signed-off-by: Chen Zhongjin <chenzhongjin@huawei.com>
---
 kernel/kcov.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index e19c84b02452..466d7689de5b 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -133,10 +133,8 @@ static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
 static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
 {
 	struct kcov_remote_area *area;
-	struct list_head *pos;
 
-	list_for_each(pos, &kcov_remote_areas) {
-		area = list_entry(pos, struct kcov_remote_area, list);
+	list_for_each_entry(pos, &kcov_remote_areas, list) {
 		if (area->size == size) {
 			list_del(&area->list);
 			return area;
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220922105025.119941-1-chenzhongjin%40huawei.com.
