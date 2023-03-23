Return-Path: <kasan-dev+bncBDKPDS4R5ECRBAP552QAMGQEAZ6N3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4352B6C5CCE
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 03:50:43 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id i7-20020a056e021b0700b0031dc4cdc47csf11348498ilv.23
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Mar 2023 19:50:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679539842; cv=pass;
        d=google.com; s=arc-20160816;
        b=iprVT0qGaQswDe2yJWTxAFDG8C9g2FVIek7ea30XWnmzRhvDix2xE9ifdVALyUBRKS
         hipKPC06I9hOEqM0iEouFvRgWelrZ9ffh02cZvRowgq7NVbDU9/3Hb/4UkWsv7g+n1xA
         0kAvuM7DCJm5xVqAe978M+K0CbwxyH44z9sJu6nmZHeIMvNk3VhpeO7Gds+vm+tSkFWd
         o0oYcTgGdIwr3NYknQbGeP10kZuoP5LFqFPkwoR2TLZVmFi+tEy8cJ4rtMPvd5Kqt8rv
         vqqs7Z7K95SkBxL6yiKcuFcX8UMU9B4xTKQ8FXNz7wxVJksIGp58xrB1V9CbP64B7i1Y
         IGqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=FzVbWOElI4ZklPtkjUkBUQunvx+5nf6VwLraQ49iLrI=;
        b=rK3Oir4KqTCV4ZvpyMfPwUgT0Z+OIly2xY5yDDsasKJ6QfMVKRC7pBAOzev+IEu4o5
         yK1eyDyyo9WeAGB0eXX/sz4FHLQFuFd3f8f2qq0xbeeEqD6AHhtgaKf2X7CFacybavuh
         +7nrMrDExZMN2Hvk99R+pAQltocA9rTDTavY4dV20e4ONEw9FUai6gSKzIcI9Het19/F
         NOpN+BxCPjpEXIn7OHOqMZTjszJkt+hctRjedBTwCzjgPJzHumvFMlY3svsQ6D7leCcy
         z8rBFJUbF9V7nv6LUORu5U5DaDALBTIUS6Aq/2FGSF3b22q9TOvvrRHMQDWzzxEJUY7+
         WIow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=K5LxBdjO;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679539842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FzVbWOElI4ZklPtkjUkBUQunvx+5nf6VwLraQ49iLrI=;
        b=oqYUUtURMYJSYfIAn4KUn9EJqcf6mSley356DmQiMAaHZxYlE+VFc71APSbrqpNj3d
         8ZmpUXv2cVTXdobbSZZzcDN/x8yANxNTjAfzD/rRhwrconz8d01zpDvgsTtU4HNyqUWN
         17N+/vVP+rvTqykyZuKDKfdD8kPHfznJSt2yf0xCI3FkWmFQXqwKAKY3ceZ82nIVVR88
         b6vQVc2OXOSH3bCdfAG34t20yTxW6VcKPMVV4+CJn5xKTPXx2hNth4zvjVgDswipQ7Rr
         Olq6MTLHwzCC0nkomJtMqpDiiNzOfdJ+yMeRTahZQl+p5l29/VLrLlaaVQYhGXl004vF
         9yZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679539842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FzVbWOElI4ZklPtkjUkBUQunvx+5nf6VwLraQ49iLrI=;
        b=SsUorMUwidhOhpbAjxq57tpLDchQJpIt+yCz4FKnfcUMvioqnGVsL8vUjdjYMUSCP/
         M4NfYOL/WJHZ0/u9B6tiXWtqx9l+JVwKtB91YQh2ymImSHgUKKxlmqWt4UesamEFxvJr
         rYPIJqFFH47yW7sP3gKtGFOXulVDTrrtSidtq7WC/wLpLpG0oLwpe+p30HWeJI4XxPxA
         kLZKvu3oSW6pEvScET82A+qy2xbRoPofD/dIU6XV4ylKJjPm1K4esI3xrDzkUfKrnG53
         pLOyTT8LC5c95nFjM07ynnTIt96b39VpwHY332kklZf1Y011sJqxyqSeB2c9qvyJmQH1
         lxyQ==
X-Gm-Message-State: AO0yUKU08ycKZsGxd+9+D+DsALep17bDEUWSDv3S0yIH5u6KxvOm7SNl
	UuyAerVZOSfjVwhGXdelRwQ=
X-Google-Smtp-Source: AK7set9DshLd3VkZ1+QK/+f4gksy+uVjpMSb3N+tcc5hylie3BPjqtVIAE4aTv2ArJLotPdQVHhfKw==
X-Received: by 2002:a05:6e02:11a3:b0:322:fdba:24c1 with SMTP id 3-20020a056e0211a300b00322fdba24c1mr3739761ilj.1.1679539841813;
        Wed, 22 Mar 2023 19:50:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:330e:0:b0:322:ecc7:b8 with SMTP id a14-20020a92330e000000b00322ecc700b8ls5198267ilf.11.-pod-prod-gmail;
 Wed, 22 Mar 2023 19:50:41 -0700 (PDT)
X-Received: by 2002:a92:ce8f:0:b0:325:c8ee:96e2 with SMTP id r15-20020a92ce8f000000b00325c8ee96e2mr1902049ilo.7.1679539841274;
        Wed, 22 Mar 2023 19:50:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679539841; cv=none;
        d=google.com; s=arc-20160816;
        b=v+W6trdIn2C7G9V+T0w9baeJouFQKOhW8QYvIk163do12dLXRi1VqhDrrm1d0RXeG0
         m+UI2bwWuWFjqK+sKB/MSAx0uFYu4uoCKfueH9M/IB1DBpI2fKi2DbplqZmcwnO9GYkl
         HR/4mJYHSShSu/PWGoRMeJW42wd50V7wg+9PrI7+Wji1Eg/vHnPuWtPKa9XvkWvqS/yg
         I+BlFBB7lVOKjkZZLGhd+68sxUtbXtJXJZJVoOFMLF60WWk3ikpqttTN4ymcf1WtMut6
         2qt4M6q81za9hT7fZfKIYjdFQNVQCl5nHsXl4nShe4mIJCPQOro2nJq59nVQm64WiegX
         Qo0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=sevPZAbnJXpK9Gw6YJPfGdmbozGF7BL49NEd8f9V3sk=;
        b=v6EQJ798y4zjlC6izfAe98kQ3MUGR8ul6QyINzxiCipupkqs4L6KVRsgvwRQ2xq9td
         u9Hn2N+eq3eI8h0H3z7kGmE5ymjU8ff1Fuad6Gd8FJwZGojEebvjDfHBmX0+6wvcNVhE
         5PRJKKBzS5ToUtJMWIaGRjt1d7XiS13zlamM59fbKIwo5A1+GpNz2I6/injWcNoQWM1G
         nS8DtomT1GyNPK/dcvzueTPYllwgBYmjXJermCys5RF+1YojE2eLM7+QNWvcQbd9eDp5
         2kf+gYgrjxSeVgijiTI0ZBHM2UFizpszcacCOM1DtAFVC25nUSTQr5icZnnvWzWS23bn
         1Spg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=K5LxBdjO;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id p15-20020a92740f000000b0031864fa3abesi793694ilc.1.2023.03.22.19.50.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Mar 2023 19:50:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id qe8-20020a17090b4f8800b0023f07253a2cso596315pjb.3
        for <kasan-dev@googlegroups.com>; Wed, 22 Mar 2023 19:50:41 -0700 (PDT)
X-Received: by 2002:a17:90b:17cb:b0:23f:5fe7:25a1 with SMTP id me11-20020a17090b17cb00b0023f5fe725a1mr6179466pjb.13.1679539840378;
        Wed, 22 Mar 2023 19:50:40 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([61.213.176.5])
        by smtp.gmail.com with ESMTPSA id h7-20020a17090a2ec700b0023b5528b8d4sm221002pjs.19.2023.03.22.19.50.35
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Wed, 22 Mar 2023 19:50:39 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH] mm: kfence: fix handling discontiguous page
Date: Thu, 23 Mar 2023 10:50:03 +0800
Message-Id: <20230323025003.94447-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=K5LxBdjO;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

The struct pages could be discontiguous when the kfence pool is allocated
via alloc_contig_pages() with CONFIG_SPARSEMEM and !CONFIG_SPARSEMEM_VMEMMAP.
So, the iteration should use nth_page().

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index d66092dd187c..1065e0568d05 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -556,7 +556,7 @@ static unsigned long kfence_init_pool(void)
 	 * enters __slab_free() slow-path.
 	 */
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(&pages[i]);
+		struct slab *slab = page_slab(nth_page(pages, i));
 
 		if (!i || (i % 2))
 			continue;
@@ -602,7 +602,7 @@ static unsigned long kfence_init_pool(void)
 
 reset_slab:
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(&pages[i]);
+		struct slab *slab = page_slab(nth_page(pages, i));
 
 		if (!i || (i % 2))
 			continue;
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230323025003.94447-1-songmuchun%40bytedance.com.
