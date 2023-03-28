Return-Path: <kasan-dev+bncBDKPDS4R5ECRBTXURKQQMGQECFWQFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 98D276CBB97
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:39 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id a17-20020a921a11000000b00325f9878441sf4720488ila.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997518; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnGb7yriPsXDt6eGrI0Nsu8wzMjX8kvYY8wdQMSIq1qjBdnYe1ocBNRdrrVIB5CsNi
         QXhlZWcH5QTUn9YKOdQKV+2OR6Vv4oQOrJra1GW12x0BG2fowAJpT7cEis8VjQpSohdG
         QbDB14Xp83T7jtQjqVbwyzl8hSEAtrsDGN+a0DPfIbj864PN8gsg6AcCS6fIzsiZudg0
         W3NodHS80xfkhKcEv0Zg9LS8qRUoPVIXK0oKGJgHY9nzMQGjuLZlPQiIcWPpo1HygPeW
         2/5D984V1WHwiXVCLuLVckRrw2fFY/LMKTmxcJzDuOoE0JrefxiXOxy8QfrHi3fbX7P6
         Sftg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qVndg/eftF86BK/c0M6ntXjybZKrInaKs1n5CIFS94c=;
        b=09kNYhfUnSY2NVK4lG0rpReJvzSui/LcIz+PGUk8aRh/pDIaiYJqp3ttWmxSWdZg/J
         BnwGQvhjVjfZX0cB2vgapCMwWFM4unXA8kdWCwN3T90XJd+w+o/dWJ81HahUwpo+jdxN
         pVuZRqWzRErBoibqsQRSmkzB86XCKsPRby0wdJm34LEry5MPPdAm/mfCT27Zxzak/ELN
         /7vq8JIfKFFIk/m1B3UXd0e4T93Y8s22Ev/6ISMhf17rA4bY7OoeuOTT8TgAlmFyFDLB
         zWpSMj08qUVq5wqJcdbLTG1VOW38AyzyPQWGAj/bBX/O3veU6n6st0rJx0qopXFNNhzE
         kf2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=HhbQB+dg;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qVndg/eftF86BK/c0M6ntXjybZKrInaKs1n5CIFS94c=;
        b=THV0UODwcYmv656jDnGDn5vv2UjKv5BPRzlXc+KWF72dd5iiIe0kGMacdR66AbVCvv
         qRyQtiWGvwvp1i0DsgJk5zzkAryXOAdeHllwqeXN796s7oc29YmP7merafc4POc5ycYN
         cAIHpLkRf03cNwBiaYAwyZiVR1fXW3Yzdpo9Z+IE4hsdBR++9Himcu6RNjbaIDJ+lS1c
         8BVXQji3iDs9C1+WlAS1rZkscwPrmzVXB4hWICj/CWMgk2l5Cv1q4ugC/05MN2c6F45+
         JA8X9jzQ97mKl8RITRHrol3/Pq6vptyvs95aFXOYsI4EyFuO09peCQcJltfpJ4msZ+ki
         kXYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=qVndg/eftF86BK/c0M6ntXjybZKrInaKs1n5CIFS94c=;
        b=ND+jOqwTZ7ks5wm6b9VP9xcFoL7NuB9Wl9VYJlLCo+HhHK1fnHKOOIl41DIQCrwslh
         0Mv0aOVx0F6ME1aeo8RHjz3jWGyyLQ9dYLqvy4IemWLWZZVUZgRFytWMLzXZKtAPSgpE
         DwU9cELxOHst4V6XipxCmByO0RCPX2MebwpluzMLGruo+8CYW0cNLgPkoGowBCohBr7X
         pXcJL+Oia++x1o5I2kQ0tvYkTD42d+0suL/u2GCcQRaCyPRZxfg26SzoJbTcmQIVE4Mi
         Q/i0kEmxDMXvxCUKPry1Wj5mxhFjYpvpiWVNBIitrFksKqfHaogiIvWkjpi3AfwckGbI
         hXeg==
X-Gm-Message-State: AAQBX9cNA3rIF5VZ4tpRQGFyLInsf9eaqWujR1/4tKegqiNb22dejL3e
	jafANcoRNIPHJ2cOaM1Hhks=
X-Google-Smtp-Source: AKy350YZvAqj7DcuI7MQ94OmslhiPlkpr5jmevAFQAVZRLOGYV5ufMnpE5K3JjSv6hUsNZ/2ZFoJfA==
X-Received: by 2002:a92:c264:0:b0:323:17d:1e42 with SMTP id h4-20020a92c264000000b00323017d1e42mr7903057ild.5.1679997518540;
        Tue, 28 Mar 2023 02:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:15c2:b0:317:9a9f:53a5 with SMTP id
 q2-20020a056e0215c200b003179a9f53a5ls3292902ilu.8.-pod-prod-gmail; Tue, 28
 Mar 2023 02:58:38 -0700 (PDT)
X-Received: by 2002:a92:2902:0:b0:316:f980:da93 with SMTP id l2-20020a922902000000b00316f980da93mr10858040ilg.22.1679997518046;
        Tue, 28 Mar 2023 02:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997518; cv=none;
        d=google.com; s=arc-20160816;
        b=uv0AEeeaacUae3b8fn5NhlCCkQ4M9QmwGujqcJxI3nEtpOMYPw739/8wqjpEkfNUdx
         uS1SyG4BFLQZLSuFEGq0FTGu8iNWQhwIcoU3MrBuXRc0nBV6de/wWtiT1gU2Y1MfBxbt
         F0oZc4C49orgPp/SexcHbJmh8uB0mBW/NH+ZoS1raRgMmLWU+q8OM8T6u65kBVJQkLpD
         GMwA24xuB+b78q97/mynpsodikESLhURgQV90nmY8DNalEvCvwg7gpcWVGgNSio2yEGq
         ZA+rzfQ5JmT54Trn1+VPtgJq5q2mvKHC3Ad2kdoO6b5XAz/wHkcnMFccVLkukkNF8Xi6
         6gJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lBD4yaWYkYDbLkNhZA944C9ObF80BX09B3zGBKkIydI=;
        b=bxICczqzyOqwRIIXPhJ3s8pcCeRUiOm6m81grYdLuJWJbtkXnMrTqMMIJCYZwEEtUC
         Wyyhv9MjoG2atdzVqwNWm2thF83PrYPcIj0bI9utKh9ApiwBawC7BgeECbygCfoVLUJT
         xDrfq3ZrmQZiYvZ0TMf3FY5KxGr5TKL3mCgnkBjSOw6UMkbkrVKTxnMFGNiTp163WzjF
         +VL7NfVY32EU33MBBuQOImMnjEp/aXspBCpCwWLOGqtsFW1FZfH4xUFsR7/CZJi8b/Dz
         dAeCtinzCsrRUKjlPhLVMPVBN+BRrW3i+0fFJ96irF8dAy8Jo48JlEHU1QzaDlk9tMRL
         SXnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=HhbQB+dg;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id f12-20020a056638168c00b004063285e3f3si3280185jat.7.2023.03.28.02.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id cm5so1748097pfb.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:38 -0700 (PDT)
X-Received: by 2002:a62:1dca:0:b0:627:de2e:f1a5 with SMTP id d193-20020a621dca000000b00627de2ef1a5mr13507673pfd.4.1679997517751;
        Tue, 28 Mar 2023 02:58:37 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.33
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:37 -0700 (PDT)
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
Subject: [PATCH 2/6] mm: kfence: check kfence pool size at building time
Date: Tue, 28 Mar 2023 17:58:03 +0800
Message-Id: <20230328095807.7014-3-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=HhbQB+dg;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
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

Check kfence pool size at building time to expose problem ASAP.

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index de62a84d4830..6781af1dfa66 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -841,10 +841,9 @@ static int kfence_init_late(void)
 		return -ENOMEM;
 	__kfence_pool = page_to_virt(pages);
 #else
-	if (nr_pages > MAX_ORDER_NR_PAGES) {
-		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
-		return -EINVAL;
-	}
+	BUILD_BUG_ON_MSG(get_order(KFENCE_POOL_SIZE) > MAX_ORDER,
+			 "CONFIG_KFENCE_NUM_OBJECTS is too large for buddy allocator");
+
 	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
 	if (!__kfence_pool)
 		return -ENOMEM;
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-3-songmuchun%40bytedance.com.
