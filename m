Return-Path: <kasan-dev+bncBCKPFB7SXUERBUPR5TCAMGQEJJK5GBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4938FB22766
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:51:31 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-2425e41424csf64655745ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:51:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003090; cv=pass;
        d=google.com; s=arc-20240605;
        b=DcPx34/83+CtC/D1gghUpLrP2dA7yE0iVS+yd32Vt3eetCbHRKulJVOn9IXM+JtreZ
         P+pSbIN+pE5RZYR6dHTd3xr+Ozeac1Jsc1Jr1ngn+o8KAD7wqhHrD49A/SvOEmO/tf6O
         Ih1C04T/be3T6dvUpxa2Da4nuPPiz3B0CRIImyrKL0NO5W9+tQGW/KO1CqSeVqtBgmrp
         ice5emAf+nNfYieGKOOSB+seRJBVU8el34rhrN2YoyJE+zjgnytIEV5oNO8QW5RtYbj0
         zEl0betOi0tVN5xj3I3v/EVL2isn4ZDDAf/oCYwf6M1Z9V2i9qA/+RB8YTDWM1vQHZ1X
         YWXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ScJXlDtLB7TvUAWsMq2v04gTLdfVe8Ej6XcGXSJ6ufs=;
        fh=y+omMjKe0nXKJ+CKnOU2tJf3eb07TsMiX2CWVea1ns4=;
        b=KKllHbJGNUlLGSmKc4frEohR6h/xm6mNC9RDxEJNeMwd8n7SgacdAhJW2pKzPi5E1e
         zX4P/oaSMSAgsuMjziHYbkYWgu+BELO7LKtsQaeT+c8mxQDb6R4wt05gVkvin+9H5E87
         v5eu54vxzKKSlqr1GyRWqHA3tiT4iMumiyuoDSB3270hM7oo3tUF6nhXUhaxKBqccjkZ
         j+6hiKO0WddYcV+xtQHrAENaACz7d9s9GLrKkmNOFY7HBII9lzUZN0Ebyu4FVtZnuBbX
         CpvDshoDp/T3P1Ddn5W0rZQo1D3mMqfBwPkZ0pJbzn55nUJtr0koR45Azgt1ILJBZUTy
         40ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ieKYKiqa;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003090; x=1755607890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ScJXlDtLB7TvUAWsMq2v04gTLdfVe8Ej6XcGXSJ6ufs=;
        b=LwyerrULlUDgzDPTZS9nKoDh82Md4bIsc3WEmIdsFWDh4nxfKBP28dKVUPWlvDtrTO
         UWintSQp07EDMwRuQzH9kQWcFgnqKdmFbjs7kwnzIkaZDzLsACOZmF6srd6vDGEbbR59
         3KTHRstFkm5IPBW8aLsJ8fm3Bx9jIsjWCq433bgRLhyuJTozA5iqbsVggjtmFWzooaOb
         2h9mdjzrKy4iwOYM3WZOrtvuqtojlzRMENTlLj6EbkTL1umgy72KKRzyFmsBY2Gcbhz6
         D4ZS1vOaMMXXA15fZpzCHuVg8pQYPuSAaiLSGAk0nrZT/6CuB3PXm+NXdsxlhfG2MLhw
         2Ipg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003090; x=1755607890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ScJXlDtLB7TvUAWsMq2v04gTLdfVe8Ej6XcGXSJ6ufs=;
        b=eKkviySHr66Somy2bro6RvwFGb2hlzYyM+rz0S+0EUOd1YJUM4ieAYCYe6zxXdjvd5
         WRB3/RfqLHL1rgFWmOz45c6qkdNwgvNnQm/GoF3WOMZs6dvL2pI8U8ocn2sHBuBnzaMY
         wqDE65rdM6eAiLZlF7UFLiIA4TEzv0K7GgcWdMPyUCb64r35uaXAiyNXxR5HIHCHiS6a
         2s8I2eAv92XRAbpDc2UEaRFHIEHfJLqWUlAO24dbyY7uht9hPi59GXxfRxTPuDOyS2Yo
         qpSihObrr+5DaRBo6HkwGAKD3tH2zLQSXh0I4kIx4+F50dqlP5RHHuaibLqfiSVgbeox
         g+dw==
X-Forwarded-Encrypted: i=2; AJvYcCUKHqFgeRe5t1qra5qui+EBeGf0HGkwr39JXel7PGDlQk1gvL5w/+6JlPkLPS32YQgEMNjMmg==@lfdr.de
X-Gm-Message-State: AOJu0YxlHHMFHqqQYsCNoYlTSL0sxPgP1dNLGocSG2dD2Cz4Vk/2y2Ae
	q2DFwurZZCR+7Mbyr7H9I7gjW1q2X0f+QKkINwdX2aGefYyfKTHC2ZPL
X-Google-Smtp-Source: AGHT+IGxPJoxbjTz7jP7OB3YrjxJ94tf5vrrI0Y9NtG2I0Qe3q4PgJi6/5bLXt3hez3qlUVocCB/5w==
X-Received: by 2002:a17:902:fc4c:b0:242:9bc6:6bc2 with SMTP id d9443c01a7336-242fc38b2fbmr43683605ad.57.1755003089626;
        Tue, 12 Aug 2025 05:51:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfMeoy4l/sxYFO//KGeWzkZVs2vGXrZOQRLwZRef9cyUg==
Received: by 2002:a17:902:ef4d:b0:240:9e9:b889 with SMTP id
 d9443c01a7336-242afcf5e6bls64548565ad.1.-pod-prod-01-us; Tue, 12 Aug 2025
 05:51:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVninJisNoTewhjDpqIVjs1w8hdoE6RA0gTDhE81IYkLgifuTX1A8nA5DZ74Uvo6ejzmylmVhvGzik=@googlegroups.com
X-Received: by 2002:a17:902:d4c6:b0:242:9aaa:1351 with SMTP id d9443c01a7336-242fc230ed5mr43676835ad.13.1755003088388;
        Tue, 12 Aug 2025 05:51:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003088; cv=none;
        d=google.com; s=arc-20240605;
        b=TZWo0/Bg7LA/1AtyTjqGzLTTlH8BZ2FZk0mnVqtbLrUrXpkNZ7PFfVTzpYJJyBg2mH
         fJ49XEI53TbbPRPOreDWVz8Nfg5UM76NnboapAtL6XYayFr78MSa1qG7LLZERlaAwE+w
         oAP9IVXbzk/2icP3RH51KaHK8FH4ZzjTCDGBqj+584X/9Hoieiy0F1M0Gi9m4q22F9Q0
         xxAxs3tsk6P7V3LWtG6rRVf0V4t+Z7etrn1IaUkxxf2bj3SQP6KuO+VBlxgk63dd4Aqo
         EmJpmSx27hEzyNPY6fkfp7qZvzwLRgQA7ANRRQxtxwsohF1FFakyo+ALjky+tKlPYqOH
         A+9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n2YWNQ1R3q2yuyqJw9ejU5xCE0/f1sakMXwMmNRUMe4=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=Xo2FxLENtcA+t/a5AF+33j2wehwPy/QkBvOw7PZyMx4nsaMOqD1PXTHt90V3hcnLl2
         xwbbqT2n9Mw/5zKbwcqq7z17GdG2XoSyl0jVWxDBXhyhaL0wgoKRP0bq+nsV++6CTzDe
         nPBJ5X/fFvlkEWFWYks/nzHFAXaCYAd9wgnnB2oVw/ye6PlsHdsYIiMBXQo9wx1DHEU8
         1Ej3T5rXAyVzoEWZEQ4eY6NBsRLkC4WU4khHW97mgxnUCdwPWf/+Q9HSqnfbL1uT0Sga
         emQtqEk0yVaHezcCHwDBGvUAX1eZ64tXsv8T1gb4cizMCktITTrryTc2RqmUempEF1qd
         O0ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ieKYKiqa;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1f92d58si9424235ad.4.2025.08.12.05.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:51:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-665-9kKnlE7PMdGWBVGqhx90ng-1; Tue,
 12 Aug 2025 08:51:24 -0400
X-MC-Unique: 9kKnlE7PMdGWBVGqhx90ng-1
X-Mimecast-MFC-AGG-ID: 9kKnlE7PMdGWBVGqhx90ng_1755003082
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 3E4DF1800370;
	Tue, 12 Aug 2025 12:51:22 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BFF7230001A1;
	Tue, 12 Aug 2025 12:51:15 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 12/12] mm/kasan: make kasan=on|off take effect for all three modes
Date: Tue, 12 Aug 2025 20:49:41 +0800
Message-ID: <20250812124941.69508-13-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ieKYKiqa;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Now everything is ready, set kasan=off can disable kasan for all
three modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 32f2d19f599f..21b6233f829c 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,34 +4,32 @@
 
 #include <linux/static_key.h>
 
+#ifdef CONFIG_KASAN
 extern bool kasan_arg_disabled;
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-#ifdef CONFIG_KASAN_HW_TAGS
-
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
+#else /* CONFIG_KASAN */
+static inline bool kasan_enabled(void)
+{
+	return false;
+}
+#endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
 }
-
 #else /* CONFIG_KASAN_HW_TAGS */
-
-static inline bool kasan_enabled(void)
-{
-	return IS_ENABLED(CONFIG_KASAN);
-}
-
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* LINUX_KASAN_ENABLED_H */
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-13-bhe%40redhat.com.
