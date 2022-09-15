Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUP6RSMQMGQEUXA2JYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E1E5B9E20
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:54 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id bn39-20020a05651c17a700b0026309143eeesf5564603ljb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254354; cv=pass;
        d=google.com; s=arc-20160816;
        b=oKGNMl8PRaixqp1f9KZUd6SszjBU9vnUW8fPLmP0021a3XPR/E8y4Tff7q7IGzwO9b
         3Adwh+TJMrIbi32gyhNEW/nsAO4izXKblEkHmrsf+tuuPZdefE0xLaCp0LfNN93BAHOx
         XUtaZ300wtGMPVatf3Ayl3oqoHuzO4fyUwhVmIgXsP0OkbZTywUOkySTFuvrCltmRbkx
         C0/bnEsLz8PecQpze3W07HfUM18WSkRS4+N/q+amKoofe8HLAZriCizIr74Z/y9hJfF0
         zFQhiS8S/r8tZwrjgCqI6rZWVIDU1krBEsf3vEaXjDVxoJb50Bav84I+zZNLT0jLrRNo
         en0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tUPT3DxbibwrNVH65X73rxZdXGtLtGwDyb4jiXlRbmU=;
        b=UabVHVtuaN1IaPXA7s2zNwBTMBcXIRIlfPJmsjqCW+lkRuA9q7SbsLwR24MKhCYoza
         lnzcqTGy8cvhAlCAv8JQgivZq1LiO3eAg3YLgyAxGwCN1i2BM5YI+gW6dbCykS7NELU1
         0jzjexYlgjJzZIG2vSs3wTJjW7xnxED06bEPpfDzIntrTyqx7rf8wbc0uLTaoiwztXTl
         bDJe3PhB1sqAlEmUyy8VZlguHA1q2NutVgqlY0K3yoTCj30Cqtl70R0W81XGDM+HyV0N
         Ea/KuPVjTYFvpySN2LMlNEmkXzqYUhyrmT/IWv2kWzHDNOZi3SER6dB1zfkFA92JUWvP
         CYew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bjU5Y1Uj;
       spf=pass (google.com: domain of 3ud8jywykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UD8jYwYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=tUPT3DxbibwrNVH65X73rxZdXGtLtGwDyb4jiXlRbmU=;
        b=nd8DbFVy91hWEFumB7cI7brRyQoKXPIPmdmNORrJAmKBX2vzufUCw8asxceTgZomi/
         YxLx74+hx7DrTWXeyuwK+M5ZxKhrCnGSbXvXRMc+oYkY2Y8knZf3RywUV5WbsOwojixo
         RA6NHbSnHDlB84l90CeT5INm6jgqJvJ5gXBM81GUXTbap3mrRKLvnArZof3curGj5v5V
         6gjZSZTN6MYb0++n7ZuMgzQlQ9w5thvrGgG9doZUjglDPKbHXLYSBpFRiS3FwA+kG7Zx
         TyO6bMeEioYjFTG14VrVrAO49LjEKW+B1d7+fbM7DOMl5YMT8jTOvMJMIggHaMiKihP7
         5OYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=tUPT3DxbibwrNVH65X73rxZdXGtLtGwDyb4jiXlRbmU=;
        b=l73G0Zzcrau4QJRp0ORpLoXwVHfALrsF0WDYcEeIlGUundys29BoDjS4m3x3azZbmH
         rPWTVrZ8E4afSxmIOpNdCHSmwHWyzCZhljlEx9TdKcAGdh5gpJVetUHc2SC8hVq9jjro
         WQx6WsZTGlOY6czZqrTPdfTeJcQXL1mOISEQZ7645YwIIvpnXQ4LxDAOc0846zAY2B7m
         15J8QwcEFsG43zEbo5Scss551EJg2qtWLwGuenZNdeZHfma78VQDkV4306Dmf9b7H/0Q
         1YJDdXoJ99meHPsqimtiQuVVcA18dlx1F/5U7S74YOgO7eZc4wGCqxQjv8vedxRHDlT5
         JTNA==
X-Gm-Message-State: ACrzQf3Lqg/k7Yu+KPizA1PBdGXSYSf4b64xNGuAcnOwxR69wXHCXTmU
	gOCuChyVZoN2xhBo1uadolI=
X-Google-Smtp-Source: AMsMyM7HXDmkhAVVsxD6j87AqjREkUs2nQf6y7BH00WVFxg3+ObkZIKE8F2ksEJGOd9bLjO+Uz6YMg==
X-Received: by 2002:a05:6512:39cb:b0:49a:d1e1:16df with SMTP id k11-20020a05651239cb00b0049ad1e116dfmr123434lfu.438.1663254354132;
        Thu, 15 Sep 2022 08:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:874a:0:b0:26b:fc3c:205f with SMTP id q10-20020a2e874a000000b0026bfc3c205fls135983ljj.7.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:52 -0700 (PDT)
X-Received: by 2002:a2e:7802:0:b0:26c:362e:c59f with SMTP id t2-20020a2e7802000000b0026c362ec59fmr60945ljc.440.1663254352487;
        Thu, 15 Sep 2022 08:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254352; cv=none;
        d=google.com; s=arc-20160816;
        b=FCy8CnZjZ74/AV1ld2d0PW1cZ4JWP63OMqlVsvc7TdeVpzOqxaEG2tPbsUQujXUVCj
         pgbFQUUj9PBCy8MZWSVq3OFwHCOrOACujeW2Rb8Umqw++kXxVFTA+vwcVozMkpi5sKAf
         EmJoRznL3BZnY9FOQv+6302IngXI57Vg3vvOcg32IxC17Eu5WLCjmdqXHvxQW7syWYjI
         3yB6PlCRumAewiInZms8hthPOdmB2DfsWVVJNRjjsPYnIgWPTsilLxk9g1A2A80M43sx
         mZ6jRgMHMqLGyqVUz7sSvAA2yGZ/YePIJBsLcZvK8+2mXQTQVEmu0N+0jd8KcyI/LEFL
         6C9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=T4yulc1U4RDI/lAlxqlpzG4AIUYO9fQrzg+B84ydySw=;
        b=AOx/HG6ggZjy6Pk4EPKlpkKS1OHqXUnyy2Nr3+HYFJzs98U1xHll1iTHKGDB4SoUZj
         l2xwwGuUUFlFqErKL0Re3043jWdx76IBas7EsKQfjSClSJU6XeUAna3R83+GcDIhuNH9
         giOs+DS2nWXer2GZ6iyACEyz/xlAiNQeE1uQ0Flkq8dT3dD8u1EpZXrwVLtWSWz59wvk
         DVIRw7+sYlEwi3wD3LXFIsdkxaHad1T1EpwGRFNipT+XUyiju3rJ9sqktTt0Ho8ljmHl
         piSF6gNyoHGFFIvs1sGjvnvvju1S7nDl+wBPCUJSqeEXgeBgNZXHgMWSWqDpiRqMa/gY
         FhAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bjU5Y1Uj;
       spf=pass (google.com: domain of 3ud8jywykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UD8jYwYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id u19-20020a05651c131300b0026c1dedf78csi249329lja.0.2022.09.15.08.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ud8jywykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gb9-20020a170907960900b0077d89030bb2so5491786ejc.18
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:52 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:d06:b0:440:3e9d:77d with SMTP id
 eb6-20020a0564020d0600b004403e9d077dmr260579edb.286.1663254352056; Thu, 15
 Sep 2022 08:05:52 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:01 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-28-glider@google.com>
Subject: [PATCH v7 27/43] kmsan: disable physical page merging in biovec
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bjU5Y1Uj;       spf=pass
 (google.com: domain of 3ud8jywykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UD8jYwYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN metadata for adjacent physical pages may not be adjacent,
therefore accessing such pages together may lead to metadata
corruption.
We disable merging pages in biovec to prevent such corruptions.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/Iece16041be5ee47904fbc98121b105e5be5fea5c
---
 block/blk.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/block/blk.h b/block/blk.h
index d7142c4d2fefb..af02b93c1dba5 100644
--- a/block/blk.h
+++ b/block/blk.h
@@ -88,6 +88,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
 	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
 	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;
 
+	/*
+	 * Merging adjacent physical pages may not work correctly under KMSAN
+	 * if their metadata pages aren't adjacent. Just disable merging.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
+
 	if (addr1 + vec1->bv_len != addr2)
 		return false;
 	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-28-glider%40google.com.
