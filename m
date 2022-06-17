Return-Path: <kasan-dev+bncBCT4XGV33UIBBK6LV6KQMGQE3HVFM4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE84154EF4C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 04:23:39 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id j20-20020a05600c1c1400b0039c747a1e5asf1654047wms.9
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 19:23:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655432619; cv=pass;
        d=google.com; s=arc-20160816;
        b=DgD8JgDkTm+wVxvduZT9YxAqclYkSgSsuWO8zI2iX/le2285zdQTL3Cvd5Ua/22+o1
         DIZ6yfsqE940ni7Ji7XinJmrhABzhf0kVshQnvbQxy7uGn2GH+ZFONXXb1vZgMnUD41b
         5dAVx5oB9R6t6fFXIzWWLh7+xlXq0jmijWM3txVnH/2pHoqMk2sJTnTGpPIAXJfU0s75
         l+CYbUsLFQNBSzC8k6Bqa5yEOh5chACaq/ogRaLg0rujJOd7SBBUq3PAISsYu2JdxNwe
         yCP041APgJjIFs1izlt70DamWSJLKtiVkIWpmPhTbkarIX+gW2bvVnucE86c+oVtESmV
         AQ+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=tlI3kzA5B/OXCvhOJPkmRVtfthXrDdPri5fIbUAAAks=;
        b=BJz2Kup8/geSpCnPErrGxZ4avtImNs3SGczsGBvX7smWxafpxG0wpj2oer02r1JJdH
         oD4NG1Sz6kWrMZHXj8/YQXsSx72ZjSQT6iRJtwzUH3kaTYSV5rr0Ue2n9e1huxDelS+N
         qapZxPGTjd6Aprj9hDlZLnPtnJAucRY+rmBki1RJNOm9eTKqDqQukATUk/oNHJXYsnx2
         ut7eKM9MgioQtOiWZs1XX6btAjz71tFHsiLlZTHf3LwpanoJdhuUuyaQk6cl3g3ms0pz
         2tUdVWQaPXPt7/+4b0Q5Yf0GWXF45kBO8HBxkaS/J8i22FgMcjEMc/bypLSv3VUbW2JP
         wSSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=oI9MClnG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tlI3kzA5B/OXCvhOJPkmRVtfthXrDdPri5fIbUAAAks=;
        b=e2Dupc5wuCLV7GJhxHqzmsoDkke+/jl2nL8RtDH3UKPriA5/3jguKSEXPdLjQvaf2r
         6o450Umo6Rs0nO9+uefY5vKqEqqc8CMBJNIuCITdkEbJQXDEFZsp4Z8De+bGqdzvLB5U
         bxFhSjY/HN7IWS4Jd3jFrfFFYoEbRmJ4zsaRaZg0m2xHm9aY/im41KRxZDk3vuHSBqBC
         xqxxTluV+g9Uzvn8aieClI/vZYBcX9l/FzmjsCyC4CM2iQlsVOQKcZXFFl3N1/D6JEIc
         yKG1i3f85OpAWzAgY0pLoKyWeHIgcJnyezarma9Anrcz0y+o2dlaDyYShD+iwYy/OCRP
         r2xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tlI3kzA5B/OXCvhOJPkmRVtfthXrDdPri5fIbUAAAks=;
        b=afRU4Hz2/pPZ/jvOQuNjOXtjMwtvuDc7716j8Mx9VWEEf9lmT1R6W70v+/Ucaj9h/X
         mfle2rr1uotVS5vFufTq63s4mV66SnJV8r7CHnFe9YMja7Pswa0M820mT+w8UAicU+99
         MwCsQrcjjShbgrDad5fXOWHkU9RveUF9JTXVD3AQzECBLiYgSrvOig8C3V+Boys2opb5
         aI2Ts8nzgEaKt9yqkMTCPPl+O7PWntIbQ95EgoXgq2UOImI8kqdN4/rVoAbk+O3mDLfI
         8AwpE0h7A5fFFPu3IztzpGDnTWkZNGn6ajz7EWksQ1CXvMkMjpQfCB+Zk/BU4K+Hw8ya
         u0xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/ji1i+Y7RtQFfeSkklqfW/2RUAyqJwC4WCgoe9m2k0VDE8xx/m
	8NIHX8IYYca6+aM4nx0SK4w=
X-Google-Smtp-Source: AGRyM1tO1GljcTT7IUwK7f1n4IlUzKnEWUTgJ2GUzY1BfNK5KXQAxe05/O6/c1hgAhf910Ln3MMo1A==
X-Received: by 2002:a1c:26c1:0:b0:39c:6145:a804 with SMTP id m184-20020a1c26c1000000b0039c6145a804mr7879204wmm.146.1655432619387;
        Thu, 16 Jun 2022 19:23:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ec7:b0:39c:871d:313f with SMTP id
 g7-20020a05600c4ec700b0039c871d313fls1735900wmq.2.canary-gmail; Thu, 16 Jun
 2022 19:23:38 -0700 (PDT)
X-Received: by 2002:a1c:4454:0:b0:39c:603b:ea19 with SMTP id r81-20020a1c4454000000b0039c603bea19mr18373426wma.48.1655432618085;
        Thu, 16 Jun 2022 19:23:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655432618; cv=none;
        d=google.com; s=arc-20160816;
        b=XqRsY7QQMAL73bp1iTOOczIbBlme37LfVNUhTo0++czUPvLGNlk7G20GLrKnQTABkI
         HVnXtw/tnFFe3/c+QBYvr7oEZiNsTQjAXBt7kWSoF7rH/w0Cr9CgV4Xtf9perJfd0JL1
         dtXqQnIHqCPc96gjZHRhm+MQn/xsVE5QYRq5qSvc64tP+bD8RFibyVa/bdB49VUfpB1g
         XlF4blg4qEdFGYbnT17TTqOfZauAcz6jczv60ZwVHKW0M/s5VkUyRbx8Tj31BDtw0Qvc
         1CAfM/tbomawXnhQY2URhg22I/wdhqViIaKSp/RO4Sj9go0SoKbi2A7juyd1CjRUdc4l
         HPwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ddm0/Vb4w1M5ZW169lvJNfEwtGBau/Hg/zMVLm3wJUE=;
        b=b2Sx/OSGvSB8Z8TM5GW4ATWzjl6o8I9CXBrD4NXjl4kiOS/vBlv6titxkjlAvUkC0s
         b3ztSF4RxSbTtckfpb30Al1BP8hwKtkAsogjW7EkIAmegZko7oZxgbmjinF3kjPtjamo
         7gdzjbhTcXUucJ5DgTl/ErQsqnKH98W8bDlStmkRQAAsyaFG8gB9JxR5moqZbkvVWi74
         BSrEtiyfroJxV7S4fO+Q+cWurRpUNOp+PWqtsK0++xDTdP7Pu1aguszFZNKeByGvSslV
         62yBQwmfab2kg40kS7gqNKtssLfWRTMgYQQtW8f2tQffPr5PDZ//mlHUXmH6SMt1XJca
         W44Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=oI9MClnG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id b6-20020a5d4b86000000b002185f697309si145672wrt.5.2022.06.16.19.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Jun 2022 19:23:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B0C29B82692;
	Fri, 17 Jun 2022 02:23:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 10930C34114;
	Fri, 17 Jun 2022 02:23:36 +0000 (UTC)
Date: Thu, 16 Jun 2022 19:23:35 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 1/3] mm: rename kernel_init_free_pages to
 kernel_init_pages
Message-Id: <20220616192335.0f1448680d905a6e22ff700d@linux-foundation.org>
In-Reply-To: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
References: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=oI9MClnG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu,  9 Jun 2022 20:18:45 +0200 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Rename kernel_init_free_pages() to kernel_init_pages(). This function is
> not only used for free pages but also for pages that were just allocated.
> 

Not a lot of review on these three patches.  I'll plan to take silence
as assent and shall move these into the mm-stable branch a few days
hence.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220616192335.0f1448680d905a6e22ff700d%40linux-foundation.org.
