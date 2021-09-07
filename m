Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLHH3WEQMGQE4HMDXRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DE54402A81
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:06 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id r1-20020a62e401000000b003f27c6ae031sf5146928pfh.20
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024045; cv=pass;
        d=google.com; s=arc-20160816;
        b=a/quDcKq+bL9fBWa7cz71uohhBONHFvOs4hohzo0BzfV12M/G8d0DLwVAUY9D0j9mQ
         BEZ58L9nS7TOqgUdnCSgkPgcNJSYWFZM4WuNu+5JVIE5oUGFoaSAagtZoOQFw2hO0i2I
         JxVnup8Qi5gyMw605Hvpi+gO1IULY29LYqHl6qAG6OEIHSrHO7n31nRBv4UieWOpLAz+
         Z5oSWg+k7MZo3xzv7QQlzOHVQinEkUPpSd3VAfADAlZB5yQYjpScvz5UADo76cIQhSx4
         A7tXQyEUP2GYi3tXvqgvcHzcNSP2cD929WrHA1edRWgjTil/IdhrY5YleA8I0zVOWXLY
         TnXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=sZePix3+wBE8NEbAR20OpyS/mde+yvcGYx0lrFWnlRA=;
        b=Fg6YL7T/22jJb846TTEiQwpCdtv9Exi11oHMNNvrT8FrlON8VgOCnxHvAM7B+wDdHi
         HBWV9/LbT24NdkvtUCSLzXPFZ++22jTAP+HS+MaZ1dO0ZeEz42thvGmMEC9e3GjF0p/K
         zhi0N3j0IQ0JkE7T+qHUUHM0EiTkya8fMFeBXzGQ4XyF/oFCDRKevf7wsYvES45eFE60
         3NetipSPRIYcAeRHjLdW1qFXmqJfkZqH/T58nTCtBYTdcytwErQwEc5GDt66DRO+MqFV
         NnfE4NS2Nd6WgHuyQknZwOE1o2epVfNz6Z34zgBC2Xj0m6pzRUfwKzsWSYqU12BnIG8M
         watw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FIdzWcWC;
       spf=pass (google.com: domain of 3q3m3yqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3q3M3YQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sZePix3+wBE8NEbAR20OpyS/mde+yvcGYx0lrFWnlRA=;
        b=MSJPdf425FzdyFi9aaZ+b3FG7NBbvq0M9uASeB5ujODl36pS9cznJNMgS3txijGUN3
         HDHLrRBZIl4XhbgERVpAGhx5wE2mkgnMTIWQaaG4yqaySGIaFIWc8jHbUzv4jAHqKAMD
         TZqfY5GNLtSnOjHhzYOJcYdfGE3MQv9Pbi2O9R049Dm/E9CvGu5Nn+YacQisPRU0c9cy
         i50n8RJO5vE3kjtGoRAFWVUeShcWO6Gnkr/9XhF5GsTBok4I0zpdwTCJKgcoa2J8seRt
         87PCcpipX4LpG9s8zaQjMYn9KRyox1Y2iLSQAUrdb/HjPBRkOvPJJ+YUnxg4ikZIhVMA
         YarQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sZePix3+wBE8NEbAR20OpyS/mde+yvcGYx0lrFWnlRA=;
        b=GmJz/GEFp/gW353BvfUfCpznMATNTbh573OGJwfe2h33RvDHOjv/Dnj3ZBCFdbPLV1
         1+HxW+rsUxeubYOpm7GH1FVG28S8cIFNPK8NCMQL3r8Q1upgjZaz4peytbp04I8bOyig
         f0kYWPz/ne140H+CvrnCs/LDFdxMX+nEjBkHufyek1ccOdzRj6qvQJmVpI0gZDyPJ2Qk
         2vsdBKqthZt9QtEQfwvQZBLHMFkHBrWM9hQS41ug3QdR3pgmq4GWdxv2Cmwz48etofu4
         mIBxbanrVfvQWw6CshgvGjnHB3LhVOuzcOKUSgDBR3M+G3YkZR/zE2KoQ4dRHq3beWDJ
         qq9w==
X-Gm-Message-State: AOAM531rxcLTVPtzaYy7Vn+21yJOBDOupf1W99N4O2G4lgtUrlDrzU+F
	Uuu3PmPI1Gky4uBjLHuKxDU=
X-Google-Smtp-Source: ABdhPJwtXTN0bR6RBNWtx4WGEGRrncwAu1PKtMenMOw5UOlL71PbXlRbXch80OWQv0SXnjYbcBYWnQ==
X-Received: by 2002:a17:90a:3f83:: with SMTP id m3mr4859129pjc.46.1631024045012;
        Tue, 07 Sep 2021 07:14:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8547:: with SMTP id d7ls5125835plo.7.gmail; Tue, 07
 Sep 2021 07:14:04 -0700 (PDT)
X-Received: by 2002:a17:902:724b:b0:131:ab33:1e4e with SMTP id c11-20020a170902724b00b00131ab331e4emr14791279pll.12.1631024044383;
        Tue, 07 Sep 2021 07:14:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024044; cv=none;
        d=google.com; s=arc-20160816;
        b=YuIRFfjiQRk5y3B90le1NeXEjNKd49NCM99zqTT23ph6CYvYK2RkUzKo36Nrs9WzEG
         4EL0jZO0fPhUJTpeDwZnImtnfmYZ6iNeOj4H4nSOYw1AGhNDZNEllRe3wMDR9Ca+SZ/Z
         1sWP0YbKaZCYWKUSy1nk8tUg6TkoEJ8DJ7v4o3GhFQCFX1WZUusI43HS2M1KptCvBOMS
         wS8aPlN1VL1AKxNn7z4n+MMlZFHSCvXXYRbl4tiOFDQODMEaDaNxqNkzFIcSKkWoIm5C
         kcwT7+rLDvvhHq92zObd38fZEqXTmcT2LYJvHnzBwMuVpWTA1Dzc4VrVWGRiB/B9r/1H
         IcEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0HnGqpsoRrU1QmVhpHGIABru/4TEzN09iOx6pzAlIgs=;
        b=wnDf/3ZxU572Dt6XxlVL6+ppjnp8eqJ7H19eIk2719vtWODsxgVgnKDSkqmAIMNfEI
         EU2b0imRuoz0oq5IkA6sa+f3kgXzsIrtFhXNHbnwFrD7FgVwd5iJgUpCpA7YDRzc696A
         PGKFVv1KJYe10kdxkCYrzbA2g/HhK1Aes3non8YmVN9o6WlVP++qSfgQYhMTGxwniOE+
         hUBTCf1s1h1/xqHiU6TvJhmeNv9UobJXyRSsdKluqJ1rjSuWYbB2LPdpnizgaWNKP7kL
         tV9dlNjn8clyvqMacHGRzdtwuQTNMGrWMS+9iuFijqUH+B8PkTvo2wA1UaryjBwPTdO5
         1NLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FIdzWcWC;
       spf=pass (google.com: domain of 3q3m3yqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3q3M3YQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id u14si656792pgi.5.2021.09.07.07.14.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q3m3yqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id o7-20020a05622a138700b002a0e807258bso10135320qtk.13
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:a0c:e1cf:: with SMTP id v15mr17153429qvl.50.1631024043569;
 Tue, 07 Sep 2021 07:14:03 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:02 +0200
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
Message-Id: <20210907141307.1437816-2-elver@google.com>
Mime-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 1/6] lib/stackdepot: include gfp.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FIdzWcWC;       spf=pass
 (google.com: domain of 3q3m3yqukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3q3M3YQUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

<linux/stackdepot.h> refers to gfp_t, but doesn't include gfp.h.

Fix it by including <linux/gfp.h>.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/stackdepot.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 6bb4bc1a5f54..97b36dc53301 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -11,6 +11,8 @@
 #ifndef _LINUX_STACKDEPOT_H
 #define _LINUX_STACKDEPOT_H
 
+#include <linux/gfp.h>
+
 typedef u32 depot_stack_handle_t;
 
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-2-elver%40google.com.
