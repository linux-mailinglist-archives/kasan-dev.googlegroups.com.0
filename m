Return-Path: <kasan-dev+bncBDY7XDHKR4OBBRXIXKFQMGQEYDDTEGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 91EC1433555
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 14:04:24 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id m9-20020a17090ade09b029017903cc8d6csf1456548pjv.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 05:04:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634645063; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNLK8KTTuRBlRQ2djTyH30i31i0OUVvGA0kpVpbzDS2Tq03KJ9SOQU5hNnXWzngLgb
         dsNKPvFgr8HQC+jsjiFa/BTmqn2B9PLaa5QZG9/AZfYJ2pOT3nslPGn41IlAJwy9E58y
         idVujAeBTxX6sjp9XvYWnW/vE/w+DHG0oXNatPRBI2zvQ7dPr+Y9OgQgIQLlk4UJieSl
         Q/gYQCvp7Hg3xp05sfhzgfrmrzLbxtQY3A3rvyjmZ/z5aZ978oLoQboRaC99cdIzbMvD
         HaS9wbFho6XaICBLir/6xlbJdBzRQyRpcHQ/vAJu5LEXcXDYQIpKr+7Pn04MbSGrCy3l
         pKSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IcLIKwOV2DTBkkrDNf+aUcZbpQD1DLuiopcfw5xeznQ=;
        b=h7Jv4ed7wuzg1VsBLsQjqwyfItYz1RWGoeeHOKpDuIDG56ejeBeRCUtniOu40f70V3
         dHSCQdc3YkOEjn7sw1JvF64UUE2UJOw3mh4HDwaa7IBB2GVFDqj9CgYthUdcYgp/tNsT
         gNqg4+NuNH2/lWqI4xXrn9jYJrD1qL1lejK9IBn8KNaXohCRuGCE5NFcsAuWG46ulMss
         APC2F/IBFqgWUoRzuHXL0Bpxkk7SuXSlV+gx/xzheJEoAa7UyZOvQGRHR+fai3gVnsDB
         z2NkMUDGRZDG3sXo6NoTOeSf3qxowYk3haHzp/+LiVXtVd8WrB2++N+ea7lVyDSL6K3Q
         lh5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IcLIKwOV2DTBkkrDNf+aUcZbpQD1DLuiopcfw5xeznQ=;
        b=CQ9tP0zT9t5ELTkySTE5UMewMRteSmEeZMaISAEKvVtfNLBKXDYU3BCNAe84CyU6BY
         O+066/UK8sJv3JfgQv5CBLsmNAGctVnvXdw4AlV7o8LTUzOUUu+Gy7WdEiq3mgzamcCc
         glgF/tY5s1iXQlgxCd6hq452aPX1ivh8D4+BEQg2pGl0l/ebiMy/7cNzg/w9fIbNaNlY
         Fbmqt6Ld7o1qYyyXuN7nTLyBFsPaEtO7o+lBgzQ+jyoVXgUf043RoYo4mebW6n0HGvvM
         LR1RjgCJkKWsRHuFGL/5JQhrXsADglBJAkvF66v7x4rYU5AfRTxe0O60HiS3CpR7xvcM
         Rrug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IcLIKwOV2DTBkkrDNf+aUcZbpQD1DLuiopcfw5xeznQ=;
        b=HDRDT1nhXu8cGZcc6yBb/oeshAe+lXe1awqSRcK9kG4Bjv5qNUUj9RY+K+9xZ62XIc
         /uup7wNZnn/kLKKWy9AU9fVMPlK9BTlGiNRw2LvmweUfAELl0m9gbW8AgqfAkk8zenop
         Jl18mzF60BbsQukNXA3+BRuoBUlzNOFBYGiPB33Ujp4euW43tdshnK8SoyPvcgOHWR8I
         26o08eUQMEuqOX5kjuDqMFFaUcJNgpw3+c8sWxRRaK8jD8w1+sLKlaaU1j82VHK4gy74
         tzBOCaMP6dqAGwN8oViHWrAt7oy01bvaUBXP+VvPo6SjPA+uziYE2L2k4G8t7nhKScHU
         WAKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hZVUaWgrZadmUCt4MMQyDWK93+8nRUvQ9swdyOo4gnq8ek4Mz
	2WThB0KV8yomOHKktSTWywE=
X-Google-Smtp-Source: ABdhPJw8uDU4PbgHQqLEoFoDzFgifOrqsldgKR/yBjqJSszWPVx4dryQc1z0TxAnXSVFQWBopYJGSg==
X-Received: by 2002:a63:b04c:: with SMTP id z12mr21408613pgo.363.1634645062767;
        Tue, 19 Oct 2021 05:04:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7846:: with SMTP id t67ls507862pgc.9.gmail; Tue, 19 Oct
 2021 05:04:22 -0700 (PDT)
X-Received: by 2002:a62:3387:0:b0:44d:7ec:906a with SMTP id z129-20020a623387000000b0044d07ec906amr35654461pfz.69.1634645062202;
        Tue, 19 Oct 2021 05:04:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634645062; cv=none;
        d=google.com; s=arc-20160816;
        b=wtWQoXDHZBfMdFJW0Ci4Q0mgJMg3bYfGFM29HV1hBpFElHQHzJETwQcGUYQ7h+jSWh
         ffcBq/0YR0rPD18j9cWOelGICoSwJVTS7kLhO1Pw2Q6/7h5g6GmYwTjhoXeNLu7bwV/b
         xTCoVuDJq4/5w6V0zn5wbJCAlzo0yFxkDt7E1Uwph0+xw7QHVG2M4r7qTa8Pp5S7/Nz3
         BErsvczLJZtRwr19foAmUI/XxpYeH+fDH5gKkh95PGqXU9jQvzafYj30OYaOMQRoyQI7
         l5nydYmvJDs/X4N7HemYGkNKvHRDL/l5AUAjKDEnQgBPyZQdWe9BU5eHsFh1RJ43Jx0s
         N5Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=/AmYClIFhmjezvnN0NpC5OIkaBdLOL1LWu5S1FXNQAc=;
        b=MaOuGZdVchUOAsdZU8fo2IYxX2UORe1aLcVjKp7ajFJnxE3Q45EZriRHhDND+Z+QP5
         nmu7HFph8YWZzxgVfSuIAjhivGRryumFDp/xrxO93X4hG2J0itN7dr6u5qL+ceKOrij8
         g9V91dVFwn+pt62wVmhAXbdN3jndfIH6q1fw7aul3GzqpP5v5BYcmWTQsbOB1kaVABbq
         gznvRSUn35GknjXj/XRD07h9Ss5POb7LTiClWM3EvI55p4y5dvqccd6hZbSMX3osT9vS
         qahEE/f+8KyEVYgmmi1GAL54QfmXrEkeHj5Ojg4AI13+RCYjILECymGODjJAL+WZQDeE
         K6yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id f11si472778plb.5.2021.10.19.05.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Oct 2021 05:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ad45a0871a10492ca17d80620b9e8e06-20211019
X-UUID: ad45a0871a10492ca17d80620b9e8e06-20211019
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 428895041; Tue, 19 Oct 2021 20:04:18 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Tue, 19 Oct 2021 20:04:17 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 Oct 2021 20:04:17 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
	<will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>
CC: <chinwen.chang@mediatek.com>, <yee.lee@mediatek.com>,
	<nicholas.tang@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH] kasan: add kasan mode messages when kasan init
Date: Tue, 19 Oct 2021 20:04:13 +0800
Message-ID: <20211019120413.20807-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

There are multiple kasan modes. It make sense that we add some messages
to know which kasan mode is when booting up. see [1].

Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 2 +-
 mm/kasan/hw_tags.c         | 4 +++-
 mm/kasan/sw_tags.c         | 2 +-
 3 files changed, 5 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 61b52a92b8b6..b4e78beac285 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -293,7 +293,7 @@ void __init kasan_init(void)
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
 	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 05d1e9460e2e..3e28ecbe1d8f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -168,7 +168,9 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+		kasan_flag_async ? "async" : "sync",
+		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index bd3f540feb47..77f13f391b57 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
-	pr_info("KernelAddressSanitizer initialized\n");
+	pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
 }
 
 /*
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211019120413.20807-1-Kuan-Ying.Lee%40mediatek.com.
