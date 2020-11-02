Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK64QD6QKGQEGQ5YCYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E38842A2F02
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:59 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id h22sf2316122ljh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333099; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yl3StxbxUOWDdorvz0vZUOuVzPFqE6LWVIptwl1KUfNz7s+YgnZktxhytahL9Y5UBF
         N6xcutYctgBVvnZC5/BqoR693y7m2f8bCBQAvSjsAGsYIYFfXzRVJkRS/U2sp+cIMhRj
         uvBcyDixdgTeo5ChicBert42oeOR5uaY+t1tYspRLm5i6mg8K2NCQX0tX1Iv5O23h53u
         9CRGihMgE0PMdaO0vufWwDRvOqnkTUAgifhpR5GVwrIyTO8xN2MZByCpWGyoamaj93c6
         WSAIRinmKqy7RNWnYISCpY2jvcaW0vXYhjFPeemNnmEryOl6D0+xXAZQHX4oCYnwtEXQ
         Vy0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hWEnST65mk+GUb5dGISETRXhMJLL80fWSXUnDcjyr3Y=;
        b=JDLBBexXkrzhHVs9fOpivdRqrUlHaCgjWyTpwRrpjIakX+mKngLeeoHGPBLDu8TKTj
         eSflmK5Sr6ZFcPZa66lzJccVXdaj4d7jCgEDhXHBewkWMUSUmXuI4jAowVevoiEbZAMz
         di9ACoxG/L4cb1ZyzfWe9BrCi0Vt+apmEXR36HvjCuMtH2PnYKE6HstSOrurZo9UmW0m
         BUQSJ7UKZdEfiuMDLH+BPrzBiFLxOcdg17ZQn+8+BvULCajT926zsz6UdrL7iXBlWCr0
         lJn5lbek/hz2Yg5neH/5LqzWiuqxKh0QE7gt5BWA84gBPH/jqDJ77oon1GgmFhlxmayZ
         WBmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="p/cULzh/";
       spf=pass (google.com: domain of 3ks6gxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS6gXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hWEnST65mk+GUb5dGISETRXhMJLL80fWSXUnDcjyr3Y=;
        b=F7gmffBFJddBBLZRXN+uUSuCmpXKegBLwvnUP7cWb6v6L7f15g5UIyjs52RlH4PLy1
         3E4IXf1U9o82Hrb7mlAUwXNO/8EcrIhEgyhwUIO8q56gffeFnMj84YY2A68tlYkBtGRW
         17/0+AJamR8GA9/PU8/34dRzuCyiMSKK+SvOeBoMgr0ML+HvNyl/FiWy84zpDJTiNwfj
         aUG2N+5oymlo8Uo/Ge8HWDyxpWVrpXuAQfh9W3J/tQ/JtMVl45z8McclYp8jKDdjhjZ0
         KEBDxgYniA8Caku/lfG4U0xOHyksb6cK31urQgznfQ5BOMsgo8oUiTusgQj9586SBmYy
         +5mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWEnST65mk+GUb5dGISETRXhMJLL80fWSXUnDcjyr3Y=;
        b=aroluSwS3E5K+An3kIaYho2tCMi83GNDHdYQIr6j2fejjGSSe5rbguKduHoSwcYuCk
         +NcFbXajR5ukXIOWZSgnmSDuLP6vsQmU2ySHM1koxh2/A7BWJnOChaa/Cm+ljsLduhw2
         wZZOXv6zzUOsv44nMl9y1UDxQ/sYGGpaWf2YroVgiQi5hQhbBOs/tyY5/TOmxBvL1KDM
         732lXHhBcW2xI+s4V6kNRL4foG6jfWhqfeoO5oPfi6kUljl5s9znL+CTzgSFu/1vrmjo
         Oj2Gls1iBB36pwXOv5W9Tu65h7bVlvk33o0ymIWlXVmg3M0f8IbAlLB3ofZBN/811fHQ
         WYFw==
X-Gm-Message-State: AOAM530pOTjOWYHn7aopby9WQXZ4P4Kdsy1V9ZR40XKLfmcUVSZsR4vI
	f825/bmFcB0bfxSUk4rebTY=
X-Google-Smtp-Source: ABdhPJyHTRKDtJatgK0GcthPrB5IULeQ5ML5p5wdmfj5CJc/LmoiVTeiUEeuQr6G/GztqEnLInoHpg==
X-Received: by 2002:a05:651c:1256:: with SMTP id h22mr7425728ljh.263.1604333099279;
        Mon, 02 Nov 2020 08:04:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2023:: with SMTP id s3ls1376941lfs.0.gmail; Mon, 02
 Nov 2020 08:04:58 -0800 (PST)
X-Received: by 2002:ac2:4d96:: with SMTP id g22mr6538850lfe.335.1604333098220;
        Mon, 02 Nov 2020 08:04:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333098; cv=none;
        d=google.com; s=arc-20160816;
        b=aolhD912MyGI/NBPrMxYtcw2fgFu02XkiAG6w027v3iOIKu/vCaPYc4Hq+gSsHR+GC
         zxuApCa/4hLvGygeTqCw7Ex2c+IhrzoTFnF3rBqmVIlcS0oKwAeJwWEGCKTIK2PKniYh
         3wHvloNdB2N8ybsqjrNR1j58eTb8Wu0auqBHw7f7HjqK0MCIITfm4zWXYxxIENcApDFm
         tl9A3Vn3LNJiW62aFNf1Hm1YVy/KczNiVmPajmaNUjoSLmRBTpbPuX5V2bXgnKfqZgSi
         QsHjmJSwvcNzCYtB1PqjCwE48poLewjGbUbFD1oPOxbts2Gu9Z2e1X/f1yTXrVF+lxkl
         qsUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=49TVXy6Rr5NIl62UeWZUyRusw+C/T2q2yO6DUxLqnOs=;
        b=IdPey7WtXp8G8J12gooFzQOftuJ9hAZTaiPAlk0RjDpOMofztAJXt86EcXI6EjWixe
         o6Nwnz8Zx/VZMK95lXebYSd+P4SSe26Msd0bdnJiTm7bN9OdYQmFKrEzePI2TuGz/Ywe
         QIqZ7jbsZV4y0J1j9mapK5HSUa2dQpixSS+2h3Yu7a0DddJD5wEhrohM0iFVmqJxITjs
         Vlc/vA009E+CkyimJK6gT2nF7i+o9LBob/T1weOTWpLGJO5mrWrV2PGMUdV39im27o2h
         efx1BZevZwrU4i+AWvJSeRBVgOQhkUq8BD8g1HQQ1W2lA82sF6vllYSF8m4p+jYVFR5g
         eZ9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="p/cULzh/";
       spf=pass (google.com: domain of 3ks6gxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS6gXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i17si496332ljn.4.2020.11.02.08.04.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ks6gxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j13so6654346wrn.4
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:ce0c:: with SMTP id
 m12mr14013286wmc.114.1604333097658; Mon, 02 Nov 2020 08:04:57 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:53 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 13/41] s390/kasan: include asm/page.h from asm/kasan.h
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="p/cULzh/";       spf=pass
 (google.com: domain of 3ks6gxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS6gXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

asm/kasan.h relies on pgd_t type that is defined in asm/page.h. Include
asm/page.h from asm/kasan.h.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
---
 arch/s390/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
index e9bf486de136..a0ea4158858b 100644
--- a/arch/s390/include/asm/kasan.h
+++ b/arch/s390/include/asm/kasan.h
@@ -2,6 +2,8 @@
 #ifndef __ASM_KASAN_H
 #define __ASM_KASAN_H
 
+#include <asm/page.h>
+
 #ifdef CONFIG_KASAN
 
 #define KASAN_SHADOW_SCALE_SHIFT 3
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl%40google.com.
