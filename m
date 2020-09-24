Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKOGWT5QKGQENN5EAQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A474B277BFD
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:26 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id s12sf387743pfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987945; cv=pass;
        d=google.com; s=arc-20160816;
        b=fSeq4XClTnH4QaqFQ90sfEUS4Ytw+LQ99EKPO03nBx4vEmslf4jrFAVVHWU4jkms2S
         irfyT7wHFXJPeHCi9ZOgcMHJacJELQ0Crs2aGNZ/gHz7MyStEZ9Y9DWtrJPJUpryd0zg
         du0MHnocRBacHusvMeb348c6otk2SGjJbXw+5QvQ1MMs2hxZrD1HWdtZ3VpE2652wj4S
         c9gl04Hmo12Y1fJqrlcGB9Ifnm07Se5KQVEcVRSAveNKT/xHPDXLd6eScqhz0KZFNywB
         Bb3ejVTDksCH87WtHcXzVusc74bBo/oWTHDlUWxbjYlXSYIPBvkgqzLdQvAhbQ7knaUQ
         oi2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=t2+OMRMgN8xo+ceLaYUZQ684UEjvYEXvwr8YgT8HAaQ=;
        b=w6eoXf2YF2/RRIMcQiRQC6O60K/QtK31xsgJbBTW+BFCQTEfNQYCVHkcegPwtpJzVM
         ePm6MtJ6sUdWxDMPtU9hEXxtF6TVQcpjAKChEUv42/VOgkeX7bjmKA/2X0tBUpMrt15j
         SlaaiOM9dQ4WVDkhB8gocYX6x3Lm0bcAObS5qmdK6DsifVeZ2h8UyFUhPxA6GCE+5Yr2
         A+eIDKu37gXastS026tpPD9tBWO4dvnGuAOxN+pfU5Og74eG/Cgszt7PCBYgRKBC5h7i
         GcI8fuH/CaMLvksmbP1S6Iwgi/x61mcYLSSOT2tHm90vF0Wg6sltAmYLFhPlZbzcwMQ5
         pJ/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JIbAlw2W;
       spf=pass (google.com: domain of 3jyntxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3JyNtXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=t2+OMRMgN8xo+ceLaYUZQ684UEjvYEXvwr8YgT8HAaQ=;
        b=L/RcDcEb0h1S3MaG46KwCtyqn2OlLd7XluyiX9GZjBEHU3lrOIesY1l8PHdOLYttX5
         J3JU67YDyxcwpYEDjMJRTVK8B+Bwqb3jVNXm/aEf+QLY2a3XWvlyfPZajSet3QyYtSCs
         JGzfSD71toHAc7F44TSWn4EQniTowxhrutZEB5/AdU5Hbsr4V+Lryq+ToR4RACezgPN8
         yURRk0jU+lbxxalJKyJ8qIp+xKLrHJk96+C+DyrKWjtZFCt78/LZi8IEV3w+n5E0177a
         zXW5srIHyUMXVH5PRDW3fBegVbXpBcAZg99rZaysvIhX4Jxc7TkqMR2qyQEZNxJNX0Qt
         PBcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t2+OMRMgN8xo+ceLaYUZQ684UEjvYEXvwr8YgT8HAaQ=;
        b=eAQsSV+6q12yYFmcYwEEt7WQvsY74uoy4Zu5U7oCare0JVVM9UNYs/SlPdn0aj9Haj
         YibQaFe3Jzdd3judnyzACC2nbnZEwRWYj7J1XG+AhG+ljT2Fez0u/FLLLE2E+gBc2atE
         BciNc6sbHzlyVRhsTuK82MT+lWjAoKVYpx5P15INk4R6NvHch/SJ8kY5CvjKP1DBZX/G
         3sYlWeJ08Ga6H+I0ZiwsYikAoY0IheCHRsUzTr7sElNdOTayuHucYX0oUKj34BidF1s/
         vttXCYWnsTYn8VHQEVrUoLelbP+TKsjNOzT88D523mywYl1RZUOUM0PynJnR1L/ZprdG
         lbeA==
X-Gm-Message-State: AOAM533l/Y237YncoFbo4R6wg2c5E5rzbGBVe3/H5Edz6TG7YcDXhnOx
	cFgOOyvDeF3iDDSz1OzZEFw=
X-Google-Smtp-Source: ABdhPJyI8I26xPaPsDYj20atHylAkewxKZnYsb/gmVIRP3RFsxaHeYjQ7ELkCfDhEiUOnWop1mvuQg==
X-Received: by 2002:a17:902:7206:b029:d1:e5e7:be6d with SMTP id ba6-20020a1709027206b02900d1e5e7be6dmr1383191plb.71.1600987945409;
        Thu, 24 Sep 2020 15:52:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d90:: with SMTP id v16ls246920plo.3.gmail; Thu, 24
 Sep 2020 15:52:24 -0700 (PDT)
X-Received: by 2002:a17:902:830c:b029:d2:6356:8743 with SMTP id bd12-20020a170902830cb02900d263568743mr832182plb.40.1600987944823;
        Thu, 24 Sep 2020 15:52:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987944; cv=none;
        d=google.com; s=arc-20160816;
        b=T9ODIXQMIVFght4xPx2oaSTcwQwVHzwhVukugP9iDJoPXDEEsD+GIOmj+7JehQpvaH
         KQ6jCrs/kqK3cn9rVRrRGktgZb7dI29NdIsCu88u5HRW+vniYSyF1WZByTBJrMNpX3dF
         04FJDkc0jhHKQ41NZwEEokFn/HCkgNtGSdRNqASgUM4caIhxyh6J07mD0424+f40mCk0
         gXiXw9XooOxt0DxahUWsFeDmJZReM9Oe/DpvIz1C8e6xbO1EYrdliQPAFbwBwV9KpdYU
         pbbzCaX2cva3i9uahjne284WEYuen3dmnX2VHLw6dfJzxypSWuTqQIskQylRuqstNeXR
         aEcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gEuj2b9WdC9oBanHgBD8GdnBbbRvvuF2rkOpQJigrMM=;
        b=YDnfRCFSG4v7W97U0wzlBetvI+TY4yx1QIHeeqIjeXd1pkDAS7F1J6d49qUYN67A0j
         a/puLUkPKoPQLLdmzBmdiphJPDMyy2W5NXW9KwNlD4W/83l+NE/haPNmjqPVLS9UNeY2
         8gWrYq3ey/AVHSEVpB+FysS2OIK0eEDsPlI3VUq2Dul8vhXEhSDP2fucxzkwifkg1bU4
         UNg3+zixSee1y5hUVx0RlaWXWHCi/l+XJ+ZvHTHjlNtIU4D98rOkToNKak89W0cj8sNG
         2sY+OFssZG772qdhB37bwcBHE/Ksa5SNQ29vdqtLup2ao3ndxKNrVraC52q3suQQQoxe
         oWNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JIbAlw2W;
       spf=pass (google.com: domain of 3jyntxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3JyNtXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id d3si54461pld.1.2020.09.24.15.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jyntxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x191so704919qkb.3
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:24 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5387:: with SMTP id
 i7mr1572849qvv.43.1600987943938; Thu, 24 Sep 2020 15:52:23 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:45 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <04d60f57ea65706bf38450d29a64e34a69df2123.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 38/39] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JIbAlw2W;       spf=pass
 (google.com: domain of 3jyntxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3JyNtXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e28d49cc1400..8d139c68343e 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/04d60f57ea65706bf38450d29a64e34a69df2123.1600987622.git.andreyknvl%40google.com.
