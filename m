Return-Path: <kasan-dev+bncBAABBW6KQCUQMGQEQNMGGZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D205E7BBB9C
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:53 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-3fef5403093sf11248025e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605533; cv=pass;
        d=google.com; s=arc-20160816;
        b=tLsSi39Va5YqHLCSm65HCzzyeZB7zhhN7e7JaOzI5xjwamLe533Ak3R4HDu6TAB6kX
         /Dz67UbZIUOmJow9ObMQClcXrAQEKoWnUAJPqK/HuzF+EVrA0L2T0febODjpxxcVdaM8
         UKio4L1UMQuyq7IkLYC4KbaQUDjGRCKUnjEzADB1gdd7aZUgRgalYtrXTU99ua9vW/K3
         44khB4h3X69f5tqlXkyRoqkHDu8ojpQcuBtvInLxLLyiW809q0nZrCyiO5SR3/b0hHSd
         nJYs0pSHGdaPfssFX7ozQhvATNEUa2U5umYEUh7TFj2fWee1Eowhzj8/97uvufDCxRPn
         6ccA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zDobSxBhQbEDZmarYz07b6q1xpydwHcXeLRoSiBc1EE=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=dOHHt/fVWmDZLd7YwxkbcAmqwQv4EYQDdMPPa+vpuI8uKAGB4MAMrlzAwhpIluzIN1
         v3BY/caugtW6k8N7y8fIQY6DVAT57QEgG3nhqC+dTrNB6Sd2QuVk8u6iMjkcp1B9yEAK
         5w1UeCWNANZsjlJt0/akrQlwU+pRRJKo4BDmLRnwojzd8Kh4QDgHcmClV182s4VNg2OY
         w74tptAg5ylJE1v2rzcNxAyzuI1WtwFRdbMRD2n0jCctKhxea20dMRGKWMU3kHOOf4Nb
         7/ucmNkr7YhyUuorXBU2zHd3Chl5yQAwzW7yHe/YpCtahBlSpg3tFTS55Pt6EUn/sKkH
         5Hqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cfUq+xwn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.205 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605533; x=1697210333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zDobSxBhQbEDZmarYz07b6q1xpydwHcXeLRoSiBc1EE=;
        b=oLw4kEdHepLne/5PFaS9WxUBD5/t+gTW/ZArlHcC8vgJSdxhx1U3ransnbdkvk79Pr
         HlXy5qJVyFyrz5y5N0LGmUIrHvdmmkawR3xeSpMX9s1rfMIHu809rysF0T6VVxWmXe1K
         Th9cZ9LX0zuKcfNTtUB8bKioQ8i40zCk1pwXcyskU6YpTyeIOwejaQ/fcEnPKPvu7q70
         tOAX3jtdffkG/liy6bkVS7dR4IHCywxk3lWa+a7lIe9OH4k1Oe2x0Iw81TEC9f5EcW/w
         rNBJ3ROkr3ypa+mTvZ0C94qDIpSi3pxIeDa678uOOyhULEBUpHi2dNfmUuEOzXx2k3+o
         b8aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605533; x=1697210333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zDobSxBhQbEDZmarYz07b6q1xpydwHcXeLRoSiBc1EE=;
        b=hdQMBkiNMgQuc8YjFqTh7L1NmU8hgZhA/FVse0c2bd8qXLC7ypnp+RVJMYtzLyyBzt
         MVPIkiwdIldaQij/KNk69U/Ln3W0eDsvrPspRhapxCNqez76fLwP6kNJmuSSbAot68L2
         N98m3f+BhcXUWShmXtT9dkLd1prcBIBh1+wSUThaSnzCBU1wjrgRhx1xFr+IDC05zWjs
         S/WWvmpaHHr/Q+2AcX0OD+yGzKooqzHMsr475eH+2gsG39W5ZjmQtvon4CA4dlU/8CzY
         EFPDlWMqY3HonctmVDWZwM+oOUqMCXLxuhG1lydks0GEszVoxjOmIaenfQjhxhcaIrOd
         lySw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywx55WzZJSjN1qcSvN/46xhVmCSi9wjbpla+0EndV/8dwSjaG+m
	kDOX0vh5Gtj957UOkduWWJc=
X-Google-Smtp-Source: AGHT+IHaYYjQX95WTwWRwfu1MO2x+e3IQLO9loKYFI3hGzYEGuwwcNb+0Ix9l9iPi2Qw1YOT+K26SQ==
X-Received: by 2002:a05:600c:21d7:b0:406:45c1:4dd with SMTP id x23-20020a05600c21d700b0040645c104ddmr4338580wmj.14.1696605531974;
        Fri, 06 Oct 2023 08:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a84:0:b0:323:2f57:ee78 with SMTP id s4-20020a5d6a84000000b003232f57ee78ls479880wru.0.-pod-prod-00-eu;
 Fri, 06 Oct 2023 08:18:50 -0700 (PDT)
X-Received: by 2002:adf:f450:0:b0:317:ce01:fe99 with SMTP id f16-20020adff450000000b00317ce01fe99mr4626571wrp.9.1696605530433;
        Fri, 06 Oct 2023 08:18:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605530; cv=none;
        d=google.com; s=arc-20160816;
        b=fghcKWf53XFsF6Z5UNcrZMaHrCtCwjk22EVvykAOkFcJgyfFhieGz3CqtWaaQFR/kB
         JIpPlS4VN5U9/EQ/B6VafnLjMzI6zFt1mcKt636Me+T9KwucTbC68t8ZWk/SDFYatpLH
         3k/mn1eEK/3iszp/8+aBZVlnsx14QSUW6/edigOIU7GUdPRgVjxX57buxrDs+DvKPaGm
         jMiGssP4zVMMCkzcmRRwTbqMTFlcFNv48c6MRAev2CnTP0Q8iJUefzhIfcoHXHGqcEyG
         lg+dOCIyKLoK2LyF9Wl52MPsB8UChhBDk/OCmC+PJsSBuu6kgmH/OMWYfujJRjo20BeQ
         f0Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7bRSqkxN7Q+9ijSJoX74SBiGUljonarnkrx60Wx+bkw=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=iBcwkIi90pPfoHW3VSN4PoALsZkUMkTwz2W4yIO8Zv3GpaEkFnjTJ3p16yMDsclpkf
         9p8AL+dsZ5E9/vzk4J4mlCo4nXfuSu1yZ0dsP0QZwjzTFqDQeqcMKB902CALUPqYwuXa
         ztTZ/5BWdiRxeFFt1EVLYuaxn3RbN4ORvtPTOelF4SWIDoOjpUHv2FvoKhf9ZVU0oZ0A
         u5eLjBeArLBmOoogi1SI2/L7+n4rYKXCxI32KYXM967Au5VQwQPpxi51YWwtklKoaoEq
         yURayoK+Xj29DkOx31wkn1UnaKEzsNmZn9lQbWxChdtPIiKjC9U9ou163SZGa9RKGlu+
         tYmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cfUq+xwn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.205 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-205.mta0.migadu.com (out-205.mta0.migadu.com. [91.218.175.205])
        by gmr-mx.google.com with ESMTPS id bp30-20020a5d5a9e000000b003263a6f9a2csi81287wrb.8.2023.10.06.08.18.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.205 as permitted sender) client-ip=91.218.175.205;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/5] arm64, kasan: update comment in kasan_init
Date: Fri,  6 Oct 2023 17:18:42 +0200
Message-Id: <4186aefd368b019eaf27c907c4fa692a89448d66.1696605143.git.andreyknvl@google.com>
In-Reply-To: <cover.1696605143.git.andreyknvl@google.com>
References: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cfUq+xwn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.205
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Update the comment in kasan_init to also mention the Hardware Tag-Based
KASAN mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/kasan_init.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index f17d066e85eb..555285ebd5af 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -300,7 +300,11 @@ void __init kasan_init(void)
 	kasan_init_shadow();
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
-	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
+	/*
+	 * Generic KASAN is now fully initialized.
+	 * Software and Hardware Tag-Based modes still require
+	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
+	 */
 	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4186aefd368b019eaf27c907c4fa692a89448d66.1696605143.git.andreyknvl%40google.com.
