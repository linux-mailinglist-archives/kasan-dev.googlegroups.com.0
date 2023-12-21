Return-Path: <kasan-dev+bncBAABBM75SGWAMGQEZKLAB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id CCA6881BDE9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:06:44 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50e4dfdb01dsf1023906e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:06:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703182004; cv=pass;
        d=google.com; s=arc-20160816;
        b=uPQFOxOLz+RNI/TZieMJ6X8GoswYEZKtI680xGVItDCLWavyC31R1Yr4S25mxzgBFn
         Gq6m63XWUK0jKFp1ouwFor20BJK3xdDXMiS6aL5kp3jUb7JEsSl86E079RnFmnDFyIAL
         aBnTOVGAhjmnYA3V8LJCVfbDq0T+62YvGTXOcI1zhxPocQfSfPl+/XBlliazmI4FOFwn
         +scWyQ1a5JJ4QmFcI8o2++CsA6cTNC2fjec8seQrqZkvPm7M+jEghRt176wwu6tgb//0
         z1JKQqREzeUwvEHrdgbctDQdNVGzTofYxM7ous2unPymsq9F+nbitZjMprtgUpnSyyTE
         tunw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bEqsyO3zshGYyDRL9NGM6ZXel56pkp/ygp4ab2KQ+cQ=;
        fh=YdJe40n1bQZ8Zp3iZn6I1d2ZUtlNbbOfpFd8CFgERIY=;
        b=tQpz+gqCV1nxp+97uIDmWTLeQa9pyCe/s+RDxMrCQdApEnT6jdTiOi8IbQUvLAyXQg
         gjlU0aGKF6htunmrI8Zz6HUZVYD84lA2sGjU9v6RD9K7z/SZFxs6DWRiGnMsqRe5i8cM
         S5z7BYjDP6LGQFl1uJ00Cltk6qwDKqliw2aINiRocvGR7l5AqjdMkgjthCvF/tzd/rBz
         gE7kR1/kdZ5q1MODC5yF7Kq5iO+SDeB1qV+ofvv7tzmMiREFP0F6BMM1dgMCRw7Vk2Kb
         lLpFP6gjTc4JLrfC4I+Ob48kxLBqsAXAXMtKdo2blyVrKrGxLttdDLxc7tNhVZno8ciR
         mI4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=de36pMIh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703182004; x=1703786804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bEqsyO3zshGYyDRL9NGM6ZXel56pkp/ygp4ab2KQ+cQ=;
        b=s4QRozN7qGCPP64UY1OoOX3h1xZgfMDBtQWyKqL64UV+RXp4RFPlDNDg8dFqAYYY+a
         PfHZOqkUCH92Q/t83NYOSWhemg7yf9hYYWGTulP9Ms+Lz0O8R025qyBAwZ4ueHPtQq9B
         Z3ffMw8b2ZqZ5dWzUEeE3pJhCwFqt1zZgQxWIuDoUsqGLLLess1SoL9E0kXlyka2H3xO
         24E0kdiTj+qU3BtL1X3BgY+O2theqdCHyl6zOD+f0N/vYq746o8dE5XYxE+hW8T44sGu
         0D3mzG20X1bSkhzN10YafV2H1hVwua4d/YDyeORykPwxcH0tH9SV9e2Mk06r8P1UtZa6
         7QVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703182004; x=1703786804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bEqsyO3zshGYyDRL9NGM6ZXel56pkp/ygp4ab2KQ+cQ=;
        b=a79IGcy64gLYfepwJ/y5Gw+e5ZSxAKNBd79CqvLjV2CO7wgsZTDyayp3eskWZkh4hJ
         eQu1T38QYn7B6wocSsKXsQRW0k5ZldHcVgw5FwC7Ih8ZuO7sAHriFRKTeP7Orw3Hrilp
         z8Gkodg7afudSszPZ0TncitV0MQgPUc6+VUX6c2SPKQt6EH4rnunUYKrtOIHrBJTMcHT
         Vs0N2W78FmboW5qb0GHGjf1MbwoHCInqajiQ7OGgi9/4YPY3VuOPcXi9mT86RwJ0s20S
         MC/ur6AzYiUivi6GxkB6fkO+Q1ovFoju1HYXQ/YZeIYdQ+iYv7K4LNHM1QU+eH0pmMfe
         9IzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwAQkAuFHTmeSdvGbpG6yHkL9ZU4crsS/5kwDkbf3Wimembh3D6
	ymzShgkMree7pF460A0aVIY=
X-Google-Smtp-Source: AGHT+IGJvvChvPPVrt6/XLLD4tXiXVilhq168aOCBrbPxgBzV1GKKvbgqMePvlDKb4YDhl/CRMmpEw==
X-Received: by 2002:a05:6512:67:b0:50e:59fb:ef1 with SMTP id i7-20020a056512006700b0050e59fb0ef1mr11098lfo.98.1703182003577;
        Thu, 21 Dec 2023 10:06:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1291:b0:50e:3dcc:980a with SMTP id
 u17-20020a056512129100b0050e3dcc980als618640lfs.2.-pod-prod-09-eu; Thu, 21
 Dec 2023 10:06:42 -0800 (PST)
X-Received: by 2002:ac2:4184:0:b0:50e:34d7:ff24 with SMTP id z4-20020ac24184000000b0050e34d7ff24mr9052lfh.118.1703182001838;
        Thu, 21 Dec 2023 10:06:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703182001; cv=none;
        d=google.com; s=arc-20160816;
        b=r1T98GoCG4wE8WQDaLYoazEGM1FwBAfR4QmqsGMjP7bt6hsshicD7qxdn65EkKI35E
         6F7K8PJpXnLfEtJbGdxkeyTgz+njM9SnrbkBvCFtnJGX4EQ70xiHcqVqU+LoA8eIHpZY
         xxa92qMHcG/dBI5AZIQ5tgAyq3l/AfqvexHQ0tSFYu6KNvzLRjh2SBjNGkxFfFJytmfV
         4mNUyKr7JgOY/Ehm90K8Kwam28zM5mxS8u2ZJZIUmpWhqHIDQ7ZJbc2g0RlZW9eH5PtS
         bXwhOhn0KtbjoQ7Ec+kjxm8QCtAlt2ivJY8ga/DB7+1FVLzdKrmLcyQtJTJalNyZJC5K
         6uoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=i0GLSbu+FVh1lkI5GuUWSCHjI1Tbl3xktQLpxtmlTZ0=;
        fh=YdJe40n1bQZ8Zp3iZn6I1d2ZUtlNbbOfpFd8CFgERIY=;
        b=Cljq7PeXAHngTvgks4K2CZzBU7DBBn/7hRshKGT+onJLD1TPgUn/E0bN6Hae9XPzy/
         r5iOyjp+LrQOTVaSTZ4pFhrLxKBivM5YDQiDy7NxFETpUKZbQGSpf5ZaUha+HAY19nzl
         r4EZHauzy5QRhEgiGE8ouSn0sOT/ztpDiP2qNTS441cNQkW9I1u1QL4y3E4wWaMwu0iX
         +XHlc8rNU0r3PeZdUxDrvu6SfU0/XouCej48qlrQROe59eJx56R1J600H91hJGM4WIxA
         BhW9zn8RdaVRy/j3IFl6bGfiQDqQXM3hJZbGu0pBvnevhmYv6E+BzsjAdxoUDj4/QGgC
         weCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=de36pMIh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [2001:41d0:203:375::b9])
        by gmr-mx.google.com with ESMTPS id m7-20020a056512358700b0050e38296320si106347lfr.11.2023.12.21.10.06.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 10:06:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b9 as permitted sender) client-ip=2001:41d0:203:375::b9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: fix for "kasan: rename and document kasan_(un)poison_object_data"
Date: Thu, 21 Dec 2023 19:06:37 +0100
Message-Id: <20231221180637.105098-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=de36pMIh;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Update references to renamed functions in comments.

Fixes: ac6b240e1ede ("kasan: rename and document kasan_(un)poison_object_data")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/shadow.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d687f09a7ae3..0154d200be40 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -130,7 +130,7 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
-	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
+	 * some of the callers (e.g. kasan_poison_new_object) pass tagged
 	 * addresses to this function.
 	 */
 	addr = kasan_reset_tag(addr);
@@ -170,7 +170,7 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
-	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
+	 * some of the callers (e.g. kasan_unpoison_new_object) pass tagged
 	 * addresses to this function.
 	 */
 	addr = kasan_reset_tag(addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231221180637.105098-1-andrey.konovalov%40linux.dev.
