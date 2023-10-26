Return-Path: <kasan-dev+bncBAABB3EX5OUQMGQEDF53MYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A5F317D89AC
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 22:28:29 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-53e698fd32esf912a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 13:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698352109; cv=pass;
        d=google.com; s=arc-20160816;
        b=z9+WzudrpaCc7o2FhzdDgSxsy3D/CNFKf8Im4S8t59Un74G5Lsq3GUqYo2tADa5IIu
         ZidjmsUrZc3ANd1x4CMuTG3IMK6CATGeMQdu92Y+Ns/LE9CP7Zl8aFgEKze/bQWMjLPl
         yXTsDRUR6//MvAQ0BWGN/Bhx5z67HLeBqQqL1cw3G//T7qKoJwBM3IsLzdiUelesJwTP
         XI3pqrXM00N2d7Z7G7OA0SBJcjFaEsN1jOgTwGkBiunlAFp/BMaQlzvJ/8+v80U7N5xs
         uflZUxB/Sy8Hq4qEOrpXLkq/00UDZVlsH7nKdJfsPy6g1d/O8tVSVGTGNxYj8OrPe8KK
         yOiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=k4pN5osCbgjDtTeN0cP1G95sXIcvJ15cSlcWUF07FlY=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=uv/gtEggwn0y6WRb7+6EHStDZTi26BIwD3+qVU8InL1WAMcjbWqnPUHZJkcDMgTlFM
         dRztmA69fdU8p5kfM8dk6A0ZO8rmUzy9AId8c1wCO+AcvKzp88r0/Al/M7ahj1rEOIkQ
         A6OWCEfbbZqt7a2jmyb1RkNTKDRBNIJFin6ucdZwA0cjEqsZLA2OuiIDPjIYWHYGz08d
         AZy1IwNk55iMtJ1lcpzNq6fv+X+Phydr/1FDgVXqrf7jTkLSviCRZ6PQguyM6XWrb7gQ
         D5GYtoywOLtkKignpNSdZP9/CGDltRRXHx5Y56MsnlYeSMGUTpED/Ongv+uz7iNz8OXC
         ilxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W2lYs0jB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698352109; x=1698956909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k4pN5osCbgjDtTeN0cP1G95sXIcvJ15cSlcWUF07FlY=;
        b=Suwch9wo3YY8KSYACgxUqlD6MsyGmWporvQ3KRML++vO+ys8NmbO4M4lnbkioq5kjG
         zH18hkCJBNFNV/XfArgovb118GGpcRoojOlM1ezIWzj2t9kguaJBZrkkuiUFw1U154xr
         afiQPVef0EIGtIJv/UFfF0H2z3usvaLUUcvkrf7IKKcSf7DmKUDYw2zzFin6Lj+s+R9/
         TuFi9pmvNUwsWBQVeyQXeFuou5pWIpnRMc42SzyDALRlGYa4X2ZFfblsXfIRJPbiJxwS
         3usyRHXSwbI2weNSUjep3j5oCrniVx76Ca0jp7dfc1sqZkhlx62kfsWhxolDqjetkt7j
         PPQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698352109; x=1698956909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k4pN5osCbgjDtTeN0cP1G95sXIcvJ15cSlcWUF07FlY=;
        b=X+22GO+gR/YhjY4Z5PVziIepx1tfRqb9KQNy9l8PTDsGslZq2KkOubMMMkFaif3QBu
         7G+Bl/JbkkzelOy0HBc3wVXIF1xMQNnl1qsuyQRL5jpJcDAclP6IFI5QyVRFuJaEenKl
         FguL+MmJuz/emXZTMqKB11RfrykyhMtxbNJfLASyl5ClWHGn56QFu4d9sF1tyAU+QYvg
         /FLzNmzbDxvSyVWP1RJV7CDZOQDXq3e4Ert7bV3b6EGDN4O3x0GQ1BK6dakZfdXe/6Rt
         moNm/HHsUqnO9L2hQoLRAKNdtF0606KcEgqk6cdcIXlNANCcRrZW3XohopTi3NZzdcgI
         njYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YykC/82v22wwgEwBiWzmb++fpuc4r4WIIO9PdCkGWrK3d/5LvZn
	DjDVEABMJfw+zqfepkSwQrQ=
X-Google-Smtp-Source: AGHT+IFzKNrdPh1w+oawCa4gPaby4JtvpJT6hcAZhNpLbB92xRwyMySIYqOw8Ugz5wCYT8xMOfwYTQ==
X-Received: by 2002:a50:954a:0:b0:53d:b53c:946b with SMTP id v10-20020a50954a000000b0053db53c946bmr37373eda.2.1698352108624;
        Thu, 26 Oct 2023 13:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be9e:0:b0:2c5:dcb:9764 with SMTP id a30-20020a2ebe9e000000b002c50dcb9764ls280175ljr.0.-pod-prod-02-eu;
 Thu, 26 Oct 2023 13:28:27 -0700 (PDT)
X-Received: by 2002:a05:651c:10d4:b0:2c5:4956:5112 with SMTP id l20-20020a05651c10d400b002c549565112mr518038ljn.35.1698352106909;
        Thu, 26 Oct 2023 13:28:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698352106; cv=none;
        d=google.com; s=arc-20160816;
        b=daZkzhGdonJbpy6E7qr6One0IAtQW9XtmYB6mNOvVVhJeaQXGfzGor+zEJoxnh9dmF
         pz8/bP4xDUsplrnMxvhJtjRHX1WNvksz8JgVGNAlyHRuM/duKnEOu/E4uykTExaIz+x5
         VkIw0cbvTLHb+3sZiqGOxPb3Nc1j/N71Zpij55Zkrq3HESB646MzIXvdsWQKXHT9n2kD
         ee3YaqEFIY0r+VCW/8uS7fwlQnGSe6za0+NO9ZzILw90ahiJlO7v1gkhpNqvFGRXR8FC
         nVENuatj7+tgde8Fcanm7btHJW0xY5sUb2m+yL75E/y+MU+zyWW9K0Ai+YW+VzwZyaai
         uaPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kXYcCHbJg58Ieumk8Pr2f/O/cn/d7Aaxj+WCDVOiCJ4=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=eTxnux57MGZB6xyC5XDZUxwWbnw8I1PbPy+Lo7/udbl/oAZ4HXbjo5l8iSIHb0mDxl
         fYQwaf4jVUN+vOZn2l7/xAwsnXZHB+eOnnbfQoS67CKOR7Ls3Vmjhw6sNOt2iBiSJPlU
         KnODzMyOonzZEpLFlHbQIMfj0dwAqev6G0eW8G00g5kkjFMqOceWYAZ1jq6mEIbJStYY
         Ho6fV98zBDResjYOln+1IJ7RJDMRzuaDuHpEiDVnYzP3KEXDpxrWkjZsD/9W7GWWRHru
         QkzRhCqsgUpN2b61nNWFSqkd9UgFV0JhGcKimiu6ndCf0Er9Nlg+J/ooAqAx7NPbiI8l
         1OJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W2lYs0jB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [91.218.175.180])
        by gmr-mx.google.com with ESMTPS id b12-20020a2e894c000000b002bfbc15cfefsi239ljk.6.2023.10.26.13.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 13:28:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) client-ip=91.218.175.180;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/1] lib/stackdepot: print disabled message only if truly disabled
Date: Thu, 26 Oct 2023 22:28:16 +0200
Message-Id: <e237a31ef7ca6213c46f87e4609bd7d3eb48fedf.1698351974.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W2lYs0jB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180
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

Currently, if stack_depot_disable=off is passed to the kernel
command-line after stack_depot_disable=on, stack depot prints a message
that it is disabled, while it is actually enabled.

Fix this by moving printing the disabled message to
stack_depot_early_init. Place it before the
__stack_depot_early_init_requested check, so that the message is printed
even if early stack depot init has not been requested.

Also drop the stack_table = NULL assignment from disable_stack_depot,
as stack_table is NULL by default.

Fixes: e1fdc403349c ("lib: stackdepot: add support to disable stack depot")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 24 +++++++++++++++---------
 1 file changed, 15 insertions(+), 9 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..0eeaef4f2523 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -101,14 +101,7 @@ static int next_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
-	int ret;
-
-	ret = kstrtobool(str, &stack_depot_disabled);
-	if (!ret && stack_depot_disabled) {
-		pr_info("disabled\n");
-		stack_table = NULL;
-	}
-	return 0;
+	return kstrtobool(str, &stack_depot_disabled);
 }
 early_param("stack_depot_disable", disable_stack_depot);
 
@@ -130,6 +123,15 @@ int __init stack_depot_early_init(void)
 		return 0;
 	__stack_depot_early_init_passed = true;
 
+	/*
+	 * Print disabled message even if early init has not been requested:
+	 * stack_depot_init() will not print one.
+	 */
+	if (stack_depot_disabled) {
+		pr_info("disabled\n");
+		return 0;
+	}
+
 	/*
 	 * If KASAN is enabled, use the maximum order: KASAN is frequently used
 	 * in fuzzing scenarios, which leads to a large number of different
@@ -138,7 +140,11 @@ int __init stack_depot_early_init(void)
 	if (kasan_enabled() && !stack_bucket_number_order)
 		stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;
 
-	if (!__stack_depot_early_init_requested || stack_depot_disabled)
+	/*
+	 * Check if early init has been requested after setting
+	 * stack_bucket_number_order: stack_depot_init() uses its value.
+	 */
+	if (!__stack_depot_early_init_requested)
 		return 0;
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e237a31ef7ca6213c46f87e4609bd7d3eb48fedf.1698351974.git.andreyknvl%40google.com.
