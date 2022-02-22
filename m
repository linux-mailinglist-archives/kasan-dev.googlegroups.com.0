Return-Path: <kasan-dev+bncBAABB6NR2SIAMGQE3K3AK5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 114C14BFFCF
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 18:10:18 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id h82-20020a1c2155000000b003552c13626csf1123453wmh.3
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 09:10:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645549817; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxvo8d3b8cQCz1YL6DFAN+aQ7c0x+6RYszFroOLycJE1ddFt4wsQvP73IiLWQx10mz
         alHa0hray1NVqmji8v3HqDaOW1HGIg/L8X3TVacAs6FFGIbtdMNY6xT4HKSm9uZ+ih6J
         SysN5PRcEFXpE+aTGJtwMUdMD9NNu3Chnb1XiPRWyRRCcHsWyrAqZ8nXvBzv7gaJbAKG
         8wMNZUPK0jBZPnJUQ5t83YAXJw7DIE+34fyWOYfjcHs5IquVEZorh7U2g79cKF30axon
         BT/cRg9Fasfrn42MS1oBvBYcMVjt35/ACKXBzpQOwR2pj5HjR5rlvsSmuT7idrbDKE1B
         61kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zvMREi7lJNXhGudNky46rJ22i0zmHo+oGPvtrrtLHPQ=;
        b=gJzJ3UsXJTBaWKVTV1JfJXY1TuvfUkF4SlZ34wm1C0q1TECiP6TGp+AKLl2h2q3PQC
         e3jBN4lOVTjK2+95gvdw+HflGwU8F+3byyrEbX2U4XEyLAs+7v6YUJDX+N0BWtz9bhD+
         mrbklNGdr2TqrNxvzje+xVcBBc68p7GrruXbGAeDLG0wMXGhPgegsXw2s/+hmZCSW1OC
         3uaFmJy+eXwprxO2XvuVnolXsURrExx1B9PPQh6s4+GyN+MbOwywH8yeZbefWJ/LURB0
         Nm6iXH4Li7oZlEsj2r1sHC7MxQwM5r4WbVYeY9apOB3uPLgUv4ilYr7VXsEu09Vlr/VQ
         Eqfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xlYQqe08;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zvMREi7lJNXhGudNky46rJ22i0zmHo+oGPvtrrtLHPQ=;
        b=BUsSI/kHOLQxtmiSIDAdWuSMN94d+H/qfB8tGmFMdJ1EaztmeFqq9vSlTDhzRWiS4X
         h340JrR1xb52f433fZ607bYBGlMm5AppdM5yEMMqP+EXGZxCpd0jubVSWh8AoUtR9WQh
         j22Hhj6TxWj7Z3jB8OZjNwRBZwh9RdIsmMV+gUfJXWYneSpWvjJ6cuXo0WVcFgLl7s7f
         ovpFEfgt9MRM4qD2CiW2xUmdklflc//PnNlqQgDBIrSRXWkiSQuRKSOSNgvMDIdhKOq3
         MC4iK7HuroD7BraWFu96WaYaJHgslq0NXSqwhE+8VS7KEsx5O8mQY6rUlQwvTFKVpI3C
         OL6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zvMREi7lJNXhGudNky46rJ22i0zmHo+oGPvtrrtLHPQ=;
        b=n1Hzk9ywDm3zfqFVFXlyYBkq/kL3I2B4c4gBPA0vtJP6tQGM69z1BoBwCjPcR7QWI9
         0dQCQZqh4w2wIFlsalRreB7wiGIkP2IlSswYSkN2IjoeWxvGEl8w6JUhYMAphgnRHvdg
         T6G/T7sq8v6LUSFNrw02f0mceNoWSgjWJvdP3VyAkWwU86478GRVxm3i69uzlRPeSJ6W
         48FeMoqt8puEgUQrjElgzAY1g9WgvoR4Eng7C0fozj1TNDmvK6EBXG6Rze290zH0BEWf
         L2ZZEui+DuTTU9U2iSBFwsFr2SWlU2BYZxvKlcnrDHpDj7yeaUy1p77gUSo7qaTpKncS
         ssgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZabdGFGofXqeAf0Qm5cr/S3ykO6FUCO/xLtURLqajYVXOSiZj
	itbWYHIu4+fy9QmANOjx2sI=
X-Google-Smtp-Source: ABdhPJx+zfN6vp/J7dekitoxm2ASNmpbgTj3DM8t4fndntACee8nQY2rW0ATVV81ZZy8i3ryJJzo7A==
X-Received: by 2002:a7b:c215:0:b0:37f:93c9:9b40 with SMTP id x21-20020a7bc215000000b0037f93c99b40mr4262489wmi.17.1645549817747;
        Tue, 22 Feb 2022 09:10:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc6:b0:351:e65f:f614 with SMTP id
 o6-20020a05600c4fc600b00351e65ff614ls1606768wmq.1.canary-gmail; Tue, 22 Feb
 2022 09:10:17 -0800 (PST)
X-Received: by 2002:a05:600c:4fd6:b0:352:c2c6:8f34 with SMTP id o22-20020a05600c4fd600b00352c2c68f34mr4279515wmq.186.1645549817079;
        Tue, 22 Feb 2022 09:10:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645549817; cv=none;
        d=google.com; s=arc-20160816;
        b=ljZYamQ4iCkkJJvU9NLFEmuMVhDZF+GilRS7wV5MyhPcfaMomUJw2dze31Od4I4D1j
         ChfD/itT0r5ycvwtZyBv/RoPg08U3N0FEOrxsNOAjZaNRoySjmiNshvZuPyWliUUAGRL
         Y4UaveRskRQZDUyF0u25+YrzRQoY9XDwKnYsHTLkSpIQXaENAmOavbD4rRbHXkgWUslo
         p0XQjLzE2pM0MKRNujWPEeqM3Mm9k5e9w3iZ5o20S9ag8JQxcnTY7dQ3Zr6joAfGjmO2
         JACEbW+/YBiezNgw905koGQC2o6VMX3keSfzwy0rYe8chqgeKem3heTKwJukW0PvuS2+
         NKww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=WtAp4AiQx2cFjDZg+kQhLqiCnjHbJYbWSztFNAebJV0=;
        b=YoQg6adnc+tIgyrdPnbrYKmEoFjhd1YZYAivmLNoHpl9UddxAPChW7coCMY+2gsbFJ
         dg4ozO65D/dGZlM/IWs61IDsaMlCOJRkwIJe8Pa9AKSUmNAKviUjnJ9RE1X6epUdFcbr
         MXFnJ7UG60UQVhqNvz69ZsSE4d5oTnKqZEK62L/VPSF/7sAVUOrz4AqQ/GNFlYEl2CWM
         UgwqwSX0omEYX0EJX9RJbl87ed5HbaaxtKQq9nwlceufx+wgFRVN8sYsllOrR/PCUlHd
         dPMfYCaLGvHSykGwpPjsOxoR9OUuWdRpxWojvZ7GsmucciI9UDmpqo+XS6orZarn8V4s
         Vx4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xlYQqe08;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id r2si146487wro.0.2022.02.22.09.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Feb 2022 09:10:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH mm] another fix for "kasan: improve vmalloc tests"
Date: Tue, 22 Feb 2022 18:10:14 +0100
Message-Id: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xlYQqe08;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

set_memory_rw/ro() are not exported to be used in modules and thus
cannot be used in KUnit-compatible KASAN tests.

Drop the checks that rely on these functions.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 6 ------
 1 file changed, 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ef99d81fe8b3..448194bbc41d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1083,12 +1083,6 @@ static void vmalloc_helpers_tags(struct kunit *test)
 	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
 
-	/* Make sure vmalloc'ed memory permissions can be changed. */
-	rv = set_memory_ro((unsigned long)ptr, 1);
-	KUNIT_ASSERT_GE(test, rv, 0);
-	rv = set_memory_rw((unsigned long)ptr, 1);
-	KUNIT_ASSERT_GE(test, rv, 0);
-
 	vfree(ptr);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl%40google.com.
