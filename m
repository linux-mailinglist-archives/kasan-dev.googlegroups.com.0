Return-Path: <kasan-dev+bncBDN7L7O25EIBBNPZQS3QMGQEAEZ7JJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 141FE974A8B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:46:15 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6c3554020afsf94968986d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:46:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037174; cv=pass;
        d=google.com; s=arc-20240605;
        b=RMlI/6PQExVBbXUr2k+UPHvOAhFOPIsfIUduHfbNp0NVzP2kNyG/RehchO9Dw1isP5
         XEGoZa1tH+a9WNDKcx5GmZuGu+JWOHCYTnUhHNp0AHbm7tPRv2/CcpOfXZ87xubzdkmq
         iTcDj4a4YIF7kZj+IvKuTsx8v7qrWYR4ARDSmxEryumgCPaGLmUAI1m9g290C9MtL9Gw
         j3KPW4tkrI7QeRaxOSZX6iOK7uKYJC6IN+bGmcWdapvuomo11SLC8YWXvVxuaQxwxu3g
         c4xngCa3DBTHkOFM+ukKE28UZolbPN7CDRgvb7rCzwfarP5R41/O1+yExvUh5kJ3YbbT
         EckQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tzMu4eTOqgvc+jzpwf1QLJmWFnIiPG2Pvh/qGxybsVc=;
        fh=lAmX4v8AJG+5jxo8lADjx3M2kw7OEHdyyZ0V/NyufF4=;
        b=eQd723UxvpH89faI1yv9+ppgv8z9VNjqlExV+3NGsgbyZ3qIlqNJ4vgDELscqfIYcR
         YbpRNQZFYoT8XmL2XGS7LSYz/c+yt6gG32wRsCJGeR40V3F3DIN+r4P5ueWnpino+1WT
         v9aoMqFlCFTCjQ1Igu8RFNXGuv7HRoVgRvfSFiMwtGSFUJEMKWUDYHiguOHx7s1m6ooC
         0afNpL3Ybkjj/M4vjdhZ1dPzObQNHVQBz7c3J5AZHQ3j52VnphOSEvBWkyc1GyxWkFlC
         j6bGs86wwCuY2S/6jwFSc3oO81IAbI2HyRTC+V92M+pCfLreHng0WgPhdrMMEfJ2myU6
         Ua4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fv9Uxp48;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037174; x=1726641974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tzMu4eTOqgvc+jzpwf1QLJmWFnIiPG2Pvh/qGxybsVc=;
        b=r/YwEG6unkd5GddPCeVlrdEx+f+S2T5cTjqu0ncXtO61dzNPVZ9IWbjjcgYcY/Dcuv
         x9ErnLyHK3i6/L8/XagYSkcxuul38DTt4scaMHXz9kPrHGRf0FZVRJVLuYSIMMVs13n8
         p4L2EZA6p4mbIq309mJQj01MohVv19beDKMP+KGMqRNEIQ9cdvnwX4uMiyOfB3A3AOYD
         bNcNr16ySQcEzmvG10DDpGi5vle1RLhvP3MUza6E3UpD5tzffxwowjDr0f3EWs2GiGVw
         5hekTe7OBU+SCAhwcbpFqaW+t7/UUcalAIsiL01ATOanY73LBtRuxavFsRjUMO3h6kR1
         DYGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037174; x=1726641974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tzMu4eTOqgvc+jzpwf1QLJmWFnIiPG2Pvh/qGxybsVc=;
        b=hPYzYja50nNPdc8NoilC/28Q30pIUaciB1OO7MvgMapZAyzW/4Q0Ok8TgzaexMNZxo
         AqDrWjN7RzFoZWCAVc8x0T/1yWQMEznLoWOJb/F8Iax6O8Kl1cvlcjnJuIRyC5ZI9lOO
         N8ayiGgP8Yhp3I+g/G2ktrjdfb0ULEbd3tujuSMjjOYGFX8mbU3p3aj99BphryxEm72/
         vLOkaR+UFP7VwDG6VvWZGojnfdOL+OxwD8ubkJyG5blUN6G+5krtwO6RyjiFfx/TVnTI
         Az+5TeevKNTI1uCY06hCmwmZoVPk9NqLjU3VBzy4LeN+G+e9f6q0EcVuSNdjz0siYHjp
         lx9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgJHU1f8xFOCdSW5B/CV5VYKH+TRDxk1Jswgc6rDKBLvapI5wKBOeeYIgj/oPTXr1MUcolrQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAPXVwRLqQ+jepo/go9Ca2BLkYa93JP90YNQGnmDUoke6SwU/C
	JTe5JNvnpNJKpjlwEvJg26GA/00dLxkFZ/oK2QTNMIf83GVl1480
X-Google-Smtp-Source: AGHT+IFP8sb07rKHLDgJPOUBKg4PHasML4Bt6VVp8AuypdV8eCZRvraNyv7tnoqaezoSFT6j/MALNQ==
X-Received: by 2002:a05:6214:3f89:b0:6c3:5346:8c6f with SMTP id 6a1803df08f44-6c532b455b3mr200000696d6.52.1726037173741;
        Tue, 10 Sep 2024 23:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e47:b0:6b7:9a07:4191 with SMTP id
 6a1803df08f44-6c527d4aff0ls93815916d6.2.-pod-prod-01-us; Tue, 10 Sep 2024
 23:46:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTue8c98bsgyDfsHzyhTwJZP48cofQW878+bfesaY8lHi7WnhEEDglxsi50YQd/NRAGYaos31Wmnc=@googlegroups.com
X-Received: by 2002:a05:6122:2a06:b0:4ec:f8e4:e0bf with SMTP id 71dfb90a1353d-502bffa0509mr12364695e0c.2.1726037173063;
        Tue, 10 Sep 2024 23:46:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037173; cv=none;
        d=google.com; s=arc-20240605;
        b=eblIZ5d2wvH/cqmqOC6Fv8WrSnnm6j+DuGlmR7+MXGM7K213WA8UZEOOLRVB2BLNy8
         C7o2N2LYqBeoEj/xYWgvdAln+rfc4DzA8e17oOz8nfjaLSgdNGiduq/zOgDrPYa3NuN4
         rn46p3oHP8bXP3B5wMQuPSaOLaGMiUu52/5Q7Rtjf5aa6d8WJrBmWPI4VqB5ZijYznx8
         Fl6eVdwLF061+i9jAsV0T809kw9+vrsG/c0SKmzPB5WI73MI7jof+sAKPU2ad7Ftl4sj
         AhV3ymz6nbFiN9DBZAtY3LSWEDm3gjmwqvXFU0bXRj1d3hgYy7idssRLgxDf1wkgaaCj
         abvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zm6mEmpihmiTwCFfdHniUQp/gJG3DwrB6e0k4OJohiA=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=V3cLwWB8rnglmQnrXhD1H3Xwku+1NRuz7Xfgl9tqi1wCW5N9ohkr+H8jznd5EXAE31
         sFFlmOWsFft0dykafluH9bK1Y+PIRokqp1rWZSlGu1622KvV3XRD/e7k/NHwM4rXalSQ
         +eBFoXV8iU14074ap27+7zhi9BD7Oz5A9DcKmBaxqIGForu7V9I4vPGGd8zAcMunbgak
         bi3agD2DrUn1agSS+h3cyiMLX1Eiy3cB1mIdQQ6v2Ga7IcuOBP95Cm7UBr7od2ECFu/e
         x0qKQ8vU55oaLNkg821HZqZoeXf95WKRJibhtgT2J7X/afbqsOq6OdLWjxQY8K+ARuQ9
         VeeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fv9Uxp48;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-458230c72d5si3632121cf.5.2024.09.10.23.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:46:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: sWTumR3CTLCfTerCZFFUIg==
X-CSE-MsgGUID: A8BvWS0gQh6tWXge6DZ0tA==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36173001"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36173001"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:46:00 -0700
X-CSE-ConnectionGUID: TlC0q2XjRdmz/RXKu5H2YA==
X-CSE-MsgGUID: ouEYEDaZRMK+unGJAsKkGQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771491"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:45:50 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v2 2/5] mm/slub: Consider kfence case for get_orig_size()
Date: Wed, 11 Sep 2024 14:45:32 +0800
Message-Id: <20240911064535.557650-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fv9Uxp48;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

When 'orig_size' of kmalloc object is enabled by debug option, it
should either contains the actual requested size or the cache's
'object_size'.

But it's not true if that object is a kfence-allocated one, and its
'orig_size' in metadata could be zero or other values. This is not
a big issue for current 'orig_size' usage, as init_object() and
check_object() during alloc/free process will be skipped for kfence
addresses.

As 'orig_size' will be used by some function block like krealloc(),
handle it by returning the 'object_size' in get_orig_size() for
kfence addresses.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slub.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slub.c b/mm/slub.c
index 87c95f170f13..021991e17287 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -768,7 +768,7 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
 {
 	void *p = kasan_reset_tag(object);
 
-	if (!slub_debug_orig_size(s))
+	if (!slub_debug_orig_size(s) || is_kfence_address(object))
 		return s->object_size;
 
 	p += get_info_end(s);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-3-feng.tang%40intel.com.
