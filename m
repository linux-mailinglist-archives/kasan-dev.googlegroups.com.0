Return-Path: <kasan-dev+bncBAABBENJWGZQMGQETWPRZJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 414D7908D6F
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 16:32:51 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-57851ae6090sf1325672a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 07:32:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718375571; cv=pass;
        d=google.com; s=arc-20160816;
        b=k8fcmDsYJrbWokJ4oHAbQVnei5/T9DzI5CKozAEcKMlUkyCLRjnQmIMZzmyq+fsvex
         6zB4fyLYu/7IoPRmIryyLIWyjSbh/0HER5/pnnM4koGf0KKSIF5IshuHlW3khnem8Nny
         lmWlRQg9Yz8o2SCPwPoH++KTqLCi3EKiZ/oImjzJpJtguGPPCvpDc/uquVEuRlF3GmJU
         D/6vKqzkYMealCNDz1vh4Jgdh/fYVmnaMjVlAYwAOeHMBjtrXAh+8E0Fo5PbedzXO2xJ
         FpQDkXAfdXCeEmy9+Wonfnxw9F+HvA81Ys1h+EjF0EurEh/S/JWY9rWg+sqYNHOPbTll
         Gc4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7xDImFHan4HmhGQipCZ+HhkxEoZ7LUj7SM/eMDLGdq8=;
        fh=5QsiLObVVOJbFfAvG2Z6fccWKiLdnkw0pEmIBkB/Hpk=;
        b=kXqtjkBxHMJE3alHb/NDBiuizf7GSN0lPd4vg2HUwav+BgsCI6zLjKSY+6ir7g9PgA
         v0bonrloTObGNcuNzSP2NvZZbNWQ6Vmd6TjJ+zZnYmEh7ahY7Ru4a26PI48eYfi71adz
         fBgnlOXMpLZTwbxHtUk9xqDcjbZPKYEJcO/QwC+bICdckyNkD1eVJ2fFmYMUORuODmpd
         fjD+UMAnurV5TyVWxbeXTrGO0fCdkh/pvfnI0YY2IfjxoQJL7q11Uq7RfRJcfQ7tn5ob
         t37zRPigeSa5LQX1FHuvw6hsrz+GK5NR0vTXxO85j5aO3RinnyFoBgVDr88nUe6qflTo
         kxaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vog70K8s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718375571; x=1718980371; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7xDImFHan4HmhGQipCZ+HhkxEoZ7LUj7SM/eMDLGdq8=;
        b=dJwqksso1Ezxq79NHKgv8OB0xJN9VF/9hJm7mPC4q7IUemmO2sBl3U4NjrULy4Mmf4
         1tWefmRuWz6GWGbcemgnhoI6rZsvf/cV15luIqFYV+lvSTpjRY6RMWlld4AK4+a68GRR
         4FnWMgmx/yAeN+TCLx02g93XGzqBJcLEViZFbbBTK9Mhlwtk0sfR6AVsxhrsaEYNEZcG
         u8KLub+uP4EZ/AEV3Oxwcb1GQ1S9tf3M6H4RNfhd6/pgY2+8Jqs92ae0liHq1yZQw9i0
         G+Dnds3OWQi+4lH3yzuwCrG0nJ0xSMNn7UTn5vXisw8KUhroBC3rye9+kmB3WhSg80cn
         soKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718375571; x=1718980371;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7xDImFHan4HmhGQipCZ+HhkxEoZ7LUj7SM/eMDLGdq8=;
        b=a6Leoyq6MmTqAx5QSvMqqsKezbPKTxPw6LQRynwqh1fheQ2sT2/qerxqzFRn7oCUM8
         d1JTwmGS++8WEzs3C0B39QQIjDEa5voGd0HldLlrgHtmjWwThiI55FbdIfWdXTUy4IGh
         /vB62XcRpJNyPqzH6ExPehNv00VegR7TAfnC57sm4nRNYN/TxyhbNhUb1AZwQt4o2Zdk
         Iq3Ho51Y/CC5HoR5KWQizSozzrCnrZq/4gmYiCEW0D5Vt7wsTGSOr2Lg2u/ipQ/BM+Zn
         NQCvB2wF0DW1a6/32wERfHr3sqcvZCv+qUj7Hz+FSY4dFrj9Y4RjsMcswj0KTfyPDjbw
         fN+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV10pHjii1TI0M0+Ew9ccdbz5TLnJFPwvl1ee07iGPpWAr/72GEusVHfV+eJxQXEl6g5ujb+n5dZP+a32IWnvpXZn1BYFYQPQ==
X-Gm-Message-State: AOJu0Yx9mqlVqwmvkebHiZZV17xyaLws07J4yWAd8moTGUz8WFZha4Qu
	gb0Tn0Ry/WnDaW2oxB3W0LCaafouPvxMwfvo2gDMt8J24Vxw9ZF2
X-Google-Smtp-Source: AGHT+IEuH3m2dGe8VSveohsPeoLSgK9yU9G9HCL+uqfmBClP4+6zhkNBYUr1Pz2aiMnMZ5nJ6rWDKQ==
X-Received: by 2002:a50:8a97:0:b0:578:3335:6e88 with SMTP id 4fb4d7f45d1cf-57cbd4da967mr1960477a12.0.1718375569644;
        Fri, 14 Jun 2024 07:32:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c3:b0:57c:9cb2:80c4 with SMTP id
 4fb4d7f45d1cf-57cb4b6509els1327697a12.2.-pod-prod-01-eu; Fri, 14 Jun 2024
 07:32:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMPrihBXvbPCk91EvG0QS0tlWgO+nRHd46/gvl5xSK6yZnRblP8GsD1o8PeMWoAVHj2MlzUVgiP0O2dw8ZicGRUvJa5CnoJDBtrQ==
X-Received: by 2002:a17:906:3e15:b0:a6f:4b7d:599b with SMTP id a640c23a62f3a-a6f60d3c70cmr183025566b.33.1718375568121;
        Fri, 14 Jun 2024 07:32:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718375568; cv=none;
        d=google.com; s=arc-20160816;
        b=fEKh64Ia03FT4t7uFuQgiJ9NS/obD/2Jw2XKOZBjoVnQ4nUX0S7PbU7VSfPKRyNV67
         4EByabR2npyW6025rR72+gHQM2hq/eHRnPOHugxAl5jZUuP6Oh5lvf+Hoo6DHm2HvHfR
         f5iCuP3mw8Qby1zzcO01zj4NLqCyAos+kV9H196uLCiHoHghKksk45tfoAd4/YQCPPWu
         G0WaNiXk0Giu6kuWswr9qdkJnUsgSXazAqJJWN4JBC+3sjaz7r23euf9oIH7T5vxe9a/
         c9kuobKGQ4P4uwyusSSYPdoKV0/VqC1xTKD9gyF04biDMYGrXyQ4T7qBXcsgsopnx7xh
         hW1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oKGgulHI+TDI8kNJgxolYwa/zBW01wITWhncfioM0zI=;
        fh=K6K1wo6dyg42f7iKfGi4GfitrsRLpnbcLv1kzwYlCgs=;
        b=RBIjsn37l6jYtw9lAjJzHVkQkya8JN3ZsNuYC5qQKndbxZITbHhO9dH7DKPfVf8wdl
         uUP5OUK/w9lO+kcapc76J/q6wmYBuZK1BzykdJLuDG5wya/pQP3CDkFGLTkxNc1zS7mb
         EDPdD2IncjDUBjYDeQ+OdhqdEj6xq3DZsdVvIqcBKmh1k0oxgbmXaPBaOI5tlearF45J
         KNuEH6sThWcYzSJtgFDTkBJHXVqLFDMhU+U9+dNQ6Q3SfP4uYzkPXfZ6EoF1VAY0KrpT
         cTUtO5GZCMk/n5u99mCUcrUPECPpTNzFYBdEECGRh4afRXC4m32u13Smq5XgjM9Ik0kV
         VsVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vog70K8s;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta0.migadu.com (out-183.mta0.migadu.com. [2001:41d0:1004:224b::b7])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a6f56e8139esi6138566b.1.2024.06.14.07.32.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Jun 2024 07:32:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) client-ip=2001:41d0:1004:224b::b7;
X-Envelope-To: akpm@linux-foundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: dvyukov@google.com
X-Envelope-To: ryabinin.a.a@gmail.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: linux-mm@kvack.org
X-Envelope-To: spender@grsecurity.net
X-Envelope-To: linux-kernel@vger.kernel.org
X-Envelope-To: stable@vger.kernel.org
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
	Brad Spengler <spender@grsecurity.net>,
	linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Subject: [PATCH v2] kasan: fix bad call to unpoison_slab_object
Date: Fri, 14 Jun 2024 16:32:38 +0200
Message-Id: <20240614143238.60323-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Vog70K8s;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Commit 29d7355a9d05 ("kasan: save alloc stack traces for mempool") messed
up one of the calls to unpoison_slab_object: the last two arguments are
supposed to be GFP flags and whether to init the object memory.

Fix the call.

Without this fix, __kasan_mempool_unpoison_object provides the object's
size as GFP flags to unpoison_slab_object, which can cause LOCKDEP
reports (and probably other issues).

Fixes: 29d7355a9d05 ("kasan: save alloc stack traces for mempool")
Reported-by: Brad Spengler <spender@grsecurity.net>
Cc: stable@vger.kernel.org
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

Changes v1->v2:
- Fix typo in commit message.
- CC stable.
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e7c9a4dc89f8..85e7c6b4575c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -532,7 +532,7 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 		return;
 
 	/* Unpoison the object and save alloc info for non-kmalloc() allocations. */
-	unpoison_slab_object(slab->slab_cache, ptr, size, flags);
+	unpoison_slab_object(slab->slab_cache, ptr, flags, false);
 
 	/* Poison the redzone and save alloc info for kmalloc() allocations. */
 	if (is_kmalloc_cache(slab->slab_cache))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614143238.60323-1-andrey.konovalov%40linux.dev.
