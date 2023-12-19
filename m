Return-Path: <kasan-dev+bncBAABBAMSRCWAMGQEMKN6HYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 88BAA819228
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:20:02 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2cc8aa28cbdsf2789361fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:20:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020802; cv=pass;
        d=google.com; s=arc-20160816;
        b=MzU5TSkg5TL77a9/D3DOMo9XI+Oa8xDRVyVeyHOQj8bB/mKyJseTNPA4zj4JoQ2VC2
         WWTsEfWYj7MQIWMg14aj7vNiZoJrayTc4Ligit2FQvhI6b0ynCTyz9PrgSUebqikT5fQ
         gBR+XXP8ZJt5aZuTBbChk5vo3MJlva4QyescoFqNdvGT6c9m7ZO8c5mIOrtQEOrs3100
         MC2gUIGa09TG9bW+CMCcVBq49Xm2xZ7WNHujRUaRLWYPK3AFYQMf2bwYAox4C78JxeHN
         xdELJWfUr/zqrLu8kd84ew2XF9Y1qIeAXcBfunrmZzMqsxtIzuC6LGG3ADRw5E2nNV/w
         QBtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZeE6zLYabt+vo8YVOlp80Cw1hQd81zY3Z0fObxe2g2g=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=G0XiyA9cHAV8BxZpY/XALl0+GZYGxmIcJBNEHV+s52P1HF08tcRIzpvS7+FXn/0cyc
         vnBUhUNWCpi8d3ynv2cfR/BgdYK/2hvXPtQ540ushAlyDgcvZ/y0XBfTjGO0dlDcIfQh
         Kx+fltgLa+36kUf4gaXELW8NTIIF1rvPutWlVmvLnTZA2+cZI1Qa/fgH1OxlfJ9KT3+W
         Te7i5sT/nE/qL7M8HOn6YNpxNWo7Ri1gq2/bvXTI/qPgc1ACD3LvLzSAWFoLmJwqwwBU
         IRTvJgIqCFkW2Pcp3Ya779+vXyQJgdQseuOhvcu0VlHoGZWNL7iMkitFH0tqj5KYtCBX
         q5Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qSi6bCK8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020802; x=1703625602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZeE6zLYabt+vo8YVOlp80Cw1hQd81zY3Z0fObxe2g2g=;
        b=VmOIYQjH6OnKeE+2A3JgiqALMTb5ckX9rSVJdSfwFsViXFOryh5DyMMZQUBhmRKti8
         6NRlUHsbOW98M6oLDsGwwzQHEcVeKEJoKcaRU8q7BCrC/LZPv6ernTwUROZu1787uCc/
         +fU1hSGxZMbSWSANiGGTZr0Mve2bjpudSAy0jiJp5uIn9iU9AGTVJ/EnmwDqY0V3KOLT
         dpXi2jqjm3MdmSxbmImh9YKgN4f8pTd83d02UKlAZMiaXKOPQUQT2nCw5xlxitd7qYoh
         oMEFzxiK97z+KhQuEjLuzGALMCzniR39eiJzqUv2f02NPacfC6CvLH8aDCeVsnm2DAE4
         gSdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020802; x=1703625602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZeE6zLYabt+vo8YVOlp80Cw1hQd81zY3Z0fObxe2g2g=;
        b=Ipr+uSLk94xIdBX+2cJZhuEt95VRl4LZDreMyUMRph9eoe5PJA5VSDqPC+jodI4S+9
         YJHSXCYYVm5zZhY2tbIaky0YwCWVJzGJzTvoPtIFcE/5/rmJCTI0VphxCJZ5X0ZjMmx0
         fDRhVNP3Kb4Y49MbWR7uSUU3MORZz+dTunHsDWTRBa+MRKUVh1j6H/nTbIEHMPz+24BW
         MIvDv0LANB6mblXCU+5bcLvKIRGyash1IZmwPfNQB6+tdIUg0/hNWEFdYDwfy9HoNGLU
         KjNfX9Js+C16KAoyFGH2TREvQ1l8JAekpoPaMHTV0MPGtJ/ElsbJ+M5bxwGNx8vzVGVl
         zAFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOPtzFbaOJbb8rVGVWaccIdU0RlSNU0HJ1WpeZw4vd79Mr9RKU
	t+LUcaVIE9FI70/tmRwxEzI=
X-Google-Smtp-Source: AGHT+IE9K/7zpWQggC+aGICFbThVHD4on6EpHVh+mHrdbsNwtJddSfGeVjTG8qhqCsIkyk+/rVbo/A==
X-Received: by 2002:a2e:9907:0:b0:2cc:7035:24b2 with SMTP id v7-20020a2e9907000000b002cc703524b2mr2042508lji.94.1703020801381;
        Tue, 19 Dec 2023 13:20:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a454:0:b0:2cc:6f45:8ae0 with SMTP id v20-20020a2ea454000000b002cc6f458ae0ls1143279ljn.1.-pod-prod-04-eu;
 Tue, 19 Dec 2023 13:20:00 -0800 (PST)
X-Received: by 2002:a05:651c:489:b0:2cc:857a:a2e3 with SMTP id s9-20020a05651c048900b002cc857aa2e3mr610638ljc.21.1703020799596;
        Tue, 19 Dec 2023 13:19:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020799; cv=none;
        d=google.com; s=arc-20160816;
        b=zcwg3VQ56tuy6Ifpbo/sxslhcFWPaMVZFHBdgGmbL8dSab3j71TG3GnLxjOJgJrpgB
         Ugw/gnLgSvqzHSM8IhRylfH9a84nhDUkm6xWZb0wS1OIQq26gKFejeXc6oDD1UnbnVTM
         4reHVUDY/tJdLNo61AF3WMs0ECDJg1D15OUtxy3inupKfo8rTuGfS8FnuKlpfyEoqyqy
         JVPrY8leoH1PDf0/C93PWhsyJCAaozG/54jpFAX+jlVrGYsMifrpR2IaNwVCHn5UbBRU
         Px8eNHohgPITAhDG6a7hCZR3VfeGKvRYZAK3HcY6JexYyl89JhAvlyE565VR2qIBIGoO
         thmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fOHzqh8IZvvUQEcAVUngjlYsg+ArhHiPZJoDS72WUGY=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=Y9b87HzUV9WqIGIuQb7rWqdQw29m7oC/u0TbcEjghs4AB2itZ0iz6YLZuI+NkfMEn/
         GFA/jaHv0P8aFp7G4inQ6jBySQtxnHLSdD4VvY7abef98KERmTzTAke8Qd35IrcHYFIN
         xLij+JcHTVTixbVP7DNvGpTVYClBF87lmsjdN+F3dux5eR5cBHbjsPKohGOdFG8FvoCg
         OsXmAqQyGb/7rVWvXUJJrb0PdmRsShuEju2EthemG1yAOyrGZO5zVprVEWHz9Grv+Mnh
         5M14SYy71GSph71ZMl7cMV4eTMlC0Lr5iUXRmFJZo3Kqpqd540I313opX4+YWcySuN1Z
         dGpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qSi6bCK8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.186 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta1.migadu.com (out-186.mta1.migadu.com. [95.215.58.186])
        by gmr-mx.google.com with ESMTPS id f10-20020a2e9e8a000000b002ca183166c5si971757ljk.7.2023.12.19.13.19.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 13:19:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.186 as permitted sender) client-ip=95.215.58.186;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 mm 3/4] kasan: memset free track in qlink_free
Date: Tue, 19 Dec 2023 22:19:52 +0100
Message-Id: <db987c1cd011547e85353b0b9997de190c97e3e6.1703020707.git.andreyknvl@google.com>
In-Reply-To: <cover.1703020707.git.andreyknvl@google.com>
References: <cover.1703020707.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qSi6bCK8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.186 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Instead of only zeroing out the stack depot handle when evicting the
free stack trace in qlink_free, zero out the whole track.

Do this just to produce a similar effect for alloc and free meta. The
other fields of the free track besides the stack trace handle are
considered invalid at this point anyway, so no harm in zeroing them out.

Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/quarantine.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 265ca2bbe2dd..782e045da911 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -157,7 +157,7 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	if (free_meta &&
 	    *(u8 *)kasan_mem_to_shadow(object) == KASAN_SLAB_FREETRACK) {
 		stack_depot_put(free_meta->free_track.stack);
-		free_meta->free_track.stack = 0;
+		__memset(&free_meta->free_track, 0, sizeof(free_meta->free_track));
 	}
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/db987c1cd011547e85353b0b9997de190c97e3e6.1703020707.git.andreyknvl%40google.com.
