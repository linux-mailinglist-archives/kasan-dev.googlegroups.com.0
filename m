Return-Path: <kasan-dev+bncBAABBQ5B5GVQMGQEORYWK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id DD132812416
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:48:04 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-50c21a1733esf6518256e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:48:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514884; cv=pass;
        d=google.com; s=arc-20160816;
        b=kaPUeP1fT7wxYB/FXQ6EvMQxnp3OrrOONfdavanxP03hm5MPUcojt2bzxHPKBFWSGm
         tttVKbgav2N/1YDkwQxCon5FrpQQESBvrXwjniJwAqost8UMj7hiVDJdMyYqe+2kKi2p
         fdQny6LXPAGnUAG0DZTh6TXFaGOSjQAfOeLupaEBooiblXj5rQZUZ4EL2Bv51gVFb4CK
         DMIBqL2t/uiRKBWqO/P25YmY89H5e6eVnjyufMVzLAmEY5NmcS6oQ7OX1cJ1W6CVdX+I
         Yq6jCzFcmDHCa1RZyS7A5hw2Ssf3h4xaJkJc7yOF2jr+cXD++yrgDdHlVBVPQPvEnqN5
         pLqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RYMoG4Ol4M1ik8DmkdpNdNG6AwQ+UGGghwPcGnkHFvY=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=Q+A5MHSje2zThGoYe6CopXe2G6hKEoLXWGbGzEyCT4sDDB6dIflXhW9khlAGewwa9k
         gZiBd/mEQDpWrvT9+EvU8hdqlgDXLOK6Vidf1ekom3UBapN0M961odIVIUj8AxlB2Axr
         RctvdmMDSf86LsjVHqv9ADJyFIASAC1jatkUHRJW0ZlbUy3mDLFPaI5p7qSheh5zh9aO
         a/AFclZ0EXkFzY7xT7SdkvqpzugTL9K6jEyY/n6Is+Gmnvm/4vW3Kw4eMW6+0jSjGim8
         1xO34OX7A29cjfSj7UsVq8wGLsDTBup3FvYF/3oG7kO1pH9jH/Mg/3sAnlC/EVWz2iwH
         NTUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mE3jhmI4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514884; x=1703119684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RYMoG4Ol4M1ik8DmkdpNdNG6AwQ+UGGghwPcGnkHFvY=;
        b=tkqt3phFvE53rtYb5132NTSbG4xE2EaSz2nYxcH8MJ1sclwNHJZmGgm78RLnJekz2I
         6YGW0ENyTcAyf+wKItZBhINIvmvkgukQZGkxOczTlORtUy+OFzlYVkSqcJkdoiESJocY
         88pvjkKqzUhcW1qdn5OGz6EoyrrtEld4hBycsSRtJ0AAcDk1JVUhtIe8KTpzS3gSypJg
         wKz8zouKv2uQpJJJP4dHf2qd6+G2QRemfwcYyes1z9CBWABgzBoQ4ilmjRquycgYH1Pb
         TbMGiMzw3gn8cns7Tw9zKlc9kTOKb+ToMnBhlAMrc2iU/Tb1ikpYJ3QKsGrQPdKYwMwh
         kdVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514884; x=1703119684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RYMoG4Ol4M1ik8DmkdpNdNG6AwQ+UGGghwPcGnkHFvY=;
        b=v69CTZHB0Q1pPfVledRF1YfBnE3si8SsRTyr+xCKjaVgQiqBkN5lNmNJnUjjL686k/
         MbA+aLtQPsjSOsC1KAQOeGjn9nldLisEM+vy8xLFuoIRGNtM6dJKyPuGL7FE0TsSoXcR
         fpGxxFHexK5ar52+hLOZsxZt1/5asafHKGydL6JFrX/J3aJKg7VTZNBlqu+52YlkEEuN
         g+hDtcsLhagja/c2nXplrzw4AvCirjlkVbknLMgUMI2nsJl+9FwHD4seuyX1SFfqhbwI
         2XVlzcveufThlArBuOHdWeK1/2xbbqeH26iKdRZbysheX9aaUjb/oJYaCNhr1SPHVwo+
         V65Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw6Ir/aa9Sl1OLsPrTpVz9CVh9PkaZJ0ArCL3nOdacs0tg/wFgc
	zwjKcJSeCv2aY4JLb5tNXhkc4A==
X-Google-Smtp-Source: AGHT+IEe2dkd1nn4XNISYn33LAjQ+mTu+SCVCH97F2rPm/+tNOhiZohvNqWFBYsEc9HJ/3qJuE7Ohg==
X-Received: by 2002:a05:6512:12c2:b0:50b:fd44:d187 with SMTP id p2-20020a05651212c200b0050bfd44d187mr5092902lfg.4.1702514883923;
        Wed, 13 Dec 2023 16:48:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac7:b0:50b:fcd4:97ef with SMTP id
 n7-20020a0565120ac700b0050bfcd497efls1217132lfu.2.-pod-prod-04-eu; Wed, 13
 Dec 2023 16:48:02 -0800 (PST)
X-Received: by 2002:a05:6512:3e1a:b0:50e:1412:57e7 with SMTP id i26-20020a0565123e1a00b0050e141257e7mr666923lfv.8.1702514882096;
        Wed, 13 Dec 2023 16:48:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514882; cv=none;
        d=google.com; s=arc-20160816;
        b=yImYxqC1Q1yCKEDNXA7iDE3V3CW3FPk6cvB/XYxuMobPwh610/ZAiK8yvxANgbXl70
         1OvCfc2TqUFKsMGbvD1yruGgwXv9csSGL42gBZuLOjwlnGC5YWNehuMeRqfeVs8DaFht
         HHo8tBEhG8C6/Hr6gyNAIXcbeYHOUdrQXGYkoRZJeiCNuFtO5piyb6WApG8yDEbXzdc4
         zqxUSQmEtyg7xt3w6C5+3zTUp8jC5zB5/+vNW5In/7rYYdjvsR+hZc/34NTHadJfLa1W
         BvFoYm5kuopD6biv3679g9iIDB/kkbGmxEthmHgxxUJBPuAq4+enwPBCSWWn/xR9jGXv
         vaXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fOHzqh8IZvvUQEcAVUngjlYsg+ArhHiPZJoDS72WUGY=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=AuwbugKlJB/peCsQwKPsKnUkRh8hkIr23k6fYv+aV3yxeqHxWjJu9TQkbzIUO+VLPa
         nPsPQ55+VexXNPA/8K79UE6miyle7wLCB/mB3d6zR3mXgCNFxx/ID+YMP3tK4CSAJG9C
         NPCIVCjo+6OmLRAqa7g5PdAxpXXlysKGlaEUpjx0NXIGuotYHDeQx3T/bto8X2IuJxdE
         +BAzeAKdlIlrdAs6GqHCfuvG9VGtR0MRzvlOQXhwbvJo586XhZDj8bUIENmD/aQ3lzjz
         uKW9ca/h0Fz5x6JlgnGPVVqJTFnO+XAIvLCZPSbp4b2H4tMSlGTC0yiTFDE6Q5536vts
         aZ5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mE3jhmI4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta1.migadu.com (out-185.mta1.migadu.com. [95.215.58.185])
        by gmr-mx.google.com with ESMTPS id 14-20020ac25f4e000000b0050bdefdd07dsi539252lfz.12.2023.12.13.16.48.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:48:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as permitted sender) client-ip=95.215.58.185;
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
Subject: [PATCH -v2 mm 3/4] kasan: memset free track in qlink_free
Date: Thu, 14 Dec 2023 01:47:53 +0100
Message-Id: <39bbc4d0bc72dfaf02f9dc63ee6f25a8f3a1719c.1702514411.git.andreyknvl@google.com>
In-Reply-To: <cover.1702514411.git.andreyknvl@google.com>
References: <cover.1702514411.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mE3jhmI4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.185 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/39bbc4d0bc72dfaf02f9dc63ee6f25a8f3a1719c.1702514411.git.andreyknvl%40google.com.
