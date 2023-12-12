Return-Path: <kasan-dev+bncBAABBVGL32VQMGQEA34BGJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CD3C80DFE4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:14:14 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c9fa16728asf39297661fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 16:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702340053; cv=pass;
        d=google.com; s=arc-20160816;
        b=ebmLHLKUBv9xcHWsIppGLy+voovNmvMidQGGc23Bs9WVU3y07D6gWIDue2OMKMJPMZ
         wKNVOb52BSStkoIAVLEIUKpqvEMRRe/e7b7vfBiZ2KAZft6T26/kBPXDkrAPb/msijvG
         u4FAsYIcvND0Uj5qMKEa42v5r5VAmSWLv0ZUDhqaHdMR8PhpchpE236xxxiBPSpSjJat
         6CPbt+VmZaODjU7GzS/D1R1buKj0fiiqyc3MMkqJRE0hOstX+VCfxuq6R89Lr3H+oPdY
         s49CfFWMT3bk3vBqAN4zRvKQHDGkDGKZ6A2ppmqkdAXlj4O/kVLZMXyTvjElNiBTCnY3
         gwEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kzxKSVhvB2l6/6EqFt2tdIhdnRwPAG+eHHy2ZVptRpw=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=GwYoOuMTg62uS1gCJQbHPBJLudkI4MnBbRH1Pvhk0tlmy3j+4u2WSniRlh1TuUZZbX
         VoN6eRpbibHiR0t2bbtQQ2VrB0StghhARcKJHkLAKqtrF5vz0nJ61ONu35DdGr9vMOOM
         WjQ00KGwvH/UfLTmzEDB/6/x+7g2FqkbX7ed4UrnBe4bL5kZ1+x0GAv+auoPWAveJBin
         8anTLF4vx6tqle5lwzTpeXNRdKYa1ZxLMsCa7WtLNMEWEw+6lTyBNwRHYQ6Twp7pSCXT
         4pm7T5SaT/zQ7OsRrvq95waJBzYUaFzGW+d4DXAz8io5ezorKpmPXicmCY2LPfWGAbem
         jbLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AhuNEvWc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702340053; x=1702944853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kzxKSVhvB2l6/6EqFt2tdIhdnRwPAG+eHHy2ZVptRpw=;
        b=UxQXVzaEpONTsrBYAzeRiUVpnjM9bU16Xt/5056ikfpZaV7QnKnwDUUpPVpER0yKC7
         vq8Wz5GeeJzRUTrACKFeYonDHqkzeA4j3POezgLa5L6fG1E2ocsBABEld8WAHjNVKRto
         EKyqoMOIE6vFfLMPRiHo1lCapOiCKhDpMu+g+fxOU9QJZn27EkB+r18bqUbs7emWh5p2
         f9/Ci/hYgoKCT8Pv+oT3vrbtJCO12ilIpqtsYhIyFoIxGiiaUi770NzkQ1pAXIxwDNG/
         trytfSs4mvRduMaeBc80lFLM9VxS3TAvsuOct5igwlq7o2DMS3xtEgToDQR3ZOuxc+HR
         xJGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702340053; x=1702944853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kzxKSVhvB2l6/6EqFt2tdIhdnRwPAG+eHHy2ZVptRpw=;
        b=hZ4EUDxWkA75HXXGmd0I5WzOA6ZCdcUbEt8M65pSnJTdKFih5w0Y1S/YKFtGg8DI3l
         Mp1PPnXUcrLqLQIILHzxeHrXpzoqNtjLinImZOlrty4I4vd+xAaBcQnKCOv0E8kJnosF
         ZztnK5U/1X/qoliiUSKZXYDPwv3hZ5HRuqXkC6BX4fVY/bYuo+oPn7VXV9dFRdqthJqr
         FOnTG7liCtuubc1Y2Tauszxsaaq1FfaiCuOzWuTz3HJqP85RRHmVSCMZ4zWxrCdRTbj2
         O3WB/MUsxM5LKmBu1GbBv2cs+FukcAidAPennSMxwz82nRQmHuDQUz/RfURMm6nxI66d
         6u0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxaAYtMzPUMA2KifAtw39EgDP3Sj+KvD45fVBjILfbnemF5h9K6
	tF00e3De1llJM1ekuHZwHfw=
X-Google-Smtp-Source: AGHT+IE92nuWRdQ4Tp7m3cdXGbWT/69WsuMIND3nKr8bvcOECU5dODNPoKDozEIfgAli9xu79RtjHg==
X-Received: by 2002:a05:651c:104f:b0:2ca:84f:2fa0 with SMTP id x15-20020a05651c104f00b002ca084f2fa0mr2067345ljm.25.1702340052840;
        Mon, 11 Dec 2023 16:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2123:b0:2ca:70:d358 with SMTP id
 a35-20020a05651c212300b002ca0070d358ls473790ljq.0.-pod-prod-05-eu; Mon, 11
 Dec 2023 16:14:11 -0800 (PST)
X-Received: by 2002:a05:651c:1051:b0:2ca:ddd:ee22 with SMTP id x17-20020a05651c105100b002ca0dddee22mr2049005ljm.81.1702340051316;
        Mon, 11 Dec 2023 16:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702340051; cv=none;
        d=google.com; s=arc-20160816;
        b=bvi01gipskY1fPyrMpdQ7scqBAFlFYu200kFgZc7C1btuKFJgFtmdElLFXt/qk2Ruo
         OB5Z82mps9W3QGZUEi0fE4HWwSYbvn9EHMLtCGcGzmEI48vvmloJasG4/0ZJ2XUkNikj
         LBJ/u7liIjXmkQXk3zDLmnj52RdjBXFMkmo8aTlYIWvkGynsrEqBqfhXUSM6WKYefVD+
         QIRKSiZwo6fSNIQJIf5mWcBPRI/BNfHrs1+KPLEgE/o3iv+IOJN6ojJ2PSHKsgjOc61Y
         o/8/Fb1DQgOd0R8dZpw0LCEGP/J7nTDgZwbera/JAk8QqBZFxRJ2lCJDMqZVWwsAiHea
         X5Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OwbAGppKL3WPs8Dt+2mYc7aec7Z15bPqx/lY8lY4n/4=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=zLkmP/nW/TK96HaneWiUkFsz3rO1FawiDLn7DKUCwH3ZlN4YdHxq/wx1C+iK3lVsge
         brVB2mp4HytE068BhXBylHUf351g/jhWNzYWejK0ikXfTk8F4VO+Lt3xGfrLMIknAwbA
         LQKyZF0nKQtabCLJR7fkU0wzksWm5UsnuvUJ3qpjSZU4YLpz9KicnLyTgNnLvhWnskUY
         Ctvz21Yn29X6K1sx5sEZXd+NKya3oWEiqxYBIEVoJlX5hIalzOpQiquv21XzayKXLRDu
         d6dY3XH2T1iIQyqaBLBWqO7kDdmdUZFkKh1OV3pRnhODSZWlemfEf95tPqTkURpjBG7u
         vFWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AhuNEvWc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [95.215.58.172])
        by gmr-mx.google.com with ESMTPS id x24-20020a05651c105800b002ca0f31f41dsi371146ljm.6.2023.12.11.16.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 16:14:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) client-ip=95.215.58.172;
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
Subject: [PATCH mm 3/4] kasan: memset free track in qlink_free
Date: Tue, 12 Dec 2023 01:14:02 +0100
Message-Id: <d0943bd69fdfe27fbda20fde9b143e57c825546f.1702339432.git.andreyknvl@google.com>
In-Reply-To: <cover.1702339432.git.andreyknvl@google.com>
References: <cover.1702339432.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AhuNEvWc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This can be squashed into "kasan: use stack_depot_put for Generic mode"
or left standalone.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d0943bd69fdfe27fbda20fde9b143e57c825546f.1702339432.git.andreyknvl%40google.com.
