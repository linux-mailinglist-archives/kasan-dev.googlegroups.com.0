Return-Path: <kasan-dev+bncBAABBVXDQKHAMGQECDHWECI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DFA4147B154
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 17:39:50 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id cf27-20020a056512281b00b004259e7fce67sf1180469lfb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 08:39:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640018390; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEzUHLQEzWxQ2Hy2eQdyocyklO9tCllRIf9UCwUtkuA/7clhMVNTpZ07egfd4/2ysi
         ti3NHLX5Wcs46esYFX6zkjo0HpjCmGf4k07HepetvXPL57/RNU9BXmJ5LHEBYAvDW0of
         msC6DdJyWgyPe9HWlLZ1VOkrebAHopR3ofM31HydpdtyKwTbnAAuIhNSMGRksl/49mBy
         K6uztgRt6OcK5nbBVGIDak3S4vPVEPnB3FtyNa58cjA3pXiQaBKF1rnBFLSXA7pOau0c
         YTlLXbjEmrZNJD9bHIZE1RuCxX+76EY987GgzzNa1c4Ut6U2tpEw3JNWUcHFVE9Pw00c
         7VTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Y/mg0crUUnmxoojmHuhK63/0joCSPTF0AXcS8HkwVPA=;
        b=G/Thk3cCHOFuDU6Y8Zg7MpxopBGFyd3ImUsdpen7peVd5F8RUc2RgDDDsVmjpSI3zU
         GGqO2F+PrYjVbHiQM+KE0pAyLDaEEIDj81e48XkIc8G4rFRTHlQNnnEMH1hmshARt0X1
         ejzrNZxuHnQFhZSPPb1vhDmX9gvYQF7P+x5xaGYN9hj57cL29wyA2TFiNcG6p5HJhaa2
         C1EMCDHLy0M+bs1M0eeNEwuo7fzxQZK2sZ0/edR6iLr5dUaEGUDri9sHULRp92gbv+yw
         ZP6aVO0f6G6yZg0MWKL6uamt35Qbr4vb2bRrI9XdgnNQf9Lv3uQMwgsOrwIGUGMHwOTh
         rMHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vz6WWZWb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y/mg0crUUnmxoojmHuhK63/0joCSPTF0AXcS8HkwVPA=;
        b=NMqFyS9Ik1GFqnN5MhUbu/gLrRKLhPT5GtdpkbjgH1enrPWVgpBoFyUxbYJvKrATnt
         Z4CEFlBvCGHQQielMdxfdsctM1L5HK6IBApsNH/neak1JmIgZfo/tsCOfj/bDKtBWk6R
         GNbYTDh1/jCnSBWihb7ZHxz+OtETi1vGFtvl5kNFGJn0ws6K+B7mDYTRmsIGwrBAxFoi
         VYLeh9j296h8t2ab3NZHg8PAEjRquqVXxFncnFR+eqjZbaqN4uPcaAHvIwC1ECl38m5z
         kRX981Zz4wdbJIZ75Nc4VTjUbOsZoZT/RMrCgaPbAwg4AJZg6+Dj4jHovR0irHz05Lik
         7ubA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y/mg0crUUnmxoojmHuhK63/0joCSPTF0AXcS8HkwVPA=;
        b=grDSm3cPF4HCqd35LDzuuhnshIjmub0t54FEcXu+R7y5qD6p7rP1k9+yk57gzSXgVo
         62sztSBeOqi6H6zjWWwKqb2WUhxL99GmohhczeqSXYsHJH+DXzzhYgF4fADeIJEMcK+w
         Th3Qn2MErUICpK4CzzLsskXInSCBMoDXlRq/1QVkHMyf+dKZkdGc55xvhN5LYcD8yn9V
         xqPnEt1MAEu/XW2KCAOBpcRjE3hPXPcy6bkafNCUlC85wsx4PWf2P0ECTgMiPvEJcOXP
         +h2XlPhsyl5+Yx1M+eo+/C0oAmBgTm3cP8+NRnwjCfXb4hZZ/6UsuAiCV1q4lI9WzpIe
         olgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EZ7bQWLzEYraC9Scx/PuAKWeElPWiCJvacHip+n2ZQVRv+ced
	SvHXXspSTaMd8S9b7Mb8olE=
X-Google-Smtp-Source: ABdhPJxRWGLNtUyl8TQdbeHVWfuWNJuBtlUBNTcIZyA4oqT/hfK42DvALU9l7t+us09D+GxtYthyzg==
X-Received: by 2002:a05:6512:1304:: with SMTP id x4mr16717670lfu.484.1640018390347;
        Mon, 20 Dec 2021 08:39:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls314362lfu.0.gmail; Mon, 20
 Dec 2021 08:39:49 -0800 (PST)
X-Received: by 2002:a05:6512:15a6:: with SMTP id bp38mr7047893lfb.116.1640018389549;
        Mon, 20 Dec 2021 08:39:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640018389; cv=none;
        d=google.com; s=arc-20160816;
        b=dUREGIstD/Dodi/60v3Io5110akFqkBrEy6A0sqik33O5PpYmnikVq04jg0aFcnjPN
         RFZgvWVXfpXNisMGlRkEJF9tUpxFTKaJ1xxMoL+cSpa9gPHsyQYyKszqsF5M9dEgxyua
         htEE63BI14kmIkNfgGnQWtS//0fMAFZWwDIPmTmzi3ZuJg3itGE8R1C28y7YKHA5ZlHy
         k8aqioy51crm1ToYjrRYDxMuXnUNiLV2yg7N5tNPWwBlli7z7kxd+BDsBNlSz9beuQjG
         B2NBJtZQy8a0L+SREqs4EUqGEfUrtMuzZ8NiP5GmkuHmY3wwozqWmINWJroXcbAmZ0gG
         /e+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DlacqxZJQgYqXIpFXX6uZOVHwn8FgcGRJKw5vj65G5A=;
        b=YmWR4KJU1JLh+njuVTuYlpLux8CbURTy6G02PWcfopR/uyqnh1mTSHuRVBi7l+l+6u
         gvQEew2H+0FP54sd/ACcd+jd7dG3Vb6Ieq8g8pGAJP/3ZAOHqDsiC0KvEqM81h3IZYH3
         M7pkXroguptzN0ghJOPtxR3IJnGdyRAF33xSh5ED/jYhRLsZEoIwQAQrIE66HNKDlyDB
         mEiTTtb+fSGJMSKGxKzjioTrebccPPqEMYH8nwzlwIlLCwluz/DMf5OUl/UQ3soLC2w3
         RZFfSeVHvlP7C2NnRS8tDv2gJjbDhh6zQw4vXGV364+2pke3KPzbS4fByjP9+5FU66f8
         /9qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Vz6WWZWb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id v8si871949ljh.8.2021.12.20.08.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 08:39:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] lib/test_meminit: destroy cache in kmem_cache_alloc_bulk() test
Date: Mon, 20 Dec 2021 17:39:43 +0100
Message-Id: <aced20a94bf04159a139f0846e41d38a1537debb.1640018297.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Vz6WWZWb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

Make do_kmem_cache_size_bulk() destroy the cache it creates.

Fixes: 03a9349ac0e0 ("lib/test_meminit: add a kmem_cache_alloc_bulk() test")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_meminit.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/test_meminit.c b/lib/test_meminit.c
index e4f706a404b3..3ca717f11397 100644
--- a/lib/test_meminit.c
+++ b/lib/test_meminit.c
@@ -337,6 +337,7 @@ static int __init do_kmem_cache_size_bulk(int size, int *total_failures)
 		if (num)
 			kmem_cache_free_bulk(c, num, objects);
 	}
+	kmem_cache_destroy(c);
 	*total_failures += fail;
 	return 1;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aced20a94bf04159a139f0846e41d38a1537debb.1640018297.git.andreyknvl%40google.com.
