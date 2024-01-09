Return-Path: <kasan-dev+bncBAABBXEJ66WAMGQENZZKR3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 35CD9828F75
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:12:46 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50e7a951ccasf1504e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:12:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838365; cv=pass;
        d=google.com; s=arc-20160816;
        b=rFAKfemYmACcBsKMdbnjeqcAzaW0oZsQXfrJl6h0MzB1sntmeLW0/ozNviH03B+h19
         WcW9/8TG4fXeTLvWd1C4bNbQEhikqd/CGxq7ykX0KcLeYhT5V7wLj4sJxz99fA5huJ1A
         3ctJNzkcsw70VC8Bg04QS1gAzdLSWuXWOqx7qdBvc+ASiXCQufpsFU3fy14zoBIxiG75
         Ip3xsVm1txMouMEJMQy34DUyV0cQZJK9bvaHPeOYno664Ynnl2myhkLF2Tn/uzmgaw+6
         feTGV9oGVdPMqYhK1h06kri2l8Gir937xbh5lw36wBVY73IxlTPI+K6alwiJVabiERWq
         1O8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Ex92RgJFvl2noGp3IIRWRfpvPYeOiw2veVl6iPl6ZKs=;
        fh=LR59V+RzXHE2yptcMXdGLPI79V/pXZ7ZmyhyqeIltIM=;
        b=Bn66GJZnkXEoC/TYpdnuFvbbYky/LoPWCh283vY43tcRlYOFEFuFiodMqKEbxb/G6b
         UaFm4kklG4Md47OGpgwK+OrOX2SNCwYcJ5bjM2y0u5kwynlk+ipNrOxe6sofQdU8Mur5
         BT6BmI4ADoJzupKCh8ESiUXl5MA1bOm2cqwuvsAzB6+8k/nLx1plaGhWSbFGm324+jGW
         lA6J29bdptbnAn8IrsE+SYJxBdeiGeKus7F/sO241tDcfBpsR1y8NlISeZmnaVTNrtzf
         Y0V6rz48uEHTK7Ckdi5fKZZRQXtZnPUvuwKuAQr7O7XZ5QWRT8GYlUzeIh0vEcesu1ly
         7Fkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FeUfEWH8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838365; x=1705443165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ex92RgJFvl2noGp3IIRWRfpvPYeOiw2veVl6iPl6ZKs=;
        b=KgI/Zn86+guBPgKhHH5024atilDdNkAR+WtmDSFDtLjWUeo3cDPIvhPgG46osQECze
         h0xGclE2mJSe7OtBRkay9uqhV5Fjljhw8Ik2IeW026aYi7j/lPmCXZWCQwBlgJb0/Gop
         9ioKF0joL6nL0L1FRXULTm/ynmjcYxy9dFy2fSqu1K6Ew9I2i4i/p3Vy3BqB3MwqvhMO
         foNdx4t5zd+DFe0t6+kB4Lodq1FWW/D7DPHV9RBqreabzW1p8xBFC1s/F4d5OkjtlMxy
         kI4rAwUzqnhtG//SeMbMpHNrilaYZKt/66HOY2Y8d5Q+dYqI6EXr2R4zcsvzuFNZp7B9
         85RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838365; x=1705443165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ex92RgJFvl2noGp3IIRWRfpvPYeOiw2veVl6iPl6ZKs=;
        b=v/AW6dMmcdZCWVHFQl6tVRi3xQFYyWuJD/HJt8e0tvHPZPCfCybP0gFgPx+/dOOB9n
         hnhLoqBNOFTqb6QX3ltL2lwhZu236V/1R0paQB/gGP58McZbomipakcdU7L7a7rTDSMP
         HBtKrJqIe/faB9z/QaMvb42vzV6nAngRlS1yOq1Bx1JCRyZ224FmwrP6bscOjY4AOPfj
         k4Wf+HliNEf4aAH1yIeQehjCBWwGSruaoSrV6tFqvRdSrne+514YF+yc20OB+4brGwyy
         F2chHXkyDDYDmEeW0TNyf7A/Ta23AfFq2m2dpXET+glG5HNXrAEcnIoXniYpn1QWUYtV
         DAwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YysU7eauJ6Y9wuRHFXFpryK3S8d8lgcFEzN94GwkzU8m4D/B261
	mXylx2jzq49gAIrPCoODths=
X-Google-Smtp-Source: AGHT+IHJXQbdDK8WOx2f2jOO9P7fdnMMod8suacIHCCA7l/dbpnkBir6TMQO6G3+odkb9VmxQBmfbA==
X-Received: by 2002:a05:6512:3a81:b0:50e:3828:d29d with SMTP id q1-20020a0565123a8100b0050e3828d29dmr72481lfu.0.1704838364395;
        Tue, 09 Jan 2024 14:12:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2803:b0:50e:7663:9a90 with SMTP id
 cf3-20020a056512280300b0050e76639a90ls487169lfb.2.-pod-prod-02-eu; Tue, 09
 Jan 2024 14:12:43 -0800 (PST)
X-Received: by 2002:a2e:87da:0:b0:2cd:17aa:55ef with SMTP id v26-20020a2e87da000000b002cd17aa55efmr11638ljj.43.1704838362689;
        Tue, 09 Jan 2024 14:12:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838362; cv=none;
        d=google.com; s=arc-20160816;
        b=PyIE5NR9QHzLW69EkZXHrzExdNygdP1oglY6SlQdCMLmslHtZzkGCubf29qkTXSNAb
         cZv9brsSuxSqF9Awh4QdFqZUqVRiG2yIMQA0k41Dj39n7//WBHOERj31Wqzpf6zP52/7
         ca0qPzu+P9i2vTlJ6XmqLSc2s3Mo0VVGbPKePnLyLW6IHkq090sfoKr8/fBklKuxMStj
         /hbuuDF/lnnphrB10CwEfn0J39g/CuifTZfA6u94TcSLHyOuvhoEXwmFOuSmN95OCITd
         EQ2CWK2QYi7mhQbJ6BBTBjk5segHr7K8przlwz5kogiMYWd2eJns4YQ2MYuIcoB/FqBm
         kcPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=+MEfEwS7YBgABTVs4pBpb90gb7WYrZTDLj1svt0+kOQ=;
        fh=LR59V+RzXHE2yptcMXdGLPI79V/pXZ7ZmyhyqeIltIM=;
        b=qDerM4HMmRQbVh0Swmw0+PXgq6fYm9HI/N4LTLbyBP6iEDqXI6geCDK5Y5+YNj7e2k
         BThX/NPNapp89rNS3q3W88jXuMm2YuzmdA2xjJR5apfc5kSzT5wXjPIGhTC2bDSj5Iwk
         bJdnlmNZJITVZvz38Z2n7LPRR6/dLMqq2EEpMlCUDS/pd8b6sn/lTmjBtxYazKULG7Sx
         0v3GViTV1kAEqjkqzjvIyanpvQc6pmCWBNx3YH9Ejql/03MIefpwGnoO3ahqFhK2hA5k
         eLP2J3DDVbVt4LyzopeOZo0AI0XDsE9hfx0pSXJ+ijHx8afm9DxGZ+B+pJdumwU1ZD4o
         o9uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FeUfEWH8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [91.218.175.179])
        by gmr-mx.google.com with ESMTPS id a19-20020a2eb173000000b002cd6569c00asi64695ljm.0.2024.01.09.14.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 14:12:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179 as permitted sender) client-ip=91.218.175.179;
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
	"Paul E . McKenney" <paulmck@kernel.org>,
	Liam.Howlett@oracle.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH mm] kasan: avoid resetting aux_lock
Date: Tue,  9 Jan 2024 23:12:34 +0100
Message-Id: <20240109221234.90929-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FeUfEWH8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.179
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

From: Andrey Konovalov <andreyknvl@gmail.com>

With commit 63b85ac56a64 ("kasan: stop leaking stack trace handles"),
KASAN zeroes out alloc meta when an object is freed. The zeroed out data
purposefully includes alloc and auxiliary stack traces but also
accidentally includes aux_lock.

As aux_lock is only initialized for each object slot during slab
creation, when the freed slot is reallocated, saving auxiliary stack
traces for the new object leads to lockdep reports when taking the
zeroed out aux_lock.

Arguably, we could reinitialize aux_lock when the object is reallocated,
but a simpler solution is to avoid zeroing out aux_lock when an object
gets freed.

Reported-by: Paul E. McKenney <paulmck@kernel.org>
Closes: https://lore.kernel.org/linux-next/5cc0f83c-e1d6-45c5-be89-9b86746fe731@paulmck-laptop/
Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kasan/generic.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 24c13dfb1e94..df6627f62402 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -487,6 +487,7 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 
 		/*
+		 * Prepare the lock for saving auxiliary stack traces.
 		 * Temporarily disable KASAN bug reporting to allow instrumented
 		 * raw_spin_lock_init to access aux_lock, which resides inside
 		 * of a redzone.
@@ -510,8 +511,13 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 	stack_depot_put(meta->aux_stack[0]);
 	stack_depot_put(meta->aux_stack[1]);
 
-	/* Zero out alloc meta to mark it as invalid. */
-	__memset(meta, 0, sizeof(*meta));
+	/*
+	 * Zero out alloc meta to mark it as invalid but keep aux_lock
+	 * initialized to avoid having to reinitialize it when another object
+	 * is allocated in the same slot.
+	 */
+	__memset(&meta->alloc_track, 0, sizeof(meta->alloc_track));
+	__memset(meta->aux_stack, 0, sizeof(meta->aux_stack));
 }
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240109221234.90929-1-andrey.konovalov%40linux.dev.
