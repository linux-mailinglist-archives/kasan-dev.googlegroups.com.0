Return-Path: <kasan-dev+bncBAABBUWL32VQMGQEUCF55UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 72E9980DFE1
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:14:11 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-40c2dd83bc4sf29880445e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 16:14:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702340051; cv=pass;
        d=google.com; s=arc-20160816;
        b=cQQCy02ne0zsux0CUoiRC+RQzbB/OR3P1TFQ5/loeMyn6Zs2WWEa9KAyVHHXgWPUgF
         H0NUJb8cxPZWk7liEzfqwSE1jwWc2ovARyfUqzlIYOACC9DFNf9BWjXb8vVxZ+z8LvD0
         vCIXrqcM9FKuBzxXKCHqPWTCdNMvFQImX+VZBd93IHYzCebYXdP72+KFFTjN3CUNLnGf
         DXY+apE65HKf1SHNLhNfM8AddE+0yJ3t0PQZI0acVpUvNMoUqfBpWRpAUKC2L5IdT2Hx
         GPH8DhO+AA8F/S2VKQfR1s4hXGOphQwWREH1yU6dURo4LsenV7VLEidWs/L6VYtBfPYc
         vtgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=81JZ7VVmV/grlnc3byEEpZmSIFcBU1Z6xDlbh2PiKqg=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=0CoWT7HDUrF91EocHIrBv3zplmChzRdDed8Uo5c8B2NXwF/O6uTyJuDM9P69HEB6vu
         gafhGGNyJyeWFQGvwP5YBNxIInspVcCy4Z9Trhwr8YuAU2INKi25WReb5pX+b/z/x9GI
         E3UrGo0QObk4qC7fLFEzUsUG3JVHhPyZ7JK17cH1aIJ7fINPKYO8ltXuGzE0jjdvcQGH
         +n1EGjrXiaYj6d93zIx8rGVvDDBSWuu7bw3XEHtCr+msyRsq5tfnOuvEv6BCrvFYCMBj
         4Y95KTe+wGa+lJUPt1oEKFpcyYEMECSDb2O50WiA9m8y09kHQB6m133yhPozMgWe6d8r
         Ubjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bKtKFMTe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702340051; x=1702944851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=81JZ7VVmV/grlnc3byEEpZmSIFcBU1Z6xDlbh2PiKqg=;
        b=eUps9mPumpCAt2C87YeYxRXtx8s5Mk6R9cWOwd1iTn6JVoSZI8rYPw/Dn6sw4mL/bZ
         cqRoz+GtuebOTMzoa7rtQjcNnPpbeINTSM0m7vwubaqQnJKKu5SAnYiSqTj5Nou42LAl
         DCjAJ+OD+NbpfrsVaBQqLUEBgKsybWSD2eRei29wp3IPONTf/Lz+sxwJjeZd+Xqafavh
         o21C8q/KSGbKZyQOIOqgB+EFQXxdoCejq0z1TaCFZxixUvALtmaefSTP3FiouwZFjsVQ
         MOtNh8b3ZkGf0C+/vPHyxBF/DhybGUou+dS3LcAVStxGP0QFN3hNKqv/OKeU36mBdl0F
         rABQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702340051; x=1702944851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=81JZ7VVmV/grlnc3byEEpZmSIFcBU1Z6xDlbh2PiKqg=;
        b=Pa4d8vCvv1nqWi5rgButYE1OS4HZkF8ZoQC0jGmcfgWzq0GGLJWaZZE56n5gVnKFt2
         IR+xbG5pBQlyDAMkzLBNrXG8onLBcaQglona5LPKytExLbkQvCK9a61NaIVw95xI9UmF
         1UzRlP8Bj0kIk2mW/caigRDs7oYQT+1PtxKrxH8zNb+86rrfAfHYyX8pgB8HTJ6NnHaq
         vcSpp1GCzi/ryZRH0nXj/uSY0fHeCeKAtEq+NAmC7FOddY3M8TF5sZVVtgbYWz0/OEgx
         daxWtnBiCxj+XQc403oTC/mlVnY3L7+23E0y6TWemrY0Z3ov/tdPze7aDpdZYTeNzzzl
         bn8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzFBwncmy2zSU+ARBzGDo8qU+0k0xkspdMUn2CEg0suJOF6LUdD
	FMsF2UzuotMrs1uCysGVw/4=
X-Google-Smtp-Source: AGHT+IFfQd7QCJOXUhYMI2qMliZRGJbbuPDcHkJxCBKgYTZ90GS5KifBYDdGWjS/w0l4eO+svyklYg==
X-Received: by 2002:a05:600c:20cb:b0:40c:3464:f821 with SMTP id y11-20020a05600c20cb00b0040c3464f821mr2681459wmm.68.1702340050538;
        Mon, 11 Dec 2023 16:14:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d20:b0:40b:3267:42b6 with SMTP id
 l32-20020a05600c1d2000b0040b326742b6ls1959557wms.0.-pod-prod-03-eu; Mon, 11
 Dec 2023 16:14:09 -0800 (PST)
X-Received: by 2002:a05:600c:3105:b0:40c:48d7:b025 with SMTP id g5-20020a05600c310500b0040c48d7b025mr1096527wmo.148.1702340049080;
        Mon, 11 Dec 2023 16:14:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702340049; cv=none;
        d=google.com; s=arc-20160816;
        b=cb+rrerB+mZc30aEfKjCPsgMsqnTHYnVlOIiUv0IR4RsHV2CX7SMsxJ/X7kdGDf5ze
         C685mJpnpvqXF2P+J2U8Rl55HUW4QlIExWcHz2SGn5EjFUZieRCn5lhdNFLGQIKHL9//
         /XcEWaWK1Ii6reNRe4Qq+u1ZuJQ837g67vuulkzKXM7fkGGlY/zsoaipEkMt2g6g3K4h
         glvsL6URf+m7AXMwC3cIlFxZ8yV97W3Xl3fHQzLmHawpHwB+JJShH68pb5p8AjCVlPhM
         /wALhvWF7sK3vze3QB1NgiXxXbdTas/HYaNDT8q0oGEOFuw12zNeg9QdloTzIbRjuwcZ
         0XPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=AncAwIfqeN0IVwxDTP835Z83czb+v0Xl5CDrKJjV5+4=;
        fh=R37Itr4vM4DSdM7nCVEJRaUzpyR01xRhpmD5Puf7xME=;
        b=ZvkDUUe9MNhmPj4hGj8wbCtWjZm5Xdq+ej6jGyxcsSifH6xyees7JpgOc7kj0c5aoy
         Cj/Sd7APW5yJeEcvkDKaJVyEgEv4yN/ia0lqQgbJrUFwkv5G1bGYZfGeM3JTWeZ9VrSn
         DTuwFkB5XXz4lq6G+f6Q7k0tPKsRMgjTD2TK2CJbyNfZjjKphmZoTah/olrj1LdM6taq
         jmY7Ows5YLzMki9F2CfvxbrCgI1O8JJYBYFRjD1fUgmmrKt0iWE8L9TAptW0nDphJf2H
         vl+mww1Z0e1xV2ds8tpw8J0PNHL2BjreMI6myosshLItqhfoNqli2rb73ZpkqwIWDPz+
         Wqqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bKtKFMTe;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta1.migadu.com (out-176.mta1.migadu.com. [95.215.58.176])
        by gmr-mx.google.com with ESMTPS id m30-20020a05600c3b1e00b0040a25ec1cfesi8645wms.0.2023.12.11.16.14.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 16:14:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as permitted sender) client-ip=95.215.58.176;
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
Subject: [PATCH mm 0/4] lib/stackdepot, kasan: fixes for stack eviction series
Date: Tue, 12 Dec 2023 01:13:59 +0100
Message-Id: <cover.1702339432.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bKtKFMTe;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.176 as
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

A few fixes for the stack depot eviction series.

Andrey Konovalov (4):
  lib/stackdepot: add printk_deferred_enter/exit guards
  kasan: handle concurrent kasan_record_aux_stack calls
  kasan: memset free track in qlink_free
  lib/stackdepot: fix comment in include/linux/stackdepot.h

 include/linux/stackdepot.h |  2 --
 lib/stackdepot.c           |  9 +++++++++
 mm/kasan/generic.c         | 15 +++++++++++++--
 mm/kasan/quarantine.c      |  2 +-
 4 files changed, 23 insertions(+), 5 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1702339432.git.andreyknvl%40google.com.
