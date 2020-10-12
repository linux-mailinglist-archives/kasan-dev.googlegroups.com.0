Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYEASP6AKGQEXWBPVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE4328C2F0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:21 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id h17sf3167507lfc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535521; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7vPzqpPJWFHxdLpNNURl0/1HrP7iq90lW+corxRox8bDpI2ioCM5XgwDLvyHzHFmo
         wa4pSyMdPKLZKlG7WOmFlv9WqO9J/U1zgxKiCnOlo6fRSMbH7JjnKY0QcOj3SylwH3Az
         Fnh9GIgS6589lJsmAEBBfzsGDQKNo9XD0zCXtQ6Y6Sm987uQ+2GRKX3RWneRsZbVRfFq
         Mj8ioGc0sEHkuiv8ybYbsQSL12YUP+EW4qheUYiUS3Zfyqx8NpwM+qLtuky4Ogk31TG2
         LW8Q8PBf0kG92UjhB6jrQO7uKNEbh9jNjzr4QNRtobVFp9nDfRRmrQdifCYyQAuEvnPm
         sOkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ONoanDsahh2zaPAKdgFKeYkx7Ts/bgwORWhR6fZE7OE=;
        b=xDA3Q1S+F/sG1f6+ZbnHpyadYhQTZRvsAFAKQEVUpVSV7UYaIYTeTp8TN5EWoz5h0L
         Xw3nUF8N3aUlee+HlnBCQjxPV43yh7KN5xauUGz3Tv2p4aFIvqP5SWfrJA71xfpzc2iD
         B0W+OiSIQu00j/u23YA1e4zg5tis3IBiIOvKc85ApzG6Im0G44QbiGSPLcFayUFWp+Vp
         BjmuMDj1Yp/C+6ACjFKlVisetWT/sWM1IqoGdVqwpF0AxbY1tO/7C+1d0NnTT4XSv0j5
         uukyNBO/MAdehymBfqCgPavXEil04+HptMKDPJsHLGNL9wxfygeGw3Kn7AjVGJ8r1mIG
         d6TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P9Bpbwrf;
       spf=pass (google.com: domain of 3x8cexwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X8CEXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ONoanDsahh2zaPAKdgFKeYkx7Ts/bgwORWhR6fZE7OE=;
        b=EZ9e0d0h5SdlSIQLJUJHhf6+u0FDymVQL1T7iqJCxZla+8CqnPVjYdTtAcjmYxCkPZ
         HfUBh2MlLEMPXootJdIZ9aDFkKtILP3AyNHOw4Btdo7rz/PSYft5LSbbfPONA7y5Qq2I
         rXJiZGGJR40Wl6VLfsB97WjAEBTenMIF8dXHyn25HhgF2fCmaWd8ksNywjg4B0UTpT5I
         3D/s6gKmkS2dxqXzXjPnC5fzJxUHRD9HffDARBPKdw+VYrlOvBl9aDoMDoO35LP3V/QL
         zRG4SzWGCjOPkVSmovVv75zkZFShXEHNrfrdmSBGBxSLW+wwjUgcdKcviuq8u2IJqF+P
         Jh9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ONoanDsahh2zaPAKdgFKeYkx7Ts/bgwORWhR6fZE7OE=;
        b=Rr4ULkmIA1A5/zOfG+8URqHzid9UcO+AvhRzYBihh40juamWptEjVMxoc2WxLKWzyE
         102ZJCcX7Qe2R8++oBgAYNl5f7lMRNXLmalYk4cBXbd9Cj8WzD0OHHIvdFQaJfHuaElA
         PypAC/OukcZ6Ra2Pv6LPQ+IhxiWtdpDuFgPWehtooZMHSjnWhzFS3yPkIX+d+zqA2mwU
         f4XhGdvIxHtTh4o4MVfd5tHMjuV5TZNmbvaZaPX33ImLJrWMkROiXmKVDk7aBBj3wLna
         SBJJ7FqIX4pK4wA5VcpKrwDRRrYdWlrMMoOO+6B9/mGY0LFicMHhKYFCpLerolFEHKSI
         EESg==
X-Gm-Message-State: AOAM531m0QAFa8wQspsQK2SOFcHeqmloeRCHfJ2x6q69LMOvoVbJSoyz
	Q5dVx66ZkJb/CRAH92BMBnw=
X-Google-Smtp-Source: ABdhPJzAnYgPk3xr4f4A5LKR+W7cSzFH31f9In3bs/MnU+C6ts7usTOLuNmCQXcXQ4uwhFemlAWsUw==
X-Received: by 2002:a2e:b619:: with SMTP id r25mr7693804ljn.465.1602535521169;
        Mon, 12 Oct 2020 13:45:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ad43:: with SMTP id s3ls840365lfd.2.gmail; Mon, 12 Oct
 2020 13:45:20 -0700 (PDT)
X-Received: by 2002:a05:6512:78a:: with SMTP id x10mr9591455lfr.340.1602535520099;
        Mon, 12 Oct 2020 13:45:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535520; cv=none;
        d=google.com; s=arc-20160816;
        b=cIpK5HumwJFr6lD/xpz8v5QZbh5Hkjx0+/xzmUZqM9ucxMkiXVmiv4/W9lMIFJ5+cZ
         LqRt6O6hwmezj+H4GfKBOp4YQw9/A2E+4w2/arr9UgRzCwsux1MnLvc7f9LUIua1pbUR
         u0pehfjoMhDVlkv7zpa4mJ8teorJk8jJqGuDQm4PSgRkp7sNq7iyuFcqO2ALx7pur23I
         T9xaKFBWik7F/E5avNp6t1OXcfJQMCA8EnUIQOlR2rAGOuJe9iM4MYbWCReyhHYov9eS
         6lQVbHuemhUryQSSJwqKIkaS/CRmnr+z8Cuagcha1x2vs3E43HRF2S2VXWJS3s6Zmdaw
         RvZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=u0M3JfYyWMkI/QXNLQNS1i7R0v419+PHcT21ye/NQ34=;
        b=hNwY6/0+YgXHeYASvI+gOTzHrom7wjfTSvrHPlc4vc+E/83k3Nx74IKgYkpPteMBu6
         zk12DW7Ck+Zyz9jbvTEk6zxou6Q19Ye3ec6XlFDGhAc+kJGN63c7+cdCAdLS9zYDe9J/
         MwmmhE2K2SMJ6QXLn6JG8M7IcBQXkzOQrDnn32/eJyzuWvTq9nFdmcMDBuE0CmjckrHD
         TWqvMxbmxAcjOiead2yr5snEtaA43GlIddqjjArCy+aXOeoTtEHKOLamN7D62ahCr9Sf
         mlc98dqtrCuRQb2S0o0/3GMGQUVmbbHirlNKDOuDzpCecrLQkMlV+5Q3TKHEnMQqnyn3
         epvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P9Bpbwrf;
       spf=pass (google.com: domain of 3x8cexwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X8CEXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x19si537940ljh.2.2020.10.12.13.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x8cexwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so1610028wme.8
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:20 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c10c:: with SMTP id
 w12mr12912546wmi.175.1602535519488; Mon, 12 Oct 2020 13:45:19 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:17 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <6106512e93a35c20a082b052f01b799b259f698f.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 11/40] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P9Bpbwrf;       spf=pass
 (google.com: domain of 3x8cexwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3X8CEXwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..e1d55331b618 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6106512e93a35c20a082b052f01b799b259f698f.1602535397.git.andreyknvl%40google.com.
