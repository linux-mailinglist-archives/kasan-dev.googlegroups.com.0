Return-Path: <kasan-dev+bncBAABBWWV2SIAMGQENSN3U2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id CE55D4C013D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 19:26:34 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e1-20020adfa741000000b001e2e74c3d4esf9236417wrd.12
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 10:26:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645554394; cv=pass;
        d=google.com; s=arc-20160816;
        b=tCbj1tG5FYB+DqhXkUuj9HIk4cdjxDd6uGrAZXIUnqdQ5djQKvjLOMmZ8T1bJpNSjA
         UWEQqzGah9L0l7OyRQ0fMdX9O/qaymuUqKhU1VlBFv4D9yrrWPYKYgs1YATuWlPRpwQn
         ino0FCVnWmVCrgmG9MiDq6/PvYL+hCgh2g5RVHV4XbPFrkA/rFIsW+fSVkLllbygKQSu
         OGl2S+2suCAEClr5nGO9WlXtd2lPLKN7Te/6Cyd9pP61Scxmf4L38QFE6b2rh4CSm4W1
         EtC6J/sRqgtEJWcwl+ClekDvf1RcVF23bUYHPLzhuvTmOaWLf40v+F1gqreW7NSOFtPO
         Qjjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vVij6m4ZxKnbF32wiX+Tn0wytuwXT+NylwqZxLzI8ok=;
        b=DNbjgmwanaFMnJX0SNTlzqe3x52qsaTq+4tp8/N2mNoHSG3QVTSXnQT2wNibNGvrjH
         IQcgFh64gQaT9FGknOU99oLz1GE7f4sc9bsjCbGcj/0N/OpdNtTTwrNs2ivZknv/2T/l
         HB4x9/x+kC6Gv1iqR06uNu1uJ1TP2zsaghXMQ59uMFwIs/DAEgZycE3bFAVsq1jifQMf
         x3hGhlSoN+PGg+3dCPir+sGTja5gc/LOrxDDdYh5cJvdtiMXV/XGOE2/CHsSjxHBz3dW
         IlReyaz0gjqt6g038v8L2ZtPLIwUHtXDWPBPrizLh4FJmDCeabUQBkVfOC/Y7yc7/9Zy
         YD7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l7Bx2GUk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vVij6m4ZxKnbF32wiX+Tn0wytuwXT+NylwqZxLzI8ok=;
        b=WDNEewntDXXw3CKMnEX2nvJKDL6EUjKrnWN9wjWFtOGZ+nWF/Supp8OvxNlgkl43zN
         CVO//A5+j1s2imzJvIB2N+wrVNargu2QoWzlSW6g4VU1LxRCt8FSgKYTc50hs7n17rl0
         nWwvcuEx8dfl25MgRCln8HiQn9xSigGqp6ODSBAwP3br6gP4kjOJYcWPA0YsEWW6gzBI
         tk6TEIh06jY+ZsMGkvv35BmOS4YgTeprpi8cQ2nseHYDny5FsVfbQwsS6nUtf+OsXDQf
         98mi65eFSWPedh4L1/7IHA+O840C4XCcGBzOChccM627jzSeXfJg3bLnPWcVZKZmoGG9
         Y36g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vVij6m4ZxKnbF32wiX+Tn0wytuwXT+NylwqZxLzI8ok=;
        b=lomnIdUi89AllgPe+0wgxmpEvuL/3e/YyN6gto/+9S2h7D9TMX/+PZEfk9eeiWd+zA
         Jm8105jVX+Y7fUHuXQuw+4PfH+ZY0MXKRW9kMuLKLBpgbMH0tJtsWd1OwM1Xr5R0yua+
         H/IkC6a6FM5JB0PtRZ6m7n7DVQMYeuFnFYcNuBGrZ6bslxBm7CJcM4pdnNuG5dW8XpDb
         ikBcEiZnCE16ffB0SvuPe2ycRuZUZMWEvRLYyzFhhow0zDWo/DwAkOlkmvEZvvzgUmSC
         MddOZGXzpTRdLjYAeL2WR5UPBlsthMfjWETx40aS2uRIzwTk5pnu6TYCJ93mt6SRmXY1
         343g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+GjGvydM6lzUMpy43EV0bOgmlCQG68m8DmL1NFeVLsORV4BWk
	k5RLc7qH66ijNXlu/Kcxp6g=
X-Google-Smtp-Source: ABdhPJxvVtu/04WaCzYiFjowGUtbcoHo9tIKRok0m5q/4cYewgzNoFkcdqHaYMZGtEKB9TsT9HDO2w==
X-Received: by 2002:adf:f7cc:0:b0:1e4:b2d4:f432 with SMTP id a12-20020adff7cc000000b001e4b2d4f432mr21029308wrq.430.1645554394524;
        Tue, 22 Feb 2022 10:26:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d84:b0:37c:dec7:dbbf with SMTP id
 p4-20020a05600c1d8400b0037cdec7dbbfls1760133wms.3.canary-gmail; Tue, 22 Feb
 2022 10:26:33 -0800 (PST)
X-Received: by 2002:a05:600c:154f:b0:37b:c5cf:40e8 with SMTP id f15-20020a05600c154f00b0037bc5cf40e8mr4456502wmg.27.1645554393802;
        Tue, 22 Feb 2022 10:26:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645554393; cv=none;
        d=google.com; s=arc-20160816;
        b=djO1/vfdEGToSirVGwnj4w84D7HJdX84g0ULLruNlAo4jlyPyLKZkki3xu3Yh8Rh/q
         CBVtes07/NaGgLO42HdNju/DjFL4/Ncnnf4EjFyKnJsSPBYbrMDsWTN6c5eLOX79ytjj
         dgX1+DI2uPHw0LdjRCWARj5zYhCfdpPCnnsXPtp8NJcmFIV1rJeGcbIQYjW04YZV2r6X
         mVtTZrWgDzeF4jrWrTQSeGCIeKDgmmiHjgMtOIogx/cOClK4yEmMEig4qg18f3d4mKo7
         0m/YHnUL54EnFHxovU06fduSvLVtZtAM0JQ1Zq8CyTdpssUroQHYCUffBGlwYEbuCMQH
         6ZRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Lb/QQb5DmP2LHrXtHDNMk4U8p312LQBN/82u4kQO66g=;
        b=IA4OW69zYEDXtlZ6rzNf9PoTfVewuSa3klLrI6R/S5tLtX3foTS7ETN8C7pEgx9bo2
         MDC3QmE/snAM5u7FGv6Lh2zHL/2RabBQlHXDOY3s5JwgHdjALvzM9K2jCv7Hlqg1JjLK
         tWvYeVtXUFMiHztHdYb7vzC7ALWwPB8YkjwA9OTCbjJK9GGNOlXgI8xTRZI42t9LCajy
         n+Jf3Oq1a8H7blccGvTIspiFRrc08rcWmBnG8PGvo2+E+j1c6nNU6hRsXn0b6RASQN6L
         hsRinwzvXZpmPWJFpeI+XAjtx6OVeB2r2qrbMz6msRS4zx8wQ75nJGPXzRme+p82O10K
         Sh9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l7Bx2GUk;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id k15si795828wrp.3.2022.02.22.10.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 22 Feb 2022 10:26:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v2] another fix for "kasan: improve vmalloc tests"
Date: Tue, 22 Feb 2022 19:26:28 +0100
Message-Id: <019ac41602e0c4a7dfe96dc8158a95097c2b2ebd.1645554036.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=l7Bx2GUk;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Do the checks that rely on these functions only when the tests are
built-in.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Hide checks under #if instead of dropping.
---
 lib/test_kasan.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ef99d81fe8b3..c4b7eb2bad77 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1083,11 +1083,13 @@ static void vmalloc_helpers_tags(struct kunit *test)
 	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
 
+#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
 	/* Make sure vmalloc'ed memory permissions can be changed. */
 	rv = set_memory_ro((unsigned long)ptr, 1);
 	KUNIT_ASSERT_GE(test, rv, 0);
 	rv = set_memory_rw((unsigned long)ptr, 1);
 	KUNIT_ASSERT_GE(test, rv, 0);
+#endif
 
 	vfree(ptr);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/019ac41602e0c4a7dfe96dc8158a95097c2b2ebd.1645554036.git.andreyknvl%40google.com.
