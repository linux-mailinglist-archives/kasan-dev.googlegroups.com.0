Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWFT7T7QKGQEMDZPGBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CBC492F4F69
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:03:36 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 198sf764187lfj.19
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:03:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610553816; cv=pass;
        d=google.com; s=arc-20160816;
        b=qH04zj2YsnywniQ/8tbKjoV/xeylzxtWnKLcURhRlZAglifikSPl/sSDxoRUB3+b2v
         KlXbYjd6NFQB7x48E+LS7nNihA7/+wfEbhjsKjMB1oTHr3p9V6jkHg7j8ZAEH6yvaD7V
         ck3PDDfXxgiMS/vW00PB/F/uJCZzImOmny6vgjQgP8uUB2V4Aqs5osIlCNwZXlQnZKRM
         RAGyCym4y5fk9hwd1ErCA1ME3kdMH3c7Fk+kkem431SGpmTxDildhsfBDhM2y1GV7Zuf
         brweGIf0KkNpzKgUzvCu7XuNRRnScCf/brePNwsOy47SLeDclBkNloTcQvjXJcv3GAzr
         cJ1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=E0sC0r2q9paNHWX6PCVLZF4fNqAWYTfmlzXdj2ehWxE=;
        b=RyOQCmpvYgy2bfzk5uCXK96r+CvW6LT5WSXCXXjKlkziQ6gmfx6MVb41snELOU6cB3
         ph/Tv/onT97XSNRa7Hs4YfBdFDJyP20IuLjROlNaU9SmHt5tQRDCRRtXoJzFe1+83uwP
         UBMYGYJ3RY4d0KEuyaMMbpUQ5wQiKr9kWsGGOv3x9jBj0mpBMTB1LF05pXfXlCf/HPG8
         F2AuXlZrWxwaoCi3DWbtKZrtaGi5UUw36E/Ek1Smtn8YgI7fSDCJoeB6WQkK3m7B6Ueg
         hcPR8xACksKxZos8yn/XETUQSJH/2FB9Bzx/9MwgF/EuztY/t1/RyYjhlxODJB35B49D
         kqyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJYBEOIF;
       spf=pass (google.com: domain of 31hn_xwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31hn_XwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E0sC0r2q9paNHWX6PCVLZF4fNqAWYTfmlzXdj2ehWxE=;
        b=tZx47rGICCBiYL5N9iIdsNfomHB2483byNSHRZVOL7fQC2wDCDk/9fbs2u4QhD/Fpg
         olvZDtqlc5+XbvMrGVQnCfzaXMmM0x/UrQPjNq7i7/EqegRZsY3VlvC5y97sya5LbuBj
         rNu9wC11gX51uIBUA+F5G79GIX4SBvZmp/6xK4XpSMc5deCrXwU20GdnGLP0QURa85Sd
         kbzxHCp8dFNXoGmAmIvg09aEF/2LFA7BhJOItcOuPAl2yze1rLzTNKOF66Rr6LWOB6Jr
         RlVVNE4YAyqMURNdL0H82cdh5lWkFBDYotcOkM5Z/3F+Jqicyx11k95CGAFnEW7rBfEA
         WExw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E0sC0r2q9paNHWX6PCVLZF4fNqAWYTfmlzXdj2ehWxE=;
        b=C1gfbwVLljGEnu6xoZ/LKh4ZKv2Bhrqyh8B6B31b0NVFGMn26IgiCklyYX5baM28RP
         un4+DLsEM4wKh0/C0O//3XXwheGYsU/3jdD0pbPABDOIaqJ1vTLhV4IevmcTMsKvU4Ic
         91bGGWXutVkyRug7iW88AAsw88Kl4tKYnSRbiSjaCMywnW6conkPeMwNT84odNu5iABW
         +qmyxpKqag0a41BPIInSI4sCmO9zXwASr+y2GZE8goratMAyr/8A0BJBZrqVYkUmmQuS
         vPIJHmduJzNFeZRRZmEGKhCt9PXV5efA4lbTp2XO5dLKwLU2z3Yuiarun8fuUynqG42u
         hRKw==
X-Gm-Message-State: AOAM533CtSjj4jfr0n72IZFBzhYRmt1vqK/dmGfeYl25QJr5UElWnEE6
	7cr0VniMyDxPqynHyWq3ub8=
X-Google-Smtp-Source: ABdhPJxV0VaQlOgigJIYFDPjdQypxvMuQaRb68qlj9qK3F8pE2lFRcnuGN7l+0BdYOBF+xwP3pu0+Q==
X-Received: by 2002:a19:5041:: with SMTP id z1mr1255723lfj.77.1610553816409;
        Wed, 13 Jan 2021 08:03:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c1cd:: with SMTP id r196ls394153lff.1.gmail; Wed, 13 Jan
 2021 08:03:35 -0800 (PST)
X-Received: by 2002:a05:6512:3284:: with SMTP id p4mr1102263lfe.245.1610553815414;
        Wed, 13 Jan 2021 08:03:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610553815; cv=none;
        d=google.com; s=arc-20160816;
        b=BJxveRyitx0yrXXIQjVvY7eIMPlC2S3LSDJeAjZl1tSz7FdRnw/3Vw8GgXlnYlFDub
         vRzVb3Ke8bmRK+gIMCn2ibXdfygfFSPduncEY0wxsjooKv1CZsoxtWbkjwx1RRHRGexY
         8uPLOnQcNmuADdQzpL4qt5LEZzzde/DMsx2rkh6K4SeLzXveoaqPWFE08yGN1Qs5Ryhb
         B54xlRFdHyfd0NLLgu6hHAN4eWo6QRus0+O3RN+rzoIhy24qXXdbTrVoMcBx9vgKJaH5
         wHJMcJGDgEe+ZGVl2SBugo0I5/bckuX7eaqWPEsB04CjW9KvpH7yp9ehxt26MSOhLDY5
         +Fbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=uxn0PEieT9aKbavqBd55kNusrAII89J23REmBtgP+I8=;
        b=mw3JUDdKTgbX21MeVNbZAjOUn4clqWMSVMj5FJPMoEs2GPkV/7gdWnGI6kriO6W4pQ
         FSF8CkIPNTlOGw+t+hokMMJuBgRasOgFo707pasHDYqecfTch94osLROJRKjpN5XnhbQ
         XZig/0xqjEkfAs1q29mTgeoNcAaCQAXWGGDaCmqOE9jPkC4aov7HdwnBkkIs5nh5WLDH
         duJcdOp61Nb5dllc6BiJh/Xtkn1GWlpUL8G9Rx17qAbNQpdUlJc6vbfL06T1+sqdhlfP
         8btR6uIzg4FNgBDyljdzI7EHYsLcQQ/7JO1RAggUdZ+G+yss5p9IPuYtDWe8gafyDui4
         60xQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rJYBEOIF;
       spf=pass (google.com: domain of 31hn_xwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31hn_XwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id c24si114085ljk.7.2021.01.13.08.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:03:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 31hn_xwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id k3so1048428ejr.16
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:03:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:e94c:: with SMTP id
 jw12mr2149396ejb.56.1610553814149; Wed, 13 Jan 2021 08:03:34 -0800 (PST)
Date: Wed, 13 Jan 2021 17:03:28 +0100
Message-Id: <cover.1610553773.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH 0/2] kasan: fixes for 5.11-rc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rJYBEOIF;       spf=pass
 (google.com: domain of 31hn_xwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31hn_XwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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

Andrey Konovalov (2):
  kasan, mm: fix conflicts with init_on_alloc/free
  kasan, arm64: fix pointer tags in KASAN reports

 arch/arm64/mm/fault.c | 2 ++
 mm/slub.c             | 7 ++++---
 2 files changed, 6 insertions(+), 3 deletions(-)

-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1610553773.git.andreyknvl%40google.com.
