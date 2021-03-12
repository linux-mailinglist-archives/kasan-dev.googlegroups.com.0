Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKPTVWBAMGQE2UWFNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD2F9338FDF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:41 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id bi17sf11555020edb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559081; cv=pass;
        d=google.com; s=arc-20160816;
        b=r7O4aya60nC8wSE5aInQSodPBnmxXdWDIPpeVGnHjbONP2PV+4RaFUnSwmyk/OSEyB
         0hIe2RSL+AdWzQQQLGcJs2Axh2qkEN+QoUVHy+2TvvdmW2MzSapObmANED6kdLlB+mrA
         Va//QC5IdAWBFnhCc18MkERVlTQ1gywJ8cYjl/8oA6iiCRBZ+MRwLZY++gim33DpkKZY
         2rilooSoGk4x4umw/U4mZwd4f9BagFuSi4zsFewjodboPScLLpI1JZJy9LjibzqDofSn
         uKOC175nEjiIlz99wg33VoGxm4inCK5ioSOA0wOmW1gIxTRqzGuUr/stUK+Qn6uKxArw
         a8mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=f13coZeYa6/5N8YKzcMnwftC1VheYaZhv3U3HaHk7Xw=;
        b=T5INqbqIJeQt/XK3WEUgt+r30Cy9iFLuYoesPWgNAaPNmD5JC/76lpt67gNWFQg7NN
         K6TGG4fu1TDmzWjODiKM4mI8GaIhyq0Jkw5+0cdp3mOgl+RrCZDZXk2+VCiKhy3wF3uO
         zKe4DMvi4PKOdrTOUrEmjdZeZ2T+9OJAXdwov2F2bXk/4x8Cho/QnRnQBGElB/gi9zFF
         av4FD9oLKI83bOyzQEqOdrO1wc14FbuMRWZ9sTrImQQ8IAbicQeWUZxkk7XTX4wmdL2P
         mtZcATvXsKbGLanh0v8TJdowGibg/GjSG4lBppE/w7jMSHqDrBOO/Lhgh+tZ2StvrEt1
         63/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/FaqdN6";
       spf=pass (google.com: domain of 3qhllyaokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qHlLYAoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f13coZeYa6/5N8YKzcMnwftC1VheYaZhv3U3HaHk7Xw=;
        b=eNuXu/9IiSMp6yd9vyvsSJrYqXl2opTZRHckChUAABmatJoORJG3CCBSrIYs5e+GOy
         eX/rALTvQFNuyh4WZNZoQY1S6GzVAZOrvnlOPo03tVaNIDBCFdgD/gH4rzp5PU75cfAc
         LhnILSAkRsR9YtspF76DzdqMe+K6yTH5T0xpO4afT9hD1wHM1EQsaFcTKGAwxNKFbaOm
         FCPGKROFu0ueRcVxK4PrYFRRddv+f7pCQr0hZpxTAKPfGzMmCD2PRtFbcvoaTropGunu
         63MMVYMdc8MxtFQNf35ctXufEtU03PXJe6YiO6vkM2pQMYYMSfTMslYl/fI43c2GVabi
         dFnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f13coZeYa6/5N8YKzcMnwftC1VheYaZhv3U3HaHk7Xw=;
        b=O6nnBVMjeiO9uhDZO0mp4BNVFUhDf+nidp+MwCRJM/kJTIOw/NaBUo8hcSSybm8Jfp
         5L+w/4p5lEo9RjBs6cyTi0tLLdBWgJLCjuftSJryOGtYeQasitHst874KjMqR+XHqUwB
         ESTG855cxXolrf+021U6OZziT/O1mMcFnp2oPmMMhTqcN9JwoiQdwqvyXe5q3IgHe6C6
         DB0tBoF6AaAaSS1CMdk9lxVik2/wGKSNAcw6aMHuyLqBCbSqTwRb3qIKgjNmJreWvfBA
         8JiL2IErYpkgB8SKOrQ1DBNEDp3pxRZKabQZQymYD+Uxj0QmR2pvMoUGOKMucbIU3PhR
         b5OA==
X-Gm-Message-State: AOAM531w70ODOEBVer0thYWnMPCfTQ86EKQjGMUU98OnsAVlkiAHtiZf
	VUXC3rzOJ5XSb49Q4W3+Fq8=
X-Google-Smtp-Source: ABdhPJzLFD/WvO8sHGsmeF4EA3H89fUrBPJP5U35e4JQZRMLomTHWDx5Vy593ZH2RNVa0zltbBDwGA==
X-Received: by 2002:a17:906:1fd2:: with SMTP id e18mr9062274ejt.49.1615559081565;
        Fri, 12 Mar 2021 06:24:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:97c6:: with SMTP id js6ls2211937ejc.2.gmail; Fri, 12
 Mar 2021 06:24:40 -0800 (PST)
X-Received: by 2002:a17:907:9e6:: with SMTP id ce6mr8600375ejc.207.1615559080679;
        Fri, 12 Mar 2021 06:24:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559080; cv=none;
        d=google.com; s=arc-20160816;
        b=R0czCyzP2LzIU+KZZFPu3p3TocIQFzQi8/HZrjoQ6AMNHaJkyEd0J6IC2I8rizKgLz
         ksnE/afc/3NZ0n+rbYjMXIC9pbXfv5SU9MiSp+KllTrqTXF3/3sKIKR0mLBtcLWqRNMM
         ZLscq2HxNqmzSj6kMPqok4dgk0U4yqZptEdAqRwYDcAsIxiZkJXphvcRbyF/GctiIWc0
         a71MHlYDbLDE7M+zvfL7aKl0oI77F/ieLF3s4HvvGryn+aR8e3w6PecLrsw6MV7yjBj7
         BTbKDrWpOUJ34dAN0fgfoj/pv2YYbBZn7Xjmc2grC4J4SLW5Bj3NqfalnFF43QcicpP7
         yqSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YmrfZsjCUnsbI/dxLimuvoNopBZleUT55sQpN4+LAO4=;
        b=s+7kxqc7u/V0N676gwF1x7EaDq2nnqSpUvBQWqGg0yApmr+QfmqhxXommWDqqS3Jim
         ch6yiZf+q1Ov/5UgcPOeZNOwHizNYyQbqrM6+nATaENs79u7jWnn/fcGPjgD/SY2SASy
         jKF2kHhqZe64wnbkqqYZoQxo7Qpra29+Hx73sgeRzxgWggd7MSlOK2uBVzc3Ze4CMpvo
         StwcicshG0kYzAWI7dBnJo+/RJxKJ2K84MWYZ+X0zHObihrvyiwKfAvnQv4XxUTi13Wc
         gOBdlYF6vRpZwawwG02b0PUayg8NyyeqavN+XVdxSh/3v/yKWwPbAVtJkLHldKNAGPyv
         +9Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/FaqdN6";
       spf=pass (google.com: domain of 3qhllyaokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qHlLYAoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id w5si202052edv.1.2021.03.12.06.24.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qhllyaokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id mj6so10189039ejb.11
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:40 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:a049:: with SMTP id
 bg9mr8819448ejb.186.1615559080372; Fri, 12 Mar 2021 06:24:40 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:25 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <1486fba8514de3d7db2f47df2192db59228b0a7b.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 02/11] kasan: docs: update overview section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="j/FaqdN6";       spf=pass
 (google.com: domain of 3qhllyaokcdexa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qHlLYAoKCdExA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

Update the "Overview" section in KASAN documentation:

- Outline main use cases for each mode.
- Mention that HW_TAGS mode need compiler support too.
- Move the part about SLUB/SLAB support from "Usage" to "Overview".
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Mention GCC support for HW_TAGS.
---
 Documentation/dev-tools/kasan.rst | 27 +++++++++++++++++++--------
 1 file changed, 19 insertions(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b3b2c517db55..2f2697b290d5 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -11,17 +11,31 @@ designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
 2. software tag-based KASAN (similar to userspace HWASan),
 3. hardware tag-based KASAN (based on hardware memory tagging).
 
-Software KASAN modes (1 and 2) use compile-time instrumentation to insert
-validity checks before every memory access, and therefore require a compiler
+Generic KASAN is mainly used for debugging due to a large memory overhead.
+Software tag-based KASAN can be used for dogfood testing as it has a lower
+memory overhead that allows using it with real workloads. Hardware tag-based
+KASAN comes with low memory and performance overheads and, therefore, can be
+used in production. Either as an in-field memory bug detector or as a security
+mitigation.
+
+Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
+validity checks before every memory access and, therefore, require a compiler
 version that supports that.
 
-Generic KASAN is supported in both GCC and Clang. With GCC it requires version
+Generic KASAN is supported in GCC and Clang. With GCC, it requires version
 8.3.0 or later. Any supported Clang version is compatible, but detection of
 out-of-bounds accesses for global variables is only supported since Clang 11.
 
-Tag-based KASAN is only supported in Clang.
+Software tag-based KASAN mode is only supported in Clang.
 
-Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
+The hardware KASAN mode (#3) relies on hardware to perform the checks but
+still requires a compiler version that supports memory tagging instructions.
+This mode is supported in GCC 10+ and Clang 11+.
+
+Both software KASAN modes work with SLUB and SLAB memory allocators,
+while the hardware tag-based KASAN currently only supports SLUB.
+
+Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
 and riscv architectures, and tag-based KASAN modes are supported only for arm64.
 
 Usage
@@ -39,9 +53,6 @@ For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
 CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
 The former produces smaller binary while the latter is 1.1 - 2 times faster.
 
-Both software KASAN modes work with both SLUB and SLAB memory allocators,
-while the hardware tag-based KASAN currently only support SLUB.
-
 For better error reports that include stack traces, enable CONFIG_STACKTRACE.
 
 To augment reports with last allocation and freeing stack of the physical page,
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1486fba8514de3d7db2f47df2192db59228b0a7b.1615559068.git.andreyknvl%40google.com.
