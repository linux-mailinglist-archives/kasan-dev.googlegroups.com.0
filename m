Return-Path: <kasan-dev+bncBAABBXWKQCUQMGQERIBOXXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 78FD47BBB9E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:55 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4066a468880sf170925e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605535; cv=pass;
        d=google.com; s=arc-20160816;
        b=qxj8TrB7C4vwT678PW4wzTGgbZuesGTQ+Yq5VLO8fxtI/cq9zWugwZddwQuV/2Ds/u
         uB0jorw8yOEBquNxH5m+rPL6t66UDjvJ6rbQYhykRFgX6ab9PlX9E6n1fHB+pCGA0P9T
         ym6ujhTHJMhzMxg3MvoI3YHF4Ic5KZcSO08jIGIXr40J+qB+6zr60Os3HhmFFqk7s8CV
         OcPa7gZPLd9P2Qb95Y9A0NmnlfWflnn+Ge+G1ay4/pWp1KKEt4Xq5H01l1tc2jdET244
         9ZZpgZofZKSp9SkteOD3TZ6OQ6E72XHP8Lx7N+yv0jy3Kxs/MkyQJR48zwRoNYosnbxP
         DYjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7ZHz8Jruzw9J1UUeQIZvsGDbHXjSVOM4uBtB6w7aM2Q=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=vA/k+ZIUiEohhXGgN7T5xLUmEAi7MLMnwcywat5+RthYNDPLPbSO8IJwVxoZXW0E8b
         J5FiqGX2I7r09GsHBCZIBVt9Dh2gfv1HYEvYOQWjYPbLV6godQEaZ7V1Iac1548U3af4
         5OlKLYtmolezsC2+sHVZbO4SgpfUH2U86dA5fS9+NO9NuURwhAW/X51ENZ1xsFHgSuhc
         aQn9A4RD/wWWwdFnxCj609T9qOds6L2IWxdFd309f7s/0cBNE5GdUSKGcwCWUDPC2N72
         DZSPtC3N6VfHQoZ8WVFjb8JO3rfkjKtuNiut2TWumka1xfaVMF03zUzjAQAPETgqee4/
         WfTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cvyFNI4O;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.209 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605535; x=1697210335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7ZHz8Jruzw9J1UUeQIZvsGDbHXjSVOM4uBtB6w7aM2Q=;
        b=R/86fZwWIUmfjyqql7XndlxUvWR480R3Tsz3GlHYnBA4D9Wln8+bcRszll1ZlHhWJz
         iczvWkSK4Q9WVX1XOY3toj2hJSm7L2xW4vjwFDsr1FHYbQDQ7/SUP8B6HdDD3nfMD270
         AD4q91cts4ZIruPRLiwoawJ4vsPIrkVZv6ccJ0x5Q1LaEsU2ANwdBmhuHVIcAcuXypEi
         mvVBvA6/SKAaG/tRKJ8B/yJmWIpciCa6F1E22cE5Id+X0IGE8p/OV5hZkiDNWV8KK0FV
         0wKDrMB39L8XZ6U8USdTuep0LLGWvRt/UDiqV7dJ6jBUCaGdkUvykBcDgS9HkmKJ2dnV
         vGpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605535; x=1697210335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7ZHz8Jruzw9J1UUeQIZvsGDbHXjSVOM4uBtB6w7aM2Q=;
        b=Loi/ji2o/eEO2FNh41J0lUkKpBHW5KIz7NltTQFd3Py6aa2doZMnu2K2KlO9RArxJo
         hH1Wqg9IcM/dkP4uz9H3L+lnEFODtfB3YmmhoQsm4wtd2UnCFFudN9mAcK436uQZG1W6
         h82hN85uCF7Tlsfz/aD+vvJbHu5g3w8xzic4jhiURDPtTyrQCQgBA0s1qjyJAFlSO/ra
         EkdZIZhELsZmZh30B8752xX9v4U4GIziifBZgMgIUyxbvTCWplEyU6+cE8OaUOIegnZL
         3qRfqkNQHk+nMFmL4wsUAkYbuLQN3O3VsdlZGYGV+ofZlf14jjQYfAddDTDqgCoMDo5J
         PaJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwaYj2m3bp2Z1PVXkNkB5skeJyvp0+sPFmUBRVPI9gvsKFtMRAa
	QVd6EXv52kZkeiTFsaVUQrU=
X-Google-Smtp-Source: AGHT+IHY7KTS7MZTEbw29INjtnsotH1m2pQF+Le5I9jjuNofKe1PNY+Bx3h2tGucmyfTgUmkHPtPsA==
X-Received: by 2002:a05:600c:45d1:b0:405:35bf:7362 with SMTP id s17-20020a05600c45d100b0040535bf7362mr173059wmo.0.1696605534511;
        Fri, 06 Oct 2023 08:18:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c15:b0:403:419:ad1b with SMTP id
 fm21-20020a05600c0c1500b004030419ad1bls1191973wmb.1.-pod-prod-05-eu; Fri, 06
 Oct 2023 08:18:53 -0700 (PDT)
X-Received: by 2002:a1c:6a03:0:b0:406:535a:cfb4 with SMTP id f3-20020a1c6a03000000b00406535acfb4mr8080603wmc.1.1696605532963;
        Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605532; cv=none;
        d=google.com; s=arc-20160816;
        b=MBRloO/TiP2gvhE5qy7gSKq7f7uuEm5OgN0K4k0Bq6vIw/UnqwPPaaYvlr2OedIcOo
         P1AC7C1c/KGwFcplNNUAjO2aQHAR7hkDRTDN92F50H8FN6zoE2Al0sGkUUSjgYLuYDfO
         AU/EY5qp3stEMxIo8UrntzbjOaMWH1+O5EtUPxpKFmL0dnDJn/cILkWFVFKWE3qEoOVz
         k+bCM2001u//MliHBSFDAD8dE9BNzjZQuvw9uNhO6umn7Nbe088dDlq+8gpxKcbClKlY
         8w0K2THBttYf8OtfP/QbNdx/yoEpfCorWc1MdNHUSg6dFGl7OIsJehPAvuLuVb5EUk65
         s1Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Er5Jgf/mIYSvRRXnkgZed7EeXQhYo+vHYR723lnpJKc=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=nwMHQgn0pSbm1Th11dxgpkK6320mIeuNBDme1b5YUeKfJL4RunHEkHvSQF+fhZe3TZ
         QD4YPXkWurZdokrZUIoKaKJ2j0Z0fp89NcPMiOwxIm7j6gmNOEcshc79Musw3ta1N29b
         QK9wcybqjWIgMI5qjLsY7p04r1ftTsYsBmPkg9gjD7s5oPi2FbEStClKaxbTNqE36TfE
         zKDEmnU1OfBxWs1lFyOWS/qx3Up0BwgwlhD+Eiqlg0RgvspHnzs+CT0XUi1dmlBEKfzG
         DnHyFj1Ud4PKFVRe562PfkYh3IpGuSd1U/1UODZgrXuptq32wiE+oEuXBHhdx3ZrMZOX
         O/lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cvyFNI4O;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.209 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-209.mta0.migadu.com (out-209.mta0.migadu.com. [91.218.175.209])
        by gmr-mx.google.com with ESMTPS id fm18-20020a05600c0c1200b00405c7dd428csi383420wmb.2.2023.10.06.08.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.209 as permitted sender) client-ip=91.218.175.209;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 5/5] Documentation: *san: drop "the" from article titles
Date: Fri,  6 Oct 2023 17:18:46 +0200
Message-Id: <1c4eb354a3a7b8ab56bf0c2fc6157c22050793ca.1696605143.git.andreyknvl@google.com>
In-Reply-To: <cover.1696605143.git.andreyknvl@google.com>
References: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cvyFNI4O;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.209
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

From: Andrey Konovalov <andreyknvl@google.com>

Drop "the" from the titles of documentation articles for KASAN, KCSAN,
and KMSAN, as it is redundant.

Also add SPDX-License-Identifier for kasan.rst.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 7 +++++--
 Documentation/dev-tools/kcsan.rst | 4 ++--
 Documentation/dev-tools/kmsan.rst | 6 +++---
 3 files changed, 10 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 382818a7197a..858c77fe7dc4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -1,5 +1,8 @@
-The Kernel Address Sanitizer (KASAN)
-====================================
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2023, Google LLC.
+
+Kernel Address Sanitizer (KASAN)
+================================
 
 Overview
 --------
diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 3ae866dcc924..94b6802ab0ab 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -1,8 +1,8 @@
 .. SPDX-License-Identifier: GPL-2.0
 .. Copyright (C) 2019, Google LLC.
 
-The Kernel Concurrency Sanitizer (KCSAN)
-========================================
+Kernel Concurrency Sanitizer (KCSAN)
+====================================
 
 The Kernel Concurrency Sanitizer (KCSAN) is a dynamic race detector, which
 relies on compile-time instrumentation, and uses a watchpoint-based sampling
diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 55fa82212eb2..323eedad53cd 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -1,9 +1,9 @@
 .. SPDX-License-Identifier: GPL-2.0
 .. Copyright (C) 2022, Google LLC.
 
-===================================
-The Kernel Memory Sanitizer (KMSAN)
-===================================
+===============================
+Kernel Memory Sanitizer (KMSAN)
+===============================
 
 KMSAN is a dynamic error detector aimed at finding uses of uninitialized
 values. It is based on compiler instrumentation, and is quite similar to the
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c4eb354a3a7b8ab56bf0c2fc6157c22050793ca.1696605143.git.andreyknvl%40google.com.
