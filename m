Return-Path: <kasan-dev+bncBAABBVGJ36UQMGQESVCWUVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 869267D56A9
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 17:37:58 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40768556444sf28585735e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 08:37:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698161878; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fhr/QoPIYwTeX4JRpyu0WycB1dNxHrbWkZkD5wc/vMo9JhdNybe+BnKYf30K8CiEJ/
         8gb6K0yHnO7KRJCBFkWHThCYqePqLe84angIZnKfJbOqqQMWKntXrkYx9kUsrS7DyHmw
         F1W6CHeuBA3Vp2YqeIDNGcIaBj9pcetGGxGce6ygTOPpvmrne6OfeKU5U1goshVovwEz
         9GlfAedofV+g5VvK0Vxe+Mdr7tO78aiImQJwSS5L+WV096vxazC/65iHRUdpVknYljnF
         PjZkr+IvvZQiAYV8OxXtSxYfomk3PKSpeqS08moJayxbnILGbisug2hlfExZ7nJBZhvu
         J1bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rGV4uW0aWWdrQDrGtHiRreWGYg1pIr7F3YJbQlejOFI=;
        fh=YdJe40n1bQZ8Zp3iZn6I1d2ZUtlNbbOfpFd8CFgERIY=;
        b=HwKjA4CGS7h75gZYvITwiU/vK1hQXADk5AqoOgfA5i+jOUGi6hrCinsNWH2Bp+mDTT
         YMgi40x80JngznzVvAYmsCY+vyz8OQvpLX2BeBMJG069ZvyQEgKN13edXuHpMQvsXMDX
         1kuMJ36A1uK9jVOzBi0cYQ9+OGldYw18fdvcYZPWT92mFATofvM3Rpywmymeg7WKL+LZ
         gk5fJABgA8kSKmOhUdxLxB6tQ/LHC9spX8furvfnwkfoKocfzI71PDAlNC+ee4uskxkp
         oIj2OVvraqLuNsrfmiXMFCfFHm7STWnKPcua523lovfsfoEN1kEjhi1Nd95nyVIcOR5H
         ZjTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mR9+IMKg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698161878; x=1698766678; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rGV4uW0aWWdrQDrGtHiRreWGYg1pIr7F3YJbQlejOFI=;
        b=r6vQbGAxVYpOb6DCTGseQizWFBdMx58+IlIbeWeEulwQL3PgcYde1kd0Os1iuWKVs3
         k+fLCWPHu/9O9H5kJFmPl6pRRvil47G6qrzAJoi5nGfOLxNzk4Yc/QBcjdld3vydlwj0
         m5ruaY3dullFS/X5Cb8JLk5QliAu1FilipTOT90HchpOMSLDeoUBEq4qjbSM4KhbW2uI
         JxItS8XSiQWEum/nn3+4yPhDS2fzRPHXfic7ZcUCLfLLtgxmlcDHEhXLVmpUQdxtHFUS
         SaYFejAprGxrExRvFkc/iJ6zOjdbmulSuZmAgg97WUw6674oCJ/8UEJYzB3g77OXoHtY
         2Cmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698161878; x=1698766678;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rGV4uW0aWWdrQDrGtHiRreWGYg1pIr7F3YJbQlejOFI=;
        b=qIor620u+XjG9SlXSGfC+68CkC8B2eLDrh6boz1QmkpFMOJs6iMmImcup/alIV3js8
         f0ipiLuSVGXDTnVikzPpVIyY81b9wlbl7nigUJRkhmnEMQQOEuHi1798E+1sPeEtm/wP
         JajoaFK5G5e+fu+bwxOPvF1jmsZxk1XpvW1sW3f82RmjmQoFisw/WVkI/AQxh3w5pXoD
         TRtIwQXnLMpIomwUKBFpTLYmiCNGvdtHpICZim7nZTXTQVUgheBfnZfaG6kOHpW+jV9S
         5zqpWjFyXIu/LC8mBwDxjSzgAAWhufXMGKcRS1JN9spywWsXcK1uJNuDuHY7eTNLaC8G
         ChSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxahMfO5EivoR2k/9aoBNdO34JN1BT+kyZTSLne8I9oDkFIw24M
	V671U2UTHzjMz6xa4aNuPD8=
X-Google-Smtp-Source: AGHT+IFC9JsRbwWiswm7yO8gdYaeEq1s3npU1lPeeB0IVjoNzJ2Na3CR+BMLvnw5D3H8YIBvVLv1pA==
X-Received: by 2002:a05:600c:1385:b0:3fd:2e89:31bd with SMTP id u5-20020a05600c138500b003fd2e8931bdmr9803091wmf.14.1698161876643;
        Tue, 24 Oct 2023 08:37:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1d:b0:404:7eae:e6cf with SMTP id
 j29-20020a05600c1c1d00b004047eaee6cfls1450498wms.2.-pod-prod-05-eu; Tue, 24
 Oct 2023 08:37:55 -0700 (PDT)
X-Received: by 2002:a05:600c:3b0f:b0:406:44e6:c00d with SMTP id m15-20020a05600c3b0f00b0040644e6c00dmr10829006wms.2.1698161875181;
        Tue, 24 Oct 2023 08:37:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698161875; cv=none;
        d=google.com; s=arc-20160816;
        b=m+fZnOV9jvb+gCazezgPbPfeP+i0u6QhUhhvnuc5DQS55UX4HJyhMGPHiWF5ZS7xpm
         oBe1DvtQX02RBbXT+I2J+HM2VQIenz4T/el9jC12o2BS7uTr1YPxf/VyWNjEOYRpn89u
         zI+59Wo2eDnSgACZzzMgEjjw7RpRAcCWSf2Fmc1EGAUQ0L+Da19BsWxZlL3DGBEbd2cG
         YeU5sNEH+Vgo0oB1vLug/knG89HtYHrzBHe/85W7Kg2CvrxMD7m+uXuzD1rG0YkIMVQE
         fluqne509q9YGC7Dzh7Ys90a2kbNS+HMyICsTGXn8H20TXISsMeyugIYWIwMkzobhnQX
         bzSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=v9uv3Jcd4oOy0sU4EDVHX6hPTQsYlHbkl7jOhlyTyDo=;
        fh=YdJe40n1bQZ8Zp3iZn6I1d2ZUtlNbbOfpFd8CFgERIY=;
        b=TQn+SN4efe4GFi0Js1HHKoKPXX7DTQCMxvYWvsf2wWkTX3onpF9Mr5UsYwCzYgc0eb
         cjBEV81uFIJkQ1poTrqY/4uHc/CTTCkbXF614No766XY3xGpAlCDwcJiN4vGxLfqozVT
         8NGp23zF2w9CcKIUhG9mEOgjtfeeIadYMOoZztZVPgAtVQJw4gGcZ6ziGv0vjSdhIWPx
         rVGLxlbKOVbmAZBDQQoP2oFE7gJHkXrLMBLTEyMyA6zB9KabUAC9uXSC6Q3r/zQx/Nnu
         otPHbTL3bUDC0p9jby9HjSg6HT59QhIGJFXzpazubbIEG8O7JI4vI42h548TZ/xjpEQb
         SHUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mR9+IMKg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-208.mta0.migadu.com (out-208.mta0.migadu.com. [2001:41d0:1004:224b::d0])
        by gmr-mx.google.com with ESMTPS id o20-20020a05600c511400b004045b3248b8si79800wms.0.2023.10.24.08.37.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 08:37:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::d0 as permitted sender) client-ip=2001:41d0:1004:224b::d0;
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/1] Documentation: ubsan: drop "the" from article title
Date: Tue, 24 Oct 2023 17:37:50 +0200
Message-Id: <5fb11a4743eea9d9232a5284dea0716589088fec.1698161845.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mR9+IMKg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::d0 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Drop "the" from the title of the documentation article for UBSAN,
as it is redundant.

Also add SPDX-License-Identifier for ubsan.rst.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/ubsan.rst | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/ubsan.rst b/Documentation/dev-tools/ubsan.rst
index 1be6618e232d..2de7c63415da 100644
--- a/Documentation/dev-tools/ubsan.rst
+++ b/Documentation/dev-tools/ubsan.rst
@@ -1,5 +1,7 @@
-The Undefined Behavior Sanitizer - UBSAN
-========================================
+.. SPDX-License-Identifier: GPL-2.0
+
+Undefined Behavior Sanitizer - UBSAN
+====================================
 
 UBSAN is a runtime undefined behaviour checker.
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5fb11a4743eea9d9232a5284dea0716589088fec.1698161845.git.andreyknvl%40google.com.
