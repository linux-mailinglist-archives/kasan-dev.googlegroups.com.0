Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV5RVXCAMGQEPZ6Z6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id AD059B1709C
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:51:53 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-45359bfe631sf4351875e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:51:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962713; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOrOeVj0ITri/lnLd6dKD82CvugQZ6FZRNJi/KJALQ3r9iOJEDjoUtPAtZ8S8ywcxL
         xp7j18+s54tbJnVhVe5pVyizy/ZaRV0j7QoMseb7PIQF+70VL2qLsQBxJTEJ1pYaYupO
         Mt0JaPjwExs6/SZS/C0Sn0C07roYoNeH9ZmJc0SVrXfcCy7nDqYBEilTpMk6YP3u5MTw
         Hdk3nWMR44Q3c8nZnzceArdz86KhKl4WlQYAeR8CXl9oPqri64Gw22X5/aCAwLuALLEj
         1EQO4RkBplRnFZxNAMxSTwmrdKv1apkII3vJ6t9mMia7PPC3Uayuh4YSqesjJssqbKuw
         xV3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VnJ2y5k6ZSDgRjGRLsUxvzwDvaFNVfYqoR8MI0vfCnY=;
        fh=NfrMi3tLGNFztbfTG0PdrP4CAS0Zf6XsYClpQV9sJYM=;
        b=bUsI64hY02zssNf92KiplQzXa5tifJEhvqUF7BP+uMzBZhPzH50J5a04uUNOrGQyzr
         luTvtSfrg9Px1q8mfivvJrbdqsHyk64oMtcabuc5aFerK5PP5eSH+5r70U8kuV1kBJYW
         2nt2eenfQz8mP7KzvJJyQw0qJbfDVKGlzC855e1+3xJf4mtOabGpPst5QIebL9Ce/xP+
         JlnbPLsWqxAkg5w62pTn1dMlMqywCmVk/HEwcXuhSRtIOY6CiB5jFOQ5++HTMI08GWnp
         YFh7KfsEoHdB0uRsvgFtjt2/HgF3IohAvPSXt9OBJpeACbd+hZUc4Mr7C6vREzl/OjFG
         MSDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QsX8wRAy;
       spf=pass (google.com: domain of 31vilaaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31ViLaAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962713; x=1754567513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VnJ2y5k6ZSDgRjGRLsUxvzwDvaFNVfYqoR8MI0vfCnY=;
        b=tpvrzpdqGTVsaR28mI42ZsWnqeYamAHLEACqOKsKXHQ+aVGg72sPWQEtVkQzcEG0LZ
         K2wHti2d3jkxXtWZp1WY2e69tOLMl8XbHXraGvD8hhM1HNKjPmJhXKUqjECEK7RMQZt+
         WYqKe8d26KSpaY+P0+Rz9NTn+EyPxUGleOnwq0oSBQbiJLj8ecFAmvOX0kX3zuo08nYM
         0nkbpTRP9f7Kfe8Rfrho9jyfCcC2VIfZ6exxon4lpkQ1UHrbsBFPbmG0qaHlWQhUfQw7
         AQcJtVZsbgUkIKTjSbCqcK4OiMsxka5crfozB6X5iYnp1cp/gBVD64MoO7im2wOXLMLV
         8TtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962713; x=1754567513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VnJ2y5k6ZSDgRjGRLsUxvzwDvaFNVfYqoR8MI0vfCnY=;
        b=lsvrfIYeU86Ry84ViJIa3Xe+uU0Sk+HdZ6Brm/iMz3cDG7H3biT0TXt7mikNNLTknD
         QSHD6SQogjjeZ1JD9jyde59zSEcLVbWDUoQSyDActgZBNjPBVESKZP0t8iVVQEEbrTkD
         6sYoCoeu+B2vfAi9d9xrMMU2ebGYNDgP2KcacjB4s+U2eh1QjfdNN68v9wGyusxAfJdT
         Gi+qcTJqbyiBCs0T8nIOvi4oXX58drZRrkX5jN5yLDtVTKML85JzuzKfIjGO/LRxn7Cs
         BtJDgovz4AfwMqGANKFuQcXrbKwNCzysn/Wsz3kvVmqz/WoSzZMKJLDNWWCCf0AmNft8
         Pj0g==
X-Forwarded-Encrypted: i=2; AJvYcCVg5yB24olsG6Te4QYONWJZ3uC0Lh2oBUs7Zkq8/fuPXVGKFTg1hVWcOvEXvB8hUobpGNtv/Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy56xHBRJwR/JvJw4i1hiS3HT0uWqap1PHAkoSnXb9bFmGlbzR8
	FFTuV7WypdbWOny1FUCWw+UxCXrzRPDkjmyeHutj87TAFqmwgWfgBBpC
X-Google-Smtp-Source: AGHT+IHOnT1HMH2DSKzJpcRkuVQnEKvaMYVxugAg20G6UsIq7CdOBdvTz8ueowzjdWru9qN5hAXA4w==
X-Received: by 2002:a05:600c:8706:b0:456:1e4a:bb5b with SMTP id 5b1f17b1804b1-45892cea07fmr57994095e9.32.1753962712517;
        Thu, 31 Jul 2025 04:51:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYLsWDWcNUMliBm3E3up/GF0/THZAvvvMeSV1EZVj+lQ==
Received: by 2002:a05:600c:3b98:b0:456:241d:50d1 with SMTP id
 5b1f17b1804b1-458a7e2907fls178385e9.1.-pod-prod-03-eu; Thu, 31 Jul 2025
 04:51:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvWMW0Y502xC6Fv+5xt1DSvEVgInHFsryi1fhmgJSGm/sYv9Qc6q8B88er5MtWFnZZT35KLWS2xao=@googlegroups.com
X-Received: by 2002:a05:600c:c177:b0:456:c3c:d285 with SMTP id 5b1f17b1804b1-45892b94d53mr60023605e9.1.1753962709891;
        Thu, 31 Jul 2025 04:51:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962709; cv=none;
        d=google.com; s=arc-20240605;
        b=aoUSMBR6S+vJL2EdgKnospucKXv0V6PUoAThnOmQ8LJnTp628CE8Xc0iNvXvuoAWgW
         AVhhay97zqnMFlQcpTDIzMt7x3RBuHvXpN17n3nPy4qEfokWXsoxZfSlPjmn3XZMghRN
         ydH82v4EYqsDs0UvXN3zUYlQKNMqKjPIhh2eDcH0CVt7T6fjYMpdi7kfcioAsfIlzqwY
         3IfJUBmkzJ6thNteWGwvy9nmKTlbCG3IHxnNqprbCCbEngFfItappBQAKFAgKEMXA4Jy
         X++aQtAY0q52SyigtTdh1IXQSlPprFZGAsofV1xyPBAHxQ7TVEgea2TRjwieUzeGeMez
         a+iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=CQvXhi+JRNfdVXUC3A+PGrkf/DlYZ6BztZDrEED0HWA=;
        fh=ScQg9LMG/V0HZcpRLnjphduKD71yzob7cjeZfQM+2ug=;
        b=kZQNgL9dgaL2pqLvUjCrsCZydnTg4hdpSw9vv7MhlbUo63EyVnJRsPE2mgKt37ZO03
         Ccuz3jFaliSt9NYcDctFozgAp/oLaVia6/xsKLVXdqAzFF9nTNR6Yai/xQpUAi1UQTh4
         Xwh21mJHYjcTdhooxODlYldUTgCfoHDXzWXpVnfYsBKdRcQHjB+Rn8qiXl/Zimy12Ukf
         8kVcL87TNf40qxsUrZwTWXXx5BVYSNw6bb6ddjBspDsnR3HP9tADUEQ10MgUivkshKJf
         Qsd4touA0LSytPmQvl4y2IC3kxuyQdWjCIQajzLcsV/6OEcOEvh8Uchs6M0kpOTaApNB
         5YzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QsX8wRAy;
       spf=pass (google.com: domain of 31vilaaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31ViLaAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si2385775e9.1.2025.07.31.04.51.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31vilaaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4538f375e86so7242615e9.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXeHzD51DpULRY7yb1xwFE9UQLBZUsEGTfXutuYaKlK1Uoh13DwA2eXdAE4KH6ax3E7oU7oKLbtCJM=@googlegroups.com
X-Received: from wmsp27.prod.google.com ([2002:a05:600c:1d9b:b0:456:1ba0:c8ac])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1388:b0:456:25e7:bed
 with SMTP id 5b1f17b1804b1-4589af5ba2fmr58419925e9.14.1753962709498; Thu, 31
 Jul 2025 04:51:49 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:31 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-3-glider@google.com>
Subject: [PATCH v4 02/10] kcov: elaborate on using the shared buffer
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QsX8wRAy;       spf=pass
 (google.com: domain of 31vilaaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31ViLaAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Add a paragraph about the shared buffer usage to kcov.rst.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v3:
 - add Reviewed-by: Dmitry Vyukov

Change-Id: Ia47ef7c3fcc74789fe57a6e1d93e29a42dbc0a97
---
 Documentation/dev-tools/kcov.rst | 55 ++++++++++++++++++++++++++++++++
 1 file changed, 55 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd24..abf3ad2e784e8 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -137,6 +137,61 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
 processes only need to enable coverage (it gets disabled automatically when
 a thread exits).
 
+Shared buffer for coverage collection
+-------------------------------------
+KCOV employs a shared memory buffer as a central mechanism for efficient and
+direct transfer of code coverage information between the kernel and userspace
+applications.
+
+Calling ``ioctl(fd, KCOV_INIT_TRACE, size)`` initializes coverage collection for
+the current thread associated with the file descriptor ``fd``. The buffer
+allocated will hold ``size`` unsigned long values, as interpreted by the kernel.
+Notably, even in a 32-bit userspace program on a 64-bit kernel, each entry will
+occupy 64 bits.
+
+Following initialization, the actual shared memory buffer is created using::
+
+    mmap(NULL, size * sizeof(unsigned long), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
+
+The size of this memory mapping, calculated as ``size * sizeof(unsigned long)``,
+must be a multiple of ``PAGE_SIZE``.
+
+This buffer is then shared between the kernel and the userspace. The first
+element of the buffer contains the number of PCs stored in it.
+Both the userspace and the kernel may write to the shared buffer, so to avoid
+race conditions each userspace thread should only update its own buffer.
+
+Normally the shared buffer is used as follows::
+
+              Userspace                                         Kernel
+    -----------------------------------------+-------------------------------------------
+    ioctl(fd, KCOV_INIT_TRACE, size)         |
+                                             |    Initialize coverage for current thread
+    mmap(..., MAP_SHARED, fd, 0)             |
+                                             |    Allocate the buffer, initialize it
+                                             |    with zeroes
+    ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)    |
+                                             |    Enable PC collection for current thread
+                                             |    starting at buffer[1] (KCOV_ENABLE will
+                                             |    already write some coverage)
+    Atomically write 0 to buffer[0] to       |
+    reset the coverage                       |
+                                             |
+    Execute some syscall(s)                  |
+                                             |    Write new coverage starting at
+                                             |    buffer[1]
+    Atomically read buffer[0] to get the     |
+    total coverage size at this point in     |
+    time                                     |
+                                             |
+    ioctl(fd, KCOV_DISABLE, 0)               |
+                                             |    Write some more coverage for ioctl(),
+                                             |    then disable PC collection for current
+                                             |    thread
+    Safely read and process the coverage     |
+    up to the buffer[0] value saved above    |
+
+
 Comparison operands collection
 ------------------------------
 
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-3-glider%40google.com.
