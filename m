Return-Path: <kasan-dev+bncBAABBTMJT7CAMGQETKJER3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 76FECB14220
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 20:43:27 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6fac45de153sf73677296d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 11:43:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753728206; cv=pass;
        d=google.com; s=arc-20240605;
        b=lciRDPrC+1na5/ojyE2Hta/mHfV2AruHYnyiHtV2ZoE3r9ITmhANVMAnfp7ec95WHh
         wGg/+hVMAQXzEcQUH9Ee2QS1ZLeMXRG3nrCx8d3Zzv806n2sJcAWHG4iN7woiKUpxigd
         N7osJjtdT1PaQH2sCUr9nVfLwtyxEPstN04J5XTRN8pUiT20cl+hbpQYkdbiSIaiL7OZ
         hzbKdDnUNVmwKE+X4o5ws34i5+ULpJEBR6evusc58i/admDMbMV/kf9F6wYKv//Viwza
         vFeJ2hNnV0+goP39ZQf425t1dK544w9bKz6GeIrBON3OxqzJU3o3n5wo5IR/MYBKLaGG
         nypw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ewRfr951PftqupZ3Si/d5fh+0PlBYgdqojmZTTvXfZQ=;
        fh=1bqCdXW0vwQPyR46his+RJOi8hAQELGLgxKESle9oAc=;
        b=dtYnm48bHH5HOjL/omQXVgF2nCQqj04uld39gVgRZIir+SePKXZfIR/qmkSZLFTwMu
         SPEo7M0SBiVO5kw+BB/gMGi4UjshEod8ZsU/URt2+p2+6WFwS3fjpVbig2MSIl0/iQmV
         s+Mqans13fQHQuE7bSIX/nKE2s57IHWChTTtzqtawnPWfO2NdKW0c/hLCe2aK4+jBTyY
         N/ZQfAm/VjxiQl7eylpw07LN/y5eFKHkmRGOvYgKco1QsEj1CD/qYd/ZaNDM0AYuTqQC
         xio7qt1guJAtEITtt8XEzeE7qyRP6tAXWysasHs8wwPzfmmoFUj/3Sn41N7IC5VH/SsK
         rFvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=FlNeO6Nx;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753728206; x=1754333006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ewRfr951PftqupZ3Si/d5fh+0PlBYgdqojmZTTvXfZQ=;
        b=Z9ezjloBF3oNWk4pZxgznH/jOr/U8AGcnnIzapn5Ke770CfzaZLdG45WjbgXgWcLUx
         1STnO/ttEs6fVnDOEtN8icuhfxzMQ0mise1vFfgCOwQ6GcAte2IK3qboFa4YfBVad0pO
         7h43Fq9tHsYGuU92J/lDFXjX7t6AkGDRB7SClQWf6ZYDGBC2fjMAK0zuaM+G0yuJEiWM
         vAfHZLC4p6vf5yxDkDaTbuC9j6LYpMiF/vYNxhBPsiU54MIhdV5FB+ZbDrxCynUARJoZ
         SdhFlOUMv0NL8AzeqpL5jj+6uTmXxSAvgcorsKfAQNsUicRemJll75BEJp5Kdz/yIeeP
         72wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753728206; x=1754333006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ewRfr951PftqupZ3Si/d5fh+0PlBYgdqojmZTTvXfZQ=;
        b=czZCZxvROVl9YQEls+FFzxox4sUsW7fyGbL9xXI93UGWSzRGaCjtT+V1tGlNxo+O6k
         YJp3DLMiZJ2n+YA/hT7YPphp5yeziOKfthR5WBI6bYZENocxKA6eCukbzQJjDiwNM4jJ
         VnU23vAZzbs0Xb0Hs3+CI1Mv8VOevZsPHwS0i5hn86Q0PHQf0+HvP7qKuBTf2CCrfoZm
         EPP5Vg+G79oBqnynG8mxz0P9PtoPDDNT8PEaHWHZGgBdUdt8wpyvkOS6jGiV3K1cJLe/
         CjGRAHb69oJM7ZFYBWTksOp/lSCB9by8nYs0Kg6PcvkBRlwKvPIjDUVpnK+KG8PW9YUs
         SaBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYTimKHUhwJD16LT5mIykFhmnCPQ6wkN0rrg6YSrUCrgqfy1VbQgqVPy8dj8DsFUo4swmSOQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywhl+SjnGFnZ5Cawa4XPBKz1bOwqOgv7SADBL2ZBfVq7LRKknfQ
	+1sXpbBUZmfK8q3uU0igSHf2l8soja9WRmD3ACSlllg5jYrzo/9at3Xi
X-Google-Smtp-Source: AGHT+IEJuRJywqXgaRxh5Xo0C6wBB1GB3dS2W/o6wTVxr0buKnHne4tjcpFp99eM+oA9brolwee76w==
X-Received: by 2002:a05:6214:e8f:b0:6fb:25f:ac8c with SMTP id 6a1803df08f44-707205a5506mr204590826d6.31.1753728205623;
        Mon, 28 Jul 2025 11:43:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCCHglmSaqLDrj8iiNFVa//UL+CWkwD76fa+Yny26h2Q==
Received: by 2002:a05:6214:8204:b0:707:56ac:be5b with SMTP id
 6a1803df08f44-70756acc0c4ls2879796d6.1.-pod-prod-02-us; Mon, 28 Jul 2025
 11:43:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVG97AqW/vDEYhdOkZfhlC3/xKbYnnOI9m6LoNB5cYI8K05sLHagXM8EVMrsEF6Cxps6/7gaNLnlg4=@googlegroups.com
X-Received: by 2002:a05:6122:2a45:b0:531:2906:7525 with SMTP id 71dfb90a1353d-538db583a56mr5663938e0c.6.1753728204792;
        Mon, 28 Jul 2025 11:43:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753728204; cv=none;
        d=google.com; s=arc-20240605;
        b=Xv08WAMxJM1eBvXXHEZUBGq5RmYkXKjV8RuvGLhnK5sCcYmXTv4aaSUqQ/3vEbGm21
         ggGiK6WAbiWwywI4QOT4dxotrKIGhNHbSHLQITaOihI9jDeq84fW3KvGV26pSFl6mcR7
         rP8jwuWP82jHOVG8if/2lAuf6bsU4yoFK9XCMCCoVzgCYL5kl/IgXPEIM/z+eyhXkMIG
         KNuNfxFeLPAXSZ9Cz20mcvnfv/GvjjphLCghMaUOesYlkmip/QpnAKuje+CjyDiDKi9g
         FkB/o3shQB+f+HwljYVQBfeSpw8naQB4jgRnqdFZntXjGrfe0go6nOQn3S+1gvz0URwo
         4JKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LJWZsgdfqmGbGMEUvKqlGSsZP/ZufiEcjtM+tKAgzuA=;
        fh=Spr1FW9jGs9z/q/FiUd9ELvZNQivoYeLPzx4dkbEjbM=;
        b=I+uK/2OnhA8m4yIPVIYQGVIQdyoGTRnjamh8M/FYK/x6wMgnJM+TCD9ZjT8PGttw0D
         fYucvptXy5qm7jr1gZLUP63vgIST/BGxutPiiYX5eBZe08EOIB9QpDHK3cXQazWoUDD2
         y9SIoh2l1yTdQNQAsfeudWEvDeM68Jui+PDmUHnh6sjXmxNcbB+6pfuilhasBDf5V4LZ
         QN53S4+L+6A1Tzl6NyI1zzraur1v2hRYCqncmNaSPJABst4CG9uLsVFm8tecxmvRlwc7
         2Zr5UKptICRO+hO7xQbhpvCGEUL3oW4ddwggasraLbBNcDAwzzg9BxTh76HLgjY23Ktr
         OWMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=FlNeO6Nx;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
Received: from ipo7.cc.utah.edu (ipo7.cc.utah.edu. [155.97.144.42])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-538e86fa87asi255622e0c.2.2025.07.28.11.43.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 28 Jul 2025 11:43:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) client-ip=155.97.144.42;
X-CSE-ConnectionGUID: hP2vyLc9QvKWD7m64bTLyQ==
X-CSE-MsgGUID: y+JZmYdYTSWX6T2DUuf2Pg==
X-IronPort-AV: E=Sophos;i="6.16,339,1744092000"; 
   d="scan'208";a="398910703"
Received: from mail-svr1.cs.utah.edu ([155.98.64.241])
  by ipo7smtp.cc.utah.edu with ESMTP; 28 Jul 2025 12:43:22 -0600
Received: from localhost (localhost [127.0.0.1])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id 8798E3020EF;
	Mon, 28 Jul 2025 12:41:13 -0600 (MDT)
X-Virus-Scanned: Debian amavisd-new at cs.utah.edu
Received: from mail-svr1.cs.utah.edu ([127.0.0.1])
	by localhost (rio.cs.utah.edu [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id u5RmEL0Ur5UR; Mon, 28 Jul 2025 12:41:12 -0600 (MDT)
Received: from memphis.cs.utah.edu (memphis.cs.utah.edu [155.98.65.56])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id ABB523020E9;
	Mon, 28 Jul 2025 12:41:12 -0600 (MDT)
Received: by memphis.cs.utah.edu (Postfix, from userid 1628)
	id 556EB1A02A7; Mon, 28 Jul 2025 12:43:20 -0600 (MDT)
From: Soham Bagchi <soham.bagchi@utah.edu>
To: dvyukov@google.com,
	andreyknvl@gmail.com,
	elver@google.com,
	akpm@linux-foundation.org,
	tglx@linutronix.de,
	glider@google.com,
	sohambagchi@outlook.com,
	arnd@arndb.de,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	corbet@lwn.net,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Cc: Soham Bagchi <soham.bagchi@utah.edu>
Subject: [PATCH 1/2] kcov: use write memory barrier after memcpy() in kcov_move_area()
Date: Mon, 28 Jul 2025 12:43:17 -0600
Message-Id: <20250728184318.1839137-1-soham.bagchi@utah.edu>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: soham.bagchi@utah.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@utah.edu header.s=UniversityOfUtah header.b=FlNeO6Nx;
       spf=pass (google.com: domain of soba@cs.utah.edu designates
 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
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

KCOV Remote uses two separate memory buffers, one private to the kernel
space (kcov_remote_areas) and the second one shared between user and
kernel space (kcov->area). After every pair of kcov_remote_start() and
kcov_remote_stop(), the coverage data collected in the
kcov_remote_areas is copied to kcov->area so the user can read the
collected coverage data. This memcpy() is located in kcov_move_area().

The load/store pattern on the kernel-side [1] is:

```
/* dst_area === kcov->area, dst_area[0] is where the count is stored */
dst_len = READ_ONCE(*(unsigned long *)dst_area);
...
memcpy(dst_entries, src_entries, ...);
...
WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
```

And for the user [2]:

```
/* cover is equivalent to kcov->area */
n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
```

Without a write-memory barrier, the atomic load for the user can
potentially read fresh values of the count stored at cover[0],
but continue to read stale coverage data from the buffer itself.
Hence, we recommend adding a write-memory barrier between the
memcpy() and the WRITE_ONCE() in kcov_move_area().

[1] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/kcov.c?h=master#n978
[2] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/dev-tools/kcov.rst#n364

Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>
---
 kernel/kcov.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bd..f6ee6d7dc2c 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -978,6 +978,15 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 	memcpy(dst_entries, src_entries, bytes_to_move);
 	entries_moved = bytes_to_move >> entry_size_log;
 
+	/*
+	 * A write memory barrier is required here, to ensure
+	 * that the writes from the memcpy() are visible before
+	 * the count is updated. Without this, it is possible for
+	 * a user to observe a new count value but stale
+	 * coverage data.
+	 */
+	smp_wmb();
+
 	switch (mode) {
 	case KCOV_MODE_TRACE_PC:
 		WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728184318.1839137-1-soham.bagchi%40utah.edu.
