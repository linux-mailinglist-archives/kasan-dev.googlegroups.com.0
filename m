Return-Path: <kasan-dev+bncBAABBYWBTKGQMGQEGDNYI6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 05E3D464109
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:35 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id y21-20020a056512045500b004162526955fsf8553896lfk.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310114; cv=pass;
        d=google.com; s=arc-20160816;
        b=G95g2Tl6t6qIjLlfsb6SybaaDG3JsWV/RRIJ5/9wMBtN2QauGiDK1JsWaJwGxndyxI
         pv2jEB+BOoShoZ82z07fLM17hIemU1v/zW0DDhFlRoLAnMOgpdaNZpChQbo0sAAs8x3l
         oJ5sZs+Vi2/ZewKaQ2BwsIqcqIY6VQvtGOwDJyU6FdgjW6wH11S1Osm5MQo+K/T89jc6
         Oq30x6IMV7kjI/6w8zu4eAFPL/pkohIq6p8qKqrxmTmZIJRI++PVITM1Eewx/+aYuEOG
         PnV8RBe/5+ZnM+dHI5VAcDTX923FjWCcDekYKiqYBlKOez+iMtfwKiELBG0J31VpiDPF
         Wgqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lHFyy+nJU+o7rxpVbp/CAjLNTjBgyDh0Sx2WSmC0Q04=;
        b=KJizzyHiGFWA7pZbI8wITyFdcT2FYggp8z8D9ore98Lv8GQXwcmMS5aSclUgiPMdUV
         PBKRVXOqMYZXeFeCbK+BJWzqUtX7EgNUJZfqgy8gsiV87qAgtyFuB33gRYDDPXbmeBQz
         3Z3WKWuIBi/+g9b34H7sm7h1ktDotfh8G5riKn+7EeaIiOvQsQ6oqZG8RRls0FY0r27t
         axLsOqH3Lxcv9O/dSGKjKFUKhknA3w6X+rZS2YpDOxUgW3NgJMdZVO3OW23nFUVtYRsB
         dO0ZjmT/bzf4KTU1XRBdXZQpD0MD3nfZTxf8X0yHEaVsyLbOoiEZLWsTmM+a2N9hdE/t
         iwtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ai8bN5pw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lHFyy+nJU+o7rxpVbp/CAjLNTjBgyDh0Sx2WSmC0Q04=;
        b=i4dk1R/lMdiJyHqhSqECFy4RRe6V47gqi1KOwUg2nT3KRz9kVvUhjc1ivM5vT6/u/Q
         mZ16HlDQaUMpFdnssmm+GExblog9UPtr02GCHOx9ldHuOG1ngbfa/EeazcLK576h4iuX
         s3dKQ3IoEviU6koJ2x+qIyYbEc00Yi/DAYXjKMI1QKGFNDCV5/F+Pzds1lMO8cctYgrF
         Lxfg63v+uGEQ5HvyAgBBhJ/cL8c+evLUF9hpps3cy998yLWJLW7ESdFmTXpaeptnvYJC
         sLfX3d4perBvoqM49HkfjLhqsb1ATym8Z1Ch7vBwBSr1v5GISczf74Vnrwxy5DJLOhh3
         QTkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lHFyy+nJU+o7rxpVbp/CAjLNTjBgyDh0Sx2WSmC0Q04=;
        b=OA/BBtNoog9pc3N6k8SxwSDkLFHDuuma9obxxZZWxZ8yD40fpJsOMjkUyf9rSg9aGw
         QrfBAPR8yZzY/1F/wtelXA7St+zShwk/xOvIkOEfNc28Sh190LPolw79To01iqgb+BCj
         6/kf7HLi9WfbPHJkG18/naF30uyl0Iro7vbtWw+jbYteeS9TdWR1IlM3jVNptvF+ov7T
         BGdm5E6xNAfWNwqRpIHpOnAKEPCbWQn37rBC8voajYDhJvaai1NysWjSFk2WmoNWSoNn
         rRm9BpN7UMxAQJOKM6cmX8GmxmDAE03q5ca7lnVW+54r07/ZoQih09Gjn6hjUYRH1Bye
         Z1KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531KhTAj3tBhaNScgErRv3eOo93ICqozUIb+B2RLvU1nxICyX7er
	Zuo58W4y+nOSjuNzj25EGys=
X-Google-Smtp-Source: ABdhPJw77AU4mvncnOIE5jQeJv6fgQgX9PV6d/pf2p06CczHmXZ3faYIgaAAt7dO1cdgIlGhy54gmw==
X-Received: by 2002:a05:6512:b0e:: with SMTP id w14mr1841309lfu.433.1638310114608;
        Tue, 30 Nov 2021 14:08:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a222:: with SMTP id i2ls12060ljm.9.gmail; Tue, 30 Nov
 2021 14:08:33 -0800 (PST)
X-Received: by 2002:a2e:720b:: with SMTP id n11mr1583153ljc.351.1638310113897;
        Tue, 30 Nov 2021 14:08:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310113; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9ksW73BUHmDnyiNrdyVpgcbIt0P95V0HmqaPe0Tv320X5UAfxek0Nogm7GCHLR23Y
         Xp9ep4uEDByUG5897QSi8qOzSfHc17AoWFyWYxdUBIGbbkFSqs9spQmPKEYQeIcKAzWH
         I27MNh1ltgg5pRs6O6CP9ycg5JjgD/NYCAxwjKOEQnEeFEYhSfr9f9j4U8M8F7yKNuvP
         tOicrrnjmmsBB4s+Wv4ETN6D8O+Ec3tAef8x6vMHkVW9EmQgni1RQ3ZQrp4jOnWzph74
         ds5yEf/Gz0yOctddg8FvRw6xBe+a1fqx0hoLG8sU/6eAwMuNH3oxbfvWd3GZrIPnTaNH
         +L9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AV0M9szKvSlfXhwybxJe1jA9V5abexpCELFOGxjWDjg=;
        b=LXE89sBKe+rK9yrCX5udeGRriiIhjqG583ontK2pn7/WHPOq/6UsXO18rw2Yck9oXc
         SM9eiC5hT/kSLVuVoDpDOJemJSceTccY6XMOOes1eBe28qwAjr736NUytUxMx/Q8AIP3
         qpSf6uSbzBaUMdjAja2NwXVewpcj5xCC6fEw2PYPTB5UXZwHbETxFsJmhiH/Qz0lwgW/
         oY4ZYAs61MVg5mHtWKSNc1ZIQL01z49mRn924N+25KAOxE8PlLxnYe4FpQs2TlcftyTu
         v7Sg+Ov9LR3acLFdoN9trkqQUFHXDXSTzgA70nPnxZ7Y8fBncYHyZsKMmV+kxse9+WGJ
         J2Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ai8bN5pw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c15si1706974lfv.8.2021.11.30.14.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 30/31] kasan: documentation updates
Date: Tue, 30 Nov 2021 23:08:25 +0100
Message-Id: <0525538d5a3a57c831f4e2442824768af56109ff.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ai8bN5pw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Update KASAN documentation:

- Bump Clang version requirement for HW_TAGS as ARM64_MTE depends on
  AS_HAS_LSE_ATOMICS as of commit 2decad92f4731 ("arm64: mte: Ensure
  TIF_MTE_ASYNC_FAULT is set atomically"), which requires Clang 12.
- Add description of the new kasan.vmalloc command line flag.
- Mention that SW_TAGS and HW_TAGS modes now support vmalloc tagging.
- Explicitly say that the "Shadow memory" section is only applicable
  to software KASAN modes.
- Mention that shadow-based KASAN_VMALLOC is supported on arm64.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 17 +++++++++++------
 1 file changed, 11 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 8089c559d339..7614a1fc30fa 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -30,7 +30,7 @@ Software tag-based KASAN mode is only supported in Clang.
 
 The hardware KASAN mode (#3) relies on hardware to perform the checks but
 still requires a compiler version that supports memory tagging instructions.
-This mode is supported in GCC 10+ and Clang 11+.
+This mode is supported in GCC 10+ and Clang 12+.
 
 Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
@@ -206,6 +206,9 @@ additional boot parameters that allow disabling KASAN or controlling features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
+  allocations (default: ``on``).
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
@@ -279,8 +282,8 @@ Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Software tag-based KASAN currently only supports tagging of slab, page_alloc,
+and vmalloc memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -303,8 +306,8 @@ Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
-memory.
+Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
+and VM_ALLOC-based vmalloc memory.
 
 If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
 will not be enabled. In this case, all KASAN boot parameters are ignored.
@@ -319,6 +322,8 @@ checking gets disabled.
 Shadow memory
 -------------
 
+The contents of this section are only applicable to software KASAN modes.
+
 The kernel maps memory in several different parts of the address space.
 The range of kernel virtual addresses is large: there is not enough real
 memory to support a real shadow region for every address that could be
@@ -349,7 +354,7 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and powerpc.
+arm64, riscv, s390, and powerpc.
 
 This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0525538d5a3a57c831f4e2442824768af56109ff.1638308023.git.andreyknvl%40google.com.
