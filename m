Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7FCR3ZAKGQECJFL6TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 34FCC15A0CD
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 06:47:41 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id y123sf1258888yby.6
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 21:47:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581486460; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rk14SF3fqBrZ+yfTWBOYJmIhhnt20jIzI5MXdF4tKBNoUVvcPC3LCcYQnnLLmYc4ZH
         yJlcji7xBM1CvwIN66P1TIvK12qsf6ageefC8s7xUDxVRyv+f0LHRk0ufYhj+poM5kpo
         VGgmRMfVggJfQQQS52l2rw46BcX8wXh8KSCKJo+i3MjBY6tcin7Dr6BHdKCSOEObdIAR
         fgSsfJwVYOyBJbI72e0Z0xdpcWTlIyFFsgtBU0Vp5y/QDtfC70ORYL5I8vfFERLl7ghc
         2vQn4hsoyFVVSH6st/y1OaNmDksSZgBE19aFUVPxlYZlwtZJb4/DL1q8B/REcmTBOmhf
         2mnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ju1TvM0M0pOSQHmSzrqxlikbo41SNQ7RDECXkmaczEs=;
        b=nHNKIVe0QpZ6BIkLH8Oz9pVO9UWSwjJlv2p8rZB40oPTKNcicA51tOKYJ/UUuuVZSS
         ucMIScVBxQway8/rcnFmikQ3XkaVfbZ2VqECi5lykSxhuF8BAFfVJCW3R/Y0pQTWoPtd
         GeHhi5w5wNDnXLWrFp3CJMDcsfil+iVzCgeHuC7DhDpGZinOprq6KtrvSgNc2Q6O1fwL
         Mu8VEPoOz/+Z8s1aJLDRGspg+A49VSEdiJaiZWce3m4wRAHgG4DgmxSI21q/rvE/jTRl
         TmS+TC6PyeJ3hHy1w2GWBOPZx4G8YdBjx7dxzsQZHQrZTIIiOxfkgdsejn0Jc57Sa/mT
         I28g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=DumKrTfg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ju1TvM0M0pOSQHmSzrqxlikbo41SNQ7RDECXkmaczEs=;
        b=RrtPFWPvJ1VWKRO6kMbkkTBCLJdxx5xVUoHZSlhrTxn1GltGIDg1h86AYhbEgMOVnc
         UMazxheixPvsZlvORcydQpCTx2V02pRWpROxeSAb/nKUNUNz2dvveBKErRH6l2Ea0yUU
         c5n5DPjNVymFDLkQENgQLk0hknyt+BBEGXJc1aB2SxPznwnLPgaHggoKDU4nzXDWcuBa
         L3FR1rufqdmqnzTldqeCeqaXbsNqeCHQ8x3FNgsyqnHcL5wYlXzrCsJ/z+IGonN/0pyj
         2toHZts043KVGB0fELLD+ahBkZw329ttiNvreW5hJqWKXpUepJYzwLDia4VdXKIsld2W
         OAtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ju1TvM0M0pOSQHmSzrqxlikbo41SNQ7RDECXkmaczEs=;
        b=brIb8iiHXHMnNQZoolIWVrxmvfuA3H71D8Js9E6DR/EYLUxD4p7eRgW6p+ZHvSOqtf
         /mAhIlSCx3/M4KcviX+0VcomF1s7Kn2IQSWWnaC0D0vFG0fvi8F3q8C5R+OqmcKKeXAf
         oGW7I1IjxzLuzyHCI2nccGuWRgZ56367lQLSOO6V5/D0vONZr6YGxKeZCYhfFiS6/3+r
         PG0kA+VQQjk57TDKVnxEOI3XMrIcuJTXyy3JTCsSGLOzhKHPMW3eepizqUrjhBceyX2V
         Uta7ITeaSCSRynVx2XQyKbtXFga6I/Uv5D9zlDtwYKPTSqMLuq1k/sh4vzCp9n7wd69p
         tC2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU28DUVPUJ2a0/x5k8xyEYyfXgfBDGsvPvWSOxtqz0z4nwOR0tA
	/wHGWE0PBnlquxcfDlMqZlM=
X-Google-Smtp-Source: APXvYqw7xvbl1fqqx4Hu+ImzdVEntnL/X/SASFnAog5NXPoCsI9dIvhHCoYjcNYeEQIpUHqv4bjgbQ==
X-Received: by 2002:a81:37d3:: with SMTP id e202mr8535669ywa.292.1581486460187;
        Tue, 11 Feb 2020 21:47:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8012:: with SMTP id m18ls2148034ybk.9.gmail; Tue, 11 Feb
 2020 21:47:39 -0800 (PST)
X-Received: by 2002:a25:cc45:: with SMTP id l66mr5315848ybf.446.1581486459768;
        Tue, 11 Feb 2020 21:47:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581486459; cv=none;
        d=google.com; s=arc-20160816;
        b=PhGTN6WRE35yoiUSHy9zFtacjh1zjAVRnktRRzdmLidyTV7X7pJZJ8MybBKIp5QFgw
         U8jBeuedbP/l0xCrryGOITsgMGZhaxfPNmpjcyzF+hK+iB4QL73+iBXquxuLZPerKGEV
         bphXpgaRuRRZsZgPJwh+X8dmwGR3wSxNxmGVkcLPtuLbuxdc63LiyPrJDC+7XYiLEXrW
         UEMwtsrNyar1+xur/HjwNCZxKnukCFuGfMt5jPzFlnC/3geVh5ZHQEamig/Hdz6Kb0cI
         yi3l4IhhAmvMbbjqW4Z7Nafe5CtF50mJh0ATHcnsGRgww2JD8+IQ9gxZDvqjjDt4bFDT
         XCVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CaOpE+RnykMge29WfCqnRai8zpZuPSzzYfJQc7CCb6s=;
        b=c6AcLdri6WNnHBQorbeHEDu24FfIhz3EFHrjY7Zi8S98V5qsReWKx7eIjoESuLte/5
         Wv1HjyZ1ag/sZdhSipgkvTS5R+2mryi0aENE97e9xg7tT50UfCmCjVzOtU2t/uEf7AO2
         qQIQKxr0/1mGu/5jH9hVUm/1BIRbCoLoKJ9nFEhii3+6P7e0FsGKz0IctHFPKQKloECD
         QzWKeVW0gEEIO7FT3KO5cJI9yrz3M9UJ5hZwzRf4MJ2/M8Q7QI3flty5NyV9zgN40Jam
         x7WetRBPSWp5fAuiLGn+tdSILFbBu67JK2yt75lMwaQpLXTq2ellyq3j7O0W+rd5MSow
         eFBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=DumKrTfg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id y5si59037ybm.4.2020.02.11.21.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 21:47:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id p14so667463pfn.4
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 21:47:39 -0800 (PST)
X-Received: by 2002:a63:c601:: with SMTP id w1mr10154971pgg.449.1581486458953;
        Tue, 11 Feb 2020 21:47:38 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id h13sm5424371pjc.9.2020.02.11.21.47.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2020 21:47:38 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 2/4] kasan: Document support on 32-bit powerpc
Date: Wed, 12 Feb 2020 16:47:22 +1100
Message-Id: <20200212054724.7708-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200212054724.7708-1-dja@axtens.net>
References: <20200212054724.7708-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=DumKrTfg;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Document s390 support while we're at it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Changes since v5:
 - rebase - riscv has now got support.
 - document s390 support while we're at it
 - clarify when kasan_vmalloc support is required
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..012ef3d91d1f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures. It is also supported on 32-bit powerpc kernels. Tag-based 
+KASAN is supported only on arm64.
 
 Usage
 -----
@@ -255,7 +256,9 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently this supported on x86, s390
+and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
+with module support, where it is required.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..26bb0e8bb18c
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is optional, unless built with modules,
+in which case it is required.
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200212054724.7708-3-dja%40axtens.net.
