Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMENUCDAMGQESVGW4ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AB1B3A7375
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:29 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id q14-20020a4adc4e0000b0290249480f62d9sf7895088oov.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721648; cv=pass;
        d=google.com; s=arc-20160816;
        b=FV6ZA6p+o/2L5SrFjNlsAF9FfdeL2L0fK6Lboz+4Fw5J/yXIav5vujT873fmkSKFFd
         uQTyaalIWgDIJDVF8Cvdn/BA1Vo6CEpPEhcspT6GCn9eLIBxkWzoszq7bz0numhpRpL4
         saAHRbQRTvdzzZN4jE6P5tdAn9gF3fcScwAxzbALAXWr7svZvOQSIH7dkKrcjs0yESsN
         GoVs4TI7BQ8S/vDVt6lc/TIanJieqJgdLC1Xdjj2MV451nYMQSEX6LyDntg2Q9yT2cYG
         Ib+B+ZwVUCBmReft+LK1WkXFM53KMwmEKr81AhLjA2h/7L8TuuFp68FdzE1AnplkRE+N
         xstg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AMxXljK48BIsderEvtmfEYc0Z5ffX91nXyFt+GI3rWI=;
        b=b3gVbFB6IvUWtiM7gecmiAcyDQ/ZIPxyIoFgGzSvYD0+B/rQMgd3RCS5fAYM72pNYL
         nMnauYuvxe6uV2RpQVX0a7gKx4KHcgLoKUaNZ2MJy6I61j0ZTVdsmvzSo4kk8zkZT0uh
         HZ5oz5qsOzDyNwBcWqe8plElsXH80qBw3gV6FhD6Vqmmy6JNnru6erFunkk89XuNc8K4
         N/zrxk+mn7WQV5Dk1kL7Lg5D+8PAiEkPIMnmF9SMekJBRdrtXzud/qLCfFOQGU70Vl91
         CYSXFRWag8feZHtJv8c/cgPkv9Gt6dnjlAw60gedSuZZkceMTPEXdvbML7M1Ym9MI25d
         BgdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=X0nswPKS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AMxXljK48BIsderEvtmfEYc0Z5ffX91nXyFt+GI3rWI=;
        b=PHh/EEozIdv9/EvozPIlrbNAzGJeXX3TMDlVj3cUwq/ypCQ+suP0lPA6RmgkGb3Hd6
         cD5veiB/XdBhYD+K6CJvrNI4o/xTGDfKtyYRw/57sV8i9EOv52JNvg8Tp70pV0nYwh8C
         AJe6OihiVlo3lP94Aj8ePnUkEtorSg6tYVtLN1buFhi4lM1kVea/0Dp13GgGq32KQ0r5
         cSX/exxIP2qwT+cDERMf88cr656S0sFoz7FVlxmXWW+JwljbZulBZ71Lqn17+3mOWi8u
         qYkdO8gK3YOAAPQM6XXdDiPX7MuUG4bs/w4yAGWaJeudHGTROss4F6o1iWK80yTU2r/G
         lHzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AMxXljK48BIsderEvtmfEYc0Z5ffX91nXyFt+GI3rWI=;
        b=DdB6ir6uWDbWFhUYEjc/MRPY3xLi7DbdEgSb8spBDDL2C3DX9AnrlUFvX/ZK2nb1xm
         Kt5EkSZf5gJDdYRzJwMWUdBKEYziNHEPB45k9qvowFzs1m33g2NVG7gLBjZohcwbKcvc
         k1T7ie5ogWwvfwXvyeeBlk1Nz9OEy1xXaluYvtezgs1Kd2yYw02gg1sdhEpasofq6ddX
         ld/BqdK6QcHk7enLEcnJZYkL7PPB47mcodhKL2L5gtiXjpLVj8SK+I7DbTqva7TYgFMT
         SV9en5oMXXUMZdfE/eLrrBp/IUNmK+tl5BB2qDxJmzDQQHtYoG7RXGZNgYuSg/s1qW5y
         y+Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w2DgRA0gNm8hBviwLE0KK9rIDHdcSYV4VfjWEMKxUrFb/tQCN
	KbKuUXSmigZkfJamv+aZ0XA=
X-Google-Smtp-Source: ABdhPJzVUdLZsynx0fNgCPMM+tM0fxDrAMY4S3nbQNO8mcmKObOyuOHOWHrDAfPwx9iQ9NHGpJDv2g==
X-Received: by 2002:a54:458a:: with SMTP id z10mr12511149oib.6.1623721648551;
        Mon, 14 Jun 2021 18:47:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:641:: with SMTP id 62ls5742153oig.0.gmail; Mon, 14 Jun
 2021 18:47:28 -0700 (PDT)
X-Received: by 2002:a54:4385:: with SMTP id u5mr12387503oiv.30.1623721648186;
        Mon, 14 Jun 2021 18:47:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721648; cv=none;
        d=google.com; s=arc-20160816;
        b=y/P/dRqY0abMvBhQ0wGO7zbI1E9MCCkqfVlBz72Z5MEHWCl1B/Ox4DPMyDZuXhHPd5
         UzGtTA2WoLy/1U7hymkuSA6ncLtQF+UwxeAc6zwmPgv3m9OKPRiR58q+XsMV9bpB8dZi
         jn1J+YRdH4B3k9JU3N8OEtPLWKr9k0/RQxnU/pqdGHyitLsHDaMqve0ANqGs9fdih4dB
         ZyFjfNwQoixl7CdgllgtLOpunrInZKmpX/jwBFfkOLdCGn7i8cJ+TicBEkK37/LfvTYg
         utJS0vCcATDE6dL4m3nmRab8N57XhtqUqF7TSKsbtk3kvzI4/dHjzkQjBkRNzrzTM+pA
         6CZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l3K1BTqaM5pKy65dpCEo3lZI1RCD2stLd5UR2x4SDMk=;
        b=ycSRawS0wZCS2xhXTINo3ihslfJosdu9r4seP1JZm6oybyUR26wQhyrZV9VosERPWa
         GCpiTJliQu7F8qrVrMCnkPwnKRiEjuF/uAyXWrJ18p7HQIL7TfWn26MHIYZ1kVJAHadp
         dnRuk42jnqFvNf6zMjcBl9eSNHMrMLmX/Xu6vhX+koav8Lc73lrH9lnYV1Iq80LfCYuu
         7tr1Yjzk5vfwR8O1yX8N7Ud4eVsIWy00ZbbisF0hkAS/3m0jsekL3AB9ICpTGB8tv7VU
         /0qeKF/qciZ4Vgh0/xm37mzRR3lPsJkDHftuzCb/SzsLKxe9RxlpM5x1rJYiw3LWbDb8
         zoXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=X0nswPKS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id u128si145156oif.2.2021.06.14.18.47.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id x16so7826047pfa.13
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:28 -0700 (PDT)
X-Received: by 2002:a63:5d52:: with SMTP id o18mr19853904pgm.440.1623721647575;
        Mon, 14 Jun 2021 18:47:27 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id n6sm14378524pgm.79.2021.06.14.18.47.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:27 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 4/6] kasan: Document support on 32-bit powerpc
Date: Tue, 15 Jun 2021 11:47:03 +1000
Message-Id: <20210615014705.2234866-5-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=X0nswPKS;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as
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

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  8 ++++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 18 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 83ec4a556c19..05d2d428a332 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -36,7 +36,8 @@ Both software KASAN modes work with SLUB and SLAB memory allocators,
 while the hardware tag-based KASAN currently only supports SLUB.
 
 Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
-and riscv architectures, and tag-based KASAN modes are supported only for arm64.
+and riscv architectures. It is also supported on 32-bit powerpc kernels.
+Tag-based KASAN modes are supported only for arm64.
 
 Usage
 -----
@@ -343,7 +344,10 @@ CONFIG_KASAN_VMALLOC
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
 cost of greater memory usage. Currently, this is supported on x86,
-riscv, s390, and powerpc.
+riscv, s390, and 32-bit powerpc.
+
+It is optional, except on 32-bit powerpc kernels with module support,
+where it is required.
 
 This works by hooking into vmalloc and vmap and dynamically
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-5-dja%40axtens.net.
