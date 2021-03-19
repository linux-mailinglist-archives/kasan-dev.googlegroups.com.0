Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEPQ2KBAMGQECOVUR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BB7E9341FCC
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 15:41:22 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id b13sf11219573pjq.7
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 07:41:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616164881; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLHTiPk2wltHbUdaLdBd8XJTjQ33qeGZR0qQRGiwIFPX8EbD1PF64bsdDg/LdGipSU
         WtRv5Oan7fbEzrxPnI14MOx4kHW4yOQ8z0ct5p3Mo0E9T6gz47fwHppHN22Cm3tiM87P
         noWN8hA+W/g7WVbChgGAegOI8v977OTkI2hdFzl3afCBMsJnnsbUeKFxJRdqvyNTkgzR
         yWj4YfOMJ3c0HnzEAKlOI5455zUP0V3qhnnzfUHuRG1BkI8qfIxVEAnzteAZHfvuVgES
         aeuvcXgKu4opsEu7/TsJ19py8X0GOPxH1XegkNos8u4twO14VZ/C8D88Y3NjvwC8WWua
         VI7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dTsJvgwqbzyrxhZr96o43hTkZYPScrkR+OXSIUJ8BSg=;
        b=dsyIOahGOpcSA9ONQDP36cvmPvtm7GGW7MtP+KjWxhMls2bR/l/9a5O3y0Q6QqfY+Q
         aiqDr4C0YxLwT+JRaM/W/sZeKp43tHuy4UngQnrtmjgRTu2+RU8jMMGdw5xRXUmQrJxH
         0Q7AsV+gJDvpt6hPkHK7tBdf18ov6bLaRvTZWq4Pnfs8VwrZJ5d8dknLlotp4r9bKvzg
         VFilJC+CLQwDE/QsXm2TaPi1gw41EDpXlsr1+P/xpeHaS94RIwo9p21Wz+6zAK4o8xl6
         EqcNydkG/fmzId/3n9hQ0bK2KHu1zp4weeUb1yPgwaMZF7+9cbKwdbM4UP6xf0xA/wzD
         Sk2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Kcj5V4JO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dTsJvgwqbzyrxhZr96o43hTkZYPScrkR+OXSIUJ8BSg=;
        b=CX6aWr5igkICX8QQ9TJ+PDpXWr4FIaEJpGA/pPBiRKrh0HeStsik4uOV4l10oJHsGW
         0HnPNBvwNm9blh1zUM7+0qy+eu4hBEJ4qkQZ6AseaQVtyiRlmOyPMWpJsMbbsCD2R2KX
         HB7fgjojIXdSRHS2BdjlXkTtF4rQatCygx5WbbIcxmxAUOCcK+M/ukjtXwA6ALoivfEp
         aYnSJXm7AsdAOoTSnaCsa+4wp5TOCBQvkJBPcHy78498DwiyXC76lcIf39eBhNXveyut
         h92prTdJlpcgmHs7BjyG313Ux5C0WgjzX84XjMJV1BOpzyt+2DypJ81Rk6EmKDUqFr1B
         duFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dTsJvgwqbzyrxhZr96o43hTkZYPScrkR+OXSIUJ8BSg=;
        b=AOomLZ4CC9yggLdECGoa1sLRcG5dxySaap/w88lbq7aKoSQaXGpG507y4WmyosV0Il
         lYPI/8I2auNNs8i35z7TIvzv2yv6gWAhIgTLtYimgKL1P7fLb7JIBp8b5UjjM0Steao/
         1xCyZ0W8gqaWTh/mURp2/3dWmsqXABxpnsi16xIEDYIgPb85k0OACPBMqGcXLylxwotV
         0VqdD/VhnCu2nkffsQxZEPvIHQD/wAOOP+yUPn8B2/LknTetPGnjtQNT4i2AMm/fi4wb
         JQUnHEKkhkS4np5kFWZsZWCmW2gf1/4+p2r202YhrGVQziQpY4FrLBmpt0MGjy4IQzXF
         g2Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kQ2GVRaNmYoFsODeXWL6d++FzlTwKWPzvdITaN91DonNcdFOh
	0pSoeSgt5ByPFYhJp8K16Cw=
X-Google-Smtp-Source: ABdhPJyD8fl3JRSuAqaaa7jmv20cUIuJDJnXVDxRHIpL4I8HZl/I1069GQdn7iFFRBmZw6fPzViZ/w==
X-Received: by 2002:a62:cd8d:0:b029:20a:7b41:d1e0 with SMTP id o135-20020a62cd8d0000b029020a7b41d1e0mr9623951pfg.38.1616164881233;
        Fri, 19 Mar 2021 07:41:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d43:: with SMTP id j3ls2052786pgt.1.gmail; Fri, 19 Mar
 2021 07:41:20 -0700 (PDT)
X-Received: by 2002:a63:5020:: with SMTP id e32mr3694230pgb.357.1616164880699;
        Fri, 19 Mar 2021 07:41:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616164880; cv=none;
        d=google.com; s=arc-20160816;
        b=sDkHsEND24HegHUZBTX1JuIwKFCyjUrUQMXWG6BLGzxDDqXqvwVsVMxh6cDutacbvf
         aDr0X7wdOBBom4woL1vrdkfV/HjLKujVYdNrgg3iLQtXMU9l86OMoiDv9pGiiVLfOYXU
         qY8m0Zr5/3bD8CnxGTtNvdPoIv3FRgywmW2gI3ypI9KgA2q6RFfxS0xAfVXTaguJHded
         pQPZNxfj0HBIlTjouhU4SY3zaU8WRc6yKNLDm9cmrD/W8PtNalOGxOHthjuxIllbb8ed
         F5qRx6A8iSFFcMNmzD00w9Q6Lfv2uv6wlORsL65oDJsGNWxgptN3qpIsBbwS7oUAJ6Eb
         1zpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dCC3AVfnj1w2eD4KT8qv23tgUysFvODW8V6tvYzpnj0=;
        b=LrBKtt0rVjbIoJy6rDFbsRWD/kXsKizvdPEadmy1aO6PRup6xVxvlYxJoUaFeM39XQ
         MuLDzjhlzQYiTSXk/ajCpVmX8vpCY2CLxMQvXstlOxq+FyGkd2VW47t+C5gElsiu+pjV
         Os4nYxTUT/W2h/OYpatdqJg2BTGvt/XBleyNwJHf4o+nW9gpQzDUKJTsVdTMlofOLk/q
         4fK5DjDg3CjrA7EfQMwPkFiV7yIcq876bO3ITsv9da7YO0TmlJsjY+j7TxhrvThAcgMV
         SgUe29/JMjfS/AwDFonMxo1w3QPD7hbC8lHeCnht/Cx+R9pppwy8DNgV4Z9ZLz2n6Fxs
         8/Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Kcj5V4JO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id t5si360741pgv.4.2021.03.19.07.41.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Mar 2021 07:41:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id kk2-20020a17090b4a02b02900c777aa746fso4954928pjb.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Mar 2021 07:41:20 -0700 (PDT)
X-Received: by 2002:a17:902:ac93:b029:e6:548b:d61 with SMTP id h19-20020a170902ac93b02900e6548b0d61mr14570825plr.80.1616164880480;
        Fri, 19 Mar 2021 07:41:20 -0700 (PDT)
Received: from localhost (2001-44b8-111e-5c00-674e-5c6f-efc9-136d.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:674e:5c6f:efc9:136d])
        by smtp.gmail.com with ESMTPSA id o197sm5984619pfd.42.2021.03.19.07.41.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Mar 2021 07:41:20 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v11 4/6] kasan: Document support on 32-bit powerpc
Date: Sat, 20 Mar 2021 01:40:56 +1100
Message-Id: <20210319144058.772525-5-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210319144058.772525-1-dja@axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Kcj5V4JO;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as
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
index a8c3e0cff88d..2cfd5d9068c0 100644
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
@@ -334,7 +335,10 @@ CONFIG_KASAN_VMALLOC
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319144058.772525-5-dja%40axtens.net.
