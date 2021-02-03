Return-Path: <kasan-dev+bncBDQ27FVWWUFRBS5A5KAAMGQE2IBVJEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1C530D95E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:00:12 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id l197sf18456260ybf.17
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353611; cv=pass;
        d=google.com; s=arc-20160816;
        b=a6fTp3hSMDzkelxcEkjUCT9FzbN+NPJP7Dq5cbJA8v0VnkoM5s4khoIPGkmWEHQfaa
         maRkhLTP7C++G5dJbzOArl6guYTyYeQRDnLZ4rpdqZtefFNOLuQ3PLpMemuLp2K6a/CQ
         rxsXbWP8hQKT+5IU4LcZuMLDwojm0ZoNNJEPkwtg55xHdLvDpOozExr89No7Jo6iosCx
         ri41aPxqaSpgkIgGmpp3R3Tqo67Lk/EfAj+JH6kKi2cmpF4TT7P28G+px7PRT7hrb6BJ
         2vSIJPezgw1mp9t2oHzfVAYD/dtQ44i+gGv4WUxpQ9APTY/N0Md6dnGsSo4FnxLaAIPx
         TI+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qbkv91Pp+3So+Rrlp/QTi38dKzymWz3Tyyo582qctfs=;
        b=ZXk0ra9U5K/dEkHke3CjIA/4p6V7V1gZN0yMXJwAcig+097Y9yzZ8qPO2MNTBSxM3k
         vZf+NUumdLTbTPvaRxyVcE4dUBawlX9Dkt1tIEOqJ3rr5g2wUKd4Lp1QKgH8XQ0ZuMA2
         AwAmBvohc30zPXlqvjg+g1RwGa9pcY3qIL+OoFp3lrmLy+1ELJrmJ+rjA76etH7FZlIh
         UJrwmdB8fbnZGcaaAhctemdtpPo4TIrsgOH90OiFUYbrTLy8txxjlPaOAxnj99KsDvzM
         lMkS0LQklmPRhaGK/smNha8S5nlN42sugFb7qD4bP7vxwUeXUlNlP6PoUmihOfUtYQEO
         SCTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HGv0pMdL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qbkv91Pp+3So+Rrlp/QTi38dKzymWz3Tyyo582qctfs=;
        b=RCS+kIs1ypH2TvPKsOFm95ivkzLTqAy9No6qN3xvZPjEhSYuLgRsoToaYpylgD2Ymd
         b8i2KIkSXcmaN/YdJazDFBH7Rm7roHuLLR+hHflSqV0c9S2SzFgsS0au79WkOjYBf9gr
         YGPTEqYBCUnAxOslQRqOajD8jdQz8f23igcqE7GvhJcuSLbGrQQZPvB/uhqPpWHv0ZJN
         Emxoq/GGF9jGQYNSiXYI95fa8w0lFEujKcnPHemASFJ6pNZqLS81NltHs145jn0nDQCP
         cLtAX8Pd04iBGQLkBl7zfEQ+wgtmE0x1XFf2WjllW3/XYxknuw4TQiqjFbLBdBzoXKK7
         xTdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qbkv91Pp+3So+Rrlp/QTi38dKzymWz3Tyyo582qctfs=;
        b=Ihc5CUB+svkk7dfOhIQ5tFgB/fetq1DNB4ZanRGd+efELFCCGMAycJk9qkiXZf42Hx
         DyRTqPGvFKLi9xUJ+8l4TQ7J80e+wXWaFerJnjsRX+tLVMAqFl4mP2VipIKyWVlildCW
         pVGifviYwBnjrJqWIrYhrBMJLeAMKiJxcrdNWlrr1s+Q5U3zwf04fM8iVYjz9UQJq1vz
         M5MY+ltP1XYj5OiFYTBj4lQF0IWtyKY5MPUB+OaixIqbuqXk3nW41Yyi9mGme4Wiqc+t
         5hGH04kY6uqCo24MlVo98glkgedYNM8XGWEOWnBg6oF8hWtiXWRFq+2tp0KVxEGlUCo1
         sWUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532O5YHSUwKIMerEVqYX/ABAOsB+VAyLgEf0fkkCf9aZyaygziuu
	knOJIGTVjUHRYrVEuuekYf0=
X-Google-Smtp-Source: ABdhPJwx4jC3xE23fOL/R9x8SU5FtOmx1Z67Fo1lNn8hpwJGdr2HBMlI9LlyZef4ZwcVU96G9CICHQ==
X-Received: by 2002:a25:7415:: with SMTP id p21mr3938989ybc.62.1612353611214;
        Wed, 03 Feb 2021 04:00:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4c06:: with SMTP id z6ls924638yba.8.gmail; Wed, 03 Feb
 2021 04:00:10 -0800 (PST)
X-Received: by 2002:a25:d150:: with SMTP id i77mr4043186ybg.55.1612353610815;
        Wed, 03 Feb 2021 04:00:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353610; cv=none;
        d=google.com; s=arc-20160816;
        b=c6YmJvkh1z1GLCq0m6EShpMUFd4BxYAVSIABulvWag0pYQAJ368+4BsgPR+R5CfIyL
         Z43BS3Ns22uIfuOrsdi08kBLMiB5L5O1rt8wTjXLy/aXlG2xSLMoyJLjvgyetDaB/qCZ
         ON5L+4OGs+3LINKxLKAJuqgpvPPagmGxUADWHw6OCaSx0Chzk8kUOtLQk48Zagm/Iwiu
         yozJn45CA9oltD9j6eX0EYydce47mj8OErRTN3HrAOWa2Swvtm6m9l6pYusOB9nOUzjg
         iXxzztvk+L2LCCmID5/466D4TtCWp/plXu5QuDpM6NlFUTCYV4Ffko3NXTqz1lh+TuLd
         wEDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qiaBVEZpA8Xo3CJyOAtaUaP2kzBvWdhYRuLo/mSWVKU=;
        b=wKRTVLyiodrLlKUspAHwWUUdSMdobY+SB7FKol+KLPx8IUmDQ5r7XW07Wei4PJgxuD
         6q8Ri7DntDAUeHsrXGMXtbd0nysELWHMQylqRB1uKCX+kwakpSboYwmKvKYOkW5TwlHm
         Q8alP6UFB2peweJRVpYfSJ+/Q8MfRqGh2Tj4f4yYBkrRRlbZQ4Z/tWjaB4FNExwmv160
         RgeF2s/H3QdkiY7/G4LjRtbmvBTxNxvHPPSeFymroU//soSF+JrJ6L55b/xNixxtiY6C
         kSazVnBux3p4WUhfi4tq8wIJyFU8224eDp1hMwNk8t8wssqsTqvNTPJcQPZplBfLI4De
         l4YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HGv0pMdL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id k12si96194ybf.5.2021.02.03.04.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id v19so17197337pgj.12
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:00:10 -0800 (PST)
X-Received: by 2002:a65:408c:: with SMTP id t12mr3287866pgp.157.1612353610461;
        Wed, 03 Feb 2021 04:00:10 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id a19sm2226291pfg.75.2021.02.03.04.00.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:00:10 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 4/6] kasan: Document support on 32-bit powerpc
Date: Wed,  3 Feb 2021 22:59:44 +1100
Message-Id: <20210203115946.663273-5-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210203115946.663273-1-dja@axtens.net>
References: <20210203115946.663273-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HGv0pMdL;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52e as
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

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e022b7506e37..9cfc116cc6bf 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ out-of-bounds accesses for global variables is only supported since Clang 11.
 Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
-and riscv architectures, and tag-based KASAN modes are supported only for arm64.
+and riscv architectures. It is also supported on 32-bit powerpc kernels.
+Tag-based KASAN modes are supported only for arm64.
 
 Usage
 -----
@@ -332,7 +333,9 @@ CONFIG_KASAN_VMALLOC
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-5-dja%40axtens.net.
