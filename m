Return-Path: <kasan-dev+bncBD4NDKWHQYDRBA4WUL6QKGQEOHTAGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D0E72AAE7D
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 01:19:17 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id m64sf5134599pfm.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Nov 2020 16:19:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604881156; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxcZNGF9sG47+EDco6SNwrhsUeKAyIYgU313mc+dHUzdD0g6a9zGfhqXOLVbl1hPQw
         m4WZeB4FyupY6QQJ1sjQ6aUY49eh57BffHH/Hbm/QJTdZloK1U4nnNFd1uCC+qk8peXk
         0xnWduL8v9SMg+0mgTFvqhoZng7l9pRxNdkrrudaatyfRUbMJdI6zsT30AkZ99S3pnIM
         BhfHV42p1E1tdtropBNqkGyZuZh0ge/0sFZh7ZJWPVE9QxFxNJlnnPrYlOmhuxJPXWHy
         4AdjETVDF/4i13VysM+jpxBSPtkJbjHfkIy1j1B/YVw5LlI9Ff5uEuVtNn4tIiqelpNK
         IaFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=bnXwTL2/AXaEbA3Tpz1pDBoDl9d1p48TMMfDysS1BMg=;
        b=RKAN4nUuHO1Jd7I9nEChUTpsCmHpADK8FuturPQGbsLId90Grednrq5Re+SgUZy1HX
         MiHPQFmWQRzlgfABP3lq94UjUQ08UPPbbnHcCm9Fhuk/+S/m3Tmbqv/xrd1r/U35HoIv
         uVJE1z/3FDJMWAWrRoaR1gs9XydcHA+WGV0d7/kfpLNPwGh3qleok1fFK4bV3z6m2sL5
         B47udehAZF9Bpv3zcqFKZMn0zxNydSJn4sCAU+WeQAuMoBUFXE7NkzKkyG2vzwEVbFPC
         1a2G53r6kCzh/0APdkrq4Y7h2f2DR2yqGCRO9+vAxXD6O5E0THaOpUtohYeoyrWJA92s
         x0gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=R8zuVCcd;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bnXwTL2/AXaEbA3Tpz1pDBoDl9d1p48TMMfDysS1BMg=;
        b=gBt+mSIRbjuIG376ege83q5WCWSyeM5cHw27oZhNCoqdam5dZgefFW7DtE6PhnAukK
         5s65Su71B0B/t9FpKf6MEibVc8F2Zi3swVnPWUcOAOcm6psnnYr3zBNx5rZ0HqpURKCb
         0mKjF2NBuuDtfPYq2sArB2NMtDH2LXeSbUWrPwb5f0AcGCmr2/O5yfqcA8z4It1pxIlm
         sWM/pItXDECMFELxU9SLwxm3ekq/7IfWdn7CaTajUQxXwoGpFV2jZNdsbzgV97OZOvxJ
         9yD7pBSUwR89s50OozspU0g+f1qKwnIGwh15n31IkVg9zSsRV1Mwm9v4D8ilFmVIKwcC
         QlEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bnXwTL2/AXaEbA3Tpz1pDBoDl9d1p48TMMfDysS1BMg=;
        b=D5zigcEycDbKLRYGA3dF7RrDcRSg7JcSf+YNhHmYsrbstaU4u1OH3LZxDRpljy845L
         9QEOQB0NeE3nP96kRiGn2Jjz4RGfCxEuFSaJTPyecAG+/cErSG3PrWq7YApBWCmOaHUT
         3Vk5Kkn3TbLptWPNjQ24O0g+USPRDVygwn8uneG1+M8BSiMAm3FBGzq5fj40Yl+2a+VV
         1GbTigYbGsl8y7t0/PKoi13eOvkguX+yYTdlAOtFcOKf6fW7Qy6GvZeI2LAPFFbdCyH3
         qwxVxOiFy6sE9D+3EjgFix0/KoGF/gsPCALuKGbz0H3S1RiXfS55/QtDEwYW+8FDZ1Wf
         qSGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bnXwTL2/AXaEbA3Tpz1pDBoDl9d1p48TMMfDysS1BMg=;
        b=M3YYmrM/0haR9qZdgpCxfOamXHUSO75QyQ7fmX/8k1uwVgh4OcexrECwOnwjluUQhp
         DYgOr9jY0/oeR5HuBkcG1HnnrpCses37F/HdDlFXYRVPhCiOY1lfdQOfpmenZXanP3YB
         XQBGvtqVX/FBePKU+d0/pc7xLKKAWKTdfirNFBpSUsMllC+Nq2chqj91C0OMJrIprmZx
         4CXC93tL4vgW1upE5s0H5XYsQARMqsuwDLsDajmhPuZQOxuXnCqz/+bEhwvb2rcoPD7s
         Ep7JSdZQ/IdBWhkLvuvIQWLVlkWKCbOt2PkMbMWh33n3g/Uu3JqJZ98udNFKzac7LPSt
         Vlcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532O77bOyIIWhg/zKRwDRNfm0Dol4JllK8AzMFChoT4faduhhhf+
	6We53uYB1c20NJiL7zfR0dE=
X-Google-Smtp-Source: ABdhPJxm0456lEJM2aveAmEZTfrdma6BWIvGyMhXDYJBtJGK3DOXbqM+uZN1kuZhunZN+6jgj1VwmQ==
X-Received: by 2002:a65:4b81:: with SMTP id t1mr11103346pgq.263.1604881156034;
        Sun, 08 Nov 2020 16:19:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:485d:: with SMTP id x29ls2341526pgk.3.gmail; Sun, 08 Nov
 2020 16:19:15 -0800 (PST)
X-Received: by 2002:a63:7847:: with SMTP id t68mr5884880pgc.422.1604881155581;
        Sun, 08 Nov 2020 16:19:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604881155; cv=none;
        d=google.com; s=arc-20160816;
        b=ChHF6b13fOZuBnpFIBi2wq1DJjFjPFyzbAdNpE//w0y2NOYF8BY0qKPM/vRVDCx849
         HC9msOy2UkzHOTpfOZDwDJOxpM3uN4uwsCrDuQVXgFZMDSD3hprquR0sUdrREroj7csR
         40V71snDa5mFp8tFqm+11Mol63yL8hvSc7aduceuIziTH6bxn0TEgcRn9991ZVcA9Lop
         t2ZBXuVWCACFOqdjA/j4dx2RnmwlgagzHM0tmA1yUWowRZmnbD+HjO2qTKLrXcRN1pg1
         3tisktoXos/vGsZdjm34D/3QYGmehKEvEdnjTLmys98BZwDeopdlXR0XNAg6kW3mz8Sj
         Jhyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3LcMZKLiUPDXMEpD6ZsN+QTNJLzBAx+sHH3KFfJGyJ0=;
        b=nU0cdlldn2r7zARMvHqnm2N5Ny1vB7NDb8JPlISPIftUAFzHYLuG5dag4JFK9XEyJL
         zFuoW/viDkSnRFY+6+qoMBIhBIP6slQZlJQ51DsB+jd6OmJ7sEuV7IP1p3rCKurMyhQY
         vIHFVov4l7g4SkacbZZ12FLa4r0Jf9F2/V4JDpdJ0d4jsBuFZkVJrMcAcmRHZbk6S03z
         05ruasRjAV3MWzG+jqpNf4vj33Ci93+99B/BZBJ0Q3IC9dDyzQl8qw4pstQ84C9bYpYj
         5JVepeENWy5oKyTvUXKEiQ6FdSyOzPKY5iNhsSyPeoeUpbnSfVlkdS3tg5FjUBYmvIPG
         J9kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=R8zuVCcd;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id f189si457195pgc.4.2020.11.08.16.19.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Nov 2020 16:19:15 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id n63so4957053qte.4
        for <kasan-dev@googlegroups.com>; Sun, 08 Nov 2020 16:19:15 -0800 (PST)
X-Received: by 2002:ac8:13cb:: with SMTP id i11mr11094139qtj.390.1604881154657;
        Sun, 08 Nov 2020 16:19:14 -0800 (PST)
Received: from localhost.localdomain ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id r19sm4851517qtm.4.2020.11.08.16.19.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 08 Nov 2020 16:19:13 -0800 (PST)
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Abbott Liu <liuwenliang@huawei.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Joe Perches <joe@perches.com>,
	Russell King <linux@armlinux.org.uk>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	linux-next@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Nathan Chancellor <natechancellor@gmail.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	=?UTF-8?q?Valdis=20Kl=C4=93tnieks?= <valdis.kletnieks@vt.edu>
Subject: [PATCH] ARM: boot: Quote aliased symbol names in string.c
Date: Sun,  8 Nov 2020 17:17:13 -0700
Message-Id: <20201109001712.3384097-1-natechancellor@gmail.com>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20201108222156.GA1049451@ubuntu-m3-large-x86>
References: <20201108222156.GA1049451@ubuntu-m3-large-x86>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Patchwork-Bot: notify
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=R8zuVCcd;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Patch "treewide: Remove stringification from __alias macro definition"
causes arguments to __alias to no longer be quoted automatically, which
breaks CONFIG_KASAN on ARM after commit d6d51a96c7d6 ("ARM: 9014/2:
Replace string mem* functions for KASan"):

arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias' argument n=
ot a string
   24 | void *__memcpy(void *__dest, __const void *__src, size_t __n) __ali=
as(memcpy);
      | ^~~~
arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias' argument n=
ot a string
   25 | void *__memmove(void *__dest, __const void *__src, size_t count) __=
alias(memmove);
      | ^~~~
arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias' argument n=
ot a string
   26 | void *__memset(void *s, int c, size_t count) __alias(memset);
      | ^~~~
make[3]: *** [scripts/Makefile.build:283: arch/arm/boot/compressed/string.o=
] Error 1

Quote the names like the treewide patch does so there is no more error.

Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
Reported-by: Valdis Kl=C4=93tnieks <valdis.kletnieks@vt.edu>
Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>
---

Hi Andrew,

Stephen said I should send this along to you so that it can be applied
as part of the post -next series. Please let me know if you need any
more information or clarification, I tried to document it succinctly in
the commit message.

Cheers,
Nathan

 arch/arm/boot/compressed/string.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/s=
tring.c
index 8c0fa276d994..cc6198f8a348 100644
--- a/arch/arm/boot/compressed/string.c
+++ b/arch/arm/boot/compressed/string.c
@@ -21,9 +21,9 @@
 #undef memcpy
 #undef memmove
 #undef memset
-void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memc=
py);
-void *__memmove(void *__dest, __const void *__src, size_t count) __alias(m=
emmove);
-void *__memset(void *s, int c, size_t count) __alias(memset);
+void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("mem=
cpy");
+void *__memmove(void *__dest, __const void *__src, size_t count) __alias("=
memmove");
+void *__memset(void *s, int c, size_t count) __alias("memset");
 #endif
=20
 void *memcpy(void *__dest, __const void *__src, size_t __n)
--=20
2.29.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201109001712.3384097-1-natechancellor%40gmail.com.
