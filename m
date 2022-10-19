Return-Path: <kasan-dev+bncBD4NDKWHQYDRBM5TYCNAMGQEZAU6L5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B8C49604BAD
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 17:37:25 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id cu10-20020a056a00448a00b00562f2ff1058sf9761255pfb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 08:37:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666193844; cv=pass;
        d=google.com; s=arc-20160816;
        b=E8wNmqXHQedZyRRfPCRxAVfMG6sRg7LW7XUmXEZ0a1rNsEvs1lOMuOdjX5TsyNMGCr
         4SxgW4b0M1ZBHDM8KDPosD86UgRI4bSXzI24kFO01aZT5LnDyMZlvWb9+VBUSE/2vaKt
         ZF8CZvUnqvek8K0LvdNuty6BOhuIdJTsPhNXKiasCK7VchJ2RYwYcooy5P+psa9+OHKi
         BVCHpR39+xFTMD9rzMK+vwiGDUQV1uNV80lg9g8SKVWKr8mV4lgpAh94rhQgi/6UUDI2
         rgr62WSngQdLEomlfG/1zC+yyaw6RKN9R16ny2VJpDMKuhsNBgG//d3OswAA0jBmixJF
         qjJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=NDtwyYvwuzEzmqxz/lnoBrhZXo8JPCNui0Ms1WaAurc=;
        b=GiqXpTu+AExot3JC8YSyYUUcG9btX/kReyo3RicE8JQzykuIop70jGnxIA980C8uGW
         XXfNuinTIua/KJ7Ilod0TV/KUUHBUHTJC3Cnn/dTdhdMJq8gR72fFhaEsNU83NFDyMrt
         FTmuRIi+pDYKNNEPx+X3DW/GCA3BrXUl+Mm7xYAJrEg5UAGwTTEvKEyX8uTH3+K7NcnO
         qP7YtzJz5iv7NGerrSkHgHalO2idh9P0/zXwZhflP2bcfPTXaQ1HU2F4VLwQ7DosBvDo
         ApQHKj+8azJOlgsOTgd6eQG5Jtm1RMgc/P1KmVTBj/Nzsl7cf2TxAhs0fyfJU3LwrbvD
         AtHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rdDLnjfb;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NDtwyYvwuzEzmqxz/lnoBrhZXo8JPCNui0Ms1WaAurc=;
        b=NYuB9loD4l/EqjKWI+21QYtSs/D1dqdk2e6HC4JQa1nbuAIYk8Q5gxSik4hU+mPFym
         DOUx/hrK+25ZoTLdK6bxTjkbsYphiLbL80XIMlR4D8GlErSECRmsIiQjOpgG6PRwUWbd
         y2KTnhz+z48TpOrNrMknlMNtpTHRi/kj98dnW9JyVvMSZlS/Tez1mvFqQUcn9TtNOOSZ
         elxwMRVLQ5alXk6QTd2Zk6sxCHsGXlHHaDslH2cuC4Vo8EH0sk7ErDlcwjWj/9F48DIh
         LEh5zzgg9BEYSqumopmgOMW0LFnDKAEAzxM7GOl72DA6xn8Waefcx2aKRbtLfwGMyYfI
         OyBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NDtwyYvwuzEzmqxz/lnoBrhZXo8JPCNui0Ms1WaAurc=;
        b=wFexZTC9F4P3zPj0Iy7FJWSvpuzm/vTlGPndb/KIRoGIrOr2Xa1uY21ojn6Aic9uC4
         gkIe+gXFpCX139ayS1nLl/NaZaNNUDCNp3tA4parTnkSXgX/B4od6HM3i+pAqwp3erF3
         CjWo7NYWBpamEREjBO4Wg379PNVMbplKiCcIcKCxBd2cqqbPIk6I0L9U+5/9ZIZKjgy1
         7XLj1WhkoB/uIfrObnl/ZNDONLCu3F7MzW+Kdj3Z/0lR5b8sbsXYVTxokOl86pqQp3mk
         4xe27YBDCWA+5PrUG/e3Uhp0VYZEiFeg8vj6DRIyJUoExvk+psECxYTpUecjmyHXg14y
         QRbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1cyhbjAlmskGdU8JKpmGhJfCNCbuCO8WHBtvicDQBMXgfbMtja
	18qpqCCBs+qmDgp6Io45BL4=
X-Google-Smtp-Source: AMsMyM49vPHOZEMsduzbksbnyy6p28vxOsZ+uTsHKLbxoblhjs9cN6Xs4SS+Nn2Kc0sAEkNSWIkCCQ==
X-Received: by 2002:a17:90a:bd01:b0:205:fa9c:1cfc with SMTP id y1-20020a17090abd0100b00205fa9c1cfcmr46604624pjr.116.1666193843919;
        Wed, 19 Oct 2022 08:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:728b:b0:20a:feca:b873 with SMTP id
 e11-20020a17090a728b00b0020afecab873ls245706pjg.0.-pod-canary-gmail; Wed, 19
 Oct 2022 08:37:23 -0700 (PDT)
X-Received: by 2002:a17:90b:3c51:b0:20c:2630:5259 with SMTP id pm17-20020a17090b3c5100b0020c26305259mr45415808pjb.177.1666193843077;
        Wed, 19 Oct 2022 08:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666193843; cv=none;
        d=google.com; s=arc-20160816;
        b=VLtw4WLw5xmSFcryGBglUXrD6tLLGfuZyjYnD65BSb15ckzAszbRJsGJ8d2aBBCjmj
         f98JUadizBF6FDp+jYMTLgM9hdOrmYTiIo04o6vUyyZpC/6gDkZTXDkdnDZpehZX4uzR
         1FEQPM0yMQskd9MMxYrIANQccOGdby2/nsHzs0KhdfCzhfxAVFgNaJ5sCO58W5y3Vq78
         8pCJh+RW7kZt5A9hIupErqSkDvHP1LK+cnvh1t7zRBtehtCxQSBbcacoXdUtDf+qB6Dr
         I9d2oG9xLX/5m2ES5SmJWdP3FYwFDsFPGM+bt9ePWBehzhgHEMaVAlW/99kekH4Oo9aa
         wg/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/2iM8jKklAiO77h1Ju3oLdNpaIcGNpt+RYVknQ2p8rs=;
        b=Y6klH5jYhT8OvPtbV/1n+KKLEsz+w3FEijNZ1o39PoiZjk3u1dP8ufYDVELazWXCb7
         XvMok5EDuzvbhQZm8VUBGSRCVbexXiADjK6dzBDSnsnzzUZPnZycceG99BSRPP3CfKBG
         mhESij1uqdye++UVNfqQgWvJtSVEa/TRL0qJvZfmme8RkEbv/2Nwt7eVjMdAeZNnh0+t
         HZ4WRIDt8HNq8ZifwgHLpbMwaYMY2etazBgosD9LAEFkfGqgDQoH81su9OmprHeM32m1
         JdX58DcG7YIg30u0Htj7jaJp4jm8uojrseVLovHWKhEb7vLLJVfl+hVfhJicLzPshXSq
         3S3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rdDLnjfb;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id mm4-20020a17090b358400b0020a605eff06si8949pjb.2.2022.10.19.08.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Oct 2022 08:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 8756161844;
	Wed, 19 Oct 2022 15:37:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 79A20C4347C;
	Wed, 19 Oct 2022 15:37:21 +0000 (UTC)
Date: Wed, 19 Oct 2022 08:37:19 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: -Wmacro-redefined in include/linux/fortify-string.h
Message-ID: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rdDLnjfb;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi all,

I am seeing the following set of warnings when building an x86_64
configuration that has CONFIG_FORTIFY_SOURCE=y and CONFIG_KMSAN=y:

  In file included from scripts/mod/devicetable-offsets.c:3:
  In file included from ./include/linux/mod_devicetable.h:13:
  In file included from ./include/linux/uuid.h:12:
  In file included from ./include/linux/string.h:253:
  ./include/linux/fortify-string.h:496:9: error: 'memcpy' macro redefined [-Werror,-Wmacro-redefined]
  #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                  \
          ^
  ./arch/x86/include/asm/string_64.h:17:9: note: previous definition is here
  #define memcpy __msan_memcpy
          ^
  In file included from scripts/mod/devicetable-offsets.c:3:
  In file included from ./include/linux/mod_devicetable.h:13:
  In file included from ./include/linux/uuid.h:12:
  In file included from ./include/linux/string.h:253:
  ./include/linux/fortify-string.h:500:9: error: 'memmove' macro redefined [-Werror,-Wmacro-redefined]
  #define memmove(p, q, s)  __fortify_memcpy_chk(p, q, s,                 \
          ^
  ./arch/x86/include/asm/string_64.h:73:9: note: previous definition is here
  #define memmove __msan_memmove
          ^
  2 errors generated.

I can see that commit ff901d80fff6 ("x86: kmsan: use __msan_ string
functions where possible.") appears to include a fix up for this warning
with memset() but not memcpy() or memmove(). If I apply a similar fix up
like so:

diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
index 4029fe368a4f..718ee17b31e3 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -493,6 +493,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_size_t size,
  * __struct_size() vs __member_size() must be captured here to avoid
  * evaluating argument side-effects further into the macro layers.
  */
+#ifndef CONFIG_KMSAN
 #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,			\
 		__struct_size(p), __struct_size(q),			\
 		__member_size(p), __member_size(q),			\
@@ -501,6 +502,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_size_t size,
 		__struct_size(p), __struct_size(q),			\
 		__member_size(p), __member_size(q),			\
 		memmove)
+#endif
 
 extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
 __FORTIFY_INLINE void *memscan(void * const POS0 p, int c, __kernel_size_t size)

Then the instances of -Wmacro-redefined disappear but the fortify tests
no longer pass for somewhat obvious reasons:

  warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memcpy.c
  warning: unsafe memmove() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memmove.c
  warning: unsafe memcpy() usage lacked '__read_overflow2_field' symbol in lib/test_fortify/read_overflow2_field-memcpy.c
  warning: unsafe memmove() usage lacked '__read_overflow2_field' symbol in lib/test_fortify/read_overflow2_field-memmove.c
  warning: unsafe memcpy() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memcpy.c
  warning: unsafe memmove() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memmove.c
  warning: unsafe memset() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memset.c
  warning: unsafe memcpy() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memcpy.c
  warning: unsafe memmove() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memmove.c
  warning: unsafe memset() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memset.c

Should CONFIG_KMSAN depend on CONFIG_FORTIFY_SOURCE=n like so? It seems
like the two features are incompatible if I am reading ff901d80fff6
correctly.

diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index b2489dd6503f..6a681621e3c5 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -11,7 +11,7 @@ config HAVE_KMSAN_COMPILER
 config KMSAN
 	bool "KMSAN: detector of uninitialized values use"
 	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
-	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
+	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN && !FORTIFY_SOURCE
 	select STACKDEPOT
 	select STACKDEPOT_ALWAYS_INIT
 	help

or is there a different obvious fix that I am missing?

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y1AZr01X1wvg5Klu%40dev-arch.thelio-3990X.
