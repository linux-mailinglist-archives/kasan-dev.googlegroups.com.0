Return-Path: <kasan-dev+bncBCS7XUWOUULBBJWOSOEAMGQEA7BTLYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 35DF13DC3AA
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 08:01:12 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id g21-20020ab05fd50000b02902a6182fc181sf4491521uaj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 23:01:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627711271; cv=pass;
        d=google.com; s=arc-20160816;
        b=BV/AFT1WOikqSEuEOWoCB4WGekRY2lrQxZP12eIwbgoUQuCCJ7MThNIcRB6coB/Utt
         8lVkiLIFCVVCFntPAFw4wDTdvBmy+UOGPm3yib7LNQzj0MjhKJO11Gq8MEru5qUm1xNP
         R4UbfTs4xmVCFjRW3LX6EJGf3uU060Ebj2K8r1S25nVSNHyliXEq597y6sXNP+72pK6I
         IrOxP12gGo5PQF8WDScuBY+dhMNhcHkpuS2BY1Du/lRHGrfOyVsJC9703qgcvNsVgNg2
         SL9dm5UGiaYxov70otjiyH9s/0gCfQO6QhcUUEUGjYndpDmwj39nAYuA2xhZeuD5hoqy
         3hRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=B1cSed+H820wZkgx+XhoBDuhz/9es6rQ6N5OgdGwiqE=;
        b=SU7q0BZ1t6PIF4tg/155XdE1pH76hw24kd3XiQPmJ21OrkvbOS5Uv9ZQoiPrraGEkZ
         UcIAtq+sylC8GNYTztlPDXdpJMN5g3HzitSiU2O9A6m1BGuFUYiL8B7e8qW0a6oYGOSz
         IAGhHNCBEgjPFK7xv383h/7SdgFzy9mnfxw74rrtPCw1K7MfExiiUWG7oOgdgDBaLwWK
         /qC5v9GyDG+Qwwsa8XJ2DrvX0OhBld+cMdWq/yPn8g6FRCW60oIv4g4DYVl8h3l022tR
         o8nlDVph21g3qBw3uC/YdbKT/T+fRDDN2hdam3DS34siExSoM8dn3Jj8ci4Siyff7OKE
         NJVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=azNSPWyE;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=B1cSed+H820wZkgx+XhoBDuhz/9es6rQ6N5OgdGwiqE=;
        b=Q84U+oMtOkkhezlL5rDZGLijuFEwx3dDXarXxYtibT0rrnM4sittEnfA7uZhqskP23
         kbvvl1zMOMUpyxUE6jtf9wTMMQ04R4y83XtU5G8lgXzkUwqDGRMDTNzCRjeu3isp0WhU
         F1A7odrNFbo/JL0e4dUxE6Sl0tywW/pMitUi+y1kNnHFh/A4SZNeS7zf8DfiqyzItYZb
         dOPxihjCT2o4vxphJrEb3BXibE12dvRNaYdELZPyg3Lshg5LuHSVPfa9MxezXLudt1fD
         H2CNyIWcAnKMzy6x4FRPOfMrn+G1lihPXYRYDgoGlN+e9HQGwFstDuzXtomsHi0P2tje
         exTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B1cSed+H820wZkgx+XhoBDuhz/9es6rQ6N5OgdGwiqE=;
        b=YypzWjkckXrLEmK3MgtKag45evmeAojU4PryqA3fHiPJMljS/ZNcvhSw2jqdJykxys
         Hq3s0s6I6Tx3uynE9nc4X/BHsVn94JtIWjktudVLUrMEHevbSQ7baxFrKl5z0GuKXzXm
         BvtASUNVrsTN8U7DP4CbSQVJtYtD6/BWcTX7mlPF1J8MvOodaKr/xW6Iq4a8nxnFEmry
         y1eioHQGeMS7mHmp0eibhhJj1PN0yec1yb8ZlD3DVWrWlWrjA+lMroX+33srcquzz3me
         s4dWvgJUM8xuumzdq+b0zEThb4ZZprx4+Mx7Lq+ySGyNz1jY3hWooAiks1xk5pHU/w1+
         RnvA==
X-Gm-Message-State: AOAM533hb5XrSIPTc5QBHem44/j6rbHqj/z4+5PSjFiDb0i7vYvJeVR2
	TU3xgg1SE8//ALtTFC3nkNk=
X-Google-Smtp-Source: ABdhPJyuo0k4n7U8tmjSGQLmAzAJsu+8rTcH3rD6sL6RGavnEEb5Y7J2/1aN+cQj53TVtNzeIViNgQ==
X-Received: by 2002:a05:6102:21b:: with SMTP id z27mr4894342vsp.18.1627711270156;
        Fri, 30 Jul 2021 23:01:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ec03:: with SMTP id d3ls783631vso.1.gmail; Fri, 30 Jul
 2021 23:01:09 -0700 (PDT)
X-Received: by 2002:a05:6102:1343:: with SMTP id j3mr4930040vsl.38.1627711269729;
        Fri, 30 Jul 2021 23:01:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627711269; cv=none;
        d=google.com; s=arc-20160816;
        b=OPpfkNXASiJ7cpEWHQAEowPbSS+7czYcUXDKbEbCUvUzTxMiy60L9L1qxXMzXwpSte
         opegsxElnEy3BHBNWqldTKR0xcWx2L4m92kiPIVMEnFGf3d38X3YV9pGtbtmBYa4g51a
         ueV0kyh+c0p+pjHRToQu0CTq0PIdXjHbBG99WQv6vdicf0Uyn3AyXvpCfpiMOovH2D9Q
         2522jFJBjTxDB3GulX0DPTOhVMuWiC7O22vE3K5aUIRodolQVb889zrwklG9I9E61kkr
         M3bd+1DdGq3OolPE9M/oW6PJUygxNEpTVvTAmE0rlrRNpQxVoNFcrSUs2WtAkTdvKhon
         JhcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RnJbeFRABx8gv+E+NAXey4lvwWkcIEVkiEIkxS1UNwc=;
        b=wpzv0QbjyJOTZE6ugwhk94ze0rBGZAX9fIdmg0zAHIzGGSMgq26XV6n8R0N0KWnWQX
         dOgHm5DOc38fUeLMFaaYy2F3XYC66GDDEDaokKutWoU4kYo7GNINU+IcgdvkxbBuo8DK
         5rEoh8gQ8zwjWVtNskf+Nw6fPGGqDbUV5MYTFQCzrfrgWIqbbaaqFKkpcQ9Zm2Curv37
         2Hj0oS3c+SAPwqgFbfi7xuIvfkJkfPP2y/bZmGYvsBGqk4c1JUy0Xp240xCl0TiNf5Wx
         fnYv1ekTcu4XI9j5sKbW1v/RJ0jbt6qqiP/c8smUlj+76aziDeMQtRDj00o/nkoue31J
         vLIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=azNSPWyE;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id y18si160960vko.4.2021.07.30.23.01.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jul 2021 23:01:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id k1so13568240plt.12
        for <kasan-dev@googlegroups.com>; Fri, 30 Jul 2021 23:01:09 -0700 (PDT)
X-Received: by 2002:a17:90a:d596:: with SMTP id v22mr6926387pju.51.1627711268627;
        Fri, 30 Jul 2021 23:01:08 -0700 (PDT)
Received: from google.com ([2620:15c:2ce:200:160:995:7f22:dc59])
        by smtp.gmail.com with ESMTPSA id e35sm4090000pjk.28.2021.07.30.23.01.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Jul 2021 23:01:07 -0700 (PDT)
Date: Fri, 30 Jul 2021 23:01:02 -0700
From: "'Fangrui Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Marco Elver <elver@google.com>, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	clang-built-linux@googlegroups.com, stable@vger.kernel.org
Subject: Re: [PATCH v2] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
Message-ID: <20210731060102.3p7sknifz4d62ocn@google.com>
References: <20210730223815.1382706-1-nathan@kernel.org>
 <20210731023107.1932981-1-nathan@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <20210731023107.1932981-1-nathan@kernel.org>
X-Original-Sender: maskray@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=azNSPWyE;       spf=pass
 (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=maskray@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Fangrui Song <maskray@google.com>
Reply-To: Fangrui Song <maskray@google.com>
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

Reviewed-by: Fangrui Song <maskray@google.com>

On 2021-07-30, Nathan Chancellor wrote:
>A recent change in LLVM causes module_{c,d}tor sections to appear when
>CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
>because these are not handled anywhere:
>
>ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
>ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
>ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'
>
>Fangrui explains: "the function asan.module_ctor has the SHF_GNU_RETAIN
>flag, so it is in a separate section even with -fno-function-sections
>(default)".

If my theory is true, we should see orphan section warning with
CONFIG_LD_DEAD_CODE_DATA_ELIMINATION
before my sanitizer change.

>Place them in the TEXT_TEXT section so that these technologies continue
>to work with the newer compiler versions. All of the KASAN and KCSAN
>KUnit tests continue to pass after this change.
>
>Cc: stable@vger.kernel.org
>Link: https://github.com/ClangBuiltLinux/linux/issues/1432
>Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
>Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>---
>
>v1 -> v2:
>
>* Fix inclusion of .text.tsan.* (Nick)
>
>* Drop .text.asan as it does not exist plus it would be handled by a
>  different line (Fangrui)
>
>* Add Fangrui's explanation about why the LLVM commit caused these
>  sections to appear.
>
> include/asm-generic/vmlinux.lds.h | 1 +
> 1 file changed, 1 insertion(+)
>
>diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
>index 17325416e2de..62669b36a772 100644
>--- a/include/asm-generic/vmlinux.lds.h
>+++ b/include/asm-generic/vmlinux.lds.h
>@@ -586,6 +586,7 @@
> 		NOINSTR_TEXT						\
> 		*(.text..refcount)					\
> 		*(.ref.text)						\
>+		*(.text.asan.* .text.tsan.*)				\

When kmsan is upstreamed, we may need to add .text.msan.* :)

(
I wondered why we cannot just change the TEXT_MAIN pattern to .text.*

For large userspace applications, separating .text.unlikely .text.hot can help
do things like hugepage and mlock, which can improve instruction cache
localize and reduce instruction TLB miss rates,,, but not sure this
helps much for the kernel.

Or perhaps some .text.FOOBAR has special usage which cannot be placed
into the output .text
)


> 		TEXT_CFI_JT						\
> 	MEM_KEEP(init.text*)						\
> 	MEM_KEEP(exit.text*)						\
>
>base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
>-- 
>2.32.0.264.g75ae10bc75
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210731060102.3p7sknifz4d62ocn%40google.com.
