Return-Path: <kasan-dev+bncBCS7XUWOUULBBU4FS2RQMGQE52UZYBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id B6DB070778A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 May 2023 03:43:49 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-24e22283d6asf380382a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 18:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684374228; cv=pass;
        d=google.com; s=arc-20160816;
        b=JaZjf1Os8OPLdIEk34or9j4FjxNqeuTvZY8+5ddwSBnE+idfdiathepbI/31DXDeNX
         Bvs0lq9OJAbrQdPLFmOv0fXBNr0TKEw3KETG/83V6PCL6Uaq5GrMlmlBOcoaFk9dLlCi
         Xqyltc9KyyIknbyyQ+2L6XAKqq4cGCWonGaCWJ/DosByVTC9E7Nx17Z/aDXxdsBCjESv
         S05Lhb3KGLD5bN6ObDP6ScaoN9qc2VPY/6jS60aFD+7UWiDHihrSvxCQ8QanEnBY1P3i
         XGSE9Xdg2i2/qJYezdRg3JsgSW5zOSrjd9r2/9lOTr6fh56ufxsJdoIGxieeJHsiaM1M
         u4Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qziF/L+E46TVCvSRlOLWIETSX7JAxxvcCOy9yO7IImw=;
        b=LV/Y1HwH9DZxWWC17nMD9JXJQ0fon+ZOMZwpYgkAEDEyFJFGMlshPFN0QV+PknYw+6
         93rHGhnC5R0u6iyjscPKF6PIA5pIrjyZkUdv+e76TVIBvfpeOWAD7On6K3fk6GKbSG4C
         pmm5PkC3+4dnMLiVi24+Be5IxZWbRstkvrNwoKiEWUvK9yBa/5VC3VrXs8LMQDd8/6OW
         XuHL6NYUtPgnx95R6EkzeSHxifRNo+A2olu/ggjdwtnR4392LFXp+niYSm0pZzuH6TlE
         JtqDSMY+UfCfgipHIuqBjEFaXEUU/s9gxEW5tKmQ6yUARqsosulL5qHPYDeufvJFdF7r
         QIQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Xyb4IV2y;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684374228; x=1686966228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qziF/L+E46TVCvSRlOLWIETSX7JAxxvcCOy9yO7IImw=;
        b=T36815GWuHadVZsn8eNlroNDhapzKJHvUBql5vTEV3cUO/dr3FZTnmQwpEYNX/MVUF
         EE78IgQo+jqmXY4vUN4JRnwXQ+1KiHksgQmXdErbljxC3RQsLFVJHF41FB0XGUNQNSqR
         Yc4It8vC0+2/EoQ0zF69iI/OI0SlyjisB/3dmPHDIaQumWmGdg8W7BSQ9aHBK4bhDycd
         FgySDYD+ifc4a0kAGCuHssSlilxiuCrT65taP1uDACyuSsSt1kyV7F2VBO+VwnvF2958
         ogf5+I170xnBOJrbN3OuC6ycqlC5yT0qduNuXknh7suW+xZ1jqgpOaQoKid1UE0h1oob
         SiIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684374228; x=1686966228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qziF/L+E46TVCvSRlOLWIETSX7JAxxvcCOy9yO7IImw=;
        b=USgMqJUasAQhUCS6moONQZk+YBh70Sf51iOF0n6eKdRAmTlb8Gu9BPPyOeKU6/EyZe
         JLobfR3KD80w3bVkbb8vAbDzsPCd26DJRrz4DP1dGfZMaa+O07MiN189u8QOuCvIGICy
         luJtmP2QD9k1QURWsojWw4DI5dhd+W9HvEEiws6uMlKmsG09o010tI24FfDPseQb77A4
         NSmdWASGpQJqz3N/RBi0mPm9eAQtH4aguYbGQeGGOgDTPpq8Gh1j2r3grkFESa+SN/y2
         dBDRVM2XNPBn3x3mSIlBLV7fPdws0Hlp8Skry8C2Uy8eFfOaxPCLp3f8fg11EHCTVVqo
         xyhA==
X-Gm-Message-State: AC+VfDwzi5FtfNFZ4xv/hJ35Dj9FTOLCz7XqX21k8zjMtxFXOMUqYVWH
	X6jH9BmJB8cLOZSrbJ3ieHU=
X-Google-Smtp-Source: ACHHUZ4VM2OBgI3RZcZkfO25moIKoJczShDaOWTdxnu94/MIKAAb20N7eEKSbpAdohBN5HBDsQT81A==
X-Received: by 2002:a17:90a:e2d7:b0:253:32b1:e567 with SMTP id fr23-20020a17090ae2d700b0025332b1e567mr182946pjb.2.1684374227870;
        Wed, 17 May 2023 18:43:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:844:b0:1ad:d7a0:1d73 with SMTP id
 ks4-20020a170903084400b001add7a01d73ls330051plb.0.-pod-prod-06-us; Wed, 17
 May 2023 18:43:47 -0700 (PDT)
X-Received: by 2002:a17:903:25cc:b0:1a6:84be:a08f with SMTP id jc12-20020a17090325cc00b001a684bea08fmr635304plb.64.1684374227053;
        Wed, 17 May 2023 18:43:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684374227; cv=none;
        d=google.com; s=arc-20160816;
        b=XXRfhHK2M/VP9s1hBCuSH1kuEWCtyWIOZXGqYtlbPILMz15ByotZ1cdt4FyuS13j29
         U+qwiPxx86VOrpHU1rjzv0EcMMbmitoxXpJMNBWYTszQRUIgvhwzD/XGXrwio3Hg0wb7
         jqCSe00Khzxf/UDH2+/2l5+iHD7Ss54Qmu1IAssCh4PXjuuSL44dDgDgZEmOznlkNWOh
         YbThvuMVCLOI6WkXXE0pLRpnCusxnmQGnoJh12TMRGmy0/clXw3x8f7MG6vUEGKHQJUm
         zoHIaBUTti03vsGevk+IlBszmE/bPlUYRZYvLNnJwtLWkt0zWPXwc/VTQeQEiGOcqEEt
         vgpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0PO3eq+1UMnnMiki2DRBn6QhtFhDNQwR095O3RPt+vk=;
        b=0G2xrsKArTaPURhTCisLl7aRwBCkSzoKVEmqKtiRiUdo0KrzhJszjlGk3cFLHp6esh
         rU9mE1dKl2fZkRlhDFsO4V7KfVGj23UViZm/hmsvi81eQSVhgAaPnQsjisej0XpzrNcy
         g9w9hl7KSG482AYKTUFjr4d9pRuEYotYMWft5MHZDuuLIFVfMRdX9FMDwcD7KGm3itqi
         d/SxPwgBH0aOSjCYQ8wplG5KwouC2pT690Bi/AAAzxqlyrHzvUi9M/OVfyNsfLb5sNKM
         7NL4n8jgaQmeGFKdsXKrouKdOrmheXicOE6ilutf5b195m/5k3+09Eb6rEEsHM0vwG7f
         JbFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Xyb4IV2y;
       spf=pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=maskray@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id m1-20020a170902e40100b001aaf7c46645si4590ple.11.2023.05.17.18.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 18:43:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1ae64580e9fso55935ad.1
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 18:43:47 -0700 (PDT)
X-Received: by 2002:a17:902:f352:b0:1ae:4008:5404 with SMTP id q18-20020a170902f35200b001ae40085404mr80291ple.0.1684374226600;
        Wed, 17 May 2023 18:43:46 -0700 (PDT)
Received: from google.com (25.11.145.34.bc.googleusercontent.com. [34.145.11.25])
        by smtp.gmail.com with ESMTPSA id d14-20020a17090ae28e00b00247601ce2aesm2280427pjz.20.2023.05.17.18.43.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 18:43:46 -0700 (PDT)
Date: Thu, 18 May 2023 01:43:43 +0000
From: "'Fangrui Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@kernel.org>
Cc: kasan-dev@googlegroups.com, Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Mukesh Ojha <quic_mojha@quicinc.com>,
	Mark Rutland <mark.rutland@arm.com>, Ingo Molnar <mingo@kernel.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] ubsan: add prototypes for internal functions
Message-ID: <20230518014343.32kht5dmthjuly34@google.com>
References: <20230517125102.930491-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <20230517125102.930491-1-arnd@kernel.org>
X-Original-Sender: maskray@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Xyb4IV2y;       spf=pass
 (google.com: domain of maskray@google.com designates 2607:f8b0:4864:20::632
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

On 2023-05-17, Arnd Bergmann wrote:
>From: Arnd Bergmann <arnd@arndb.de>
>
>Most of the functions in ubsan that are only called from generated
>code don't have a prototype, which W=1 builds warn about:
>
>lib/ubsan.c:226:6: error: no previous prototype for '__ubsan_handle_divrem_overflow' [-Werror=missing-prototypes]
>lib/ubsan.c:307:6: error: no previous prototype for '__ubsan_handle_type_mismatch' [-Werror=missing-prototypes]
>lib/ubsan.c:321:6: error: no previous prototype for '__ubsan_handle_type_mismatch_v1' [-Werror=missing-prototypes]
>lib/ubsan.c:335:6: error: no previous prototype for '__ubsan_handle_out_of_bounds' [-Werror=missing-prototypes]
>lib/ubsan.c:352:6: error: no previous prototype for '__ubsan_handle_shift_out_of_bounds' [-Werror=missing-prototypes]
>lib/ubsan.c:394:6: error: no previous prototype for '__ubsan_handle_builtin_unreachable' [-Werror=missing-prototypes]
>lib/ubsan.c:404:6: error: no previous prototype for '__ubsan_handle_load_invalid_value' [-Werror=missing-prototypes]
>
>Add prototypes for all of these to lib/ubsan.h, and remove the
>one that was already present in ubsan.c.
>
>Signed-off-by: Arnd Bergmann <arnd@arndb.de>
>---
> lib/ubsan.c |  3 ---
> lib/ubsan.h | 11 +++++++++++
> 2 files changed, 11 insertions(+), 3 deletions(-)
>
>diff --git a/lib/ubsan.c b/lib/ubsan.c
>index e2cc4a799312..3f90810f9f42 100644
>--- a/lib/ubsan.c
>+++ b/lib/ubsan.c
>@@ -423,9 +423,6 @@ void __ubsan_handle_load_invalid_value(void *_data, void *val)
> }
> EXPORT_SYMBOL(__ubsan_handle_load_invalid_value);
>
>-void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
>-					 unsigned long align,
>-					 unsigned long offset);
> void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> 					 unsigned long align,
> 					 unsigned long offset)
>diff --git a/lib/ubsan.h b/lib/ubsan.h
>index cc5cb94895a6..5d99ab81913b 100644
>--- a/lib/ubsan.h
>+++ b/lib/ubsan.h
>@@ -124,4 +124,15 @@ typedef s64 s_max;
> typedef u64 u_max;
> #endif
>
>+void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
>+void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
>+void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
>+void __ubsan_handle_out_of_bounds(void *_data, void *index);
>+void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
>+void __ubsan_handle_builtin_unreachable(void *_data);
>+void __ubsan_handle_load_invalid_value(void *_data, void *val);
>+void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
>+					 unsigned long align,
>+					 unsigned long offset);
>+
> #endif
>-- 
>2.39.2

Thanks. I've checked that these signatures match the definitions in
lib/ubsan.c and the order matches as well.

Reviewed-by: Fangrui Song <maskray@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230518014343.32kht5dmthjuly34%40google.com.
