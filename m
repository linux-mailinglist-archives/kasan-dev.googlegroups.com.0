Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6ME3KRQMGQEWNFW4AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 44E3571715F
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 01:10:52 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-53445255181sf2755216a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 16:10:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685488250; cv=pass;
        d=google.com; s=arc-20160816;
        b=nvOO4zGrBAZgiXR0IJePVPu1CtZEIuTb0puu2vx2qZ3iX/KguqQC+WciqxyTMeQXsJ
         1XHOb4ZuyQVgymAiMFh01NhwfcT6MNKXjwWFHHrAgtS0CyRrOeZHA4ti/SXN/sWpzJI/
         hhKxqdh8AXDx8Elalg74S1J8kGjMhEP7zuV9yzzeie9JGejojzbbMWk4s6SYp2lO7aHR
         pqburbcDlQlx1xoQQXtKXi/8OY79M+isD2NR0mNQUdf5myCSzj4HxpthlEKQQDwJJEB6
         F9bc2pZAYfVZY6FQSaHRV7AX1sRF8iFHhDzQuMDn8zHkjThpgECMc6IwEEmnR1UACsTV
         vHzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HA4PGjXSck/T9ci6iokVoL/ClGOHVqLbOQOzvVScEzw=;
        b=Fln8Mqkb7t1DFy0alikgI4J0nANlLb2WLYJDOIKH+qQbTpqF9A0TdlVOHf3Zit/UT6
         492nbOnf+BVgBXSEwxeJARfUdMhkEWPXdvDANzr/sWE0f8IKUmIfAU9BV3/fsDuiQNE3
         4ZidSUPamnWwr3rCEVqIxsZobMZMkLnIDtBwFTHom/GVClUw1bIYR3osXdY2cWX6yQAU
         /3eIgFqVxT5Dhx58+YgXm+PMfkjezHfLP0KmOwWEsEt6K9Kyc+fIaGqOmevdhtzxQhgD
         gxW02TiXVskO3fPwPmdyKErTp20TsvMI4YCnpiaE6ibVsayLSRJ94OXbawz9m5yQa8yI
         wS/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fEJERwCS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685488250; x=1688080250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HA4PGjXSck/T9ci6iokVoL/ClGOHVqLbOQOzvVScEzw=;
        b=SiryXVWm6x9E9KLyksrpl87oXhNa32Xot+0QEV6PepIvcI5cj6VgnziPlA4rakfsEq
         IN2FpZhNi3JRIfi6P48PaEbFlPLzpkWs54b2tDfUIV1mP39voiR8G5icIwsk9lshKpXI
         1jSLbSYXiddQBjesCDKonBKxc7znBZrGjxH70/KjuZoQ+twhlgUfixFn1VzrP11QHJN3
         P5sbQ2LI9Vdyk5NikKcf5/VV6uhBFUVxCwL+yZhT6mBrKwU5aQDbPe1zkbZieN5lW0tS
         uP0Cff3jPQzIrg4QZFFPjtBOo6M5+pYSrMos5p06pr+pKioIlBhj4D+97XTryzIdhhhM
         E/XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685488250; x=1688080250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HA4PGjXSck/T9ci6iokVoL/ClGOHVqLbOQOzvVScEzw=;
        b=T/8NKyMBPyTMqEia0f/ymp8VJMbdGvegF5Lg+Yb2lOsqIPZL/MtFQBfdaMpDK5pSAL
         XUZRPWu2FfJFVEkpwQYb541TMuIupwgOLJj6fZMTpNiIrUut3Z8gf9atqVqPl+E1sXpE
         vunCD0eIviIMG3s2Vgi7piYbwvE4p4uDwBTRTms3VaFIOYoQheQE9Jp1okQoKVXTS2gR
         GWTnofC3onTyh947nrzTyRsZsM5gw3JSh2natmwQrvIT+gZPo8wdff3frTa76Qg1LMlF
         w3UslBa1u2U8N7nRdkHiPGMmDvrKyuJbYBS8uKqjOmp97EsRwafUn2IPySTf9P+lpHCo
         CWwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwbZrUlfaP0hPMgSgSJjlMof/PUYfxtgMvbdjWP+Wgsm90H36cw
	MT7ingZAqC6w+PSevf0jV0M=
X-Google-Smtp-Source: ACHHUZ5HBUyjrDHv/c0nm/58PtXnEvgMBkqVUe2d3qyqCHnDyJEDWbQofVV4iBmnfQj3YO9nGh2wCA==
X-Received: by 2002:a17:902:6907:b0:1af:fd3a:2b39 with SMTP id j7-20020a170902690700b001affd3a2b39mr971669plk.9.1685488250067;
        Tue, 30 May 2023 16:10:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:73cf:b0:255:4635:41f2 with SMTP id
 n15-20020a17090a73cf00b00255463541f2ls4392040pjk.0.-pod-prod-02-us; Tue, 30
 May 2023 16:10:49 -0700 (PDT)
X-Received: by 2002:a17:90a:cc3:b0:255:2dfc:6c6f with SMTP id 3-20020a17090a0cc300b002552dfc6c6fmr3794808pjt.24.1685488249266;
        Tue, 30 May 2023 16:10:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685488249; cv=none;
        d=google.com; s=arc-20160816;
        b=lcWKNnTfpBGzdTCeowoCONUax098SNgDlMk8NhQA+j/tbLI6ajL07m6Gsu2Xk5HWM/
         vRct01KHwrrkQ3N+6ntgBntDrLpXznUUadRR5T62wxeFe4LqgGAC0AO9NSuY5KHQMb2v
         97A2RInVLVHWdPsCSNDMDqVYV8z3GQjUoGY9KGOqXLodu1oztodqirXBJLu8/pmOT7pQ
         cQq1su0WtW7vMkl1DApLPlNYjudV3/q5rMT4AgU3aYICti+TjlzRswQIZ30o7TCtZH+G
         asCL4zoJ5HZShmovh9Ig3woSrvhFFH0UCHdH4RAU/ZJJ7gE8f/xOrtuiV6XcwRWfZewt
         QJWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uFt7XEHQNVyt2Kkuqvp1ttAPdqoItbGL7ZFzJEOFPcc=;
        b=eADNdB+HrC23/9jJ/B++yQ1RtC5dvMWbiZTd1iB9f3V6VGF57QNG2SJ44ZvcSICeJW
         9Zu7drHR/VTzWjOH/5LmUMrT1J9RYFV7A7oxbdjvmljb1XJF2Q8HRFPz1PYraQ0u5HbQ
         1jBaVI4KHK06WicN/w0OfRsnBNcpk6HBmndRI0nbtQpFdQOaV7915PsSaQPUuRzIETOX
         JH6oEbovlEBTibH+FkH/JCfc87P6YhYX/Gj9CtkI5vH6Lc/2wBFytNgeFVRr1UOFwh3i
         uPJa0V2mpDvvQNFqcfLEBiQgKhfEP3XRy2r/FtdHl61pbrg056z4xc0xT6h2K4MsvBOR
         626w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fEJERwCS;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id lx1-20020a17090b4b0100b002504e396db0si614353pjb.0.2023.05.30.16.10.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 May 2023 16:10:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-64f47448aeaso3736425b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 30 May 2023 16:10:49 -0700 (PDT)
X-Received: by 2002:a05:6a20:12cc:b0:110:7edc:fb50 with SMTP id v12-20020a056a2012cc00b001107edcfb50mr4923350pzg.9.1685488248858;
        Tue, 30 May 2023 16:10:48 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id b11-20020a63cf4b000000b00513973a7014sm9165279pgj.12.2023.05.30.16.10.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 May 2023 16:10:48 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: andy@kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	glider@google.com
Cc: Kees Cook <keescook@chromium.org>,
	nathan@kernel.org,
	dvyukov@google.com,
	elver@google.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	ndesaulniers@google.com
Subject: Re: [PATCH v2] string: use __builtin_memcpy() in strlcpy/strlcat
Date: Tue, 30 May 2023 16:10:46 -0700
Message-Id: <168548824525.1351231.6995242566921339574.b4-ty@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230530083911.1104336-1-glider@google.com>
References: <20230530083911.1104336-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=fEJERwCS;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, 30 May 2023 10:39:11 +0200, Alexander Potapenko wrote:
> lib/string.c is built with -ffreestanding, which prevents the compiler
> from replacing certain functions with calls to their library versions.
> 
> On the other hand, this also prevents Clang and GCC from instrumenting
> calls to memcpy() when building with KASAN, KCSAN or KMSAN:
>  - KASAN normally replaces memcpy() with __asan_memcpy() with the
>    additional cc-param,asan-kernel-mem-intrinsic-prefix=1;
>  - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
>    __msan_memcpy() by default.
> 
> [...]

Applied to for-next/hardening, thanks!

[1/1] string: use __builtin_memcpy() in strlcpy/strlcat
      https://git.kernel.org/kees/c/cfe93c8c9a7a

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168548824525.1351231.6995242566921339574.b4-ty%40chromium.org.
