Return-Path: <kasan-dev+bncBCZM5DHZUQCBBUUCUCQAMGQETUJF7DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 389B96AFD64
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 04:30:28 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id h14-20020aa786ce000000b005a89856900esf8224691pfo.14
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 19:30:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678246226; cv=pass;
        d=google.com; s=arc-20160816;
        b=ngtxTt6p9/Dtczg1DMf0m+pQSpaF1vZDSuHGhw3BbaRQD3YScxqhANbMUev7/h9wZg
         Cekonc3DcZag9CEBEAcWfKjORss8BgFNxyi9qN/6QR21+6JxmPrW+TOt4pw3edjZG3+v
         TtPe2SekeOk/b+9d7ibZKCFLgCVu8Jqex4AjOP5+f9o5G/pXVIsA/pYvR5kLB1ISZ/0P
         qELS7LD9isZodbJ04EoaJeyxfQI3WVvS6jsFV1Vwy0niY8r2kt341FS3O6vSfxOgXO7p
         E9fyFxLDclwKhKgWYcUZ1c8S5Bo+LuEPgOiiPOSFcfsAtOxk/+3qNsdJsBRR5ajWaSq7
         yYXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:mime-version:date
         :message-id:subject:references:in-reply-to:sender:dkim-signature;
        bh=rcLAeU6g/gmamnTawAALO8I6cZ9kfOo8MfvEDAcFdlA=;
        b=Uqqc0MYcUpzCVGwsVvcSwXMXPfkeQN8L6azeEAwZtPmimefr6btr/UigvGJgXKHDbj
         JI1lir6qbPpBDvgcrq4I84TncozZq64sFpIOfjKM67r2XjSJ8ufpHQfyGBpJTArR5Qkn
         1d8aCYE7SCW0mp384p5dO50wwfanKgqhnbXB3nJVoARu3GJyLgSWjNYBHpWVZoqhSJU0
         J6zjJrYTAlZtDen2twFEkQ7897ScU1oNzBhOS+86zvyeo/3GDFLwOseCHirKmkC7OtRo
         DLBEXLhLrAH6V61F2pzvaXc3+qhqo4XiSgmEy6AAdmoc3di9ynv6YDsD8y4ZI9g/oRHv
         Iz9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=nMEKpiB7;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678246226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:mime-version:date:message-id:subject
         :references:in-reply-to:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rcLAeU6g/gmamnTawAALO8I6cZ9kfOo8MfvEDAcFdlA=;
        b=C0Kz20DCn6EucS/I77JhE08DLccAf7zFl6M5zS3Q4l9LZb974+kJITDh8TjNe9rLYL
         O/v6uqd0gLE80yMemUzMTtS+FT18XHHBvdc9dpMmeuIGR7Pzc1EIM9kqKfKuaZ24vH8Q
         dc3QKMNQ5+820sbiPDlF9xA8q7oIebsTw42ZvVEqTA3MKKPVP2CcPLdGgWDL7k3yahIb
         nMZ82jhZBC1Y7trzpiB3Ak4CVNE2m1ARccYCEPpXcG2u1HjdSuqp4VX65FJ/gPMQYvHG
         hE+CPltR3YFecJ7d42sicfGWNOJQ9gH+zh63tdmUW47GnOCZ2x6TwEbe3gafRf+nD5l2
         QbVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678246226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from
         :mime-version:date:message-id:subject:references:in-reply-to
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rcLAeU6g/gmamnTawAALO8I6cZ9kfOo8MfvEDAcFdlA=;
        b=rWpSAK6tb1WxRLUF1qu3KVCep63tO4C+QGPH9WQqqCAGSxLKRoeHsquU7ak7KHFDqr
         PL81kQmVKm8sl6gqtHM4+YYKeDTpsHxyR8cgGDXwNvC1L91HUTHqxb3edlQDX7xW+YVR
         20JUs/3i7/yoc/gmUtE8TdBmcxXWdG8r9nGbtki5FmOlyQkUR81xqjOjn55G4v0InGsw
         YP70xdt7FzA7TxzPyq4eij43b5C+GaNbVRzfzvPlx+LsxR1JPq/bhyVCGjG4n2gNTNIO
         fFb+qjrhvilsxZPN4YoDxpuqGrKQeItyIhq38fSVe6x1hjKeciUdEzrAXK9mVyxyflzT
         8PIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWfjAtpWQkEMiDWgiJXHZ5qk/yA59iSv6p1zGd3OKEu4TxY8G3N
	gdODN8fd0UMjo7/9OSDC0ro=
X-Google-Smtp-Source: AK7set9bJUXsjVYl82Intp2bB/IQbMchWS9fRyXQmFPWh0lS42mVSj4cmtTre69q+VwVYBtxUn2suw==
X-Received: by 2002:a17:902:ab55:b0:19b:c29:3932 with SMTP id ij21-20020a170902ab5500b0019b0c293932mr6449149plb.3.1678246226296;
        Tue, 07 Mar 2023 19:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c3c5:b0:19e:398b:8d99 with SMTP id
 j5-20020a170902c3c500b0019e398b8d99ls14712688plj.4.-pod-prod-gmail; Tue, 07
 Mar 2023 19:30:25 -0800 (PST)
X-Received: by 2002:a17:902:c14c:b0:19d:74c:78e4 with SMTP id 12-20020a170902c14c00b0019d074c78e4mr15093158plj.55.1678246225466;
        Tue, 07 Mar 2023 19:30:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678246225; cv=none;
        d=google.com; s=arc-20160816;
        b=WT5RIqHjcsXrKd3XRWykRZM+ObnVuQuiWRQdlfrzbiCL5G4Z+12nHi6WqvKQuCaiN/
         r8jMls9wzT61Uq197haFqQCuZoKriebx0amyUB45nLOMgfrOtgnKnSSvd95zYesSlyzF
         jv8qPZ/XKrtzB6ddBxb3xn/wSYiEDQ6db++neok5Xw8zRXx+dJujwDjLxdfbo6g9pDLz
         /M1luMkP0mFGQGZxEmm4n1EDOJ4TnaVfavbQj0WXvzCYRjnY5hnk1g3IAZ4ZZjwPE9E4
         W966csZPrZ9Y6sNmAbFHwSUkYzJX+tuxwzZT++gGwcRwX/A8661H45BFTRFXWItVga9Z
         AVZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:content-transfer-encoding:mime-version:date:message-id
         :subject:references:in-reply-to:dkim-signature;
        bh=IrGumBD3CuL7JhmpbkRoYLuQ9iRztdyj8h7PwNT0G+k=;
        b=O0CUSPYF7CIzrLYcoq/YbQCrBX3ZucshGH2d8iTFQ8KBgW+IynPZ1c66yAk6iPQG2a
         pRFzR1myh4tahOiPMOcXVml2FN1N+9EM9/v30S6+pOrU2DNX6ifNQvUYKnIvjYLhWSKe
         vGu8wbtFEVAiTy7JXaGW8q7WaZvRWE/aFdoMmk7QMcm3Nw0aoiZx5NRyGw7hN1eq8oFa
         gkA+qkrFtpp/IAe8lPNAvb1rnZkisJhMb0JUcPsQBEEvgXN3cVqCqd64tu9+4xk4rQX4
         BmHUzWcP8TX79RrqEez+DzLm1wM+26cHPuPo1gs3OTcqMnMQFl07/s9CjYP3b5+x5y4A
         AiJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=nMEKpiB7;
       spf=pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id b4-20020a170902d88400b0019cc2dc4fd8si742212plz.10.2023.03.07.19.30.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Mar 2023 19:30:25 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@rivosinc.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id p6so8927945pga.0
        for <kasan-dev@googlegroups.com>; Tue, 07 Mar 2023 19:30:25 -0800 (PST)
X-Received: by 2002:a62:1758:0:b0:593:d2ab:fdfb with SMTP id 85-20020a621758000000b00593d2abfdfbmr13432662pfx.13.1678246225092;
        Tue, 07 Mar 2023 19:30:25 -0800 (PST)
Received: from localhost ([135.180.224.71])
        by smtp.gmail.com with ESMTPSA id n13-20020aa7904d000000b0058b927b9653sm8771578pfo.92.2023.03.07.19.30.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 07 Mar 2023 19:30:24 -0800 (PST)
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 0/6] RISC-V kasan rework
Message-Id: <167824615129.30763.10646446884793553712.b4-ty@rivosinc.com>
Date: Tue, 07 Mar 2023 19:29:11 -0800
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.13-dev-901c5
From: Palmer Dabbelt <palmer@rivosinc.com>
To: Albert Ou <aou@eecs.berkeley.edu>, Andrey Konovalov <andreyknvl@gmail.com>,
  Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-efi@vger.kernel.org, kasan-dev@googlegroups.com,
  Paul Walmsley <paul.walmsley@sifive.com>, Alexander Potapenko <glider@google.com>,
  Andrey Ryabinin <ryabinin.a.a@gmail.com>, linux-riscv@lists.infradead.org, Ard Biesheuvel <ardb@kernel.org>,
  linux-kernel@vger.kernel.org, Palmer Dabbelt <palmer@dabbelt.com>, Dmitry Vyukov <dvyukov@google.com>,
  Conor Dooley <conor@kernel.org>, Alexandre Ghiti <alexghiti@rivosinc.com>
X-Original-Sender: palmer@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=nMEKpiB7;       spf=pass (google.com: domain of palmer@rivosinc.com
 designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@rivosinc.com
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


On Fri, 3 Feb 2023 08:52:26 +0100, Alexandre Ghiti wrote:
> As described in patch 2, our current kasan implementation is intricate,
> so I tried to simplify the implementation and mimic what arm64/x86 are
> doing.
> 
> In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
> instrumentation: all kasan configurations were tested on a large ubuntu
> kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.
> 
> [...]

Applied, thanks!

[1/6] riscv: Split early and final KASAN population functions
      https://git.kernel.org/palmer/c/70a3bb1e1fd9
[2/6] riscv: Rework kasan population functions
      https://git.kernel.org/palmer/c/fec8e4f66e4d
[3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
      https://git.kernel.org/palmer/c/1cdf594686a3
[4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
      https://git.kernel.org/palmer/c/415e9a115124
[5/6] riscv: Fix ptdump when KASAN is enabled
      https://git.kernel.org/palmer/c/fe0c8624d20d
[6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
      https://git.kernel.org/palmer/c/4cdc06c5c741

Best regards,
-- 
Palmer Dabbelt <palmer@rivosinc.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167824615129.30763.10646446884793553712.b4-ty%40rivosinc.com.
