Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY667L2QKGQETSMBR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D42481D52F8
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:04 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 5sf2032723pgb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555043; cv=pass;
        d=google.com; s=arc-20160816;
        b=cu8YfGOMJ2LaloOVCiHdwdkgv6Pj9Ei3wByqPC62boBe3fojJz0SWXAIBl6L4PASpb
         wok42n1gtSDTAzU7DFxLhmS9yK1RkIXqj5nFdHqpYJV7EB/uFju64JDn6ikwBlJpTwnh
         0jyQu9pQcVn3y83kuqz/36tzsQ3fUweo4LCYK9wdzvhU8EGoZYWb4UUMbdtOSxdi8wTv
         Elt4AG1BnjfvLS2ThtI1N4KwhC3EmqUo9goTeBLlAjfrmqbK/bUw3KlCJj4r1t4CHOHE
         SBUKO4BhnfbMjBxpqj0kdbnBgT3FVzlpMlEwnAduuN0CB/0zkn12Gvt4SCFkIBx9+Qoa
         M3+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZgX7e7+knvdOPtC4iAKolUaT1SC4DF5S3aEOZakp7ok=;
        b=U8J+LW+2vaebiAg+f1+b0IfSysD3AYAwmvu1jhgrb79jFIPnmosPjlFkQFiqsQU+ux
         3k5+YgtcE8rQqVBwvh09CN9Cy6wxdSfE90fxm8ttleTIGb8k/YM0pkWW4delsXej6sw7
         AyvKsTR92ONspO1Oapj7hyMOFdv/4ULktk6zFmwKnTwMMpKPR77nyh3TLq3TcAqrtSAs
         U3UzInd8LDiqhWWNiehMkHKXTOFmn39g/uRLIAp/42VQQ+BNunYd0DbZI0kjS3N/iLoU
         jva5gvrVZhrOjpOBqdMiUDYL8BtKccx/fFdJeZX/LZFWc6aNq9Z0fA/tUC9EETclI64f
         rYtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XabRop8t;
       spf=pass (google.com: domain of 3yq--xgukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Yq--XgUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZgX7e7+knvdOPtC4iAKolUaT1SC4DF5S3aEOZakp7ok=;
        b=LtU18C0uCUEFPtS+fTWSvRZT1Uy7wHqoQYGkCWgy9b1RkVqmnYhpInqcCyx2xO67k6
         FbX0ai9iVveHXuSKFhARWesbKwefrDCe9ZoWY+QHPmG6lXi0mV4g44xyMFlCgn92OnLq
         j1vwCYsJmPnJBhgN52p8eU/+5Uix0Odg9l6WuPsDEQ9tHOj88dsYgTMmyGliPSZtBRTi
         O4vHc7891DXDtgUHklYdXQOnFYmZ4/Klwt8tCpwE7kWEmiJBt8JSTHePWIUzlwiqNJTA
         79v7HYjZ/8ci2maHJL4wKYcUwxYcUpCZxzYg+dHF5OdjjlaDe51eEHCYcFksnBF05JOs
         oNAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZgX7e7+knvdOPtC4iAKolUaT1SC4DF5S3aEOZakp7ok=;
        b=n5gfzJQPXIJwkjJr5dyhfbQN/o12eCWqQ5264KtKG9hQKB6aSO9uwOZX4I08cRTL5a
         COBAwk3B2laxeFVm16cxbHduVhMBdOOoLuZo1hAEL+lxLX5a5JkPyWwe3JCjR/dFcWNc
         RHJWsmA5KgOrHg2QjGiTLcbq2VxNF0F/R0t3b2eJu1+HuMW+mzlWlV3qh/4QrD/YxEwo
         561kR12STkKvWRCvQACR2V6PHrdqA8yRta5AljeIigYjmW75hiKXhQGklEOrmtqhUCvv
         7QoEr8Sem//2XsNyn2/bVrxvat4JuvAtnFVWJSCub0694fFZXK95dKpizKU+Z/rCUrin
         4PLw==
X-Gm-Message-State: AOAM531uwrw6AL8PCBpBwGb6XH2YaLUlUk33iOh8N8PlGeYndPngISSi
	wIO1qlh2zDRzySqv8/kP7ro=
X-Google-Smtp-Source: ABdhPJwj2S5QUZ7PwlpkByHCrcANL5GjxovaWyC/EHYZ1h43llGQ//R5QakcxThKfzYQVHfDSoj+Ug==
X-Received: by 2002:a17:902:7285:: with SMTP id d5mr3608433pll.206.1589555043628;
        Fri, 15 May 2020 08:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b702:: with SMTP id d2ls921054pls.6.gmail; Fri, 15
 May 2020 08:04:03 -0700 (PDT)
X-Received: by 2002:a17:90b:4c89:: with SMTP id my9mr3321284pjb.216.1589555043012;
        Fri, 15 May 2020 08:04:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555043; cv=none;
        d=google.com; s=arc-20160816;
        b=qDgmWIAWGnBwhNdGz9XogCOLU9Buq/U48Jw0zeovD9YmXyKpIywdrdIyTSOtzPYBib
         PdhSbmM7zcwjahhktQU6n3thtxzlq/KbSSc2rlhGabjIPIIoS6pdejDspIC0mPuFFB54
         eVwp7AfqCmkK2pvXyKRoP0zQyucY7Pnxqi3Pxdq8LffflNjj4v0uabNb9EYrTy2DBUZp
         l8/WWn54N7ehYnChZZPpLvlf0x/2ux+Oc+EOPpT1uVFYvRRZj1twgy2Oos4IJ+6fVVdO
         VheWCKVrIpUVEUP6qx+8FM+JDFDEh/I21GmNBWe2vkLSIOeCT51sa8XA+cDeaDoW9Fz4
         8ndQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0j39NvXrsyBh4wsV8IVEExoloRXnW3VKds76JrKCKC0=;
        b=wcXpT4a4BlwmEEMeZMcQds6lemA86KKySNi9DrveyofwLF4tOA0GY1wapocFTVneY4
         fYF36e3EHLx7XzBFvJHxM/hhxrAsQ5yy5sFKlOB0cvqSxtdr4Iq6oI7ZaH4G7NkWjrsF
         fAO/0dc2sfugCbrO65HUJ1P8LoiU/67UNz3B3jDFxXWc+ZNXRRMeWAhe7c5SJAYjcuM+
         3YgMdCYmRbrclL4pWAtO1F0nbUKizjIyRKYVUFldtMF01KBe96SFRpTdmRMk5IAi2MFK
         LjmC4v1m+j5DKmbJL7ohBH1vu1zWqfiPN+6W3sDdsBo+jGwKCCt3iu/LHirR6yNRr8qJ
         0Xpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XabRop8t;
       spf=pass (google.com: domain of 3yq--xgukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Yq--XgUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id t6si1074742pjl.0.2020.05.15.08.04.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:04:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yq--xgukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id h15so2893179qvk.0
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:04:02 -0700 (PDT)
X-Received: by 2002:ad4:5604:: with SMTP id ca4mr3961451qvb.6.1589555042352;
 Fri, 15 May 2020 08:04:02 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:35 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-8-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 07/10] kcsan: Update Documentation to change supported compilers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XabRop8t;       spf=pass
 (google.com: domain of 3yq--xgukcbcbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3Yq--XgUKCbcbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst | 9 +--------
 1 file changed, 1 insertion(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index f4b5766f12cc..ce4bbd918648 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,8 +8,7 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0 or
-later. With Clang it requires version 7.0.0 or later.
+KCSAN requires Clang version 11 or later.
 
 To enable KCSAN configure the kernel with::
 
@@ -121,12 +120,6 @@ the below options are available:
     static __no_kcsan_or_inline void foo(void) {
         ...
 
-  Note: Older compiler versions (GCC < 9) also do not always honor the
-  ``__no_kcsan`` attribute on regular ``inline`` functions. If false positives
-  with these compilers cannot be tolerated, for small functions where
-  ``__always_inline`` would be appropriate, ``__no_kcsan_or_inline`` should be
-  preferred instead.
-
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
 
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-8-elver%40google.com.
