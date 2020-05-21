Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCWDTH3AKGQEKQ4JH6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 490521DCBB8
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:03 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id k54sf7206752qtb.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059402; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+DEFUgBm3e3+3peUO33F477zJQW5uSPlh4cZK+j7oDl7jA/4WsgKu/WhwNBqJcWcp
         n66tyqKdjnYr5i/GKLRLPHP+sLKV9SlB5RfUxZ/82pxgFLFpu8Gq+OnnqJfu4ISQ+SLI
         ZnEvJku3UkPeBY6D1mT4FoueqjbEOevY8GktNU2pa5lpnwePEFsVogkIl/pf+H4g0v61
         xRHIkF9eU+xlCwFnS1dpxe2KL9zjoKeYDm2dA2Qc/DtFI4zC0pfhKbC6pNmfKMtCAfmG
         bMa5duYHZPSr21oLmEBtauh6s/60w6POlJvnPotSno3Z4KYEuCGfb/0oPvUdA5w5wc6l
         SxKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ioW8gXLMGLqQLIAxXEL6KgDda3lfLxMOws9IpirYCZ4=;
        b=JQax0asMH5bbyUsgqFJnf5jx3s7DhhSAW1UpB945Q8lcsBUAKLNY1DX8XPNyMUAbhe
         8DkKpznrSFhmBERX6/VJMTfFQHtZIj01J7vdWRQzM3LEDNa5T5djSq+vwffJhpBGukyE
         MtRy5KRFyfCGmcXYlSxak0TdIfTvg7YKyOUd9fFs4XnhLUx0uLdvXPYeg4JBVmGBTqLm
         DpxjXQhY+W0fBLceQGoUF4hhoUAwvpNnFPxdCIHhZRNb0s3i74ToJnFbF405M5fSh4dr
         VvVLso3w7mqGBM9U/LOmJCXgKppxBRnCdHXUZ5fhL8yijL3KwKfl1rr2Gc4uwellzbmf
         u44A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VtJ/Urbf";
       spf=pass (google.com: domain of 3iwhgxgukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3iWHGXgUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ioW8gXLMGLqQLIAxXEL6KgDda3lfLxMOws9IpirYCZ4=;
        b=J5O3Ju4LZvLtkI6V//yVChCEscCPzr9MazEk5krxYCA1QKS242NjuxiOY32oU2Vcrv
         JpNXXWzeAWLTx84jHJkcfCr8J12AOuxt58zaGzkLgh2TKrZ0i8y7YI0pVkvabdJdUESV
         r73+hxwRNlE/+OBPHtckURduFGaMCEsabW9SK94jRTfDAsvzAkHmJX1kXlc+RxBEVOqx
         y1MHb4jxwWD8Krsj/CPK5WBZSrM9iYCutOGZWzyiewd2Z0JBD/ufzRcno6aceTLZEXiB
         Va/ORZC/K95nYtibu0cpIclma/Uf30zHqSOKAE4yX6y0Xqui7p4J1fBJeL2UCsJzVxSv
         BcYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ioW8gXLMGLqQLIAxXEL6KgDda3lfLxMOws9IpirYCZ4=;
        b=F2NxPrkjNzfHAedzZxd6Drfdnvq4PyiFWLBF7G7beY5bn7pJhjm+N7mnti8RlMg7n7
         yuvjFAH0QgcHPdLB94xSs4UCtHisiFDtgKulb1AyE4MKcFtgWxkQGoedORHKS+sCeoBJ
         V9rwaEWXO/U2F3HfFP9HQyXyRxX6AD503j5lcMinL26yzo8LZ0ovBHb2kjyNQTMs7PR/
         oeBqn8ku9nN0VI4OueWnxCOjwYPJFdQsWv4bDZG1m2+DPSoeKdxzX8jLgcC1EMaslXXJ
         jKGb4eChO6PvhOrmgtgYwh21NpEqw1uUe6MsjE5acNz/qgZubjvubNv2XtRnxCggmabQ
         ooug==
X-Gm-Message-State: AOAM532FIHdybDtdhWrXPXyG8bboURr4YseXZtJjNfg9HxIWnSGAvtWE
	fd+vV4oWQFqglaXKRaNksb8=
X-Google-Smtp-Source: ABdhPJz5E2Y/uCyZbX3d6Gd4VNuFPqwF5sGAl8DOvcj2S1VLOEiz7V/b0ixIZwGQPVawn54UNDL/pA==
X-Received: by 2002:ac8:1bd2:: with SMTP id m18mr9789483qtk.77.1590059402391;
        Thu, 21 May 2020 04:10:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b1c1:: with SMTP id a184ls865436qkf.3.gmail; Thu, 21 May
 2020 04:10:02 -0700 (PDT)
X-Received: by 2002:a05:620a:136e:: with SMTP id d14mr9741175qkl.9.1590059401995;
        Thu, 21 May 2020 04:10:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059401; cv=none;
        d=google.com; s=arc-20160816;
        b=zd5FJ9ypTm0NsDZgHimK7ZR3nqweiNpyeKvrD4ApK+s+qKstqFsi9fgfTZFDPDup0I
         2nOESh4PPcP5uB8xh7TjZPTG96z6VCF9QFcQqXejYS4AVJNHDpK32IQD/WNwxsTX37FU
         DIvoVbnZDN5K3n3sVTmoG66AfizlttB617oybUag8ZcUeeZehppV/4yrQ+VxAItn8E1b
         +hcvJPfiLkDl/2jFVYspv8WCP08Zmw2zvYMmRiPCJCQUulfocUNDcfkGg4IkGi4eQVE6
         EtiUCAVL2yC+CfDy0M4ZHgKmUsFQk1gJJn0okS3qYzjmkwGIxS3Fd1/fz+tRe7LHXDUG
         Di7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=O66Rrrp+JcFi/5yju5R8rYLztnbdicYxc/HcFiSiC0Y=;
        b=sQfkgkPlYJDHOXdvm7Q4MLiOcjYP3ttThjqkKHG3S7ZRnbHgDSyh/lKCQf3uIEG5OX
         Rblszm0am3ZzBkOY/lmbQDrtAkI8c0R2Iv6V2gTuGOn8aJgOs6wwGdqulJ2syJYA8A7n
         caviY6YDrSSLAjIWumpp67ckKz2k32Q76TQyWjVIoRvzAgiZZV/Q7npD4Vq87dg6lmmt
         7dRBm1b7YwbzLS8CUOBDOvCocJ72csxOQfX99nlw4314q7DJN1qQ0jlsIObuDuATtmIM
         VsN4Kt/It4F8Bm7VZOp3/aw1h4g6V6g2k+QfD/vDUDMNpTPGSWGQduLylyTm3YWXW933
         h0QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VtJ/Urbf";
       spf=pass (google.com: domain of 3iwhgxgukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3iWHGXgUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id m128si425868qke.3.2020.05.21.04.10.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iwhgxgukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e44so7247868qta.9
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:01 -0700 (PDT)
X-Received: by 2002:a0c:90e7:: with SMTP id p94mr9692288qvp.219.1590059401676;
 Thu, 21 May 2020 04:10:01 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:48 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-6-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 05/11] kcsan: Remove 'noinline' from __no_kcsan_or_inline
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VtJ/Urbf";       spf=pass
 (google.com: domain of 3iwhgxgukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3iWHGXgUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

Some compilers incorrectly inline small __no_kcsan functions, which then
results in instrumenting the accesses. For this reason, the 'noinline'
attribute was added to __no_kcsan_or_inline. All known versions of GCC
are affected by this. Supported version of Clang are unaffected, and
never inlines a no_sanitize function.

However, the attribute 'noinline' in __no_kcsan_or_inline causes
unexpected code generation in functions that are __no_kcsan and call a
__no_kcsan_or_inline function.

In certain situations it is expected that the __no_kcsan_or_inline
function is actually inlined by the __no_kcsan function, and *no* calls
are emitted. By removing the 'noinline' attribute we give the compiler
the ability to inline and generate the expected code in __no_kcsan
functions.

Link: https://lkml.kernel.org/r/CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index e24cc3a2bc3e..17c98b215572 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -276,11 +276,9 @@ do {									\
 #ifdef __SANITIZE_THREAD__
 /*
  * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled. The attribute 'noinline'
- * is required for older compilers, where implicit inlining of very small
- * functions renders __no_sanitize_thread ineffective.
+ * compilation units where instrumentation is disabled.
  */
-# define __no_kcsan_or_inline __no_kcsan noinline notrace __maybe_unused
+# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
 # define __no_sanitize_or_inline __no_kcsan_or_inline
 #else
 # define __no_kcsan_or_inline __always_inline
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-6-elver%40google.com.
