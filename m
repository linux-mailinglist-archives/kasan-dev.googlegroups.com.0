Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMM5TL3AKGQENNZ4OAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 748A41DCF86
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:42 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id e43sf7930470qtc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070961; cv=pass;
        d=google.com; s=arc-20160816;
        b=WZXgu1Ex97HSMduxeVRRQGJBC+mg2ZC9cQohB/kCZokK9yKqXx1VhP/tvn4x16TDmA
         Foxa2qSTYUP/Cv2MpbG/16rO+8Qr6r3m1xhFnqRKVxRke06vwlk0HmqoNFGxbSHimoXO
         EazbtTp9Wg/odMIYQ9X2sX/Z0TryVnH9voA9PdiCO6zYFJnJiWQuelQmIhQzYrbe9smI
         jeUIUvHkCcDChySoGmv1OYorUra89lyhRispzKdcdZxB/LS2Q+q3bD/N5NKw9tLe8TwU
         LUNbF/ge3p/sArDEd9qKE6dJ/ZHXwDRV46Zb3nVpUfhi/QzSZThBvjcmfEELZ9hBDpln
         lPLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MTPch74fzbfRNIoh9jdUK8FsWFTARSFAa4Y2d/eye9Q=;
        b=xPpPgNmaX8tecbYlsmUQIH03sOT7zQJ+8GEzsDWxlUHR1IwcQnyvS2t09rWCQ/K9M8
         +wdUIAHn3zVgP/yml+8fnjhH14CrjGfnX8P2Z5advaTHkFmQ8HJe1qzqiW8Qqf/lkVRb
         q7cCUJr17L4X1aqrFEkDIp+ug/V3CbhoP0Yo4WrnWzAFNjdVDjfogXbU1Y7/AnmffIBM
         brDwFau+EAHlsFWpuR7b36us+wWjyrxaKyk4FtafJUykN+oXFS/8MgOaZGJUSC/6n1FL
         WdrbcFrb0xvIerT1+4l8X81UF2MeP+od4Wxt280Z96IPShUKu/Nwjj2CokuASGRpzPwe
         wCMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=joJLl5J1;
       spf=pass (google.com: domain of 3si7gxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sI7GXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MTPch74fzbfRNIoh9jdUK8FsWFTARSFAa4Y2d/eye9Q=;
        b=TYyVag9ZwJLlMPmEe7v3wICK5USWKfSGSZS9zH2p8+rw+helgI57JrX2980R4BvM/n
         9CJ7AYZxAXUe+i7DqQAY1Qg+oND+/uRqQOacqaN2uAna0jaCMqptZKdG4UqLxK2Lt/UJ
         EqW6GCPSMw9cL9Wl+aag3JTZbL4cxqz5J0Ek9q6fV9jR5aseWwNYHBkLheVcpRstFrja
         rCO/nV9Jsa9zGqnd/tP/xHHeGocO+Ju9TnmNjMjOKsTFYsGICMfF47ycEbzw+aJirUn1
         u4Rwc6n2nIrKU93FzuuvgF8hLQahKnetgEEjxqAQMRZv7ZsWMav0iBT6esB42kFoka8L
         sPQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MTPch74fzbfRNIoh9jdUK8FsWFTARSFAa4Y2d/eye9Q=;
        b=YuzVWmNvoXIQJEY8MFJh0hrBLLqBJue0GOZ9vjhevQ6h1ReL78gBMeeCtAPkFFctXM
         ePUW129UuNHi7tC6d70zaSSEj8jCLTQJbfreSA6U6V6vuDJMAA0Q0QSierBmgoQttbsW
         x4k8ul/Q4KA7u9QyeYPKu70+xTDb8RgHMatlpmOElAHo4bCEGcq71Mb+kKGkMXxm6Lez
         5j0U5fX0g/y9YBzRRRCdDUAWuDY/nC95RE3E/c6jD7xP/t8PRga1E85eXJd+Zqjzwr/X
         1BKCqcT5E/o2bg8BCn/n9/2ycW8DDtlaKcIg4FftLo2a7eR/C6lH/TncAyDOnSn2SwSG
         XR+g==
X-Gm-Message-State: AOAM533LKh1BwatmaId2TNbPoO3SCBU1DXITD/LB2AUtSTBdzXuF/RWY
	hS9OuxMWOgMzpb6wYGlJHPs=
X-Google-Smtp-Source: ABdhPJwRW72knXnQF1biB9VnxcaKri8KTzm9hKetUEBFECpWrU8sELQasVrQvot8dfZ5SVGyrMpyJQ==
X-Received: by 2002:a0c:db83:: with SMTP id m3mr10044304qvk.40.1590070961504;
        Thu, 21 May 2020 07:22:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2d62:: with SMTP id h89ls982803qtd.0.gmail; Thu, 21 May
 2020 07:22:41 -0700 (PDT)
X-Received: by 2002:ac8:7354:: with SMTP id q20mr1476654qtp.249.1590070961143;
        Thu, 21 May 2020 07:22:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070961; cv=none;
        d=google.com; s=arc-20160816;
        b=bTJWkqKV3nyIs56VBjjEuP1Bw4wvPb+xn7sgjlbhf81L02kU5FsrHV87W+IGObRGxy
         FL+dw0uGMB/ipPRxYJh//eOG0hijWFYdL/qGxcETJif2HUeDB2fdWJVEGFVLMYJyo3nB
         sQi6141pQpf164KToWMXbdU4VMo/n2N6ASTAI8FcBEsyUJ97DZdqU5VYmHD97wvh5315
         qQ++wPc+T9Qmvdtk45QvzHS5Fy6Fe903q7Ez6yQGq5Kw9bNoCEtzDgy+afJxLz4QbfrN
         Wu9AwaG+MnIqZjmykZ7lf/eWwCJENQjrMgS2vqm2u0auY41ufBIj9Q+L0yzvNcIZpCpI
         uDBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2MIiys78gGheOmgr5sadClIeI2A+sMpKPCOuDS/ESKE=;
        b=Vq9qA9u7c2JNCAVRXjL5esmeNBJ/wcUm4oc0iZDNAhqZNGJnhuyhIYDoHUL+dJjA87
         RrN7XvorPNOzxe3EZlaAbitqLhHyLEs8ezNVWC6jO31L2wMf4+ZicpluEjpESErtHYe1
         JJphIpY5ShUsmIH34Bnq4u13H/e20O0HNL5Ezw1wHIQzonIEh/aS+1hXBKUkc3gjoONp
         rCN3rSQXt3kEHY4iVUD+hEwXJFDD+RZU1e3g8NQFR4AjoxFqJcn9YUJrxLFOF8FkHOCH
         vmhcD7qI65G6OFR0TP4XiCnfFeRdehrYEM+x+tmxatxrSgjxy0n7J4JHmm69h1YFcVqu
         mVOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=joJLl5J1;
       spf=pass (google.com: domain of 3si7gxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sI7GXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m128si465306qke.3.2020.05.21.07.22.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3si7gxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id m1so5486183ybk.5
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:41 -0700 (PDT)
X-Received: by 2002:a25:3608:: with SMTP id d8mr16539361yba.11.1590070960816;
 Thu, 21 May 2020 07:22:40 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:45 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-10-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
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
 header.i=@google.com header.s=20161025 header.b=joJLl5J1;       spf=pass
 (google.com: domain of 3si7gxgukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3sI7GXgUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

It appears that compilers have trouble with nested statement
expressions. Therefore remove one level of statement expression nesting
from the data_race() macro. This will help us avoid potential problems
in future as its usage increases.

Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Fix for 'const' non-scalar expressions.
v2:
* Add patch to series in response to above linked discussion.
---
 include/linux/compiler.h | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 7444f026eead..379a5077e9c6 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -211,12 +211,12 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
  */
 #define data_race(expr)							\
 ({									\
-	__kcsan_disable_current();					\
-	({								\
-		__unqual_scalar_typeof(({ expr; })) __v = ({ expr; });	\
-		__kcsan_enable_current();				\
-		__v;							\
+	__unqual_scalar_typeof(({ expr; })) __v = ({			\
+		__kcsan_disable_current();				\
+		expr;							\
 	});								\
+	__kcsan_enable_current();					\
+	__v;								\
 })
 
 /*
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-10-elver%40google.com.
