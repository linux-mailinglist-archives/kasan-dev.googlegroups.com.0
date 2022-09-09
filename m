Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDO35OMAMGQEDAUYTAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 00F495B3050
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 09:38:54 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id d16-20020a2e3310000000b0026bdcfbf9afsf206558ljc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 00:38:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662709133; cv=pass;
        d=google.com; s=arc-20160816;
        b=UsrAo/fMq33fADzex2de181SJC+ROtGFX7b7c+JzeZa2CLr4AzMb+Zcv6cGH8ZlsVf
         F9tMICVaE5SqeTRH0UsT1Tuz0LF62O9qtwPFb4JivxnWqOEO1nUx3KCLyldOkTTVModL
         7nhZFLWqCtmDnPp91jHCKyMN8Z0qxrwoqJc+hewHkSVTM9Vr6YU+Rg+vEw3KSZ7ONLCE
         e/sIR8/2jskJFYo/OOOZekXegQMZSn3VXCwz1ENt4731aS9eOsm71kHT8DKqVutdpSlu
         tWKWk7KgSPGVM/PE7tt+RrLTsgFSPBtFBUAqz9Gl3Kup7QIhd0oCPul4+wt4mwDg4E3G
         X6Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=Z+GCxlg4Mgy+35Aq6d+1+bgwNozFQP97HfFngyIQflk=;
        b=sATD9WnUEwYWnssqjUlF0Mw9Yw3NYCiL9fSA1szJkhl8Le9TbbhjKuSD17gKdd+FJn
         LU08hYDavm8yprecNVvX9Bydhuwa43bk5G+RS/l6qDxJ3WhQx9On6lZ8ob8mUZFmXzLD
         9Yc9aHZTPUmBJpmZ5at8lF2NRvC1zQ/ekWnRjEhJqAnTTS9wtbKaNs8fNZ2HRF7DRAiE
         gY4GtNzPvP5H+5wW/BF08Ndpcm6f0yjFLcb+8H4Srgb/4sEsrFnTVOqdgEernw+jIA59
         taVy4lzIP9RcT7Z5n6IjDIOCXK87t40+kutCMfS98/7zFHaTBx3ATy3TB9OV1SDDd1fY
         Dveg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j+UIMYBT;
       spf=pass (google.com: domain of 3i-0aywukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3i-0aYwUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=Z+GCxlg4Mgy+35Aq6d+1+bgwNozFQP97HfFngyIQflk=;
        b=Bx8y83cvjqxfXtxfsibOBXcNoysF6SxyEMBbbffRmTJmLioPOjlgoN+adAe5XDqM3p
         OMA3S2KxTDcJplYkH6CpGr3tdZfYWC9Wb0jHsGfM7D2MesT8cmDE4zAiWwnrLfdPHleX
         hnYAO2fnEcT56WDz2hDJwq9yHrRkv7wjqCEMP1djSXl2NrhjRyCyCDsTAX9dp1HVtcn9
         CTfnRKeetFKMhF9RBcynONZlP6PoBa/X9/ATXJYyL21PxddWoI5YRnx6bPRA75jBSdZV
         e5gv1KhHQ9osX5hY+SK9f/tEOXlPc5vCl+hpU0jYe3spJkT5O3SOYact7L6rCg1JmL5E
         eNCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=Z+GCxlg4Mgy+35Aq6d+1+bgwNozFQP97HfFngyIQflk=;
        b=5n052T0KP7pfNW7WT7pzYmJquyjd7Z0sZG+9CzqveWB0EFe3Sx0PU/MXdDvUKE5VHr
         oTFstau3DGM10GoQz7CHyb6T/tWFwJtfln7Cg8Iw5PvGAKbOhtUsviepKNW/QTxjz1fE
         L/RBNuOe2HWqdvVystXd6YGeC+3SHvvm62sRPeXmmin6man+2w9j0Dx7ENY4uaoe6l2H
         5FENOigthFiLhl/fQN0/u9W/1VROkTMBXE4Np7B4epZEilDxElXbSLpjQbcvT2gA635G
         fS8/zYRN9YQRojYSDLOuBJV7UXOV/iHUqxXATI2EoyyK/CRQ+QEfjtlqMdWo5/FBk5YH
         4xqw==
X-Gm-Message-State: ACgBeo0b+mqmrObx6yEoylDqcjTtwfQNocqA4R2RLr0BJavvkVXK3JkF
	3+p8BmkmP5fxQXXarINYrgk=
X-Google-Smtp-Source: AA6agR6tY7AMadm4zXJ+P58euTrGC9Iyuh6PGtKByyoiR4wd0Ow8cSPGOvs9iU+BLl3hzGLZ7fLSZw==
X-Received: by 2002:a2e:944c:0:b0:263:fe39:4a91 with SMTP id o12-20020a2e944c000000b00263fe394a91mr3768921ljh.311.1662709133263;
        Fri, 09 Sep 2022 00:38:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860d:0:b0:268:a975:d226 with SMTP id a13-20020a2e860d000000b00268a975d226ls600761lji.7.-pod-prod-gmail;
 Fri, 09 Sep 2022 00:38:51 -0700 (PDT)
X-Received: by 2002:a2e:9a97:0:b0:26b:3f4f:cb90 with SMTP id p23-20020a2e9a97000000b0026b3f4fcb90mr2406398lji.137.1662709131748;
        Fri, 09 Sep 2022 00:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662709131; cv=none;
        d=google.com; s=arc-20160816;
        b=zZXOoQVsp5V0aqlK967k04ud+o9h0JkpKJI+Z+y175+VZ9RhwbjpHjqokJaKM9Ra8g
         MD6sbUUhJ2VrntIv9EQdO75k5gQnEZrX5XlwhsT1V9KUBItiwcbBxYhKTAtP85daQIpj
         sSRgpEyeFhVVT6d0s3coXjAwYc+llvDdYCBvs+EX/iEjY8ELDK+3GEEiIMKMbfgp3Rc9
         fCnL3nPW7j+UP7qIN0eP95QMHcVh4dy2M7/QbBw3hs2SNCX+hgKHtr8r9/Uee7ZOnABT
         dKK4FonjlRa3qqQ4zeQfLr9bf0vtG7yEpzpotUkGMVxUBsnWl0acfyb5+Mm6VJl8fN+X
         VUhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=ZgjuXiR7GOoWQwHIqm/Zq+w7cYIxur6W3viv+dY7RH8=;
        b=ukhyFtTTdTrYoYLVaoaNNvUGt0P7cGdtZfcVSMSx4l4mTLwKP1pddeSyMMkNr6Kaqn
         6rPNYBr0OakNI5Q3p03PYpYccpcMo06R9FdAPcX7/HLSa1ILqtp2G7VH51kijSNJcbK+
         yWx2HyZXo7dJbSxpK2B6I47G5lvcZ3KrGOml5KACLl0cnesmWFDbNQT242sizAm45hpw
         TU/NCPqQZnvG+5lcyBwCa56K0GaRSqgbr960VP8ska3ygWBRAzeQLdi8GnnZdknUDpfn
         Fa8V5BsRBhAIIttMCScHx3KN6dAUsispw2UAKbLwVUT9JfoU5Up+VA3kPE50MJG44sJk
         DogQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j+UIMYBT;
       spf=pass (google.com: domain of 3i-0aywukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3i-0aYwUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id d10-20020a056512368a00b00492f1480d0fsi44875lfs.13.2022.09.09.00.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 00:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i-0aywukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gs35-20020a1709072d2300b00730e14fd76eso575039ejc.15
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 00:38:51 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1d1e:ddcd:2020:36c2])
 (user=elver job=sendgmr) by 2002:a05:6402:27cd:b0:44e:c4aa:5ff with SMTP id
 c13-20020a05640227cd00b0044ec4aa05ffmr10390086ede.193.1662709131149; Fri, 09
 Sep 2022 00:38:51 -0700 (PDT)
Date: Fri,  9 Sep 2022 09:38:38 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220909073840.45349-1-elver@google.com>
Subject: [PATCH v2 1/3] s390: Always declare __mem functions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=j+UIMYBT;       spf=pass
 (google.com: domain of 3i-0aywukcfawdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3i-0aYwUKCfAWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
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

Like other architectures, always declare __mem*() functions if the
architecture defines __HAVE_ARCH_MEM*.

For example, this is required by sanitizer runtimes to unambiguously
refer to the arch versions of the mem-functions, and the compiler not
attempting any "optimizations" such as replacing the calls with builtins
(which may later be inlined etc.).

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 arch/s390/include/asm/string.h | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/arch/s390/include/asm/string.h b/arch/s390/include/asm/string.h
index 3fae93ddb322..2c3c48d526b9 100644
--- a/arch/s390/include/asm/string.h
+++ b/arch/s390/include/asm/string.h
@@ -20,8 +20,11 @@
 #define __HAVE_ARCH_MEMSET64	/* arch function */
 
 void *memcpy(void *dest, const void *src, size_t n);
+void *__memcpy(void *dest, const void *src, size_t n);
 void *memset(void *s, int c, size_t n);
+void *__memset(void *s, int c, size_t n);
 void *memmove(void *dest, const void *src, size_t n);
+void *__memmove(void *dest, const void *src, size_t n);
 
 #ifndef CONFIG_KASAN
 #define __HAVE_ARCH_MEMCHR	/* inline & arch function */
@@ -55,10 +58,6 @@ char *strstr(const char *s1, const char *s2);
 
 #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
 
-extern void *__memcpy(void *dest, const void *src, size_t n);
-extern void *__memset(void *s, int c, size_t n);
-extern void *__memmove(void *dest, const void *src, size_t n);
-
 /*
  * For files that are not instrumented (e.g. mm/slub.c) we
  * should use not instrumented version of mem* functions.
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220909073840.45349-1-elver%40google.com.
