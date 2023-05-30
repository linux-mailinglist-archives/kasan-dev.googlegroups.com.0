Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNPM22RQMGQERJYFHBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8217158C7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 10:39:18 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-514b19ded99sf325775a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 01:39:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685435958; cv=pass;
        d=google.com; s=arc-20160816;
        b=YP0TCzHAqAhUKkK4EF7gpmXH2llgT3IfGs4PLsC36xSe1LCYIoO4NoGVeQaGNvb2Jj
         m5PGV/SU3kiX6GkJOCccR1uRwswTpCYhe8MpMOlc08rgm+zBKya1TNFMNynd4yS/fU/c
         wPXXYoeq+vO9PuFzoa52D2kQ611VAeQFwTdNhmTfSK3ZJPgWbEH7XMNeMGNiI9UqRI3W
         aoVcMtRYXtrNb+BH04j1PF5q5tlkjvVtmpbYLxPiJZ/aStBY3AqnA2ZUH9Fs0YkV50ab
         UJIALmOLZw4+7545y8Cp9Xi5IJ8FAIYbAejoHXpVnfpAewh0tY2Mhzc0gnOmOCKjBGrs
         v96Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=ODJioy5P5Q38g6tOJcODOl0rje5oHmCMcel+dEqXSEM=;
        b=rjf4Awl5ZPvxJVf17tJNOECZCcFaRqFn8uqYNLWELuhbTbbcn/cyTPF7WxKKhaBF4X
         Z65p//CM7nTrw4zHbvHqvDDM8aiDd2mjWhxi8yqTX31snZw/ETSbJbiyPimw8aUwsjNx
         b2jLDQTQQX5n2eiMpaqdGMaQj34S597pm+oufpbmiKhk4a/NTNDe39Pe2G0NvV9gV0YX
         7MwnNc7tWlGKKiolLciVTQGByTm3K/B/GPUj3+Pqb12yMolREABPYayjWzW8qJ+rZYz8
         pzlapnL383kyEqzHmdr5R5a8XZlY8EUzxVPkqygTHEnhqCtPeUoFT2TkLBrL2W8z4DYQ
         oH6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Qr8jpDkX;
       spf=pass (google.com: domain of 3nlz1zaykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NLZ1ZAYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685435958; x=1688027958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ODJioy5P5Q38g6tOJcODOl0rje5oHmCMcel+dEqXSEM=;
        b=T0h1IXpzwZrIw9u3ouoEFGl+GdH+oBFvoFiofp04PSfnX6btJIXeQLNI694CBoipZ7
         V/TXVmcCO0h8nbREu7FsrrO/SSPKCVOlcFkwT3c4ic8b1bmpQ33Umh5iZHBcbvbNk7ah
         znTZd5oo6AmcQ64KxH1tR/LyTS6DCoXbAnUBnnkaxE/gZFfMWD7ytT6b+o1QuMnDyNrS
         LZ8dLZPV0W8X4SFGiFjpPZ28gaYsXAFu8Kg4+D8eV/v9zQ8dOwKnDIROBHMfgi1QyjHi
         RLAVldDowB0ZBr49nUFdde0WrAHVFSLVeJ4DIrEJ9p16SwNI9m+tiQ3ChCUWLfRP+2Ao
         vo2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685435958; x=1688027958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ODJioy5P5Q38g6tOJcODOl0rje5oHmCMcel+dEqXSEM=;
        b=YmOd9pP/9LASn040LpZnWHAJzk+f+hl5/4rmXYb4RfVWBVP1H3snmNrb8kePnMVFZO
         KB7W/rtb1aqX0ho5cVrRFbs2QsVKA44AEHoAg/FWg2c/Yx/M2lM44+BfSBYRGUIZQxL7
         aAQOIBhQxv9CnZc0UHQKNrrwRO2Q2OUvYtFClsA5vAHbWIS2hMx4PpcXUTC3vfoxsS8z
         I7+6ldgbxQnTBu+2V72cuBYmOv40ySL2rwqPJsycM/GpT0Ka7hS35cjvhTAqfd+ZDCTv
         1UXOKMg0dr9N22pusF+glySHPrjun0f8UoYKBJnwwvRh3FYbvDMjwymEfBdVoXWWOYc2
         ZJXA==
X-Gm-Message-State: AC+VfDwPCm5T65X6L8vumQERWYbIFtxieWI8PbvpPAlVCKsSpQNNZkMK
	/IYZTb3UnjsPE3YgkKwqmQs=
X-Google-Smtp-Source: ACHHUZ6GEU8pqeJMfdW5Ve9kqqhTcX5RibKAflrQLQLIEygxiIVh60uVmIPir5C1ra7ZPxUljy6pAg==
X-Received: by 2002:a05:6402:1352:b0:504:b177:3ef3 with SMTP id y18-20020a056402135200b00504b1773ef3mr1241214edw.3.1685435957570;
        Tue, 30 May 2023 01:39:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:656:b0:514:a0b8:647d with SMTP id
 u22-20020a056402065600b00514a0b8647dls160062edx.0.-pod-prod-02-eu; Tue, 30
 May 2023 01:39:16 -0700 (PDT)
X-Received: by 2002:aa7:dd10:0:b0:514:9c7c:8a37 with SMTP id i16-20020aa7dd10000000b005149c7c8a37mr1179956edv.28.1685435956316;
        Tue, 30 May 2023 01:39:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685435956; cv=none;
        d=google.com; s=arc-20160816;
        b=rwPP7Ewn82LtRpVXcXlc1WrvQA/99si70deOFvh/CwP87K6aA2XYV6oFhRZU0z2DXn
         PxVm9n2NZgr3gTYRSPSZqoW37e5VbtrcrwpfA0JaEr5YwzfNO0FYVKKX4GtiVGCH+uCr
         UEZWssLDqydej9dGv+Es7u8Eeq8bKns4vPoe4eUcL6WZgNigU/X5M4TCH/pdgSIurl28
         q2/9hwcRwec69p9HUOjRoB4W453H1nvH05w3+WgXteUJdGiHIPzkWTmMb+FvdV/+WfN0
         VAcT/PyNVafOwsmpeyDQg2tD/3pBl5cWxO0+E7JEq112qhyx6iX6kWXngUrzuP1z9gLM
         D7GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=d2gZVOqgM2bnB8NENsAMpjub1Q/xoX1pCqU5k5h5AWY=;
        b=FW4mer61lc0G823Fe+uBjvtwrm5VntLqJgIs47eGchg2iZPB0eVQi5KlRS3qiT3WMG
         1EM1vMl28rKhib7klIiDU4tteHlJMJKT+Jrw+nWtQHW3oVTDFeX6OQmOFFiDnHgnvHll
         mH25qn5d//+/2lMcnwI9mGYmeY1GL4gzDlBu3v7CrgZ8DUv02BKbrPSNNw35EwuVuX4H
         DGX9DzpP2K0B1sBnoSHXT36+1xh4s8BgVhj87O90SeAGduuPKmDceKovMwPTE+pjAwE6
         3QBiClCN37ni2pWA6sh0PiLPLT2k1Sr9+6EnNoT0HoWsfnMu95c+a7mTRbfo8ziu+moT
         ystw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Qr8jpDkX;
       spf=pass (google.com: domain of 3nlz1zaykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NLZ1ZAYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id er12-20020a056402448c00b0050bd0abf2b4si638136edb.3.2023.05.30.01.39.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 May 2023 01:39:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nlz1zaykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-506beab6a73so4100109a12.1
        for <kasan-dev@googlegroups.com>; Tue, 30 May 2023 01:39:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a4:5738:5a7f:a82e])
 (user=glider job=sendgmr) by 2002:a50:8ada:0:b0:50b:c4f7:fa5a with SMTP id
 k26-20020a508ada000000b0050bc4f7fa5amr529352edk.3.1685435956071; Tue, 30 May
 2023 01:39:16 -0700 (PDT)
Date: Tue, 30 May 2023 10:39:11 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.rc0.172.g3f132b7071-goog
Message-ID: <20230530083911.1104336-1-glider@google.com>
Subject: [PATCH v2] string: use __builtin_memcpy() in strlcpy/strlcat
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, andy@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, ndesaulniers@google.com, 
	nathan@kernel.org, keescook@chromium.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Qr8jpDkX;       spf=pass
 (google.com: domain of 3nlz1zaykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NLZ1ZAYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

lib/string.c is built with -ffreestanding, which prevents the compiler
from replacing certain functions with calls to their library versions.

On the other hand, this also prevents Clang and GCC from instrumenting
calls to memcpy() when building with KASAN, KCSAN or KMSAN:
 - KASAN normally replaces memcpy() with __asan_memcpy() with the
   additional cc-param,asan-kernel-mem-intrinsic-prefix=1;
 - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
   __msan_memcpy() by default.

To let the tools catch memory accesses from strlcpy/strlcat, replace
the calls to memcpy() with __builtin_memcpy(), which KASAN, KCSAN and
KMSAN are able to replace even in -ffreestanding mode.

This preserves the behavior in normal builds (__builtin_memcpy() ends up
being replaced with memcpy()), and does not introduce new instrumentation
in unwanted places, as strlcpy/strlcat are already instrumented.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/
Acked-by: Kees Cook <keescook@chromium.org>
---
 lib/string.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/string.c b/lib/string.c
index 3d55ef8901068..be26623953d2e 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -110,7 +110,7 @@ size_t strlcpy(char *dest, const char *src, size_t size)
 
 	if (size) {
 		size_t len = (ret >= size) ? size - 1 : ret;
-		memcpy(dest, src, len);
+		__builtin_memcpy(dest, src, len);
 		dest[len] = '\0';
 	}
 	return ret;
@@ -260,7 +260,7 @@ size_t strlcat(char *dest, const char *src, size_t count)
 	count -= dsize;
 	if (len >= count)
 		len = count-1;
-	memcpy(dest, src, len);
+	__builtin_memcpy(dest, src, len);
 	dest[len] = 0;
 	return res;
 }
-- 
2.41.0.rc0.172.g3f132b7071-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230530083911.1104336-1-glider%40google.com.
