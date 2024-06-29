Return-Path: <kasan-dev+bncBCT4XGV33UIBBZXD7WZQMGQEF4U226Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id DEFF391CA98
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:03 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-25c9cf90f74sf1399459fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628262; cv=pass;
        d=google.com; s=arc-20160816;
        b=arlz5uCYlwkmWltyfFkLlGcp8h8THIBW5QWrBB+L9DA+rgtlTZkt4FXr6CTmPRAF7t
         IpbwsBTPeMM2vitZhCnKLZoEl1fLgWEMxSLmr53XYR0DtOctFxkal9mUnHHv2PnSueN1
         jThlJzxC0CXudxGwumcTjm9k3fi6cUnayiJ+VW6anUX6tf1ClvMJ9lyD2cS5dAaTfpdT
         zntDhpn/4uVouqgKiUFgKi3B3In/tSQmueyLnJwZypbpeuGvtQy+tuiPKf/2V5icDyFy
         5mXE2hlB1VN9m2J/Prb5LND1wnLgcLYmnSw3hlvG8r+4hlu+eZT/6CbNTr3HmXoFWUf8
         aakg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=KzYPE7bhTrSSTXg+1tT0SxTRDTiBQNZwd6eSBqwiT38=;
        fh=p8skWc0tgdZEIN3FKhDkdSiOktf2o6AWq47XuRv1FjM=;
        b=zGAMzhElA0Ev1SzHA/nNGXCT6dZRzO/SYmJHodKz5E7vs7lkT4BcgrtUZodQvnLKMK
         kWPKZVfHzy2TwOguPsS0szrgyIEJ6wv+50TUi/jgNiB8j5gBM9uGA3m1SdTsOq/DfADP
         Z/idIl/jKkJ4h3Tu2q6LjEKO55acC9YwBiKAAvsvJilUC7u9Qe+plPcNMgWmT/E3lNzR
         0OR3KQyuI5vM5OmypBirO5opyulGJ5w1b5eKaywjV0UvabdBBleHzyCePMZvibLAeGQe
         1eDljSlS3VZbU796GmOrdABej1NvGnvcslM3IsrRg6iGjHsq900xpIStewCZ88vqLOZn
         wvpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=iktIPeYh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628262; x=1720233062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KzYPE7bhTrSSTXg+1tT0SxTRDTiBQNZwd6eSBqwiT38=;
        b=RD/5I7mgNFhifKHwAJjV5mp9DhzC/sC4YIRaaFwBoBSCgPywTVESU28ctWA1ppj1mV
         xtbl5viMO+AvB655eV+4T5VkPhZh6tGm8UjhxNma29QrwIGSFGMYB0HVkSPnyiqmLIDV
         VINc0K3iNkB31NahkjpCy6Y8MhpbTkTdtCEIz4KPpoKyb5fAP8AOxll4e9mUk2TLciTg
         Ln5SPrzIDxZlmvZQh7uwqTQwyycTx6nvmMdA9tX1dR6bj8E1tXWbdxkDNOT2S3XX11xJ
         7H2qprGSZayZ9koXlO0D2x2+SRF+HYi/gz4NsOd4ojenG9L/M9JjpEbkEuA0Z6udkwIy
         HlVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628262; x=1720233062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KzYPE7bhTrSSTXg+1tT0SxTRDTiBQNZwd6eSBqwiT38=;
        b=Am8dHEzcHlW8cyw2yM7qoFYjBXRFBKT23ysPVeclpWtrH3jXD9eKEM0BEb1DEGs4gP
         YtXNETSbuF7ivCb9QU+rxV1LwqQv4kNcx1yDnv5zVO8/4vRRknnsfX8DEKooKq17MKXC
         GuoTnByM8WPveydFSwdP+Kdj4KIFYjCvWlceZrnhl03dhOpdgR6hQXt9SZjvlEPVl9Kr
         VKTq/ROwqqkglF1e2d2uYYxYeK+PU5G8yQrVTc7WswbvUz9aajAcy1FYbYF2+TLp2sqe
         ffPN3jojPzEsvQX0c4lM+eEVcfXWW+5nItobf02sbCGqKSi+6POPVCC0tRGa2TtesdHs
         PPGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdyUcHmHKqMvGhtk5QosznYVecgjWn6/MvLLbv40/Wi2YOnQ2CBQixM0wJfr4tibx9aWP67IFcGwlRnWtltstdueVvAWvl0g==
X-Gm-Message-State: AOJu0Yxc9N0oTkd67CJJOkrqAtkdFk/fYnXlGmPUlpLQVZjyvJk/5ID6
	rRMsqz7jPOhPwZlDJu/jyv3hgKFQchvI1d4mjXavjsjRcCxp7eLj
X-Google-Smtp-Source: AGHT+IFvE+0eG2Ms7tjEHKrK9GjQ4zziLJaozn3E+KoEptDQ7PeI4rku/jaEhqh/JdCR1jO7yZWqHw==
X-Received: by 2002:a05:6870:9a8b:b0:259:89fc:db65 with SMTP id 586e51a60fabf-25d06eb7bbdmr18297814fac.50.1719628262659;
        Fri, 28 Jun 2024 19:31:02 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8202:b0:25c:9eee:583a with SMTP id
 586e51a60fabf-25d925fd2f4ls1227363fac.0.-pod-prod-06-us; Fri, 28 Jun 2024
 19:31:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJaK9cN0K96ibTVw+5nKu6HfTW3j/xB3TTOJWiJlui34/U2AlChQmli6Y/FYpl7LCpnEzUsWd2br+ihcMiqOv+sbB5AL00/845sg==
X-Received: by 2002:a05:6870:a3d5:b0:25c:bb8b:85bb with SMTP id 586e51a60fabf-25d06c129admr10935827fac.18.1719628261671;
        Fri, 28 Jun 2024 19:31:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628261; cv=none;
        d=google.com; s=arc-20160816;
        b=1FEPIq6YJjUp6oWsHbiNLGLDrqeLRMEZjHeHfdzFy7sgEcrG8wsQMY9W1Ioxfk1YuI
         Pqq0qmya7v64z0OiRUBM8y2qu0zcayAUM7MdPv/hOwzmoeIu+2UEBFL0ufp9CwsqHTZw
         w7dcUzZzRy8iPHh9ddGTTHvG9W5h8t+h7CmfbUTPHROaAfDdINE9t83ybkD3P4ts9CwD
         Hyj4+i/TPwbZrTOle2lUUQKa94lJt3uNsy1sf6xEfcLoeC57Y0YDA+Ug++ToK0/49GOS
         t967hh9tQkZEBaOvWwUJIOYqrXeNTM+Nd1bXuWcrTp9VJMxXMt+dH096YflvcWLJJ/xn
         zUaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=bTjkDrQh1jj4QJRij98bx844NYFpCR+vzQaSEMPXA/I=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=HPn3nqhcIgY6b8j6EiRAkD/nqosjNhWfjIbOx+YUevkOOBbwGiW9WGCUoUTQ9JzjHL
         NIHUEs52+KlJqdmGMlGAiuqkXrK21j9dk5mZNS6Xx8R2WjJXcXzdQAo7Xg7/97sFSwyg
         /aUBYuUWqCr957jQHPLbT6dxTHfDUYg1tUeGPDlMGdfbhHeYZ9bjPLaDFedvV248HSrM
         hObHX3HXDHE664osmlxRDQ+eo5CXA+rw2V0TZA2jQIdEUR60HVdfqu8kqzuCWRfvV6lg
         l3ZlhqKV21dtFD6ZXRKkye2SUpqHIlbbufHWbHpOGRefq4QiN29IDuEqwwC6y8PeawNf
         zFjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=iktIPeYh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25d8e2084d1si194120fac.2.2024.06.28.19.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 71C20622B9;
	Sat, 29 Jun 2024 02:31:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1A511C116B1;
	Sat, 29 Jun 2024 02:31:01 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:00 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] lib-zlib-unpoison-dfltcc-output-buffers.patch removed from -mm tree
Message-Id: <20240629023101.1A511C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=iktIPeYh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Content-Type: text/plain; charset="UTF-8"
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


The quilt patch titled
     Subject: lib/zlib: unpoison DFLTCC output buffers
has been removed from the -mm tree.  Its filename was
     lib-zlib-unpoison-dfltcc-output-buffers.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: lib/zlib: unpoison DFLTCC output buffers
Date: Fri, 21 Jun 2024 13:35:04 +0200

The constraints of the DFLTCC inline assembly are not precise: they do not
communicate the size of the output buffers to the compiler, so it cannot
automatically instrument it.

Add the manual kmsan_unpoison_memory() calls for the output buffers.  The
logic is the same as in [1].

[1] https://github.com/zlib-ng/zlib-ng/commit/1f5ddcc009ac3511e99fc88736a9e1a6381168c5

Link: https://lkml.kernel.org/r/20240621113706.315500-21-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 lib/zlib_dfltcc/dfltcc.h      |    1 +
 lib/zlib_dfltcc/dfltcc_util.h |   28 ++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+)

--- a/lib/zlib_dfltcc/dfltcc.h~lib-zlib-unpoison-dfltcc-output-buffers
+++ a/lib/zlib_dfltcc/dfltcc.h
@@ -80,6 +80,7 @@ struct dfltcc_param_v0 {
     uint8_t csb[1152];
 };
 
+static_assert(offsetof(struct dfltcc_param_v0, csb) == 384);
 static_assert(sizeof(struct dfltcc_param_v0) == 1536);
 
 #define CVT_CRC32 0
--- a/lib/zlib_dfltcc/dfltcc_util.h~lib-zlib-unpoison-dfltcc-output-buffers
+++ a/lib/zlib_dfltcc/dfltcc_util.h
@@ -2,6 +2,8 @@
 #ifndef DFLTCC_UTIL_H
 #define DFLTCC_UTIL_H
 
+#include "dfltcc.h"
+#include <linux/kmsan-checks.h>
 #include <linux/zutil.h>
 
 /*
@@ -20,6 +22,7 @@ typedef enum {
 #define DFLTCC_CMPR 2
 #define DFLTCC_XPND 4
 #define HBT_CIRCULAR (1 << 7)
+#define DFLTCC_FN_MASK ((1 << 7) - 1)
 #define HB_BITS 15
 #define HB_SIZE (1 << HB_BITS)
 
@@ -34,6 +37,7 @@ static inline dfltcc_cc dfltcc(
 )
 {
     Byte *t2 = op1 ? *op1 : NULL;
+    unsigned char *orig_t2 = t2;
     size_t t3 = len1 ? *len1 : 0;
     const Byte *t4 = op2 ? *op2 : NULL;
     size_t t5 = len2 ? *len2 : 0;
@@ -59,6 +63,30 @@ static inline dfltcc_cc dfltcc(
                      : "cc", "memory");
     t2 = r2; t3 = r3; t4 = r4; t5 = r5;
 
+    /*
+     * Unpoison the parameter block and the output buffer.
+     * This is a no-op in non-KMSAN builds.
+     */
+    switch (fn & DFLTCC_FN_MASK) {
+    case DFLTCC_QAF:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_qaf_param));
+        break;
+    case DFLTCC_GDHT:
+        kmsan_unpoison_memory(param, offsetof(struct dfltcc_param_v0, csb));
+        break;
+    case DFLTCC_CMPR:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(
+                orig_t2,
+                t2 - orig_t2 +
+                    (((struct dfltcc_param_v0 *)param)->sbb == 0 ? 0 : 1));
+        break;
+    case DFLTCC_XPND:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(orig_t2, t2 - orig_t2);
+        break;
+    }
+
     if (op1)
         *op1 = t2;
     if (len1)
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023101.1A511C116B1%40smtp.kernel.org.
