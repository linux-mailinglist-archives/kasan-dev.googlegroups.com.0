Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBH4CY2HQMGQE5L6T3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 21FB349D075
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 18:13:04 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id w5-20020a19c505000000b0043798601906sf33060lfe.5
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 09:13:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643217183; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZWW9oWk79yUGLtQFPpysUTSSj49y1X5hzLyZJaKscdnwmxvxVNnNF/vjaoH4YUn1Mk
         ONlqEOVgqJ6/edJBgRIhBsrllTYJUPwAVds9c90AntEoL4bs0NpPRBrPWBLXKLE9tgVr
         25yGnfVhCZnG5YuOsRALtUSH1sYzGxeQCKe2AJ8oU8PoBsainOqw7RucNc5qNgCFWyPP
         EeXLBWN+S1ups9phaKBzmnkf5Nbjq1chqkaZQarqZdXgCyTrl5dDGaBwnmgc4yNZ1U00
         N5cIEySPHvhzR0hxmvjvcaGO8h4XZLzE98qw9tncDDy6ou07YVNkluUgAmmyepobm44R
         eu1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=IdckQzZ+GzrLO5ervZVFmn1R0Io85GcEvq68Rw9l9CM=;
        b=JblBoF6SmLhXGx/J7WaUiP9OBgPIrfnLCb4qpL9NZlMcL5OszIg4kGm5PSD2A+U4X7
         hWwbWI8FvvWN2PeWXnnW7pNod6GlKnG4BIYPnU22auPAnUo4x+SZrJe+yuEDUxVv/DXu
         srPckl5BcVz0x2b/N1KirFdX2knyfFi1Oh1nVIOu6FuERcYzpzd+h+HBIvBcAiqfEmg4
         M4WeZPLZATT0YZW+OVYz46JJe1f7bzVSaNNgxGK65cOylyfViGgtMNehb8DVmdEXo6r5
         /n2MZibjw31Xj3YvZkKUufYXZzvSV+0HAHry8hGav6b2qxG9EJ9MXHEY7NgwBd9t+xah
         okOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PckkjWov;
       spf=pass (google.com: domain of 3hohxyqukcfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3HoHxYQUKCfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IdckQzZ+GzrLO5ervZVFmn1R0Io85GcEvq68Rw9l9CM=;
        b=GVVA398+j8mmJqgCDsGowqkWNO6LO8JjbTL59jk/XD98bXrAq3I7ACkrKr83ewxw3r
         3C6yCck1VF6B2o3QSnicRua01eVF3i0JwHv5jaUGyHzI0zhfuojLEtJL4vEzdwCh4E+v
         2eYJ8CvKO6UyqOCDm0z/TDCyLmrgah4VeUg10VmHc4SiqLp09zOSSHJflfKGnZ7aLaPO
         7AmpjyxFhYY6Mtlds67kKvxMUB3CnCrpzHyNveBfUEYFdhu207Z3/fJhjAPM4gI62qAN
         xkv1lZtj36BSakQ0O2uvSmdsG6jvMcfxSHVGkYzqZoKxNYLO09WpvtkAPo3qlZTRdpPX
         sObQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IdckQzZ+GzrLO5ervZVFmn1R0Io85GcEvq68Rw9l9CM=;
        b=JhNOs51RnB5A2SZKjNIZpl6L7vo5FC32atrrHND7zaHoHy2npo5STQ0cbUm1CLobQ7
         ZMeyUk+sArRPA8lhiLtUonyjo85ioePefbN0ZZdavi9O/LN0omjkKqwsDJBym1S+mzKy
         RuDf8Aeq+M62oexG6WHF/02y64iKfiQzgt3Ucf+zOF/yby0aluAerkPdoKnnz/jmgGv1
         QZfhWakgwNG17EzC1GNMYgtHwmQg6j3s5OkJpnWxWlGEJ3tY5yzdT3VoAkDXnECPr6jP
         5nDgIwLExYLYE8e603Kixu52PnKNXG8uNngqA7jTOIOE/7aF9bPoVqUt/WDtcFXu8TAz
         B8xw==
X-Gm-Message-State: AOAM530e/Gq6Uf7IH6Z80TvOroSP1wnBvjybD9xcGCdEJnkeCdpaD+wV
	YSf95fmFbjr9SzJf8WTyZkk=
X-Google-Smtp-Source: ABdhPJzxfSqoe5KEblJbeCNyOKAd4D2lmBQBhF/s2M1IphsAECcN8fXGCSj7CQB82pv/RvXcFTgXQA==
X-Received: by 2002:a05:6512:31d1:: with SMTP id j17mr10025700lfe.363.1643217183485;
        Wed, 26 Jan 2022 09:13:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls1469021lfr.1.gmail; Wed, 26 Jan
 2022 09:13:02 -0800 (PST)
X-Received: by 2002:a05:6512:2824:: with SMTP id cf36mr11242300lfb.617.1643217182522;
        Wed, 26 Jan 2022 09:13:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643217182; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRfcOqi+YlOn0kJ3ZG6+7Ib2QuRekey76ic6BCGA5MSjphT48PRmbi4RJqsuPv3uVO
         UvJIvsND78vGm3RaEBn0GaDzgG0866cj5e8bXtT8P4coL1CZxZ66qGk1Clzzeg1rKbrW
         wnTICQmK2RtGUE1iUKpBDr1tQeuHN9h8RMc73b3iWLPXXyGh7qzgVQYLj4wWl310UjO0
         SRbGm/qTOujaL1kkLnLodgC9I5yXT1eHhbU2XnFVflJiSgstYpGNIl1zNgN274cB8i40
         tBLX2vvIsxl3AG9nKza3EnpnDx3KcbjIJ8nOcul+Fe4ETfrpRxiXM4XFyGaj0OJJeBhQ
         WOew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=pbBLINmGHzM6V42XBweXNxOpKFgkK8jWD+m3tGBDCwM=;
        b=bM8lZ2srIBx+vCvhJWoEz49ZmxNKnhHl9fm3VDeg24fgeLCOohznGlOD0DJ8DGubi6
         K0FYlPnOI0eYc51Si8ytUh0WXshl1ncQBKZfJLOACPIAxd3QBDN/Y9LWQJDrcH9F6a/x
         OKoWCScXx+YLakl9AXIx1TPd3n4VPWcnAmGTjFDE13GmrKDBoXrYLfGhfYMsLeW0HXsl
         o7X8HjFHs7Dplm8JusoXSDd9xU/7Go+Vwb7IaqYX0cAV1z/HpzJt4cZ2hKX1mINkcXZp
         UMtNy3/BG+014xlV/ktWvMd8p9X83RBMnLJN0yxQjDOQI+MNZFRhLi3D7FKFGhHtTDVP
         dHmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PckkjWov;
       spf=pass (google.com: domain of 3hohxyqukcfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3HoHxYQUKCfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id q5si758709lfg.3.2022.01.26.09.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jan 2022 09:13:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hohxyqukcfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id c31-20020a2ebf1f000000b0022d87a28911so133587ljr.1
        for <kasan-dev@googlegroups.com>; Wed, 26 Jan 2022 09:13:02 -0800 (PST)
X-Received: from jannh2.zrh.corp.google.com ([2a00:79e0:9d:4:e695:855e:ae74:d6f])
 (user=jannh job=sendgmr) by 2002:ac2:5fad:: with SMTP id s13mr19320668lfe.41.1643217182081;
 Wed, 26 Jan 2022 09:13:02 -0800 (PST)
Date: Wed, 26 Jan 2022 18:12:32 +0100
Message-Id: <20220126171232.2599547-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
Subject: [PATCH] x86/csum: Add KASAN/KCSAN instrumentation
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Eric Dumazet <edumazet@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PckkjWov;       spf=pass
 (google.com: domain of 3hohxyqukcfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3HoHxYQUKCfsmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

In the optimized X86 version of the copy-with-checksum helpers, use
instrument_*() before accessing buffers from assembly code so that KASAN
and KCSAN don't have blind spots there.

Signed-off-by: Jann Horn <jannh@google.com>
---
 arch/x86/lib/csum-partial_64.c  | 3 +++
 arch/x86/lib/csum-wrappers_64.c | 9 +++++++++
 2 files changed, 12 insertions(+)

diff --git a/arch/x86/lib/csum-partial_64.c b/arch/x86/lib/csum-partial_64.c
index 1f8a8f895173..8b0c353cd212 100644
--- a/arch/x86/lib/csum-partial_64.c
+++ b/arch/x86/lib/csum-partial_64.c
@@ -8,6 +8,7 @@
  
 #include <linux/compiler.h>
 #include <linux/export.h>
+#include <linux/instrumented.h>
 #include <asm/checksum.h>
 #include <asm/word-at-a-time.h>
 
@@ -37,6 +38,8 @@ __wsum csum_partial(const void *buff, int len, __wsum sum)
 	u64 temp64 = (__force u64)sum;
 	unsigned odd, result;
 
+	instrument_read(buff, len);
+
 	odd = 1 & (unsigned long) buff;
 	if (unlikely(odd)) {
 		if (unlikely(len == 0))
diff --git a/arch/x86/lib/csum-wrappers_64.c b/arch/x86/lib/csum-wrappers_64.c
index 189344924a2b..087f3c4cb89f 100644
--- a/arch/x86/lib/csum-wrappers_64.c
+++ b/arch/x86/lib/csum-wrappers_64.c
@@ -6,6 +6,8 @@
  */
 #include <asm/checksum.h>
 #include <linux/export.h>
+#include <linux/in6.h>
+#include <linux/instrumented.h>
 #include <linux/uaccess.h>
 #include <asm/smap.h>
 
@@ -26,6 +28,7 @@ csum_and_copy_from_user(const void __user *src, void *dst, int len)
 	__wsum sum;
 
 	might_sleep();
+	instrument_write(dst, len);
 	if (!user_access_begin(src, len))
 		return 0;
 	sum = csum_partial_copy_generic((__force const void *)src, dst, len);
@@ -51,6 +54,7 @@ csum_and_copy_to_user(const void *src, void __user *dst, int len)
 	__wsum sum;
 
 	might_sleep();
+	instrument_read(src, len);
 	if (!user_access_begin(dst, len))
 		return 0;
 	sum = csum_partial_copy_generic(src, (void __force *)dst, len);
@@ -71,6 +75,8 @@ EXPORT_SYMBOL(csum_and_copy_to_user);
 __wsum
 csum_partial_copy_nocheck(const void *src, void *dst, int len)
 {
+	instrument_write(dst, len);
+	instrument_read(src, len);
 	return csum_partial_copy_generic(src, dst, len);
 }
 EXPORT_SYMBOL(csum_partial_copy_nocheck);
@@ -81,6 +87,9 @@ __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
 {
 	__u64 rest, sum64;
 
+	instrument_read(saddr, sizeof(*saddr));
+	instrument_read(daddr, sizeof(*daddr));
+
 	rest = (__force __u64)htonl(len) + (__force __u64)htons(proto) +
 		(__force __u64)sum;
 

base-commit: 0280e3c58f92b2fe0e8fbbdf8d386449168de4a8
-- 
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220126171232.2599547-1-jannh%40google.com.
