Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNP642XQMGQEWJOUZEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id D9EE1880277
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 17:37:10 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-430938ff8b8sf53873601cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 09:37:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710866229; cv=pass;
        d=google.com; s=arc-20160816;
        b=m02eC1QL9wgCYYj6Xm/c/2eDp274r7SdafqG/3aNjMK4pkquIQasBwxjPKY63QUpmp
         cvNny5oFVLSSGmwUz7AZormqnTbDEwTvavsuN56lZyzxH09L5RW1l4zqVnY0arNJb7dG
         hT1kMzErAv5qt29VqQ/ivAMpInQZcfH/uXAWQJ8s5jiu+jDsjG37BwZvQq5P+VwVe+8f
         LoVjazrJrBNDzpmlgwCsogWwXfcOV6iSk97kcJRTZKFiyf0/27p6yoI7faB4A8S8Sqvi
         g9teBujnFItI/jb1TH2LGEx2s0UEx15wag3yhGqSc9W5GQpAzlO8CFPQeZ9MhJHkHIuO
         as9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pTWu0jPjMqA/MTg4ydfyhyT+A2a/aRdXhop/axO+XXQ=;
        fh=rUJzrE+megiO+P8F715f/UaFc+6c7F98DTiaX7fQYS0=;
        b=S0RqnaTfP+r1ii8fVOY77z67gCQq2CdmloNRPoarPxK6ay2DEHyT9k5c7TctQ+bz4H
         TIkOpjCR5BworrF4NI7syiWcGoEx1++HFkI4TmBKZzdHGJoum5QjZim19dBdmk6Zt5dK
         DZw9veFhcOSWre9UCh9aSzL/dJtY8A0N9tzpAzdMDQ+mb8NJCwt+4woXMwEthX7TfMtw
         ikNkD2pzk3U7On1GLm0G3u1RWEXaR8BMgmLGC2XamuvIrcYCjLjOBsz4YdRJA+ooNsHX
         TIDEVHOUNsR82ysaZ19vQqosNormkRCv77wSYnqW2fO2mBfUN6UNcPJ4np1FYGN0brbT
         cYkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vCcRN6pj;
       spf=pass (google.com: domain of 3m7_5zqykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M7_5ZQYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710866229; x=1711471029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pTWu0jPjMqA/MTg4ydfyhyT+A2a/aRdXhop/axO+XXQ=;
        b=JiX2MgCWwXNGKreAiyL3hEFOJDOXcOK16UlAINyyzhNfbMPkHIcz5e2ACir3H/ddzl
         FHRSHS5IqCFtgelh09TOdjrZhzc5LtxrsIHDtzmtHPPEtN5v1iNnDdOUVkz/xJrvOJTX
         /UdUrx9WWurKAmYNQvKZxY5fxX9tLGvCgGlaDjmTc9yAyZMerEhjpUSsPH65wpPwGLpF
         32T1ifSrlfRZmNYV0K7MyM/6Tr8enLjv4NzdLaDXIEbmScigY3gT6P/+VCgzST5MU8or
         XD3t8ZAQs+64E9ehiASvmnYwqYsEG2W8fMDJ18vD0A6oKKCWA8iFQoI4yjR0pz8Vum88
         fILw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710866229; x=1711471029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pTWu0jPjMqA/MTg4ydfyhyT+A2a/aRdXhop/axO+XXQ=;
        b=iI5PiRUtQMG0Al73j5vDFphkscCx6jCCvo64q1I/ujFaZqqbR7Vd768MYV5xicXxhq
         mhnD5cBSOdvHGXAnFP4lihgJdufbaN0K8Ef+qcqYzaco1P3EJMoWLOOOKU/qVFpChXXz
         XTBpAXwXkaVcB78Qmm3YA1HbkRny86Zu6phDj8sXb9TzJXR482kf8KMkqhby8Mdem0uW
         8HUySTKSPG9rlyjrCkpCmTLDYL4v9lF/T0zTMwQd3xh+KqNn5AklIzgPCO+/sGu25ocX
         Mod17xiEanxxbm6Vv3KiEMQoxtYmNvbuxjareoNuOwFLo8LKfvFR7bBue0uysB5pkRyN
         U51g==
X-Forwarded-Encrypted: i=2; AJvYcCUkL22h1x/1Hbqb0mroWWqN1eJXL7W+g4CfFE7KZ/KA0D+JvWL5Zzt0KBV9wtZc8twkNR20gW5e57wAqApJ+VtxbL8U6nzm9w==
X-Gm-Message-State: AOJu0Yw1jZRG4S/5anpY0QB8eV4NI1N6wJ5eaKJx6Mq2+lc2eiayVl+M
	KhDYp0pbvm9SDbFeGEXl36BpEeZmy++ZmkiY+f9cAPoQIqH1a1Qc
X-Google-Smtp-Source: AGHT+IFQEzDjyy52LNzsGhe4mvLGKBY9/bFkabTemUqLf7uB0CdQ6jHGBf99xMNA36B2Oc5i6b/Cmw==
X-Received: by 2002:ac8:58c3:0:b0:42e:daf5:1b93 with SMTP id u3-20020ac858c3000000b0042edaf51b93mr2569495qta.39.1710866229569;
        Tue, 19 Mar 2024 09:37:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1916:b0:42e:db6d:a2e6 with SMTP id
 w22-20020a05622a191600b0042edb6da2e6ls7980819qtc.0.-pod-prod-07-us; Tue, 19
 Mar 2024 09:37:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUVldnyx4/g8mIC1S0cBwXDMKMi5NdUC6SNvu8ztYcZXOiBrAn+NsAhyXdHjb7DsTsL9WtA4xeWaMn4o1SwdNraAK5/WTEctpC2w==
X-Received: by 2002:ac8:5e0e:0:b0:430:aebb:4611 with SMTP id h14-20020ac85e0e000000b00430aebb4611mr2640806qtx.15.1710866227421;
        Tue, 19 Mar 2024 09:37:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710866227; cv=none;
        d=google.com; s=arc-20160816;
        b=YgusB3G8A8OQLEX1iYoIgcRFynEPgYCjP173HGAyroUnOK34fpWMgNZKtAxuJNugtm
         ka3DMfIlZzglifVuqunFNrzl2EdIDLkNKxnGIYJhJS8d5WjkCrvHgweBQfJQtPYM4n/x
         c53/7J5viUtjGBpiuN8zYLmnMRglPlJ05urj5n/SnBfppUW2ZoVv3YOC5gZ7XyDtmL9W
         jcka/ateoHJs+qw6sjVpOA4S0k5r3ykvjobJYWqgX1SkjaNo4IPUFqQejtGyLbE1JenK
         +MDUZqe0ClCYSVaU9qfUfhCrZsLM7S7oIJoWWQi7A1e0i/15aAmK2mRdkGp0VcUVhHYW
         h3DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DNX90sT1lUbl5lD9B0qqgx+siiIHXGud0HrlrLB6kTU=;
        fh=MxgVZQgUS6dFlPbWWwkVoGhyiZRypZpIsOeRqAUAkG8=;
        b=yY/XbaK8KWLZ8wBBPPJM5n8VdUB6TZ/IyaFfyiUQT/oMDq+9ti1TTUwPLQYqv/25Yj
         C68NnYoffVBtD4KUX6n3rs3BPQleZMZRr0FEJy6O/Go+IvbgxVE2RGHJoRlBxly0U9R/
         w7+E7lElDEJir9qSfx1x9aCQP7nchTPLhaZ4z8LC4szKRVrG1GUc5nipI/y+yXad48Sl
         dQRSokoNBC3YugLB6BH/oF4N1jP2Sp5TeJ10ZI+ah5ADpJxdm2hp1mAfO7bngcFlr8MC
         TjU6N7rYvfAOCVvT+ZemcPelk8FC7Ok/E1Rvmvw1z6f0Okid0BjiQA/jRqvCvrvxXUQL
         0p0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vCcRN6pj;
       spf=pass (google.com: domain of 3m7_5zqykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M7_5ZQYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id f10-20020a05622a1a0a00b00430eec15a25si91009qtb.5.2024.03.19.09.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 09:37:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m7_5zqykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60a0b18e52dso296107b3.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 09:37:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUW/utLwyS8YDBMIBx6KATpG8KXvaIuSiLA1TzVx6luOnPxwaMm0viGewiB8eABntfbxPYyFbd967Wy5He8+FtQ0mrnRet19F1bpA==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a0d:d950:0:b0:60a:1844:74ef with SMTP id
 b77-20020a0dd950000000b0060a184474efmr742423ywe.1.1710866227040; Tue, 19 Mar
 2024 09:37:07 -0700 (PDT)
Date: Tue, 19 Mar 2024 17:36:56 +0100
In-Reply-To: <20240319163656.2100766-1-glider@google.com>
Mime-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240319163656.2100766-3-glider@google.com>
Subject: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vCcRN6pj;       spf=pass
 (google.com: domain of 3m7_5zqykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M7_5ZQYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
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

Memory accesses in copy_mc_to_kernel() and copy_mc_to_user() are performed
by assembly routines and are invisible to KASAN, KCSAN, and KMSAN.
Add hooks from instrumentation.h to tell the tools these functions have
memcpy/copy_from_user semantics.

The call to copy_mc_fragile() in copy_mc_fragile_handle_tail() is left
intact, because the latter is only called from the assembly implementation
of copy_mc_fragile(), so the memory accesses in it are covered by the
instrumentation in copy_mc_to_kernel() and copy_mc_to_user().

Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
 arch/x86/lib/copy_mc.c | 21 +++++++++++++++++----
 1 file changed, 17 insertions(+), 4 deletions(-)

diff --git a/arch/x86/lib/copy_mc.c b/arch/x86/lib/copy_mc.c
index 6e8b7e600def5..e8aec0dbe6bcf 100644
--- a/arch/x86/lib/copy_mc.c
+++ b/arch/x86/lib/copy_mc.c
@@ -4,6 +4,7 @@
 #include <linux/jump_label.h>
 #include <linux/uaccess.h>
 #include <linux/export.h>
+#include <linux/instrumented.h>
 #include <linux/string.h>
 #include <linux/types.h>
 
@@ -61,10 +62,20 @@ unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned
  */
 unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
 {
-	if (copy_mc_fragile_enabled)
-		return copy_mc_fragile(dst, src, len);
-	if (static_cpu_has(X86_FEATURE_ERMS))
-		return copy_mc_enhanced_fast_string(dst, src, len);
+	unsigned long ret;
+
+	if (copy_mc_fragile_enabled) {
+		instrument_memcpy_before(dst, src, len);
+		ret = copy_mc_fragile(dst, src, len);
+		instrument_memcpy_after(dst, src, len, ret);
+		return ret;
+	}
+	if (static_cpu_has(X86_FEATURE_ERMS)) {
+		instrument_memcpy_before(dst, src, len);
+		ret = copy_mc_enhanced_fast_string(dst, src, len);
+		instrument_memcpy_after(dst, src, len, ret);
+		return ret;
+	}
 	memcpy(dst, src, len);
 	return 0;
 }
@@ -76,6 +87,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
 
 	if (copy_mc_fragile_enabled) {
 		__uaccess_begin();
+		instrument_copy_to_user(dst, src, len);
 		ret = copy_mc_fragile((__force void *)dst, src, len);
 		__uaccess_end();
 		return ret;
@@ -83,6 +95,7 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
 
 	if (static_cpu_has(X86_FEATURE_ERMS)) {
 		__uaccess_begin();
+		instrument_copy_to_user(dst, src, len);
 		ret = copy_mc_enhanced_fast_string((__force void *)dst, src, len);
 		__uaccess_end();
 		return ret;
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319163656.2100766-3-glider%40google.com.
