Return-Path: <kasan-dev+bncBCT4XGV33UIBBQH5ZWZQMGQE6EFUHJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16C0390FA9A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:42 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c72171fd6esf438420a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845120; cv=pass;
        d=google.com; s=arc-20160816;
        b=SfXriuzCh8n63izHzhLci2oh3nbjsGJ5P5Q0sAGoSFT0WkPEy1Mb3sZtzunBpIfUBt
         Gu6EtV3XRnPzSEkCoucR48tvWh37bNf55d4+HuF+APxb/uNKVKLDhxC287O+ggabhQGV
         bh5hqxVeZCAyXL8n5KP+70UZb8WPa0VQ7c1Q72csJyj6lXvulpkBDcbIHblMWvi5qGZg
         AQckc5mQKmo1CPpNZxVrQH2tUI1FwWZyNHmd9aUc5Bvo8V/wYLNPRu/8hGmq3k3a5mUj
         3RDtnlsp221kHvffbSl+5YDz3ozw6PDIUyY6YaImHP5HOsG8ryl3AIaWdlZCRsmFlwc9
         rW9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=CxX62HibVJH5owtLTWXtgiRdZbX2pzEI+BDOAga7PPg=;
        fh=Riw0s8z0foF3adYCh6IV/4BlKWaDKAZXjj8BBereXYg=;
        b=NoEWqdv+pq5aAxUV0xoUJeJtyuRir2GuLXtqDtdMphFrseLHexTOPQztI53LlGxj61
         8jusPGYqQJsiDi63XnQNCGuGu5KriKGBDAVYjscUojveh4OXQC3TBend7yuzavAMTlgn
         pZmQ7fRorF5n6AMC9JSZ5At2wBiNrBZnGDOYxhGYnEeh0TLlbx0kmja2omKzxytAWEIN
         T5psUmCeKB8BdBOpUgzx8KeIgdBTnATIwYfbhRQoNUywx55t48JIYmqDvcUUp6AnixTI
         Sj2xakSYnf39rXp1JEDzkD5fNTHR19+YM+CVvB3PDZFQ/TL/6Rnnw27FtBQy6HMcN6mo
         N0Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=u2fXjLcC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845120; x=1719449920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CxX62HibVJH5owtLTWXtgiRdZbX2pzEI+BDOAga7PPg=;
        b=ff7vUppLA0OLUbyMYtBdFgWF35+m7P5JbeGqAurXcy+Tu1seAQf/niT4xgfCLbhXjn
         rrtM7Cf+L4zi802UHy6dTK+HVjzVMWWHAk2nG5fWbqr9F29g+nvpNHIyINk7zENmNmc3
         3Z/Y4IXmWDhcc+/4mPTojz4yg7GqxFgIi7bEPlJAbSwS3NY3voz3OISqP9FXCHFWmyz+
         V88NzmKsKQTjibS6mOU+PoeosS4xg4dPf4HS74xjZTvhqEVF8qwAwtpcL2Lc4BtUpmUA
         UfkHtxEvcXCXoQbNl8y8L590fXhGchWwsCAkL0VRinTL9qOq1CaBkFqZ2GlzlgLHPyVF
         rOuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845120; x=1719449920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CxX62HibVJH5owtLTWXtgiRdZbX2pzEI+BDOAga7PPg=;
        b=F3RnsVDaTLyEPjE4gkBGXGjBVqEGhaeBOPG/hYD8y7uoFh9Q4viIbCX/Tvf/06tX+u
         XM4BmWITdshMFqQelBiT5qDpu8EScnwIno699YBpqCOUlvYJgWgK8CXizoXIZzCEVrI9
         /sd3hxPSs3tTLuHltHazjWa3BD+Jk1OYV4KZ4xjkJtpeRmw0y1Z42m4AYh0oV9GHsv+C
         DzmE7LqSNSwErx3fzhJg5q2vwhOU6N3XLq2cKm4PH/cUir7SBL0uSxI+qLz5feky6krj
         TwH+gB+CddV3opKKVk0rZsXe5R9jvWD9yMHPMR2CHa+lmOt9BWMW/6oLGpQJfeKuJ6fv
         ExUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSw5f9i+mYyEx5LFPGftt6i+ZTJm4O0M/kB/5cwV38QHZO/hAHTIuB121OXoxgQRNSmjRDznS8WE2pjEQ4p+JgcKzMGlVgBw==
X-Gm-Message-State: AOJu0YzIPm0lN8afd3nRBOJNUAuu9T9CTLESZqtL5A/rDICUf+9YMHxz
	ISFYkdfpd1imwZ1isFUkuw7i3ABYzw3RVKDlIZEbs5BnHEp7QMJe
X-Google-Smtp-Source: AGHT+IHPwdBn/ptsOybtIjeP8bwVJZ0fNqBxrsn7AgC5QZZQ/J27L2vwEKH0eimbJmeJCQhBEh5SUw==
X-Received: by 2002:a17:90b:386:b0:2c2:cfd1:768b with SMTP id 98e67ed59e1d1-2c7b5af953dmr3949140a91.12.1718845120458;
        Wed, 19 Jun 2024 17:58:40 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:364c:b0:2bd:e914:8fe1 with SMTP id
 98e67ed59e1d1-2c7dfbe9ed0ls196189a91.0.-pod-prod-04-us; Wed, 19 Jun 2024
 17:58:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXws5ozvSjZ2iaCKMX6qtjBzilaRzuLkTom8QL+6mwjj3z6YAm9YzoyNXkfy7gzZnRLsXGwyjvelrALJZKA8BW4dJ/jfxwmtPivvg==
X-Received: by 2002:a05:6a20:12d2:b0:1b8:2211:b7dd with SMTP id adf61e73a8af0-1bcbb5c48ecmr4872906637.30.1718845119137;
        Wed, 19 Jun 2024 17:58:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845119; cv=none;
        d=google.com; s=arc-20160816;
        b=ACNkv2doEW9PfDm8S7gQcUExGErNEI0KxVWWIV6masKm/Meyxy42keuINSO4Gkev4w
         dNCg4zD5pbNThv4W99DQZPbJJLIfiikD5tPyDe4fXxAcqUYBkkBGcnUCUk+Iu0EXpsEv
         wMHQoHID8R+QtvhBg8NYVPpRf99HgiO1oO/k+wbn/C65L1W7G+PwkLEVClYnZ7tbPmQk
         h4cbi9md1dZ4NypyyOPxv1EUHMxMPi5Qx0HQ5YIASt+ifviHLaQhBaIHKSx4LHDtlBE2
         5PbMDQ4xF6H5IQvyJTMTPcPr7aOm2EF/Oqura47sB//XZV43QpzmW5w33OrhdKWxEpQO
         SGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=1Zy+q4U8Er9JMNrbydgUAFHJP1hcJg3hA8R8OPk0fl8=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=tLqXZPANLzDETyIgDZdx2IJDwY9262k7F9uyM3fzrpElzs5LTEjocP3lzrlpuc/O1a
         c5n42hV+FU9bBJKCWSpDnhVJ6NrdvGt87Xf3NNxvFO5S/SXB7irgeTUHe3zEXdSZKFsP
         uMrifrRIN+ohkIa+F0DjIcaiJC/fxR9HAk8nmqLc0Pqk0x2E+OI4NDCv85V/pCS9miS5
         jjiDcOWVs+vJV3HQy7EolQwaheABmE2ATRuc5NhdYoECc9nOxiFTE7Bcnc8OHcnyFEH2
         N/lePz10kjHPOd4PgiF9Ado6c2AkaVVaEFDC0CK7gfOGx4MsGEovlGUbRnxsMeAZKeeq
         40qA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=u2fXjLcC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fee4affcfbsi264518a12.4.2024.06.19.17.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 84D3562023;
	Thu, 20 Jun 2024 00:58:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 26F49C2BBFC;
	Thu, 20 Jun 2024 00:58:38 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:37 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-introduce-memset_no_sanitize_memory.patch added to mm-unstable branch
Message-Id: <20240620005838.26F49C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=u2fXjLcC;
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


The patch titled
     Subject: kmsan: introduce memset_no_sanitize_memory()
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-introduce-memset_no_sanitize_memory.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-introduce-memset_no_sanitize_memory.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: introduce memset_no_sanitize_memory()
Date: Wed, 19 Jun 2024 17:43:47 +0200

Add a wrapper for memset() that prevents unpoisoning.  This is useful for
filling memory allocator redzones.

Link: https://lkml.kernel.org/r/20240619154530.163232-13-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>
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

 include/linux/kmsan.h |   13 +++++++++++++
 1 file changed, 13 insertions(+)

--- a/include/linux/kmsan.h~kmsan-introduce-memset_no_sanitize_memory
+++ a/include/linux/kmsan.h
@@ -255,6 +255,14 @@ void kmsan_enable_current(void);
  */
 void kmsan_disable_current(void);
 
+/*
+ * memset_no_sanitize_memory(): memset() without KMSAN instrumentation.
+ */
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return __memset(s, c, n);
+}
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -362,6 +370,11 @@ static inline void kmsan_disable_current
 {
 }
 
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
_

Patches currently in -mm which might be from iii@linux.ibm.com are

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005838.26F49C2BBFC%40smtp.kernel.org.
