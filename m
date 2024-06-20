Return-Path: <kasan-dev+bncBCT4XGV33UIBBS75ZWZQMGQEMEUNRJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E9CB90FA9F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:53 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6f9ae61d8a2sf361059a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845132; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZiwnCpxYxOc5i/fvfUx7fEWg7+ElqhPyts9csGKvxg/vEfZJr1fFp4aIzd0R446hw2
         EDPbURdQYBzjdwtWjweIXoENTWBMwzDXhQrl8s0fdmJchjJ8961bGXaUUQlfpECG31hw
         dhe6rnW0NM17RUM51E0VYo5+r3IfoCe3DGMkQbGY4/7d4mTQtQ6cCqgh38OdPD5FAUyR
         HnUueP4PXVb5YfRpYQCWSH1xFNS+rG96iCCGOam3BQqTy509H47GZ56iPaTTuLwV+dzY
         3fFMVpTt1smsW4iHj9Eu50LykqKQPhsL1GuEpY/7phfuqy1VEKuvOFhRuh0+uXRBtsEW
         bqrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=xeCOeOU7yW02SUDwLe+AsybaLSG0kp6Qp8NSAhkU4bQ=;
        fh=YQanYoUrz3nBzpNS3WFvkI1MxbfVV7SDLok+f7RwdUg=;
        b=oiRi2JuK6Pb5VpPMx0pXZnewOIkM2Scg+Xwarrn0P1WNHmfx9PLsGdrHQTPfv7nNSe
         aSJyAdm1I7GxNeHGQqW/meSg7xStuLevKcWuS5fHcZLcdaBl/XhM3SmqG5b/V3dOVr/v
         gt0M1eKgqGYpP9zsiEuIlC2xfh1vV0aImpmWjWTq73mCPTt9w4bmxGZ5QRPESpSuMtSD
         bGzM3Ro3mC7BHprDeCC8kC0g8VuTO5WBvRpEBw/aKn/JM6zes9JkalnmCITV08GeAlH9
         OCvA+nsULfT1Cdack3EE93mz6V93D/B2cbDyG4PduMLDCP+M7FRXFCiyYSkDOMN51/Dt
         uIFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PuiKoXbw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845132; x=1719449932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xeCOeOU7yW02SUDwLe+AsybaLSG0kp6Qp8NSAhkU4bQ=;
        b=ZXhmCfCVGGC2uvWZeb+lJSLMQMOfjTvUgSc0avF6DgnUfcCCnPpp6g0k0rJGUgvFdi
         SU8ldu0EJkdr6hWB4opr3q4jO14kExmRhc7oQIiu9IytaREYg4RLuDw6jfIpR3JqA2zP
         AnOrdiR7acHeaYk9CTRobzHcpe6Zl3j+0glzre0Ui9URAzjnhUnHlWe9wEnOLLpgco/S
         tf2/0iPbsYeiXSNmqwsy7RbKxQ6jgseHTutto8Ps0L10M13EoBkUVH+iT1aMW9uEclYL
         QBRP9id8nA0/a8+6g6IkQ0gd9jNU/lNfMWe1uDZfdR/xUkSy7f6MLwgjXbDHJSTHtgH5
         POsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845132; x=1719449932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xeCOeOU7yW02SUDwLe+AsybaLSG0kp6Qp8NSAhkU4bQ=;
        b=lkPSlb6iGz1lJIW3pEyLdndI6JM8s2Ad3WEpDjphJtKhxgp0w1qpQX9I6TBy1LhLRu
         SYmx4Hc/6lmImJRnrONzM00BlULBGsVkQEs3TukNpL5nKY6/dL+VgOnSiKlPZYiYIwjR
         F28v03Nwi9et4N41S09yMjI/E0SLgipvtWqtmVt86t+IKzUT2FFyAyYz2CTOaH7N7KW9
         jMNsDp27eNMvwSA1k9wBoFinuH+ISQyvpgQNw7omyif9JmVnrNb5aQdgIuBDiA6Rz/zv
         nBOIAXNq0QxNtAkY7LXJ9oQlNsiG+33zvcROCkVVWeTOXIjEmcXbbHrLlIApvFhEQYXD
         6Akw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNAPpdcoHYN6PrGFCemSVvAaPbc8W5VIAP7xcdHnjx76piuJQRKhJSJzUmQXe9shl50Y64h5h/Zzyh1oe52vw9QG5tTWwVPg==
X-Gm-Message-State: AOJu0YwioMhQdf+uRSMeriz4ASnkTWhMtmjFvkPE7rx0SROr5yz7pig+
	l2ulfNpJwIqcjB4vWsXTv5SGlB96Jaa9sx2933V3Nj6m91SvMoPa
X-Google-Smtp-Source: AGHT+IFJaST9u0O1919usmbsA+dVf6VZIMR50V0ojSmu0MheP7mX3qD9ZyuRXAkFbCHBf5JZrG3j8A==
X-Received: by 2002:a9d:5f07:0:b0:6f9:e049:e11f with SMTP id 46e09a7af769-700739448d7mr4221506a34.9.1718845131997;
        Wed, 19 Jun 2024 17:58:51 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2b95:b0:6b0:91e6:b46d with SMTP id
 6a1803df08f44-6b51009df6als2077066d6.1.-pod-prod-02-us; Wed, 19 Jun 2024
 17:58:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPvHVg1lxS6CTuOrvFd0awheiDWZ5qdoUB6UMvd5GgDS05zQMGAurnpTnXEaiYL1mXSRiu83K8H87sELUD2FxOCXcqyKGtUVNENw==
X-Received: by 2002:a05:620a:2a12:b0:795:1e5a:2ad0 with SMTP id af79cd13be357-79bb3e1a460mr493429985a.14.1718845131136;
        Wed, 19 Jun 2024 17:58:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845131; cv=none;
        d=google.com; s=arc-20160816;
        b=s21eiUkvBj7vJbfCi4T/o1IsobPmkjqE/ZtxADjF6tAL2YYHc17dM2GX0P77/zYJXz
         n5Au9Gu6vGTvdzwXHBERhW12rzyAcWsVC4wdbqAJ00pSuo3ceBy7DcINdaTVq0gbwxPu
         BCT5HuMXJqdwZUz2RjTGF522+avfTgh4fo6toxyXjz4sAC4r+y7z6exnmkDCUaLXxxD2
         5M21k3NSWcO2AeLlv79j4fCSKlRSa0BX35HP9FSLTnv0Ji24/fE+LsRlJdKxmRoJb6YT
         272HAGdYztUJiK5Mv+AMGVrqxARxMkGjZRminRoVuJXJYsGwswBhQXXWxzoDCqaNa9cH
         eTBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=17xV0xMWgCrl20KYEAOF+TwIXMwm3JA/pxRGDjAJUQ0=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=qr4bZ8vdzMQi22gIQMWTlDLQEDlCowjP+Q3WzVh7Q8nODxkcna66XAv9R0a4EcJsQ8
         XJagcb+9iVW7yaLcC23wwm/QjDRrVdoYo9sRqyw4Er0oZIvLstLm15EA30eiZ5x2hvt5
         6yub3GAfwBiFjOMQuLm3jSgF/9ad2U9CZQ35qLanh77X/0n9kAryEJMAgPPFzgUbihmn
         Qv8OEt56oN2oyKbZlyvh6+OqUXgFsEYNxm1dcQdFmRdoDJQTiQuu/zeaOyHk2l7o+1Qf
         bZKBWNTgr6/NNYf5gHINk47bcNE7QKuhgv+kHR8Mw34mWlAYsuwzJHsIU3I6aI0buiY/
         ZHkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=PuiKoXbw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798abe4f369si62230285a.3.2024.06.19.17.58.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id AD19861E9D;
	Thu, 20 Jun 2024 00:58:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 52650C2BBFC;
	Thu, 20 Jun 2024 00:58:50 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:49 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + mm-kfence-disable-kmsan-when-checking-the-canary.patch added to mm-unstable branch
Message-Id: <20240620005850.52650C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=PuiKoXbw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: mm: kfence: disable KMSAN when checking the canary
has been added to the -mm mm-unstable branch.  Its filename is
     mm-kfence-disable-kmsan-when-checking-the-canary.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/mm-kfence-disable-kmsan-when-checking-the-canary.patch

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
Subject: mm: kfence: disable KMSAN when checking the canary
Date: Wed, 19 Jun 2024 17:43:53 +0200

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented and
sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only check_canary()
is supposed to ever touch it.  Instead, disable KMSAN checks around canary
read accesses.

Link: https://lkml.kernel.org/r/20240619154530.163232-19-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
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

 mm/kfence/core.c |   11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

--- a/mm/kfence/core.c~mm-kfence-disable-kmsan-when-checking-the-canary
+++ a/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_meta
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define check_canary_attributes noinline __no_kmsan_checks
+#else
+#define check_canary_attributes inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const stru
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static check_canary_attributes void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005850.52650C2BBFC%40smtp.kernel.org.
