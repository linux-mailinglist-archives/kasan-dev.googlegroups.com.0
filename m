Return-Path: <kasan-dev+bncBCT4XGV33UIBBS75ZWZQMGQEMEUNRJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A73490FAA0
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:53 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-70634edd984sf429086b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845132; cv=pass;
        d=google.com; s=arc-20160816;
        b=LynLJYBeu4Be8S+8g3QUZ4AcLjWrA05CEfS+uaOAoB6XNrCuCK66+4GY3C0NDo2W5P
         w+pa7YFglGNFDRGs4Ee5J/qdcs2SHk63oghzqZS/oSbD+jzty+/5YYJKdgAdFFmtgOg2
         lZkJqycDaV4PTybPyBKxvYvMWpRKBi8bHeQOR6tjYdnT4UsqXilKDxwriig6LXrRLksS
         qrscBRxjANGTIBZEh1i+qXFgRm1xIr/9gS8ijTXPvQvxv+9DRFmeLReLibUr5DLn7gWV
         eBIY+RYo+3ugy49nuNNd67GuZus/thjQOYIhMgDWejf4/iouac0EPl5Ov6LjXk/0yLL/
         Tgsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=IFOHKF7ABBlUhquqqBJ8JIlcjCxRvMjlOOa2xfRfyjw=;
        fh=u0hD2zuD1fmk/Yf8j6JBNnxO59De/gW3R1WfCPwVzCM=;
        b=Ar6ef0wEFyf9cCmKdUVfZWseKnjmVAg9D7otbhUV6oJpj8RDYvN0sZAffD1nj5Dlkk
         0LwixTkQjJBHM/AHV0d47x60MBQCBiQefWWAPgjlugLSL3hFJXXTGz2wubIci+5tifvL
         FNvgMLOOc07IS0zxEQ7eyVvyJvXI5Nlb8PVaM9p8cP68Lp9E2XfyiVhtBJtjW6wkNbwO
         A2GY1gKaLPtFEvxlAyQCyJu6bA3e87HglqYRD3ESKQ4q19nhPAM4w22D4eQpGyiiBCGS
         ivQELTUq/u8D19kgui0bEcDswmtadW2fl3gtc/Ng5NuInteIyWKQT++N/EFYNL0RJBBn
         YIKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uKqL7HCp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845132; x=1719449932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IFOHKF7ABBlUhquqqBJ8JIlcjCxRvMjlOOa2xfRfyjw=;
        b=xMMIo38+joa2CwGzibSVR2hbInlIny+wgA3tfxBvuD3te0ghkfo/yWyC3MZ+3LdoTi
         Q9Xv5+cSJuzqTT1yqs4Hz1BebFTsROkM1zCR38Y7kReo5Kedh4RiYcphQTcqX8hV8xpD
         l5ueM/bECAB0Rgt3G6m64sqXHNw+uWfx3Ib880Ki92s8A6lAx7uGbqH0QZC/p6XxDb4X
         yAZ2X8cr4WqEE3jmBko3+5EDKqzjRweB+enuTneyga9JVvkXOAFvwgrhI0oBFTZhywOK
         IvRnat/cOLS2Eq+ATkPYem/z8LhMeAmlPkeCch0xDMLXy0rxEsny4tbzifvUlP0M9ZZ9
         ELqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845132; x=1719449932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IFOHKF7ABBlUhquqqBJ8JIlcjCxRvMjlOOa2xfRfyjw=;
        b=V16R4+VmbXxBNE606J/LShTPYO8SgITzXB67yJr8/XQFRMP4sQJmoQrzAs9jIQld5A
         WbcU29Z9F0pZ/OElSnqhfVCCzRLnjp5AUDCAHYvJlb3lBb8mMJE9zZmeDlkGkrlD8D+s
         1IU7XpsshtHJFwwVu+n1Dx0i149p/5FhlP7T8/lWJe6uBi+1GjvKI+Nf3v3ZKOleWHKM
         2ZEZQ6vedUmc6RouDpkpouVXtnuB9Z4btyS84mZSTY31Ht4zkwkucDwx4FzAS0o9yjSt
         n7seFIiga+hf+cNMtRZNUd9AoA+YfKS0yaRS2VASZRTV5D7Wu+T9V5FoYlj/XJqbOu8i
         QFCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeRycWoMWFjsrGsqWuv3Dz/NGzD/vZIBd1Zr+TUBVbCJmPSYlmUzQi0H5PoiTWG1XFVJw/GasNzG17Sy1oReboxyUOPYm8Cg==
X-Gm-Message-State: AOJu0YylZAeWPjDAjeDZNlnIFw1lttDymSzyTYobRR/TYnpiQKLWmnKn
	TQ7TDrTzVV5aiGTVe5k5RqgBHFlETs/2rCN6DUErLORpoicvO/DC
X-Google-Smtp-Source: AGHT+IFm2SKRewa7DA/P8IhVENgxCSHT4QYtfGo1QpuvzsfgASLog5kWZ/+IYMZhrkdtJpIEipIw7A==
X-Received: by 2002:a05:6a20:1e4a:b0:1b4:33c0:4a12 with SMTP id adf61e73a8af0-1bcbb426f83mr3915536637.17.1718845132067;
        Wed, 19 Jun 2024 17:58:52 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a4c:b0:2c5:128e:23f with SMTP id
 98e67ed59e1d1-2c7dfee7277ls215038a91.2.-pod-prod-01-us; Wed, 19 Jun 2024
 17:58:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSJh6f8f5it7EHPe+Q1oIjywhp3F4Ps1bNxVSk6yg9qFtOZyABNxT+yij6e9baDx1Pykh8wJNV4gvK15gmxOFfcivuGJvQLDa7nw==
X-Received: by 2002:a05:6a20:2056:b0:1b4:772d:2892 with SMTP id adf61e73a8af0-1bcbb594fdbmr3870709637.32.1718845130837;
        Wed, 19 Jun 2024 17:58:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845130; cv=none;
        d=google.com; s=arc-20160816;
        b=mYnL74l12l0R7xlU3jBpwq8VcPvFDgWkEvqRAlqOq05BplJD8uuW6xmTV2NmPMzv+Y
         o745n8K8oSvcvltpu1CAnLobFmcWWP9/YpLT98fDSolXK66UQbc53Nwsl76ThtKM8TWt
         Frni9TyIBQXMD980UyOriVw2SyXhl4kjkC+5Okp1CaOJRDWv8YW6fsUWBi2XzPsw2b+S
         iHO4blwQrPD79A8UlQp1JEPGA4Fplw0ooIR/Xa2QQFHYXRKSPirCvOY96LSbMWJTmFk8
         H7IOeKbcu4lG3uGgYmX6cduCO+L3l/2jPo4FDtDagnIw5VYGnNC81XZt+UesfRQQ8wCk
         6Tag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=/djel2naCPfZVFV8wtcTEvPjaEhwnWQBMRT7FnOHvD8=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=QaeEuGEFCqjKuuIpJP9GvDP8EaWA4sqMHfkcL9fwQ8KSafXbtkUIvfX8QZn4wwljDn
         gT3aseL8PtGt6PMq84d4xcROuM+y0O3H3l7F3z7C0CRn5D8LI+H3Md3UfIAl1aLEYKkn
         Abep12ES3WJMAiTCGWsZAh/hVM00OOTxKd4XKtZi068EuxZ7SKZAv6UXv7FjlNQSdgc3
         nebEqOJvb4rximklEd/sWCB4uyNFMY7E32kElhSXqWkQ1Oc625wgZgz5bJp7J8Bc2jLe
         bJpuExdYT2HgJfBhMShwFlaXspuMLXKTxNU49/8S1NOeuYaT6L5keZLAn71fKHUF9n5v
         zElw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uKqL7HCp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9a3b48d10si1620575ad.8.2024.06.19.17.58.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 0367BCE22D7;
	Thu, 20 Jun 2024 00:58:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46933C2BBFC;
	Thu, 20 Jun 2024 00:58:48 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:47 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch added to mm-unstable branch
Message-Id: <20240620005848.46933C2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uKqL7HCp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: mm: slub: disable KMSAN when checking the padding bytes
has been added to the -mm mm-unstable branch.  Its filename is
     mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch

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
Subject: mm: slub: disable KMSAN when checking the padding bytes
Date: Wed, 19 Jun 2024 17:43:52 +0200

Even though the KMSAN warnings generated by memchr_inv() are suppressed by
metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns `*start !=
value ?  start : NULL`, where *start is poisoned.  Because of this,
somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

One possibility to fix this, since the intention behind guarding
memchr_inv() behind metadata_access_enable() is to touch poisoned metadata
without triggering KMSAN, is to unpoison its return value.  However, this
approach is too fragile.  So simply disable the KMSAN checks in the
respective functions.

Link: https://lkml.kernel.org/r/20240619154530.163232-18-iii@linux.ibm.com
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

 mm/slub.c |   16 ++++++++++++----
 1 file changed, 12 insertions(+), 4 deletions(-)

--- a/mm/slub.c~mm-slub-disable-kmsan-when-checking-the-padding-bytes
+++ a/mm/slub.c
@@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_ca
 	memset(from, data, to - from);
 }
 
-static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
-			u8 *object, char *what,
-			u8 *start, unsigned int value, unsigned int bytes)
+#ifdef CONFIG_KMSAN
+#define pad_check_attributes noinline __no_kmsan_checks
+#else
+#define pad_check_attributes
+#endif
+
+static pad_check_attributes int
+check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
+		       u8 *object, char *what,
+		       u8 *start, unsigned int value, unsigned int bytes)
 {
 	u8 *fault;
 	u8 *end;
@@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_c
 }
 
 /* Check the pad bytes at the end of a slab page */
-static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
+static pad_check_attributes void
+slab_pad_check(struct kmem_cache *s, struct slab *slab)
 {
 	u8 *start;
 	u8 *fault;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005848.46933C2BBFC%40smtp.kernel.org.
