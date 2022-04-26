Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCWDUCJQMGQEUE5QMQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D30285103EE
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:58 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id dn26-20020a05640222fa00b00425e4b8efa9sf3781060edb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991498; cv=pass;
        d=google.com; s=arc-20160816;
        b=lN2PD44Rc1KiHxrrpdb04johf0mR/LzcEmyfISHF6QlEZPtWMn7uuxX180j02S6rAE
         mwMLCMnCu/6Df6U9UT3EUu+8OKgl5Vh1RKCvFYSJFxpwiyZ/FEW+qkyag2mo92JgNUoB
         zXoU6qX/JOSIywk1o1dT+kpTSahrEKfi/QRT/UIsEyXpxSMMaE58/BkBZ36qM+J4/AHn
         c2kKVZRDaCdLgW7mXPstG4KJRrOBwWNaaOraipg7j039lORi50kFo6X6l+50ZYrWlmU6
         9ee148A+o33swMvGjQWBCxWs6qZUDmbsPHpVj0QjkMCERJFiDGx6ulT5ubSfb8fdbDNA
         TX6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=dbESHk+ZxdF905PuqXEACaQ8zw+TAh47ygL2e2UeU2s=;
        b=swhN+0dAn8aY9NjYj3z/tAzpeFEoYo0X1RB7AEiQfzIuk9yu+YPdkS56aRdpcCz1pV
         VFgl+UBonir319UDxYMnznwtaNE95b0QqNPl3d0DDNTz8U05QdNjNYOlhIy7NFTMyUN3
         ed80sL/+un7w/igSSECqrA49NpaiBB/zTThPg+NF6QSRwSo5Q8s7CvXoZ+Rc94OlLwIS
         F5/3hykWmAQXNkADdd1wo/5TQxE3Hk343ADRLcqcPWhRkbmTzu/y3DwlmJz6bLaSdjly
         zyvLrKA4/PyEX0vd7W4RLsk0ayM3ngYEwXL/ofvxqMOgZ2Rq9JxfZm6XqJ5T5jJXVF+R
         Cy+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GRtnB1LL;
       spf=pass (google.com: domain of 3icfoygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3iCFoYgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dbESHk+ZxdF905PuqXEACaQ8zw+TAh47ygL2e2UeU2s=;
        b=XckHtb5AY+ZSm6TyGkrFpoc1WZjd6m1Tx9rbyYZdKFv8VMbSt7dnjaeM5GIFKqdgQ+
         OAdrNtT9/OuKcA23bDaCmzN1Nq/CCspw5m8yZEax4deiSlz6BgofS8XEPVtvwPeOWLIT
         ibpLtnD2VfZp4++gd6U4yxisK/9XUE68yB2QG5YVoVlmO2+ZQJewI/WUS4VgUVza6LUq
         HpwMXtoayn1Zw3a7Pqd3hTYOJM9JTmagjVt1T7n+Mqqn0u+1UghX2N+UurTI0GdYLilB
         8HzmKeidZQWihHZ1aMpLtaAvW9VacXDFUdNrqBQenKMuglJ4OH08wIrT2qfFECBp2HPh
         KxRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dbESHk+ZxdF905PuqXEACaQ8zw+TAh47ygL2e2UeU2s=;
        b=zxSE3JMkJ77KQzscGtnd3x8wIowilV7gHY8RekMXSttPIRK8C/FfeCnxywUn9++CM1
         9QPEtD2+49RvkHOmHQnQCDluN9DBgRM5+736BTO7G+sTN7IdNLBKjh7F2CeJQQ3qt4fR
         pnjcme+FtDXcd00twgEJvxZl0dSNl6J0smnsxPi2mUN8QbHa4sN2un4gSXDifC5xbfqg
         wcDzlivC8pp5wKLs65Pufh1IXUvlIyWkoHV+DHYdzCZRviUhi8pjoSfXXG+4DY+crrmT
         aHo5zmHOhSl/O8UCKKJ/hOCX3dGCUtYMmRGsvtRRTuHLbzbOz8SJAwsV8sKD37SR9Wsn
         7pzA==
X-Gm-Message-State: AOAM532PfzyTSrR5cjYF1qO4Lr5+M/zv38ZZj555qc2r7Z1NCCVMnBUj
	kPLgd3v7L6sO5+0+9pOPHsQ=
X-Google-Smtp-Source: ABdhPJygjLVkJZOZ0l8fEOvBplKSaL8IaB6ngCePVN+6/nTeZfNza8h7LmRdX2S754hcnI2jziBB1Q==
X-Received: by 2002:a17:906:2294:b0:6f3:bd02:95a3 with SMTP id p20-20020a170906229400b006f3bd0295a3mr1604894eja.201.1650991498687;
        Tue, 26 Apr 2022 09:44:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d1cf:0:b0:403:768d:84b2 with SMTP id g15-20020aa7d1cf000000b00403768d84b2ls1367684edp.1.gmail;
 Tue, 26 Apr 2022 09:44:57 -0700 (PDT)
X-Received: by 2002:a05:6402:516:b0:425:c896:b1b8 with SMTP id m22-20020a056402051600b00425c896b1b8mr20088681edv.212.1650991497696;
        Tue, 26 Apr 2022 09:44:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991497; cv=none;
        d=google.com; s=arc-20160816;
        b=KajBBRJQl+jnJ5FLtyAFvhxAh/7RMyPOz33IZDk/TSvMy9y9ZmPpZ9dzyREQOMpsDC
         uVP28a6lrG8R8OawV5lgrIBtZGViCVwojlIy5v/TlLy7o611t9DV+QUvHRokbzYm2/oS
         jzjnE2Jzom85nezERhpnyBgT0a1fRGX3ZsFL678yvZc6Rx/ipXYjnr+AbBg8Z393SRcn
         5EzY9ii73reR/GPwaxZwQoKa1CxU0wq+irQP7kToivZ1nNDMl5ff4OU31IKENgyD+Z8l
         CgVuDnLKny0L+9RRwrBZV872UJHbnmiYI0qiHK/1x1qzld/C4HpsYPtbph+SVHKjMafL
         WXHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QRr/YK4fONn3HTG8Fp9y+tnnWkzL1O1MoaFJezJL3sE=;
        b=hvMfOhCOMZjIcoRNyG+8g4NxjQOOgQDD9DMLhwnepMXCCwG8839bhheUKQNW54jib6
         kqS7BG/77EDwFLnJ0TuGT4gmx+bUyGE+kKlxJUJhgFd2t3lNL1kNZSA+++s+QCx/NICe
         jRND07Ninuj9MOJKX9D/70qOsjIQAjmaIw9C3LvvyBpK4C4Cukngjt+OPmk1ZpOkj0ja
         MXKSoDrbKcRMHAKomST8S/YXs3yVFopiDm+tITGkAyTTkNS0vqqb8CzNjeEcMr/1JkF7
         3oUnV3pnC5lorxd+5/HVmD3IVG0sQ01P7m3xnCN6EcfQ2eNhmJ9C13L1XTUnNhAQkUM8
         e0ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GRtnB1LL;
       spf=pass (google.com: domain of 3icfoygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3iCFoYgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id b15-20020a50e78f000000b0041cf5333d81si963641edn.4.2022.04.26.09.44.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3icfoygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id x4-20020a05651c104400b0024f253d777fso430940ljm.16
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6512:104a:b0:471:f0c2:99ee with SMTP id
 c10-20020a056512104a00b00471f0c299eemr14014612lfb.142.1650991496992; Tue, 26
 Apr 2022 09:44:56 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:43 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-15-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 14/46] kmsan: disable instrumentation of unsupported common
 kernel code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GRtnB1LL;       spf=pass
 (google.com: domain of 3icfoygykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3iCFoYgYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

EFI stub cannot be linked with KMSAN runtime, so we disable
instrumentation for it.

Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
caused by instrumentation hooks calling instrumented code again.

This patch was previously part of "kmsan: disable KMSAN instrumentation
for certain kernel parts", but was split away per Mark Rutland's
request.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
---
 drivers/firmware/efi/libstub/Makefile | 1 +
 kernel/Makefile                       | 1 +
 kernel/locking/Makefile               | 3 ++-
 lib/Makefile                          | 1 +
 4 files changed, 5 insertions(+), 1 deletion(-)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index d0537573501e9..81432d0c904b1 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -46,6 +46,7 @@ GCOV_PROFILE			:= n
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 847a82bfe0e3a..2a98e46479817 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -39,6 +39,7 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
+KMSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # Don't instrument error handlers
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index d51cabf28f382..ea925731fa40f 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,8 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/lib/Makefile b/lib/Makefile
index 6b9ffc1bd1eed..caeb55f661726 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -269,6 +269,7 @@ obj-$(CONFIG_IRQ_POLL) += irq_poll.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
 obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-15-glider%40google.com.
