Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA6JSD3AKGQESNVWCCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F4D51D9F4F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 20:25:09 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id j26sf128190uan.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 11:25:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589912708; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ru+LqADFV55fULIofgthvnWMus7H7G4cBwpE805L4jxMfWu3Aa1Qe4mRvPSygPyQwF
         H19RfxxQLKD7kAbd81lYhPOO6dyLDQWfNrIzeEpv2ufExE4W1kAQhCUu1kgIHuddFGdG
         k9ughlNvqihJ6hcP11szfq4lXtP6ckk+AWRqRpcblPLBQSlE/1aqEQCmcn3WjjsxukQv
         IB2aCI3BmknWwet+d5s4EJ13eenMIRsaT1059C3YV19OrHWGL3d6ED2TME8jp+NkWR3x
         btpcOkAJd8E/q8P77yN8najYwITkGfHCqkrfcEcSx6gi7qyXmWNVismm7X+M/tQF83w/
         mlpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=SG9uvjYgV+bB6DHBKM7jhpcRgdr3brXz2McrVlo7RDY=;
        b=KqxULdbvYvgzvMfipD4peqioKYPhBD6NDxNS8GWI+YloafiXGG4g0g9qJIATjff5eI
         mBLiGvVuqL/oUqYADEOIas6QjNhAFo2WqKmIDKYD5yp4hzwKj5HY94R/3DtzoGhYtuwa
         4qWPnj77mr5d+U/9zIJ7gmBJBDRdaPUaWSqPulQ5SfG0SfdZsmMIgeKMjrEKRI7CJraM
         dazKiSp53dBNE41iUerUrLsP3hRJnkxnf276p3mL4XwarxVV+kPgX3ajF4L+V61LBhyD
         CiCmlhE9C9UOHWlrOPpjQuZrT+hePLC1AnGNIcz6kN2xdZHqwigTKhnYFff6pTzPyYJf
         0jog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S8dNvEpv;
       spf=pass (google.com: domain of 3gitexgukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3giTEXgUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SG9uvjYgV+bB6DHBKM7jhpcRgdr3brXz2McrVlo7RDY=;
        b=lpO1DQBGcJNwVyiTMYNQJEjPsiStUMYOps1Za278XxWixLBL/i+7YRzDfazScTHLbE
         idw1OcwJifIf/O334rDnbm+fsX18mmZhWNMWDHNfbpucaFDmDK4tOgU9mzjSSmiVNdZ6
         nZ1QCNo3ur6c0Y9esKJde7fgvtEDzHEtjqtiECQ5qraGFdniPXrEAFDLPib4m19dfFEk
         /OY6L8WqEqbRw687kv5r/5to24SePYhwYLYrnwHKpdfj7jupeQOUq3/XqRTV4mFHKyuh
         ZNLDK+bJepTHZ6+b9nmYmjq/O9Nwn6aAWaVZirEyotZ0fyuqMWraeSmtVgvhlf39gL5q
         gAKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SG9uvjYgV+bB6DHBKM7jhpcRgdr3brXz2McrVlo7RDY=;
        b=ZPw9xWPZI+tqht33qvCb19NmrlIvdIUrq76iH4UznIcjkRadIyg5QHTXhkBLJjQqhw
         lxix9Jos+cM1hjEfnHnassUIMeHWRHwoJPkD8nOudBAREnFR1WlWml+iCHIoHD7+GHKS
         3QqZQJnd35BYnYO0aH/rE3hgUMNOXJIiwOKIEpNDyj33L8zu+Tl3womvnTLAdwr0j7bk
         hbdqRQwG3MRPPyRMMrj2i1z1OkOgAnZSWbN7hkES0lYxO76QhtOj6rkqV4xkbwFfsWNJ
         Jvfr8rs6iYHnWa5QHcQRNhDkkcy2uDoUK6G0T1egF8QnJedFnJo9g0YwC/J2ga3Z5CHZ
         YDkw==
X-Gm-Message-State: AOAM533IGJg0xmL0X4uHA80BpOdsS3X0MAoOnWsrIaSHiCB7BiMmpobd
	r7z3H93ApFY1NcixVY0szSE=
X-Google-Smtp-Source: ABdhPJylC03o+w59kiF0m5x2WPhQTqQGTUvrg+eWeOYIJfBhVMMHkO3/axIlh22DLpVnPWuFWUweLg==
X-Received: by 2002:a67:7715:: with SMTP id s21mr400618vsc.110.1589912707761;
        Tue, 19 May 2020 11:25:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:5d43:: with SMTP id r64ls19125vsb.4.gmail; Tue, 19 May
 2020 11:25:07 -0700 (PDT)
X-Received: by 2002:a67:eec4:: with SMTP id o4mr400652vsp.220.1589912707398;
        Tue, 19 May 2020 11:25:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589912707; cv=none;
        d=google.com; s=arc-20160816;
        b=nULvyYvQfSrQN9omJbkkGUof0R33MrSor1zbjtbZDXqec1WQGOFL4nNaw5wFrtrCmn
         qoOWTTgcChrfVbEHozbF7QlA0kHcEuIFzsDE2MUy9ckasFrnIeReOXIMXVYhlb1gly1u
         ziFuznacoMfBwIvw0ITc+H7V7Xb1/gAX8TQR2ij/D4arm6RaNxgXZnegykxQ0kH2Kcug
         0tW0vqHa7EZT5Je07s26ptqBKCE0WIobqA+Pk3ZrSoGFQ6RnhpUr+sgYCiFm5faBTjfg
         phUnXJUjL91O6njQ1l4v5XAEX53v+JKdvDDjw0rbwfHOOnxNS2JkxIotDcH0yvVqHbT/
         zOcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=/YztpDs6K8vdorsBByvnDRj+nEKIuoGb/xCbk1LxXf8=;
        b=DQSuadoNQUp5lpm0DCzguOA7uaa8pIpyC4fMrP4XMks0uQonmaLeb77AccM7wxU4+6
         xcCWSfHX4++UD3gMJIQr2FJnIWvJa5GGteygOtUbXOH0KjmQol8U6adBb3chIKX9EBDp
         tVP9qWFihnaucAR8/eFuaKKQPOV30R4JFa0BORmjcEqV6WIqVo18vXgU0KcWDUAbootL
         KxVwNK8fRFgpw3vh7+m6eatg7oRfM8wvN7ebWyfRlBoozg//EQox63aHydHGN5RBKv2B
         WE0iiMNQUsT06zAzlo6SetVIEbkkkUBEM4EfeB9e/oBkVipBdlyKNEzTiuVmXgRNRN5J
         hjNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S8dNvEpv;
       spf=pass (google.com: domain of 3gitexgukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3giTEXgUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 137si33833vkw.5.2020.05.19.11.25.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 11:25:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gitexgukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id g143so705859qke.12
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 11:25:07 -0700 (PDT)
X-Received: by 2002:a05:6214:3f0:: with SMTP id cf16mr1034113qvb.4.1589912706953;
 Tue, 19 May 2020 11:25:06 -0700 (PDT)
Date: Tue, 19 May 2020 20:24:59 +0200
Message-Id: <20200519182459.87166-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH] kasan: Disable branch tracing for core runtime
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	aryabinin@virtuozzo.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	kernel test robot <rong.a.chen@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S8dNvEpv;       spf=pass
 (google.com: domain of 3gitexgukcdc7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3giTEXgUKCdc7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

During early boot, while KASAN is not yet initialized, it is possible to
enter reporting code-path and end up in kasan_report(). While
uninitialized, the branch there prevents generating any reports,
however, under certain circumstances when branches are being traced
(TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
reboots without warning.

To prevent similar issues in future, we should disable branch tracing
for the core runtime.

Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
Reported-by: kernel test robot <rong.a.chen@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kasan/Makefile  | 16 ++++++++--------
 mm/kasan/generic.c |  1 -
 2 files changed, 8 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 434d503a6525..de3121848ddf 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -15,14 +15,14 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
-CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 56ff8885fe2e..098a7dbaced6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -15,7 +15,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519182459.87166-1-elver%40google.com.
