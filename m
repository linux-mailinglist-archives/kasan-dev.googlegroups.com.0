Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFO6D7QKGQEE2OYR3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 666202F0ED3
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 10:15:57 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id w3sf7493290ilj.17
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 01:15:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610356556; cv=pass;
        d=google.com; s=arc-20160816;
        b=uUQYvHUtRN7c+MIcYJwQQt/zkwwNqT42hcT4HqJjFHNuyq9i1oNAceYqvy+yzFJQeR
         Khcvl3Y2Eq85a0LM/p/BZlAEDpL31Znc2fduEruqIqDWtMMJyWmnxKZQSozKC4xiZLVr
         QdFAFJZJmuzpi4WuCt3Uzqc68aQLxVYIVn9TR0qQzMV0HogfyRuwh5l8lt+H4Kg4qB7S
         ykgUJjPBlNaFRvFq9cyNc6GiXAHXBO/Y5lIXhWsFZA1y+ArfEGHBLk8E4Th+tkIfFrX7
         EC9D7K3m5ueIh1ZP9maKA19WuHDuVktmKHL39cunVwbNaSksYel/SUlKg1qRBNvwY+7W
         em1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=P5se5a0Lk76tEln0byS4HVuzTGrDf45p9/CxFU1P2Ec=;
        b=nT7kkmhZVkuD7UJTCJDpvUOH8E0IwgFbxIpDHYOHLPxP3TDh4Y/wlUvp+tvZ1QiSR2
         0G8btbbzWcrZzMZHy7UTea2ZuFfDYteuiVpUP7EUC7e7ijC/DVnKPaqOSBqDnU41k+TI
         LosizGLrSholuQRD1CkS/nWRh99Pfu0XMj/bbRLv8nBCs8tba4RHDvr9gJyTfEq/e2wg
         8TcDodejqgXOFQDt4xmHb9aHZxVHfg/vTcK5RbfSiO3Bk0rJjQik5poNBfK1ba7Bwgku
         T5EbRsVa3Wzb7ego7tE/0I6BFnxf/k9P3cDBA4y14RFBAwObns1WU+PxC2S6NKtpfV6F
         D0FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ES15Qh6b;
       spf=pass (google.com: domain of 3sxf8xwukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Sxf8XwUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=P5se5a0Lk76tEln0byS4HVuzTGrDf45p9/CxFU1P2Ec=;
        b=gqiHMXNhyg7OB0ShfalnT9iZSD/mJNO1WLxPxwY6iC1Ce/e/GBfDYOY7J3CLfu9NM+
         OcXINjg6nJKf8Yo/p7Demf0G8uJKlxw3aVSjKWGKqOFObVdszjkDXcGSyS5x1sR7KXy5
         O4thu7fuCaRSk+9J30gHMGwvY2TPoYPJO+BYyJRtoyDymsjJ2epHXqPOwg9QaUye/gJr
         xW+h7z5LdvmJUygdKhLUdmef2TsPhXMjJ8LdBysFN/Fu0QlyscgtHDdL8kySGeNUYlnk
         CD8nyG2doU3SMwsYOcdj8Io+5TfRr9782/txL+Yt0N99VpEn3sEzqtE8rJIA8twrdH8q
         p/7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=P5se5a0Lk76tEln0byS4HVuzTGrDf45p9/CxFU1P2Ec=;
        b=oRDwkHIVaXF1ZfI2dZqueZ3Ect9uqo67+Jt7XOyxciS/jmVaSKCY9XwQZalyh+1N+1
         aCVXJq7t8Puz94mSmjb4uwZqirwovmDp28C/e//MYm7QkcrES+H4VlvyuDeG6Ka6xDYf
         R9vwoFXiSg2lW+ZYzcU0MhCJbTXsBrb9LcXnP8wUEWPFFuadN0z+mhMjEqA6aRChxnoj
         Y1HCKPgqtGqFogm78t+RsT8z878fqUqlQV6ugpsIDqHSqShm9sSsKlXHeUh3jTU/H7bz
         dr6PHQ5wU5fWJuLiU5X5gZc3ZIXCEQioGwQ17/NGb36WvteYFgyR1Uv7cOcOKY1MPxGf
         jcWg==
X-Gm-Message-State: AOAM5322zEcYvLd9WVxdxyUgqME1EQOjlrf5CAtctMNGW7q607Hd9ulw
	W75hcW3vdI7VLxT547amg/I=
X-Google-Smtp-Source: ABdhPJxjEBHwbuLPp4zpTuIkDMircvTOTNEqdMm1CzTxqNVL7yS4r1JLWG9aG0u2U9M3WGPCZSDxAw==
X-Received: by 2002:a05:6e02:13b3:: with SMTP id h19mr12171255ilo.187.1610356556486;
        Mon, 11 Jan 2021 01:15:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1687:: with SMTP id f7ls107205jat.11.gmail; Mon, 11
 Jan 2021 01:15:56 -0800 (PST)
X-Received: by 2002:a02:8791:: with SMTP id t17mr13521110jai.28.1610356556110;
        Mon, 11 Jan 2021 01:15:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610356556; cv=none;
        d=google.com; s=arc-20160816;
        b=VfU0lbSjEOGhrlb6/E1Mq0XAOYiGl/tK5qyjHDU27WH4i4om/VX172mWEfzX1fOOy6
         /bsIsVoz8gcU3Rj62Vel9J26/SVG8pJJmHX9lhUFrv2pRXYj+EYeAO8HQjSjkSJw3itr
         AI1lrWzmqfjYuRorus/ye+2KIauNPZs9a2fqMegl0SaIYLwpG3KdOc2rPbYb62vjkyQ5
         lTdhTDzeW8Xa/GHrojQNNQCYW98suCrWbxTkgyZVDWJpu9UN8zsppYr+C/8vbkCeCVpe
         GCE1i8+BgNaQF11mSzw1Sf0ujj9GaUfNtUat6IE63odDxzUtkieKtooRgz/FAdrypdmk
         Isgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:sender:dkim-signature;
        bh=VoSddRN3eE9jLTCktDJ/olU5g0AXyCtJzEB2jcx6iRw=;
        b=uBISj8Gj9GZQ2hbvMlskVkVWqop54ON3yKtRDVbnQ2TWahVmheRZHIsPW6dOkzeWiJ
         7epcAsBt4c4EuS2glVA4JRdJ/wK1sAA0sByJA1NoKEPZe24v/gqaKXjQ1JvQ7QuixA76
         1oj4UjU7YHDQQir5UeI3vIOmuxXV9GEVra1b9TRyuUuOvjZshyIT8kGJ9h23mhykiCNd
         wQ1+ypO54X8bOUoArmLuxhSj7qe5PK36whWuMk4EcRFNPuDo4/tWzL7oPbqk8NTS3e6a
         FD8hWkj0PERJndyqXXqku3bzYMGnC7aPzgEqPRMKXxoJD7Pe6ZJSkCLUZphDwWGg56zf
         M7Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ES15Qh6b;
       spf=pass (google.com: domain of 3sxf8xwukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Sxf8XwUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id b8si2062780ile.1.2021.01.11.01.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 01:15:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxf8xwukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id k16so12758458qve.19
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 01:15:56 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:bd2b:: with SMTP id m43mr15065393qvg.32.1610356555502;
 Mon, 11 Jan 2021 01:15:55 -0800 (PST)
Date: Mon, 11 Jan 2021 10:15:44 +0100
In-Reply-To: <20210111091544.3287013-1-elver@google.com>
Message-Id: <20210111091544.3287013-2-elver@google.com>
Mime-Version: 1.0
References: <20210111091544.3287013-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 2/2] kfence: show access type in report
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, mark.rutland@arm.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	"=?UTF-8?q?J=C3=B6rn=20Engel?=" <joern@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ES15Qh6b;       spf=pass
 (google.com: domain of 3sxf8xwukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Sxf8XwUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Show the access type in KFENCE reports by plumbing through read/write
information from the page fault handler. Update the documentation and
test accordingly.

Suggested-by: J=C3=B6rn Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 12 ++++----
 arch/arm64/mm/fault.c              |  2 +-
 arch/x86/mm/fault.c                |  3 +-
 include/linux/kfence.h             |  9 ++++--
 mm/kfence/core.c                   | 11 +++----
 mm/kfence/kfence.h                 |  2 +-
 mm/kfence/kfence_test.c            | 47 ++++++++++++++++++++++++++----
 mm/kfence/report.c                 | 27 +++++++++++------
 8 files changed, 82 insertions(+), 31 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/k=
fence.rst
index d7329f2caa5a..06a454ec7712 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -64,9 +64,9 @@ Error reports
 A typical out-of-bounds access looks like this::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
+    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa3/0x22b
=20
-    Out-of-bounds access at 0xffffffffb672efff (1B left of kfence-#17):
+    Out-of-bounds read at 0xffffffffb672efff (1B left of kfence-#17):
      test_out_of_bounds_read+0xa3/0x22b
      kunit_try_run_case+0x51/0x85
      kunit_generic_run_threadfn_adapter+0x16/0x30
@@ -93,9 +93,9 @@ its origin. Note that, real kernel addresses are only sho=
wn for
 Use-after-free accesses are reported as::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
+    BUG: KFENCE: use-after-free read in test_use_after_free_read+0xb3/0x14=
3
=20
-    Use-after-free access at 0xffffffffb673dfe0 (in kfence-#24):
+    Use-after-free read at 0xffffffffb673dfe0 (in kfence-#24):
      test_use_after_free_read+0xb3/0x143
      kunit_try_run_case+0x51/0x85
      kunit_generic_run_threadfn_adapter+0x16/0x30
@@ -192,9 +192,9 @@ where it was not possible to determine an associated ob=
ject, e.g. if adjacent
 object pages had not yet been allocated::
=20
     =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
-    BUG: KFENCE: invalid access in test_invalid_access+0x26/0xe0
+    BUG: KFENCE: invalid read in test_invalid_access+0x26/0xe0
=20
-    Invalid access at 0xffffffffb670b00a:
+    Invalid read at 0xffffffffb670b00a:
      test_invalid_access+0x26/0xe0
      kunit_try_run_case+0x51/0x85
      kunit_generic_run_threadfn_adapter+0x16/0x30
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 7ab718603f4b..10bd03ee3586 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -382,7 +382,7 @@ static void __do_kernel_fault(unsigned long addr, unsig=
ned int esr,
 	} else if (addr < PAGE_SIZE) {
 		msg =3D "NULL pointer dereference";
 	} else {
-		if (kfence_handle_page_fault(addr, regs))
+		if (kfence_handle_page_fault(addr, esr & ESR_ELx_WNR, regs))
 			return;
=20
 		msg =3D "paging request";
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 907b54d3b990..66d2db2f2211 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -734,7 +734,8 @@ no_context(struct pt_regs *regs, unsigned long error_co=
de,
 		efi_recover_from_page_fault(address);
=20
 	/* Only not-present faults should be handled by KFENCE. */
-	if (!(error_code & X86_PF_PROT) && kfence_handle_page_fault(address, regs=
))
+	if (!(error_code & X86_PF_PROT) &&
+	    kfence_handle_page_fault(address, error_code & X86_PF_WRITE, regs))
 		return;
=20
 oops:
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index dc86b69d3903..c2c1dd100cba 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -180,6 +180,7 @@ static __always_inline __must_check bool kfence_free(vo=
id *addr)
 /**
  * kfence_handle_page_fault() - perform page fault handling for KFENCE pag=
es
  * @addr: faulting address
+ * @is_write: is access a write
  * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
  *
  * Return:
@@ -191,7 +192,7 @@ static __always_inline __must_check bool kfence_free(vo=
id *addr)
  * cases KFENCE prints an error message and marks the offending page as
  * present, so that the kernel can proceed.
  */
-bool __must_check kfence_handle_page_fault(unsigned long addr, struct pt_r=
egs *regs);
+bool __must_check kfence_handle_page_fault(unsigned long addr, bool is_wri=
te, struct pt_regs *regs);
=20
 #else /* CONFIG_KFENCE */
=20
@@ -204,7 +205,11 @@ static inline size_t kfence_ksize(const void *addr) { =
return 0; }
 static inline void *kfence_object_start(const void *addr) { return NULL; }
 static inline void __kfence_free(void *addr) { }
 static inline bool __must_check kfence_free(void *addr) { return false; }
-static inline bool __must_check kfence_handle_page_fault(unsigned long add=
r, struct pt_regs *regs) { return false; }
+static inline bool __must_check kfence_handle_page_fault(unsigned long add=
r, bool is_write,
+							 struct pt_regs *regs)
+{
+	return false;
+}
=20
 #endif
=20
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 96a9a98e7453..a5f8aa410a30 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -211,7 +211,7 @@ static inline bool check_canary_byte(u8 *addr)
 		return true;
=20
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-	kfence_report_error((unsigned long)addr, NULL, addr_to_metadata((unsigned=
 long)addr),
+	kfence_report_error((unsigned long)addr, false, NULL, addr_to_metadata((u=
nsigned long)addr),
 			    KFENCE_ERROR_CORRUPTION);
 	return false;
 }
@@ -350,7 +350,8 @@ static void kfence_guarded_free(void *addr, struct kfen=
ce_metadata *meta, bool z
 	if (meta->state !=3D KFENCE_OBJECT_ALLOCATED || meta->addr !=3D (unsigned=
 long)addr) {
 		/* Invalid or double-free, bail out. */
 		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-		kfence_report_error((unsigned long)addr, NULL, meta, KFENCE_ERROR_INVALI=
D_FREE);
+		kfence_report_error((unsigned long)addr, false, NULL, meta,
+				    KFENCE_ERROR_INVALID_FREE);
 		raw_spin_unlock_irqrestore(&meta->lock, flags);
 		return;
 	}
@@ -765,7 +766,7 @@ void __kfence_free(void *addr)
 		kfence_guarded_free(addr, meta, false);
 }
=20
-bool kfence_handle_page_fault(unsigned long addr, struct pt_regs *regs)
+bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt=
_regs *regs)
 {
 	const int page_index =3D (addr - (unsigned long)__kfence_pool) / PAGE_SIZ=
E;
 	struct kfence_metadata *to_report =3D NULL;
@@ -828,11 +829,11 @@ bool kfence_handle_page_fault(unsigned long addr, str=
uct pt_regs *regs)
=20
 out:
 	if (to_report) {
-		kfence_report_error(addr, regs, to_report, error_type);
+		kfence_report_error(addr, is_write, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
 	} else {
 		/* This may be a UAF or OOB access, but we can't be sure. */
-		kfence_report_error(addr, regs, NULL, KFENCE_ERROR_INVALID);
+		kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
 	}
=20
 	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index fa3579d03089..97282fa77840 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -99,7 +99,7 @@ enum kfence_error_type {
 	KFENCE_ERROR_INVALID_FREE,	/* Invalid free. */
 };
=20
-void kfence_report_error(unsigned long address, struct pt_regs *regs,
+void kfence_report_error(unsigned long address, bool is_write, struct pt_r=
egs *regs,
 			 const struct kfence_metadata *meta, enum kfence_error_type type);
=20
 void kfence_print_object(struct seq_file *seq, const struct kfence_metadat=
a *meta);
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index f57c61c833e6..db1bb596acaf 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -71,8 +71,14 @@ struct expect_report {
 	enum kfence_error_type type; /* The type or error. */
 	void *fn; /* Function pointer to expected function where access occurred.=
 */
 	char *addr; /* Address at which the bad access occurred. */
+	bool is_write; /* Is access a write. */
 };
=20
+static const char *get_access_type(const struct expect_report *r)
+{
+	return r->is_write ? "write" : "read";
+}
+
 /* Check observed report matches information in @r. */
 static bool report_matches(const struct expect_report *r)
 {
@@ -93,16 +99,19 @@ static bool report_matches(const struct expect_report *=
r)
 	end =3D &expect[0][sizeof(expect[0]) - 1];
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds");
+		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
+				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_UAF:
-		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free");
+		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
+				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: invalid access");
+		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
+				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		cur +=3D scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
@@ -121,16 +130,16 @@ static bool report_matches(const struct expect_report=
 *r)
=20
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur +=3D scnprintf(cur, end - cur, "Out-of-bounds access at");
+		cur +=3D scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_typ=
e(r));
 		break;
 	case KFENCE_ERROR_UAF:
-		cur +=3D scnprintf(cur, end - cur, "Use-after-free access at");
+		cur +=3D scnprintf(cur, end - cur, "Use-after-free %s at", get_access_ty=
pe(r));
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		cur +=3D scnprintf(cur, end - cur, "Corrupted memory at");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur +=3D scnprintf(cur, end - cur, "Invalid access at");
+		cur +=3D scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		cur +=3D scnprintf(cur, end - cur, "Invalid free of");
@@ -294,6 +303,7 @@ static void test_out_of_bounds_read(struct kunit *test)
 	struct expect_report expect =3D {
 		.type =3D KFENCE_ERROR_OOB,
 		.fn =3D test_out_of_bounds_read,
+		.is_write =3D false,
 	};
 	char *buf;
=20
@@ -321,12 +331,31 @@ static void test_out_of_bounds_read(struct kunit *tes=
t)
 	test_free(buf);
 }
=20
+static void test_out_of_bounds_write(struct kunit *test)
+{
+	size_t size =3D 32;
+	struct expect_report expect =3D {
+		.type =3D KFENCE_ERROR_OOB,
+		.fn =3D test_out_of_bounds_write,
+		.is_write =3D true,
+	};
+	char *buf;
+
+	setup_test_cache(test, size, 0, NULL);
+	buf =3D test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT);
+	expect.addr =3D buf - 1;
+	WRITE_ONCE(*expect.addr, 42);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+	test_free(buf);
+}
+
 static void test_use_after_free_read(struct kunit *test)
 {
 	const size_t size =3D 32;
 	struct expect_report expect =3D {
 		.type =3D KFENCE_ERROR_UAF,
 		.fn =3D test_use_after_free_read,
+		.is_write =3D false,
 	};
=20
 	setup_test_cache(test, size, 0, NULL);
@@ -411,6 +440,7 @@ static void test_kmalloc_aligned_oob_read(struct kunit =
*test)
 	struct expect_report expect =3D {
 		.type =3D KFENCE_ERROR_OOB,
 		.fn =3D test_kmalloc_aligned_oob_read,
+		.is_write =3D false,
 	};
 	char *buf;
=20
@@ -509,6 +539,7 @@ static void test_init_on_free(struct kunit *test)
 	struct expect_report expect =3D {
 		.type =3D KFENCE_ERROR_UAF,
 		.fn =3D test_init_on_free,
+		.is_write =3D false,
 	};
 	int i;
=20
@@ -598,6 +629,7 @@ static void test_invalid_access(struct kunit *test)
 		.type =3D KFENCE_ERROR_INVALID,
 		.fn =3D test_invalid_access,
 		.addr =3D &__kfence_pool[10],
+		.is_write =3D false,
 	};
=20
 	READ_ONCE(__kfence_pool[10]);
@@ -611,6 +643,7 @@ static void test_memcache_typesafe_by_rcu(struct kunit =
*test)
 	struct expect_report expect =3D {
 		.type =3D KFENCE_ERROR_UAF,
 		.fn =3D test_memcache_typesafe_by_rcu,
+		.is_write =3D false,
 	};
=20
 	setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
@@ -647,6 +680,7 @@ static void test_krealloc(struct kunit *test)
 		.type =3D KFENCE_ERROR_UAF,
 		.fn =3D test_krealloc,
 		.addr =3D test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY),
+		.is_write =3D false,
 	};
 	char *buf =3D expect.addr;
 	int i;
@@ -728,6 +762,7 @@ static void test_memcache_alloc_bulk(struct kunit *test=
)
=20
 static struct kunit_case kfence_test_cases[] =3D {
 	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
+	KFENCE_KUNIT_CASE(test_out_of_bounds_write),
 	KFENCE_KUNIT_CASE(test_use_after_free_read),
 	KFENCE_KUNIT_CASE(test_double_free),
 	KFENCE_KUNIT_CASE(test_invalid_addr_free),
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 4dedc2ff8f28..1996295ae71d 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -151,7 +151,12 @@ static void print_diff_canary(unsigned long address, s=
ize_t bytes_to_show,
 	pr_cont(" ]");
 }
=20
-void kfence_report_error(unsigned long address, struct pt_regs *regs,
+static const char *get_access_type(bool is_write)
+{
+	return is_write ? "write" : "read";
+}
+
+void kfence_report_error(unsigned long address, bool is_write, struct pt_r=
egs *regs,
 			 const struct kfence_metadata *meta, enum kfence_error_type type)
 {
 	unsigned long stack_entries[KFENCE_STACK_DEPTH] =3D { 0 };
@@ -189,17 +194,19 @@ void kfence_report_error(unsigned long address, struc=
t pt_regs *regs,
 	case KFENCE_ERROR_OOB: {
 		const bool left_of_object =3D address < meta->addr;
=20
-		pr_err("BUG: KFENCE: out-of-bounds in %pS\n\n", (void *)stack_entries[sk=
ipnr]);
-		pr_err("Out-of-bounds access at 0x" PTR_FMT " (%luB %s of kfence-#%zd):\=
n",
-		       (void *)address,
+		pr_err("BUG: KFENCE: out-of-bounds %s in %pS\n\n", get_access_type(is_wr=
ite),
+		       (void *)stack_entries[skipnr]);
+		pr_err("Out-of-bounds %s at 0x" PTR_FMT " (%luB %s of kfence-#%zd):\n",
+		       get_access_type(is_write), (void *)address,
 		       left_of_object ? meta->addr - address : address - meta->addr,
 		       left_of_object ? "left" : "right", object_index);
 		break;
 	}
 	case KFENCE_ERROR_UAF:
-		pr_err("BUG: KFENCE: use-after-free in %pS\n\n", (void *)stack_entries[s=
kipnr]);
-		pr_err("Use-after-free access at 0x" PTR_FMT " (in kfence-#%zd):\n",
-		       (void *)address, object_index);
+		pr_err("BUG: KFENCE: use-after-free %s in %pS\n\n", get_access_type(is_w=
rite),
+		       (void *)stack_entries[skipnr]);
+		pr_err("Use-after-free %s at 0x" PTR_FMT " (in kfence-#%zd):\n",
+		       get_access_type(is_write), (void *)address, object_index);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entrie=
s[skipnr]);
@@ -208,8 +215,10 @@ void kfence_report_error(unsigned long address, struct=
 pt_regs *regs,
 		pr_cont(" (in kfence-#%zd):\n", object_index);
 		break;
 	case KFENCE_ERROR_INVALID:
-		pr_err("BUG: KFENCE: invalid access in %pS\n\n", (void *)stack_entries[s=
kipnr]);
-		pr_err("Invalid access at 0x" PTR_FMT ":\n", (void *)address);
+		pr_err("BUG: KFENCE: invalid %s in %pS\n\n", get_access_type(is_write),
+		       (void *)stack_entries[skipnr]);
+		pr_err("Invalid %s at 0x" PTR_FMT ":\n", get_access_type(is_write),
+		       (void *)address);
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[ski=
pnr]);
--=20
2.30.0.284.gd98b1dd5eaa7-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210111091544.3287013-2-elver%40google.com.
