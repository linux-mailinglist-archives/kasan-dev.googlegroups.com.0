Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAUB4T7AKGQEF4W45EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 924F62DB3B9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 19:29:22 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id g25sf10397277edu.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 10:29:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608056962; cv=pass;
        d=google.com; s=arc-20160816;
        b=E2t2uH2ww9urnRXiut6yR5GtGB0AcWZBnLd3BF6G+jX/gtUiXGoMc2cU2MApz3oQoF
         yw/qUimkGoPfcQtrctl/dH/wIcofhfRZIpByP70cuKQbaDNl0/eC6jyGc90YXf83lN6B
         7GPMiBxWOYJRxlqjBoxUQY6ZfoGcFRAVCThM4j5uch3lGT63wG+7igA9xlhCj/iqOBqg
         qAZ6KVUQcQzCB6PRgXuvR44mSWsQG9yxS6Wegk/A3VYVLiP1oiBVqgywWRVzCYS3h1hz
         19mvgFbx/OX7wH2BKVSUw4+sXh6Z2PZPxOgQUTZ4x7cwzDhA0pqWuOjCcccNfyCVtLtL
         y8WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=CXXnguGCxRmvdXiQhkERV55IGm3BOYrJyXnpi40bcxs=;
        b=09mdIuG0lC8KkAgljLIcjaJ1Ii1U5WGfVNn2s2WHjFCZKfmRlte60/s677sw8z6ap+
         IRaTac9dwOk00FvASeT9QCprtLoWaUZO36ECxFAvb3Vlz4p2rCZuhAJVb52TUuIWaJkU
         eiJ+FXoOisJ1VbQn8PtM8PONjmhPWpPzwbhKt23LVbzkJSILKn0VLAZVmGaPigmgDH2E
         VeQnQHgMMzwD+9R0czoyV06mHRRdaTDxXcKlCARFQciSuYuk2LYXAQ5MBOVW2IxgLG9F
         NqEXcFpw1sG1oyB62W9N7TSpSBpr1cCeNBHgtddsjUrTFc5oeBWK7Q4je1eqGPkXTir7
         PE2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u92i6CCT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CXXnguGCxRmvdXiQhkERV55IGm3BOYrJyXnpi40bcxs=;
        b=rSGWuQj5//urzkIBbN+BX3fpW92q6GaZMGsfh6Kx0hnP2pZMG4bYxgMLgvZ+5lDFVZ
         WZnEdjrgS0+xq3SyyPKX2DcY8JR9qtvcS5Nvx1rQrj+nMUlI39WiLodHVI0lloqIpatW
         hqhMFo3DFuXtYhnNjU+q4vk62Dg3LoTGYGDlQN+10GNv/rhgD6Dn+U3Xpcnxg4eOlMSO
         rJFrBSsC2aonRh1ue2chVs1y4k4C2uHIslI5Vc4Ci1fiW3xjwWjcAlXyrlreddb3UCi6
         h4UkRcOTraYrJRcgN6C4jRjOb+KZpiVmGEf7fUUn08UvmkQq8LakEg/a4ATXfG3L6a7X
         3ZrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CXXnguGCxRmvdXiQhkERV55IGm3BOYrJyXnpi40bcxs=;
        b=gWTIRi/F9bd3xnRcs1irgmDPud86lSYqfCJEaUGAKeWOwxe3z/aGX9vE8j4IBmXg6q
         Ua/uwsHlHEIN5Dm3Rq2joGB5cj5CVRNi1oSqBDXTbtveA4E32dAvnYvsUMS+il7d1RbE
         EMVG+0pS2iORScyKTsZRIlYN+V5qpGLZFsJqFZUphwdp8quW4kWdX1pROjOC1SwVN0sp
         De4/035tv3w/0iCH5G8PvR532hv/JpcfDHcAIfCIubFHTvqyiF3DXwfOOberQqfpd1p0
         k8iQeqqlq+ja/IN40CpVtcUJeUYYn/LmfhMRuamZnbYXcksGdf1zjmzIgMSGf6Q2CS9j
         a14w==
X-Gm-Message-State: AOAM531U9yAovOxyNqvfDh1993eTHAwznwv68Wr3bufdIngCIgZFhXaz
	/4DLEn9FY1iVw//YS6IENAM=
X-Google-Smtp-Source: ABdhPJz5t4HSuGqj+RFfL3vbJ80EQrGHyfanq2RSCJGRYba7xnLVXYmLtOUwt8rHUwhc1dqdkQX+3Q==
X-Received: by 2002:a05:6402:610:: with SMTP id n16mr30315839edv.172.1608056962257;
        Tue, 15 Dec 2020 10:29:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1dc4:: with SMTP id v4ls430814ejh.3.gmail; Tue, 15
 Dec 2020 10:29:21 -0800 (PST)
X-Received: by 2002:a17:907:111c:: with SMTP id qu28mr3334512ejb.540.1608056961153;
        Tue, 15 Dec 2020 10:29:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608056961; cv=none;
        d=google.com; s=arc-20160816;
        b=mvBNylpXkrqPUrqgfokH57WIcvi/WccjeCidACZSDPA1omTsqwdOcBpstK8qZKx+0Z
         ukIBQH3SeKbW1EKy72Hj0bKUYQ3nhW4ZGhPGiNfwfwWDcY8mYrBuKyXF451MbqFtzd9g
         WJjZ3GOPaM65Cy6MKSIhy9Je9+JBnjqZnu6TtvxCNE8+/5zTr3k9f0qekpIluVBIlYXO
         ItetX1Ydvthcf4iRnG6ZME5zg9D+MJy8jzIGqhSzx0NhHb3SuiULIs3txB2p5bBMALyL
         3BWEvKbpMfbkK/iCbjPJRj3yPx2AE0F8s9Iy/+Y32E4NmYrplo1rsi4qM5FgCB19l0lT
         wI8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=meO62pyIQf3DFJwCOpjoYopi7IHhW6i/skbqVmNASYc=;
        b=U2sKcnq3KW1Lm8ZYlIKxlktOVpjrNRDTuccUBD7t5Wb4N2Tjxqn2sdodsOQZNgO+13
         tFeuPB6guam55rE0mWkn1z3As8GniibHCl7xA47nlBjwXN/YJ8YPC96eexw5c60Arqje
         myfs1RUREPGrponpF/ViP9JVlDpTawqONiBgOYmwR5Ro36HuEeJiGpvEo/Xg6WbZqeWu
         UTfEIviakxPVwH2Iq8FZDr4NKFGR/etFs3DaIVrli/yCEBwklOQjfEKDZsu1XngiuR3m
         K4gt6iVGyEtJB9DvRNQDdKuPhVsjH4LD2WYFl7U/iJWzBuISrZRMaVYv8L04BxR9qios
         NcRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u92i6CCT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id i3si647600edy.3.2020.12.15.10.29.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 10:29:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id a3so137126wmb.5
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 10:29:21 -0800 (PST)
X-Received: by 2002:a1c:454:: with SMTP id 81mr189224wme.178.1608056960725;
        Tue, 15 Dec 2020 10:29:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id g192sm39252747wme.48.2020.12.15.10.29.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 10:29:19 -0800 (PST)
Date: Tue, 15 Dec 2020 19:29:14 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: stack_trace_save skip
Message-ID: <X9kAeqWoWIVuVKLq@elver.google.com>
References: <20201215151401.GA3865940@cork>
 <20201215161749.GC3865940@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20201215161749.GC3865940@cork>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=u92i6CCT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Dec 15, 2020 at 08:17AM -0800, J=C3=B6rn Engel wrote:
> On Tue, Dec 15, 2020 at 07:14:01AM -0800, J=C3=B6rn Engel wrote:
> > We're getting kfence reports, which is good.  But the reports include a
> > fair amount of noise, for example:
> >=20
> > 	BUG: KFENCE: out-of-bounds in kfence_report_error+0x6f/0x4a0
>=20
> One more semi-related question.  Can we distinguish between
> out-of-bounds reads and out-of-bounds writes?

I'll send the below patch with the round of KFENCE patches for 5.12.
Not sure why we didn't have this earlier, but I guess we were busy just
trying to get the basic feature polished and these details go missing.
:-)

Thanks,
-- Marco

------ >8 ------

From 4d76cb23df9ebc58568c23b1ce64e0685e9df886 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Tue, 15 Dec 2020 18:43:27 +0100
Subject: [PATCH] kfence: show access type in report

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
index 183d1e6dd9e0..8184efe4a4cc 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -323,7 +323,7 @@ static void __do_kernel_fault(unsigned long addr, unsig=
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
index 53d732161b4f..f231a54a164e 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -727,7 +727,8 @@ no_context(struct pt_regs *regs, unsigned long error_co=
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
index e1c33f86c9d0..2eb67fbed399 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -214,7 +214,7 @@ static inline bool check_canary_byte(u8 *addr)
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
@@ -353,7 +353,8 @@ static void kfence_guarded_free(void *addr, struct kfen=
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
@@ -762,7 +763,7 @@ void __kfence_free(void *addr)
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
@@ -825,11 +826,11 @@ bool kfence_handle_page_fault(unsigned long addr, str=
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
index 1433a35a1644..e8ae77d57b75 100644
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
2.29.2.684.gfbc64c5ab5-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/X9kAeqWoWIVuVKLq%40elver.google.com.
