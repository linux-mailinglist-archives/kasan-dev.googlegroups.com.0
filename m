Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLM3VKBAMGQEY6LYIFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 624AF337FB9
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:50 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 50sf3264703otv.6
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498669; cv=pass;
        d=google.com; s=arc-20160816;
        b=ImlxkHfa93h4NvSNEJqxwark02ME6wOqqiJj3cmVZ58zKsImMvlZTAsKg+uIPsz8qd
         yiCF1/hjUpE9z2ROFEVWmkqmswhlk/qt02vyp4h3/n+M21j3XdXuF9xCXOs/A0v27GkJ
         Yy99u7qghlWgA9CN6upL3NZH5pbpMXNtL3mVGT26bpo8yY26bieDUAq5xgzo5cAC6rqz
         lApNbch1AvcdiohTjJ6Wy6aS9Ppo7VO1l+GaZGsCUXJkxgM/L9iVXA+3a3KeQ05DBnFa
         JN4XkuCeaWGVD/sfipxuYS8RXCCA6xb9ZQtXzjgxCFePrSvev+Yry1iNGUFo2n9AXnp6
         xTRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Wt20geGNGc8Ana4wRA/nLoVEHagnSGp42I9hT5Eh3gY=;
        b=pp9koM30JR+PwL2b/SzisrEoHbDhJfe6d3Kh3ah4UbCdPin4julWgTEo2ASTlZuVHp
         Qxo16Rv8iRIw8QZXVXuX1GHQOOklxbOIPb3/GhWIVRo0F0t9xQvV99AqGRjvt7MUrGUT
         XD/Oc76T23nIbpf+Bkq/gyD1IlvEtD0bRv6gIfzdzy3LVM7PIJXutJCuSm/X3haLI/un
         gv5rsqCiLvgdVZNurxK7s5/rHY/VMEjjYJJ+Xv4cvFJG/Sx/3uoknywh1ZDzMPPrJ0pf
         EDp6Xb+Ih9hXgXdNXrD6712as+Mpvfk1o1aG9as4SYgJl0qMHNJnAtcphlNszbvmJMkl
         p8+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ax/rWBbW";
       spf=pass (google.com: domain of 3ri1kyaokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3rI1KYAoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wt20geGNGc8Ana4wRA/nLoVEHagnSGp42I9hT5Eh3gY=;
        b=QTqJmNmhTyOmXUGEP2RspZyNBU3vAOea3Wbvd3+c2KcXe/fLwN0HmZhHlHwwFiMcWJ
         VaDwYATLcOfDYq8tYSIvwqwFjKMFu36T5UMogY1wtua9Ktb9wbWRU8vvMP40mR4AHTnl
         DSr0CCr0fCyS7/H+HRtF9V5RsbHd65SYm64pDEm8N+e6jEJu0GqwtsbttvL7ECJR8/l8
         2skwK5uB3bheRMkxxGoRdWyegFyhu5WJS4b5DPrgMcT3qtBvb55Z7/EQsOGMbK7T2I5Z
         KcIgEOJkJ2fVkH1kGey/pr36mkhndEMa7Cl/U1QztFaCSAp8aPKTy6z3NhgHbL+sP2mM
         ItNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wt20geGNGc8Ana4wRA/nLoVEHagnSGp42I9hT5Eh3gY=;
        b=dadebTNcia/L8r4CH/iiTcJYLW7BOgeNGJD0GpMj5+PAZhwpyaBp+IeJAYVJpVHslV
         5wJrnJmnm+fyKFB0nEJcGIqvqF71mS2+hbQbhcFSIyudglWU/uwJTI5//wL3hVymzdJb
         Z0frxmvKA/ck9/SA6g+iuhAHXKqROdgHFgqk3U2Bh3pZ43fyeyMyx0EAKwac5Qgibfun
         BT3Pco8rIQ5BgfQ/sWFmcQpMwEH77sWPVHkAmXxpBXVbMVNXbSul1rchH0p3kFmPtKac
         UBd1/CVaBTuYVMuB5ZZqSwdBg6K8LeKdntMTKdRZV8x0DLFkzNpUYIMms+aPwTxMyR4l
         rqXA==
X-Gm-Message-State: AOAM531sTQBFWnTp0puXXwWzfxb3cVJS7tPS/LqRlyMHROLLE0YLjIDE
	3jbXibnxMbmFKdW+EO97/SE=
X-Google-Smtp-Source: ABdhPJx09Y3fiwpdsDnkT/h/GWQgVmFPwZVDlZniJdZ3VFmRD3FWq9hS6sxqMq5NSI0gETgrfhbY8A==
X-Received: by 2002:a05:6808:1290:: with SMTP id a16mr7944541oiw.161.1615498669461;
        Thu, 11 Mar 2021 13:37:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b303:: with SMTP id c3ls1745661oif.11.gmail; Thu, 11 Mar
 2021 13:37:49 -0800 (PST)
X-Received: by 2002:aca:ab44:: with SMTP id u65mr7552421oie.122.1615498669157;
        Thu, 11 Mar 2021 13:37:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498669; cv=none;
        d=google.com; s=arc-20160816;
        b=cO8I4CBdpY5o9MEmUR+iwYxENCSeA2WiCl2rgiarDZrtokAkDXFGtcxIVA/hTUj4ju
         BA5fteIkxOLuF+IgVGmq1FFTzzUc4waK0Q/+oRce4C+tiDAK9NOqPpegubwl3IKz2nmp
         aamHhng34bkNrqyMXrFBQBWmeoVzj2fR53ekn36H5psw8MbP1a61rRMjNhwEYH46TvBI
         qRHX19Xc41x7CRWsqYFDVknZnnmMoeDVF2nRcFxE0qVbaEv9H+FIqAc63lHrYtT+S5w2
         krgtWF1IDalXJTlDDEMHYEOZtNWXfMyUWwdzzoO5H/mbKyyfpbMnydOjyiZCp3cNeTqr
         VmDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=d9MD7r+sgefmh6olz506jW43mtPrrCIc3sAEHbrSzj8=;
        b=NxU2uHD7QUUvugqPiPDenoBz5/Fwdd7AodQb/Yzrjcb5dtnoGnrIsYsbWZylMThPHo
         76qShE+hjLtcGv+JMs+yBXj74wqCG6zaXEjGYaqW/mHi+Ci2196SthbHlyF9klzrucED
         9dyOt37ymnfAfbIiPUGtSxYCDKgpqzL/FU5c5Hrt9Dr2hCheZ+z9qY8zeJsZja2XX87l
         KjvLGJcSin3xv3CwnuDFcGYtKg1XNU+U3rnCQ8YNjlWv9zJxV/04ZR048lq1o7Cenr21
         latKUKWxiOJttPUWzpFiBA8gPIGz8KpW+evlxm7jND7Pf2g/ZvziQ829ITutIqZpICG3
         P2Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ax/rWBbW";
       spf=pass (google.com: domain of 3ri1kyaokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3rI1KYAoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h5si309746otk.1.2021.03.11.13.37.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ri1kyaokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id h126so16684869qkd.4
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:49 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9cc2:: with SMTP id
 j2mr6061470qvf.2.1615498668637; Thu, 11 Mar 2021 13:37:48 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:22 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <c0f6a95b0fa59ce0ef502f4ea11522141e3c8faf.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 10/11] kasan: docs: update ignoring accesses section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ax/rWBbW";       spf=pass
 (google.com: domain of 3ri1kyaokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3rI1KYAoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Ignoring accesses" section in KASAN documentation:

- Mention kasan_disable/enable_current().
- Mention kasan_reset_tag()/page_kasan_tag_reset().
- A punctuation clean-up.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2b61d90e136f..6628b133c9ad 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -368,7 +368,7 @@ Ignoring accesses
 ~~~~~~~~~~~~~~~~~
 
 Software KASAN modes use compiler instrumentation to insert validity checks.
-Such instrumentation might be incompatible with some part of the kernel, and
+Such instrumentation might be incompatible with some parts of the kernel, and
 therefore needs to be disabled. To disable instrumentation for specific files
 or directories, add a line similar to the following to the respective kernel
 Makefile:
@@ -381,6 +381,19 @@ Makefile:
 
     KASAN_SANITIZE := n
 
+Other parts of the kernel might access metadata for allocated objects. Normally,
+KASAN detects and reports such accesses, but in certain cases (e.g., in memory
+allocators) these accesses are valid. Disabling instrumentation for memory
+allocators files helps with accesses that happen directly in that code for
+software KASAN modes. But it does not help when the accesses happen indirectly
+(through generic function calls) or with the hardware tag-based mode that does
+not use compiler instrumentation.
+
+To disable KASAN reports in a certain part of the kernel code:
+
+- For software modes, add a
+  ``kasan_disable_current()``/``kasan_enable_current()`` critical section.
+- For tag-based modes, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``.
 
 Tests
 ~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c0f6a95b0fa59ce0ef502f4ea11522141e3c8faf.1615498565.git.andreyknvl%40google.com.
