Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD6DTH3AKGQEFONSSGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CF5C1DCBC1
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:08 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id y16sf5002993pfe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059407; cv=pass;
        d=google.com; s=arc-20160816;
        b=T226IM55/r9Yla7Xn6/g9iYvVbrQJRgy1K0wUvVt83b+9ZgD9z+QQ9CPVPcyCL/NDT
         iVz2T+KA8lwBu7EIAt1NuSvUTurKDoBed0VOmryTh5fMsFOdKOCLnzIQC3uwMhWUgFN/
         Efd915uGiCsu5RfYKg4O4oKBtfr55GHrUnu3y8T4stmqJDcyPiFsnufZq3Ev5Cy6NkoL
         3c90onascKTpeRQRdQ9K+BgqaF+zHcFL7O8z5anSun4XbwDlZpB5gUdekOygy48webcW
         GErTm29rE7kluy2SrEXPbm+Sb0GE6H+pFLqhBM977MIVfX1BShYJEHmAIfGJd51K4jFN
         EvzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qgGrHJuVsZ4Ir39LMw6xwVjs6LZHw4QGE06tg2nCy84=;
        b=vtxkyW6S56M87HNm9LFngign4aVrZ6z1lP/0hAqX+l/t4MyBIT+bZwLl2R7fE3QWDM
         9YjVR2r8j89QIirZzV81/tefv29JQQ8sNqpNANBSL34QuzdHcgNenSkUPCHDMjnhncme
         H220yNXp/YRjwbFCnXVW5nIHXpTW6U2Ox37/C+1+cIJL061l3A1GBwFc3895q5RZGast
         FmEBq3xtTBH+o5cKnJLOeKoGwzfWaC75k0zyliu42YdtEmV3IR3dt3pMXSSxCulUT906
         qx1GbCyvGZo4iqBcWJHiBMBAcW7o3CQLd/CIQTO7Fa20c70j0TDZ9QmIurU3y04HWzEz
         tBsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KobY7OKp;
       spf=pass (google.com: domain of 3jmhgxgukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3jmHGXgUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qgGrHJuVsZ4Ir39LMw6xwVjs6LZHw4QGE06tg2nCy84=;
        b=QL9e3gEWTcckFXTzkME2ECWq1gAoBxZLLRVSl4LuUI0TWVA21TgfMwOrUG3v5GcJ6c
         uQzodrJtlWG3752YnhNzs9EbTiMWoIjybb+ivDPf6GrxLhChCHBhaeMKbdqi747LSDR6
         PKIqEQZBPHKJAWndHHypY9oxHFUFJfhtw6e/AWzuZMDHFdlwKdLoZBI7IsbIqFtD+scR
         IchO65EKGMJRHJ0PX5rG7+YFvPo25wxDkk6aDRT4+bddMxhK8j1Op4T8dt3JaUmUa/q+
         58TOIQ4/r9mVxHVrwNsGsctQLZ0Fu3MHCSa1DO+OCUr0CbjAghPVhKkC5Qw275KgfFYh
         DFHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qgGrHJuVsZ4Ir39LMw6xwVjs6LZHw4QGE06tg2nCy84=;
        b=ubYMVgRjgMuhCWJOlkqunkJ/NwV23zGoM6EOD4jQazOpsInSWTNahTWoylic5yO68A
         LL68mIxtYYO3OBApYMF6Zvn7GlpZgY4sDQWYEdrEMC9HU16RkTf4yNoA2muKO93iBE0M
         Yek1tTWE8dBv0eKLeZ3F2jpnTdzrsqqBeLyIZEXMcfaodGAgBLlggKW4NhcCuGwblj74
         XdHVRzMRzYUNVRwHElrHrH4WKyqbhwmsScI0KSFBMLENDEkhIm5W1iEUILUEtzjDQr2G
         c0Js+SDDyBaItk0MxJc2f6AtllKFRj/wf1X4bUfT1EUYKvCcBo+hbuK1XOuWTSrzr5/+
         Y3cQ==
X-Gm-Message-State: AOAM531MabXEJGhx1lDxA7p51W1YlnFdZjltMGkUlNfPnpGXNrIkzOgw
	1trZcBNFx2HNyeeyNGW9gd8=
X-Google-Smtp-Source: ABdhPJx6sCIOglg+38c8J/iPfdnEcxI00+SWyGtbEeTjFVCnPk3KcLKXjDKgUJvZywAKYyIWeofZiw==
X-Received: by 2002:a63:f304:: with SMTP id l4mr2874927pgh.235.1590059407107;
        Thu, 21 May 2020 04:10:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f04:: with SMTP id p4ls1034857pjh.3.canary-gmail;
 Thu, 21 May 2020 04:10:06 -0700 (PDT)
X-Received: by 2002:a17:90a:30ec:: with SMTP id h99mr3778022pjb.213.1590059406664;
        Thu, 21 May 2020 04:10:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059406; cv=none;
        d=google.com; s=arc-20160816;
        b=x9qK8QQD1FUq9YktiE2EbxECN8PqO60zNPXUVi42NiNP+RATz9PS9nM2/S7x+vBYys
         Fs6+oJ1kO9dB3MNeD49oMrCXvRrKdkaJniRK5aVbHx4opsK8mpImr8C/YRLGZOgJpErE
         Ry14SfzyR/1ISqGIYpTGb0g9SZM5TFsY1egTc3hZ1O1bzZ53567PVJkQoU3WvRGRe81p
         lao+tHTTLJHMQmV9jzpx5NhZRQHnkxBYLGihBz7kZuH0RSNzaIixV7lUjXiq1jieGs8r
         r9PqjRlFzY3uG6qGPAkWpUn7clnYB2CcHrA78R4lr7WEc6XM/Two7Ir3THTCc2HD5F37
         mUeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0j39NvXrsyBh4wsV8IVEExoloRXnW3VKds76JrKCKC0=;
        b=LzDSBDuxGM0bQcGUyvEpSPkEU6p8R7i0CE6FZYflISbjljS1g0ifXk6U7rK0Gz/nAj
         uVcNFwqcfHLSIg7e8n2Wcq1vcRZjlsynyFICdQ/d0D25UczKhLssLPUgW/Rnq7qbAL0i
         vyycBuIcwlb/eVAYxU4fkIHYPrCCgzyqtzriny8qix1Xq5MP/qt0rLlzAI6JRwUuGxAm
         NQz9i8bw4tjxblDRTHUR/WqfWQ774JhKSR8XLBAD++ZXRpDXyUqrSyWDAXZaN9X0AB7z
         uJgpqzu3qt0CO663qLS4vxMd1ihc0YUezmnS1CCHrQSSBXJ011jmmpJBgtkJGcNyC71l
         lBmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KobY7OKp;
       spf=pass (google.com: domain of 3jmhgxgukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3jmHGXgUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y7si447491pjv.0.2020.05.21.04.10.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jmhgxgukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id r18so4893038ybg.10
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:06 -0700 (PDT)
X-Received: by 2002:a25:d181:: with SMTP id i123mr13986899ybg.316.1590059406104;
 Thu, 21 May 2020 04:10:06 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:50 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-8-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 07/11] kcsan: Update Documentation to change supported compilers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KobY7OKp;       spf=pass
 (google.com: domain of 3jmhgxgukcwcjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3jmHGXgUKCWcJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst | 9 +--------
 1 file changed, 1 insertion(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index f4b5766f12cc..ce4bbd918648 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,8 +8,7 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0 or
-later. With Clang it requires version 7.0.0 or later.
+KCSAN requires Clang version 11 or later.
 
 To enable KCSAN configure the kernel with::
 
@@ -121,12 +120,6 @@ the below options are available:
     static __no_kcsan_or_inline void foo(void) {
         ...
 
-  Note: Older compiler versions (GCC < 9) also do not always honor the
-  ``__no_kcsan`` attribute on regular ``inline`` functions. If false positives
-  with these compilers cannot be tolerated, for small functions where
-  ``__always_inline`` would be appropriate, ``__no_kcsan_or_inline`` should be
-  preferred instead.
-
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
 
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-8-elver%40google.com.
