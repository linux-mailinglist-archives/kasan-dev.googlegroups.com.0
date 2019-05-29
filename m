Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VLXLTQKGQEXEHGHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE8322DF9E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 16:23:43 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id s4sf898344pfh.14
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 07:23:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559139822; cv=pass;
        d=google.com; s=arc-20160816;
        b=FLMd0eCRQGHTSuncQyazY5ZOV6Ag722OBrbveuQUOhnDn8B6nqteDZIfM7V9tejti+
         V8KD0MVjqrq3mkemwmo6HHKcUOrNLRiRrUFO19LVRiLKe77Pr1w4TZvmBxSECYXYY3Ap
         E5p4vTegFrdElSeaJg5LRShiLIaJP74dDhfo48Eg9q4xR1QvGqzk2rVtPm6mc/8Xnt9w
         D0jU2EOrzHwDw845hyjKBdVV09kNlfY+DHgW1gPv1gZyj+5d36FVugb5wcorzP3VWutH
         9LBDpgiiI5xTe7Ei1vP+aAoth4msAPxYL4kIOlDOPIViKmDvUfJmxkBe8iHzHCYD1BDb
         rujQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fQ/V+6STJe83CU/EaBkDnQ0l9vUxw00UGGsCKAVYMSg=;
        b=XXr52YOZT1ZrEq2jePg/BZJdjxqqeyW4w9EiO+26QHi0ayQdRo9h3lHs/4xIdkP4uO
         qiZ7bY21GisKLiJ7Z/QTvLpcHJD+Q4Xbj/hMX7c4jxzp/T1dcmmkngOTnvnXvQ+URMnF
         S2qydjI89GRVm0CQAOIWyigb4ck2ommzFeSFslyka1jRT1Yk/V1eiJ5Ztuv8Efo0LxKY
         XQ2rCS7V6Bn7x6psD0buxk6N8vhCC5Iy6AOILJqwfVbYaUlJuXYX9jbZl12Sb59rT5fm
         orqRhWCKGpbYWtpVzhBoyUGoe7vsm5yK8gYzrBaA7q5ffJ+j3DMCB13Fs/p/wQvH330S
         Hf0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YKxGQyRU;
       spf=pass (google.com: domain of 37zxuxaukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ZXuXAUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQ/V+6STJe83CU/EaBkDnQ0l9vUxw00UGGsCKAVYMSg=;
        b=aoA041ZsV4lvpXjPVT90+RTEVtiUvV+GCqom4x44I1Tl5/sewYvq0PN9tG3tDkpWqM
         W/p3BZAyO2oE0T2AuDTd2U5ExGWqqYsms4BPjxVkGrPj9sn+6FfBcHNWqU//QfFe7qjk
         Gonkojvl5jKhhCWQ5x4J8vRP6e0oOT90/HX5jZFizAoy1dx2m4QFk0yT9887VGkQFzg/
         WNdDjebWad/I8dSznaRM2fOuqnU+RnblrWxhumgnNSECYMuXdj1y+9rQlmcWvCl108+y
         NvobY/JyRE4ch9m0b9PeeUWdC3+CvbZ+P7XouLVLwZYx4XF6YTtBLsC3VNkY4fVnROT4
         6tmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fQ/V+6STJe83CU/EaBkDnQ0l9vUxw00UGGsCKAVYMSg=;
        b=hdjn0wPDbrkK61xW6/JaYCF944mbDEiKHBLV8x95xytbY2JnsoI6qp9NdR+4IysSog
         C0jAax4S2HT67UjcKnIs+qg8JpBKfCunDaEq+Phq2OSRfGP5DLTxAdEHSVrFoC7vujAp
         VGhN7TyYt5MyqXSKd3DbXXM6gp3K4U+zysh6GBKjLWlviE5W9UcNtbJWyEZA5zccWdUM
         OJTZIvSnSYTI0mJ3ahmT5+TKT4utfLFVWQRrTT+3pe82q5HIvwoadLIlRQlpkfJPwWxC
         VtwS8gTNUeOqAlDYkMEvB8RWRvED4p+GxqdMUwMIbmgVp6LWgWTpImRjT1MpWVBlgHNu
         sjYA==
X-Gm-Message-State: APjAAAW6ZvZzrLPuaOW58CW6t/WNfejd1dYqO6+KFD6kL2s+eMaUPRVY
	c4M4hlFYcSH+Zc0xjU4bpbE=
X-Google-Smtp-Source: APXvYqyMHmjWaJR8VpuJQ2KnzRUD1I0tSBI8UZBqPKGlHrPqJzC5CNl5xyAn3gMSOAXK1iWrQ8yohw==
X-Received: by 2002:a63:4104:: with SMTP id o4mr20207596pga.345.1559139822540;
        Wed, 29 May 2019 07:23:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f204:: with SMTP id gn4ls587146plb.4.gmail; Wed, 29
 May 2019 07:23:42 -0700 (PDT)
X-Received: by 2002:a17:902:8490:: with SMTP id c16mr6318558plo.259.1559139822138;
        Wed, 29 May 2019 07:23:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559139822; cv=none;
        d=google.com; s=arc-20160816;
        b=nvDIg1IMLS1hw2G5L6+khIKepro3imvhu715Uql2ekAshq6k6t4rgZA4VSAAzM/m/u
         r7P2rJ/iiAOJT9c0w0dxy8kkM8JCWH4sZSrSGeAgO1mkund8E8jrY0ceD2+nfvRiPfOh
         ClF/Jy8TH+4661ZOzLj5QPVuQyXUYZvn5i6o4QCWmw//H+KeNePb/MVcPo/mmhh6eY3X
         zvPQlxEt23RoSpzwdft2S7HvbTDSSVe39XQ4LMy7LiIr/m2zz2FGy3AC4s/LJ28waTUf
         KVtxbEKxO0Y6nlAI83Apy/ca/8HE5Gp7kHsrOBUC0fbc4t4QatQxQdg2Xy6XeJBaM7F/
         C3Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=hnwNAJD4/mUkL54igU9we9Ltgm5eIKoyhCAZZdgQs58=;
        b=gDQS/QAr4XpWGwGsT65GmZLlXS6Jam8QTSGBn57eHZPQVlIiT/V536jOn9+mR23vfD
         NW4H0BAIeS5BkK2EgL4+rEUWtX4/4SiXa7mUYnwHN6q2zPENdYgoM4z0AIfBPG5Az5cA
         YN7+mwFU97ZsONN0eon4r0QlLQ1paaxSfTXWDn+62P2bIA0ovLudTHl9AtXexSxqEvjs
         6qfCJXFsW43HGzMInoAkyKiuzC9yajCNhtEtbPhJRzLBjen4fYpsEMINUrneq2tW5S7F
         vqEZtgsrmDp4thvxdF4CxYeYvqUvcSFe9UjHX5UI6wa+QaBSRJtjaVt+jVlK/KPg/BX8
         VP1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YKxGQyRU;
       spf=pass (google.com: domain of 37zxuxaukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ZXuXAUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 137si58290pfa.2.2019.05.29.07.23.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 07:23:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37zxuxaukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k10so2033047ybd.14
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 07:23:42 -0700 (PDT)
X-Received: by 2002:a81:a393:: with SMTP id a141mr11425823ywh.330.1559139821308;
 Wed, 29 May 2019 07:23:41 -0700 (PDT)
Date: Wed, 29 May 2019 16:15:00 +0200
In-Reply-To: <20190529141500.193390-1-elver@google.com>
Message-Id: <20190529141500.193390-3-elver@google.com>
Mime-Version: 1.0
References: <20190529141500.193390-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH 2/3] x86: Move CPU feature test out of uaccess region
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YKxGQyRU;       spf=pass
 (google.com: domain of 37zxuxaukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37ZXuXAUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

This patch is a pre-requisite for enabling KASAN bitops instrumentation:
moves boot_cpu_has feature test out of the uaccess region, as
boot_cpu_has uses test_bit. With instrumentation, the KASAN check would
otherwise be flagged by objtool.

This approach is preferred over adding the explicit kasan_check_*
functions to the uaccess whitelist of objtool, as the case here appears
to be the only one.

Signed-off-by: Marco Elver <elver@google.com>
---
v1:
* This patch replaces patch: 'tools/objtool: add kasan_check_* to
  uaccess whitelist'
---
 arch/x86/ia32/ia32_signal.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/arch/x86/ia32/ia32_signal.c b/arch/x86/ia32/ia32_signal.c
index 629d1ee05599..12264e3c9c43 100644
--- a/arch/x86/ia32/ia32_signal.c
+++ b/arch/x86/ia32/ia32_signal.c
@@ -333,6 +333,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
 	void __user *restorer;
 	int err = 0;
 	void __user *fpstate = NULL;
+	bool has_xsave;
 
 	/* __copy_to_user optimizes that into a single 8 byte store */
 	static const struct {
@@ -352,13 +353,19 @@ int ia32_setup_rt_frame(int sig, struct ksignal *ksig,
 	if (!access_ok(frame, sizeof(*frame)))
 		return -EFAULT;
 
+	/*
+	 * Move non-uaccess accesses out of uaccess region if not strictly
+	 * required; this also helps avoid objtool flagging these accesses with
+	 * instrumentation enabled.
+	 */
+	has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
 	put_user_try {
 		put_user_ex(sig, &frame->sig);
 		put_user_ex(ptr_to_compat(&frame->info), &frame->pinfo);
 		put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
 
 		/* Create the ucontext.  */
-		if (boot_cpu_has(X86_FEATURE_XSAVE))
+		if (has_xsave)
 			put_user_ex(UC_FP_XSTATE, &frame->uc.uc_flags);
 		else
 			put_user_ex(0, &frame->uc.uc_flags);
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529141500.193390-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
