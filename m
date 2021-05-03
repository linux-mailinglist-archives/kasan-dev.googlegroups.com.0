Return-Path: <kasan-dev+bncBCALX3WVYQORB4V6YGCAMGQECKJARUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 633B4372187
	for <lists+kasan-dev@lfdr.de>; Mon,  3 May 2021 22:39:15 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id e64-20020a9d01c60000b02902a5e0014358sf3112344ote.23
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 13:39:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620074354; cv=pass;
        d=google.com; s=arc-20160816;
        b=MSjryYtRI+oEkBSmJ6oVcE9jTWIBWUpqnLtxg4SDnGOamWLVYrVhzk4lNjecYSiJVF
         ts+9ppXeCcdYfzxsGfRoHJPYEoOfW42O3EXSfsf1tSqWm/O0adCMD1OoGNdHRDARkazi
         d8SpiH5ilcIkq/Vj1l9eE/lWpSEtWmUQcrJSTOvp5qoxv2ebty6L+CZpunPOhoTF+5VA
         B1YbQnQlNZMd8raL9UappInxt9AY49bCCVfKeAuajeF3RIRZzWf2QxOU3mCgJ10ADIeb
         DEtRnvR0vsluRSO9YUgxyYsUXrev0olpN7svIEE5ZtM3BiDZRd52Tl/CHHwpNRrnQwfo
         PiOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=M44dp5XZR5s20yGYaRxaNdanJUedD840cZWYHB/gY+o=;
        b=y42qFnShgPG2mqIUgyKwrGUEqrh9PX3svaFFWogre4xh+Ckl7vSMcPSpaEvswRTTdU
         QzUUjHVgXwMEgKYgvKD2KuHGSHNYht5BDmFdTENwRSafvXx51BDemojnnvTpoQW+03t0
         t/3O6paXxt5sSl8Et59vDNK4j9aVynVC0O0dYdq/7GFzpCBVr3052oHotK9ZbZGm57Ay
         oT9qpjEIhBBHn8Ueq+pamxDYjaWOmgPHWak7GfA7VvQnU80vciZkpMPSqk7c6ymw3b+F
         yzdkycONJcIh+u9QA15gSkkS2w0A/ZlgkWwMwQyEV+UOiEDJQIpfyxd8VXf9iMg1u4kc
         0rHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M44dp5XZR5s20yGYaRxaNdanJUedD840cZWYHB/gY+o=;
        b=Hq03AVTCnaMq2C4/AHJZ1PLBmvdtAv1VvLdLhdB1CknQYMxMqvtQdvKcB8n6b89IQ3
         A3ILt0IQrvh/1A/hb329MUDjEm+zwWSvfbmDnbgZXrO667fBeyKrTZNUr9w8iW9gOtaK
         Y3/YWSGJL4n0mdOzZK5EKIQLl14obYkd0SNqM/jFJ1fBh5oorZqfPGQwCkO8wubKQ9LK
         7INODIpY/q6LZrEyrsq0QmTbRkypMhahC7BBS5Nfw98oIdzFvvqNFRKmhuQ/ckBGJTR2
         bfFu2NdiOTbmXj3tXPbFznRRhqb2QXoHco2LY1bUqBxK7HvKicgZh1yTU22kZjZSPsJn
         V2nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M44dp5XZR5s20yGYaRxaNdanJUedD840cZWYHB/gY+o=;
        b=RKNDt1dHr+0YcsVnhmFIpZJw6qhmPJAwoAPrXD1WclLBTX/uqxXEXDINbUuNareUvO
         KU+QfV/Xztg6M8ZY4yOiobZFqbkmsPYYjzZAy2I33uSOKoqypoGFhaan9V1tTRM44aG0
         CBMdn+plWZr0YK7rJ2S9Nz4NtSPDJGoaiZCmP91rUf11aQdbwqublQp2InAIhUFe4s89
         xWjILUDjgeFnK/l30OlvfsJnpL0RxpHzRWlRNa+wFsyJzaLJjynDvfLolMfAwwC6IMXW
         DWn5DOeI6hW6Wi/CDiWtp/vcdr5U1Dkpv0XhnEt32z7A+OqSssaUyHkPDzj9PelbkQQo
         LmGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cLX+j2QD0FhNf34Cb7n4R2rO5pK/JA3UqBkH4TljzBnagaW35
	SFHv1Bdu1Tac1tn1sbpOX7s=
X-Google-Smtp-Source: ABdhPJz9ybFpYZ9E6QayjxnXd/EqMdDOr3jXw4WRiG/tGPsAVovT5Uy+I+4/4WKWfrfj4E3tgCakvQ==
X-Received: by 2002:aca:1e16:: with SMTP id m22mr14964178oic.153.1620074354323;
        Mon, 03 May 2021 13:39:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b4c2:: with SMTP id g2ls1095626ooo.8.gmail; Mon, 03 May
 2021 13:39:12 -0700 (PDT)
X-Received: by 2002:a4a:96a8:: with SMTP id s37mr16711143ooi.60.1620074352900;
        Mon, 03 May 2021 13:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620074352; cv=none;
        d=google.com; s=arc-20160816;
        b=LoRs3AAJY2et4lkl3gmgVuMDuD0l3OoiibUpRSkPiLq8smEvSAdkjjgEHZSKYRFwaP
         Odspo3OsG0DTo0Hellmq2FvO8RfmwsSW9sfyxwPkWfreGIJR9IowCuyTrclwSUSsn023
         p1giOZDeSLMLSpqZDjkhfPuPW4wukokf5CaC2wHP9baPc/QCsXWHmNJDz3ucpEDw+9+g
         XXU2SUYAxCrGbZ84MvHvVlgpxVpAKoiMLPGQ3X6ycKGHv2Xl20exQ0DwernYq7ny5tVk
         phuBm5YMGUmIxiaIKkkO7OoRvBrwZzw4Ha/oKd2nk5sT4Gx6i3Ksk6adNmMz4/A+2GkB
         jbrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=fS0TtSsLiZpbFzttcZqcsziipVBhk6kgFX1Hmb7QWLM=;
        b=TFcoNKhWaHUONTgYzWHUrhCMpI11lCCDDJPS0NSNXOdHXpF7WelCIRxkouME3DOpSP
         cjhY8rtZX6+CNCs2Fhnxm2r6NQBkSxZEChPDVUBnW15l3tdR7ru4wu0flrcXeFa3PADT
         KJhoBbjMMCVMluYSrY7OVJExxPWoGw2dkZQaMojlyNJ/iTrpBpGalvW/0dXhYq7ladgj
         P9iwIpbPAF4nJeiQWzCqL6jWUeqPn55VAeQaXm+gBNRP8/5BhtILaMJdYzmgzJ5hFP03
         hgIDHqWpvMutytH2L+HjZ4haeLixyR7FK9kSrWkDNUTlQc2JyRWlKLcm3UAQH+Ejq1pN
         EShA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id b17si53523ooq.2.2021.05.03.13.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 May 2021 13:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLS-008icb-Hj; Mon, 03 May 2021 14:39:10 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1ldfLR-00E76Y-Ig; Mon, 03 May 2021 14:39:10 -0600
From: "Eric W. Beiderman" <ebiederm@xmission.com>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>
Date: Mon,  3 May 2021 15:38:09 -0500
Message-Id: <20210503203814.25487-7-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210503203814.25487-1-ebiederm@xmission.com>
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org>
 <20210503203814.25487-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1ldfLR-00E76Y-Ig;;;mid=<20210503203814.25487-7-ebiederm@xmission.com>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX18FP4RNUbzM/PkY8dB6ZN9AdHcHvOZHhDc=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.3 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMNoVowels
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 318 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 11 (3.3%), b_tie_ro: 9 (2.9%), parse: 0.83 (0.3%),
	 extract_message_metadata: 11 (3.4%), get_uri_detail_list: 1.32 (0.4%),
	 tests_pri_-1000: 13 (4.0%), tests_pri_-950: 1.24 (0.4%),
	tests_pri_-900: 0.98 (0.3%), tests_pri_-90: 52 (16.3%), check_bayes:
	51 (15.9%), b_tokenize: 7 (2.3%), b_tok_get_all: 6 (1.9%),
	b_comp_prob: 1.70 (0.5%), b_tok_touch_all: 32 (10.1%), b_finish: 0.95
	(0.3%), tests_pri_0: 217 (68.2%), check_dkim_signature: 0.46 (0.1%),
	check_dkim_adsp: 2.0 (0.6%), poll_dns_idle: 0.58 (0.2%), tests_pri_10:
	2.3 (0.7%), tests_pri_500: 7 (2.2%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 07/12] signal: Remove __ARCH_SI_TRAPNO
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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

From: "Eric W. Biederman" <ebiederm@xmission.com>

Now that this define is no longer used remove it from the kernel.

v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/alpha/include/uapi/asm/siginfo.h | 2 --
 arch/mips/include/uapi/asm/siginfo.h  | 2 --
 arch/sparc/include/uapi/asm/siginfo.h | 3 ---
 3 files changed, 7 deletions(-)

diff --git a/arch/alpha/include/uapi/asm/siginfo.h b/arch/alpha/include/uapi/asm/siginfo.h
index 6e1a2af2f962..e08eae88182b 100644
--- a/arch/alpha/include/uapi/asm/siginfo.h
+++ b/arch/alpha/include/uapi/asm/siginfo.h
@@ -2,8 +2,6 @@
 #ifndef _ALPHA_SIGINFO_H
 #define _ALPHA_SIGINFO_H
 
-#define __ARCH_SI_TRAPNO
-
 #include <asm-generic/siginfo.h>
 
 #endif
diff --git a/arch/mips/include/uapi/asm/siginfo.h b/arch/mips/include/uapi/asm/siginfo.h
index c34c7eef0a1c..8cb8bd061a68 100644
--- a/arch/mips/include/uapi/asm/siginfo.h
+++ b/arch/mips/include/uapi/asm/siginfo.h
@@ -10,9 +10,7 @@
 #ifndef _UAPI_ASM_SIGINFO_H
 #define _UAPI_ASM_SIGINFO_H
 
-
 #define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(long) + 2*sizeof(int))
-#undef __ARCH_SI_TRAPNO /* exception code needs to fill this ...  */
 
 #define __ARCH_HAS_SWAPPED_SIGINFO
 
diff --git a/arch/sparc/include/uapi/asm/siginfo.h b/arch/sparc/include/uapi/asm/siginfo.h
index 68bdde4c2a2e..0e7c27522aed 100644
--- a/arch/sparc/include/uapi/asm/siginfo.h
+++ b/arch/sparc/include/uapi/asm/siginfo.h
@@ -8,9 +8,6 @@
 
 #endif /* defined(__sparc__) && defined(__arch64__) */
 
-
-#define __ARCH_SI_TRAPNO
-
 #include <asm-generic/siginfo.h>
 
 
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210503203814.25487-7-ebiederm%40xmission.com.
