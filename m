Return-Path: <kasan-dev+bncBCALX3WVYQORBPEWWKCAMGQE726DYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id F3AD83703D8
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 00:57:01 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id a4-20020a056a000c84b029025d788a548fsf95771pfv.8
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 15:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619823420; cv=pass;
        d=google.com; s=arc-20160816;
        b=KM0F3dU+XYyUYF3z4Jf0nuvo2xlnVdBuXIfcC4wIXVdbfXrBn7HF826E1lAhUNbn26
         keCre/WforMjyISY75tCczwcwQ+g/jH++dmy8rjOzDmBSpHHHWtCwoppKbpdjsCPfK3X
         TWcKF/9s7kGUIoSukS306wON2RPIsW+cfiic5m4XFOePdpZlSeT3zIJWcz7w0w38vY0D
         ho9uUD3DaVthv3W4qUwGLadAV8zan9cRauSv2CqIZ3OxxpVx8fe1GlMSTkZVbi39Cngi
         zHu8vwy6FpjF9/YCOdyl/x5iVpBdly3cc4HV6PQVe9QMMGnURBWXVmHNXFZMj1PGrOCr
         OXTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=hkV5AVSbKrCXw99hdbk/G3/qswVIGkPdbcUuV2mDEU8=;
        b=q8b1N65/wJcfVw05OAEMk3PjOB5PSCWmiVThmpBLnNScFEsAEhBoelVUZFY98GVlqQ
         +ZVxn+DJoi+Ui6zo3ekeAFrdmAFYVK7lAPfFgDfcaGEI/aaY7tAuEXc08cZyi4WmApj7
         lrUrUaWrgVjH60BAYDWBWC8N8nUbboiKocsRewDoLmftFKIaGMV7xgq3ZbUqJqGlZHJQ
         FMhLu5B/x2FRPnBuiAGKcDRAJ6+YVCo8WJXTcy/dUFjCbieuwbr0yc0SOj1XBBN5Bp4S
         o7AvGJMNdQRDVwphJQ5oAeCtK8IoZTw07XetUYElpVkhgBXgSKUOK/WBjbqLGkFviQlu
         faFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hkV5AVSbKrCXw99hdbk/G3/qswVIGkPdbcUuV2mDEU8=;
        b=i8Z3H+JKlvWK2htk5gpjuDMohCGtAJLKFfIrkwcy+y97s5gyMo6RfwRvBgXX7FWrhX
         jyFK7Kb1DlAJOzS+jAgh2YW+quJKokMp5NJF/YkhQdouQyFvucdkE26ZzPhIKFyWm/wn
         S7L6Zzoo7ANB2gr2msH67IrNxOtIW7ftk6RTNNmqZxZ+uggPU+Pq+yG7gh+8/nj5NeZ+
         EWkV/kK+wC2EOt7whimuCAq/HaUp7QAgO+CzDhXHfLRYh9AjRWsWH1NUSF8wxfSbudBf
         u0BB1+dW/f8Q5rJgumcb+wFUHFnX269vHh5pDZ3+WYGD+G2zm/Y9M5d/mao7LbgDQEhr
         0cQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hkV5AVSbKrCXw99hdbk/G3/qswVIGkPdbcUuV2mDEU8=;
        b=FOXW8yBP/0M1ulCV7pZYgErs4DM4s2DE6oKxTKX1kFa8EvkA+N25CiznOgH2WPEaCF
         zzUxXaYo27uHieHO2u7zeq8lN5FCFLen7vVVjdPJRWbOrKfrDkaLvXEeZET8OugjN+EB
         ZGQQmm7xXo3UQpbpabxJ6G/B6kyQYhYZOtH7J112nIAry+/jEzLkZGdDQxDD94/0ELLN
         kB/C40/1emgfbfKmIRrXxtRpnzPfct05ytO89RiV+1+NMBwCU7jNKb329HQA0i29/Rit
         Z5CkpzrgrBltzvfP+tbvWh5Iiv5ZpfXKIj2n3dsAR0whpWclpgnMaGSnRbRfgqObVXyO
         qJ1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GELXbB2XHrtxVY4fZHGmsOWzL0hSTpZxk1EBLSvdkR0u5poRS
	PB04J5J9pjVp8v4CmKK1nhE=
X-Google-Smtp-Source: ABdhPJxe3sB0HPPad9I1GXllf9Zf/RZDkAINxifw8RhNJgJMlK9nOchgmhnoT/aI6ftcMarJvopOZA==
X-Received: by 2002:a05:6a00:170c:b029:225:8851:5b3c with SMTP id h12-20020a056a00170cb029022588515b3cmr7218412pfc.0.1619823420746;
        Fri, 30 Apr 2021 15:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1d4a:: with SMTP id d10ls2993543pgm.8.gmail; Fri, 30 Apr
 2021 15:57:00 -0700 (PDT)
X-Received: by 2002:a63:f608:: with SMTP id m8mr6571876pgh.54.1619823420180;
        Fri, 30 Apr 2021 15:57:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619823420; cv=none;
        d=google.com; s=arc-20160816;
        b=x3Ezgkt9Cq9hDgDKV9hd4UePow5/PtKTPbYpVocVVi7L1WwWibFWPwpH2bEwpSUSJ2
         yJ5BnWEOK5JxD2Zcnn1mwbsW5vncmua64xwQV9nG69djhxg5h0rsjHYqnH9EB30AhWTp
         ISxdnWzpRDrbjJgo3AVhvL18Kl4katSWOwPMDVTOfRQl8vwnz0P9PcThVfTeBc9++P4R
         aQNnutcoovWByxhIdf8NHAMPoixJCKG7H/JwIj4Ov86hWkZGEO/gAB+0+opw26JEHgP7
         inIKgTFAsjcJlw2nYUL+3HSPRR4R2XMZ8MjlMF5blaLuRKQO61sV1oqEIJsNQ6iWGa6l
         mp0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=1sC9KHWcCtjWfBZqSqn4NwWLO28ieRjDhWrNE9FWJy4=;
        b=u7YQfOQTd11NDrXXRfqnz/vjRj6/CbwLgnxxNrBuSziFgdzvwQQD3j758nYCDR2QBL
         8iFdmRjJWhtsa0dPfM74eBIKlZIJHiE8jFVDGXut9sfIuUFDPRUldGpLN9Q2IUcVuRVK
         De3TfLbgwgMFDK1T9V+ocpfx0+MGK8tP+zshngkRPUa71XKg7hNgauvm9kRmw1az2Phb
         l1Jy9liy0f/4QnJEZ7J3Frc8xmAe8e9NdW135yWb/im82o93seWJt9hOYkFB+cZyME7T
         UPuuCadVkSdstbRS/3yg8qBrTapxPTPC58onexJTYQoJedsFeQPRR4R5kpgAOPoel9IM
         XHxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id a8si728589plp.2.2021.04.30.15.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 15:57:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out03.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcc4A-004BNH-0M; Fri, 30 Apr 2021 16:56:58 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcc49-007EZu-4g; Fri, 30 Apr 2021 16:56:57 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 17:56:53 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m18s4zs7nu.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcc49-007EZu-4g;;;mid=<m18s4zs7nu.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+BMZLJbzu3OHJko4MsxvJEsyXiW561s2M=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa04.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.3 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TooManySym_01,XMNoVowels autolearn=disabled
	version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4900]
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa04 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa04 1397; Body=1 Fuz1=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 309 ms - load_scoreonly_sql: 0.09 (0.0%),
	signal_user_changed: 10 (3.2%), b_tie_ro: 9 (2.9%), parse: 0.74 (0.2%),
	 extract_message_metadata: 9 (3.0%), get_uri_detail_list: 0.95 (0.3%),
	tests_pri_-1000: 11 (3.6%), tests_pri_-950: 6 (1.8%), tests_pri_-900:
	1.54 (0.5%), tests_pri_-90: 74 (23.9%), check_bayes: 72 (23.4%),
	b_tokenize: 10 (3.1%), b_tok_get_all: 7 (2.2%), b_comp_prob: 2.1
	(0.7%), b_tok_touch_all: 50 (16.2%), b_finish: 1.20 (0.4%),
	tests_pri_0: 179 (57.7%), check_dkim_signature: 0.62 (0.2%),
	check_dkim_adsp: 2.9 (0.9%), poll_dns_idle: 0.79 (0.3%), tests_pri_10:
	1.89 (0.6%), tests_pri_500: 14 (4.6%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 4/3] signal: Remove __ARCH_SI_TRAPNO
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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


Now that this define is no longer used remove it from the kernel.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m18s4zs7nu.fsf_-_%40fess.ebiederm.org.
