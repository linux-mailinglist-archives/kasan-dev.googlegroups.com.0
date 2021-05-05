Return-Path: <kasan-dev+bncBCALX3WVYQORBHWPZKCAMGQEDQ6YXPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BF70373D3D
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:44 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id i13-20020a5e9e0d0000b029042f7925649esf1318060ioq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223903; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsJchVAiSrhskZeP8oQCxAuOUgvb9aHFihSXU11aw15IuYnyhB89oj1qRwgUqjfeMg
         GOrjC9/XJDdXvxLO9L0TdoXf4XA8yzpgb/f6U8waua5N2KnE6XJefCGPfNgzR3XyFli+
         tI2popQ8z8+luEVSsPM/A2duWGd9zjN2pYBYW8tWrczMGnSm00OFQT2YmEI4XF7/lT5G
         5cSEHEOAvC6XTJnXC4Q/JIQsAFfFzLlwjE7azQdzZxljwWlopYFzAkvZGZGky6ZHV1Qh
         VI87+mN6D6rbuXobGrWkTyh32mBpUqe251F+XpWMd1fjET2t+RjZEIRy8bO6f2/c8abp
         88Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=L0enF/Dr0sTYIblWIcc+giWNhd8vdKgq/V/9XfyMIhM=;
        b=s4ktefOi/yRPqmVBTi6GS+7rvR77TVaf2NcXQGkUvqS4zFZIQWt8Rxw8hb4yuiDZMo
         94DCX1maCf4Spv6obBXMAy0eG9TNOteWsBXCAJMzp7vWJeg4F0MlCnqjSaFngZTBvX0W
         ezbivFZZbJulV5Zv6fdE0V9EZe47XrpoowgcAK1iIEZS2ohlx939647x8bomOOGEHikV
         ffC/r0q6Xu0OaFj+pPnh42iT7BzVGqXKNVMCVVo/tyYhlhDnl1WJnlEDrcx1aLVNUxDm
         jTq5zT6UKW/ZSfG+wgmhHZwNMmuEhX3bDn6bVdfeByST5ZS8/z/tCuEs1Gz/gsWwUQ/9
         tfMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L0enF/Dr0sTYIblWIcc+giWNhd8vdKgq/V/9XfyMIhM=;
        b=bkwfa1IqjI1o/NE5K56NFZ12XGg/gaKyDVp5/ZcAfB+eDo8EZXH8INQgnWcnnH/kgr
         hWUZef9P4WliwFa+WdsiId4etuMxbF1Lw4f8OOLYXAsqR4oCJjX6w7rr9Yf4BokSdCe+
         Tdxm97ogRmm8/5G/0SWG52aOY0EL+4JEcFBTB8Pcf90RcZb0J0VPkSt/8Cqt66mQ5LJL
         1j/buWymoteApYPvVqMGmgbSodfUsOkvLn+h55v8xOBBoNKgXnVNouIi8FrND0VEJJ7X
         4PCv3KrEgMHXH4a15Va613G8vHmc2seXAZTfHEUNK3WOctLLQZJOf6+wgwNg0Z9+bwEM
         i7gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L0enF/Dr0sTYIblWIcc+giWNhd8vdKgq/V/9XfyMIhM=;
        b=Wj7rw6InOO/AveNHPYv7Bfe5DQwnSERI9McH9GsNu1uxknPN7cWrTpSBYffBxTpVfd
         4BHHUGH1iToF8TGaBAhEPr6UkZd8AB5wny/4wmL5FeNE+cLL8BoJczb8GmHOoFdkOyd5
         E/pgCd78NXKEj2ZE9rHhwnCJRCt4jqcjuimFSfjbaVFp9hqMJddM+mwAf5Y7YI3qqSdK
         wxhccOyujtgdnNv5YCFg4yumI1CcctCeriAqCW/lCAox7/VUc3aVr+8///JnmAKgleC1
         ftc9N+oJDUwAgs1KFT3j1Gc1yjbcvOI8xOCcopoIXR3A1JVQeKQIqeB516e44umlZTSd
         iwNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SU7eGvY8T4+XrMzbE/ifLzmdF0xuKh4uNIUno+pvyfEVXyu2F
	ilNNcNdZitFeEMp+lkOrJ68=
X-Google-Smtp-Source: ABdhPJxsyEPt+GAtiAxSBWROMFHolLBH0Tk8S2ekefV+g82E3YFH6XtTTPVjDF6t+EnLqlVYrJ7LMA==
X-Received: by 2002:a05:6e02:1c49:: with SMTP id d9mr24040875ilg.95.1620223903072;
        Wed, 05 May 2021 07:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2cd1:: with SMTP id j17ls1592936iow.8.gmail; Wed,
 05 May 2021 07:11:42 -0700 (PDT)
X-Received: by 2002:a5d:84c6:: with SMTP id z6mr23271936ior.116.1620223902749;
        Wed, 05 May 2021 07:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223902; cv=none;
        d=google.com; s=arc-20160816;
        b=Mo6G8TR5K/s1FeQN/2k3Uof82SFIKE0DZY4rbbZg1+eUtLE3/u7Ss0Un+9rmlz9iX/
         U5LzQrHIpVhuDYXmbuW2GGcLeO+3x+YjfYMGQNeGa3lNW/0DVffMgTKFA37+lsQorUI3
         flWFzU3hMsV54kJBTlKsDv1K38boM1rCf3TlqVyN7xjDCIODrZtTtso7Mg7ohOXoduvp
         Wk5Ub6M7nlTcePYlUUHI0ZeZN6i+0Ssg56lzHABYoabBtZrpJiGqmvul5EIE1fL5uz+1
         jtU2EykBK/G2UsXtC35NCYU83wjtVcnjY7BPuOuqQQkLDu8uTjckqjMApKEsVsRDglGA
         el4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=fS0TtSsLiZpbFzttcZqcsziipVBhk6kgFX1Hmb7QWLM=;
        b=EcLBmLisfY5LlSkixGoVvO2e//XSU4BqKRnnjUKY3f24zKPowlbw13LcfXWXhA0Zxo
         pQaTdtWI4bAMSaNt6APmhGbAiRk3PUCVSvefiOyQYmHRK3zFGhBiFypfxEFUqvllnown
         VI9gHbFt8AmDoq/CTAuoUoHJQrSNVnDDxMMNMD1hSijCm3U8u4ZoPs8bQ8en5Ht4CM0Q
         9w1m0HWOKVCtXfOSGHUk/NbUa7M7yjr/54aZX/jhMbeOWvmHbTxdc1XfS7Z0deDJBewh
         kTmqeQVlHQGR37er016uTclZ70dOLK+bNYy1K61TpM52gwAm920od/ncZgF/0eik147y
         tt8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id l25si463498ioh.2.2021.05.05.07.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFZ-003DNA-CP; Wed, 05 May 2021 08:11:41 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFU-00007y-Mt; Wed, 05 May 2021 08:11:41 -0600
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
Date: Wed,  5 May 2021 09:10:57 -0500
Message-Id: <20210505141101.11519-8-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFU-00007y-Mt;;;mid=<20210505141101.11519-8-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/QXnIVQ6G593CxEvZS6/KauUA3zjfSAPU=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa05.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-0.2 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01
	autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa05 1397; Body=1 Fuz1=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa05 1397; Body=1 Fuz1=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1321 ms - load_scoreonly_sql: 0.06 (0.0%),
	signal_user_changed: 12 (0.9%), b_tie_ro: 11 (0.8%), parse: 1.61
	(0.1%), extract_message_metadata: 18 (1.3%), get_uri_detail_list: 2.3
	(0.2%), tests_pri_-1000: 19 (1.4%), tests_pri_-950: 1.65 (0.1%),
	tests_pri_-900: 1.40 (0.1%), tests_pri_-90: 54 (4.1%), check_bayes: 52
	(3.9%), b_tokenize: 10 (0.8%), b_tok_get_all: 6 (0.4%), b_comp_prob:
	2.2 (0.2%), b_tok_touch_all: 30 (2.3%), b_finish: 0.92 (0.1%),
	tests_pri_0: 1192 (90.2%), check_dkim_signature: 0.79 (0.1%),
	check_dkim_adsp: 2.8 (0.2%), poll_dns_idle: 0.35 (0.0%), tests_pri_10:
	4.4 (0.3%), tests_pri_500: 13 (1.0%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 08/12] signal: Remove __ARCH_SI_TRAPNO
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-8-ebiederm%40xmission.com.
