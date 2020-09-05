Return-Path: <kasan-dev+bncBCIO53XE7YHBBXU72D5AKGQEKCWLIOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id C48F525EB66
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Sep 2020 00:23:27 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id h2sf4662352oop.10
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Sep 2020 15:23:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599344606; cv=pass;
        d=google.com; s=arc-20160816;
        b=iha4SLNOkUpbFnJC82SuJSrC92a3hkGCkPwsJ197Ne5CsIRr0eBRljObtn4xmeyRfy
         KBAlYfduxbr871tTxwuPwe79nsrJWI5/npoWQDBNuZvl0Zd/zhYR6uoRi3E5vcCdIwkO
         IJfkmmTgmNCVsxXnBz97aniQKfTQgG0szG/G+gAnb23a5ZvWafa6x15VKZmthmb7UwbF
         fJ8JTScfPSgoc/OgU1FB1TFSYAZE9j+0vnWxnwcluosdrTQwKUfg9sW0CJSM//xBpR3O
         8i7HzcgMjjHOIz8Js//SAzh7Tdbk5mzljrRnfsTy2Mv7CmY4G4skByKJoZvuX9BhLiZS
         wjNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=92cReWe0zbPl0kX3FFGziItQqt1f/2L4X85qAp/ns3c=;
        b=wQmCct8GF3w39Zh5qCn28AACGKNeogXhhzRwTqm1kbOMWeYoSF+RNgifPeGzLzmHJj
         wt9TRL7OVMJRXlj3SzOLsELyxnC7LZdW8PZkL/m4mPyd3Xl/zlh8v0JMWjOXiaJUYjJL
         qMCHkLf91hWFGA323a1we5UBREVDd64Gu0loHsj+i2Qibj/EE8SvCN3LPwMfWkz7ERRe
         dSobg09kUz0W2LDq/yVQjRqo9BWqpvHm4tEVs2QUXqUJofj98vWfNuXKPEIEL2nqkYjk
         UkoXCSiUuF/Cl5n+35wbVjQ9NRT9jRl9w156V6ZDSNsMZ1FCPhhxOU/HDPBGIs06p4QW
         6wqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92cReWe0zbPl0kX3FFGziItQqt1f/2L4X85qAp/ns3c=;
        b=ITWm9nQbcY3yvhAas0BF/2uRBb0Q01NhhQZxyUV65XEe7nQkbUSETAbz/vpassvmsy
         FUnZ+Hp4yryzss7OIfbUg8Rp3DDade+1bdw4ugnnyDJMQfJ7GjMsbH76rJv6kEcAahwG
         ZEFh9wzm4hJZOTQ0MXs234/zmu3D5botcO66HbXrkJcg9s3rXNEX7GMpALX+Ec4GL8Oy
         v6V1EApknnoI+eV8Y85iuvg//JhsqZt/GadRel35x2hecL3Kwc5ZGPBza7HHKZp0uxyr
         TCi2XqLQGcQem3sLkc6gFzUOI0qd88pjlBiGFSJUNHSBqDhYufKQLYHFfKxT5nDCiet8
         mf+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92cReWe0zbPl0kX3FFGziItQqt1f/2L4X85qAp/ns3c=;
        b=Pk7YEzlwvRNFH/xJj+EWtFladEXK9QZd33AjQgztnePoaAad4S/lqhJ5GeC0D2rxmi
         fmaPQF8V4XYbrHw5Sw9jEI8meT5ku9pHNEtyTSoJOO4DntsZti8uglAW1d2dbksl/ACI
         6OqvBl05Hw7kCltRrlpzJxj4z2dKaX38r0hO24QSkzDvu+s2lWGFjfZF5afoE3vjV6Gw
         q9qreykjRNaivqSRF8RHp2GzshPXqUGWwNecSXn2uAEFE+ezCTH8V4rzUHMwxje4RF9C
         50EXv1DTIFrSziOB6mmRgkTSnC3VU7gkMsGx+EFDUkPZU16aD/Av/rx+pIYzKsddayRc
         UaNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530egDH/Jei/IR72OYKyiETen28C1Mpg9C0x2nUT1aJlSPKsi9p3
	pYA4c2y0MeQypNX+6QYGx4I=
X-Google-Smtp-Source: ABdhPJwXM9CeeP9nIGl9Cp9rmIsST64gVDi+UHUnCYRMatQiPtGCPPW191xsKg1GKZMDTryA1BJfDA==
X-Received: by 2002:a9d:6d95:: with SMTP id x21mr10274342otp.339.1599344606427;
        Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f31:: with SMTP id e17ls3460160oth.2.gmail; Sat,
 05 Sep 2020 15:23:26 -0700 (PDT)
X-Received: by 2002:a9d:6543:: with SMTP id q3mr10428951otl.196.1599344606128;
        Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599344606; cv=none;
        d=google.com; s=arc-20160816;
        b=W+ZOoUOwYeUgjnrqeEDJOlp4Qfr5/DlxsYKPF9BhAuEIxaXGVddcVfg12isPwDsDP3
         d5ijg5qPyujCOTvJwxByvGS2u0oL5DDSC4tTr5DfGdmCzC435Zv6FiQykQcv9AWRU+Nn
         ymWqA9evzsxdyRWCACyCuvCNJP7i9JM2MC0zTDMvUfwFjuWWHkkO0t5pggaBu3wwzTIW
         UranjaJ0EhoBAJBcKr41ho50V9+ErXvq6mbxpYI7gxk9gDO4zgacVUZz2E/to/y7Ffae
         qv0wVxSmq/ohHPk/77+9ydQFk3w/bEll059/CN8Fbg40awei51yh9Qyx2jPzVDWV8/hZ
         8Wqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6VKPGQC771vLuZ22hJIQJu8j65qHx+zzwcv0HoMyALk=;
        b=INeJcq9Kgy7Tpb0dapmGIPu/80kf8Q+KNPz5ZCBNmQ4UjD4GqL95PdVkxYFsrRl97g
         pW8qwetRT/bJeVPhSkwjEmUOEbT5cE2zXtUgX3LVHyCzusDSqZUg3ZvoLWajOrKcpkrS
         T4Jr6nptDAfcDieyBIT7NSkW9CeWSZkWFqfl5Aft1kt4obes4zjArWYZy5SlZYF0ps/t
         W9mTRr75ZPOGy5QmKP12/yHLDcPZlr5iAKYtW36m+LQ3IbTSdZgoNGnrxleE94sFJeKz
         AsRQAdTJWB0SQ90sad8mWj7j09C+i+kq6dfZPhOwXliNdstJoBwR47UPh3vDrXDtd6fp
         uoKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qt1-f193.google.com (mail-qt1-f193.google.com. [209.85.160.193])
        by gmr-mx.google.com with ESMTPS id d11si618046oti.2.2020.09.05.15.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as permitted sender) client-ip=209.85.160.193;
Received: by mail-qt1-f193.google.com with SMTP id v54so7470780qtj.7
        for <kasan-dev@googlegroups.com>; Sat, 05 Sep 2020 15:23:26 -0700 (PDT)
X-Received: by 2002:ac8:7650:: with SMTP id i16mr15068556qtr.268.1599344605851;
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id n203sm7323886qke.66.2020.09.05.15.23.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Sep 2020 15:23:25 -0700 (PDT)
From: Arvind Sankar <nivedita@alum.mit.edu>
To: x86@kernel.org,
	kasan-dev@googlegroups.com
Cc: Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 2/2] x86/cmdline: Use strscpy to initialize boot_command_line
Date: Sat,  5 Sep 2020 18:23:23 -0400
Message-Id: <20200905222323.1408968-3-nivedita@alum.mit.edu>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200905222323.1408968-1-nivedita@alum.mit.edu>
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
MIME-Version: 1.0
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 209.85.160.193 as
 permitted sender) smtp.mailfrom=niveditas98@gmail.com
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

The x86 boot protocol requires the kernel command line to be a
NUL-terminated string of length at most COMMAND_LINE_SIZE (including the
terminating NUL). In case the bootloader messed up and the command line
is too long (hence not NUL-terminated), use strscpy to copy the command
line into boot_command_line. This ensures that boot_command_line is
NUL-terminated, and it also avoids accessing beyond the actual end of
the command line if it was properly NUL-terminated.

Note that setup_arch() will already force command_line to be
NUL-terminated by using strlcpy(), as well as boot_command_line if a
builtin command line is configured. If boot_command_line was not
initially NUL-terminated, the strlen() inside of strlcpy()/strlcat()
will run beyond boot_command_line, but this is almost certainly
harmless in practice.

Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>
---
 arch/x86/kernel/head64.c  |  2 +-
 arch/x86/kernel/head_32.S | 11 +++++------
 2 files changed, 6 insertions(+), 7 deletions(-)

diff --git a/arch/x86/kernel/head64.c b/arch/x86/kernel/head64.c
index cbb71c1b574f..740dd05b9462 100644
--- a/arch/x86/kernel/head64.c
+++ b/arch/x86/kernel/head64.c
@@ -410,7 +410,7 @@ static void __init copy_bootdata(char *real_mode_data)
 	cmd_line_ptr = get_cmd_line_ptr();
 	if (cmd_line_ptr) {
 		command_line = __va(cmd_line_ptr);
-		memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
+		strscpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
 	}
 
 	/*
diff --git a/arch/x86/kernel/head_32.S b/arch/x86/kernel/head_32.S
index 7ed84c282233..2a7ced159d6b 100644
--- a/arch/x86/kernel/head_32.S
+++ b/arch/x86/kernel/head_32.S
@@ -102,13 +102,12 @@ SYM_CODE_START(startup_32)
 	cld
 	rep
 	movsl
-	movl pa(boot_params) + NEW_CL_POINTER,%esi
-	andl %esi,%esi
+	movl pa(boot_params) + NEW_CL_POINTER,%edx
+	testl %edx,%edx
 	jz 1f			# No command line
-	movl $pa(boot_command_line),%edi
-	movl $(COMMAND_LINE_SIZE/4),%ecx
-	rep
-	movsl
+	movl $pa(boot_command_line),%eax
+	movl $COMMAND_LINE_SIZE,%ecx
+	call strscpy
 1:
 
 #ifdef CONFIG_OLPC
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200905222323.1408968-3-nivedita%40alum.mit.edu.
