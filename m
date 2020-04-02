Return-Path: <kasan-dev+bncBDY3NC743AGBBZMYSX2AKGQEYEPWYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CB58019BA41
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 04:22:30 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 60sf1944870otp.16
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 19:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585794149; cv=pass;
        d=google.com; s=arc-20160816;
        b=cDXqnuaiCe6hziaLEw3VRG1RMtqkANylJuRL7bK3lsFAx4mFuhuEyEbwDRDVvfAezB
         //RgtB39FLUd7+Sfj6cBVlOHRyLXEQ32Ix1t0uVDHyjYQf6CuuZe+lNIjolBPe5ckZYe
         nYl9RM5x/1OZR69ueBxIfFHDwSp2/TD3uSJNFHRGHBJK9JfajLQJqo3dl7hHNfE+Qnn2
         UdyhMRIuG2bPh9HvKrtYE9Fco8+6Fw8M641QQf+sD6tFVyuSbrb0kr5b7bO0ErUk3iBv
         IPNpDFwAwzTHzlHOvm8FMDFRLvaMbXvQaYUBycs3AFSDLgDyrHypN6MLIpZsXf8nnUW3
         JJyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Um0Pc7wWDDvhtsm5YNCjyGbClwpHlma2YZZrEKyWHGk=;
        b=PF9WmAfwWXNM9TZLW437mECVsh08ATErW7A87qnMpdwqGWx7zr076W6IFQaW3buyma
         xpAFYxpngLyz/YMcW/DyofMXfKIHH9Sapctq+aHqDHhw7cUvx92R39WbyYQzplz81TzV
         5BWBw57/3Yf37UMx3HzJrA5Z+nKCiDTHEMxd6ldzP2e37m04mHldCW9cTDkgw6tO20MN
         W/coBGXm0cuzCFvruKvKzgV4EC9ASXHTE/kCWJPg6snotncmx7BdZZuMMB+/cqX/yQtx
         xpg9ekfM2lRwJ/gjsjI/BOz0t3WIjI+IPxN27pqjGNmfnqTSseZdRgviEwJQDk6o9D+M
         gIqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.192 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Um0Pc7wWDDvhtsm5YNCjyGbClwpHlma2YZZrEKyWHGk=;
        b=VCfxl9JVIhm35UzYKncrQV7oYt+vM7mAYZRppFOQXiSWjutGutwdT/d8m+homsAcA9
         +8a3iqKGWZB3iG9dq3TqLGwMl9RnAuJi+J6ATbUhjOLRJwIPE0P5e7ZK0TNj6as5YCcX
         0sizj6KXnslr46p+Jdtrq+8vnPWX7thdwopd5xg3GJ1XXoJRT+y0tJVFt2XzguUfZ7rC
         4hBgnZGq3pprpuOK/xXoSi4ZucsSX1gwwGOr8/xuGDyiR8v9rk5qQ1pfndJFYNytx3Gw
         cQGwHjIbWXlToLuAXiYxQPmxf0QYZO04jqodfWNkhxRnC+dkXgl6ctw49bOivY7i0CrW
         2m1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Um0Pc7wWDDvhtsm5YNCjyGbClwpHlma2YZZrEKyWHGk=;
        b=qMS/HCjSC9yQXWzYVW3nvGTNQQ7dlEI6rYtpzPTtfezRb9Q4rg+oJIhBt6gyGIJYXP
         gxRG+/aycbZO2hE7l8uh+oUPr6bxtulKqlKCeeIoTqA+TxkatUWEgja4/4jsRqxdog/0
         qRQT9RlCJl5HWt0pAMauwd1zfjTtfPcMfbfLLT2j1IBBmUROmaRI8YMcdLtGsXFHhtN0
         aFcR4EFxImE/Icy7Y2XEhEK703TSAVSU0lF/0P3lipzqXRAaBix8Rey6yqj91g63UD/4
         b1OLAQfgAz3RYC9vIzDzExA1bjXyYEELmCpF3UmlQuw1WkRXo9YqyhJHA5JdHSawMxSx
         37RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubY5cAYNkhcxPoRkYH9ROmR+QbEs5r/nMXrzgieq22PMsiMQdPY
	HbTs0X4ddUVhaZ/UD5BM4Zo=
X-Google-Smtp-Source: APiQypKeVRG1MEgUV7S5fQRj1Si4qY8yAKgXalvOmtHdhFCxBrbnpjnvnvSmckmlm9rx4oHaAoMbzw==
X-Received: by 2002:a9d:2002:: with SMTP id n2mr717643ota.127.1585794149630;
        Wed, 01 Apr 2020 19:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd02:: with SMTP id b2ls1017458oii.2.gmail; Wed, 01 Apr
 2020 19:22:29 -0700 (PDT)
X-Received: by 2002:a05:6808:207:: with SMTP id l7mr708287oie.171.1585794149118;
        Wed, 01 Apr 2020 19:22:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585794149; cv=none;
        d=google.com; s=arc-20160816;
        b=MhWXpSwVek4krDWRs9jy9PfDgJiAUjpY0XVyVEGf4blvM6vHM40gPkZ4tG8A0w1cjX
         EBqj4xT64z5F972ic2LIEzzOA8VlRwzWEO9Z4TvmmDjenL8O5AjO+QiQUK+GANZ18Nr8
         vz4yk8+3aN5Cob8lyCiYVw/H+mhwGsY3b6+kXH9cOic5Z1eZ2VQ2vjooI961AoYusTd6
         MMl30JpiB97d5tVk2swb/Tc3AHxrkh8LxiDrxIVborFqFO/AvIDGw1mgVH5uInD8DNSx
         CfZ+AzfFnT1yxxvPqhEss39UpGuS4Ksr2FYya+LGl5leXP6qi31/95zlFe0k60uPklYI
         D7kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=qC5sDmPx3QPRvfvZHrKK6QaRBsoP9i50Cm3A7tJ1+ko=;
        b=vECQBfS3nMwFYJ7hnMcAzXYP/rb61RmticMG+iF1nDXhw8iOLDlHAPl+fMXpj5ghj6
         Qmr7z5qO8r+K/ZRBX4BIeOxj1W72D6GPJ5EjJDryLQdQFYbSbvja4A0pE1Ft22/wospi
         24UkI7crX0mlzdBiIW1W24nfY4N/g5n6l2NChnxUCIhtrVzWiuRtPohjhtx9pQxZEM+O
         vYePTRU7r5+q47l/p/GcoXDt8cyR8YsfC8gD6OxNJcKlFB2KKf3EGnFXvYd4hzPKqIGp
         Pq2HPBU7CbT3ST9idTL7PgomoI1YPpVqfzIU+TS5mxiQYNz6A2SqohAHQ5Lf13zLAJlc
         i5Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.192 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0192.hostedemail.com. [216.40.44.192])
        by gmr-mx.google.com with ESMTPS id p29si240271oof.2.2020.04.01.19.22.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Apr 2020 19:22:28 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.192 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.192;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay01.hostedemail.com (Postfix) with ESMTP id 2CEDC100E7B40;
	Thu,  2 Apr 2020 02:22:28 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 2,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:800:960:973:982:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1541:1593:1594:1711:1730:1747:1777:1792:2393:2559:2562:2828:3138:3139:3140:3141:3142:3353:3653:3865:3866:3867:3868:3871:4321:5007:6119:7903:10004:10400:10848:11026:11658:11914:12043:12295:12297:12438:12555:12760:13069:13161:13229:13311:13357:13439:14181:14394:14659:14721:21080:21433:21627:21939:21990:30054:30070,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:2,LUA_SUMMARY:none
X-HE-Tag: eyes58_154b705020d2d
X-Filterd-Recvd-Size: 2647
Received: from XPS-9350.home (unknown [47.151.136.130])
	(Authenticated sender: joe@perches.com)
	by omf07.hostedemail.com (Postfix) with ESMTPA;
	Thu,  2 Apr 2020 02:22:26 +0000 (UTC)
Message-ID: <65cb075435d2f385a53c77571b491b2b09faaf8e.camel@perches.com>
Subject: [PATCH] checkpatch: Look for c99 comments in ctx_locate_comment
From: Joe Perches <joe@perches.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: paulmck@kernel.org, Marco Elver <elver@google.com>, dvyukov@google.com, 
 glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, apw@canonical.com, Will Deacon
 <will@kernel.org>
Date: Wed, 01 Apr 2020 19:20:30 -0700
In-Reply-To: <20200401153824.GX19865@paulmck-ThinkPad-P72>
References: <20200401101714.44781-1-elver@google.com>
	 <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
	 <20200401153824.GX19865@paulmck-ThinkPad-P72>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.1-2
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.192 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

Some checks look for comments around a specific function like
read_barrier_depends.

Extend the check to support both c89 and c90 comment styles.

	c89 /* comment */
or
	c99 // comment

For c99 comments, only look a 3 single lines, the line being scanned,
the line above and the line below the line being scanned rather than
the patch diff context.

Signed-off-by: Joe Perches <joe@perches.com>
---
 scripts/checkpatch.pl | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index d64c67..0f4db4 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -1674,8 +1674,16 @@ sub ctx_statement_level {
 sub ctx_locate_comment {
 	my ($first_line, $end_line) = @_;
 
+	# If c99 comment on the current line, or the line before or after
+	my ($current_comment) = ($rawlines[$end_line - 1] =~ m@^\+.*(//.*$)@);
+	return $current_comment if (defined $current_comment);
+	($current_comment) = ($rawlines[$end_line - 2] =~ m@^[\+ ].*(//.*$)@);
+	return $current_comment if (defined $current_comment);
+	($current_comment) = ($rawlines[$end_line] =~ m@^[\+ ].*(//.*$)@);
+	return $current_comment if (defined $current_comment);
+
 	# Catch a comment on the end of the line itself.
-	my ($current_comment) = ($rawlines[$end_line - 1] =~ m@.*(/\*.*\*/)\s*(?:\\\s*)?$@);
+	($current_comment) = ($rawlines[$end_line - 1] =~ m@.*(/\*.*\*/)\s*(?:\\\s*)?$@);
 	return $current_comment if (defined $current_comment);
 
 	# Look through the context and try and figure out if there is a


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/65cb075435d2f385a53c77571b491b2b09faaf8e.camel%40perches.com.
