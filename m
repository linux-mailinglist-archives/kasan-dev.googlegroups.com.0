Return-Path: <kasan-dev+bncBCR6VPHHTQOBBQXZXSOAMGQEOHG7ORI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 91A166443C1
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Dec 2022 13:59:47 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id 89-20020a9f26e2000000b004183c5c5b7asf7523145uay.10
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 04:59:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670331586; cv=pass;
        d=google.com; s=arc-20160816;
        b=jW/cAUztmux1JPoyfaO6W/FdCxn7UR+lyv5H5E1jm+WBdvGJ4p+p2Gu0mnFy3MARHj
         F3ZS2pEMMgv3VqcYSzkEuzBEdvsOMeWJyaLRh7cS8WyGQbaG3erdakhnWVCU/Xcdhi6Y
         Siu376EeZsTchXPDtGPKOzmeqqxkjVCNt0HTHmfsF4Gqv4zc6+S82QBCVDZG3AdODPo2
         eC+AnbrVc864KMDZgR59lk5Qg3eOI4z4ESZdpSFZN4K4NpZVDRCB5ZvdK2maTWLARG6q
         wJDXXSB5CXSycZ9f2uyr/F6eqn2WfM4fnI+Mq0dy64CEhMh0rO9AeDv2N2P6vXoTrxkZ
         gs+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=opbGQbHB6ujGI5cOP8IOPhSSfowjQm9sesAAlR/YrQs=;
        b=0+cY73j/Z8JQALFrH3IndfgsWBPACJ4U5LsigIeDoEA+0W0sJnwZNC3ZKCB8NULVSk
         wNxyUssRYmLtosmLjKnF+69Lv70N7Hro4A13i52Lr+2yXzH6uxsasDWz2LDDbBgYaWIj
         VFZ9xWmjpA1GCdxo84e3Vet7aTubVEjqFkOXmsyCfJYBR/TfHdkZHkQE64yAmOc/OChV
         Ja0OWaImMj+VvuAfmn/HOjewZx8arvveEoTHKDnvEix/4uKg1OZVFlhq5HnGj6AsIJFX
         O5iZ4IPV9jx/mm+Ht7W7WVNcVX7pMlYU96nVcZV7PbjfoAfSfovIPFVjPFf3UzGug+QZ
         n95Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bFBCIcEG;
       spf=pass (google.com: domain of zhiguangni01@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=zhiguangni01@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=opbGQbHB6ujGI5cOP8IOPhSSfowjQm9sesAAlR/YrQs=;
        b=LUh21KoWvjdVK6IIpEq+H/SFoAknw+Zu+maId+A3Juts9yFBb/lm3GnC7dQiQYDztL
         Wi3uIOYZS6lnvjhb4J0l9669nTqRFP/PV6Bk0DTPfDsWkaRFzVyASU8DNKkcRCqKYB7F
         O6wp6x1UpmpZc23jeqDeOKbNoSIPn2r/S0hFrkw3pszS/oWJwriYW2jKfm1iahvjCw+m
         +OoXGyvjt9O8M281Be5ALYRfubkKp8s8v1eZqpQkCSxGe+XH0IlU7J7n6lwqs1+nHBv2
         1wtjZtKcbKw2L0ki5xIwoXr9AKE8ecS6qdoCivtm7bTjvHbpMGywwIolhg9cMZTtciCj
         us+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:date:subject:cc:to:from:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=opbGQbHB6ujGI5cOP8IOPhSSfowjQm9sesAAlR/YrQs=;
        b=Q3tY18oZIjtvkb2z2fxMwQ3z8GF6YG7x8rJd7734QOYNl+65ej5v1II2nzqbhkvL2n
         s7xYahIsgADAG/eUuYkWm+aosVgUMDN+3oBi+Sa2AWj2Nr+vlQcjZZgm86TK+6E03HFj
         WfL8xYCiHXe7cUlwlr4sOlkshCsQ99dDSL4W+vnuOEasHqe1oyLxLvM7TUMHtDjO4TnI
         u/r9toYi6qNgVJTwGspgK+DM90XnAFYEwDrWzMSYkxOmm5LCW/aRdtPNNJJiFeVr7ZF8
         /v/QgK11wBbwEkg1+lP5ADwM9QICFNL7v0+CwFs8zeJcesXVFcAoyw9nohzyArTnej+7
         +R6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id:date
         :subject:cc:to:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=opbGQbHB6ujGI5cOP8IOPhSSfowjQm9sesAAlR/YrQs=;
        b=mIgW8DYqzl2KW3YW9lLSMaiNSvXxzSr8XLw8UJ++GIxGGQVSE7/wNuMDlBQXKr0lMw
         ym1eeSSdh4dNnI8g99tgGjCS98uEbWiF3GNCBkN+hlFUs2jT9K6q/j0cLy88417kojsM
         bKe4kbcq8tGpVwpTuA+CeQV9eCvzlhMk3nwu+CiXMDEIKM0xCI5Cw25zf6wrtUjqG8il
         ZX0S0JGBzl6tXH5DFnLD8b6Sbf4v61jZL8hED/882ChK75rDgBbVnpMRobdAZHbcKTch
         VMM5aCEmp6N32RBm4TrhCw37OnpckFkTu2reygVTgKuJFlFlMPAGrgpJThhhCE/RJmZB
         oJhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmOmxujyP/DGKxUO+tP3WMfjncz5bUZxP8ndlaaNO2MYYApGYpZ
	O4ALsOTP74jfxezmkIkTe04=
X-Google-Smtp-Source: AA0mqf6Bo4DI4Bo4swl8mLHdwqOjoAN460zc6pj0LowJcHAQmTJdiQHC7zS/OYHYxoa5a2R4VRY0lQ==
X-Received: by 2002:a67:b90b:0:b0:3a7:8ab1:244e with SMTP id q11-20020a67b90b000000b003a78ab1244emr4040729vsn.57.1670331586292;
        Tue, 06 Dec 2022 04:59:46 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cb93:0:b0:3b1:1703:92cb with SMTP id h19-20020a67cb93000000b003b1170392cbls1558878vsl.1.-pod-prod-gmail;
 Tue, 06 Dec 2022 04:59:45 -0800 (PST)
X-Received: by 2002:a67:e006:0:b0:3b1:47f0:444e with SMTP id c6-20020a67e006000000b003b147f0444emr4127592vsl.8.1670331585557;
        Tue, 06 Dec 2022 04:59:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670331585; cv=none;
        d=google.com; s=arc-20160816;
        b=eot+/zU9U7ECFm83q+l7zFZAh2lYHVXGh5zm6rHQt8dQxgUYRh0NgiK7PxwpzqBOjd
         Gv/nJR4H//ts37hf09GK9otSpFBUdjzY2B1tb9vCIqrZRSfe8FN1Gl389MICLT36hqif
         X1QTT1nMc0Bq/vNXmxbdvGrIOhmFIHTrdMG1G9nZ3NXr1A7B3Ct5WP2NhNivE9d7EvJI
         67eKabi1QddrBEhfTtEXSL5vNUdmbqzEQwhScv1YQPaho6AL/osw+79alnZ1WIov4aet
         a++iNF7GVxqNb1Yo4qnQ3q4h6DuT8NzqljTosefGfdFokRp4uX3mwzNDvDZQf5tMeRGq
         WQkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=V/khFb5lazp4vCm4xRZ42I7pi8oBjZDH7uh4Ihyi5+A=;
        b=GiK/RspOQTz/pKHrqsYdPDb6ZP0Fy9U3Tv7XJq69j4oBSvj0qt9yl014jE7Y6UPznA
         hg7jvzIybi2hv0l7ETlgwMu8ODvKi6dJqpSlqdfQ3ILQnaICmkFk7PUMgnpcePy64n3c
         nTSmGVFXvvGh+1pF8IrWhiXEDixpsFZ+W6bmdqE69CWJs9cXBotGXhRzb5tDosTPqG0R
         1LazMrQq4fKTWu+sUgqNnkWN0CkidL0YX/UpUYzf/LIx+gG6uwoQkPlwIgDMGvBUtKYm
         ugS/mU6Xf8+SXxGCan4JyDTMCYPfPUKVpDtugu4F7tRbhcXcB3/oxS26P8YoeIfRNq6l
         qiow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bFBCIcEG;
       spf=pass (google.com: domain of zhiguangni01@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=zhiguangni01@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 187-20020a1f01c4000000b003b87d0d4e7bsi1062524vkb.1.2022.12.06.04.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Dec 2022 04:59:45 -0800 (PST)
Received-SPF: pass (google.com: domain of zhiguangni01@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 136so13300001pga.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Dec 2022 04:59:45 -0800 (PST)
X-Received: by 2002:a63:195a:0:b0:477:c9d9:f8a0 with SMTP id 26-20020a63195a000000b00477c9d9f8a0mr52705642pgz.228.1670331584718;
        Tue, 06 Dec 2022 04:59:44 -0800 (PST)
Received: from localhost.localdomain ([190.92.242.52])
        by smtp.gmail.com with ESMTPSA id q14-20020a170902a3ce00b0018968d1c6f3sm12510631plb.59.2022.12.06.04.59.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Dec 2022 04:59:44 -0800 (PST)
From: Liam Ni <zhiguangni01@gmail.com>
To: x86@kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	kvm@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: zhiguangni01@gmail.com
Subject: [PATCH] x86/boot: Check if the input parameter (buffer) of the function is a null pointer
Date: Tue,  6 Dec 2022 20:59:29 +0800
Message-Id: <20221206125929.12237-1-zhiguangni01@gmail.com>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: zhiguangni01@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bFBCIcEG;       spf=pass
 (google.com: domain of zhiguangni01@gmail.com designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=zhiguangni01@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

If the variable buffer is a null pointer, it may cause the kernel to crash.

Signed-off-by: Liam Ni <zhiguangni01@gmail.com>
---
 arch/x86/boot/cmdline.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/boot/cmdline.c b/arch/x86/boot/cmdline.c
index 21d56ae83cdf..d0809f66054c 100644
--- a/arch/x86/boot/cmdline.c
+++ b/arch/x86/boot/cmdline.c
@@ -39,7 +39,7 @@ int __cmdline_find_option(unsigned long cmdline_ptr, const char *option, char *b
 		st_bufcpy	/* Copying this to buffer */
 	} state = st_wordstart;
 
-	if (!cmdline_ptr)
+	if (!cmdline_ptr || buffer == NULL)
 		return -1;      /* No command line */
 
 	cptr = cmdline_ptr & 0xf;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221206125929.12237-1-zhiguangni01%40gmail.com.
