Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A52DB17E7E0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:31 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id q24sf7234200iot.20
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780670; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lu7cfV66RJJjAzSTAQh/fJFz4I8eTqR5UU3nnJJEPo18ts1nJlsJEJc6TxQUGOHD9g
         uQhGhtfHcGsEKQaJ1fBiRE1dQc/lO7Gn61P57PT6o7DzbziBCoT4HF/a/45S8t9bNfOA
         sNY9CzPB6td32mBAKSj8stSQ/wXyW6f2rC1mEKVgmzQITYs3IGi+Jdn7PBKrLwOkMd35
         jfW6GQu9+PzjPGs7tecm8czs5OiBvrLIOaQjlFGa6+noyKf7Czdfa2cnbOQZh2ajvNxX
         hiqGu8HONkCdymxfMW40iTJMv+T/WvgQZWnFi+Q4c3onfp7DBLGAm4OOSydTwbyRcBpZ
         qAIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=/OmdTfsVvdcnnbxNEI5Jt8s8fI2mNndfVcCLrlKQbAc=;
        b=KejzHA5vs6+VHAvOYRRAT85cP6YrVf60aZ+9Sn5ZcF3UOnJ8++Hb1+QQ0svva0cwV3
         F3EUYZ06DN1Ya5slDjt/cfuyTCGWBLFAS5cYcHZE+ajVRZ2/lRSfSMOGSC/g7VNGvIdP
         uW6gsDrhVk39wdNVq7CWAz5iHQOJVTj/AIYfc3ZWpAKCs+ee3Jby2ecSef8tQwtuwqxC
         YZVefmYs8BM7kVpXV8KEN+b75J77ZyRNWMkpqSOjJSfYUBnR++WfqsbmohqkwceXzAVT
         zY9MCZb7tnok9b9xLEleMwAUjzF0j/zRiOHyldcH5D+MtoDDNb/NKp6u47ANyx8OepQz
         o8Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Y+8lvuqD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/OmdTfsVvdcnnbxNEI5Jt8s8fI2mNndfVcCLrlKQbAc=;
        b=oHXDKgHsl8RmsenCu2x3hByk1f8tQm4loRcMR2gzcDNMBNJ8mKcchLOs4VJbjBsOo/
         8DcA2PDkNVRkGVU32248EwPgn1TZ7vcYmOaufm0+8rQy5wGaeeVZcgp8a4pCLH3edmv3
         ulF08svLyrVbjzrA8tabj0OBaQTDvlpZBmOhsJ1XtjU6XAfgId10hXdJchK+3xv19t0F
         UHhS1wxgZYRhPN9cHA5nvOLyCxiYbiXOEV4CFu9VqYXrarWx3Qn7QANiPN3la+Ck4vAJ
         S9/shFKlgJFgXIKIjc6xTCgJdU6R/FmkcOxCQFEFxZ/qiN4i1YLWoAe4/rSlK8cmxBTP
         jQIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/OmdTfsVvdcnnbxNEI5Jt8s8fI2mNndfVcCLrlKQbAc=;
        b=K6dZHxrh3bB0A3VqR+J0O6TvAgp+OO7zCrwtBvXU1XpWDdmzsTF0K5GLkHVSkj7lIp
         sddVnuvVHYrvElgaXrUo5hNPKaCRCBvo2vRtMzu1wl3MPWysHA3rBVo/bVOtueeW9dNB
         WFZ+IK7y7RxwAn6p5sMs1JybxyajpilFnc+ShdwQroDmXT8grnC7psCbXJMym3lDQ9W0
         iBYg9EPlM8WubgtyPcH7vFSyB18r2BI1rjMzdwEGZMguIhrRmnTEi1kLCpD5W0+Wp8Ag
         pidPj3ECW+7kOEzd7217WlADEZGD7ilChZO4RrMG2jfdiYo9gg7ZxnvAEYQsgdZRhqn4
         4Ibw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1kMC+zIf62fZ1RszssjXbw4cCIdbFIvT4UZgAbIt8WpkEJWqrN
	hmQHqrSkRu2RHV7tBla5FS8=
X-Google-Smtp-Source: ADFU+vvE2jQKnwmC2PmyG2IudfBiBRrVqB6/Noy4Yqw1CBkYdHVngBmvW3kAU6cl8XoRjIUsXu2Rdw==
X-Received: by 2002:a92:d1c2:: with SMTP id u2mr12400868ilg.217.1583780670634;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a791:: with SMTP id e17ls1291409jaj.3.gmail; Mon, 09 Mar
 2020 12:04:30 -0700 (PDT)
X-Received: by 2002:a05:6638:275:: with SMTP id x21mr17123867jaq.142.1583780670361;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780670; cv=none;
        d=google.com; s=arc-20160816;
        b=xFjyNK/hNMdvAoERi5XCa1GQhLFD0fq6PmWDdJIlGPEyAfRoIq31HsH5LEg917TDmg
         KMlYeLiTuVhgRvXKoQamDEdiB6flmOcgeypHuornO3bTBaFQZaSBXUC/B3bUBtBtKgCb
         FS8IrY0n0ZRAJdwYb02LU7VROoGgPYd7Ba7mJdabX/GjLusCrCI6DswlKv1pBbXsRnhM
         YqlblwxAJqYXx4HydLlFVhf4HkiKLv1BHxgkwRyjDPKfVANQxSo8qD5s4Emec8ON7ePT
         0lrNu67lyhySj5nKUM1ZATYOcT9q8p9KMTdtdMP+EtVgY3UcYAoIspYK+SOnM28IB+Q8
         lZ8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=bm//1UWMQExXPldTMc1TEbEbMebt/31HpZtErvsA6u0=;
        b=LinOXEnK+g/bdRjQUODBbEVpQcGejENWtvvyLdi1NYKT/02mJyHMKNrmemsj2P6g0k
         IKOpxiDiM89t9/7p9RrW2QfEgl1SZScdZCKuuInz728z7OTcdcklhEF7l9rSi5Zbyu2f
         vSFfs01F/T4aHMp5PlhcJRYI6R+FC4MzZkXuIjizUiz5/uKzDrKaO9WUSL5AhJrxNXub
         uVqzHuFMBkQSPAsqJxyOc2Y7v+zWry1hw70YfUSAw3Qn37OyBZlLF3ZKoU8//rQNonHY
         MEBPzMph/0D6Ue1yT7S0TkLgbSkXAVo/mFvrHDZfhJvGVFWwcJtwfDk1wKi7tjVb03ff
         NtWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Y+8lvuqD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r16si112818iot.3.2020.03.09.12.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9E5B12253D;
	Mon,  9 Mar 2020 19:04:29 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Qiujun Huang <hqjagain@gmail.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 30/32] kcsan: Fix a typo in a comment
Date: Mon,  9 Mar 2020 12:04:18 -0700
Message-Id: <20200309190420.6100-30-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Y+8lvuqD;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Qiujun Huang <hqjagain@gmail.com>

s/slots slots/slots/

Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
[elver: commit message]
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index eb30ecd..ee82008 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 };
 
 /*
- * Helper macros to index into adjacent slots slots, starting from address slot
+ * Helper macros to index into adjacent slots, starting from address slot
  * itself, followed by the right and left slots.
  *
  * The purpose is 2-fold:
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-30-paulmck%40kernel.org.
