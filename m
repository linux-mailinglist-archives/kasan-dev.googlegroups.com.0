Return-Path: <kasan-dev+bncBCAP7WGUVIKBBA4Z42XAMGQEPOBEQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id AB2958622EA
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 07:28:21 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-21e6008956asf1291021fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 22:28:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708756100; cv=pass;
        d=google.com; s=arc-20160816;
        b=VvYNi2Ueat6TXnubovweoingbALJzw4EUbU6JkybMyM0JhGg4C4rgJ3fwUUfgt1fW6
         hMLTsjczRezBxf2XmsgMScE1cPLRzVPfQtPXksylOBMGycu0vvkbiTKTyqZ2Qcvngzn7
         zs4jBP7btM8mquZbYFZtJAwM+0ld1H7Nmv71mx4ju1a1Gumwq4+L/y7zHJg2CyUnAgVp
         LS3KF9NedgGZM6/lx0J5xX0FSYSvnV08tOIszpo0eJ4+qDJaXe6AAA9iiOK87X9T6orN
         hxfNxktb4fuvDgMeEPEo5v8vJ6szvULp0EWrYne5toLcW7cWC9hCRqnbXJ4wF2BCR6qp
         qgQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2uxGhNltyPCtQH66to8DiOW6WDOicWWa5zXoa+m4MM8=;
        fh=nNOaqK6KpGJnyUf1AJwr1F2UKQ5jsKCQGQc8oexzdeU=;
        b=UPDh0Os9yQpnxSDVAxWWv14qn2VdgbQO6hAajsvsyU6CKto+wVPmMytx2lXShxRyfq
         izoUIVqwkuQIOU9nHHToTGr3CAaWzcSy68O6srttF7SwVJaT25coMigff6Z+Vjbf1tHn
         zWKSVIu4cYo5U+bHOy0T+VOKj7aVZ8wiNDLcpbBnrlTbp21Af+mk9msDFZHqe4UMbx9s
         c66AEGt5AWJvy1+LZEYQNwRkUH2ASUtbTurxCvGXDbHL+jdyBw1rSvKH1kZMjIKx6/Di
         Y7O5Kc6wjvPY+GbhPHGTBBisLXdYFnkXcV7a7woYUVd602AJqsScqu9CgjzvlumMPRUr
         COHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708756100; x=1709360900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2uxGhNltyPCtQH66to8DiOW6WDOicWWa5zXoa+m4MM8=;
        b=u4Qv4ICuPfYDBL1gG1A6bkMpgdjgKo2f4McvBDhw62GqyR+7CdQMQUQi2pmiO4qDOZ
         +vWWuCllT650LFRlj/kjwayRS8ROXfopVeP9hDIj+lxPgZPl08Ve2HYRmRazKIhva0um
         hYs2uPvjId98zM/5wrIFVXRns0+j1Wnaxa7JtZz5yc7DQ8B/BYEQO9021SByCpLwGQrm
         C/T6HNQ3l6C/lI6Vu8SO+EhGvxjHgCcVt5oWNnVrPuk6iT1GSqU+ruLIJUYoC8FQ0jXd
         OZ0TejhHoIOAg5+Xr9s4wxHl8PDhzkLoJvmlOcwoB57Txj11GM0Ev1UQ9pKx17vbcaGs
         pZog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708756100; x=1709360900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2uxGhNltyPCtQH66to8DiOW6WDOicWWa5zXoa+m4MM8=;
        b=BEW4ND2CHCunUxlMMDcMj++2ili5/+y9fN405HW1aQExN8IcgXG6SK4vtIPxFENs6y
         qC/O2/A2uM+Syey9G0lioRYCfuXo0IcNR3rkxNs4uqQ26bOa8Y0ViJAivqf8fDL+NgeJ
         BQklcTWuWzOieggc492uy0ddYogrtE84UM9O7N4PQuAwuE6wAOqWWM1fC6vGKEnij3Bc
         g1eA8W0Rx32zvnQMvL+EHyvmQMUF0a78aTjnMXFB6deV8O/P396lQ6HwELDTiVgM1lZl
         YpsHykkwPEdeWZYDnqcWG4AA7Up1FwMnMOpOGf8LUyl0sbZOzzOq7yIQrrEwg6VDjRta
         1pQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGacSGl+RVTnmIBWmF92v+PLRyQCc+EoIFWqvTkRvsAkZVsd+I/UURzgQ0+VQR/VlrhqOhVW+ZRSYVVD0r0ElH1qe+pYnweg==
X-Gm-Message-State: AOJu0Yzgy9aPUDvtOShtQcQkBKdIGvclCXUuAbkSbdFWqYP0NJs7n3Ig
	n1bRSC9P/4fHPQyZTZA9xTUKCi5PnXSBsUzmP46aRvrubDmet/nY
X-Google-Smtp-Source: AGHT+IFfMheXGj9GR+uWQpZSf9cZWNkzzy8MqxArkiJmFxayLhbIZCr60NtdfXGBERoGqhgiTKLSkw==
X-Received: by 2002:a05:6871:a68d:b0:21e:77bd:b7e0 with SMTP id wh13-20020a056871a68d00b0021e77bdb7e0mr1807770oab.39.1708756100181;
        Fri, 23 Feb 2024 22:28:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e789:b0:219:aa95:702e with SMTP id
 qb9-20020a056871e78900b00219aa95702els1697121oac.1.-pod-prod-06-us; Fri, 23
 Feb 2024 22:28:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUtQFL5zIZHzhnv0IFwJqQ0iP1js6C+h0A0KUarFJkHe1Dsc6Vo0VOuQWlZqNU2lvFU64wPlrxvqeyo6hC1E9SJpH31kD1aLTHfag==
X-Received: by 2002:a05:6808:3020:b0:3c0:4056:a2ed with SMTP id ay32-20020a056808302000b003c04056a2edmr1763521oib.52.1708756099204;
        Fri, 23 Feb 2024 22:28:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708756099; cv=none;
        d=google.com; s=arc-20160816;
        b=XPpgDwbUiACU1IsD0MpVT43hk9mT9g5o6tE9pMkJx03WBLwx/2/61uXOQp8NQVoxrg
         AABHwkZjIkmnXq/sd4VKv57piBZbbLPRqHpUi76LCmnN50Btqd6hPgSbWOAIzxRUVLsu
         3mraSGyQl5/GtUr0Uk09K9YvGfXWqfMLvDtJKxaZQVgVQh3fl+mYkxAnybFEc59sUrw6
         n8cnmwqKRftWyOHsOSM+pZRMg2MempXscvSw1v6k/5JheMroPCxONSECElMwlaPbYnOR
         AgttmcbWx4/C1xd+bk7KgobRKnkAXZtS5sb3zcIuxJQjIX3xB2q43tAxlif4d4jB+p5Y
         0cBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=M9Fg4KJqLbBGP8r0njyeZzZvmuNITeV0o6CVYVXKe3g=;
        fh=4dClFmAx6Rx4KqFlA12ypLHRpanB2XjPqKYD+gyWp5s=;
        b=K3PJZOqc0nHIpjOJY3Xe1GyQeSXITo1oBmbZ+2hiBeihAlFJ+M0E5GG6667oA34gwX
         uKNOkni+DVd6Dcg4l+hnrkQhotA1dNctq4bQUqCWxTuDtCCJ5W/rnzisL461W9zccOiN
         vxnXRcDt+gl1FidPf9rTEuL8hCwBDKev8bVdZLgY1QijsSO1bC4BrvFAdMdc6CAxXDSy
         APjqoxrTXoqDW15ZV5ji9gjRJ2lXzlOOWEq0hGnC/rqwSzo+4hG4oKgF+mWiVgTucMof
         FYgTWe9J4EqMTkTiGdK048Eprctz1FLvgKP6B0y/eEgg09Gq2xZ+SWHNlARSkzahjT2N
         b8BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id e81-20020a256954000000b00dcd2dd6bba7si45093ybc.1.2024.02.23.22.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Feb 2024 22:28:19 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav314.sakura.ne.jp (fsav314.sakura.ne.jp [153.120.85.145])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 41O6Rwxi089466;
	Sat, 24 Feb 2024 15:27:58 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav314.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav314.sakura.ne.jp);
 Sat, 24 Feb 2024 15:27:58 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav314.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 41O6Rw5x089462
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 24 Feb 2024 15:27:58 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <7f322fe9-34ba-43be-bb50-539577d1c183@I-love.SAKURA.ne.jp>
Date: Sat, 24 Feb 2024 15:27:57 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: [PATCH v2] x86: disable non-instrumented version of copy_page when
 KMSAN is enabled
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        the arch/x86 maintainers <x86@kernel.org>,
        "H. Peter Anvin" <hpa@zytor.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Yosry Ahmed
 <yosryahmed@google.com>,
        Nhat Pham <nphamcs@gmail.com>, Minchan Kim <minchan@kernel.org>,
        linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>,
        Mark-PK Tsai <mark-pk.tsai@mediatek.com>,
        Sergey Senozhatsky <senozhatsky@chromium.org>,
        Alexander Potapenko <glider@google.com>
References: <d041ca52-8e0b-48b3-9606-314ac2a53408@I-love.SAKURA.ne.jp>
 <20240223044356.GJ11472@google.com>
 <6dd78966-1459-465d-a80a-39b17ecc38a6@I-love.SAKURA.ne.jp>
 <678f31f8-5890-47fa-972e-df966aeb783d@I-love.SAKURA.ne.jp>
In-Reply-To: <678f31f8-5890-47fa-972e-df966aeb783d@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

I found that commit afb2d666d025 ("zsmalloc: use copy_page for full page
copy") caused a false-positive KMSAN warning.

  [   50.030627][ T2974] BUG: KMSAN: use-after-free in obj_malloc+0x6cc/0x7b0

  [   50.165956][ T2974] Uninit was stored to memory at:
  [   50.170819][ T2974]  obj_malloc+0x70a/0x7b0

  [   50.328931][ T2974] Uninit was created at:
  [   50.341845][ T2974]  free_unref_page_prepare+0x130/0xfc0

We need to use instrumented version when KMSAN is enabled.
Let arch/x86/include/asm/page_64.h implement copy_page() using memcpy()
like arch/x86/include/asm/page_32.h does.

Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
 arch/x86/include/asm/page_64.h | 9 +++++++++
 1 file changed, 9 insertions(+)

Changes in v2:

  Update explanation, for I misinterpreted source/destination direction.

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index cc6b8e087192..f13bba3a9dab 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -58,7 +58,16 @@ static inline void clear_page(void *page)
 			   : "cc", "memory", "rax", "rcx");
 }
 
+#ifdef CONFIG_KMSAN
+/* Use of non-instrumented assembly version confuses KMSAN. */
+void *memcpy(void *to, const void *from, __kernel_size_t len);
+static inline void copy_page(void *to, void *from)
+{
+	memcpy(to, from, PAGE_SIZE);
+}
+#else
 void copy_page(void *to, void *from);
+#endif
 
 #ifdef CONFIG_X86_5LEVEL
 /*
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7f322fe9-34ba-43be-bb50-539577d1c183%40I-love.SAKURA.ne.jp.
