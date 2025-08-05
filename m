Return-Path: <kasan-dev+bncBDAOJ6534YNBBJ5JZDCAMGQEODFPFLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 836D4B1B664
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:49 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-458b9ded499sf24486795e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404009; cv=pass;
        d=google.com; s=arc-20240605;
        b=OS34/bweE2Y1q9Ttj9hgqe6/i3/jQBP//bym2ElGDDM8nW2niXXHAHRZUbkkeeRJyW
         SXEGDSKN3wdBHhfYzsP1lpIAYo0iMUCFn8DsDCXsMYDML0zQm41ElkA8B/x7XA579L8b
         V2T6WBjahjnu9qYLVNqvXdTEsfZvyoGUrVTqD2Mar20QmCsISNsKoJcGALVbp/56ZJJT
         smb6ZAvC8E8laEGqlSguidgQszM1YQ4UdPxvLLIb9IgtbqD23NWXo6N1ZnsgHm4Dfw97
         9MDX6MNitAmBD6sUDPKq+/k3pItUHu0FuUd0kVkyntu+lb9gGO4jPdMJv8jwOoeHJlS0
         fctg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=WCnT/CJry26cofJnJLCWEgSYaN+fDzEhc98dtPWrL3U=;
        fh=PBsC3GD+QR22jXfz5gsd/TYeQrCGITrDxGJ1Ztbjhwg=;
        b=XLCEwok4F1nQc/RZpHaTE2W/IN21j4+XnSNJxftAlugttd4V0MpPeptMtru0qyaBJW
         Lcr4QGBVcf8+oa4tWNuDHwkPOnuWM4fxQh1GQDHuPlEN708h3kPFM3Pqn5eSgTUQOi9h
         RZmVHllyfel++QviwQgY+toN0CS70f8Bkk9HV5npBd/zv+ePYi+xYrwKggNezmowYXwg
         ARBnke3gRr22e66G3PBXEjd4kqfqKv7BzW6vyGs3MdvkNblxjTACPe16EQqXlI+XrKG3
         fjqU8VdfMelJUCB964AqAnCEI7+EvF4PV28YidyqSvq/hcSMOO/8gBelr1rmRD9qRL1D
         Pq8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QBwQlmFS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404009; x=1755008809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WCnT/CJry26cofJnJLCWEgSYaN+fDzEhc98dtPWrL3U=;
        b=JLLRX7fcRBVwphWj64cOuMtTVse52XtpevTlkuOMSW+d69bsCl9zVND6VhP5DZkZxV
         iLx96btzzVV/OgZvsyRX0CNQoRYtR6Z1oa4O0zKeNiug54Za19h7BQPopQ99l/T+0ACR
         Ix1IKOhbdOmGGcwxC48IZjBma5LCszjj8XZ+y+JRJ7IR6xYg3fgl2kLkHTG4hOi55k1B
         TpHJDKVcTC9Aa4wtAzX9y1cWewUzhOGvG4XnMW2NhlsgEewWUKdBGzfEA4JjKZIpzjmG
         ywTIucME/bI4Gzse8QlHXfmnsihQd06wxtDwvqDkkuxtVJRUx0P3lDsBMaoqwMv3F2lg
         Y2aA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404009; x=1755008809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=WCnT/CJry26cofJnJLCWEgSYaN+fDzEhc98dtPWrL3U=;
        b=TqAYEhLbw9jdX5HwalLIn8dmelDfKtnaiftWBodYXeOBF70OiAwLKjIzNiVvA9J2mA
         V5g1kFd+p44aEYlaWuvbaqhA2UjyKLGbOcl+ozM6bW8HAWpNgellRMcjbmEPhMhZO0bZ
         jkxAnRz5wTDT/IKUBaRYru3pTLWEukHnXhDIRjsSDe0ngLz1XFMFdxPPOSswFZCLkDOa
         HZK0KNL0j6MgzhxsDpTxRH1yn39ZZ6zHfKBuYjY4bkh/pQXPPDqAtq389/Z7ZEOR9x9t
         COhhfauBu+N9OppTklvkYxG7puazGVvanZ5veXfMtDEt2gTHZyaBW++Hw+zNGwEGtO0H
         clNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404009; x=1755008809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WCnT/CJry26cofJnJLCWEgSYaN+fDzEhc98dtPWrL3U=;
        b=df8fS9pnLiVW9KcoouZwyaExvZgqwEmmQ/1VNZDJp9IUoMl/f5WDjgoMicUGb9+lQK
         MisO+T8tS6JYqlfQid+jRc+SnwaLduvDVajmESiBf0DdEm8+BlbWpW7CPkGKaz6SBOIc
         eCpBrbQw/CkCU0TZiMwqzMFqQjhjKG6YXkrOFKiJBYkopZOtm08Y7NOBCtCslr0qVGqq
         tgm1sYGoNddso5bFdNeQX8LukLtsJhwBdMCiG0gRtusOONVe57HCes9bHIwhi/YuxJ85
         +y2DRmYr165bY051wVg8v+g/AGt0qt0rJg+aS8te74orn7984VhMXNJ9GBbTxyHhCAUk
         SFdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdHpHtv8bt3WlvXtRPgRUAxlpjZfRI8hyNLhA3DoWdf2dk196Y9hoj2vm0yzU/aBIOJGfyiw==@lfdr.de
X-Gm-Message-State: AOJu0YyAnCgW1ljOl2pvEv1cfXI7n1rv2S18fyInIRs6Q1HjY4UVnGci
	31/Y1iMuJnutANPVaApKGy7uJY11kwlBFZISIlbvFRn5XxinRUt2k1cp
X-Google-Smtp-Source: AGHT+IE8zvtOJs9dgKo+iqRbhrvjQmWtK249eZtrOR2bHTNFVPo5hiWAKf9Dx3fEP5evzDxQjE9qaQ==
X-Received: by 2002:a5d:64ce:0:b0:3b7:8473:31c3 with SMTP id ffacd0b85a97d-3b8d946886bmr10733229f8f.9.1754404008517;
        Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMfLZ/juXX7TXGN5POXBPNQqP/rDf7pyjQE5oHi7p7bQ==
Received: by 2002:a05:600c:670a:b0:455:1744:2c98 with SMTP id
 5b1f17b1804b1-459d796729cls15033635e9.1.-pod-prod-02-eu; Tue, 05 Aug 2025
 07:26:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCFAjtezyY7psyeYKOpev0IL57NiuwqrAcj+dntkXOU9OrolCh0w6zz1xplaY9q1NwPppT3Mlg7No=@googlegroups.com
X-Received: by 2002:a5d:5f4d:0:b0:3a5:2ef8:34f9 with SMTP id ffacd0b85a97d-3b8d94b9fb6mr9792897f8f.27.1754404006036;
        Tue, 05 Aug 2025 07:26:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754404006; cv=none;
        d=google.com; s=arc-20240605;
        b=fNhasmy4l/8EQaSNcAmwmnAph89Jbf1KXF2SjLBi3nfiumQCJbzTqQSupvkirlHPAx
         AZxDCQ+9TkUJvH749WtEJS5y5OZj08NtNk/LPFcI7XWl7q9MGX56r09lRH/DWJmWAV6T
         KE0KhMAheDuiqcOCGwxnJFD4Yolv691XennX8wu3kG6msGNExGmSVs7Nimq1J20eXuGL
         DWcy3C3Cnwoi1YYAOVlO8RmsvTRAnTdCH9ulKQNoAOcBpKxyN7JFuI+iP6go/HyDKqWK
         VNyaQ6JRFz9z+R+HNDSvibIIXt3b7AjhTduvEhChglU3UprytK5ge0XtHc4tcR70b85x
         uHSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4lUgc2mQ1RFMODut/DxjH0e3nH7UxMqXiDg2xTFsSSw=;
        fh=t/SzNrq2LOrGrsxt7lwaGNzM6/dC8VWK+fbMPZrs0no=;
        b=lfPTMN1NmuoQQ6P85M0eF7Hhf7sNwxqjotZrh9rBuYaYAGF6Mk/JlX/oxQLRbumDOe
         aVUrXtWED86fHOnGspq8DTJfUh7P1ZdOYQAhQQgpSgw3md5tMrKh1JohwKrMZl/SilEb
         VHoh12c7oGJqcraQ5wKGIZ6Q2H36Y9pyNbEaYK5xzoiFd/QUlQrEjJHlDuqJIcf48iFD
         Bjh8CyYRCqHJzLGxvE+jsLUW6Qm6WM7Y1XIoYZSlyfbakj2t0DYWObjtqGN6WPEXjorH
         XeNqkXQ77FuuqNokkFm4crBwlAfM+DNCOIcIdKH/vEAmKXZEk3bjipI0P1KwwtrkFwWm
         yHfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QBwQlmFS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79d191681si298850f8f.4.2025.08.05.07.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-55b9c2482e9so3262088e87.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/RmDcNh6H3dPHe+YBSOGrOFSfvy18kIB/xGKLK+rKnvACSahS9d8o1r2dR/OQc7NKa2+KEh0ASsk=@googlegroups.com
X-Gm-Gg: ASbGncsFTTJVhcST5EctzFceBLUedrDafuWnbAZL4g1i2O2yYubEd7buOUdf4CRbVRA
	Rr5/5ovRt8Zr7yfJBoeTGvJG+kwltdwBN0e3oqYEvmqJyVncaM68z24f/nySrJuVD9QYxUMxnPn
	VWGWVDFGKUXBqNx4bA2jzfWtOa6Kj1fXKMwncIyRz1QYinY2ONE26dzWCem61g+J5uh4NJA31vf
	1jWOhuOxR2wUmWvgHhaDCGo6q2cPBzo6uVYHIkhdx1/yxUJDpoxR3V5EDK8cbb1ikv18KJrX8iF
	ASlnKwtKxv1576GDMwwP/ttpaIdHnQxA4gNiqUsSHo82wYglkjosN7/CQlFjoPPu8h2zthmkz8K
	WvzljeT0OfqzDEOTQVkNap+UiJrPjtbO1LNHSkOrInAX+Qhz1P9LpYq9Ft3Zt3u1QkZtVfKV9Zr
	VHV6h9
X-Received: by 2002:a05:6512:3c97:b0:55b:8277:22a2 with SMTP id 2adb3069b0e04-55b97ac64ccmr3140519e87.21.1754404005154;
        Tue, 05 Aug 2025 07:26:45 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:44 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 7/9] kasan/x86: call kasan_init_generic in kasan_init
Date: Tue,  5 Aug 2025 19:26:20 +0500
Message-Id: <20250805142622.560992-8-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QBwQlmFS;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since x86 doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/mm/kasan_init_64.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d21..998b6010d6d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -451,5 +451,5 @@ void __init kasan_init(void)
 	__flush_tlb_all();
 
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-8-snovitoll%40gmail.com.
