Return-Path: <kasan-dev+bncBDAOJ6534YNBBKVJZDCAMGQEHCUBEFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5038CB1B668
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:52 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-459de8f00cfsf7208615e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404012; cv=pass;
        d=google.com; s=arc-20240605;
        b=IOnrcH9/lU/6i4S5jfvKDCJ75h2weIj1Aj8bwAaxYNrIUmqw9xwvPw59lOEHfACZzx
         T8yaiRQuoSWaUoIfIC6kCDUPsK9I9vGAssFQwFG6U+RP+dgY8ZuH0xQ+SoDM0O/Dybt5
         EEvAcuvnyADdIdS3Nf5fJ0MB61Sx9nnVgY7oMVOhDHv/skd4QrMI9k3xTjLTIJPW4EJl
         9QdWLSMpHkpC6qVil7E5b1JL3kwfLKcbcdXDxvV1YHKpcFP4dLCSJbWVbhi71UWN8Zdc
         PAgyVLbd5HeLb4LCf6N1s8NyQeYv/+Ll+e3hVzJXBDFPej3CsjR34qrBvSJgCC3qROlF
         W+sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=v/JyVjXsevDjJ6hKe2AIWgwa1xilBWYejvNOfkTSDcU=;
        fh=HMgH75aBXgxefsE0E3Ow3UvXtVyJPyWt7Sd4XC+DDww=;
        b=JOUms6i2bI2yPDPt6D/Je4SQ/h2t2SemvqAD2UN59ZtvuD91mfsjyQA9uQ5J2VU8tU
         A5PVb+di2XcfUFtVidNWsgTdfge1HXazxsoy6MdjIKF6NHXGqB5zmZE6nXm998L354Gd
         RZHmTnhTsP9zmfv4Wtpu7+IdhVOuRYTbRwcLuB80H6MHJz2opi7K5emKzMPxrKP78dY3
         FSETgiIXLJzCPxJA6lkSVXyspV+T9fUE6qlay5F18q06ms+APOAQ5xAbQ8hEULyyi6pW
         /2ALGaodk1BIFtJ86fUgZ5Jah3nP90hAHa6UaPkETDj6q4+f10PTJSIMMlUQ8hokBjP5
         96+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PQRT9IO3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404012; x=1755008812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v/JyVjXsevDjJ6hKe2AIWgwa1xilBWYejvNOfkTSDcU=;
        b=XVXqAZ7Cr2+0GNssghsmDRymmLs/pFo2JNUKmT2liqF4xApvCdjB4YCDCrqpZvkULT
         yCr2P4/xq2u5bdBV8lb0tsV4fM28PI/SkJc50xLgiEcUMHXs2/QCJN6Iua76T3sdNqRm
         4kzl0nfSSvV0MWhjNFIIDq3o3Y6L8n2Iq5pBYaGEOU9oA7dQoQcaGsftiCi5c+4Uifh5
         wm1t58nvJcz+n5hrwNtbe5UP/7CTU2mog1VkQqjp5DRJ+L+MuM47UeAgQQtMtaUAadB2
         gzQJ7URFL9Sb2t3s+rPH9IqMZhNyQUMa2kpK2pu9XwNS118exFQ+I48xp8hIH3SKqv1u
         OF1w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404012; x=1755008812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=v/JyVjXsevDjJ6hKe2AIWgwa1xilBWYejvNOfkTSDcU=;
        b=iOC7nGKwBV06IPAcqXIZdN8BcZZFhtSSeEAz9hOTj5Nsbd2rnxYBdEEb8rq7J99rZY
         m4A+gNnjlyWmRodgoOPO4c7kEFFOvV11hP4n4y174jga0TgmwDirOdo9lJlJ5hAAU+mo
         pni5znvmgl5239wZS5XTk0KBcrBv7Y9IjtkMAfoiCVajWObD++qKAUfJLOEsPadx6Mz9
         JA/aRLtzHZ1N6rQOOpAcsGuLEwS8wrJWzJUgB88ormRJyNS2m4/bmph80MU8JKjDcHKE
         /jDdQEah7avNDtNeRnfjtsOz3+heQsJx34MtJCX2hhCiEGSWTeAqv9wpiJ0zuknQGCjF
         3S/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404012; x=1755008812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v/JyVjXsevDjJ6hKe2AIWgwa1xilBWYejvNOfkTSDcU=;
        b=EwD71DfHw2XZQ5cAnAwqGFBklkC2cc6kH7D5MZmDlnrvoHXXFuQ6zFJ8DfWFU4tv4m
         EJutp9iJut7dNlRcrFkaFfIyjsxRTbfLMfn0Y+Kh54e+wTNlrur/mnsyeiKrogRETn97
         aYnV8akJIJXzo28CgJB0AgGJzVMvX72tppNnFFwKwuYxOjv0bzl6wal6tQmzP38yXyWn
         S1Spz7wlGhuPBB+3KZ4qpXoMTRQhcW7q6Z8gLdtr4jz7DZ9ua2bh2tcd6HDnUEIE8srK
         kQbdMAd0Sw9MHLLdThK/MyHGS/1bUJd3OyIN7VaiirgN/HBtOR8L8/vmfFhiC0hDzAjP
         Ve0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUweCCDQdyG8kBUXihcsBIY5Tn76iRIkkvss41rkoDgV95jNYbc8kKQQbo6o3lbdHBcd+ypIw==@lfdr.de
X-Gm-Message-State: AOJu0YwU9tX/IENFkdVgpXF4VzpvZu96oN4iLoIOyZj6hY3nMChAwG0O
	0K3K2156ue6jeGkbmihNblRpA1nt2UchEVK9jJgemoLHPe5Nn4WGM9AJ
X-Google-Smtp-Source: AGHT+IH96ygZRjm63GMKjSFbTXrdgRR1etLKGvDrLc433tUExxW7cklb7/cX9JwYTJoNJiZTJ0UlCA==
X-Received: by 2002:a05:600c:3504:b0:43d:9d5:474d with SMTP id 5b1f17b1804b1-458b68732bcmr110855655e9.0.1754404011519;
        Tue, 05 Aug 2025 07:26:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeF8mOdYldKQrSSoHZb0Pzc3a+aS7FguXW5gtC0UgJ0Cw==
Received: by 2002:a05:600c:638d:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-458a8676ac6ls25196055e9.2.-pod-prod-04-eu; Tue, 05 Aug 2025
 07:26:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXekmMZQDGAx3k+AeMo18IMGlDDf/nuSc/j+oC60/pctvKp2+4+/o4rS+NZmq0FhlJXJeB1OgFtqg=@googlegroups.com
X-Received: by 2002:a05:600c:4588:b0:459:db5a:b097 with SMTP id 5b1f17b1804b1-459db5ab379mr69077465e9.16.1754404008440;
        Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754404008; cv=none;
        d=google.com; s=arc-20240605;
        b=gpo1Svei06xfSqJ7uEMS7HOefy/O97SsAhCULcpNsCHj0bj0GKHKsXOPkz5hP902Wk
         M78ILottqiMUkOVqLy65Ax85wpX/o2Zk47XIY1O/jyHqbk7++5UGCkSXJzr4y2N4oLhn
         j0PonIZlxMcFDdUROnYp3qJfJaCB57ynaK868uWYHbDhTQ9GlKBT6GURbhJa2lq+BxV5
         4zXokCht4kwGoLAf3yGmu3kPaoVHmW4NQEmpXp9XwvPEobv14ZXcW1/jehmJCv92oFP6
         pxymoDPjCqRurOjOE+jAXffylk6/KJIE2mMrneSIw/IB1eqVOQ1VHAnVqEPz9v6kxMvu
         wIYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DdpO03g2oqaaq9F6m1+GGOlZl0qQTOQbdkE3YGqW9w0=;
        fh=l71utR/m8ygRkDBsrbWfJX/U1kaa6Q2R5+71JFQBBoQ=;
        b=JbnU7eszRvjR4323fX8hkWayxhiSEW7IAwIsqC1z4IAL0zPXE3taap9ezRE2fguA2Y
         7hopx/jguaxMYY93oCjCTPJZpW0ykghdlWa/z/zdqDC/RGctQ46DSBGctEEDI8A4SR1w
         33RUFD0GQC2m29qxepRaBltZUN0ugkXWKw+Dx3FDP26kovm0tsH6qZyJycldSaoH2IQG
         h0ETAb6vU64g8pFxL88fpkKwOJzJDgjAGD3JLbGMit71fePQZH823tB26mGG7/dnMtvo
         YgCwvVFA3oyzkadDfeU8HuAR84WrDp1wowvZkk+iNNX3piCohs2bVBnWgYoYEtLQ3Mrg
         3acw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PQRT9IO3;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458bd5a0f7fsi1726175e9.0.2025.08.05.07.26.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-5561ab55c4dso6047225e87.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUS+idTzNLibUdmSdhH8CdNu+q/e8+/Yox5HSg0zHengDEmiJsoK2bS6oiFI6lO5nvfDnOyACFokc=@googlegroups.com
X-Gm-Gg: ASbGncvkj+3ZtTRgbLV68CdIqJlj+GgRIUF1cGkBDLf7AlXFACkD4vO8SLcr17LtcAk
	gfR+b7bz0yE0M6t8DIM5cTgay7LErAkqY+sFzf1vDm5kS9UY96T5ewyvctWzFHj2RpuiED0Myrl
	91tesk5DcsbQCbLdsSpxcw7aM/WZm7Ecw526rF8uSXvb/+e2uYctj/MxPS6Cszwb1izv0ZnJxQz
	H/245BWZJ7t25cPzP1no+yh+LN5BpvltnWBseL+9urBhGnFFP86cy1ea3aT2/9hwHjps9iVFquq
	KO8/nk3Zz4F3eEEd02s4boNhAqJJSwU8hxulm/28FL60LITJyENZhgOLJErH5rNYh8o7W/bACzB
	LiW8lGRPg5Hgtra8TRfDtVZKbUu4jRAlLk7gIPGtrg9YDGupvbfP0IklS2sDuYrbvdJilww==
X-Received: by 2002:a05:6512:1254:b0:55b:842d:5825 with SMTP id 2adb3069b0e04-55b97b9395fmr4615455e87.43.1754404007496;
        Tue, 05 Aug 2025 07:26:47 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:46 -0700 (PDT)
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
Subject: [PATCH v4 8/9] kasan/s390: call kasan_init_generic in kasan_init
Date: Tue,  5 Aug 2025 19:26:21 +0500
Message-Id: <20250805142622.560992-9-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PQRT9IO3;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132
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
and prints the banner. Since s390 doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op, and kasan_enabled() will return
IS_ENABLED(CONFIG_KASAN) for optimal compile-time behavior.

s390 sets up KASAN mappings in the decompressor and can run with KASAN
enabled from very early, so it doesn't need runtime control.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/s390/kernel/early.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
index 9adfbdd377d..544e5403dd9 100644
--- a/arch/s390/kernel/early.c
+++ b/arch/s390/kernel/early.c
@@ -21,6 +21,7 @@
 #include <linux/kernel.h>
 #include <asm/asm-extable.h>
 #include <linux/memblock.h>
+#include <linux/kasan.h>
 #include <asm/access-regs.h>
 #include <asm/asm-offsets.h>
 #include <asm/machine.h>
@@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
 {
 #ifdef CONFIG_KASAN
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 #endif
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-9-snovitoll%40gmail.com.
