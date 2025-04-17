Return-Path: <kasan-dev+bncBC7M5BFO7YCRBVHLQPAAMGQEX4QKVRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 90050A91C67
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 14:36:38 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-73c205898aasf558017b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 05:36:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744893397; cv=pass;
        d=google.com; s=arc-20240605;
        b=jxOiXG1laibiNqYDon0r9TdmkCw6RKidQ+sQ1GfzKSTaVYkRFrHdPTELB+joByzxRS
         h84UYw4p1cgSG1rG4C3lAZjVB2cK2MFdPHkvFOiHS3a4vY7aaw2AYX/h1/QSl4VzU/9X
         yUUh5u9xg0ZEu+Kj/dmifQzhrVjzjnzbstHFPAIhbt0MQO4AmM9l3JaUAqUjUkijyaTC
         udjQrznj3zc/1KPg1whahsWCjPhlqmfOfJyEE309NWxtANK7fTvznKfTANed3bNJzLQJ
         m31dGbXXm5Yl72HtXX4nioIuxtKeb8x0AV293XmGADZxt4HQ5YfRFmH1jhHvHT7Q1YwI
         mxJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9YJhoHVOipetn3QeQ6U4x9pkN4FhPsdSwvCjwB3y6EQ=;
        fh=sJm6BflcGk+cvKhTQ5qNuf82Bx75/TDWm0fg7cL6uaI=;
        b=hjxoK/P3hg5F+DWJgjZSwBaP7c3evd1a62B1rHSgxHOZn6w2Mzuy8C/nY9QwUr/qpd
         w2XK9O3tEBqdYXusIzcW9oF9lQG4m31f2HN6LQmFM/VD1DaZ1g2daukFtz/sR/diaiO8
         O6iwHaxoY0cggvWs7mIbAtYccivXxl68J7q4EUHU15W5F0icjmYhLdR+t28BC/hdncJs
         pBbWZ653/SoRFI7pkGQ+Jn8RWZirShsyCAU7W7k/w1CZ/DhG45l3G2l216qDCLfWiJUr
         nF1yZ+8Dkk7UlXsgrms38of2NL4B1Hgyd8+SbWP7gX8wF7s1jDRr7TJcztvXETgaXPq1
         Te5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VsQexuho;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744893397; x=1745498197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9YJhoHVOipetn3QeQ6U4x9pkN4FhPsdSwvCjwB3y6EQ=;
        b=bZJ0Kgt/HfV4fqzqBl3Vl6MYSDlPWJ4J6zf128iwcrxwLDHgu7+Yh28I0mGB1vYjg2
         JU2ff/FfW9Lxvm5HJsackvHs9V+iOPMQBJHeSRpOfoe085mmpyl6cweWNt9vO/ExNjvU
         OFRPuqGKE/daWLqo3IIfphii9h6LWUukHyavthpnssWAvIGJyiNcHv9kH4B1BK51Plgb
         HWPwjpYy/DTSHwa00jHtOp3AplOv6V7h/J1zlIR+GkvHe02Xf+P9Vm/jFfKvUR+bBOhb
         ZJQBSnfXgE7f1UkbKhTOjqVoDUsDq5CdvhT/L5d8y5Pe3reZPQckXt4pveZQ04n2Gmdh
         T/0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744893397; x=1745498197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9YJhoHVOipetn3QeQ6U4x9pkN4FhPsdSwvCjwB3y6EQ=;
        b=CHvTYcyIl8ME6ETI1kIRobxnXtmbrJ5wVsBf3oLD52AMPPaAC4CABoRMJ4vurohjn/
         zKCAigtitL/2ncZnd5f0ifTfV3tKnOmrX5FH6ChekcjMrFnCs6IPguK9sMimP/5wEntD
         9gDly0Oiz/0pBaBvhwXOl4J9uLZCOktGhiwc5cdF0SOTniL+G3sjLfmGqu+IbstR8BXY
         KvVbWwD8vkbYGGyPVj4f4H2GHRWiC0U6P+NSDyoVxKUmgqsdr81ghCnTLAM8fBPzQbQy
         XQuM9v0sVI3QL0YeTmrtgngYLR/1YQw7TTFpHcnDETK6nyv8ypC9Q+JtyRKCMppw77Ac
         tacw==
X-Forwarded-Encrypted: i=2; AJvYcCU6HkK5p+iF6DbxWQYs5FVQnIdH2X/0hBTwHJv10dntNRKC6D81NWNPAIF5oi5SRKr0RPiiEA==@lfdr.de
X-Gm-Message-State: AOJu0YwbaFISqGgWiJSKimyyE/y2+1A0dkkedZen+YDTHu2mDsBSmUSm
	zo1vTIDd78T/Qeh6UIqx5incv+lZljl1DOiZ3RjQX/g3JHe1Ps2v
X-Google-Smtp-Source: AGHT+IFe3ykLk+RDRB2wEM0/LTMOkGVgabDkN6nOH/3s7bUOh4NWL2xyrj5VWsVkgwI8s8NW/A3zOw==
X-Received: by 2002:a05:6a00:2348:b0:736:a7ec:a366 with SMTP id d2e1a72fcca58-73c266f9c5bmr6430079b3a.9.1744893396763;
        Thu, 17 Apr 2025 05:36:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIvmFHKZmwSyE8jiGxQckhZsw+S4JJ5TsIlBgbF014wkA==
Received: by 2002:a05:6a00:4c89:b0:736:a84e:944a with SMTP id
 d2e1a72fcca58-73c3279e8c1ls966441b3a.0.-pod-prod-02-us; Thu, 17 Apr 2025
 05:36:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7GsxToRM8g9yW0R+tJZs/ssLgc+fUfQUy4NhiOYPeEZ5YhqM7A9BLYZj2ld5qZBTI1VGWvGsi/2g=@googlegroups.com
X-Received: by 2002:a05:6a00:1147:b0:736:d6da:8f9e with SMTP id d2e1a72fcca58-73c264c5756mr7496930b3a.0.1744893395053;
        Thu, 17 Apr 2025 05:36:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744893395; cv=none;
        d=google.com; s=arc-20240605;
        b=RfCM2FVd4O7rNb6wDi2P0/TRzcO45QYguONUaQOYC7/p6LF+2HuPOhp+8XhKk0C7aS
         FCOFtgzlumrEUN3BvWmREV34YJ9ZQphqX5qDeos3HhcPMG6YeQxuCq2gdDL+w/vdfOBR
         wpa/CTgTlMDQKSjCgEnw4GGnpCxXxpLJlmQhc1r9RSn1HSi8YurVLnsNZDEhR1C29uRb
         de9ZYLxE/PiTUe7swZehVYj27zdaIZE8QqP/v0cvGrZ1vhv620CnPsRO3ZW9ANOQMzoR
         rOu67pag1IAquB+wFGd17FyTT0Q1WpMvhdFIG5OvL6jMM0gJbb538Afdss5D14OzFAOX
         9mow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:sender:dkim-signature;
        bh=8Fw9lZ2AAOJ4B3rMfETmlXbnFb/XEHSXRiuFDan0ofE=;
        fh=LqePF0lN5C/xouOrzT77eylrTLCgCNSH5lOQbFKYv2Y=;
        b=HzCjuyxLygMm/ALGN4DE0LPhUU40prxd+OoDvT7QUleQhbQc5yum73hIbKvcwNiVbp
         85D4kxoGsuQyWhJbjNMs4JMjYbUBxlWrZ/VER5OmzOiswXGnn3tf8+2fvMobUGpF/x/u
         EZFMZM9HBpHJYCvEN/j1sBClj3hxo781STonlmmtywBumFx5SNV384H7Owee4oSYytiD
         Jp+ExU2NSgJAzQq05BhGNggu35NDcA+AKoRZHxXsTVIGGNldMfLglqgYayb6Bg1RgcHg
         iKLiAPNAKgA86igguS/nTMeZ0+oSFKjg9TERHGFwzCElSAWXrCS2DT3rlV2GPSOhT8QZ
         wWow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VsQexuho;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73bd22cb007si208399b3a.3.2025.04.17.05.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 05:36:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-af9a6b3da82so442264a12.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 05:36:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURRcJrNeBGBniEdNtW+20a+Mp3T79uhTpkWXetUVZQq68Hb11r/l2TKc3cqulhZZGvBdb032yQ6SU=@googlegroups.com
X-Gm-Gg: ASbGnctUxQpRYCsmB0ED0o5wDmNdZpl1zwQZ0353OmjGwLCMAu/JVdm15cvmWVUVNrZ
	nw23giPy+KbgzMlTa2sERhtCo9WJPPpfZVeXVNn2S8k60Y+IaS1S9ZhqOubTQUv5Y198IfEn5dR
	owbCNBosReYfgghb9gXwwaM1/xuUIXUy1lGpU3abLJh+nl66wJbSeExxsU0fGMr7DTbnVWzXh6f
	rZeJ0FiZaC+3vUyPw9VetffhQNQfqvJlWga7A1HPbPc+yq7yr6VVsyv9vHS4gbhpdweTwfbmC7A
	39bToATKBrPsuGmXJzVSgeKi7Mgc2k1U1gLBmYMZbYRkYFW0M/cK7g==
X-Received: by 2002:a17:90b:2b45:b0:2ff:6e72:b8e2 with SMTP id 98e67ed59e1d1-3086417297dmr7524864a91.31.1744893394519;
        Thu, 17 Apr 2025 05:36:34 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-308611d617csm3917601a91.9.2025.04.17.05.36.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Apr 2025 05:36:33 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
To: x86@kernel.org
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	"H . Peter Anvin" <hpa@zytor.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Guenter Roeck <linux@roeck-us.net>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: [PATCH v4] x86: Disable image size check for test builds
Date: Thu, 17 Apr 2025 05:36:27 -0700
Message-ID: <20250417123627.2223800-1-linux@roeck-us.net>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VsQexuho;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52d as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

64-bit allyesconfig builds fail with

x86_64-linux-ld: kernel image bigger than KERNEL_IMAGE_SIZE

Bisect points to commit 6f110a5e4f99 ("Disable SLUB_TINY for build
testing") as the responsible commit. Reverting that patch does indeed
fix the problem. Further analysis shows that disabling SLUB_TINY enables
KASAN, and that KASAN is responsible for the image size increase.

Solve the build problem by disabling the image size check for test
builds.

While at it, fix typo in associated comment (sink -> sync).

Fixes: 6f110a5e4f99 ("Disable SLUB_TINY for build testing")
Suggested-by: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Guenter Roeck <linux@roeck-us.net>
---
v4: Added comment explaining the change
    Fixed sink -> sync comment
    (both thanks to Andrew).

v3: Disabled image size check instead of disabling KASAN
    Updated subject to match change
    Updated Cc: list to reflect affected maintainers

v2: Disabled KASAN unconditionally for test builds
    Link: https://lore.kernel.org/lkml/20250416230559.2017012-1-linux@roeck-us.net/

Link to RFC:
    https://lore.kernel.org/lkml/20250414011345.2602656-1-linux@roeck-us.net/

 arch/x86/kernel/vmlinux.lds.S | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index ccdc45e5b759..453f5b5e4817 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -466,10 +466,18 @@ SECTIONS
 }
 
 /*
- * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
+ * COMPILE_TEST kernels can be large - CONFIG_KASAN, for example, can cause
+ * this. Let's assume that nobody will be running a COMPILE_TEST kernel and
+ * let's assert that fuller build coverage is more valuable than being able to
+ * run a COMPILE_TEST kernel.
+ */
+#ifndef CONFIG_COMPILE_TEST
+/*
+ * The ASSERT() sync to . is intentional, for binutils 2.14 compatibility:
  */
 . = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
 	   "kernel image bigger than KERNEL_IMAGE_SIZE");
+#endif
 
 /* needed for Clang - see arch/x86/entry/entry.S */
 PROVIDE(__ref_stack_chk_guard = __stack_chk_guard);
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250417123627.2223800-1-linux%40roeck-us.net.
