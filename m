Return-Path: <kasan-dev+bncBDAOJ6534YNBBJNJZDCAMGQEHJX5ALI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B7F6AB1B660
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3b7889c8d2bsf2386230f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404006; cv=pass;
        d=google.com; s=arc-20240605;
        b=SKukRQOXs294bP7wpjPRJWm5IFWyW9RPcEHSWSWCJ3goaBWxLLR7X1IfLuKhxDDi0L
         A8VjO/esX7A6FxVGAsdRr/v9T8VasPSspVaLb626hpOCkWtpfHViN1+VOTGEdJ2sO1cW
         cqnqsLAS+OWlNLfm0LYcGG0EKLcEXnfy924Kn0vX7uENAvihQhwiNe7is+mN22SUy9b2
         afKsFJEK48AS1jmUVLuyoJsqYtWR2pp7AfZb2p6UimnxsJzZxcyxAJnrwv5T9EnMxfEk
         ZWimbyk04Ymg0YSxskEvNenhYWXLajGK05P4EA0nXp7sXDtAklh3Xun/hNoQ27m5NQb7
         ylSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cBwjldM3JdO2wmlqR/PzW0gcbqDXNwjVtMOZ0zwB0lA=;
        fh=mVRfub4sNEcHu8GPDP2j6rhhjEWjiknakdSxxkhSm7w=;
        b=NE/ZKBG5FFM/6uUDnXVfCzRGnJIYeNdQZQvUtdDPar+II8OGbtukAFfNe1trNFhm1F
         GJVECLwAtcfuFSYs6hcvjo/+eNin/Jt+rzJ4vnwkGP68KHoIg1VLKWBMr92cznNApjTs
         HhAnzPAiAs4MdGxvGdXLSY/Bf9sJa20c1u97t3f7kxH5Al0052T7DCXGfQVjxnqSfZcz
         VZXLTJX4UM4VaBi4IGJ6rqFNu+VqumSQKTTEQAZsovJ+qLro5lZlo2wLmnr9bn+JNl+6
         HYaAeOuW33O/KcXJvC4KQHWurEZ+lamWobaoIaetQTBpkKkoKryCIR6j+DYG1kGrdbs6
         u49A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I2L72u5g;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404006; x=1755008806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cBwjldM3JdO2wmlqR/PzW0gcbqDXNwjVtMOZ0zwB0lA=;
        b=g7907O83O8E8dkRVcsU4aeAEY/TXEVnspzjMUeCfYfY+aQ4p8tUzasuK2/uc98prUN
         S9nBPaBJ1XZ4xNAZEZytV/rkx65uByziuJZAIY+vp3Klz1E9p+PckBblXkCF2Lkpwjre
         4fCWt01jxhrjfcR7Fk/FCkUAqffyiBoEO80PLgu82d7rHUO5Y7YLMuSLB5spAzfySdib
         J79y26wn6VOho1iCOhjNzy00qzo/lSrWd7rRZJ9ARPx7TBFPqesnPrf7yr7K2V2iyyH2
         Q385K5f4BDtKqVShT0fuheVIU6GuqYPzquMt4DxjLb95A6PcrajgP9VMpoiSD+QiMeUu
         I8JA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404006; x=1755008806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cBwjldM3JdO2wmlqR/PzW0gcbqDXNwjVtMOZ0zwB0lA=;
        b=BxfJ4+GTXKtAK75+M9O19092NEmfi2KM+ldS58sEclqNDEcceh10diSSersn4g6PzF
         XJZiy8mlhKnOht6cLIEfwmN8GqihPMuYFlsAJgXldyxdidO2KmBHRX+yEqwUycLeMkEa
         gfi4eoPBV4PvI5/SeQVdmGjResUGBHbR1poDoicGVB69mb38a6FlEBc2+jikIydCMPtF
         Inl5aSzuBUHyHP46obX7ewH7ejR7LO1K51Znm35Hp5bpvC3Uigi/eTsqb/2fxNSb1G0u
         Ir3+j+68Sf231ICgWF2c+MswnlRSSNp/+A1RI7k9eYY8uvNfswfOGbva0eoOSbV/1K+p
         TNnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404006; x=1755008806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cBwjldM3JdO2wmlqR/PzW0gcbqDXNwjVtMOZ0zwB0lA=;
        b=D0hb0Xb8YhrH2FV1NWRnj3Yd8RF64uwlqPQirZMVc0PrWryw5jqV3nYOwbzf8Wr1Am
         6VozxW47xb8W4O70Yg8C+fVQlA/sybjc5BHZ4ggWzMFjdL1zEguelnlepJyYPghu/vy3
         2UFgrfandItq8KZJVKXwrif70N1sdDScFV1JsKdcgkoXOyZnq9cwZDhxH8RcgRQM9mo7
         b7ENxHY3hk/BxYZGnCvuhVC6dfjuY0zkxK0Tv/dj96AfI554o71b3VjWTthS0DIOBGjM
         suLu3qx/n1b78k5RmCvAsvT+sn+ScEkONaFGexnssAmwqJTYqfM/XUqErOCB7d1VmIrI
         alXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWubAkpKsqjl5i7iHWqNQx+oL32Kso30JJV9/vrN/xptJWbkaXfkNAB+8G0QDQxmZ/YLmUYDA==@lfdr.de
X-Gm-Message-State: AOJu0YzneaaRCBBFSVuNUsewtxahwMc67HAqeSOwqFTikVKroINYdaek
	fVHUED4AIcuINZTgj909ZHHdtpQ0pUKApqCOxVgftzDcqAMjRtC279iv
X-Google-Smtp-Source: AGHT+IGC0ZQm7Ng07O2Dbg7+Njk9LF0CvThb9ffIxk7EvncC5U9G3ki+9vbE4vLXS2gm/PE0F0HMwA==
X-Received: by 2002:a05:6000:2c01:b0:3b7:8268:8335 with SMTP id ffacd0b85a97d-3b8d94c1159mr9130542f8f.42.1754404006331;
        Tue, 05 Aug 2025 07:26:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekYUmuIUkOoWU3TTXoJsXTZ7FPiG4N5QhdnHT2Eqirbw==
Received: by 2002:a05:6000:2f8a:b0:3b7:94bc:473c with SMTP id
 ffacd0b85a97d-3b79c35c8f8ls2634074f8f.0.-pod-prod-06-eu; Tue, 05 Aug 2025
 07:26:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMM9a3fXNDcs599LAEdXPzDi+SohgZB3NA/Fnqn9jX94vawKpC/RNr5NXRIvmDttD4uRI+SRyrb6I=@googlegroups.com
X-Received: by 2002:a05:6000:310f:b0:3a5:8934:493a with SMTP id ffacd0b85a97d-3b8d94c114emr10013193f8f.44.1754404003612;
        Tue, 05 Aug 2025 07:26:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754404003; cv=none;
        d=google.com; s=arc-20240605;
        b=XQZ43d/bSy57gCuVGeI567mLJjZf854OU2+3tRfOsn/vJKfi88kAhyeipeN0WXElD5
         mE49xsPrPZ1F1YcrCZJ3+O6iIBMsWZ2q60BgeU+MTDNed2DRdkuZdNNt7fMQr1y18tCN
         N7Xc4IQTqteIL13fkYTSKE+Tnyccq4zw6J6UdAeS7CLCvZd7DpK/OvoGghTzjggSWtIy
         kX8WvrYtIXRz2n/jGHK3M86RD0kMiUQXP0v/7mNuBWVWP0zYrtBrKuplj5jiZ89644Fp
         jQGg9tmgN2Wk7lXxawZQdX9y8o4L7rIVzbbeDbTtP+l6t8K9QGZuWLGpF5vH/rTAsTEE
         0+zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Pl3xBvbmXoSLjMyBTIqb051cyNY5upcj2qfXScxGTG8=;
        fh=ZXhsvJJD40G6/P6vbRTyE0DBFCw8h2Awq4ZhQNc9Hv4=;
        b=WIyhfGCuAjy4YB4s8IWSPLnihWpk9thaokKHEOZB/ZJGworQ0JCQrnkLnJy7uGibOI
         8qzf+mVwoctnFnzxjWu9OtWuGszjtyXBxnZE1CQt7pqVqNuikBwNDhHd4HbpSPcyNEh3
         9gjaGj6jYLyRL08jwiZNS5SPcgytAkCAX5S6Mmd2wf8N53FYTSdYeETz1IyVtNXxg1o/
         oVuMzbMYxvU+FrNW2c4xYWMZYWbI0mQNjd5sAKirLev5fyOl+NsAJwnX540/9EgGmimc
         DgxqU+f3G3RKKKGn28fYvhy1MqVEjwLNci9kRfoOqtO4wU4NkMm54uAQI3DPcAKULaHp
         fj3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I2L72u5g;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c48d27dsi287216f8f.8.2025.08.05.07.26.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-55b7454c6b0so5472143e87.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/Jym4AtYco80B0mXkfNByD3rr1zdr+rAqcQVRsJIMngoE768TBBbCLMpox+nssYk9ngy0gU60uIM=@googlegroups.com
X-Gm-Gg: ASbGncsrL5Ae8t353mmZj0miP9d6h+6PPFZmbWX+6ZHq4YF/me64qFSOD2jJg42qHK/
	9xZl8MLoqTBa1IkBk7SFmc8eZ6Wm3mqn4Z9AtWfFb5Wa/eIi3cwrLKh5XJSD4g8RRlAXt/f5Rtl
	piBb+UQuxkZUdpWk/sySuhBq/L1Mb+ZZikn2jy9aRYtkA6arGWzekB+lzQx+H13BCfWsDGq4jo2
	N/ir78ysao+9djrGonk0EDBcb7P4k/b/l1DVECMEezH/aJ7mIHEfwKd+qtrVGQvyjJMJcarmujs
	96X8ZEPO/wENYm9goL5gxe+A8bfkCDh08sGyzK6G481BlTCSjRtp06ckSp+wKUywHYt1XKxgic3
	OwONuVrNbZIqEzubtGwuwZEaobawOEeIN3VWM7vne5Sg5v84j5184sIGg/1LviJuPljFFdw==
X-Received: by 2002:a05:6512:ba8:b0:55b:8e3e:2be6 with SMTP id 2adb3069b0e04-55b97b2971dmr4253074e87.24.1754404002655;
        Tue, 05 Aug 2025 07:26:42 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:42 -0700 (PDT)
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
Subject: [PATCH v4 6/9] kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Tue,  5 Aug 2025 19:26:19 +0500
Message-Id: <20250805142622.560992-7-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=I2L72u5g;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
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

UserMode Linux needs deferred KASAN initialization as it has a custom
kasan_arch_is_ready() implementation that tracks shadow memory readiness
via the kasan_um_is_ready flag.

As it's explained in commit 5b301409e8bc("UML: add support for KASAN
under x86_64"), if CONFIG_STATIC_LINK=y, then it works only with
CONFIG_KASAN_OUTLINE instrumentation.

Calling kasan_init_generic() in the end of kasan_init() like in other
arch does not work for UML as kasan_init() is called way before
main()->linux_main(). It produces the SEGFAULT in:
kasan_init()
	kasan_init_generic
		kasan_enable
		static_key_enable
			STATIC_KEY_CHECK_USE
...
<kasan_init+173>    movabs r9, kasan_flag_enabled
<kasan_init+183>    movabs r8, __func__.2
<kasan_init+193>    movabs rcx, 0x60a04540
<kasan_init+203>    movabs rdi, 0x60a045a0
<kasan_init+213>    movabs r10, warn_slowpath_fmt
	 WARN_ON_ONCE("static key '%pS' used before call to jump_label_init()")
<kasan_init+226>    movabs r12, kasan_flag_enabled

That's why we need to call kasan_init_generic() which enables the
static flag after jump_label_init(). The earliest available place
is arch_mm_preinit().

kasan_init()
main()
	start_kernel
		setup_arch
		jump_label_init
		...
		mm_core_init
			arch_mm_preinit
				kasan_init_generic()

PowerPC, for example, has kasan_late_init() in arch_mm_preinit().
Though there is no static key enabling there, but it should be the best
place to enable KASAN "fully".

Verified with defconfig, enabling KASAN.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v4:
- Addressed the issue in UML arch, where kasan_init_generic() is
  called before jump_label_init() (Andrey Ryabinin)
---
 arch/um/Kconfig             |  1 +
 arch/um/include/asm/kasan.h |  5 -----
 arch/um/kernel/mem.c        | 12 +++++++++---
 3 files changed, 10 insertions(+), 8 deletions(-)

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 9083bfdb773..8d14c8fc2cd 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -5,6 +5,7 @@ menu "UML-specific options"
 config UML
 	bool
 	default y
+	select ARCH_DEFER_KASAN
 	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
 	select ARCH_HAS_CACHE_LINE_SIZE
 	select ARCH_HAS_CPU_FINALIZE_INIT
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
index f97bb1f7b85..81bcdc0f962 100644
--- a/arch/um/include/asm/kasan.h
+++ b/arch/um/include/asm/kasan.h
@@ -24,11 +24,6 @@
 
 #ifdef CONFIG_KASAN
 void kasan_init(void);
-extern int kasan_um_is_ready;
-
-#ifdef CONFIG_STATIC_LINK
-#define kasan_arch_is_ready() (kasan_um_is_ready)
-#endif
 #else
 static inline void kasan_init(void) { }
 #endif /* CONFIG_KASAN */
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b..704a26211ed 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -21,10 +21,10 @@
 #include <os.h>
 #include <um_malloc.h>
 #include <linux/sched/task.h>
+#include <linux/kasan.h>
 
 #ifdef CONFIG_KASAN
-int kasan_um_is_ready;
-void kasan_init(void)
+void __init kasan_init(void)
 {
 	/*
 	 * kasan_map_memory will map all of the required address space and
@@ -32,7 +32,10 @@ void kasan_init(void)
 	 */
 	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
 	init_task.kasan_depth = 0;
-	kasan_um_is_ready = true;
+	/* Since kasan_init() is called before main(),
+	 * KASAN is initialized but the enablement is deferred after
+	 * jump_label_init(). See arch_mm_preinit().
+	 */
 }
 
 static void (*kasan_init_ptr)(void)
@@ -58,6 +61,9 @@ static unsigned long brk_end;
 
 void __init arch_mm_preinit(void)
 {
+	/* Safe to call after jump_label_init(). Enables KASAN. */
+	kasan_init_generic();
+
 	/* clear the zero-page */
 	memset(empty_zero_page, 0, PAGE_SIZE);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-7-snovitoll%40gmail.com.
