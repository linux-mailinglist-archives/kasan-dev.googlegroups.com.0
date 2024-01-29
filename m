Return-Path: <kasan-dev+bncBAABBVOY32WQMGQEBGGQQXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DBB784074F
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:03 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-210d5a84109sf3649782fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536021; cv=pass;
        d=google.com; s=arc-20160816;
        b=PZA7T5m2sbVqAg67JdI0JFd38MoKKIdP8hS1llu1FA9y14fkrcz1SQ2LR5LVJx05Ro
         SwN64OzH65/9eZJRq/8t4zVwZHN8wezg1bSJv5NToBaNScgye44t/TgY16ZeR45LELrU
         oa3cLRT1k8i8Dwhnc6AxMKSR5mNFiitXVNYJx1Mth15cXPqoAkj0CUdJZK6cMOOHylFE
         g9PPJ+Bxa8sUZ33GTIUpTyPH/nSE6iLaeQysBILA9DHyIrohIXRIbS355j/y+xAzwQ15
         tut5jdN5lqu+o/GbR8BKHi9QA0dLGN+D2DNz8aOVMsuFh94PGxjwF2yE4/sb3igpLNnp
         lzzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7cNFPZVIFU5VmIqHUIvuGDOlXDkSzv/dsCm4dtpFrS8=;
        fh=++8fXJvMQ1UzNvVnm3FJJkCq2GSumUC+qWJSCZ0rp18=;
        b=ftkJxA/aMb42h/HMI1ywoTG7xJfYjNStICavJ2Fh+z/g3XHc7dE77/cy7PHvhPmQU7
         CzLYJLCXj32SMxFSpZS2lgtF08UOiiHXwgsR84XcCIfg+2qnhlx922+Ju59RpcKFirvN
         qCFFFr9PiPykZkDE64O7XtFcCxZ12cKRIi33utCYYcREVEYTjslcLtDaY26rK7BCVmiA
         a23rjOsPdxKw5WfwGrb4xE0mFvS2qAbkuJzLmY7zImo7wMrLXiW6cwWNq4BCCIU0+W6j
         6ZxiLhfv3ha7DxCC6ae2Z82/ltM7c+LRkBVsXezY3DG/Syp3QpsGiILMWZDUXsZ7BHds
         yCAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536021; x=1707140821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7cNFPZVIFU5VmIqHUIvuGDOlXDkSzv/dsCm4dtpFrS8=;
        b=P1snj9tn49mWTcrkMiDYCIj7RqSpjDzPp84DF5FQaFQkeRoCaWHe3ob5ZsvQlPmrvP
         NkYYhn/9V0CkjtmWZGSKGea+v+Q9WczFcVIdrlU4hY0J5OVYFLyCnRB5Zi2D1PMyreB4
         d6XLaVS1VJ+Re8A4PhvchKmOgaNeJpiuxo/EWAMTIx9W8cExU56Spo5Grmsz5QZqVRH0
         V9e6u31C2fIeTHGNygeTW3u6FjscupBQp3dn7QXiWeSZ236XvBCsl8sN2DphDiZw5zyW
         FRp5myTmIvNPyDdSaLVFn0Mjqdkkfvndu1SXkRX3VqcqMl7FH5VchLGHf2D+5OzQFNKL
         goEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536021; x=1707140821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7cNFPZVIFU5VmIqHUIvuGDOlXDkSzv/dsCm4dtpFrS8=;
        b=p6Xy4LGN3QDn+blmgmwH1VKNoMGYWbSJc92OqOcdOfwj24BS465uf/mkASyGG47/L+
         ITGiVp6gHsEiWG6biL3WlBaYFQwNdGZCshizUTalUn3YxpzieQ0Y5ly+P2lBgv1rJrAp
         Hdaac3CEt16ETUed45oh+gEYbusqgJN8vxIwWo3rnFBIfqEaxuRf9DltbYSPDiNgA+FK
         eiK7YAzmvtZJAc9gPnE7pTDQLZiqKUyRDjdiLouKeA8600yC8MYc7ElzilTfIdvj1d6P
         yXpSKEH29SHETOhD9eF8UwBIxhhGhN39px2Un4neU84oe8qq1MluijIC55/QrA2/r7lU
         FMUA==
X-Gm-Message-State: AOJu0YyvHnO33vx9Gf3MWaBgQV3KY+8dWEEtmdqxyhSAxhyhOpKly646
	cxxO24EAlWQIzj+ZlO1bgEBrmPMpVERAULjFMgyUs+eiwFCc4EoX
X-Google-Smtp-Source: AGHT+IG0DckxIEf/0eUGtBy+Kowp4fuRT1kunbgiwyQKbJRLOe1wO7JqbypJ7VbXOsVV2uapOuqpVA==
X-Received: by 2002:a05:6871:5228:b0:218:4c19:f8a with SMTP id ht40-20020a056871522800b002184c190f8amr1863277oac.21.1706536021712;
        Mon, 29 Jan 2024 05:47:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7e10:b0:218:8e45:82e6 with SMTP id
 wx16-20020a0568707e1000b002188e4582e6ls63468oab.0.-pod-prod-00-us; Mon, 29
 Jan 2024 05:47:01 -0800 (PST)
X-Received: by 2002:a05:6808:209a:b0:3be:1ff9:230f with SMTP id s26-20020a056808209a00b003be1ff9230fmr1810947oiw.33.1706536021075;
        Mon, 29 Jan 2024 05:47:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536021; cv=none;
        d=google.com; s=arc-20160816;
        b=RMR9iDc73LFjhAN6Fb0etmS26svIvZ6GEeAVKHh40uUM8Poe5DVLxHFffEI4qk/18G
         m0kNjtjibfCtHXkc7pRMnnrSDycfCfBx4Lpzwo6wRXkXSsWPIwrN1ay6xVjQdOfFfX7n
         ipmSKY8lmNSlnF9YgpJ/nlIFtj15fj47FpoTRKTLQpzhaSigMPZv2px9/DjB5TiFGr6B
         urpDUOMareLqNk6GaPWhv3WtnDfT/VzwNs2dJQa8qQiE1HdJ1UQY4v/VdCIIi9m3YpVU
         HhfzG/vGg2YHpfh43bRSNZpEhqkxte5H2d1l8GPCgtYrjWa1he3oFDtkld3VV/8sgkj6
         8chA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=W+V3hpnEnaWvLyVJnlAq6fqrYusvwPYT3iTx/9ZgIVQ=;
        fh=++8fXJvMQ1UzNvVnm3FJJkCq2GSumUC+qWJSCZ0rp18=;
        b=AaY1nK5OZ4NVtr5cIicN6IELfgnJ+dzuy5BhOTgPnpiTtMJCs5AU3vARoArTlDYMmH
         MgXX+5kbev1s5O52vdGHagzo1hxe7YfVXE0OKU6zGSBUEsoA4EvPMjvkNh3CrgDd2LE+
         /HOdhCL0/bTov0+8OOA+fI75nu1rQTiUWA7gFrhVW+rVCjFw7r7Tb/h6ETs7OhLTJI9k
         IFcyKxTphxlqCfziL+E3oJ/91NSv/9KZsNOeWiJniwIFI2tQh6j/hBQt9r/ky+kKPPDm
         n//uVYF5lBYx+2T75nwEfDoDT6cEJ5HKqX2UOxt5bBnp20Z3trFVyBMMrcKXIj4iwgwK
         51Wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCWbH7IdoviKxX62fzzyH7rbJBSNN1WipXsTVfTmEYqqg+FFG/YKTUHD3SnlQt1i5a4AOhuWWGGhPkZi/Tyms1rmysdjzTKC/kxeVw==
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id fu20-20020a0568705d9400b00215d04848eesi923891oab.1.2024.01.29.05.47.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:00 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4TNqMD0tZpz1xmlw;
	Mon, 29 Jan 2024 21:46:00 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 0E5831A016D;
	Mon, 29 Jan 2024 21:46:58 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:46:55 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 1/6] uaccess: add generic fallback version of copy_mc_to_user()
Date: Mon, 29 Jan 2024 21:46:47 +0800
Message-ID: <20240129134652.4004931-2-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240129134652.4004931-1-tongtiangen@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

x86/powerpc has it's implementation of copy_mc_to_user(), we add generic
fallback in include/linux/uaccess.h prepare for other architechures to
enable CONFIG_ARCH_HAS_COPY_MC.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
Acked-by: Michael Ellerman <mpe@ellerman.id.au>
---
 arch/powerpc/include/asm/uaccess.h | 1 +
 arch/x86/include/asm/uaccess.h     | 1 +
 include/linux/uaccess.h            | 9 +++++++++
 3 files changed, 11 insertions(+)

diff --git a/arch/powerpc/include/asm/uaccess.h b/arch/powerpc/include/asm/uaccess.h
index f1f9890f50d3..4bfd1e6f0702 100644
--- a/arch/powerpc/include/asm/uaccess.h
+++ b/arch/powerpc/include/asm/uaccess.h
@@ -381,6 +381,7 @@ copy_mc_to_user(void __user *to, const void *from, unsigned long n)
 
 	return n;
 }
+#define copy_mc_to_user copy_mc_to_user
 #endif
 
 extern long __copy_from_user_flushcache(void *dst, const void __user *src,
diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 5c367c1290c3..fd56282ee9a8 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -497,6 +497,7 @@ copy_mc_to_kernel(void *to, const void *from, unsigned len);
 
 unsigned long __must_check
 copy_mc_to_user(void __user *to, const void *from, unsigned len);
+#define copy_mc_to_user copy_mc_to_user
 #endif
 
 /*
diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 3064314f4832..550287c92990 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -205,6 +205,15 @@ copy_mc_to_kernel(void *dst, const void *src, size_t cnt)
 }
 #endif
 
+#ifndef copy_mc_to_user
+static inline unsigned long __must_check
+copy_mc_to_user(void *dst, const void *src, size_t cnt)
+{
+	check_object_size(src, cnt, true);
+	return raw_copy_to_user(dst, src, cnt);
+}
+#endif
+
 static __always_inline void pagefault_disabled_inc(void)
 {
 	current->pagefault_disabled++;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-2-tongtiangen%40huawei.com.
