Return-Path: <kasan-dev+bncBDAOJ6534YNBB7OP6XBAMGQEQC3OUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E137CAEA290
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:15 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553cff91724sf575451e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951934; cv=pass;
        d=google.com; s=arc-20240605;
        b=IddnIFnkF09t1Q5/1hVsblXLOSP5pRm1o+eQYioq6A5maWUEyiIDsbElx2BgEkhZ7g
         dTkwsPfVxi2GJol1GDoPiP0ilY2b7Bov5VCTEj8+eTE5ZmwxnouxndKRqtm2ZFJT0e8S
         f9mSLf54te4NHaQOwu3sfpM7UPgjzNzATemPrF+NZefjFDGo/DYztvvPDGNWO/Q1q2Re
         jnEj2zrpUeUpn9wYYUbwf/oAv5zWJ4mTH+j9oEmi8NhvHplsHMUHKqcHU+xS+xC283M7
         zpC26r6T6JUUn4W2ecg4/vKQJQVO/MIN4LloMwkX6H5OrTXt/S5hFUjVhrQEZ43AsRIj
         DqqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=tYGG931A0QChc0c8cvvqAOaYg3If5ecW9QoUbuCBu+o=;
        fh=ib5p25AJeaip+uivDLEMSC+2Rk4Wuj2hWZUvkyMZ7k4=;
        b=Q6kXjNiA2LJwMdDhz2L0gDhb4URcfV0ACc8FowzCnQCmHJAMxQ/S8+UXg5ShXG02GS
         F/ZgBhSjhzhH8+/7/4m231J/1aNN+XlY4ESDpCOrDyKHy8O9lLG9rCl+xHERL1WtV1UD
         gBfAjj7LUM3W7kkxSlmjoeMCOcXpgjgTqxUkKUSvwsl8aZMB6U1wrsM6N1QoMAKXwwtV
         2FqhC2Kf+HT0yX0gGXdqhZlGjgMoGPIf/GgCa0+vnByADtwuWYKDfnGoKlsPRP1GxKgt
         vam1UiKaY8MWXtMBC2LE/dV9eHyn1JKmG9cbPBrhar0UczLnGyGUStW+UqpaAIx94LKd
         k3yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O0HfL8Kr;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951934; x=1751556734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tYGG931A0QChc0c8cvvqAOaYg3If5ecW9QoUbuCBu+o=;
        b=f66FGUIG7PfD+HW+BNS+Gb5ZnvGKqkiU2oaHSYtk4Vb6Ckvbme91UkigT98UJp2pr0
         DKZyxPe4yS94aqhoSc98OtYd3Gx9R2lSh//k8y4q22YHeZnyP+dAaPwOptCsvZNqH7NK
         JZ/rzGuCmlA8DAsizZyo38SBtynfcM94qwLVu0C0235bcua448tWWIKF88Fiw8B3xcIz
         mYlJs75yejR14G3EN0ZNGWh9wQU7U61b9b71Csp6YMxjVYQekip04HTNWQ5ucC9zjZ4L
         wzf4UK5gaL+1Swmf7CARaQIjQLMdtRQbVNbJmzKYYHRSWh26+oRzrDQb73JFtILeU73E
         n94Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951934; x=1751556734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tYGG931A0QChc0c8cvvqAOaYg3If5ecW9QoUbuCBu+o=;
        b=VhNnX2fbFgRPKRVuHE64XdI7Vx5lDjpSGPk3AwNdI9JTdXXdVZN29cE2DwgJ4ljnmU
         jFma1fwmVS3QkrX9SXb5da03SVA/5MBi+xueg5EUHi7dj1Gf3wkMT8m8z8H2dowAuABr
         nTmv4bTQ2hyUqSmUzyVvUt61guYqpALtf2j/d5NxgJJL86FqlSdTW6RXdXxpXtfhpvFB
         J5GUGzx7Q6opIXTfXKjHkKiEiDEEGbRptMBcC2QJ/ofkFwgn8ilHU2QnEABW94/Ubmon
         Ur+jzhN2uuhxH5BhfAdEY91iAVRNNBIWM5gxbuh5YTpAJBVaFZBFa3vOu5AI3IeyW2wL
         GXXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951934; x=1751556734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tYGG931A0QChc0c8cvvqAOaYg3If5ecW9QoUbuCBu+o=;
        b=cBEIDQKgCEKwQTJowdtQeASg8bhvCKq1VRsfFI6HQyaXX5nVgcwjsS/qYs029DvMyr
         nWbGWXg2lKXxbKulXrlbt+rv6C4M82+QQHxYJkYPo7LZQN2DsZcOwIco/QMxbdG/dsKP
         2hyW/m7rKqHNVxLm7vk/6rYZim6RbosNZLzC2gt34cseTdrsXzbOSts8QWtMhgeB1yLb
         bdr/fQ959Znod9ohUADy9/++rtZexSC5gFaAPzzuvQbGLu48xYEqfiyuFPO/zkckdAnY
         JzzNhl2Fns+KZM1Mbg/g8XSMD5LRJOGkG1pGS6YfQEKF7IHQB2hRgeNaCbtWwej7nC1D
         XUvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhRavu1ienxN+15cvTCjzIR9k05rfjbxP/3T4eplSRiLD2uUEkceevl1xHysG7E6ONLDwhEA==@lfdr.de
X-Gm-Message-State: AOJu0YwWbvmlGdnxNskm+O9WTI0AH6bIPDNNesNcNQW1kR4HxddPVBBW
	cXV/yrfJmYY7vQtp7xf5yDeYO70nIu0HMZv7sE1kaakx2K3+kBFzpAXV
X-Google-Smtp-Source: AGHT+IGi9wf7uWZkZ5nh2tlAwgylsGF/xXNeO+S6kbLXqof/kc+AOgYx5w83Bv2QK7xYsjM4BpWtBg==
X-Received: by 2002:a05:6512:3b22:b0:553:24b7:2f6f with SMTP id 2adb3069b0e04-554fdf5a371mr2822063e87.51.1750951934180;
        Thu, 26 Jun 2025 08:32:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/UnXRjedc3I4fJkR3xJy2Sp6o1Vr2sMNbcZ89o/9oSA==
Received: by 2002:a05:6512:6088:b0:553:67a9:4aa1 with SMTP id
 2adb3069b0e04-55502e0649els389933e87.1.-pod-prod-09-eu; Thu, 26 Jun 2025
 08:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzT4wRpMOgtzgSuKMzHnq3B3usxIC09oe6H7ItYm/lAh/WNWUnzUvU9VeF6LDHuVgqRY0jAGlHu/o=@googlegroups.com
X-Received: by 2002:a05:6512:3053:b0:553:268e:5006 with SMTP id 2adb3069b0e04-554fdf64e39mr2640351e87.55.1750951931687;
        Thu, 26 Jun 2025 08:32:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951931; cv=none;
        d=google.com; s=arc-20240605;
        b=fK8YwI65VJ5zVxTLUKcsrKuBIJHfA9sJYk0ldO6izmUJ1BPLk6Fa5+Y99WTETVv4ro
         LwI32hGwbTSf9JHqZjUSEHvgsSFbLoIFafT7EPF5TTavPOajVlsO+uAgrBT1qLRzHRMc
         b+RO04fnEmNcxaSvrfmFFql1iEoPCCEiilwwlUK+D5nMHydHJSmh4OJNkdV3EFK160w4
         tQeGS8gpHH0180QdyEBwaL+KooSyp9Uhj+XhgTMxKQky8hmkjmP7KHEZ1pKi6nsLyjVB
         2RlUTJhfRFb2mB6RdS+3TQVX6cbB8bivmDtN1BYS9qKFFiLtNMgwstNzWaWZ37xWHMEV
         +BYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8WWyylL/OQDZN+BQlllp9O148iIrISnZhKRdMW4Il1I=;
        fh=Aie1URTuEZHZu9g0zqceodnFEEp97Xajzta8nBhYLfc=;
        b=SoV7PyY0KNWZy33oggQFlUtV7n8316N8623xpqIWyBbykAtRhJdtk61uylS0ZMvZGu
         noXCjsum+ZsK2GcLmrQKwMiv6xNPi/qWS1vKkLrMWeSGv3XCl+XWdEKyfdrKDEh6BKD3
         NLMoGGtz2b66wptNNt0bb1DSlAjEqQ98i5gBEGMbVTKsIOA4fUUkOTjkI1P7ztIfhSSN
         Vbp8VnKjGuFbTYfBLyFp96zHr48gC3BEpsrRMx+oBrj3CF+wR77IRXymD7Ist9UdZ7Op
         iUSab7Ra+bMnACtJWmryCDfujymZiT10m4RPWhBgkNd7vMaMYqgJZ0PPXsmpSkAui8DA
         GiTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=O0HfL8Kr;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b29d6c5si6188e87.9.2025.06.26.08.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-32b7113ed6bso11702781fa.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUryipu2n8vEEAjx9S12qAszM8/rAH9D0vn5S4Uzs3qymcCHZbPWIZ9Nfm44ZHVVJD7CrIDKVzbQ3U=@googlegroups.com
X-Gm-Gg: ASbGncu3s5CRrNkP6hgZiyP93fuWoBNnp2qQP7W+CHGnlQcKlkn57N4vM2sP9hCC/0M
	/TLDZue2yxC2L3FCS4j2QSS1MjrvGztzwnO01DPM4DAOeadelZH+hNRNQzJVaex67mMtYb50LFU
	rx7sTSh9eq5a9J3txDY5xLDWr9Q5/7I5yhJtX8H2jeCmPy6wdAOA8BhhgwgCyOo3WFf5UcDxtjV
	ondvKn53nC6zD/zn3SJ3bbHwvmjqcl/e3JEvw7R9F9flyzlaZol8rmGSigtQsXTZ0pN+lDycgpa
	oyM6uD8kdSKYIpoa6LayLLJMKQwufzVGQw22TvjJuqiLnY3kwe9F3Ykp4ABYm5T7ZNvxqpY05Me
	9lpsx+5sXKUwQwmtH/NkIVL5+1Y86+hpMra5qxU+y
X-Received: by 2002:a05:6512:b91:b0:553:adf7:e740 with SMTP id 2adb3069b0e04-554fdd1d728mr2765576e87.28.1750951930696;
        Thu, 26 Jun 2025 08:32:10 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:10 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 01/11] kasan: unify static kasan_flag_enabled across modes
Date: Thu, 26 Jun 2025 20:31:37 +0500
Message-Id: <20250626153147.145312-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=O0HfL8Kr;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22c
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Historically, the runtime static key kasan_flag_enabled existed only for
CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
architecture-specific kasan_arch_is_ready() implementations or evaluated
KASAN checks unconditionally, leading to code duplication.

This patch unifies the approach by:

1. Moving kasan_flag_enabled declaration under CONFIG_KASAN (all modes)
   instead of only CONFIG_KASAN_HW_TAGS
2. Moving the static key definition to common.c for shared usage
3. Adding kasan_init_generic() function that enables the static key and
   handles initialization for Generic mode
4. Updating SW_TAGS mode to enable the unified static key
5. Removing the duplicate static key definition from HW_TAGS

After this change, all KASAN modes use the same underlying static key
infrastructure. The kasan_enabled() function now provides consistent
runtime enable behavior across Generic, SW_TAGS, and HW_TAGS modes.

This maintains a backward compatibility - existing architecture code
continues to work unchanged, but now benefits from the unified runtime
control mechanism. The architecture-specific kasan_arch_is_ready()
implementations can be gradually replaced with calls to the new
kasan_init_generic() function.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 include/linux/kasan-enabled.h | 10 ++++++++--
 include/linux/kasan.h         |  6 ++++++
 mm/kasan/common.c             |  7 +++++++
 mm/kasan/generic.c            | 11 +++++++++++
 mm/kasan/hw_tags.c            |  7 -------
 mm/kasan/sw_tags.c            |  2 ++
 6 files changed, 34 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0..2b1351c30c6 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,9 +4,15 @@
=20
 #include <linux/static_key.h>
=20
-#ifdef CONFIG_KASAN_HW_TAGS
-
+#ifdef CONFIG_KASAN
+/*
+ * Global runtime flag. Starts =E2=80=98false=E2=80=99; switched to =E2=80=
=98true=E2=80=99 by
+ * the appropriate kasan_init_*() once KASAN is fully initialized.
+ */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
=20
 static __always_inline bool kasan_enabled(void)
 {
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2..51a8293d1af 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -543,6 +543,12 @@ void kasan_report_async(void);
=20
 #endif /* CONFIG_KASAN_HW_TAGS */
=20
+#ifdef CONFIG_KASAN_GENERIC
+void __init kasan_init_generic(void);
+#else
+static inline void kasan_init_generic(void) { }
+#endif
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c7..525194da25f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -32,6 +32,13 @@
 #include "kasan.h"
 #include "../slab.h"
=20
+/*
+ * Definition of the unified static key declared in kasan-enabled.h.
+ * This provides consistent runtime enable/disable across all KASAN modes.
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e..32c432df24a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -36,6 +36,17 @@
 #include "kasan.h"
 #include "../slab.h"
=20
+/*
+ * Initialize Generic KASAN and enable runtime checks.
+ * This should be called from arch kasan_init() once shadow memory is read=
y.
+ */
+void __init kasan_init_generic(void)
+{
+	static_branch_enable(&kasan_flag_enabled);
+
+	pr_info("KernelAddressSanitizer initialized (generic)\n");
+}
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b5..8e819fc4a26 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
=20
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tag=
s().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index b9382b5b6a3..525bc91e2fc 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -45,6 +45,8 @@ void __init kasan_init_sw_tags(void)
=20
 	kasan_init_tags();
=20
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=3D%s)\n"=
,
 		str_on_off(kasan_stack_collection_enabled()));
 }
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250626153147.145312-2-snovitoll%40gmail.com.
