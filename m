Return-Path: <kasan-dev+bncBDAOJ6534YNBBFMHWC3QMGQEVJJ3U2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 114B797C844
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 12:57:28 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2f74d4423d2sf5434951fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 03:57:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726743447; cv=pass;
        d=google.com; s=arc-20240605;
        b=DZNeontlJfSwokn7q9TCc+JyZFFggVXaNO3dfZmZ68tfUew71Puj+SOKlmwhsG3baj
         Fg13NIAWwbnwztxLD0d6juElC9wQNvdpXBrTz6gEOfVZPOsXvfm7wAJp7WvIilPk7wv7
         CnopAxaIy24CUOWL7AgxIhdyYphaitv75YzvzW+m37eRg15fipntvk3wElHxAMvY5P2w
         vRm2L8Z2G/8no7MhHEmcLZkmspGtJPTicRZ2xgTsT0ehScNJgwOlKYGQ6GtySGB0/NSH
         egPHoeCcx/22H/X7J+EtdiC1OiPBdw4ojCVFXWEU9Max/LRWhzbHsuP9JUhuyuWOxp/B
         gGZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=Yia24dihtte+uWVX0sius4FwkuiJLmNinl0OJNEdAoc=;
        fh=0UrEc4YxUirSM2+f+U3Fyefi+QlMNWHkWPKcdbXZVgU=;
        b=a2V7lqKRoia2k5h22S7pgwnuwvXIoG8aGdMk+nHbK6rYhtWC5n0dZcz8KvRo5Pwfwy
         ysiEQT9CgINBwuhykEsfcbkOtdZAEgI+LrTwM0Es9m8ZEM0aBuLIIHhZ2RMBkYx7q3AY
         s3LHU4HeLH+rV5R76rSCAx8Oik5qVfrSmdEKZLrxIp5chmPISTPdTAYc69KRUuQBWzo0
         zFoOOjtVMYvvZo8NozggbLpzHeM1CScK0eyAbbGpHhl9brWiWe89K6i71qsI1fEKHuq3
         qG8c1BbrIoSuBHAKPN4uUzWWyeadFcbtBvCeZR2jk3YS2FI/NET1fuHqinog6fYvjM5I
         Rw9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=czA0yUay;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726743447; x=1727348247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yia24dihtte+uWVX0sius4FwkuiJLmNinl0OJNEdAoc=;
        b=NbREQjzz3fSWpYmXaSBOkSDlOavTQc4QrHbIqWDvhV7Sr+zzbbQ47Zh30QkEYu+5y2
         OXp/uxC0KOYSkE69ZPAmAg2BT2dM1PVK8GLjAA0Cj8L0qzK8czTunHKf+7BYMUOsOBPi
         5Ja7fygwyHBT5ZgciepLHz54qxgTChDZgOs9SGf/1Tz8ncqPW1DFHAj/3gqkcS+1444u
         LG9nCx/HNhZ91IbvaFFYcTkabjH0qm613DXPtlgAIDmBJWVwD7NAXSk/5S2GkhSaS63H
         4HjeraQj3D6pD7rmpC95K0HMwWSa73UNjLiAT4Z8EqREXWzPT+pUv+wPBCRCOEKJQ3We
         WnAQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726743447; x=1727348247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Yia24dihtte+uWVX0sius4FwkuiJLmNinl0OJNEdAoc=;
        b=VPxVQT5yEhx+vWFKWicWkqhQSDRxLBTzlXBDe7LGe7gA06tDSColecrJVBRDubIZqO
         BG/lShh8aE0XI8b5LOcR7HsIWUhCzPQLmC6FHm/2ZSgTpyEgIIKeRRe4XcbeL83r/r+d
         G7Qv4e7wLRfW1UjVPmfNiCV3R+ZhKwhWI4GWdrxNlA+ELdasTVqCQNLYojmRR88sp8zW
         FP9k3dzvhDoC9oY4GlNcPIgY6MousHobej/wYpNvX/5sETkMBumTfD8Z9P21J9z6L9BT
         KsiP3MgUidqdw1woz0FFN0wWjBymIpqGlUMwX+WIpdx5QO78Cw/oS0GFetfL+mBl8kXf
         /owg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726743447; x=1727348247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Yia24dihtte+uWVX0sius4FwkuiJLmNinl0OJNEdAoc=;
        b=dMH6W0C3OEMqkyr9p+qTi7xXRTvaOXYxHB1ToN9KnTv/w/1eB4ldOjqyCfTV577oWi
         Zh8wcRt5tegsUmMgTGWmKqTxoyUVcKH2eNi8IHUJFsgs9hQX4QaSlgRyWPOIkKfFbNth
         +029QEneybznPnyM0sbERc24O1z+KkkvQJToLcIYhbXSoHjsP0AO08TnrP2gpzrVHZ4I
         XW1wuapsbR/50r05K/6sKm99SlzqSeeUf0D7afKY17JLBukNQ5JyP7u9N7YwErZ7YMUS
         +8sOOj/zjWGzQpxuNMunzXYQWEC+g1jbSi8HKyIBdqofW9Hi4Y1SDWz/WvLB9pQ+ek/k
         Curg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGJ+E9Y57LEKXvNGKzRzFbSUgDWQVfpmF/4HdQ6s59nwx8s6sjoRj+0beiDaxOMri5eoNPlQ==@lfdr.de
X-Gm-Message-State: AOJu0YzTdVDB2iK92ZPWNgjvxnYDCBvMGiQi8ro9XwEF/edMq1LwY2ha
	Icnx9bQK80gDajbGPPPkO2DGuQdTtb7zkxQxtP4xvsPX8xcGNnYF
X-Google-Smtp-Source: AGHT+IGgG62eJ55Mwz4GYRwDHTetszBAi/yjlWiHLT5sg/qYltAcirqK6upkoy1WDQE6SSE8f5mEuQ==
X-Received: by 2002:a2e:be0b:0:b0:2ef:24a0:c176 with SMTP id 38308e7fff4ca-2f787f31805mr138916941fa.28.1726743445837;
        Thu, 19 Sep 2024 03:57:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a04:0:b0:2f6:6455:d615 with SMTP id 38308e7fff4ca-2f7c3e98d66ls2810261fa.0.-pod-prod-08-eu;
 Thu, 19 Sep 2024 03:57:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIpK12B/hXxEnMYldhHvOeHzTjp94H5eUqkecXpyil9If0k7AEnCzjaihE5ERPSILEg6QIw2oy6Po=@googlegroups.com
X-Received: by 2002:a05:6512:31ce:b0:52c:8c4d:f8d6 with SMTP id 2adb3069b0e04-53678feb475mr13184821e87.45.1726743443347;
        Thu, 19 Sep 2024 03:57:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726743443; cv=none;
        d=google.com; s=arc-20240605;
        b=VNdn0Jl/UPV7Skru7Fm84ifUmT3KHYKtfs4b3L12jkCme1vns00eOG2jxMHYFhPqTx
         fOTnS/b8FRV3A+AlOGtNtPxaOkP0M/XW8fiq+tb9lsVeY4uwUcUuaynYrsibLVGWiOEK
         htO+Jn9aY2GLlHppCo0hs+9zhTowXakRcWrEDbYrBW5/J3ezzUb5m8o82wnTEdzIjs7M
         IMTwGbMyVUelCZY57FK68vW7g662gkw3zSEfDepSes9GCm/ceZ03VEGoThajqlh2YVa8
         +vp+7KQidNxY9PSZaFUSVwvi7+jxHoArUUd/PoYnwoN09FY3sePKS7EHYJH9kGx2wWIl
         pXZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mJ9HZHJD0QLNFkZHIpeJlyi0Ek76HYhPtHMe5HLX1eo=;
        fh=VoxQlIDIp6az39J7SKgQhjqIFYzBqv+8p53WLwNlT5E=;
        b=Fho6oiN17yEfmP0uUHqhf0kyqz2NIPOXQudo4bVbOFUmKowJ+g3dblL+tEVD+So1PT
         AJ3WODeCBRexuM3axnR26RGcak8vI5p+CWFKBwtZC108OT3VQmfoGMpShCbyerDIygTV
         SHVGOhG7hoDLzZRQr3tY6i6HdSw1EuZKUDUPvCn6YYjBbEFbzBw0WyL2073FVw8Kg8po
         HuHFuTx5cymK/8kx03LKd+AKmwazjfqCj3cdj1+7FrdlQ/uBXstycoPllK9P7DvN3Luw
         yqdjuI0wHXcx/F85iLq1Ybycf3Fdg7yAzPnaVQ1Y3tdNaOuXCqYvRGJZCUR/C1ozVYy1
         r0Xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=czA0yUay;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-536870c6ca1si239706e87.10.2024.09.19.03.57.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Sep 2024 03:57:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-2f74e468aa8so7743361fa.1
        for <kasan-dev@googlegroups.com>; Thu, 19 Sep 2024 03:57:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVycvqAWDj5pVEFRU4IPd/ERqA8s1hEcS8vubaKSVePAfQ9BR/eFe+FOysf2YHwM2tClr/8HRcypOo=@googlegroups.com
X-Received: by 2002:a05:651c:154a:b0:2f6:4aed:9973 with SMTP id 38308e7fff4ca-2f787f5833dmr156325931fa.44.1726743442445;
        Thu, 19 Sep 2024 03:57:22 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2f79d2e1d8csm16223341fa.21.2024.09.19.03.57.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Sep 2024 03:57:21 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	bp@alien8.de,
	brauner@kernel.org,
	dave.hansen@linux.intel.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	glider@google.com,
	hpa@zytor.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	mingo@redhat.com,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	tglx@linutronix.de,
	vincenzo.frascino@arm.com,
	x86@kernel.org
Subject: [PATCH v3] mm: x86: instrument __get/__put_kernel_nofault
Date: Thu, 19 Sep 2024 15:57:50 +0500
Message-Id: <20240919105750.901303-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZfg2E7Hk2Sc-=Z4XnENm9KUtmAZ6378YgeJg6xriMQXpA@mail.gmail.com>
References: <CA+fCnZfg2E7Hk2Sc-=Z4XnENm9KUtmAZ6378YgeJg6xriMQXpA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=czA0yUay;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231
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

On Wed, Sep 18, 2024 at 8:15=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> You still have the same problem here.
>
> What I meant is:
>
> char *ptr;
> char buf[128 - KASAN_GRANULE_SIZE];
> size_t size =3D sizeof(buf);
>
> ptr =3D kmalloc(size, GFP_KERNEL);
> KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> KUNIT_EXPECT_KASAN_FAIL(...);
> ...
>
> kfree(ptr);

Thanks for catching this! I've turned kunit test into OOB instead of UAF.
---
v3: changed kunit test from UAF to OOB case and git commit message.
---
Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
strncpy_from_kernel_nofault() where __put_kernel_nofault, __get_kernel_nofa=
ult
macros are used.

__get_kernel_nofault needs instrument_memcpy_before() which handles
KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofault
macro, instrument_write() check should be enough as it's validated via
kmsan_copy_to_user() in instrument_put_user().

__get_user_size was appended with instrument_get_user() for KMSAN check in
commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.

copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB bug repor=
ts
as expected for each copy_from/to_kernel_nofault call.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/include/asm/uaccess.h |  4 ++++
 mm/kasan/kasan_test.c          | 21 +++++++++++++++++++++
 2 files changed, 25 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.=
h
index 3a7755c1a441..87fb59071e8c 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -353,6 +353,7 @@ do {									\
 	default:							\
 		(x) =3D __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
=20
 #define __get_user_asm(x, addr, err, itype)				\
@@ -620,6 +621,7 @@ do {									\
=20
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 #define __get_kernel_nofault(dst, src, type, err_label)			\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), err_label)
 #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -627,6 +629,7 @@ do {									\
 do {									\
 	int __kr_err;							\
 									\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), __kr_err);			\
 	if (unlikely(__kr_err))						\
@@ -635,6 +638,7 @@ do {									\
 #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
=20
 #define __put_kernel_nofault(dst, src, type, err_label)			\
+	instrument_write(dst, sizeof(type));				\
 	__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
 			sizeof(type), err_label)
=20
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..d13f1a514750 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1899,6 +1899,26 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
=20
+static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+{
+	char *ptr;
+	char buf[128];
+	size_t size =3D sizeof(buf);
+
+	ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(ptr, &buf[0], size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(ptr, &buf[0], size));
+	kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] =3D {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -1971,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault_oob),
 	{}
 };
=20
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240919105750.901303-1-snovitoll%40gmail.com.
