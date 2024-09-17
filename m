Return-Path: <kasan-dev+bncBDAOJ6534YNBBE6IU63QMGQEZ3Z47SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B798897B48A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 22:18:28 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-42cb236ad4asf39208755e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 13:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726604308; cv=pass;
        d=google.com; s=arc-20240605;
        b=jfRz5g8yz65kXuMJKiM5ilfqr/o65286rbXXUQWgJCaYmsY2BQDXQp/jpRl4UYwDBn
         VzTOv83IxfNgGH4F7e0oE6SngETIHWc83DlK8VBxODMFvQHZvsdpEFcClfK0PoE0PCEa
         ECIdq2tdivPAP1hvaBMBtvFlAQo2l6feOg0my/UWH0oklBw8IkHMB52Ufvl6PHUzZAzM
         iSlO9E4FNn1RoccJqp1pEeYk7elUZCD7RJf5+nrinojk0p8Xr5oYkZq9mtYdp/ovBC8u
         2ZpciVJUGQwtwAzCiDqQW9ZFdKthkbOui4KeluUdtPknYiEpAFNXoaSFkMwZRjJMD6q2
         VBjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=o7j8AMNeiQv+LLwoOgzidv0A+VJRN5+MVqBWMqslfAw=;
        fh=A4CGwE2QdCyt7jI1a1/Xax8biK3tNhu51WHpAA4vtQk=;
        b=hnNO+SOinoFekIgfhOmFuLLWsZgor7CMp+Qm1L3ubRDgqwVWGLMSCmtCwWAgpyYu1v
         noUGLk2nDztab2adqwamHJfE0Mg7m59svVVxRQsQZsARyZO76gczGxnIwwXZRaZv2gqp
         tJ4K/a5vBwPbVJ6VqlJltD31Kq2mCWzx6rOccpj3f/dplqfd98AicgosYfwr4CokUffT
         WvACAzi3I93Z+Rr7mMdZBrv59YBItGpxnwCrAR5DKAfrl6likR0818UMYZGTk6oWz0Wm
         jD9HtqL956+OwGGJnTSecmvM6e3PNKD3IC2GwwRgJz+gGo8DGFV3tG986FEe/fgH/+rI
         uNjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ABETYYwz;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726604308; x=1727209108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o7j8AMNeiQv+LLwoOgzidv0A+VJRN5+MVqBWMqslfAw=;
        b=C8numbFDr/IlvpQKjN+T7QFfiT8Y3LO2ssmw0Wj+h0AqsWmeiYjokXEEp66cVXxjP3
         sD2Pa6fXq1J4U24vOAY91wBOr1FiZqRI1wiCofolx21oIbzhOcxeO7UmUH1N6OXw1OIr
         DlzIwnhAyciW5iF8F6Sx/7qEIITd10GbO4LWGXnAKRYNuv/oPjB7Lbft5vtZDb03zGuH
         kgww6xQIgzW9uT69QtFbgJyf26ujWi3OdTsDMjRO+aKtj9H5b2++q7+grK4ZDMlDgncb
         F7JwPi8zEqf9JvOSGHs9+Hmeza4z0evYd7PTLAKGzUU0YrhuTn+AYElSMyCaaMLhHUmE
         jsWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726604308; x=1727209108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o7j8AMNeiQv+LLwoOgzidv0A+VJRN5+MVqBWMqslfAw=;
        b=O3ByWudkjZn5YKB+jjyzarqvRF+HjkP6Ye+WEuuSgmD25+wMDGtGxdgxq9cg96MCdE
         2J3AOEbZGlAScsTFK8oXrrkajYKYewhESE2aPeulsK3HFynQFI/kwPC4IPztK25fbzed
         1JlNN70bU9PPI/hWkDoa+P/nS2k2pWBnge05P1+Z00Z8NYLhOZakA2j2co701VH54acM
         x8m+C6lWT66xH9DG6m/L77ueQCkbxGyE8E6SfI03C/uK2oewMD+DnE2oGNdBi3h7aLR3
         /YOBsm/g95911oM0I//c1cRUsI6sTz1xf8Qc9L+uKvT59B9htWAUDshNr+/S43CkBCEO
         i8JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726604308; x=1727209108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o7j8AMNeiQv+LLwoOgzidv0A+VJRN5+MVqBWMqslfAw=;
        b=Ao7x5x/8Z1AIimT12fwbkjDerR2sHNiNLEoh6yd8F62nZnslEP+tx4PR3wc6LxgnER
         kQ+Fj6GtdqrnsGqodMqIy6fxvYxc9nB4ZyEiEwLygPluRRwsU3r1NGw/p/TEzizz5clb
         II1z8oXmKMMlp1fd8LyR9Ncds1ApYpezGwKtCmVvEVoW2soiEEVn9Y54S42MBjb0ZCmK
         5lDzQbAA5G9bViPzZ8BTrlOguFC9umijX73c7BJ8D8oMYOSrb4pBwnDPNKSfupCedc7T
         nnbswMhw1JLvnr/p1hGXVR58E6VGpBA5JpZV7KF857XI0DwrKXHInzpnSHeeasUtfGXj
         vRdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEOt5AH+k3AcyJ88Cc9SYrHEP5QER/JAl6lwlRH/ZvZYZ8VKFldyl+XUkvKEo/lMMwDzVwRw==@lfdr.de
X-Gm-Message-State: AOJu0Yzb9YPN6bs2ktH1PO9dmPdZcNrv4ZI+FEe7OqNfdhE7OBRyYLfI
	OKknndExsB3mvhCaTx7oYTIT8W3yCjPHFYMSbNYhlHHK7xhKmxAl
X-Google-Smtp-Source: AGHT+IHpPdEpC+vcdsOfeUZ3CnGamnAnCQBuDd1fMKH8a30MMqrYtvSev+0FIA3e9GMhX3+laB8Dqw==
X-Received: by 2002:a05:600c:1d12:b0:426:554a:e0bf with SMTP id 5b1f17b1804b1-42cdb53eaa5mr187907325e9.16.1726604307517;
        Tue, 17 Sep 2024 13:18:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c8b:b0:42c:b037:5fe4 with SMTP id
 5b1f17b1804b1-42cdb522d03ls3416895e9.2.-pod-prod-08-eu; Tue, 17 Sep 2024
 13:18:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfDiphUpp28Sx9BoQsMyHgPfwY7nSIBAYmX6V9Qe1YnEA6nfurNEwasZHVUFJbqiX5rx+ndReo8DE=@googlegroups.com
X-Received: by 2002:a7b:cc88:0:b0:426:60b8:d8ba with SMTP id 5b1f17b1804b1-42cdb6a020fmr165069155e9.28.1726604305245;
        Tue, 17 Sep 2024 13:18:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726604305; cv=none;
        d=google.com; s=arc-20240605;
        b=GppIdFeQjChSjd7pqo97BZtqmwGIPCwITr99aobD6fu+EG64x6u5rknvBdm9YI0jeS
         0PQ+n8tZuw/bOeHHd2E1aO9jaKSrGjrjEFxq6TBtvbyNQpEqrCl4s74efJ3ElmmvGnto
         JRBQ/WLMVtFyF55RHflp2OECoxMpZ5oklHGrNUebM6CMLzUVcdKrnU0EpOcZRmgEaCxr
         KzrPumCWOJawtnWXCNiNQRjQvYqbpxedFWpb4eI3e/4XXxRzsCreYjMEhwgWOMXMY8cS
         Kn45qWyZ1dqxUCT/0eAWzRq/teoOCnGk3OK+rcrOADgkeNUePF8H2Wq8lIpSoipU156t
         CMdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1KPVK8WDP2lu8d6Rf2OpDhu2yQ4Y7AWH6O/hGAY3qvM=;
        fh=TkCrgMiFzIX8sA3PsjFOrT3tiR9GVpSl3vo896gplEc=;
        b=F5oX9CkkUPVcZQCBPVnIdljGqjhPemrWJ0uDYfLtHbdCkadcC5r+MOHIZyfomynFWI
         TB1FkbiQ1TuhRKjuUVvElAeWuIU8qXTqRtuWrrWwTWeyeTR3cfIxiD77KscFBfI9/1oI
         tUHX5csbZ5ObeBKdygoKb9GSWkQBJk8DfSuimmy81LjS8DgKjW62k2G51urdXBXC5+Ig
         smD5lMVYR1lrsXri6Kow2MAI9CkHY1cZkKvfyYPm0ulfcehs70tls9HBDGUh4RpKAf9q
         F7qg31S8xlueW2pc9pywt0NgNjn4ayoWe4qLbqdpgKehYU6iuRKPoxkgonphoPK/LTTq
         vcGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ABETYYwz;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6bc41624si1717785e9.0.2024.09.17.13.18.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 13:18:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-2f7657f9f62so66213851fa.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 13:18:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8e7DnewSiiIGwv7r93cEeN7z1B2ZRnfAXWQw5yOv3wqOS4Lc+dzZz2Qbsn91pRM12YdhBKJYAa7I=@googlegroups.com
X-Received: by 2002:a2e:611a:0:b0:2f7:4c31:acae with SMTP id 38308e7fff4ca-2f787da5004mr82814691fa.2.1726604304078;
        Tue, 17 Sep 2024 13:18:24 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2f79d59b99bsm11668051fa.130.2024.09.17.13.18.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 13:18:23 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: tglx@linutronix.de,
	bp@alien8.de,
	glider@google.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org
Cc: mingo@redhat.com,
	dave.hansen@linux.intel.com,
	ryabinin.a.a@gmail.com,
	x86@kernel.org,
	hpa@zytor.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	brauner@kernel.org,
	dhowells@redhat.com,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH] mm: x86: instrument __get/__put_kernel_nofault
Date: Wed, 18 Sep 2024 01:18:17 +0500
Message-Id: <20240917201817.657490-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ABETYYwz;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::229
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

Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
strncpy_from_kernel_nofault() where __put_kernel_nofault,
__get_kernel_nofault macros are used.

Regular instrument_read() and instrument_write() handles KASAN, KCSAN
checks for the access address, though instrument_memcpy_before() might
be considered as well for both src and dst address validation.

__get_user_size was appended with instrument_get_user() for KMSAN check in
commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/include/asm/uaccess.h |  4 ++++
 mm/kasan/kasan_test.c          | 17 +++++++++++++++++
 2 files changed, 21 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 3a7755c1a441..bed84d3f7245 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -353,6 +353,7 @@ do {									\
 	default:							\
 		(x) = __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
 
 #define __get_user_asm(x, addr, err, itype)				\
@@ -620,6 +621,7 @@ do {									\
 
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 #define __get_kernel_nofault(dst, src, type, err_label)			\
+	instrument_read(src, sizeof(type));				\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), err_label)
 #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -627,6 +629,7 @@ do {									\
 do {									\
 	int __kr_err;							\
 									\
+	instrument_read(src, sizeof(type));				\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), __kr_err);			\
 	if (unlikely(__kr_err))						\
@@ -635,6 +638,7 @@ do {									\
 #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 
 #define __put_kernel_nofault(dst, src, type, err_label)			\
+	instrument_write(dst, sizeof(type));				\
 	__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
 			sizeof(type), err_label)
 
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 7b32be2a3cf0..f5086c86e0bd 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1899,6 +1899,22 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+static void copy_from_to_kernel_nofault(struct kunit *test)
+{
+	char *ptr;
+	char buf[16];
+	size_t size = sizeof(buf);
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	kfree(ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_from_kernel_nofault(&buf[0], ptr, size));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		copy_to_kernel_nofault(ptr, &buf[0], size));
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -1971,6 +1987,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault),
 	{}
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917201817.657490-1-snovitoll%40gmail.com.
