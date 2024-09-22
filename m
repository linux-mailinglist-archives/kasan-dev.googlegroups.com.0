Return-Path: <kasan-dev+bncBDAOJ6534YNBBUXAYC3QMGQEOOJMY2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ADE797E217
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 16:57:24 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2f760cbd9desf24820161fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 07:57:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727017043; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dp3wcoHw2n2O4+YqYFB2N4B7/sKgX7IQzNXOHXc9QYmSnBt29CqwKPS4A+Wck751Bz
         RkaBeGQtNozAHQA+C/1u46YP3x3z4iyEb42St3LE4baj1tZEpuS6GlOyzoKqCjL9rTdY
         ohPDllL5y4h052J3s/ozuzEHlfXEgxwIerV7akUcapPabUyLDq05bKbhvREnA8jxNrD9
         UQMIz8UMuJzQM++dzCilNmCp/XzdBSYpYy8TCASZ7/cIjGWoAzT0SB4im8L3xIIuWa8K
         rEDVqpKIcwWqmTqQsrYYQ7+GOfXP1UJ3VWWGE/CWO1pkaY6oPhPXVuQXnnKz0VXOowlX
         01/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=GOvfezW1z20s37Z8rbUciT3/WsslSwjt1GCWe98xSMo=;
        fh=Zb/GIUW+cQzRM3kLa/NuvNDtgjtQ/fPVszOs48w73Hw=;
        b=NvKkr3wqRJ+WUSBZj6APWAFLzU54xwviKEk/lDX6guaFKh2EouDZ9DF22UuyEAgPPf
         wNFQOrmHWhgDYlO/F1JOwdun1XM/6kOYShPvHfNTslY7CmhCEcA41SJeaqVYl9+4cj9s
         T8vnjIVdNsna/ESdwry44hreX5BFp5bVkqRB9qiyKPFd8MvyoqkUdPUDcdesV1vc1uEJ
         So//LiAx6vszYNSaaDMGQDtchfRGG0CAbCRV4rW3k8y+DRYXZQJaNQNONBPXA7lbdkdp
         d4zcu6T5hWcQTetICe/YSQ7LwdMMiCTkpdr24tC5PjDfnRYEdU2Vc2k3JTf/XcBfYsI9
         jS+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HXyNfiHC;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727017043; x=1727621843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GOvfezW1z20s37Z8rbUciT3/WsslSwjt1GCWe98xSMo=;
        b=oG5nOEchBpEy5bDMYJmyvmnyj7m/IIprO4sjZcd4DWQUWiHEukDBoELPndJgygFspZ
         IS/dL/AEbmTV7l09cKcQ4MrFIdjgMY4QdfvZnW9VNtZYBacXpUssKbo9gS/BT7u/6hg/
         7LB+aBVYd+NHIsrM3i7KNwPessiwinaZKu/+66mzygYlzsf96MjNM5h8Cv8YfYEdbUsW
         UGxyksagSOX4GSDO4FSTeV4hb0OqhBjxm2XO7sMnwv5VWhltycBoPU1744bPeEoTRPy4
         1VWXLEV3mkMHJp/QBvhYp3Bctvt32WJCKir2ctJMjmS/SSiZX9VAWAS5l/JTkgXN+0vY
         v2iQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727017043; x=1727621843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=GOvfezW1z20s37Z8rbUciT3/WsslSwjt1GCWe98xSMo=;
        b=eBCQW0XaJ8qZUEFBr8MCqfmQqrZ0wZ6WIyJN2nVbgapmFWGdGRHU+0L5QoGuy+448Y
         YlndxbG2DzKxxqE1ftSC0FH4Esjsi+wwvnprdQD/kI78UBgPj//4HsCMthipyzTrAol5
         b6RKoH0Q3lYNM3QwH3HVQ9orBttpYyhVPTpwITBO4EKiCDezM9HMlGT+/O5kiJjW8yRr
         4Vd3A6VNuPhNslDl+qtH7HBVApyzj8sOYYqc3jCcLT158VGPCjWUC7d1BFQDiiCx9mfN
         zp44DJpmTZ9qQh7dGsX/1c+tmfvIYocUIsH/FkDQNB+ZoqnvI+qDeE6dU2Z6qqcBjyJO
         oaQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727017043; x=1727621843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GOvfezW1z20s37Z8rbUciT3/WsslSwjt1GCWe98xSMo=;
        b=dOWpCNhDg6HC4uy3UIy6+EAvI1DGBgSCdMwohFqwTZuMIIXGbuQAdlt5wx6uv96dHR
         jKZXAasaABbt1zRx6lGEBl1eCBTWVhfhQGuwj3yJRihSRqaSziHYUXdXb4d8LTQRl7+K
         /60z4zqn+lOJnzsNJpExZFcxy73Whvp/HWAXhtmGeKPZMsZhJJWPcbXeLdEVzaL8fDw5
         ATSCYIda8rs5xDmNOJi1tOgjJ/XWwM4mtikEn0VGKyMRHmXaUks6OGYSa3VssdRfZZXp
         kBDlu0CrJGmx64n+uahIW10zmLiIXLQwiA9hBpA/0dP6ohfKdltH0tQ2FHdwhI3aeFOn
         dPLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrOb9d3zmfpQ5MyVDt/qOXWiFya7UJkhgUbvx6UpEBBASituFrXhsR0miPx+IB7Hpk8IARUA==@lfdr.de
X-Gm-Message-State: AOJu0Ywq6Xqt4MlEmdSoi43zTE2/n8vpXRGPq1pgJn5xndHYDOyZJllg
	9V4FYYtn8sa9wzgKwQ3fq9EYgppd54flRScJQCaHbpCQvevu49oh
X-Google-Smtp-Source: AGHT+IFAEZq0kG50iYH8z52FrW1B6UzylhB8DKfSXMcOSlUC1fW3zSgb4jKXQcb8ISuiIw+Vai2UaA==
X-Received: by 2002:a05:6512:1107:b0:52c:dd3d:85af with SMTP id 2adb3069b0e04-536ad17d3ecmr3752196e87.25.1727017042819;
        Sun, 22 Sep 2024 07:57:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2812:b0:52f:186:fdc8 with SMTP id
 2adb3069b0e04-536a5b7b41cls455740e87.2.-pod-prod-08-eu; Sun, 22 Sep 2024
 07:57:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8aJb57Wh1/hhicGy2esXUJgrxf4yDOYjcGpeiHjJGc7UdlQCj8fErswdkJGKKLWOYxb11o3Tom9w=@googlegroups.com
X-Received: by 2002:a05:6512:124f:b0:52c:e170:9d38 with SMTP id 2adb3069b0e04-536ad17dfefmr4291291e87.31.1727017040269;
        Sun, 22 Sep 2024 07:57:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727017040; cv=none;
        d=google.com; s=arc-20240605;
        b=gGa4qndQuR6aztWq1yaxXBaU4XHwp5sQEnj2CuUv2Subjkm1Ib3xVnuLstodRD2Qtz
         pzgqanW4d3eFurYVPRpLzQ1toIsHcSo0phLZN/paJ8Lnqx7sZyuWfvpUNVMQ6/rU/K+P
         UPGCLYk2ePxS5rAURlGbqKvkkYXvhFZ65PqfWfLNQIrEKb/lyOxYFD43FS8hZ8pJ3G86
         +gRLOK4MPb3KRLiiUjAnD3hM5G3B6Ihk++zUIE2IhOt66TfiYPX1pzONYi76uLFOoPES
         0hwsAlnSZAWrOv8lnxxnOOiaIcSedcH9FbQG1qofGBs7860enafKJeXh5r++lE8IHXl/
         GUmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rSsoTcyLR4PNClY5/YmWaWnU/WLJii7j4C/vMtkK7Zc=;
        fh=w05RtvpA0vgIWGUB9qwv1+5m524rvc+o87143iPlVEQ=;
        b=Ic1qsxv6Xv8gNMmcy25/HR7RdRQzqusctwnorCj+1d5PXSrxVS068U4TKF1c/vC7g4
         RidabvmTzBKqdYg6haopjkyvKGBCe8+IE4RqUsJdP2HM27Ip8kvNPHyeq6bnoxQ0Wb6X
         oIiLgzgrUGaL7tZYhmk5JmK04ZUhlygPxB8iOwJYoYpnTbwkLn/smBBp1p7Tf2clHyi6
         Y3sGj80wxwHLotlewad18hpzLbUxyMFNTpRaB+ilJQxlqvFkDZgbGulxStmN473+mLOz
         VMaMM4Y2nNFXUiHOBwCrQHkCYqJSzbj8vO7P3ZD31zW68yKmqfTkr8yUzu7rNUBmvw6q
         PCXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HXyNfiHC;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5368706e4fdsi418005e87.3.2024.09.22.07.57.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 07:57:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-53654e2ed93so4004703e87.0
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 07:57:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUvLTyLJ9PzN3aUZpurskwxiJ1TWsnI1jCkBr9wSD0s/o/w29Q8xr1FL6ud2zpHnWLQ7NyU6LX+k/4=@googlegroups.com
X-Received: by 2002:a05:6512:1107:b0:52c:dd3d:85af with SMTP id 2adb3069b0e04-536ad17d3ecmr3752178e87.25.1727017039468;
        Sun, 22 Sep 2024 07:57:19 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-536870968f3sm2960765e87.126.2024.09.22.07.57.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Sep 2024 07:57:18 -0700 (PDT)
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
Subject: [PATCH v5] mm: x86: instrument __get/__put_kernel_nofault
Date: Sun, 22 Sep 2024 19:57:57 +0500
Message-Id: <20240922145757.986887-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZfaZGowWPE8kMeTY60n7BCFT2q4+Z2EJ92YB_+7+OUo7Q@mail.gmail.com>
References: <CA+fCnZfaZGowWPE8kMeTY60n7BCFT2q4+Z2EJ92YB_+7+OUo7Q@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HXyNfiHC;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131
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

__get_kernel_nofault needs instrument_memcpy_before() which handles
KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofault
macro, instrument_write() check should be enough as it's validated via
kmsan_copy_to_user() in instrument_put_user().

copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB
bug reports as expected, one for each copy_from/to_kernel_nofault call.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
v3: changed kunit test from UAF to OOB case and git commit message.
v4: updated a grammar in git commit message.
v5: copy_from_to_kernel_nofault_oob() works only for x86 arch,
	remove instrument_get_user() from __get_user_size on
	!CONFIG_CC_HAS_ASM_GOTO_OUTPUT
---
 arch/x86/include/asm/uaccess.h |  3 +++
 mm/kasan/kasan_test.c          | 23 +++++++++++++++++++++++
 2 files changed, 26 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 3a7755c1a441..e8e5185dd65c 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -620,6 +620,7 @@ do {									\
 
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 #define __get_kernel_nofault(dst, src, type, err_label)			\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), err_label)
 #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -627,6 +628,7 @@ do {									\
 do {									\
 	int __kr_err;							\
 									\
+	instrument_memcpy_before(dst, src, sizeof(type));		\
 	__get_user_size(*((type *)(dst)), (__force type __user *)(src),	\
 			sizeof(type), __kr_err);			\
 	if (unlikely(__kr_err))						\
@@ -635,6 +637,7 @@ do {									\
 #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
 
 #define __put_kernel_nofault(dst, src, type, err_label)			\
+	instrument_write(dst, sizeof(type));				\
 	__put_user_size(*((type *)(src)), (__force type __user *)(dst),	\
 			sizeof(type), err_label)
 
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 567d33b493e2..c369a5b1c6a7 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1944,6 +1944,28 @@ static void match_all_mem_tag(struct kunit *test)
 	kfree(ptr);
 }
 
+static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+{
+	char *ptr;
+	char buf[128];
+	size_t size = sizeof(buf);
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_X86);
+
+	ptr = kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
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
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -2017,6 +2039,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
+	KUNIT_CASE(copy_from_to_kernel_nofault_oob),
 	{}
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240922145757.986887-1-snovitoll%40gmail.com.
