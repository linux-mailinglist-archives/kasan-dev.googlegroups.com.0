Return-Path: <kasan-dev+bncBDAOJ6534YNBB7MLYS3QMGQEM7ODCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7FE997E5DF
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 08:09:02 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-42cb2c5d634sf26117475e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 23:09:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727071742; cv=pass;
        d=google.com; s=arc-20240605;
        b=cPjT4QHQma2y6c2xTAfET7wHyyrak26GBq6rzKCY04pmL46673aX9bFCqGE4YMx/9r
         UFlPPrvzUHLQsjGSkq3GdRKAyMVcLS/jwgRvfUStiCfasIi5bR5DIAzqfY7Dud46hdtK
         siCMKuKqraudFyOBOgXI5CCFItNf7+u+Yd3J+PYNiAUYhGq9v0FAYwU3XcnwvfekGLQj
         wUbgBLy2PxPAxWuB1hFDi7DvASmKieXsrwS1boXL6SEQPw0dvL9kqycdYMbZZ+9PHKtu
         11/ORWQLJpuoDgDUWeKRyJYLntDAPyu7lIciaPgntSevYe9EptBeKX/dre+utaP9jqhE
         dDzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9pkMX1ON6l3EFJr1bBfzUpU3TYoICsjp8HOcsYcV9C4=;
        fh=rxnJFIRpABwHpdQSv50SLPXeziiB0j8evRZKu3Z+9IU=;
        b=L/jOKiionfGrrYJ+Bqzuxe+sTPO2VKu5/M56H26UAwtz/RUvexw8dtQ/To03ROPqO9
         SNTxuHYdR2QErW0KI83MpO4cZOjBq4MQQC3ZSVRni6nvl0Dbki4qKHJd04tBN/R1ljy7
         QDq3dIX02fcje/iP0ErO1SaxYOCRGcDL3/HKu5UrG9vM4qSqGUV7R/fZs51EgKAfZPCB
         itKtCQz5bn5td/mlzIOS06vjNRYVjQPbcgu1qTwSpyfCGRrCprF7yqK4hXnM5dZr6J34
         +RnsOTFO7s5mw/L8wvQInapeAliX5bmK7T1Rv0/xiIzq4OfRu967S2JLjcDq6jGYkggj
         uCDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y7c7FiWQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727071742; x=1727676542; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9pkMX1ON6l3EFJr1bBfzUpU3TYoICsjp8HOcsYcV9C4=;
        b=ue4EFFHUSlSTC7nzJmSN9r+jVkjvvDEbmYs6l4jW8yTHmn634yj0pDrtDFt9KcWdbn
         9np4GXOQAAIbuRskcHNemDeik2MpVUZpiLsWdHCgjJ82zUCRqjyIKAWaDQH+o60lBNdk
         01sK6AuNwz9HYM/FqzSB3+l0hafX8SGhldcwC02FLCGeDuUkQyQSruY2hbudlNfnyPNn
         VP0Vzv0UkfhdDllZPOzewIQUF3YdXCir4P1NeL620zSsIAltZR9K82EzEgOB/0oQtb9i
         RJ+lExOdW+OKvngzNPtJLyPQnQzixrmMmCNmjXzN96K4x/jd6XBbXVYtT5Ngb4Jw2Unc
         BTxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727071742; x=1727676542; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9pkMX1ON6l3EFJr1bBfzUpU3TYoICsjp8HOcsYcV9C4=;
        b=QFbSaZb55OqJLZa2xxKE1j4u0Sa4YiVyIlLGO8pmNmF89rLrQTxpQ7jFvL/KwszOX1
         Yv42Z1jASeTeg1mpX91e6bJvfYetilGi6oeVhuBcTy+puOakFl1LC6f+yPkyf2k7mlVE
         4sea0fDRyCVmCjSsdcMUHfjGZquBFGg7kwkCOn+tPDfLWT+EyrClkwtLiAHXqeJ3k73P
         MM7Ry7mYR8UDZeAK0mHFfKSr/GGshr2j097ymX89RHEH1hOAGM+qUUz/3wu/2hK8CaLU
         zXfqU7Rg0isFlGdFI1WQkI6mE0M7KIUNgc8UU9AV+Uerwts938juReejSyj+dDANjQoM
         ocCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727071742; x=1727676542;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9pkMX1ON6l3EFJr1bBfzUpU3TYoICsjp8HOcsYcV9C4=;
        b=ObgPT4PZNp+W+YnxMWbAQrGUwIKxAHgwfI3bpPc3tFDtPpLuW4IF+6t5klljZSnSu2
         dpf18bbPFrD2Z24bMjkAgdAL8wptf4CHPIGB7SHv6WH2Bx9F75IEDM+D6fIHQ5TBraV2
         qkp8/tZ0wk+R5/kKmppC6WvYYZhvATef9aX9z8pFJ7X3943BeH9mcUCE1ysNnSsDM3wG
         mxwZILRtsjPyur2g37sDlxcd6H2qZxrlxHXQLytEjQdblmPYRbCC5Rkx9UnGZTpC3g0L
         nMWhrcJyro0ph7vGvAgnBOhZpPYqlRhPaubDiF7bkXLL/I9M47c0jAG8WSrFQ5quhIN3
         dYmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0actmGI7vQbpwXHohJGtYNa7hb3eRYgsSbwfrEKmx7tXxQuM9rJsYFWQkTvKDeKg+/BFguA==@lfdr.de
X-Gm-Message-State: AOJu0YxV9H6VV2QAiKwJpJIc3hX4KLu8egRPtMGtJQVRufFCY1B71xhi
	zm9RT18SD6TvlM+CS9z8K6QVuesp9ZUyuDEydbRNeoJroKg55l2V
X-Google-Smtp-Source: AGHT+IEtI3OD0+vfcDd6VQdd7PIZ93omAdGjfnn1oxeAqr/GPsotTLFrZsVABzVR0fSCd9nVfYRbvA==
X-Received: by 2002:a05:600c:1c84:b0:42c:b995:20c8 with SMTP id 5b1f17b1804b1-42e7ad926c3mr67225975e9.24.1727071741650;
        Sun, 22 Sep 2024 23:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9b:b0:42c:af42:6415 with SMTP id
 5b1f17b1804b1-42e74554e9fls13674805e9.0.-pod-prod-04-eu; Sun, 22 Sep 2024
 23:09:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXM5M4nBHqjwgX8kuOVinJBjevD+Qd7hwzyWZq1juAglGSy0vIevBe0TMwvEF8odtQKMuTOGxUuvhM=@googlegroups.com
X-Received: by 2002:adf:dd90:0:b0:36b:bb84:33e2 with SMTP id ffacd0b85a97d-37a4235a1d3mr5030782f8f.37.1727071739736;
        Sun, 22 Sep 2024 23:08:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727071739; cv=none;
        d=google.com; s=arc-20240605;
        b=Lq/1TUySncJB1j1kAe6Dl9jkXjazPjpWnLuYqHtBMy3wH1TefAp9b2g+/P9RAZkOad
         iDiajXgMuCK0BlXBIDfuMAxFxJQUy6CPq5EovJV4ICHSWsS3tLI2pDJtb3CujNFujQNA
         9gZtvJ03DTolhwAsOBv23iq3UX1+RfITZkTbymCiOLopjQKJS7jTNFAgMBKV02dQpt74
         R1l8TvL/0b339+KrTRl9adrwkWwN7005p1V0fCUqBzUJ5yaG9Dvqi3RvpF16SFKVEuia
         KpVXsMXC6LaVV/Gfy2t+zcdbH3/AdhtdmdEy/ncEuZYBd+/u03jCpLY5pJC5DjmnL5O4
         jPJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=K40eclvjg+5GlWGh4SlN0FjtX41ZWIpAlF1jWels5qA=;
        fh=Ke14d5ZMwJixzxr3nyEz6GP6ObvL8ZjJ1QK+itlrzn8=;
        b=SdL3oyLZltV/nhHTzAvgfzoPOR4K0VnwDiWFcHEkup3Sw42Htox+a9DWLbBfnJm4kQ
         rZ/pvacbaiBUKdsP7x+OITkmz8D8FIwEobMJ8JYQM76dQyDuuloVFvrkSJ01BQX95Xb5
         4WuW7xL7HhuriVqT7Jw4NIZ/AML9ItkE0gYFzlCwPqYMjZog1M0O4kOpKCw2OIF5kyZT
         s5DyE9RVJquXsQ83npYWtCG1icihXW/wkMyXLsrRb86yqfRYiYqwiUSKai6dVsvj6SBH
         6DhcDr1BP7ftIx6qBGaLAOeMSzkPcjk1ufIje4150gkVBDJ7WQ3SZzZ6KLP3uKt9dVXP
         YuDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y7c7FiWQ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-378e7813b84si410292f8f.7.2024.09.22.23.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 23:08:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-5369f1c7cb8so4876418e87.1
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 23:08:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCaZ93nlMxZto1JhRNRyQOcWkSYGMTJpC4mB52h5qTLnvDoQnoaLzZVbl0oE4dq2ebarFDkD3xmzs=@googlegroups.com
X-Received: by 2002:a05:6512:a8f:b0:536:a4da:8d86 with SMTP id
 2adb3069b0e04-536ac2e0382mr4432965e87.15.1727071738642; Sun, 22 Sep 2024
 23:08:58 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfaZGowWPE8kMeTY60n7BCFT2q4+Z2EJ92YB_+7+OUo7Q@mail.gmail.com>
 <20240922145757.986887-1-snovitoll@gmail.com>
In-Reply-To: <20240922145757.986887-1-snovitoll@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Mon, 23 Sep 2024 11:09:33 +0500
Message-ID: <CACzwLxg7_HPxbjLT1v+dHG=V0wAcUJYZvqdcdLBD9xhLgNUmqQ@mail.gmail.com>
Subject: Re: [PATCH v5] mm: x86: instrument __get/__put_kernel_nofault
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y7c7FiWQ;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
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

On Sun, Sep 22, 2024 at 7:57=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>  arch/x86/include/asm/uaccess.h |  3 +++
>  mm/kasan/kasan_test.c          | 23 +++++++++++++++++++++++
>  2 files changed, 26 insertions(+)
>
> diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacces=
s.h
> index 3a7755c1a441..e8e5185dd65c 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -620,6 +620,7 @@ do {                                                 =
                       \
>
>  #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
>  #define __get_kernel_nofault(dst, src, type, err_label)                 =
       \
> +       instrument_memcpy_before(dst, src, sizeof(type));               \
>         __get_user_size(*((type *)(dst)), (__force type __user *)(src), \
>                         sizeof(type), err_label)
>  #else // !CONFIG_CC_HAS_ASM_GOTO_OUTPUT
> @@ -627,6 +628,7 @@ do {                                                 =
                       \
>  do {                                                                   \
>         int __kr_err;                                                   \
>                                                                         \
> +       instrument_memcpy_before(dst, src, sizeof(type));               \
>         __get_user_size(*((type *)(dst)), (__force type __user *)(src), \
>                         sizeof(type), __kr_err);                        \
>         if (unlikely(__kr_err))                                         \
> @@ -635,6 +637,7 @@ do {                                                 =
                       \
>  #endif // CONFIG_CC_HAS_ASM_GOTO_OUTPUT
>
>  #define __put_kernel_nofault(dst, src, type, err_label)                 =
       \
> +       instrument_write(dst, sizeof(type));                            \
>         __put_user_size(*((type *)(src)), (__force type __user *)(dst), \
>                         sizeof(type), err_label)
>

Instead of adding KASAN, KCSAN checks per arch macro,
here is the alternative, generic way with a wrapper.
I've tested it on x86_64 only, going to test on arm64
with KASAN_SW_TAGS, KASAN_HW_TAGS if I can do it in qemu,
and form a new patch for all arch
and this PATCH v5 for x86 only can be abandoned.

Please let me know if this wrapper is good enough,
I will see in kasan_test.c how I should use SW/HW_TAG, probably,
they should be a separate test with
KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
---
 include/linux/uaccess.h |  8 ++++++++
 mm/kasan/kasan_test.c   | 21 +++++++++++++++++++++
 mm/maccess.c            |  4 ++--
 3 files changed, 31 insertions(+), 2 deletions(-)

diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index d8e4105a2f21..1b5c23868f97 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -422,6 +422,14 @@ do { \
 } while (0)
 #endif

+#define __get_kernel_nofault_wrapper(dst, src, type, err_label) \
+ instrument_memcpy_before(dst, src, sizeof(type)); \
+ __get_kernel_nofault(dst, src, type, err_label); \
+
+#define __put_kernel_nofault_wrapper(dst, src, type, err_label) \
+ instrument_write(dst, sizeof(type)); \
+ __put_kernel_nofault(dst, src, type, err_label); \
+
 /**
  * get_kernel_nofault(): safely attempt to read from a location
  * @val: read into this variable
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 567d33b493e2..ae05c8858c07 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1944,6 +1944,26 @@ static void match_all_mem_tag(struct kunit *test)
  kfree(ptr);
 }

+static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+{
+ char *ptr;
+ char buf[128];
+ size_t size =3D sizeof(buf);
+
+ ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
+ KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+ KUNIT_EXPECT_KASAN_FAIL(test,
+ copy_from_kernel_nofault(&buf[0], ptr, size));
+ KUNIT_EXPECT_KASAN_FAIL(test,
+ copy_from_kernel_nofault(ptr, &buf[0], size));
+ KUNIT_EXPECT_KASAN_FAIL(test,
+ copy_to_kernel_nofault(&buf[0], ptr, size));
+ KUNIT_EXPECT_KASAN_FAIL(test,
+ copy_to_kernel_nofault(ptr, &buf[0], size));
+ kfree(ptr);
+}
+
 static struct kunit_case kasan_kunit_test_cases[] =3D {
  KUNIT_CASE(kmalloc_oob_right),
  KUNIT_CASE(kmalloc_oob_left),
@@ -2017,6 +2037,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
  KUNIT_CASE(match_all_not_assigned),
  KUNIT_CASE(match_all_ptr_tag),
  KUNIT_CASE(match_all_mem_tag),
+ KUNIT_CASE(copy_from_to_kernel_nofault_oob),
  {}
 };

diff --git a/mm/maccess.c b/mm/maccess.c
index 518a25667323..a3533a0d0677 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const
void *unsafe_src,

 #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label) \
  while (len >=3D sizeof(type)) { \
- __get_kernel_nofault(dst, src, type, err_label); \
+ __get_kernel_nofault_wrapper(dst, src, type, err_label);\
  dst +=3D sizeof(type); \
  src +=3D sizeof(type); \
  len -=3D sizeof(type); \
@@ -49,7 +49,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);

 #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label) \
  while (len >=3D sizeof(type)) { \
- __put_kernel_nofault(dst, src, type, err_label); \
+ __put_kernel_nofault_wrapper(dst, src, type, err_label);\
  dst +=3D sizeof(type); \
  src +=3D sizeof(type); \
  len -=3D sizeof(type); \
--

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxg7_HPxbjLT1v%2BdHG%3DV0wAcUJYZvqdcdLBD9xhLgNUmqQ%40mail.gm=
ail.com.
