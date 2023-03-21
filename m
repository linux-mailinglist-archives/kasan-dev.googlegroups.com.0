Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2EC4SQAMGQEVZLEWTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 770C46C26A1
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 01:59:21 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id a11-20020ac2504b000000b004e85d663fa1sf4890023lfm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 17:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679360361; cv=pass;
        d=google.com; s=arc-20160816;
        b=khVpCQYv+SGTEvn0FUDyVFCA/7p5G3i679gTPhf8URR4JBnZOG/norfM/LWoUky54a
         eZz70olko7UtXjVu1Drl9k18PCJ5tRwKGhDIik1cxuvOMGUdk7LDHfbW8Qu6oxvvFSXW
         0j1qnVk1t3K9wMitNt5dx+DXHZ7j8OfUtZM1XAGQNGGPWT4a6HnJPGhPZFK77S5k+nrS
         bzeZr1h64J8GiesU/L3Zmrb+76Nln1wjn/EKbtZYiVkK3faMksDPU7OxA8f46BRrD7Ng
         HROOI+t/+IwrSQqOlIslBPL5+4JQEpTsJWCixZOdGm9Q4IU0W/q9bD7zED434wErZGjJ
         jpdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eFLqv77puC+Bkz8yhzhOQc94Dv661OPBRhhUJXb+uoU=;
        b=hjsluh0SrTBjXQ+X10J1bl/pD0K/cC0pWFDzioum0OcGmc+jcTXbKuRXWBvPeBfO1r
         FPgGPeVE+6wtTcslejCtU1PT4drEx3jHyaqE0z/0ca6NOB25AfNXJ0zvsb5mDekc8jGJ
         V5yUrair4y8I0BExSFBtlPKrGIm0o4oJo1SbjSoE9dL7fIz4uJVv+jUT7O62bh6KEqsT
         SKacA77QUXLebht94b50ZKC4hZIO6j5AlDDqnGWrsUOzakaJ8OBnyWjOn9HkTmj3iOVV
         hKaRL/x65rE0FZF8r9F7nVnADljkCn9ku70FXUnIEj7o6EXA/gzA3FvA+PScnQp37oaB
         Atew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Usq6838H;
       spf=pass (google.com: domain of paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679360361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eFLqv77puC+Bkz8yhzhOQc94Dv661OPBRhhUJXb+uoU=;
        b=nz1tuHygmBhu9ldkNv+tN41EGxLnzP+XFjR2nLKImN6zqWAiDn5v5mC1zziu1r+1mT
         u95lO31ijP4UOhF1W1Np6jIpq0+M1VdPjzYJO9883groXr/zIkoWnUrna3lSKlsdVRsH
         JuZQGjwKjILsJTUspDggfEIJOwLtfoTWCJBCc+30ehKl5nkzzg808PnE6KaarNdcQEUt
         kmAS0VSui0nmEDwCw6ri46LiYdZ16+Y8m6rqPrVxK+VkQSTgYjePA0celw67GHBhE08C
         Bl7tr+H+/QGRHLjzRwV/20YGqhXO8svJOtn1trpdpRKRaaHfe9+YW5mXfFZC6bo6U1WZ
         SdtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679360361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eFLqv77puC+Bkz8yhzhOQc94Dv661OPBRhhUJXb+uoU=;
        b=sA5NNupBTu38OkKXaXf1kqvETMdXLgVqp+pENuRCPQihd3+x2DbMShpBi5C1shCGzs
         ZopVP9zzCZ2wCHx3Pxg11HsaNX1yzKPt3Nrg+7JozPAk9gFXUOpYgt9FzPfvrekegszA
         jaPmbX4140KLaqg71ZS83wJWGkgF1FZgNFMnNtbANdWgUz7MCL0QmJ9n3Mjg0Ia5jMEU
         4U/Ep8cmXkWIDCqn+jjukDIWlI+23kb0z9ARHLjgu0l933tfg0+oeSdmCc+8GXvPTu9M
         iA4OoE7BPQZVFyIDgA7rTsJdfs9rDezWN5aL+kmVPwRds8rubvTElD0sbocOl658WENt
         Te8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVxxdJddZP8utKXvgAcbgBupQIUe8ky2u5Cc9vKNZC5NqBImBgr
	Kz1wABKdeRVc8PTUgpPQBfk=
X-Google-Smtp-Source: AK7set83ykiJ4MThMZPkdy2Mzaev4vVDHTs5Slez6iLoPE7NOVzO7fFCy3LOCQbK0xTmb6ibvepyQw==
X-Received: by 2002:a2e:9d0b:0:b0:29a:a76a:194b with SMTP id t11-20020a2e9d0b000000b0029aa76a194bmr322469lji.3.1679360360503;
        Mon, 20 Mar 2023 17:59:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4013:b0:4e9:c006:ce26 with SMTP id
 br19-20020a056512401300b004e9c006ce26ls1740515lfb.3.-pod-prod-gmail; Mon, 20
 Mar 2023 17:59:18 -0700 (PDT)
X-Received: by 2002:ac2:4436:0:b0:4db:3605:9bd3 with SMTP id w22-20020ac24436000000b004db36059bd3mr241812lfl.17.1679360358673;
        Mon, 20 Mar 2023 17:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679360358; cv=none;
        d=google.com; s=arc-20160816;
        b=fF76x8G558oe9OeZRNDc8DytiCHILHCnmLgQvrkoiuADXjqg3q0CkkyT0g3LHeBa0J
         gwjMiNygWQjFCxqLFrlJpGR0A8ublejUB9sirlwiyuoGHBtPjhAh5QkqwmRN8Mbbcl21
         xyx2ZPlJvb9sGGD5bpErNL/ZnY3b/hxBt1/M7Zlc8VQXbB7Tlb3G5GUaDiVngpL1/4MK
         ADhTT1TbMMEjGN7+ICGe0TPVuV+5bHFLl3Bp1x0v+vNVQ2zL/PgLB6gs741HfANRCshj
         kcn6b88vRcw1/dymzoYV4dBl7W3r0qB7SQB8bmR6ptE+SyV/7/L2zmrcV2X4pgSlsRVP
         dIvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZfMScYPRX2uBS8touER8EMV1RFsntZCeyfE5I4Hqhw8=;
        b=nU7gv2W2PknWYrsb4FxXSgiUCxdlWK+BgLFfr3hf3H5Q+2f/LFmQxsPk5KEy2hrPHF
         GWMzwqLR0QFjatuVQn7D4hv2ohteYjcj4BHoGdaDIiEpBNlb/XBd5JNhicE8//sNSbO1
         a3oZbvslKCwunbnzP2ESefwCSx2/yeLDPAefgSrrYgvbfXhPFzGkPT5hA4C+1OpsQmu9
         ZOtkwwvyjI0noZlyeSCR4Ms7R1GD2sE5cnzzPATYKAlXTFBzsj65Tz2ThYBkWFpZ5OJh
         7lxUlPkCpHbOYdGlurGNxT+7mxoalXXBHO9SU4xe9r6gwbFMI9u1Qk1WnbZCngPGnodf
         Fq0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Usq6838H;
       spf=pass (google.com: domain of paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id y24-20020a0565123f1800b004dc4c1e0df8si567416lfa.11.2023.03.20.17.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Mar 2023 17:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id CAEF9B811B9;
	Tue, 21 Mar 2023 00:59:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 76E9FC433D2;
	Tue, 21 Mar 2023 00:59:16 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 23BA81540395; Mon, 20 Mar 2023 17:59:16 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@meta.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Randy Dunlap <rdunlap@infradead.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/2] instrumented.h: Fix all kernel-doc format warnings
Date: Mon, 20 Mar 2023 17:59:13 -0700
Message-Id: <20230321005914.50783-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.0.rc2
In-Reply-To: <a26f2bdb-1504-487b-8ec8-001adafc5491@paulmck-laptop>
References: <a26f2bdb-1504-487b-8ec8-001adafc5491@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Usq6838H;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Randy Dunlap <rdunlap@infradead.org>

Fix 26 kernel-doc notation warnings by converting the function
documentation to kernel-doc format.

Warning example:

instrumented.h:155: warning: Function parameter or member 'to' not described in 'instrument_copy_from_user_after'
instrumented.h:155: warning: Function parameter or member 'from' not described in 'instrument_copy_from_user_after'
instrumented.h:155: warning: Function parameter or member 'n' not described in 'instrument_copy_from_user_after'
instrumented.h:155: warning: Function parameter or member 'left' not described in 'instrument_copy_from_user_after'

Fixes: 36e4d4dd4fc4 ("include/linux: Add instrumented.h infrastructure")
Fixes: 00047c2e6d7c ("instrumented.h: Introduce read-write instrumentation hooks")
Fixes: 33b75c1d884e ("instrumented.h: allow instrumenting both sides of copy_from_user()")
Fixes: 888f84a6da4d ("x86: asm: instrument usercopy in get_user() and put_user()")
Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Ingo Molnar <mingo@kernel.org>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/instrumented.h | 63 +++++++++++++++---------------------
 1 file changed, 26 insertions(+), 37 deletions(-)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 501fa8486749..1b608e00290a 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -15,12 +15,11 @@
 
 /**
  * instrument_read - instrument regular read access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument a regular read access. The instrumentation should be inserted
  * before the actual read happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_read(const volatile void *v, size_t size)
 {
@@ -30,12 +29,11 @@ static __always_inline void instrument_read(const volatile void *v, size_t size)
 
 /**
  * instrument_write - instrument regular write access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument a regular write access. The instrumentation should be inserted
  * before the actual write happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_write(const volatile void *v, size_t size)
 {
@@ -45,12 +43,11 @@ static __always_inline void instrument_write(const volatile void *v, size_t size
 
 /**
  * instrument_read_write - instrument regular read-write access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument a regular write access. The instrumentation should be inserted
  * before the actual write happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_read_write(const volatile void *v, size_t size)
 {
@@ -60,12 +57,11 @@ static __always_inline void instrument_read_write(const volatile void *v, size_t
 
 /**
  * instrument_atomic_read - instrument atomic read access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument an atomic read access. The instrumentation should be inserted
  * before the actual read happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
 {
@@ -75,12 +71,11 @@ static __always_inline void instrument_atomic_read(const volatile void *v, size_
 
 /**
  * instrument_atomic_write - instrument atomic write access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument an atomic write access. The instrumentation should be inserted
  * before the actual write happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
 {
@@ -90,12 +85,11 @@ static __always_inline void instrument_atomic_write(const volatile void *v, size
 
 /**
  * instrument_atomic_read_write - instrument atomic read-write access
+ * @v: address of access
+ * @size: size of access
  *
  * Instrument an atomic read-write access. The instrumentation should be
  * inserted before the actual write happens.
- *
- * @ptr address of access
- * @size size of access
  */
 static __always_inline void instrument_atomic_read_write(const volatile void *v, size_t size)
 {
@@ -105,13 +99,12 @@ static __always_inline void instrument_atomic_read_write(const volatile void *v,
 
 /**
  * instrument_copy_to_user - instrument reads of copy_to_user
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
  *
  * Instrument reads from kernel memory, that are due to copy_to_user (and
  * variants). The instrumentation must be inserted before the accesses.
- *
- * @to destination address
- * @from source address
- * @n number of bytes to copy
  */
 static __always_inline void
 instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
@@ -123,13 +116,12 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
 
 /**
  * instrument_copy_from_user_before - add instrumentation before copy_from_user
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
  *
  * Instrument writes to kernel memory, that are due to copy_from_user (and
  * variants). The instrumentation should be inserted before the accesses.
- *
- * @to destination address
- * @from source address
- * @n number of bytes to copy
  */
 static __always_inline void
 instrument_copy_from_user_before(const void *to, const void __user *from, unsigned long n)
@@ -140,14 +132,13 @@ instrument_copy_from_user_before(const void *to, const void __user *from, unsign
 
 /**
  * instrument_copy_from_user_after - add instrumentation after copy_from_user
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
+ * @left: number of bytes not copied (as returned by copy_from_user)
  *
  * Instrument writes to kernel memory, that are due to copy_from_user (and
  * variants). The instrumentation should be inserted after the accesses.
- *
- * @to destination address
- * @from source address
- * @n number of bytes to copy
- * @left number of bytes not copied (as returned by copy_from_user)
  */
 static __always_inline void
 instrument_copy_from_user_after(const void *to, const void __user *from,
@@ -158,12 +149,11 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 
 /**
  * instrument_get_user() - add instrumentation to get_user()-like macros
+ * @to: destination variable, may not be address-taken
  *
  * get_user() and friends are fragile, so it may depend on the implementation
  * whether the instrumentation happens before or after the data is copied from
  * the userspace.
- *
- * @to destination variable, may not be address-taken
  */
 #define instrument_get_user(to)				\
 ({							\
@@ -175,14 +165,13 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 
 /**
  * instrument_put_user() - add instrumentation to put_user()-like macros
+ * @from: source address
+ * @ptr: userspace pointer to copy to
+ * @size: number of bytes to copy
  *
  * put_user() and friends are fragile, so it may depend on the implementation
  * whether the instrumentation happens before or after the data is copied from
  * the userspace.
- *
- * @from source address
- * @ptr userspace pointer to copy to
- * @size number of bytes to copy
  */
 #define instrument_put_user(from, ptr, size)			\
 ({								\
-- 
2.40.0.rc2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230321005914.50783-1-paulmck%40kernel.org.
