Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id D6EB6204600
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id a2sf5382217uaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873018; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXsNCjee/I9tx9hDyRbZZDMSpKg0+vfSvSNy0jIsDSITx0bHitnOwtmc3k1ECia5NI
         hnAALnuXQ77tF3pckGvpbvIyzqfFh7cLCxpHLwg67zLXoaN//aHBlcSOkbKeDS8NXx5d
         UDZFkNuTbArfM0veEoBA8owxEoV8xdbxYcWg4C2Gy/9WUgjGc2qmmqOChYNC8FJZl5C/
         b0Ak+vJ2/ngOlcbac341NcqeCVNB+0NElOSBvKToKRnqTd+2OcEezrnjZk0+lPZSVy58
         5JuC2dwZcY670tTgT1qywm1aHa1faUAXrk/fVfNq2X/xsKy7FbJhGjwG3++Z2jDiHIUj
         Bf0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=T44qiscPsqBT5hfkewuJqNfeoo5S7u4YxwaRaL0LedM=;
        b=JODQQRD/HOyMXhqWpxtGw+RwIbGvSkshl0X/MUiDfEf4hhAwJOvJafZdqPjU8ppxne
         BD1zGEcyGhOCZlKJZSDzhQwMJG4exS8UnVfcOUBTn7tLm566e8f+Zz9S8mR3E7m3AZJO
         B1nB2LGda0mUqsN/qe15EfJbNhmw73X42yAK1YHmD2xBzHxU/vq+xN7x2TTo2nyZarIt
         NTSPxiudM4IhODO1wgcguIdBbqauLqgzta+yIMojVUTBKzxYRMc9EGu23Vrgw2Vqy8AE
         skNybAO+i1KR4WcTByViFlhY7UZNbm3DsdeU+L/FJraQPHOuG6m5TCZw8EYx5kngfzzr
         BnOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RU0TYdIQ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T44qiscPsqBT5hfkewuJqNfeoo5S7u4YxwaRaL0LedM=;
        b=I3CdfofKce/BRyOWlHsf/3CCVjHjTgM4kB0VaO64JD2vWjAne3Qv+gvzlARn75j1Jq
         YoU1Cx3nZjUMO4hVjBKjP4czxHW/Uz1PZMkAnJtEvXeBKsX8Y38FXjB8bbWQjmv9Txe0
         MxvAjiUs3SEo9BhBvWQ2sUrXKD5NnrI09tMdmJSneCuuSk1m/E2t2nsMYXvRw5nsu38+
         qy1SlEl/aFIhxbF0jIGKZh+2zUK4DuRzf6Gxkfr00sYUj/SuNmQA0Um5PWBEH3KGi3bM
         whhNjUuKvj/0F5e37MmXdlKCAwoFPeC440VFGsBkNz+uRTmpv6ghlts0fxB6aojJaqAu
         pv3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T44qiscPsqBT5hfkewuJqNfeoo5S7u4YxwaRaL0LedM=;
        b=GzoIUD8RN5YI6YTjQjTFpCHnzHUcNL/1Lr8Sd6dU+dxniMsBL+fBJNvib/813FZlSb
         dTxfq2eKHygMCWHPgWan9QB0+odN/PN4bm34Zm0RXYib5BqrpRqMwdge7e40aLRwHutc
         /VjtgKuqZtpp1lk2vV5IKoQBrCGK3R2a0cZCTNTlTV3dIKoTPH7rbrkyTcHDNwcWlKiX
         3kIqNs9bqQNNu8V70i4uFlrLFLNcEbOc/BIdEuXgI+OB+v/LGu5UvgAespoDtzsFM8Y/
         eQ/cLoxoJ65oU5DnujAVt1ZyRouQerZHNOPPJIdEKL7gSAVBdchXOkyq/daLh/5z+s/t
         GDWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CBfh39xfAhNKpNXPTsRGh5FQ1YBOHAo65p2QdbHf4I0YplrMe
	AjnNuMOOC0UcmjMYfjssEZQ=
X-Google-Smtp-Source: ABdhPJwsp+JVI7YV8lAWFpoo+Qn9qB+eO+OCZHf8TIR8KLhpYCkIm8vdsH725EbmjukA22dZzkePcw==
X-Received: by 2002:ab0:cd:: with SMTP id 71mr13904178uaj.78.1592873017918;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3d86:: with SMTP id c6ls1255495uai.5.gmail; Mon, 22 Jun
 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a9f:3fcf:: with SMTP id m15mr35233uaj.142.1592873017545;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=NHFIrO8cpT/w8f5aJQDcT2Q6SFzYaDyQmDcVnp8b33Y8Dk977pT/KXhy+nkKFjIt+G
         pynQqhJAXz7T1TfurwiJ7Gvh1KpRQ43O9dfgZ5fOiqBpRYOZ0CIvJX2+vNom/16h9Pcs
         +gtT+2ONZJydD3NUwkRFS/LZylK5qkICGZXVP3Pe9SNjUmfehv/oGlZXiYTUp3VXMMNU
         NC7jph9f/ln2JYcSNBRTTFXXXyp1OVtyMyddq2/KelO7cf0Gmja9+VAE0F0Bv42ZC/WX
         eeNgO9YF6Cp8uj2MfR8+/VjCRLMCFiGm51GzEuuvheee+AjOee3Fy558rR3qlrvvZ/Qp
         vNRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=vkgKP936KFE9UPA5POIfqIZu8mFV+XjJS/my4+MmSSw=;
        b=M2IBu+DSQH5mbVBR1p0IDzw/phpjNNJGLgGRZBn/YUjic2MJ3dcCaTHQnWxOyc3xSV
         KfkpbvcvNG9fth6Bk5mIBatQdk9IEtbU5DzLe6wvKtHsnGw8Riaw/dvAHP4cwk/GGXLX
         crYpqwmiMLaV0Cl9gyMQNFjSXrrMVaG6E7YNmkR/HDMa+l3gy1eEMLkPr1JEAGuNYS7k
         3uEfGtAyd8gl48e7PSpQCQyLGaeitKKmwW5L0HAScwQJU2IQYeYXNGg6FDdhhWXLMpgO
         vYduwdBlKiKcFKlu9l/I/j7EdeCtDoscYoVHlVKsJxAT0yFrSVrpM8MIwps/iZ6BlLl9
         N2pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=RU0TYdIQ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o18si562848vke.0.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7404F208A7;
	Tue, 23 Jun 2020 00:43:36 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 07/10] kcsan: Silence -Wmissing-prototypes warning with W=1
Date: Mon, 22 Jun 2020 17:43:30 -0700
Message-Id: <20200623004333.27227-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=RU0TYdIQ;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
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

From: Marco Elver <elver@google.com>

The functions here should not be forward declared for explicit use
elsewhere in the kernel, as they should only be emitted by the compiler
due to sanitizer instrumentation.  Add forward declarations a line above
their definition to shut up warnings in W=1 builds.

Link: https://lkml.kernel.org/r/202006060103.jSCpnV1g%lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 15f6794..1866baf 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -754,6 +754,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
  */
 
 #define DEFINE_TSAN_READ_WRITE(size)                                           \
+	void __tsan_read##size(void *ptr);                                     \
 	void __tsan_read##size(void *ptr)                                      \
 	{                                                                      \
 		check_access(ptr, size, 0);                                    \
@@ -762,6 +763,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	void __tsan_unaligned_read##size(void *ptr)                            \
 		__alias(__tsan_read##size);                                    \
 	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
+	void __tsan_write##size(void *ptr);                                    \
 	void __tsan_write##size(void *ptr)                                     \
 	{                                                                      \
 		check_access(ptr, size, KCSAN_ACCESS_WRITE);                   \
@@ -777,12 +779,14 @@ DEFINE_TSAN_READ_WRITE(4);
 DEFINE_TSAN_READ_WRITE(8);
 DEFINE_TSAN_READ_WRITE(16);
 
+void __tsan_read_range(void *ptr, size_t size);
 void __tsan_read_range(void *ptr, size_t size)
 {
 	check_access(ptr, size, 0);
 }
 EXPORT_SYMBOL(__tsan_read_range);
 
+void __tsan_write_range(void *ptr, size_t size);
 void __tsan_write_range(void *ptr, size_t size)
 {
 	check_access(ptr, size, KCSAN_ACCESS_WRITE);
@@ -799,6 +803,7 @@ EXPORT_SYMBOL(__tsan_write_range);
  * the size-check of compiletime_assert_rwonce_type().
  */
 #define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
+	void __tsan_volatile_read##size(void *ptr);                            \
 	void __tsan_volatile_read##size(void *ptr)                             \
 	{                                                                      \
 		const bool is_atomic = size <= sizeof(long long) &&            \
@@ -811,6 +816,7 @@ EXPORT_SYMBOL(__tsan_write_range);
 	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
 		__alias(__tsan_volatile_read##size);                           \
 	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
+	void __tsan_volatile_write##size(void *ptr);                           \
 	void __tsan_volatile_write##size(void *ptr)                            \
 	{                                                                      \
 		const bool is_atomic = size <= sizeof(long long) &&            \
@@ -836,14 +842,17 @@ DEFINE_TSAN_VOLATILE_READ_WRITE(16);
  * The below are not required by KCSAN, but can still be emitted by the
  * compiler.
  */
+void __tsan_func_entry(void *call_pc);
 void __tsan_func_entry(void *call_pc)
 {
 }
 EXPORT_SYMBOL(__tsan_func_entry);
+void __tsan_func_exit(void);
 void __tsan_func_exit(void)
 {
 }
 EXPORT_SYMBOL(__tsan_func_exit);
+void __tsan_init(void);
 void __tsan_init(void)
 {
 }
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-7-paulmck%40kernel.org.
