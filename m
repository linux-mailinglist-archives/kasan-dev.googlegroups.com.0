Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVMH3P4AKGQEKSQSOTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8083E227D07
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:46 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id q7sf14009207qtq.14
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327445; cv=pass;
        d=google.com; s=arc-20160816;
        b=RH1p985IMOfJhSZX2Md/4/vW7W7wjnC/yvrmtl4EbhkZAPhk/deKReopikPwrF23TJ
         MJGNb0fL/Y74umD474TFYVvc4CFbhr0lWG0fpW2hulji1ZGGgyNJ5fv/T+zxoB6c+Eng
         qPKTFUocuSly4GSA2zHGUBHGA013cZkk7chFs8E4XopFXq+Xhuow+3p/rij/EarxltVU
         Ympn/Qo27BzHLIzsYxmbY+MUHnW2tXrxs9FpuaW4jdU/xN/DHCwlta9zrNHrm/X5URI5
         z8TiQco7Yw5eX4Sr+Q9a6axighu763R17pNukoI3mZDxO5aFK9wJ00iguVY6WqE1JDQU
         csKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=hFj0s1UlNH3ufQ+D+52m8C6QOoQpLcoGX8ul3mA+Cpk=;
        b=p3M1DSxGUR9y7RT4zx+KsWWmuugpxSlk4KgJBcQp67K0hdqH6S0LNFeTE9EeiJ6fTD
         cAWzu0wHk1tq9WkTUSwicEttfwzSt5oBKMLkRSxLoMST0LoA+Oi1BwAqxgjl7yGv/Ydw
         NLk00gTwy5kW2876eMrGJSP/GoD1TbngceWl8NRIxqoaxO1tRch8Mx0SBO0xsgkwKMEo
         soL7/69ZwF9Fzw+RaAnCJrDxkHKZSQOIj+5ECvtUctrW+vdnvVke3TNguJ3LPFD3Zwn8
         6VQ7ReDyAXOmXqsUdcrpxLbHI2mUbupMnav9hF1Y3UdYQCQIrpGUAozpMP3HUtoSWbYi
         cC5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o+Ls339+;
       spf=pass (google.com: domain of 31mmwxwukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=31MMWXwUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hFj0s1UlNH3ufQ+D+52m8C6QOoQpLcoGX8ul3mA+Cpk=;
        b=rVVAvW4msXVnST+uYoMSgVY0Y0hj+hJoFl4GVXg9U2CV+BKTVIzT/C2KSKahWur0oH
         i4pLvR+t/BUhs6hhNMDq29CVlYRh7udUVMrieGbCXo1mnL9DXRqwY8M8mR7SmhoUgvNi
         wLdRr6V48X0ppbPIDJ1WFUO0xuOYE0YYe+QSQY5vSwxwvmTl4jvy3JcCK9+6ypMXLT7r
         rIGCukOzqpIrigmYjRpf6SVcWXsvCnZjOtch04jcNRdPyIRkTNrofB1ytU/hCSD2EPY/
         gw/5JpetovOuJZUp6x9/zVqyJk1vhgxsC+f9C4y6ExlaHkmxBYQas7aMjoLukDEo7AWv
         CIeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hFj0s1UlNH3ufQ+D+52m8C6QOoQpLcoGX8ul3mA+Cpk=;
        b=fg/ptk1MAHUOHxL6XaJGMRQcpigpf+XHI+OJKiNcoYiO3siYsfCvW4unTJgmGfTI78
         SuAfLGtBvUgJXLDQnH22B4vk9QicoDGfetRqq08bzamRVGJQnhT5YbJ62g+5cLrfvBAb
         y21/33Eh+8TbVRVvCQUCnh91ltEL/YQkgSArPZ9JV7DPCz4N9WKUI1pL+6YVuhGGwSKL
         FNg7E/lIhwd9q+cYQ3b5kLsE8GVGueM4S10i2VRT6XyksoUJBzV3dsfll2w6o1Oab8S0
         Se7BplNUPFyIdcjOwivMC74sKRj68bLyGLWRCClSQsD/V6gSBpbZWCqUgLnNpduY2dui
         zx1w==
X-Gm-Message-State: AOAM532XZlhB03lR/1Zk2v2CfvUsi+UJe/ATe2DALtP5VQkgrDfD5ehI
	S9LkKk+jbvd5Wh+GcXGrtAs=
X-Google-Smtp-Source: ABdhPJwngBcILUgH2qfwD9r+YgpmgErp/EAUU0PztHRVV3wxxO5dsVhbAWyGcyZ1Qp3eJVR8jbYGtQ==
X-Received: by 2002:ac8:1a7c:: with SMTP id q57mr28155145qtk.205.1595327445295;
        Tue, 21 Jul 2020 03:30:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:678a:: with SMTP id b132ls4085262qkc.5.gmail; Tue, 21
 Jul 2020 03:30:45 -0700 (PDT)
X-Received: by 2002:a37:9004:: with SMTP id s4mr17636234qkd.286.1595327444931;
        Tue, 21 Jul 2020 03:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327444; cv=none;
        d=google.com; s=arc-20160816;
        b=NCdUMrdKCMCXSUMB1XV732MZp12Qvsg21Bh6aHC+RHUHjKwRNl399I7Yq8UjGwLTHi
         k74WOHWFUevtRHZvAQzR2g36qC3bwL3uEzXVxr5cttrVu8rbWDbRYTpdQZEzSYgZTu9a
         ducBr6V8OMr8zDNUE2gz8VQZ3lbnRQYsymRdkFA02qRkU9vflGC1kuKcsiB6U0ZlVsER
         Pmo+s/b/gXmDaKs8XjHJVdjoiUFPoPpK5oKVCbJKPGjYAJInn9uume3yEiJ579aLxYbx
         qNkt/C6iO21T4GRECBAFVqzivNiNop38fuZPjg+uNXFcbOm+/EfEyYF/hrhFAYlADjeo
         RojQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zve33nddAY1CvVFMV1CpDpP9i+R8xzZxDJhHrrAhrZg=;
        b=AsSs3wuNSAAHsY4JH5/lrkZjKn0rg3HmrNy2gHAaOuIE5zrJFIiP/+pTIWifiGxCxe
         0GvRgi64RH6bxLqmLYM/gsgwSl88aYI6UdFkJW4ayIrvMb4wqBtFAJYCtjgnt5X5Y07Q
         QOwAsSqczaaEnbVJkgsqCYNkn+pfcSUD1z9TJrO1xZuLxm0ds8LLscJul8/aLqAXJhnJ
         5oQze7J49GfkOFJ+RoXB9vgV1xwQpTUOzG7UqYVnpxmwHvoEXl/SZCq1X61d9SLZVRd4
         X6cm1qcoPvsgjeXnmqAK2ooFh0gxfmKz3gDdKWRs4Ot99da900Co6trBTiOeCMohgqGE
         352Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o+Ls339+;
       spf=pass (google.com: domain of 31mmwxwukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=31MMWXwUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id w195si75649qka.7.2020.07.21.03.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31mmwxwukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l53so13956511qtl.10
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:44 -0700 (PDT)
X-Received: by 2002:ad4:4a6d:: with SMTP id cn13mr26776898qvb.165.1595327444500;
 Tue, 21 Jul 2020 03:30:44 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:14 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-7-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 6/8] instrumented.h: Introduce read-write instrumentation hooks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o+Ls339+;       spf=pass
 (google.com: domain of 31mmwxwukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=31MMWXwUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Introduce read-write instrumentation hooks, to more precisely denote an
operation's behaviour.

KCSAN is able to distinguish compound instrumentation, and with the new
instrumentation we then benefit from improved reporting. More
importantly, read-write compound operations should not implicitly be
treated as atomic, if they aren't actually atomic.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/instrumented.h | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 43e6ea591975..42faebbaa202 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -42,6 +42,21 @@ static __always_inline void instrument_write(const volatile void *v, size_t size
 	kcsan_check_write(v, size);
 }
 
+/**
+ * instrument_read_write - instrument regular read-write access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_read_write(v, size);
+}
+
 /**
  * instrument_atomic_read - instrument atomic read access
  *
@@ -72,6 +87,21 @@ static __always_inline void instrument_atomic_write(const volatile void *v, size
 	kcsan_check_atomic_write(v, size);
 }
 
+/**
+ * instrument_atomic_read_write - instrument atomic read-write access
+ *
+ * Instrument an atomic read-write access. The instrumentation should be
+ * inserted before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_atomic_read_write(v, size);
+}
+
 /**
  * instrument_copy_to_user - instrument reads of copy_to_user
  *
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-7-elver%40google.com.
