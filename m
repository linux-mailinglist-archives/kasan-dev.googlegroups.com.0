Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWM5XOHQMGQERQMHO4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id BABCD49843C
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 17:07:54 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id i28-20020a056512007c00b00437f0f6da15sf1960902lfo.16
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 08:07:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643040474; cv=pass;
        d=google.com; s=arc-20160816;
        b=g1foA0zNn/lvWD9EXmIR1JrjiYYaG31oioE6aQdeDMci20yEyvoy4ieWKOZCsp9P/V
         3hFs3/88agcZCdIfT2yfSy5bkaUOQnAWP62DJwAYty1WV9wnxpAlL0PSh1WV/BfK6Rg8
         tqCx1egVAUeZdIv/BRyO1USMZD5zXMpoCpYtLN7wgCFFWYVbxbClNf+/jyHILGNcetKQ
         YrerhbjAboESby7iAFlSD3wxv930piA+bzyybcntj1udZPIUQVdHqM77GgAfC/p3doMY
         0GY0tAL93RNz1jKol6B3regV5C3xtdmIdxq4i0IKBx3gYHVbgZfQ7OUfV6waHSH7c2MT
         +gRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=FFd7osIk7lnmWcLqWpLAuQwQT7AGd6Id5pvH/y9VDOc=;
        b=ZhzeipzzTmApFFZW6+mmqshj5rH8xQn/sNpxgX+11o9BcqpZAyxdDPHvx6WvBs08Dw
         3/RnWiUvgh7miR6e752K836P8RMtskrdv5W37N6MGG+Fv3SDX3HuHpNgqaRp9eh8FLHs
         9oDFNOuiQx2y7Sm68+BtuIqiDCyUtFDNNuteBSxgJQAmGnbYn4hOaxH+foYQLmeKnFxP
         S0lg9oVVjYMHqaa5Jb2RW0YlP73O9pU8mVvAhWm0+oTb4CyDP1IKkZ5h8wmz5veaCRBJ
         bhOXKs03zeyXm4jFSjJwC8wpMkSKAPqHtL60CXau5MJ9ZxNL9xZVKGbuLpZzdRMiu28N
         rdpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QXGUwCgt;
       spf=pass (google.com: domain of 32m7uyqukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32M7uYQUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FFd7osIk7lnmWcLqWpLAuQwQT7AGd6Id5pvH/y9VDOc=;
        b=Y3/+FfjZBmdL7TVKuLCG822rL7LhPYwkon4GbUHbScdc74L0Ob6vLUwQq9VRFD28oD
         y00NpENEldaZONAHVXWcbwVdeYzZ4emu24vBSVxUkLw2Cxp7BKgpOPc8y4QWBf8QL/tU
         9xoW/chkNawfdgQoRPKqVUbLlNrJAo0lBCyjFdBq0fvwVmVr0v6XZTZoIpYdMYPRx1Iz
         05JXQI9wSQKM7i0Jk24+hfgfp8k1+qPhjhPf/hKpRk3tTYtseNi1G1hvpzoKCV+VBOUx
         0N9XHcAUlNl7k9+qAIB9I6OKhRNOh95Okm/HeDA/XfPDXNhW2zZrVF4KDaRu0eMn/QxW
         Q6KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FFd7osIk7lnmWcLqWpLAuQwQT7AGd6Id5pvH/y9VDOc=;
        b=Xg9T3ozGU4a9S7NixVN6e92Rf1QpFxFDxnrdrr/GoIvK0BX3cWbHA6OedE3RC6aePM
         pThIbN7Z/3PnwZk4+lq76GDKtEfX2xFC6N+OOC87mWyIUU/9L6olScUFQfzn+fPcg70T
         ClCHhXwFeqMOAQZhmteD1qq+I2RuGk6JESHbVgbY5r0HuKXSyoPiJIgtQ9QiLghG/E5/
         tuHE3gUOxerIIK4UwJgNIufLKusWQZ+K/V+NPfXAkp2UEd07i9DBzwxgcUktAYaWSIao
         3QdwlCIkLWhzfhNhwXpB0dJLSz9U0Kt/E6c+t9FtRhK1q/jg+WFHqx30j/S1llzmXsC4
         1Udg==
X-Gm-Message-State: AOAM53113iIT726NRJmEH2KoIob46jGEd6TMecAbrIIYKW8DKRII5peb
	6xVQuQetEuC8F8CEkabaBKQ=
X-Google-Smtp-Source: ABdhPJyt5aWMw8Yuuvg7RjjeHJpJbI7yREZ/xf908QheFyiFOCy4/O43iB6teuCcvTQiXzhf7AT1bg==
X-Received: by 2002:a05:6512:3096:: with SMTP id z22mr12834372lfd.102.1643040474119;
        Mon, 24 Jan 2022 08:07:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c3:: with SMTP id k3ls335185lfu.0.gmail; Mon, 24
 Jan 2022 08:07:52 -0800 (PST)
X-Received: by 2002:a05:6512:118d:: with SMTP id g13mr14019650lfr.251.1643040472867;
        Mon, 24 Jan 2022 08:07:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643040472; cv=none;
        d=google.com; s=arc-20160816;
        b=iZ/4yCH+55vhuwyTVKKHa7aqL68uk+QU+kJKzMyhk9hxQqRhmgyUR3ekATcUSk/AeQ
         +Gp7dqWBdd6MdFpWclE7yXZelIgnray46v7fCBWvIFkjX+L1WqrMxFHCPjdiYndXJqau
         RCGSqYX5P4qqkV6B1gQpexmdno4uvQZqxRpl5czaer351yYYs+38ggWnXGHpT8qtjz5a
         DYN5hMA95ibskOOh4ZfEV+ll9tfZcgTzP2HDbJiJ8f90K/6/LvU9dKP2C4h+rLSe0aGk
         oz/50mIZaJ9p/83WpjXLJDmsrSFk9myh0fRtSkH6bg0QVWJa1Dr8iVjMDfD9OAsY2ggf
         uT/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=+AGye14zUPVTO5AZFKONKRmJ1sfYnaX/7sKikyozmko=;
        b=uJV9LREX38fO9nFUdXYTSvlkgchPMV21thtt3Q4VJGmeSWJzAxuWlNmqaRMk2/FlPc
         dltw52YrleyQau79f2eW9boC2ELiHzJ0zpRksXhTc893mDplVFya3n6DWxBc7kgMwDE6
         kT3rP38NYAqU1QpMcr9ReA2HEMO85zMNLW6eN2/+mlBgxtsaLZ7AqXNoZDTHqZN74Gwz
         xjPsMgrTy9sykkbtv40/8TN+FKbfPFY08Q5tk5XidUF3z9PufGhuvvQhiEO5HPH1Xx+k
         D8LfsIAw2zdtf4ZxQS3uo9XUnFSdZqOaoZp3Q5bpbnaXz2AmZXlqkr0AkQOYCxAW8ARJ
         ESUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QXGUwCgt;
       spf=pass (google.com: domain of 32m7uyqukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32M7uYQUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id p21si381087ljo.6.2022.01.24.08.07.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 08:07:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 32m7uyqukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id k10-20020a50cb8a000000b00403c8326f2aso13412923edi.6
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 08:07:52 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:88a9:37db:5c27:10e])
 (user=elver job=sendgmr) by 2002:a17:906:150c:: with SMTP id
 b12mr12577805ejd.284.1643040472427; Mon, 24 Jan 2022 08:07:52 -0800 (PST)
Date: Mon, 24 Jan 2022 17:07:44 +0100
Message-Id: <20220124160744.1244685-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
Subject: [PATCH] kasan: test: fix compatibility with FORTIFY_SOURCE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Kees Cook <keescook@chromium.org>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-hardening@vger.kernel.org, Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QXGUwCgt;       spf=pass
 (google.com: domain of 32m7uyqukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32M7uYQUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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

With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
dynamic checks using __builtin_object_size(ptr), which when failed will
panic the kernel.

Because the KASAN test deliberately performs out-of-bounds operations,
the kernel panics with FORITY_SOURCE, for example:

 | kernel BUG at lib/string_helpers.c:910!
 | invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
 | CPU: 1 PID: 137 Comm: kunit_try_catch Tainted: G    B             5.16.0-rc3+ #3
 | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
 | RIP: 0010:fortify_panic+0x19/0x1b
 | ...
 | Call Trace:
 |  <TASK>
 |  kmalloc_oob_in_memset.cold+0x16/0x16
 |  ...

Fix it by also hiding `ptr` from the optimizer, which will ensure that
__builtin_object_size() does not return a valid size, preventing
fortified string functions from panicking.

Reported-by: Nico Pache <npache@redhat.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/test_kasan.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 847cdbefab46..26a5c9007653 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -492,6 +492,7 @@ static void kmalloc_oob_in_memset(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
@@ -515,6 +516,7 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
@@ -531,6 +533,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
@@ -893,6 +896,7 @@ static void kasan_memchr(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_ptr_result = memchr(ptr, '1', size + 1));
@@ -919,6 +923,7 @@ static void kasan_memcmp(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_int_result = memcmp(ptr, arr, size+1));
-- 
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220124160744.1244685-1-elver%40google.com.
