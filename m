Return-Path: <kasan-dev+bncBAABBENQU6XAMGQEOBREYBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DA03850EE9
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 09:34:26 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d08eacba7asf31554371fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 00:34:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707726866; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZiVzNYnneqDhc3NBdbViCxtOwNZYEcIn4QzkFDX2jYmtGyQLgRPfdnJ/JfGWXcag7H
         EbboSbIXFbAr50mxG38z6hsUTQtFccq+5oUjJSrQt4f2adVKuU5PQpfX62AkPlKzY0WT
         o59dEDEnc0Bf8NYT3dm2WCbhlrbmKDess2dUM3/oVRqfTj/uPJjxC8j1PZ5berfSRNgf
         2FE1yj24w//L8BbeEmxdXzUKDrtTygQiI8wlez2KpyTn3OtfjdEhOmw80dSX5Cec/fg4
         I3pIpZfxOxwz138KmcA1D0XOlrsnmRaIqZbhFlw81HZ1g4qAe6AHkGen8Wo5LvjD4VzG
         xN7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=geCYFjdPKBunZQ4xMnG5/ZFBcpbTJZIY8bOxD15fgSk=;
        fh=zaCjB+MN6iiK31RzzdpwTMUVct56nxOUhXVZrx38r/M=;
        b=L338dyyBpGXBredzdoqzn73o9iaw161nYFt45eCUoyBgczDA8xGZtwggGxlTYFporh
         srLGYNRqjLmpLS2gmpvtvHvQhLrJid8Fbcz+lksUmNZqGFSiBfTXpWnhJ+Y3xbtp9sH1
         faTwNRtfw2SJ6JsG1Vio41dn2bGVxFDebP9VVh9hAnRhfLHwRwMv+t5oQdoLbSTQIwJ7
         RPiuj0xE3dD9A3g0Oe2jvGNT3MiU1cNvHF9/2XvlIrXrwjHzpVMjL95MS9/DYKzWsjhM
         hXyGnDM6nZpcvZ//14fAUZV+Bg4EhB74W0DzT2gldRpkW/U8mNxbE03+bYn2SMkywus/
         DijQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=eP+lL5so;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707726866; x=1708331666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=geCYFjdPKBunZQ4xMnG5/ZFBcpbTJZIY8bOxD15fgSk=;
        b=a7xpDZGmhalAU6ARDRAbXepIJ2znJISQ3LuJ7MMpIUfQG4AeMFB86szTv7t7AEl0y9
         dBJwTg/I7XttmhcKCSVAa2ycfI3jXxt2qmw2RwzvMTm1/cIz9JXUw5aW/7Woz0+pQ1wq
         DiH5LHkdt06btmuF3RvHqko/w9TnOSTbpl1W8xtCnAcSJn8V1a3mZNf24wRfF87diU3b
         7oMm+l5TWnkip/hmjAzoas0DUwJAccKaoi6yZ+gQXhICZEqp+34rpT/pfIbJTAUJZU7Y
         pc52zeAcSH6Ki8egXRCkFQSYRX5fs/UAdKhS4yXoam3smQSqYOoBZIqZp8P1UPIXiZlC
         inPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707726866; x=1708331666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=geCYFjdPKBunZQ4xMnG5/ZFBcpbTJZIY8bOxD15fgSk=;
        b=NZ+DOCXzZqKXyP298dkoNd7ZZlzAFmaIaC8YRUr8EfTa8NVqIsaxoX/87YX9J2xIyK
         szg/rBtzyCmaVFFRqO6QwIZGpoWKERdH74nTgCSXXHYk6QPTTmSvcmON65l1Lr2sA8TT
         dcTZ+o82LD5rNSsuV+gW2P1a7/vqFmYfK7ecBro45vKKYo9oVoCv1QK0bRGMLwLCUNj5
         MPbSnGzvM6LOvJpbbgV953wQzc4MoTKnEgGozSWFUYG2Zh+oWlHUh8otdybvTmO475OK
         niYU1078irgSH3Eu6IaVBtQIfm7+UeDmXih2f08362TgcVHYb/gwXPrnEtBsAVr6q334
         TljQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyN6ZZfX2rW1Rp+UPKJyu3Qpa309EHELu6yn1tz+wzDM/eLSFWg
	OqQOsIGkqITOunkNPIdzVj+T0R+4a3+J1lfF9WUKn/qUQfCHjq47
X-Google-Smtp-Source: AGHT+IGVdjmHv2qezg1zOTUc8P/mwj3qgppBYT5JSa41KeWqNNscOc4TK0VBL1sQCXHlXNwU/cxt2Q==
X-Received: by 2002:a2e:9d87:0:b0:2d0:9322:7496 with SMTP id c7-20020a2e9d87000000b002d093227496mr4124698ljj.43.1707726865580;
        Mon, 12 Feb 2024 00:34:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a270:0:b0:2d0:acbf:6da1 with SMTP id k16-20020a2ea270000000b002d0acbf6da1ls15890ljm.2.-pod-prod-08-eu;
 Mon, 12 Feb 2024 00:34:24 -0800 (PST)
X-Received: by 2002:a2e:be9d:0:b0:2d0:f65e:2231 with SMTP id a29-20020a2ebe9d000000b002d0f65e2231mr2559550ljr.31.1707726864026;
        Mon, 12 Feb 2024 00:34:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707726864; cv=none;
        d=google.com; s=arc-20160816;
        b=TCnlwAjkxTeLz5mfyW3JhLt7FEtRToGnoUmCnZ6Jb63He2q1u5/3AjQBwdpLWnAmg1
         TsiJPxy5ljJdXLiiZk/Mt7OZ+p6HtMQs0B3ucuE5K05noH6TLalP5J+oCzrh2qswgINf
         ENFXq1US9r66NZiKwJEnFyDQAlJsKS5dVgdiTmN0fei5Sx6SQYsiXloMy4Evh9+GdHAK
         7Ddx62LisvMtuy0HfifjH1ctSGuYLFij/X9eEGYhcZ1m2oIGmjSQU3gUDAduAyr74J7X
         tgkqBFQ2WBl8og7989bt7p26qNBTExmFAG90dRkIssQSGXKkvvZpQ6uYyBpPHjH3cdsK
         1QKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Vrq6pH7f9iGB8LwYV2/mtF1jhtmkM8pYMdQmJLjgFk=;
        fh=zaCjB+MN6iiK31RzzdpwTMUVct56nxOUhXVZrx38r/M=;
        b=Fo7geg7K9FDZCDeT4hSjOqLV0ulEjdZUJEb1u5y8YF58M4dgnfa7CjT17jBf+NHq1i
         QKkSVh0LtvLHg1k2EUe9AUNOe2wcHB15J4epDIavMFBjG2FdcJJa5jbQ1fPDvzelVNtG
         OEjAoxolgW0PEdxVbpNizLLfnb9ukiqazWDAVZUtFmoRD1QiQRzd0EppmVknXt+19Aki
         RCIcu4Qi848S61kQMtei+RVOO8v5f/NQ7IuO7dNvW+6My/3V3/hWY/I8bULXQf/ZiQP5
         RT7uQWQ58B531fAVEZW9HEyRZXfBvMpFyC9QVBpQ6OmAdo1ioXbFhX6dC3GKbFI/NlkV
         FZIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=eP+lL5so;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=1; AJvYcCVc8Xcgy+rlLaanmbzjAHscg03hbyRkQkF0unW+v3P6GyLN1Tll1OcYPe61FliNdoZ22Nyc69aeUqgxwUS7LN3GZhM9D+gSO+y/Fg==
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e8658000000b002d0ac7feef0si495098ljj.5.2024.02.12.00.34.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 00:34:24 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4TYHnB5NqfzyV2;
	Mon, 12 Feb 2024 09:34:22 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.88
X-Spam-Level: 
X-Spam-Status: No, score=-2.88 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DATE_TZ_0000=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_TO_EQ_FROM=0.001,
	LRZ_TO_SHORT=0.001, LRZ_URL_HTTP_SINGLE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, LRZ_URL_SINGLE_UTF8=0.001,
	T_SCC_BODY_TEXT_LINE=-0.01] autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id MRHxCgA6u-EA; Mon, 12 Feb 2024 09:34:22 +0100 (CET)
Received: from sienna.fritz.box (ppp-93-104-66-45.dynamic.mnet-online.de [93.104.66.45])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4TYHn85xP7zyRX;
	Mon, 12 Feb 2024 09:34:20 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: paul.heidekrueger@tum.de
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	mark.rutland@arm.com,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v3] kasan: add atomic tests
Date: Mon, 12 Feb 2024 08:33:42 +0000
Message-Id: <20240212083342.3075850-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20240211091720.145235-1-paul.heidekrueger@tum.de>
References: <20240211091720.145235-1-paul.heidekrueger@tum.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=eP+lL5so;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Test that KASan can detect some unsafe atomic accesses.

As discussed in the linked thread below, these tests attempt to cover
the most common uses of atomics and, therefore, aren't exhaustive.

CC: Marco Elver <elver@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger=
@tum.de/T/#u
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
Changes PATCH v2 -> PATCH v3:
* Fix the wrong variable being used when checking a2 after allocation
* Add Andrey's reviewed-by tag

Changes PATCH v1 -> PATCH v2:
* Make explicit cast implicit as per Mark's feedback
* Increase the size of the "a2" allocation as per Andrey's feedback
* Add tags=20

Changes PATCH RFC v2 -> PATCH v1:
* Remove casts to void*
* Remove i_safe variable
* Add atomic_long_* test cases
* Carry over comment from kasan_bitops_tags()

Changes PATCH RFC v1 -> PATCH RFC v2:
* Adjust size of allocations to make kasan_atomics() work with all KASan mo=
des
* Remove comments and move tests closer to the bitops tests
* For functions taking two addresses as an input, test each address in a se=
parate function call.
* Rename variables for clarity
* Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store=
_release()

 mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 79 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..7f0f87a2c3c4 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
 	kfree(bits);
 }
=20
+static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *s=
afe)
+{
+	int *i_unsafe =3D unsafe;
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+}
+
+static void kasan_atomics(struct kunit *test)
+{
+	void *a1, *a2;
+
+	/*
+	 * Just as with kasan_bitops_tags(), we allocate 48 bytes of memory such
+	 * that the following 16 bytes will make up the redzone.
+	 */
+	a1 =3D kzalloc(48, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+	a2 =3D kzalloc(sizeof(atomic_long_t), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a2);
+
+	/* Use atomics to access the redzone. */
+	kasan_atomics_helper(test, a1 + 48, a2);
+
+	kfree(a1);
+	kfree(a2);
+}
+
 static void kmalloc_double_kzfree(struct kunit *test)
 {
 	char *ptr;
@@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(kasan_strings),
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
+	KUNIT_CASE(kasan_atomics),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(rcu_uaf),
 	KUNIT_CASE(workqueue_uaf),
--=20
2.40.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240212083342.3075850-1-paul.heidekrueger%40tum.de.
