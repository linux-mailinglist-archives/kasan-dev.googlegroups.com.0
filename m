Return-Path: <kasan-dev+bncBAABBGHK5KWQMGQEE65YSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC37A84494E
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jan 2024 22:01:13 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-55f21003dc4sf1063a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jan 2024 13:01:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706734873; cv=pass;
        d=google.com; s=arc-20160816;
        b=c8iiZ/dXft8ClV0N9YbD3tGXnjRwyh95oieXFlhmF18wW1B/qZu/Ci/HkB59kla61O
         edV5dtObfdTjjGA2OZkoew2AHpdY+QEip215GYrltwd1EYo3xL+jwNwsN5boWk9qVHXn
         9NvN5nTNHyFkYenGoely53DJ1OLMkNxyvJ0Tosda2g1lNDLK2WlfCylAoeOgtQAuA25I
         Fq5AnPv7Ry3itj0P2SjiPgnedToS/h2A7Xn5q8F6Y1L4GBmnhTYsN0+Bn+fDZgdNC/5H
         8c5lVgO7bHtJUC9oKJ80Iw9r+m+7ofM/aKwudn+0TjKKqBi1RRzMczeTZgwhBP2mufXw
         67+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=Z5mBySyrUbHFMxFJeYYiBuSWWGAn5ZVwb1F1qumAJnI=;
        fh=DVJ723a37gqndr1psKDrB1H/+W1giWMYSxIi+tjPbDQ=;
        b=k2NClREN5ru6bBSxTGDqI/Eo/syTiLG+Kwk9ju9QFYKMsAB6jXvTBSFgVlH2BpZ88I
         6fyLhSq0iJYoUlixO8EBvJKUn/cN3G2W1sY8oBUZqBLzakypF+iwFyrf/al9Drp0ym/6
         5eiATK5GLzbiOY9FEXbuGfX/+tvXBa9A1Ae8/Dzt/ZaavX4qZW7a72BirTGix8iZZWb3
         AB61Nz9IYGPNtIvahfzVv9q8VuRocS9ITNIrJCk51/dqdOrvohrlyBoi/L8AZ01VD+2X
         F1lrqQC1QDtnCHZUFFRc816lOJ8WfKMOoPCAw6unwm+WctFaG/kVKMexEtB8XA0HeAI9
         CHtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=BQ3ghKEN;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706734873; x=1707339673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z5mBySyrUbHFMxFJeYYiBuSWWGAn5ZVwb1F1qumAJnI=;
        b=uhyGBzd2mcuCzqXB7YfdpXAHbURKEMBVxTIjegfjBBrh48jy7hoZPQk1q0y+nSl8Wm
         KCOPksgKcYlYJ/VfBA3OVmjHkn3gkWyK/Yt1cZrP1aZEug0QrelUWVaM7WsOnbUgbM5V
         KCHEdNfMJaw//TtV/Kh44yKzZuWnrTA3FutlTjnBb2+wounWZLO77OGX6PNjG04mneEP
         3H+ZO/h0FDWQUy1bdnTgbuSZyhsy7jNfvL/zk4Esywm556TXR4CyCsXF4i6DZ1RpLUaW
         vBlyCl2LjIGXo9SDbLdWjF71cQmEHKru1khsJxrIvJfhKPolrVNauq5UbPwAGb/wcBme
         xGdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706734873; x=1707339673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Z5mBySyrUbHFMxFJeYYiBuSWWGAn5ZVwb1F1qumAJnI=;
        b=Zo7625We/k4Pdr4xxBqrOZYmgBlawYidm8NwokZK7s3sdZAdH0WPVYy5upDai+QJOT
         NurSDsXhj5inGjsc6uy6hihVSyGIj7Lk77y+tpIzH3VWLHPD1P8mOIjhP2qW30ZPfhGE
         Hx9F6dWqIzkM/bB5QG0ugcnyv5L58zAcp+ma40521lnsoBlXenn6xqbgFoVk02t8E0x3
         M7qVNngoHUG6vXSCZsAt3NP2bPgjpgvHI+cFkvfsrLhmSOof0FOd1NQ8rxAdo8MD5pJ5
         Belb7weuvKax5uGJpc23DK3PCRALGzTDdzAsPBWfRDEdfg1vxV8DR1PAHG+ywD1K6oJV
         WaNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyfaz38Zdi87FZlTztiuq6lGAwGWovDzyHiWqouc5kvmoV33Dzn
	Qmp+gWvVsx4ZtrJ6oM8/SxR/dBoN7Zl7hTmOiv0C/2tvfG8OFFuu
X-Google-Smtp-Source: AGHT+IFudquB99CaDOIMP8m1NBr5YxOCG7DfAqpFE8f+Zimo4vQ+07RCxHoND7IAEJ3SCgGKB7koMA==
X-Received: by 2002:a05:6402:b63:b0:55f:9c70:b94 with SMTP id cb3-20020a0564020b6300b0055f9c700b94mr59700edb.0.1706734872731;
        Wed, 31 Jan 2024 13:01:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58c7:0:b0:511:1ad3:d63f with SMTP id u7-20020ac258c7000000b005111ad3d63fls77617lfo.1.-pod-prod-01-eu;
 Wed, 31 Jan 2024 13:01:11 -0800 (PST)
X-Received: by 2002:ac2:559a:0:b0:50e:d514:77bd with SMTP id v26-20020ac2559a000000b0050ed51477bdmr410821lfg.18.1706734871167;
        Wed, 31 Jan 2024 13:01:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706734871; cv=none;
        d=google.com; s=arc-20160816;
        b=d6/Ix6qWWfVam5pIpGc7lWhgPKwb7m/qse1SXP9Wzz4PywCwmEXYQOSMJvpIVxnkEJ
         iUHh+aUP/w+bMysQc/k61K0SvmqsUM5+qYK7CLW9zgFx5H8dbZI/978B5QzcvZc7qqKy
         cZtrBvNtzhbWClbtjJBIYvr3/x2otj9BU+xNld8WNdTD12FlADxg8Dmk0OxLuZ1jxvPt
         69a1QAQs+ZCSzs0P6NE9koRnoUlb0Xuoa4v0DM7O1MrPieTSKB8zNA/8RdMOj1Aewdk8
         Kbx9QPCd2v31TfuQrgbSOOHht0Fje4u0DqmDVdsv/oOZFKYR68kfmIKI3EJAwDfzT8uJ
         n6OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=j63P2XRlLUYNxZkT/iXoEqnLVCU36r89QKAA3Sp5iMQ=;
        fh=DVJ723a37gqndr1psKDrB1H/+W1giWMYSxIi+tjPbDQ=;
        b=UXsNU8rPrvW531PAuHLgz8ZYthX5vLwSbJH1jaXJ28zy58sJnz2o083inPYPL6Z+Ex
         Bi3qCina3JlXlAcykKwm6EROE9zlBj88KgQooBfxQ4wKR82aY2LxBh3IjGaS/16fA8Ow
         XhGcVcEAJngPP1gZikr5MtD8+uaA9cHZ1m5sXW3HxeGfx1+fiuX10575E+GW728jCies
         W23BiKIwdaFqmkFRhMqLVZOlO0gNU/C+e439CpzlF8cy5zn7NImpgogF1DeLazgFc6aI
         dIB5vhn7kzbyZMuFBmzS+83j/WCXuC1iafKiGyJ/4i6AUPKpdkBQZPsaY8myrr/A1ggV
         zBkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=BQ3ghKEN;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [2001:4ca0:0:103::81bb:ff8a])
        by gmr-mx.google.com with ESMTPS id d6-20020a0565123d0600b0050ec7483a0bsi401273lfv.3.2024.01.31.13.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Jan 2024 13:01:11 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) client-ip=2001:4ca0:0:103::81bb:ff8a;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4TQDwP6773zyTC;
	Wed, 31 Jan 2024 22:01:09 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.884
X-Spam-Level: 
X-Spam-Status: No, score=-2.884 tagged_above=-999 required=5
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
	LRZ_HAS_MIME_VERSION=0.001, LRZ_HAS_SPF=0.001,
	LRZ_TO_SHORT_MULT=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id 8EExbMguVg1z; Wed, 31 Jan 2024 22:01:09 +0100 (CET)
Received: from sienna.fritz.box (ppp-93-104-72-246.dynamic.mnet-online.de [93.104.72.246])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4TQDwN2WTRzySC;
	Wed, 31 Jan 2024 22:01:08 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Cc: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>,
	Marco Elver <elver@google.com>
Subject: [PATCH RFC v2] kasan: add atomic tests
Date: Wed, 31 Jan 2024 21:00:41 +0000
Message-Id: <20240131210041.686657-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=BQ3ghKEN;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates
 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Hi!

This RFC patch adds tests that detect whether KASan is able to catch
unsafe atomic accesses.

Since v1, which can be found on Bugzilla (see "Closes:" tag), I've made
the following suggested changes:

* Adjust size of allocations to make kasan_atomics() work with all KASan mo=
des
* Remove comments and move tests closer to the bitops tests
* For functions taking two addresses as an input, test each address in a se=
parate function call.
* Rename variables for clarity
* Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store=
_release()

I'm still uncelar on which kinds of atomic accesses we should be testing
though. The patch below only covers a subset, and I don't know if it
would be feasible to just manually add all atomics of interest. Which
ones would those be exactly? As Andrey pointed out on Bugzilla, if we
were to include all of the atomic64_* ones, that would make a lot of
function calls.

Also, the availability of atomics varies between architectures; I did my
testing on arm64. Is something like gen-atomic-instrumented.sh required?

Many thanks,
Paul

CC: Marco Elver <elver@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
 mm/kasan/kasan_test.c | 50 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..1ab4444fe4a0 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1150,6 +1150,55 @@ static void kasan_bitops_tags(struct kunit *test)
 	kfree(bits);
 }
=20
+static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *s=
afe)
+{
+	int *i_safe =3D (int *)safe;
+	int *i_unsafe =3D (int *)unsafe;
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
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
+}
+
+static void kasan_atomics(struct kunit *test)
+{
+	int *a1, *a2;
+
+	a1 =3D kzalloc(48, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+	a2 =3D kzalloc(sizeof(*a1), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+
+	kasan_atomics_helper(test, (void *)a1 + 48, (void *)a2);
+
+	kfree(a1);
+	kfree(a2);
+}
+
 static void kmalloc_double_kzfree(struct kunit *test)
 {
 	char *ptr;
@@ -1553,6 +1602,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
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
kasan-dev/20240131210041.686657-1-paul.heidekrueger%40tum.de.
