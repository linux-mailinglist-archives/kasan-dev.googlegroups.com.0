Return-Path: <kasan-dev+bncBC5JXFXXVEGRBSGI5KEQMGQEAHLI77Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id ACFB74060B4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:17 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id l22-20020a05622a175600b0029d63a970f6sf11014883qtk.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233096; cv=pass;
        d=google.com; s=arc-20160816;
        b=aYrjIrjnYGB9CQwDwHjXKoq9Mr6NzyVwbehciSTYxkfwPoecPX/bGEjTIS5EMbWM65
         AUiN1OvgSgYun5qb0m2/Zo1vHcm7oHTnu1RrfK74jCz7gnuvGbRGzQDup5dcqnYVZTuK
         Macbs+q6QKUNoZC7WERLBVoaKyfWUNnguVy0eiU9DU8EdPV3UeI7s9NsPBWy0Djf9pc9
         T0n0eVl7BC+DQmaS36F8ih1sU140QqKEzzirC8Y6mT68GGuQ/1+JZZxe0V1AHFiGVY88
         vF34hBKpc0RWRw63zQN2nn/h7u2bFanstP1IclLoLg9I7iC+pfKu9/2LporTLbOFic7n
         CxBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Y3wbLQ3nNhz62ovbe1GCtQHysSQcObbZ6AJnQAxnaJU=;
        b=pMcEVd0ppcLt8bPDhNwt15wEBRsYMPM436cqxbgmYnNiQCp7ptpTTDbcziDboxo4ke
         5UEUKT23WDT9C44Fa5CSD29Q7n8AMIhC9kSMPU+6dRYmQQlqPA5BOjl6CCo2sawhzurj
         KEoSsavw0OSEaYfZH/n5xLsQbIlHdsvbPH5RYIQfMNHxc0x3e05KT9PP8uqyXvfJNLB4
         qPTf2YRaPOngfhbV4UiQ3aRvYsa5htQHQVUwaXUENrGFnLXhcIEpQ1Scsw3ybAP4T5a+
         OsEZZareslaBC3bG0fy2IgIm9QZpWKyV42MsJpxDaxjGyFdXMXgGbpmuQk2LBOU0wLL0
         AlJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iS3fSNBC;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y3wbLQ3nNhz62ovbe1GCtQHysSQcObbZ6AJnQAxnaJU=;
        b=Jyi6LCs6/kSIydQTucqSbx7GzxSVb7MsLMm6VUwyIdBztsGZEoxsKoDtjIdyM1g1PP
         m+3S2DrW6F/nztIdLfQMwYbNMxDr6udURKBINeTeGymsm9Ef2cpeh40KCQF/1/1x1XxU
         KJfTUrD1GORdQdnRJMYNO8xFI9Opd9pHmHav/HDkXFXmoQ8gxZbbrryYK4VJ9gC7mJgP
         yvAmoMVbPoVrBLksiuU3cvN71Ao2f3vgL1Z7mgApd+/RwOGFhQNaJ4Kh1YGnl+tP+tEF
         Ra4zIa3nJK5VSMQL75VpBke88ilgWnCtzKY7oCKV84LXybWDEw7Fzpq7z2J1a0yq4QUi
         Q1Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y3wbLQ3nNhz62ovbe1GCtQHysSQcObbZ6AJnQAxnaJU=;
        b=Nn+0Qe1UdtQu8pQkrreB2/gW+IeNaX+xlhxsnhb5J1YuP56bI+YDs0pQj7Gl7yWgng
         7gS1ljjqThLyXMfRhL70H44mkTpw+vK6o7A3MFsZfZELS5k56nCCJGm6XDJDmK9b0KKa
         JZQK9Gaqcs6Kf5pV2ROF+uII1PUWMyIH4l/R9fIR77NuRDhQzOvEk5LhtbI3VKmDpWfh
         B4kxuQbfmZo+kwhFQ2bsY40fgO0gnT5OIFMvA9yOMnmns+F+HtMEAv2eaPzj2s2WScjZ
         4FA2RXoS0l6jPmEzumJpnTBRvhor0wu0cpxuaADnYYCA+F1luKoPIhwRDtC7tWTcksyX
         w6Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GM6bUzDoCD3hdcd09VDfBgrTDUCjQ5IeI/oe8Twofw23LpF+V
	vO9CAMCW5I7O0oFwVj5WBOE=
X-Google-Smtp-Source: ABdhPJwyJukmk/OEGwOm5gyTMQezPSyoxM3Gv39F0CF5rndRfG6mW4KbC1kC7MKUQcYlOjaPxkn3XA==
X-Received: by 2002:a05:620a:1495:: with SMTP id w21mr5469055qkj.443.1631233096603;
        Thu, 09 Sep 2021 17:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1344:: with SMTP id f4ls2092958qtj.8.gmail; Thu, 09 Sep
 2021 17:18:16 -0700 (PDT)
X-Received: by 2002:ac8:4113:: with SMTP id q19mr5613363qtl.108.1631233096116;
        Thu, 09 Sep 2021 17:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233096; cv=none;
        d=google.com; s=arc-20160816;
        b=T4vaqb2wxYdIGeTDPSb8KTjj2Okj5v9uR4pF/dlG+9YWLzBkllzqifoV8Zs0Qz88uz
         1gyR0VyBu8P/1Zkd8kY66wkWKefJ23THL0KV8J3AyspW7T8+gOBod1HNvad61dj8bMvk
         8OJJaqWnNwOOdc95FY34pEoCXX+EH0p9KqA4Oyb7njYSIiXJhLoX+hY9JiA3HBZuYmE/
         cM9+B5d1TCQGmMPA1yM4AX8tGIsSYuY2qFTaDuylyE4E8ztJ8wKZT8s6BdMxNBXCgyis
         dVhHjKVvr2IbJq2VMTckdrNcK5pwH8ffTkWnwLZN+PyqiOesrytYWVcdo9cUuajpo7VT
         2kJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Njt9UUii96fHH0vnVF0YBtjCsggxRY4Np7IqQtsx3Lk=;
        b=Eao2CSdVBCrk9nLF7b/ud3HqWrzoHflidF8UG99SdsyeawJou19vFYDMhlikqkKzFr
         NorfmWWBuBtzX2k4g5BojayNb17X2/TDS0SmsdZ7xAp3dp8vTIg9V/hqfTYdpQoWa1bB
         k2Ah+sdUf1/7vAr9xaNmo/G+eGW2JbieCbjxGTAUSNrxpvZ1i338IhUi3VUhZVC7WZci
         EWLMcKCl022YOsxMNqjSSlJqJY7y3VPzQP3zQ4uepUFIqVIWQrREDALcntcTiO47jj1V
         RExG5HQvrDjwjFQobYdJkt2WIxGIXlGfX0n9FEIpCf6XTp1hh3ygHB2ekkiFPUrA9q/w
         QOHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iS3fSNBC;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k21si279767qko.7.2021.09.09.17.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 26F7A6023D;
	Fri, 10 Sep 2021 00:18:14 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.14 97/99] kasan: test: clean up ksize_uaf
Date: Thu,  9 Sep 2021 20:15:56 -0400
Message-Id: <20210910001558.173296-97-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iS3fSNBC;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit b38fcca339dbcf680c9e43054502608fabc81508 ]

Some KASAN tests use global variables to store function returns values so
that the compiler doesn't optimize away these functions.

ksize_uaf() doesn't call any functions, so it doesn't need to use
kasan_int_result.  Use volatile accesses instead, to be consistent with
other similar tests.

Link: https://lkml.kernel.org/r/a1fc34faca4650f4a6e4dfb3f8d8d82c82eb953a.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 65adde0757a3..564bee50cfa8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -721,8 +721,8 @@ static void ksize_uaf(struct kunit *test)
 	kfree(ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
 }
 
 static void kasan_stack_oob(struct kunit *test)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-97-sashal%40kernel.org.
