Return-Path: <kasan-dev+bncBAABBDN7V2KAMGQENYOU4DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A06D53116E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 16:51:58 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id z5-20020a5d4d05000000b0020e6457f2b4sf3636421wrt.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 07:51:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653317518; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5AYnYAd/HPUnA0vVYDdlhnX9DXENJOPZKuiOJjPJhXIj7Z044XeAb+RnhNnUCnCpz
         mua8mXoPaFA6lzSz7GZxRzm+7aFB3SEpoFxjBR2RrldSzkPbPj2sS6Z4dwqfOBFF9NWB
         +/qzo7/xWhyBuAShXLTvS1e5nIcfK1hIFdDJ9I/gK/E1Y1kNM7aaDJwp2pRTyOddbt2r
         +wI8gk1mNxUAKb1kH16+E4MUwy3YNvlx4a5ZVi/1gLbOohvtcQDMozD4VNJK3cXLOwOk
         zDZNB9JbG5wkxU1a+pkyvwIs+mQvgE+zeS3+odcMwhqNb31lDGBVHFfzUO5Q6TSXkZ9P
         Ue9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aAD82oaSDxw7kHzefZthCvtSiTY3CrZDejbVIkGXhWk=;
        b=aCOQiarMnCK6UVYBg8G7xATchGEBJYZ3f5qP0elygWqu7+IRDwLfBQM4CvlNCgCi+T
         4pi95gvZBcO/rTJ/0AR48kq5Cn/7DEmBtGjCC7zVFM54bETfEkcyZ/insEzXve0Ba9qU
         kiVN/PdcbT2mIXl68OyczzhdkjaYHztoTJFXV+EdkhdZ2AHFDmmmkJdWVEpUZRHf5boh
         NBnQyggPYnE1NC8tZMWrSC5ENMiSmT2NOBTBmu3g5rvMfNifiGGFirswKrKwFAOkLPZY
         CocNhx2QMOcWRynUkOL0yHen2aHWMi62ziT594MDpyB6vFs4EKLK4uSITcysJPQKPiAg
         841w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pT6NCGz1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aAD82oaSDxw7kHzefZthCvtSiTY3CrZDejbVIkGXhWk=;
        b=EyyB/KyilN8sBq/9ANCbtVw5hyhrVs68XCldZDqCI2mTtbZWeiIWJi6lajop2Jdemz
         36Ank513t6cLZi52KbvonlhSrYbX+nQejpYgBnZfK4yGAb8bqLngAA0sj0CoQxb1WrrT
         LLsVEMtHRP4lWp3W2QwvnEEhN5rXW0Rvr3DIAkd8TwmqNUzWUaK5VDTAmvKN71wwdjhm
         tW35RAg2+o0gKm58iU5Viii8qF7/QKuYlTRwJZgRJZmQSrMWmqnH6pOjsd5VdlrvwCKq
         qJ8yBjiRZPxxq3hIZn4StIpJaBQMprOLUOtuIrhp8zY589IUQOX2FAUdrQFfZPV9OvvW
         v9aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aAD82oaSDxw7kHzefZthCvtSiTY3CrZDejbVIkGXhWk=;
        b=5tIk0946yRHVSJbXYJd3CvY+BScGLnVOgEQ4/x0gLWUx/WNu89s1t3Qm+mCAAD8dNU
         GB2ML8b4MJ37ev6YZvLqAMh8F2k2OzqO++7N8Fz7/0eoWZ/Mx5zmmiBAlpwK3BLo/WoX
         Vivwtzz2PxqyhhObwwdWyN6dx5wMZtB+9PwnFAOxiGEZb7bQXyzMGQlhGbtBFmwl8OSj
         p0VL+3EiJ/skHww5jjB+rFmLh3WimTmZ4QfQPrRjY0KaqM+/spJOBKlLcRmqd1URL1HF
         vj7r3fvffFWGHoNyk6mii8kTHdIn+iswbXnaVqiaiB69pOOtYKpXCl7KZcUmGU1YNGwE
         7ELg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GwoHty+39Qp7Hj/bPbcX11da4UjFJZKSwHemINPJv6cLhNBWY
	jEtG47mizA1I/QJb3yuMzF8=
X-Google-Smtp-Source: ABdhPJxFXI1Cn59Y+GEsPIlsWvzPDYLvNlMWT3rRgnjJrtMhlIepUL0XUGBB7rVHhPln7bAoeyCCZw==
X-Received: by 2002:adf:fe42:0:b0:20d:297:f86e with SMTP id m2-20020adffe42000000b0020d0297f86emr19394139wrs.382.1653317517914;
        Mon, 23 May 2022 07:51:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ca:0:b0:20c:bb44:bd7 with SMTP id f10-20020a5d64ca000000b0020cbb440bd7ls1087048wri.0.gmail;
 Mon, 23 May 2022 07:51:57 -0700 (PDT)
X-Received: by 2002:adf:d1e9:0:b0:20f:d6b4:56a9 with SMTP id g9-20020adfd1e9000000b0020fd6b456a9mr5796724wrd.169.1653317517238;
        Mon, 23 May 2022 07:51:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653317517; cv=none;
        d=google.com; s=arc-20160816;
        b=QXYFFrd6FULDbJHE+JkXV8VdaVhKw3OGpBpOBuAToHH9IHtFVjrG/M04aUT+MUda/a
         ZY66lOVCXwgkE8zf4tnP6wyL4a0r19yT2x1MG52ns1MUgFIUTXi/FM1HnSJRmacxjj92
         5EBFtPnYwhk4JENjxvtg1EMY82WXGmlculWzc6PKbz99u6eQ6u2xvvUPbAiH+2j+qe8P
         O0fLtYCg0N+vPNaL8Um7ZEh+oOnz3MJz94Hfr4nMwjC8dmq+BAc1HobYa99GRrDCYeZc
         ut9+p/L3j9p+LnzGYlVuu+AR83nYsVks2xjbzdid3MABTvLpsGJ+/5+vslFJ7WJva/5w
         O5/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PDuBGpkT9ArerlP1XBDcRGRfZ28TAQhMJtn5mwFKc7M=;
        b=EfhCbzkNbQY+Iugk7FrXTt9bTVIE8PU/6y7OZAL+2mNHrxMsxe35WzY/2YFNXMifDY
         FmY2ikcxcv3gWnCXRj9t1cRhPEnseKXpOOr5Ye05+j6HLlvNGR7fbHHT68bQoU0aSDYb
         bJTrPyPmroNXu9Zk86jQcOXRN4GQ8A7JXMH3j3pYztdY4TZRu9FO0YmCweU7ZpGRUMrn
         ty3SmgsEeMoPUHDGHdRjMg9XbCpzdRtjtdRXtFxm2Pp3iOSfQB4mlpPsYtNIi28OUjy3
         zpVaMfXq5dKNwF+KtZiiE6rI7u/XFc1pxFvMuBdn3P5HzIqf77v8UREPZY1cFqShPmc5
         wO0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pT6NCGz1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id l21-20020a7bcf15000000b0039469a105f3si521951wmg.2.2022.05.23.07.51.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 23 May 2022 07:51:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/2] arm64: stacktrace: use non-atomic __set_bit
Date: Mon, 23 May 2022 16:51:52 +0200
Message-Id: <23dfa36d1cc91e4a1059945b7834eac22fb9854d.1653317461.git.andreyknvl@google.com>
In-Reply-To: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
References: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pT6NCGz1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Use the non-atomic version of set_bit() in arch/arm64/kernel/stacktrace.c,
as there is no concurrent accesses to frame->prev_type.

This speeds up stack trace collection and improves the boot time of
Generic KASAN by 2-5%.

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/stacktrace.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
index 33e96ae4b15f..03593d451b0a 100644
--- a/arch/arm64/kernel/stacktrace.c
+++ b/arch/arm64/kernel/stacktrace.c
@@ -103,7 +103,7 @@ static int notrace unwind_frame(struct task_struct *tsk,
 		if (fp <= frame->prev_fp)
 			return -EINVAL;
 	} else {
-		set_bit(frame->prev_type, frame->stacks_done);
+		__set_bit(frame->prev_type, frame->stacks_done);
 	}
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23dfa36d1cc91e4a1059945b7834eac22fb9854d.1653317461.git.andreyknvl%40google.com.
