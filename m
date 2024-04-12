Return-Path: <kasan-dev+bncBD66N3MZ6ALRB7WV4SYAMGQEEBNG6II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id BDE268A2E76
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 14:37:19 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5ac4939fd9esf570029eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 05:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712925438; cv=pass;
        d=google.com; s=arc-20160816;
        b=KVUmUmgzhicb38FrD1DrVHPCRtsReTJ6XH30RVxK0HwDoB198akBjk1fAbnbnmARKn
         vbIlWIhQ/kFGJ783Q9xX0poqRdoizpuJteZG0FuzY1ccq3H4WKyMpJ76Gyxtm484WV6k
         PPfraV3uSp++nj709nwYe6UYh297kSde9QHKkgxBu801DMfpH24mqE0X7SUKLL3J8DP/
         V7bsDpDi6ztzyEyH9J5H3+T/8Wc1uD2O9uSJqvHFic77EXwC1eW4ZFQeSP/CgP4kHc9G
         J+x8HJ6VRWs2epQGkm/EwiALWmCnc/nsK9tFTm9fSOQZsZX0WCMg5sWHmCW7dktqufiv
         qhkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kduA7ub9vHY5OcRWvMsZM+ds9Mh+ky5wPS4nwhKOchk=;
        fh=pxmAYC3MU4jVRc2paxH25dz9zfpyZHr+ZkwbXXn74+o=;
        b=uCmYYy1zo6V9ncSbgIEjcfQjzoj3jDBmsuHg134WkiI3aXnQyZwZw4n02MpmiVUeZk
         vwHIH8tPfBk1Dr8vysSNRr3e8K1FPe8vaQDai0RGAPQvnb0HvTRGWyb+++Icyyti89Le
         dYKohUDyfF1aUWP5oUtyGwUgNKkZJlj4zYqWh6YxW26QAjKjQHtrU5sR7pQ1KO91JTF0
         BULdIsF91k5r36a37kx3dnrq3B8JzhlZafc27d8M2MKRHTDsUJ/oiaNmSzSMsSTwYb8D
         nNIz8PTPkiYoq4BjTrZugDOWz2weN9PtIcB99F4L4kKNKmhn1956JctbB+oYXqzUFN/w
         A1Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DuPODGR+;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712925438; x=1713530238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kduA7ub9vHY5OcRWvMsZM+ds9Mh+ky5wPS4nwhKOchk=;
        b=I6oJlLpA/N+D32RPTwi105KLsqG2iTnxRVcxxmN3yABqLdncO5xDbGy88y3eG6Z/85
         9IqhxGfuwm09JwtOLm221Ki1FIga0hL639m40F8VFtI2/OzteW/i0wbtfSqBjPNgIVaO
         vdIy0hobz5jlaZ10l2QtVJmmRQjnNRgkvugU7V+ni6qNAtj1lrTDqr+oz/oMV2T9Xb+N
         43NnE2cE1I0aMib+lF/mPPtxIajQw9HilfbhViHg5qHaAiLbJfSQxxheQAsKwOz2j3zF
         RyH9gmh+yB2nwq+NQhGUYF4tGGXyhejIvQ3ANDJHpdlvUIyTNB7qwRiAlJ6qjVHPxhmk
         ptxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712925438; x=1713530238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kduA7ub9vHY5OcRWvMsZM+ds9Mh+ky5wPS4nwhKOchk=;
        b=pTicC1F8F1mFoqvDZY8mQ4KnLG1nC56VJ5FeGjgbDTMG4zCJZYic1LcyV9MdzJzBM9
         YKJRiYXYNp0HZbxgs1pOy4/+5l5uhn9a+1Nj5sDulc4dafuKDVuBtziY98VUhqv/69yQ
         FBfgECyTQvljX0N+5SkZcEVPRagoJ1ddLRLKAoSkgts7Pq8Tg3jpZAHhw6mS2KmgQkw7
         0JfoeMZZeXAlGHAbZxgTE7w3Vnl79Kz+DM9dm+PUFCueCXTevoc9WOF08Bp0DC1dLgIi
         XYwJwOlCg75O3LUenrEZIc+KPYf8M92oshOxIRWe6/o3Z14LzxSGok1566dXwE0zUigj
         CSDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQQChQbgLDOYKoOXhexOfqS2ZibdBHKzdC/gPeIjd9qCfBOSYPf1XbBn0dL2R7UG5YhydkiuNXIe67LRczVfaSYceV4AHV5Q==
X-Gm-Message-State: AOJu0Yxwnqel6EMHf7PFqoQgdpwnjCIlRQV6aCd4SE8iVI2rxuGWFqFM
	YIk1SEjGLhThSMbQIhghsDYK+rDTiTCANQm33/J5znUkWCGdnPRd
X-Google-Smtp-Source: AGHT+IEz0/f0KhnPD7FjoK3ztIVbhrTOMYNCbat33eOyRPjyt7bMZ45inoeMKsaPoMgm/lrrxropiA==
X-Received: by 2002:a05:6820:2789:b0:5aa:53ea:ffd0 with SMTP id dc9-20020a056820278900b005aa53eaffd0mr2619855oob.1.1712925438254;
        Fri, 12 Apr 2024 05:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:220a:b0:5aa:328b:95c8 with SMTP id
 cj10-20020a056820220a00b005aa328b95c8ls873297oob.2.-pod-prod-03-us; Fri, 12
 Apr 2024 05:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVs8OqoVzwKsUIAAeuUmMWoc/S05xf6D+BxAEfeVUlED2UsXe3G7h9oiy5s00k9flp2xAwkHS/3W5Bi95X5GrH59XKgy7jWAERDCg==
X-Received: by 2002:a05:6808:b12:b0:3c6:d4c:7882 with SMTP id s18-20020a0568080b1200b003c60d4c7882mr2830849oij.1.1712925437380;
        Fri, 12 Apr 2024 05:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712925437; cv=none;
        d=google.com; s=arc-20160816;
        b=Pg9EnEZoU6qWwDCXcLCLOHxaZLSL4ASNp7yNzKW8YxllUi3ZuI3WVI0sUsD1076oES
         imme1eUOQNFO90ED6KWTklxBcHThHaPTvrrVakjkpfxmq8RDAVQZQFaQ94h1kgTshy8T
         /CNIDGLk/EhWjHfleCLfaexWy+SaXT0Vap1uZ8CVnYbk8s9+G8M/5ZrhTqa0BA06sOyd
         dALj69+pW2EUo/akriSDU95he/xGUnMYLyXQibIqEvTDm+9NPqPzctN1SVDp9I9rjUK/
         3WWkTB8G2ck+mHAK6Y9mPVzat6m3Kt8HvUZd2bUugwkptZaQmXI+UWO4CRAYvg9YhKnG
         BN/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=G73VCC5q7JEsOcm9nuCMvIK+kF0cB2PArLXaQyavNe0=;
        fh=GPwOwXDR5gomaXhADzJxhvqEghAiQmiLZGcuqWyHt2M=;
        b=gbwd56y9cz7TWCtKDuU/W0d1pivBPw82WWE3GNpdx5dCLVy72CjTPj0lM81rTN85P0
         MkJ1pkoJ8KdKy84VSioFHz/KgZ5vPA+x/cKqkm4Sw7oY/2DeJVAgZnY04yPPmtcfrCcD
         On1NqmhSJaDqjmVktP7E4c22+MFeHGrdIwTYdYktEVPZVkcmSMpDEbA8+hrC8LmzADG/
         AfsXiP9qybhM6qRLeS7qwfqEU8EHrlNlnPPNDN8uDR+QSaFql9BzriTgpV3KAbVWWeoA
         7xQ9IAf+sdJU+zZskJEo7flz5O4qR2IGM59Kmkb3Pa/welDw2xoQqARnVBMLVQnVoRMy
         KOng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DuPODGR+;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id bk32-20020a0568081a2000b003c5ef716c55si190312oib.3.2024.04.12.05.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Apr 2024 05:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-606-HdPWaD0fNQeNnOeMpYxRCw-1; Fri, 12 Apr 2024 08:37:11 -0400
X-MC-Unique: HdPWaD0fNQeNnOeMpYxRCw-1
Received: from smtp.corp.redhat.com (int-mx09.intmail.prod.int.rdu2.redhat.com [10.11.54.9])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id B505B802E4D;
	Fri, 12 Apr 2024 12:37:10 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.136])
	by smtp.corp.redhat.com (Postfix) with SMTP id 73C72492BC7;
	Fri, 12 Apr 2024 12:37:07 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Fri, 12 Apr 2024 14:35:44 +0200 (CEST)
Date: Fri, 12 Apr 2024 14:35:36 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>, Mark Brown <broonie@kernel.org>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: [PATCH] selftests: fix build failure with NOLIBC
Message-ID: <20240412123536.GA32444@redhat.com>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.9
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DuPODGR+;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

As Mark explains ksft_min_kernel_version() can't be compiled with nolibc,
it doesn't implement uname().

Fixes: 6d029c25b71f ("selftests/timers/posix_timers: Reimplement check_timer_distribution()")
Reported-by: Mark Brown <broonie@kernel.org>
Closes: https://lore.kernel.org/all/f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk/
Signed-off-by: Oleg Nesterov <oleg@redhat.com>
---
 tools/testing/selftests/kselftest.h           | 6 ++++++
 tools/testing/selftests/timers/posix_timers.c | 2 +-
 2 files changed, 7 insertions(+), 1 deletion(-)

diff --git a/tools/testing/selftests/kselftest.h b/tools/testing/selftests/kselftest.h
index 973b18e156b2..0d9ed3255f5e 100644
--- a/tools/testing/selftests/kselftest.h
+++ b/tools/testing/selftests/kselftest.h
@@ -392,6 +392,11 @@ static inline __printf(1, 2) int ksft_exit_skip(const char *msg, ...)
 static inline int ksft_min_kernel_version(unsigned int min_major,
 					  unsigned int min_minor)
 {
+#ifdef NOLIBC
+	ksft_print_msg("NOLIBC: Can't check kernel version: "
+			"Function not implemented\n");
+	return -1;
+#else
 	unsigned int major, minor;
 	struct utsname info;
 
@@ -399,6 +404,7 @@ static inline int ksft_min_kernel_version(unsigned int min_major,
 		ksft_exit_fail_msg("Can't parse kernel version\n");
 
 	return major > min_major || (major == min_major && minor >= min_minor);
+#endif
 }
 
 #endif /* __KSELFTEST_H */
diff --git a/tools/testing/selftests/timers/posix_timers.c b/tools/testing/selftests/timers/posix_timers.c
index d86a0e00711e..878496d2a656 100644
--- a/tools/testing/selftests/timers/posix_timers.c
+++ b/tools/testing/selftests/timers/posix_timers.c
@@ -241,7 +241,7 @@ static int check_timer_distribution(void)
 
 	if (!ctd_failed)
 		ksft_test_result_pass("check signal distribution\n");
-	else if (ksft_min_kernel_version(6, 3))
+	else if (ksft_min_kernel_version(6, 3) > 0)
 		ksft_test_result_fail("check signal distribution\n");
 	else
 		ksft_test_result_skip("check signal distribution (old kernel)\n");
-- 
2.25.1.362.g51ebf55


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240412123536.GA32444%40redhat.com.
