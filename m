Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXOT5HDAMGQE5YL67JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id AE47DBA8FAE
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 13:13:34 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3f7b5c27d41sf2406333f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 04:13:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759144414; cv=pass;
        d=google.com; s=arc-20240605;
        b=RNTNnIpCNMcNxAgeN2+AhxIebR7zGQeDI1xFTJOS/hlDYaqbXmUYvZEkwIh1jAIDoS
         FhiLIH6SnaVlUK6SMg9i9W8tBEeOTlstP+obwo8n/DvN+pJN8XgJqWSGSQpgknicoFai
         wuzh3h/82n/Xd4rlJZ1OGAD99pcDbcNb5eW6o3/cF3SgwbiOnBt0hLRXx7vZIpnerwzb
         6HWKFonhu/MxeyszXT7wZqh7qeoAbFRNHsFcZ7kiuRPvWDTjVbZdlUwh4t8Dmqqy2nML
         PWGrqpYyQIRT10FW7xhRzLx0YHiMyuroUl+ollbzug9OubbSODgnEVxPGZL+6YW9qrTm
         0gvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vhGBvJxfnReJ6cN19tf4F83jMQ6EnFteJvCQCrCIeUE=;
        fh=gfBcLfdYth+gRJcAfn6dchuOOpfC2GURnuYdW0jISB0=;
        b=aICmXAntRF3F38StZ7QX4LP8GfLHhp1PSOjfJAQrubKBEjs26CvFZRPJj1ETFupnjV
         xaM/8uokbONnLJmV1ZQTsW6wWVCOacH/+qHOWMl+Qfei5h4To1pRHM1Jo4kna41NIF1G
         a7d9KYP+uzbEQkjGvwR+BA3MZntRJrivJnYa1w1vtEmYFWXJD2GEsjwA+q+SxDI5clp3
         db3fKSC7fRuG04/CqRy84NAld1HXJhenSqCPpu7rk/WCPfikrTXBFY+9UVkuUtUzfX4i
         0MLW8zP+E2ih1jtTO7qwVi6YIWnbDWGdCaVsh0xaRiCJ0EiF6FF1DZRf0GvM8BDhpBmC
         5M5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CErv4m1c;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759144414; x=1759749214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vhGBvJxfnReJ6cN19tf4F83jMQ6EnFteJvCQCrCIeUE=;
        b=VQQy9Q6N375RhH57Aq32lYYSSfqUgsM62vo3CaXngOh4inJfTuhLgjMM3q4Xv6jZyH
         DEP7eDm1Y/XMQbw/jD/V260d4yM/F24QXYUDU3KkFUL5mVBLmbZDoEO9nbCnp6vzhgwH
         FS4xf3UWsbjXxVx1r5PEvCfmvOtVdDVr0VM2qVeKDD/gXYwhjLnYo2AivY9PgDZEbwZ4
         0UbuvYGnR8O+2qb33Gbs/fSghVFmsPR6atAosasPMVsWQ1EXwCADNesZ1549Q3mnIfJa
         s4QAjauZQi9MX4NSWqPfFIWDnzlERcCB9T0t7uuB6aplrus09GqDt9hrMMMyW5jZWVXp
         l1hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759144414; x=1759749214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vhGBvJxfnReJ6cN19tf4F83jMQ6EnFteJvCQCrCIeUE=;
        b=UOhUGTuTDjD694uE7F6mgNU60GKt8CWkVhTG0rLjtjyUFJ7vLZY43K7w0R0FWF4vyu
         fSRkABEVmTDnKtdp3XDec1+rry88vLkqOK8wsPHZ6LeLk8pWmRF4O6SX+v0MdoR1+glh
         PbOIEZk8mbhT3syyFMzIRhfkHuOdALIxZHjq09gvvpL3gqx6YUpjHa8ylUCQeUW3VIdP
         gx3H548tuZ0cPkgJwPrVdg6o76/kUcT6ywYevyuIdUP/yAWJ5nVworKKSGUegTyh6VXO
         qifqzxFwGB5Tr6KAgONu+3PoAyX8G70eobbIKRl7iRtd8/VfaJsv/5TAjt07KFYyCd1Q
         OtXQ==
X-Forwarded-Encrypted: i=2; AJvYcCUKpn0q7xoJDyAWB/aHmFw6Rjp0YVOY8igH9RFCtv5LiabkJb3aMajPl16s+PfZWFyAYJt77g==@lfdr.de
X-Gm-Message-State: AOJu0Yzy2Kaid48ObRCKGq7hJLjSfs2WML0pz8aVeRA13XIrFWZaHNO/
	q0tWOQUQbiJaful2Su8DE6dGzZtHR+X1bh6a1dD5zAXewg712x1pR5iT
X-Google-Smtp-Source: AGHT+IFhltKNGiEIIP7H9Ythg/jpguP9fRHtdwIrL0hacZpMaVVHMgz7kgLEp3ysbXCxehmDehDNuA==
X-Received: by 2002:a05:6000:603:b0:3d0:e221:892e with SMTP id ffacd0b85a97d-42411e9de85mr164676f8f.27.1759144413727;
        Mon, 29 Sep 2025 04:13:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6AUuTAtfFLlqnTlgH5HbOQTNTpmzbpf2+p5/auQDoDOA=="
Received: by 2002:adf:a2da:0:b0:3db:a907:f17b with SMTP id ffacd0b85a97d-40e999c898als813288f8f.1.-pod-prod-00-eu;
 Mon, 29 Sep 2025 04:13:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmxCVZk2+dnff3+ANxoAsmnfimcTbfGnx37cNjjVIbv4Utc5x9y9vNxXQQES/G+O3HtF2+8FoV7FI=@googlegroups.com
X-Received: by 2002:a5d:5888:0:b0:3ea:d634:1493 with SMTP id ffacd0b85a97d-4240f261673mr205107f8f.3.1759144410829;
        Mon, 29 Sep 2025 04:13:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759144410; cv=none;
        d=google.com; s=arc-20240605;
        b=ZWxMeZEpqr2UPPhUMZjdxIFtxPYWShCRK5N8qCYbj2A9PRBQ5RbzihWiYM4m9gA5UT
         wfbkegHAiXtyk6vZ3tgjcmNTSw+qjQ6qtUHUq0lqMb7au7g2gHgNxEPsAiUnr0TvX3hN
         diR/EE54D9McZtLcTyY9Ox2oGUGtsMgFVbBBYZh440H+PmNkq23W4sJm2btaa9O+zeiC
         6mlo9b1wMSM/ASWqL6Rw7EljxlJUW2r/8wgcKa7GqkuJfHBdElPRU+dbXAZTopWjfVx0
         h5ga+8nEREbAP1ytC32mYv/Tf66hlkDQxEV2J4WkrIl6hfFHybUU0rZSFMsRmganb3TO
         PykA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DXO5GvU88t7UVH/Ib6wizEbX+5jKFC6htDrC7AhnY9s=;
        fh=uDV6PTRObkvf3lrWbEKRzN9EWm5GUZ2byuqHq5+tM3M=;
        b=JKXBrNc8ripkRR2ofK26a22+7WnMpR5LKvKHUF5fv3QWAwDprluNaFv1rDNLasyNIR
         f1AI56HKqpDQdpBmtV6Sb4xiq6SGE8rYPY0z5GjGLKOZj9dQmUWad1Yyu3EGeXtTOPwp
         JfxCfTaGiL6iaTjuzxJwF9eDPxBTY/i8axUW4FzdH3P/Jj4IDyX33Mo8vlPuw9dlR87b
         8CuyqRONnPXhCUs4HXbY+G4m3aJjqSXwsh92Y7dPs4yRZs7XTkV8209AN2i8dNyRpUcv
         Xq/s7aCurAGGrPljTRIa3KSdFDjGLsVNadGmd3ItJtq4RIfTCyglkemSfiG6jENueg+1
         K3qA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CErv4m1c;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-40fbe9d6eafsi265113f8f.3.2025.09.29.04.13.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 04:13:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-46e542196c7so3688265e9.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 04:13:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUWWJ3EhjLe2UkzUmoMvEcXSK2VDVVVRoM0grYywKFdRmqIUYx/+3ijpzsDS3Cj8gd3yiSN8DTzWBw=@googlegroups.com
X-Gm-Gg: ASbGnctgf1fhTJokbKS2c6itfho/4SDaiuolPac2prfU3u1FSRhNHIbRp/a1dWquQw7
	xOf6ThG0AdFXqC2BEg7Z338xJtX90oS4ofj7uTwJK7K+hWIDeh7vT+WORj1HdDCToL5QilrpfxG
	u35CrK9IDunad1g208FbECTnPWpD0X39eK0mpt9k+6ETKnEBlmML0rGiDoEiAtMlfA5ouMLuNJA
	hXYmsLYZoaSz7nNgkQPrnc+fYIJ8IS3AQkdR0ojcII7W6HeYB3s6mpFokAbBQ0rUi8za47E4fl0
	kuY+O8DsS1yiXVe9AHViZBXGSSX26VSY0ZV6tGK7Qt265SHYBkcD4QGWsCSJhDAEUDkCyxeBZEr
	aInB9C40V3zRbzQt4MaduQ4tflEnaj+ePAPCntm8Ez29tsVVpCFBaGGFVLThKlO2UDUNaMiJ4bP
	I=
X-Received: by 2002:a05:600c:3506:b0:45d:98be:eea6 with SMTP id 5b1f17b1804b1-46e58aa2434mr2220055e9.3.1759144410179;
        Mon, 29 Sep 2025 04:13:30 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:79dd:ee6:d7a2:800e])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-40fc5602dfdsm17729603f8f.33.2025.09.29.04.13.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 04:13:29 -0700 (PDT)
Date: Mon, 29 Sep 2025 13:13:23 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [GIT PULL] KCSAN updates for v6.18
Message-ID: <aNpp06-SzK-OOpUt@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CErv4m1c;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

Linus,

Please pull the below KCSAN updates for v6.18-rc1.

Many thanks,
-- Marco

------ >8 ------

The following changes since commit c17b750b3ad9f45f2b6f7e6f7f4679844244f0b9:

  Linux 6.17-rc2 (2025-08-17 15:22:10 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20250929-v6.18-rc1

for you to fetch changes up to 800348aa34b2bc40d558bb17b6719c51fac0b6de:

  kcsan: test: Replace deprecated strcpy() with strscpy() (2025-08-19 12:52:12 +0200)

----------------------------------------------------------------
Kernel Concurrency Sanitizer (KCSAN) updates for v6.18

- Replace deprecated strcpy() with strscpy()

This change has had 6 weeks of linux-next exposure.

----------------------------------------------------------------
Thorsten Blum (1):
      kcsan: test: Replace deprecated strcpy() with strscpy()

 kernel/kcsan/kcsan_test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNpp06-SzK-OOpUt%40elver.google.com.
