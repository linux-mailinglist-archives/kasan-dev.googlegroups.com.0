Return-Path: <kasan-dev+bncBDAOJ6534YNBBQ4QWK4AMGQETK55V4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1091199BDE5
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 04:56:06 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-431285dd196sf9429125e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 19:56:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728874565; cv=pass;
        d=google.com; s=arc-20240605;
        b=gscj29gfQbyVRlHFB1WJho3seioKCIL4e4ZdkKzD9t1qkZ7PHK2rNZ1aOf3ZQ4ey4v
         CQBg4c9jAJovdlnl0WBM73ROBL9xVWq7WWG250ZllfEoVk+THQEhVCCAIQ9mvZ5GcmTt
         Vo5uPIfDm0D1DbvloQx4SW1rtR11IxKRCQ+io+vm5m+px05R0z4dSlZHftJEwk+zTjzz
         mXtT6lQCJ2tnevTIrZd5vJGAB0P+P5AzLFDOt+gFRBWyrtfNgIKqQ21gQGr2CPIqwtfG
         YkAZl2dL70UZ8t1FTifyYaVEfIC1j7as+iP1oF4BILq3E1mXCo80szczwNNhSGmovf03
         Urwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=9XUCQ5NMN0TNOJF+MuOt+KeYAO8Md+BHevluloT8ECA=;
        fh=r+ezKuUfsIIeNfsyU68sufq3SvaBhL4XMH2tepm18Dw=;
        b=GFvRGqW2Q1FwNf8nVtH++d/6f39AAFV9YO4v2X2Mbh8AaKJrZRotPu2WjrSWLq/LzH
         QkZCXe8crWMIJoqEoLB51NuAMYvOo09gpWOhfRpoE4+yaY0Dy94VrmkWzvDcpoTakHch
         S5xdpIeoWSXtJ3SV/MteabvmnB671sPetr2XJBF4jgIwmlWIhkspl+XnMjljLVpboLcN
         rxBjgoXj9ol7S1mItC7bqTDfP+o01XVQn53kLEABYhWFlKVpUbgTe9S81ZxfBfNYg+zg
         wq+vQPeBvAGZE923pXfl0vlMjYNDjb9J8ZX/io9QSmobxKx4R9PQCF+DVTXAE+1OjoBJ
         7j4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=isp3mMmo;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728874565; x=1729479365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9XUCQ5NMN0TNOJF+MuOt+KeYAO8Md+BHevluloT8ECA=;
        b=BCPW+RIKWTxN2Xjkdh/0tAmLYYYNQBcNu/og81SHp57ONvOqMMWi+kWyDonCy9e9Dx
         VeWqEK4okL5vUSoljInaxQola+R2THdgVyhB/yE7XB7SDD7O/LiMOzRcW+dCnYiNkRt8
         XFuzWnGacnMxiYVQ4XKjqGd22SlXjQ/30W46htYMJUDhvIW6ulUpf5RbdornCRpV1tw1
         JStR6DuhWbbV3iHZZCGHKLJzX2L0foJJCTf0WAIxvfJ5KsZpH+wmJ5Gu2IRn9TXCFVwQ
         Xo/fhUttcCg1AkUwNMP+2wWtu59g35o+wl1AbWsjDzhIbi7Y1tNuP8+yscKBXkGp7oKS
         F5DA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728874565; x=1729479365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=9XUCQ5NMN0TNOJF+MuOt+KeYAO8Md+BHevluloT8ECA=;
        b=UWqnKNE8Gmoa6RSImts2vHNBj/fvzsd9zvxbFO0Gq0SCQNhz8ty8h4y0OogspqjL34
         Rwb4Q/DUCYV7jJRqrSrY9FryyQOVyKEzslFl0sPIW9AD1juIt4fFSWrI5aNRRhYnK0mZ
         QSWFPtZ1glL1ajJpywBToQoMj1abx3cQbM4T1oB7Ve0JscQxt99t9x54gxv9xq8Le48+
         r3TiHkDGswLlc7pxOEZVJVx46CxqYnTXYF2kQuWXm82y/RgMGQCn/0WzF1/nKZThvoau
         2EXSKl6AU1Yd8HxZ0V6xDWnThILpba52nrenCbzilKDP/8mQEuMNbiLKJDF4sYKXTnXX
         kBpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728874565; x=1729479365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9XUCQ5NMN0TNOJF+MuOt+KeYAO8Md+BHevluloT8ECA=;
        b=fZOcbm/TqMma7VCAcbxUv29+CgYFihzNsFGSOoo7oxZeQBzaB1GKoYYDt0SEDw98Nl
         woVecPnxf4FfKl6p53nb6z5ocF6ld8GnlF7COqN6hc3pByYqRALXIs74zUaySsW4C0E+
         0uCgLj0RR13qbGWeNGlvjl3zBJYac3qsZCdd3gm8T8kjt1mIdABZ44nIgPeS7ge6kpbX
         L0QGGh3H7NKhNcVIcqVOd9ktxBUi7ryKS8yie2VCYg6mHxhFlrz22dKvMoCZJt0gGo0/
         DDLVGttOki9r8s/D8KWJKXmsLeNIxQzbNsQW5y5VTBBR+d2BferA8ihAMeIAjtOElJcC
         oldg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWROTZTyENMJIgpSvwoRlKX2jzdPhMjRLuLtKuYNH7g0aE3AFHbeSvSzEVKvr7TZJWrGJhnGA==@lfdr.de
X-Gm-Message-State: AOJu0Yw4omXz9j7h7g1oLPEodd9gceZJqsIez7OY7vDoYKJ/O8wdwAgT
	SPIx2Qn3MHIs23kYDzIs7VYk7UiJ9IWqR6w8Xv6e2wAzVcpJEJ4j
X-Google-Smtp-Source: AGHT+IG4rr8DBszqDfnsfRwBx+lqX2C6kTkFbzzTTQTFHFT1F4drdZv4lN7OU1kbgbgkd5x+XwBP+g==
X-Received: by 2002:a05:600c:3581:b0:430:5887:c238 with SMTP id 5b1f17b1804b1-4311decab1fmr88386805e9.11.1728874564231;
        Sun, 13 Oct 2024 19:56:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c28:b0:42c:b1b4:db22 with SMTP id
 5b1f17b1804b1-4311600b81dls8360565e9.2.-pod-prod-02-eu; Sun, 13 Oct 2024
 19:56:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUPKRIIkT4JWbH5Bfv1BD91W4u9vYVZ6zUCvGQktyBEESP6wAqiIEB6mTlZdJvt39sRxUo55SJbh4=@googlegroups.com
X-Received: by 2002:a5d:6703:0:b0:37d:4dd5:220f with SMTP id ffacd0b85a97d-37d551fba84mr6596406f8f.26.1728874561980;
        Sun, 13 Oct 2024 19:56:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728874561; cv=none;
        d=google.com; s=arc-20240605;
        b=B+RBuzfN+oPZaZrUbKYiiHSvH2I1BhxVKHxdyHmqFK1vF7RcR3oLve+QJcoYnN0i5F
         oipdk5hACiFgQhYhOwBh1P2NoQr6nBoqJv9lt6Bf8PajlZJ1ZMIcHckWCqt8oQhV8jQ3
         BL4SUi9AAWUeHpcGORV/UhAhHAeOO2VD5Pq+KTu0++nCk9iOVm6/l287ZORlQ0aQuvcl
         8UbUr2ylPNwDQHIYLABnFfy2+vrLKwLCFfHhj9hacuWSEB8dchmDke+PCy7lNC5dp8Yw
         FAe8mt3OimMXKGr62Gc5xiI+LkMliNSCEEF6OqbgU6BtR2xXGE5Ii8eQ4WrP3ksLaY+/
         gAvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K7Dhocqjb276k2G2J0MeGRjVha2Bmm+qWInnAWrlt1Q=;
        fh=Ij0R6YyHeEgmmwFSO5PliyMyF+x4B2ITgMYqiP3ETb0=;
        b=T9fKAKHB+spllw43SQFzYlvOR1pWf/keLEFCB6QWP6OEn7QJCwS1cp0EFLjqXqMTgW
         3xuvEjYiZeSyEG8qdtGz+AzJMSsrO0rtreMagqPXaHLVoX5DDr6dsYuAQ7BIciJ4mJGs
         Xp99O5E8KYddG1E+fyTSFLYdQmELjPiBIymC/zvlKMdaPuckW4b4uMs3pMIbnN28HNJN
         HXpeq6Ij6BY069666NBQMJrfzU2UBe8+TST6eVq9IN5dGCy7IlUyijuuStXo0Qr78VJQ
         Kygn7tsTkHp4rsvXjkQFPcGr+A0JOX/flTe+ENRYvi0enimOwQuiaaBhqhaCm0qec9rB
         RehA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=isp3mMmo;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4304ed0f679si8780285e9.1.2024.10.13.19.56.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 19:56:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5c960af31daso1722386a12.3
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 19:56:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWcU8R1/4r3Ygx5UZAfWH52yIh4tcnHlL0XOjHP+qRQD9oNUxB8UAERtI5tpBEVzfDeV1wpOGVBFG8=@googlegroups.com
X-Received: by 2002:a17:907:6d02:b0:a99:422a:dee5 with SMTP id a640c23a62f3a-a99b970d0a7mr852403666b.57.1728874561232;
        Sun, 13 Oct 2024 19:56:01 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a99ebdfbff1sm270501366b.39.2024.10.13.19.55.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 19:56:00 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: 2023002089@link.tyut.edu.cn,
	akpm@linux-foundation.org,
	alexs@kernel.org,
	corbet@lwn.net,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	siyanteng@loongson.cn,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	workflows@vger.kernel.org
Subject: [PATCH RESEND v3 0/3] kasan: migrate the last module test to kunit
Date: Mon, 14 Oct 2024 07:56:58 +0500
Message-Id: <20241014025701.3096253-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=isp3mMmo;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

copy_user_test() is the last KUnit-incompatible test with
CONFIG_KASAN_MODULE_TEST requirement, which we are going to migrate to KUnit
framework and delete the former test and Kconfig as well.

In this patch series:

	- [1/3] move kasan_check_write() and check_object_size() to
		do_strncpy_from_user() to cover with KASAN checks with
		multiple conditions	in strncpy_from_user().

	- [2/3] migrated copy_user_test() to KUnit, where we can also test
		strncpy_from_user() due to [1/4].

		KUnits have been tested on:
		- x86_64 with CONFIG_KASAN_GENERIC. Passed
		- arm64 with CONFIG_KASAN_SW_TAGS. 1 fail. See [1]
		- arm64 with CONFIG_KASAN_HW_TAGS. 1 fail. See [1]
		[1] https://lore.kernel.org/linux-mm/CACzwLxj21h7nCcS2-KA_q7ybe+5pxH0uCDwu64q_9pPsydneWQ@mail.gmail.com/

	- [3/3] delete CONFIG_KASAN_MODULE_TEST and documentation occurrences.

Changes v2 -> v3:
- added in [1/3] Reviewed-by: Andrey Konovalov.
- added a long string in usermem for strncpy_from_user. Suggested by Andrey.
- applied Andrey's patch to modify further kasan.rst.

Changes v1 -> v2:
- moved the sanitization to do_strncpy_from_user and as the separate commit
per Andrey's review.
- deleted corresponding entries of kasan_test_module.o in Makefile
- deleted CONFIG_KASAN_MODULE_TEST at all with the documentation in separate
  commit.
- added Documentation maintainers in CC.

Sabyrzhan Tasbolatov (3):
  kasan: move checks to do_strncpy_from_user
  kasan: migrate copy_user_test to kunit
  kasan: delete CONFIG_KASAN_MODULE_TEST

 Documentation/dev-tools/kasan.rst             |  9 +--
 .../translations/zh_CN/dev-tools/kasan.rst    |  6 +-
 .../translations/zh_TW/dev-tools/kasan.rst    |  6 +-
 lib/Kconfig.kasan                             |  7 --
 lib/strncpy_from_user.c                       |  5 +-
 mm/kasan/Makefile                             |  2 -
 mm/kasan/kasan.h                              |  2 +-
 mm/kasan/kasan_test_c.c                       | 39 +++++++++
 mm/kasan/kasan_test_module.c                  | 81 -------------------
 mm/kasan/report.c                             |  2 +-
 10 files changed, 48 insertions(+), 111 deletions(-)
 delete mode 100644 mm/kasan/kasan_test_module.c

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014025701.3096253-1-snovitoll%40gmail.com.
