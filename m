Return-Path: <kasan-dev+bncBDAOJ6534YNBBW7ZX24AMGQEYE6YXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EF5B9A0B2E
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 15:17:17 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539e4cd976dsf3488248e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 06:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729084637; cv=pass;
        d=google.com; s=arc-20240605;
        b=XJh3SSNf0ZhdQv6Z03sBftiPOdCbex6eVQpczP9sJPovPd6Bu1kmlfI9wmbkvO5vSx
         f4Vem4DxgfdVdkXBc4/HTzT/ctESNkrY5UWAH54J5w3dSaWfj9B2vmXfc4y2DZA97B8n
         oK0rwnN34Q/ezpUdS0QhYZD5dfEDbd/ysz5QdezT0fnOstbOdVHcrHRdXnuuTISd4TdG
         8sUBNFMANxFUFClZhCtFlvDOCsb9NOGei02C2TgPeMi7Uc2qRnxp4xAQ6F3vv8MM3y06
         0k0XemP2lKaP5QR03WviOghfxev0i8DYX1Wh8yU/oOyttGQMaZyZEDl7bwbXGmguIsw0
         TXew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6fFSpe6WfSZOeKsuhW19/Eey3co3tYEponHGHXL09xE=;
        fh=KlvQd4jNe5TAxoYoSPUMvvnA6xLfgxH5hvXLO3KgIxY=;
        b=NWN0vdkUUowsAJ9X4XxOAyv1epoDTjr0+vLP71Iaw0nsML8FLTUyBQ/0/VfGEuvy2j
         TUaGXVW1lo7wFj3aJAXoTpU8iVe/g35PKz0dQP5P1lZAUa347kGRJH82qoFfeaOYWYJ6
         xGfPIgkjAQk78txH+xx+es7H97nqC5TeuHg4P2sYlxbvAOnLfu04ixLRYFcNIF9dIKEc
         qSNYCgfa2T2XprE3LLB9wBuN6ZpgvPzN8f+Qq7vgRk6JH9VFksmN9vMS+Yf2GeNtyu8G
         lEqnWDD1iF6EDeuk2ADleWDBp15PZLdMN9y7b/px7D+MeRcgBiv+HX1n/E8mlwAExMHW
         NWHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YZtbtpnL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729084637; x=1729689437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6fFSpe6WfSZOeKsuhW19/Eey3co3tYEponHGHXL09xE=;
        b=iumCWd5t5jDLI0aLhI/Ns9IvlbICLW+CNEhDI6pLTLjNSCo/66q2tREd5EPtIuZci/
         3xHrZ1JMxX9njf14CmuCIV+1QUveLW5/sgedGSG6X+77eqAUaBA5/zih27RXi8+ysr/4
         WDWNuA/LnjzUmnIPbLHH0DvuoYtfDiA3ttoJeOqmMNnl3H6psj98kR5eljTXBntllMHL
         Iv+/5Qr0mzqeLYIjw2EXvvMmbPiKxb7lDhMdaWoZvPaOLpR5bM5CeD+ORvH3Fhxl9YLy
         Gq0GVN84FPN1zxHA0cnUiPpc/TyxiNEvClWa1ylZebNlk4AHL4fAP0DOONp6zizkghS/
         3Rag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729084637; x=1729689437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6fFSpe6WfSZOeKsuhW19/Eey3co3tYEponHGHXL09xE=;
        b=AS8KJiMxk8F7n1/nmy3ZMYG6k71miDHbkHSjFAOqifEud0k/cIlJxHHgAkfR1IS1sC
         90jCuNpzQEKkdD2v6UdI0KMjeVjZOFf4lzs69f0TKJJmW0wMP0BQLq3AsoaJPoSpxL71
         rnBV1M/UaOG3bChxYyiAHiTMSJonPoVYe/r8XqDZNp/U0HDN9NtQTWRjrbX0P7zcKIrF
         ns7Anznb+Xql5CZWfuVVvvKv+3EU/6JTVGPlwiDKeEuoiOJ1Mh7aLhlpC+S5lD/pvZhx
         jfsxnJ0AtaYokJpf5Scf/0b3thlIwZG9spUbq0mB5A6MH64n1ttbkiQRXUiZSUSCOat2
         DSDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729084637; x=1729689437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6fFSpe6WfSZOeKsuhW19/Eey3co3tYEponHGHXL09xE=;
        b=ps84CbnpXbztnp3c2/DL/GniSK/jJD7Hlvr+cVCvWqHhT2cFeGGBa8kI11oktCAnJ9
         WaF9vR1tH3GYu51tpjbge4fNpihMVHUNEiklNExa+uzOslEiN/Vzr9A/MTBDLyg8fBOG
         ROCHlInXxvVZ42TKjasILiD/dAKnynNylwTBzk2p0xfy655205Cy6BcnAXDINvLQHeye
         ji6OCKZjQ8MOSMSciR7gxtj1E9R3TKZ60dN0EX+oncsaPGtLLeX7hcp3XMmFYnFI+al8
         EPgnI6SmgOvsbcGbRta08Kx+OC3SPlg7c4LVzy2UR+HsQMRbn659rK9crMEi/miwNOjG
         NRog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYn8KTPtZFGoyorZpGV5Ozbi3gxpnm9lBTS0E8Jo0iF8ZJEy1B/CY84TBvVnNn5qv3vVvx6Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz3ImwQcMFLkZuY1Zh/bneqUm352OOAwufyxkxp1sxDaydqLwXm
	0KRjhckGfodF5BMDxIUdcu+IOzVYJ2ePrSnuRWndJKYQW11ENS14
X-Google-Smtp-Source: AGHT+IGocgJOBplvfpw3NgVcVbIBhEvS3A+YKAnTv3ZMaRTlU7N65dCoZDW6aWEzftMOBpeHcqpkdg==
X-Received: by 2002:a05:6512:3ca2:b0:539:e58a:9704 with SMTP id 2adb3069b0e04-539e58a9811mr7084091e87.33.1729084636013;
        Wed, 16 Oct 2024 06:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d17:b0:539:fa48:9a2b with SMTP id
 2adb3069b0e04-539fa489b8als240501e87.1.-pod-prod-01-eu; Wed, 16 Oct 2024
 06:17:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3TXbCRWltkgl/HrQ/hiKRY7dH2oSihBCWXwVPN0wTDWrqbHxm3X0UDfTPycyoONFtixGXW3N8jsQ=@googlegroups.com
X-Received: by 2002:a05:6512:2314:b0:539:f13c:e5d1 with SMTP id 2adb3069b0e04-539f13ce85fmr6453372e87.38.1729084634020;
        Wed, 16 Oct 2024 06:17:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729084634; cv=none;
        d=google.com; s=arc-20240605;
        b=B1Rid2CumEt4uRuWScCVfqqK6gvAuUeHnJtWJWWaDQyxQhqgLAnvnbdncOtMKt/TCg
         3CH4eEvERCYfjbQHcGJ+jQU+vM08AyFfq6OsC37IfnqX+N7WUFG4Dgr/pSSHhb0ZIRZb
         QCV0pkYPl1LM53PrMhVsIy8sIi8A73/WSSGTZKT2uUCdLs9WSv+FMdrZxdpxsNHfu5xo
         IsDJysRdZgPA+3SWnmyEcbb1OOol3wFlI0NSd7XlhQvil0fQU5JET0+SeITGNepXuEYK
         /jmMC8Uf+kIpv9QyuI6Qs8P7gL3IKP6gtApijk76rHnN3I1Sj2BXTRTodj6wA0TBHjQh
         YQ8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=odeLQxQfk7QzT/fVHpJdy7CnXL/SLaCfPU2fty6lRDo=;
        fh=iB/D+RqpKECIVhzWx9PInPYUzHZc+2GG8niyjRkHloI=;
        b=kyJPchKN+A9uwAXOw5udFICjb7SqAORkftO+duaG/DvGsUkoJ7EGj36RqF/BXcMkVS
         Hau6r4Z/wb26P15sCZnzOIFe72Qsy3TQw1iRBI1oJD5m6//ac7kFVIIDMNTdG1RDKEyc
         jo7nDZijWcnOwDwsPIoCKHp+tUiDbZKAPB2P/pjMvPNkt3i9A/wGlASWPuVbHRxeXsut
         xO96zU4GgliUATiTyB+cc49STzqqI69n5laTVOoUVvkLqXCXvtYPY8YzNfg5czOyuJc3
         +9XiNVfLi/xEGrdkRx1Rf2atCBA9whU8TVqsLd5HohEk9VyjEvKdYHnnweY/dtwCCuFJ
         HiKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YZtbtpnL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53a0003c4bcsi61393e87.8.2024.10.16.06.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 06:17:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-539eb97f26aso4422010e87.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 06:17:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW6rTg/nhbYBRmF94Ps8v/EuNjeKeverxmv5WDSySCg5uWHpDdlRdiNLh55XaQ1tvA8HvdRzQtK6JU=@googlegroups.com
X-Received: by 2002:a05:6512:1090:b0:539:e651:5d97 with SMTP id 2adb3069b0e04-539e6515f25mr7976274e87.50.1729084633262;
        Wed, 16 Oct 2024 06:17:13 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4313f5698aesm49612825e9.11.2024.10.16.06.17.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 06:17:12 -0700 (PDT)
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
Subject: [PATCH v4 0/3] kasan: migrate the last module test to kunit
Date: Wed, 16 Oct 2024 18:17:59 +0500
Message-Id: <20241016131802.3115788-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZf8YRH=gkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ@mail.gmail.com>
References: <CA+fCnZf8YRH=gkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YZtbtpnL;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c
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

Changes v3 -> v4:
- moved checks from do_strncpy_from_user to strncpy_from_user
  due to "call to __check_object_size() with UACCESS enabled" warning,
  during the kernel build.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016131802.3115788-1-snovitoll%40gmail.com.
