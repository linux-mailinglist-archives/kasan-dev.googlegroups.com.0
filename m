Return-Path: <kasan-dev+bncBDAOJ6534YNBBIEJV64AMGQEPSV7IDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id E8AD999B972
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 15:01:21 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5c9217064f6sf2653979a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 06:01:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728824481; cv=pass;
        d=google.com; s=arc-20240605;
        b=EhB3sRqKTubeYN4ioNXCP9QGYywFDovWlX43E8rgO+Dh1gmeQI+dhfCj7CsDXt8UL0
         b+/Wpd3QSK5W3PkRjWJVUZ5qqaldjJF0REhkfdlaEVtA6w4xpQX0wuD7Fbb1ZuxpjC5P
         Z7B25yYOR6EKd3z9wFOq93gffiqMdODFnt0himp4ekLLvxee7JpbedtinCBddTbQ+WXB
         KFlgmzsy63YuKKU9ozHAWpp5tiz0iApGM/q/3xx/wmSfRxNJEZ9lUzQbxsOpvC7oGF+e
         9vZ4+vOZUBV+aJOYwXJcsbeIi/RgBEH2LxKT1pgudL0/uysnYjUf9PC84CVm2au9SUsS
         Qj1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=aWkmPYzxW/kGCD3JYat3HrKhpsqubP93aMjWDYbLLPE=;
        fh=xHf2tmHB4L8sZQhnk33VXbi8dOL3Fv8mBfzoSMXL8Cg=;
        b=Gj58/hagyeT2vByq3u31CEoZbdO7SdZOgHlY1cGAgFZzNjLOFufbU+Iy+G5mnbLU7b
         beQB5O5aDL0znTo4bFD1Z2+HiZ4UZVEvcQx0AH9RZecFOUimHEuc0r0xjIM4HYnggHKv
         S7c/lnrZbLTbpWT7802fpuYERpA5vrcy0PxN9dgDnD95rGGALuPm4IM3uWuf9FYndyP9
         cDuWIGsTfp3sLDT6XgYiKfEx5Msi+CL8T/J+vBQRB/uXHqK+Eixtddg2gdZcJ6FeygH1
         rmPn/RODTPEBLrH0ciLnqzHI37FbeU8s5m9i72pCFPYMzQUCTt9j6DUzWgApSYHnwWfo
         92gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bWTYvdFI;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728824481; x=1729429281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aWkmPYzxW/kGCD3JYat3HrKhpsqubP93aMjWDYbLLPE=;
        b=tcUTehAvtdG7e8T2hRdZLkbSHWrg8CBSbuelTJ4pQgVlNEFbhtO8esb08ok01qpkE1
         Xypf7CQ8MQ+b7PydeHOHFjYJXszeTNWKtBgQgoUx1tu7bbByl955xWr0ZDylqNhi+fX6
         2thVFVPa41If7YA+wiqIBZTvrVXCwufUKLwO8nJ6WAfpXCkvMLsWmmMDt/TncTJlOp49
         Yhw5PSdbxYmGTng4W87iSi4IBO0lwKpn+jwrbQHpT6f3NFWdr2+TwYiQajIMqzfl0paY
         Rj2M7Se0dUsBhQ5xFIDYVyq9vGx+SyxEpXkenqWyiidLmxLMKvlu3I1a8TU286RerJ5U
         9d3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728824481; x=1729429281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=aWkmPYzxW/kGCD3JYat3HrKhpsqubP93aMjWDYbLLPE=;
        b=U5XdYwQQsyeb4wM3Z81eshRlOwHbAw1fB690SjvV3/ORvcs53bP7JC2EZRBv/hp45w
         Zwf+Do956ht0cbhQ5ep4KjhaYR3XdOmWDLncqAtSiQMbcpWkc/nb6eorRD8IqcX91JQI
         5MpOB1HGmiHycOIdD5zCIRvNXigA+82oFSHQxnxzZW1JF9mKMmp6k0LV8OQTiqXyu8oc
         61Gn5B6bJnnhMfZ0g6cij+xTxSI/VCgJRgvckS9Q4gcJrEIb4yeruc3bzkbdzt8RLY/p
         IueKkA+Me2IbmDdnRjXEZAsKoqD2gcT0CxQkLzgoRcGKOk4KZswenvHAX8FaS22JLqbB
         RKvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728824481; x=1729429281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aWkmPYzxW/kGCD3JYat3HrKhpsqubP93aMjWDYbLLPE=;
        b=Zy+5IrIl4wAIgtQ2mT9AzGQUEONa1zFqlOc5RZx3a/H2oBPI/jTy9BUHdezwHM0cM5
         B4Fe0zYR8HGZS+3SyViECiTpbsn2GZm93B5ePnbKAZLIj3swa79iaS7l8Z3Bcm+KPrmA
         GoHXIeePrQfl+niYACZ6OWP2cAl/QhksNunR1XdGkmtln+2Otr3tcOIoZRXTSnzfUBTq
         as+DKa2E6VPy6nMeFg0jutuVfv5+u8ekr89tjr3zl5SoBtIGkRLxScYXuuZFjULhKvVZ
         kAMjvna0vBzMA1sSNwJSFzlWYbyOSLG+ZhzZWw8roWz21l+2Q+NRSHhJgv5+APLudsDH
         +7YQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRZG9jhD3HYDwYNNSPFiwByQbwwSR/FOB26hxUGLiCIV7Ua2Ed581OlvGEI258YEhePfWA4Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz7E1UrKnVfgKyjT7dmjbSsF1qWWBdFIJuIga+HqL9EYPVYYZ/w
	bN864vn4WT8f3e5OGAmUX0QL2lEmyEMvQfv9NivfgTfGyyMV2oIV
X-Google-Smtp-Source: AGHT+IH8yWj6ZjEeDBAWWmOjHOBGh5mwq8GyNDwwQQHAM7tNlNekBSKyGFn5TVVkQjupRvyIfXhrPQ==
X-Received: by 2002:a05:6402:908:b0:5c9:6242:d552 with SMTP id 4fb4d7f45d1cf-5c96242d667mr2032213a12.15.1728824480396;
        Sun, 13 Oct 2024 06:01:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35cd:b0:5c8:acf3:129a with SMTP id
 4fb4d7f45d1cf-5c933b4a194ls1231842a12.1.-pod-prod-08-eu; Sun, 13 Oct 2024
 06:01:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCxX7e/uFneNFCIoLiDjalMRvGpTaPfovUnCKKINyhLiXo7oVl29+M9yx27jWFgmDwpD78cim7MvI=@googlegroups.com
X-Received: by 2002:a17:907:3e10:b0:a9a:8a4:e079 with SMTP id a640c23a62f3a-a9a08a4e0f4mr126386266b.31.1728824478228;
        Sun, 13 Oct 2024 06:01:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728824478; cv=none;
        d=google.com; s=arc-20240605;
        b=UbhM9VknjYn8pbd8bLrHu89EFbrWCGd19eJxF+tl3NYT3uCIkJCEgnhhuEyNQ9uVPT
         s86UQrHRuU3L9HYLIfJ+drzNIo3BswoE+lNBz7DQimVJrhC084AGg864BCpZCMj1rgNs
         iQ9j5eTA2BROdBLwmYlW3aFPU/DtGt57X/NrLMJTlMs9i4yQJqNqFh5OHz33S7LfvEP/
         UcZN+d7M8ZzoRmOcA4AuFmkG0eFAr4kpCA2uoz0WqRXosd4MdR3Qs8zYtLu+TSthbWuj
         PDBtBqLrhi9wZkSh5u/admn0PodKnWyTLsT9wDuQTXrt0xpIDQiWxzEja6HrMDOpB2F4
         2RsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PnmJ9PN1MwOJi0VN46gDmOuqLJjC2HT4OQkYN0N47z8=;
        fh=urYFHuZC+hnXMU4VeS21e5mSBjIyZLq61QAoJqMyr8w=;
        b=T2hLnucxq7OH56jASwp0zLhjzGpCHEFMNVPsf9RySyT0qCvXsxvuVamF7yq6aVYNOK
         Y7/1In3QF156tZxv5qr4JqpDZ7biOZoh2N4Af89EEk0ZFj6ZmhHtqsM1LZ9Kd5dtlIHd
         4Y4jDCemSoOGPFh8ohXkXN/Pmg2n3wSon9cLKM8o93QoZImyIt9l4GRcrFkFrLUeGuLv
         vnk5LRP5O80yeNnVbFEpqjfZWt+B/VhkLIpEbaxAWulNLdaSEdvPTRS+HsMiLD3/eFGt
         ljPqzDDhoX3Gn0qGub/V6lgzl9ELv8k/y4JdFwx5QFlxBF2rGi5tQr9nTFajll5q74VL
         Hwlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bWTYvdFI;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a99f1a268f4si4375866b.2.2024.10.13.06.01.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 06:01:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-5c96b2a10e1so1215436a12.2
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 06:01:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSZkvEA7IMf89cJoYV2pXWh8hTozbqZzARQzUgtO917/hPpD81GzwPhG325zSpsmU5OF9QDIqW5bs=@googlegroups.com
X-Received: by 2002:a17:907:1c08:b0:a9a:b4e:b9eb with SMTP id a640c23a62f3a-a9a0b4ecbbamr74879866b.46.1728824477537;
        Sun, 13 Oct 2024 06:01:17 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a9a0d9de967sm19209666b.139.2024.10.13.06.01.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 06:01:16 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	corbet@lwn.net,
	alexs@kernel.org,
	siyanteng@loongson.cn,
	2023002089@link.tyut.edu.cn,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Subject: [PATCH v2 0/3] kasan: migrate the last module test to kunit
Date: Sun, 13 Oct 2024 18:02:08 +0500
Message-Id: <20241013130211.3067196-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bWTYvdFI;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::531
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241013130211.3067196-1-snovitoll%40gmail.com.
