Return-Path: <kasan-dev+bncBDAOJ6534YNBBKNVT7DQMGQEU5BBXPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 60371BC9DE0
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 17:54:19 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-634741fccc9sf1434937a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 08:54:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760025259; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rx5U1jCdq0odXpnv4p5/UHg+KDZOLASWZfwpYcVUB2YqWjI645kPPoIdWMuWBokhDB
         VoUlq6oH/aw9Y+tmt1mbZgmvaolPkxlQWsPsx1OpUzrw2J7B2Tg0rgPEWxAG3FdTfMD7
         tffnGxeBVYZeyeUUE8qjFeyTTUcy52SXQ6Imih9tDYN3RdpA+Q5JmpSmhHDa1XMRr39k
         sf2n1Y1jrUc6HesTN0wHPbZK6ojSV9bV4OotZGKZBLNqIIWHh+hgJdZxqUss5lJZiLTW
         /po3EKHn0lkDCaox5Z/tXLj+xnZeSbB1/HswBO8hhuACS8/mvPydg+uVE8Bk5ummTSmT
         nRuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=dV0LsjBxwhU/h2ZIoYta3016O7M6veRLIlpRAuRcSZo=;
        fh=/+u4MEe44hno7xk+AGowhivrVRfEMi4tCevjRgHr6I4=;
        b=RV177IbnS/BTqDAxKq/Ke7LDNKqK12rRRF+tcJA5ajgCf7GPxAfqvGy0+yViXAkA5Z
         mMQefnaL4x409d8NiXv4NSGrIUWllLIqCc0Nu4kXdoBkJrIaZRRAwrPEQwx0snTAXFe7
         iwupyWmnbYCvI7ZvemjWm5iFtkz5v/2sUy4i+W8/Ow9fatAIdDc4m+kAcxO0dpw36fKZ
         umcmCSFf5XY+VMTJGhBKIxqKD2WBnCYxv2POO+fhnU0hqQtjw4b2VEjVY8JpEoKkctTy
         pxiu0kUOlic/FmZzOLwer5gvcemEW70P79yQKIeh1X7h1uazwJo18M6am4ceC3YO/PhD
         lhYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="UX7/5IBa";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760025259; x=1760630059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dV0LsjBxwhU/h2ZIoYta3016O7M6veRLIlpRAuRcSZo=;
        b=M2Dp3WnKc17n9Cl6VkWjf1EDka3Tcpa5ClaJspnv5F4hIBMdyTK5pYp0teSPKcVDGA
         1ksZ1zyFsOxLbtsUcTUrj7DUJvaFph/EIdZv/T8uf/98qdI/KuNa/yuaC5oLLUeV+BkN
         RZXg1NksjVgHEcatydF4A6mpDEdFT5fu/HQTC40flH4czKY20MjRUwDR1xJZ4NVqGQXx
         L+8dzz3BakfwpqB1gcgqz2UXb754CAlARM8q53qAy3aJvKU3bBujBziuYYyPDfh794dL
         Ac45JlNcM6nWus8qOhPaJXU6jmmOfKC7ZYCuiSE3qne2HhEV82yVxQBxK8FE1GIRIjFF
         BpRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760025259; x=1760630059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dV0LsjBxwhU/h2ZIoYta3016O7M6veRLIlpRAuRcSZo=;
        b=O2Dg6CbRZbanQvGcsyrtHPQZ7MpJ6INReDw7wwSzuPSqddnUoSrZda7YI/zin5Ni/q
         k9j2Aj7YF44kHZ8m+wG0XEn5+2tlfahxvnbxBPMal27kdEzA08tmvwiDmNuAJ+1Urrcy
         PwYdtBWCy2sQxdkO9v6GCEnmTdoGeDsE0e0diyTnQubnLyg4/Teyl8oGXtPGsRzcBO+m
         CTBf02/k/S+QGKINrwq8MDWdPHeiCYcoHPVqdkxuIXni1SqazRdbd2YNfjiXERFR8a07
         cJLLzlP7t1ZOwhDO8gbr7LyKfxmX5IU/T3VFlR11QmISI70flkK8vjmuyMok1BMxjZUA
         FBaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760025259; x=1760630059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dV0LsjBxwhU/h2ZIoYta3016O7M6veRLIlpRAuRcSZo=;
        b=dTXTxE59GjEIY0UVvyemcepgcjso0q706+M0mLgvP0AYMorNyds+k6rZ3qijZBU67R
         Dzv+5Tz+csXfIzjMt4bbpG/NFxeCpaanIByON9p3T4FDw4RHG7AsQkKyEI1wPrvvvYyJ
         xA13PO5vI1T9+6bPDOli9a70rghHOfGmt6HOWRt5kDcd8oZiDBOCfvISkuBAXTgdiXz0
         9lvNNUoNOtDaXi0xDVxb8NgcQsU0qo94QGh+WBL6Haz11qWGjjBQbrneEpB1VWdiaXgr
         jGLn8BHX4n+nE9iJmf2fzohEoY5mSYCO1jHw+kYn7M3Y4iIdVwI6PRx1NDELcZsWoBy6
         4CpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVEjN3aYDOHWfPnDDb0RFkW5qUF29hECIzSB6dl5tVZFie0itldjy+FV7EyxLPD77utSm6Dw==@lfdr.de
X-Gm-Message-State: AOJu0YwAuaQ50MiGnjkRuPDHnIuW2pqJHMWudynhD7+KdXQiEip5lNaN
	UTkE/pV3bOHLommcyNF1d2ccMj/P/ph2AQ9qBxsY2Qw2NqHfQsSJUN7q
X-Google-Smtp-Source: AGHT+IFZ/BgMjaX60n/YCFWOVOGa5x0PCbbXgRtUH887YR0OZIcXnnwrKx4HaEiL2AdSxaKs16kFBg==
X-Received: by 2002:a05:6402:440d:b0:639:1ee3:4e83 with SMTP id 4fb4d7f45d1cf-639d5b62b23mr7620193a12.8.1760025258468;
        Thu, 09 Oct 2025 08:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7vS7wObIipiFRPQ+bJiULVdhA+rTrl2hZ+nIGyPD4EWQ=="
Received: by 2002:aa7:d6d1:0:b0:634:c2a7:e3b3 with SMTP id 4fb4d7f45d1cf-639f558f83bls1263907a12.1.-pod-prod-07-eu;
 Thu, 09 Oct 2025 08:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZFltsiE0d3eJkDpL2CegR57qaBL3NfSIAPozFeeN6aZrdN24/lprTHwQ5KhLptEwXIuBjQSdlKK0=@googlegroups.com
X-Received: by 2002:a05:6402:5c8:b0:637:e271:8087 with SMTP id 4fb4d7f45d1cf-639d5c43ebbmr6675264a12.18.1760025255585;
        Thu, 09 Oct 2025 08:54:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760025255; cv=none;
        d=google.com; s=arc-20240605;
        b=Jj0w2X4tWiqrb1CTJryS/yGrJHWnwnhrjd6IOOihwNofdJJNk9QnRBN28riO9uJysa
         99HaoCkghIKaAa667vu/DPwvJI8lRYA7OdhB3bXjc1NBslOJrvODYLMZh62HFayRhGGy
         s/sYltH5MvMsz4/414Qj9kYORh/4yG3K/ogxVbVIB+VWJ1rDZdgmaMC1JEuu6MzZnNq8
         r9aRa04OdGKjM/tnov5Sl1X+xujoVply8iGP4ELDht8cyGh+oYdLCE/O+q+cdcx4AB9G
         +2kt8CwaQ0ESHk024MV5WmTCcU1Iru+eAPRuFkAS8Sm+oU+xrlXocK2ZZtdCLmRhOLbP
         hqiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Px/XhEZW45988TSsx9E9crCKXRf5VJBRglVwYyG7AFY=;
        fh=RkPt8K/gxTsmtLcZwiDof8lAY2m1ul3mn2z0QrpOMRQ=;
        b=e+1CQ4g2oN4bwPcLDa6cCVPWQXAupxf6dglgsqumBoXWhWlXDodPSavR6AMiiCDu7h
         KFCz+kWbpZ25csoeDfkqRdtkCLksPD10VOT1325bceKTxlUNRG0MMqCDeI1qQxtCOduz
         CXX9v3rF6keCaaNbfBk7OzqUYRZ6OKxqdJ9+/1wIlo4qrTLCHGAQY6pHLWgCz5vE71MV
         pbCFG/UqFRdX7zWPUYiFLrPQzMVf0A5hs2WFM537Ii/uuv96AESbHBdoIEABRaHtHOks
         QgfLTMdw4sjeRmm9w7vZeFlxhnLJ36bLn4oMDTA7sg8F+h77f2qoBJFAvCkB8Fu/bzt4
         kErw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="UX7/5IBa";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63a52b67f41si345a12.3.2025.10.09.08.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 08:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-373a1ab2081so9828811fa.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 08:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyCwLqQLdgY28YgtLoqEQI+Lvr9BlK/gC0pvVM++PoXTqcMCA6k2BzRAscPX/kPUM3qcCnea4eA7Y=@googlegroups.com
X-Gm-Gg: ASbGnctI+JIh2FMkAYc2g6x8tSJj3U0eA5+cIEMIfmXyXDm0w9MBlqy4dmvmN7ZlpoS
	91bjRwq6OK6LZsczupTj9RIAJ1lBn5iI7KUdpiEcr5Y9MfZAmEk0CNatxlYRTgmNeLUs81w20FG
	aTU4S79Dsv4uPlc8ftzGEE+pxZxPb5jgo6SkBZzmXNYwsFnEO+wSEent9TIKF90MNR8It1dN42/
	h3HRLmldYgZ3zgZXBW/VKaies1O4VB0VYwEG3sHlG3GggNeDbBlBkBBX16MFKyB4nps76Cd7nW6
	iGPj8wCKCZWAix9vBM8Oixd91JyQ8vRtjyMwZzyWOOgmrPfDrV+JZVCGHL8X6oy6GBCaOy4r2x7
	pnqHvAPVgcLlU9cyxqfQKaPu684BPFcTXkmFscoB1+We6tXqo2Lbqqp1qtjjJgCS0/DZEjJaXtb
	hXqyfbxhHX
X-Received: by 2002:a2e:9a12:0:b0:336:7c7c:5ba5 with SMTP id 38308e7fff4ca-37609e10855mr24041711fa.23.1760025254597;
        Thu, 09 Oct 2025 08:54:14 -0700 (PDT)
Received: from fedora (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.googlemail.com with ESMTPSA id 38308e7fff4ca-375f3bcd2a8sm29499831fa.55.2025.10.09.08.54.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 08:54:13 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	bhe@redhat.com
Cc: christophe.leroy@csgroup.eu,
	ritesh.list@gmail.com,
	snovitoll@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
Date: Thu,  9 Oct 2025 20:54:01 +0500
Message-ID: <20251009155403.1379150-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="UX7/5IBa";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::234
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

This patch series is the continuation of [1] the previous discussion
related to the KASAN internal refactoring.

Here we remove kasan_enabled() checks which are duplicated by higher callers.
These checks deduplication are also related to the separate patch series [2].

[1] https://lore.kernel.org/all/CA+fCnZce3AR+pUesbDkKMtMJ+iR8eDrcjFTbVpAcwjBoZ=gJnQ@mail.gmail.com/
[2] https://lore.kernel.org/all/aNTfPjS2buXMI46D@MiWiFi-R3L-srv/

* Altered functions:

check_page_allocation
	Delete the check because callers have it already in __wrappers in
	include/linux/kasan.h:
		__kasan_kfree_large
		__kasan_mempool_poison_pages
		__kasan_mempool_poison_object

kasan_populate_vmalloc, kasan_release_vmalloc
	Add __wrappers in include/linux/kasan.h.
	They are called externally in mm/vmalloc.c.

__kasan_unpoison_vmalloc, __kasan_poison_vmalloc
	Delete checks because there're already kasan_enabled() checks
	in respective __wrappers in include/linux/kasan.h.

release_free_meta -- Delete the check because the higher caller path
	has it already. See the stack trace:

	__kasan_slab_free -- has the check already
	__kasan_mempool_poison_object -- has the check already
		poison_slab_object
			kasan_save_free_info
				release_free_meta
					kasan_enabled() -- Delete here

* Other mm/kasan/* functions with kasan_enabled()
	where callers are defined in internal mm/kasan/kasan.h:

mm/kasan/generic.c:
	kasan_check_range
		check_region_inline
	kasan_byte_accessible

mm/kasan/shadow.c:
	kasan_poison
	kasan_poison_last_granule

mm/kasan/kasan_test_c.c:
	kasan_suite_init

== Tests:

* ARCH=um defconfig (-e KASAN, selects ARCH_DEFER_KASAN)
	Compiled and run ./linux with no issue

* ARCH=powerpc ppc64le_defconfig (-e KASAN, selects ARCH_DEFER_KASAN)
	Compiled and run qemu-system-ppc64 with no issue

* ARCH=arm64 defconfig (-e KASAN_GENERIC) and KUnit tests:

[    4.065375] # kasan: pass:61 fail:1 skip:14 total:76
[    4.065529] # Totals: pass:61 fail:1 skip:14 total:76
[    4.065682] not ok 1 kasan

1 test is failing:

[    3.772739]     # kasan_strings: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:1700
[    3.772739]     KASAN failure expected in "strscpy(ptr, src + KASAN_GRANULE_SIZE, KASAN_GRANULE_SIZE)", but none occurred

which is also reproducable in the main tree.

Sabyrzhan Tasbolatov (2):
  kasan: remove __kasan_save_free_info wrapper
  kasan: cleanup of kasan_enabled() checks

 include/linux/kasan.h | 20 ++++++++++++++++++--
 mm/kasan/common.c     |  3 ---
 mm/kasan/generic.c    |  5 +----
 mm/kasan/kasan.h      |  7 +------
 mm/kasan/shadow.c     | 20 ++++----------------
 mm/kasan/tags.c       |  2 +-
 6 files changed, 25 insertions(+), 32 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009155403.1379150-1-snovitoll%40gmail.com.
