Return-Path: <kasan-dev+bncBAABB3FUSKWAMGQEH2O6BNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3379D81BF4F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:02 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50e40d1a6fbsf1141201e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189101; cv=pass;
        d=google.com; s=arc-20160816;
        b=qigkJtDtoBCHB/beNEKixlIj96GWNaxixG/tFn9xktac8WCs3TOZcbTFg/MxKdj7so
         XtQV4usykAjgky5f+j6jc57Oe2bDYjbsALrA4C/US9kvADghZsYvpvLzXw9ZS7BXNJ5c
         p4ON4186gS0FMg9vxAVt6wkkvx72HuG1Qui0xjgXZppRlYO2w1gcm0uylYVqrDfIBeuh
         QUD/PgHeVK5vuQkqPHFXfwgf7jQy1yVL9bmqFkkQQBQJhBrg2aXIQqaMYIvYQOWSLXbn
         0aN9Ym1zb2s+QLCus5GYrHXo5hRZO5x7EJGAHbG6tUYP097e6BQI5EvYKpqTqa6tUAsY
         S7fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pCT8mEJcnBU14siVryDUfXYGgZCtBDe/9LNMjHpYgfk=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=NdRY8rltY6nJLWhXd0oiHWsBEogzydiA1/4jRYPfOd0J/NklAxa/kPfV4SFkv3g6od
         W40iADjBYZjgvV0JbV+PLHa31OuYb2Tv1BmeblShiadXWwoYjyF5LFlttQps3pgFbU31
         KpL2gRM8D+J8unXzJZseG/7VXlq2LjH0FyIY7Nvzjzt4zobj1JhjcbzSI2+QPduEVOYi
         SzphkgsD86wFU+WsIWuNDXk16Yp3tWt7s9xFVMIMtYWGEc77CP4UAMMN8UnR6t25rCqS
         BwsSQJ9ycXBCeMqtkPLXtUk0k6+uFjL/QF6C2wKtVZp3Kn3II5QunrDCPLNGEgqM1zYq
         8Kkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=skZG0MAM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189101; x=1703793901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pCT8mEJcnBU14siVryDUfXYGgZCtBDe/9LNMjHpYgfk=;
        b=a6Ya38vVYAnBpXIE4MR+2AjiuLDHAZBlhMWGQHoJbZc7LBKn6wO5OcSaUkQCd55tzO
         tRBH9AWRKSJlUx6yxS19wN/amRh2ua8e0yURGTTHzDcYDuiVfbaFcdgPMxDMFkNdhns1
         O5CAMjwdV8UUoOR/a/bgP2cwIT/BDUPxoGayu5WWiEp1Qoqa6LcANxj3VwCzhDBAEDxR
         0rxa8tmvt8nwhOKiKETfLBL6YYERLw2tPuvkNGBwozzmx8YJD5OzjyEpCT3uTvTHuQiY
         93GVXJZABaoA/APMjG+emTZMquFslH5zv8hppNJcJrx5uk6opzJ1Kzm8RZtanxZsushw
         /yLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189101; x=1703793901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pCT8mEJcnBU14siVryDUfXYGgZCtBDe/9LNMjHpYgfk=;
        b=cY6kmqE1FYwTEEjzSMgiLIzRgXLrsvgu6h7qr8XFl3TRQwr7lsHtKAbgW7u36Mh6Jc
         baRAfXCl+cUwdhhiu1brS8lIAmBHPD8FHG6F2W0SBYEkiAto9fbdNkwrahf1OGr5ScXP
         RH0v2p/OVA56i6NcFo70aAbtsGXUP6NCKb6CF55CD5aBul//4YBopyzToMNjReswTNhq
         oVlcVBjUDhsKSysUMS7u8NkYtQE1Qk0shmxFHMarLXqVHq+m+hpFg0SSpfEPdR0+b1nB
         sF0RrtS4LZb6Lk8QZ2mw7DGY+IIi+Uadsu2cYK4Lk9LwY9rJeCBDm9hRe9ZcesxPrD1n
         jKUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUvMx19vc2b6DWO553uXsqjY9YM2b1rVzO+/oy4O0fb0o7pLIM
	o+Ak9ckvxnSqBZnb9Ug+yBE=
X-Google-Smtp-Source: AGHT+IGhZxUMEk/QuBoLCT/KOIqMSnQacBHKn8dMLmuGE/YGHU4hugnzUBSCHcOATvAl86cP3/+yMw==
X-Received: by 2002:ac2:5fe8:0:b0:50e:2551:c8ce with SMTP id s8-20020ac25fe8000000b0050e2551c8cemr75303lfg.119.1703189101160;
        Thu, 21 Dec 2023 12:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea5:b0:50e:31fa:def with SMTP id
 bi37-20020a0565120ea500b0050e31fa0defls683795lfb.1.-pod-prod-09-eu; Thu, 21
 Dec 2023 12:05:00 -0800 (PST)
X-Received: by 2002:ac2:5b9e:0:b0:50e:239d:ec0a with SMTP id o30-20020ac25b9e000000b0050e239dec0amr93314lfn.96.1703189099621;
        Thu, 21 Dec 2023 12:04:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189099; cv=none;
        d=google.com; s=arc-20160816;
        b=e3u2eOt4AvrLpOmhC+wtobyLC87Hmng9+se/HfeYkKYUyHXYOvQgVqg+jRqnYh3qwk
         A+NJ/Z9ANqSezr3cGesN/tWaG8gRVfu5PxoxgB+BT5fsUgIkh4SvxhmkfL8lY3/tPUgp
         fP1UZ4jaTf+0WgyWcSAjlHetAWg9Rx0O8aWo3mGmDrP+CzSwMMVxyT71RY54eDJA0Can
         s4jh+gZGgWf5I+5njDHgtDrvJNkw2Nledjs3L0xejBP5Lw8FsnxdPrvHAnojVOP4YtL4
         CAq+BADEJg/jh2ch4HCxkCZmQfmT7QdWXtkWwkejUCA/cp+jprlgSuzu387p4Xfsni54
         /u3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=sNjSVQSFVUV8ISkHCvyHjupyoa/1urB/LVlJZWSj/S8=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=Txh4yw9K/GZfoxxKaOZds65BYKp+QUkyTbZsks48iPCad0UfGvdxyLbB+r1gTNPv+P
         tFeoi0Sk++1M3J1kKFpHxRvujdqrjrJ2B/JO4QIDe7pKDW+K2sFugQ6PIdMkVczjZBTj
         wyHhtm2HQ3FF8ocDDvdKjmy0BqsyLEdkSav+LCTSODbSiDh+DEFLPW+PXzN1TBqYhZ0f
         k4oBVXxQF3EBUoae43mluwQjad9I3vjqb/o5izZZVXt4SIpMB/ScDUpZ7MFkRthhJTI0
         ggLZS+D3JIoFNmC0b7R9OaBcZ3F1TfdLRkc9+f9/tzqE8nb0qjtlgaoNM64H47vMr84R
         Vy7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=skZG0MAM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [2001:41d0:203:375::ab])
        by gmr-mx.google.com with ESMTPS id c28-20020a056512239c00b0050e5ccfca9esi82873lfv.10.2023.12.21.12.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:04:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) client-ip=2001:41d0:203:375::ab;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 00/11] kasan: assorted clean-ups
Date: Thu, 21 Dec 2023 21:04:42 +0100
Message-Id: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=skZG0MAM;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Code clean-ups, nothing worthy of being backported to stable.

This series goes on top of the "kasan: save mempool stack traces" one.

Andrey Konovalov (11):
  kasan/arm64: improve comments for KASAN_SHADOW_START/END
  mm, kasan: use KASAN_TAG_KERNEL instead of 0xff
  kasan: improve kasan_non_canonical_hook
  kasan: clean up kasan_requires_meta
  kasan: update kasan_poison documentation comment
  kasan: clean up is_kfence_address checks
  kasan: respect CONFIG_KASAN_VMALLOC for kasan_flag_vmalloc
  kasan: check kasan_vmalloc_enabled in vmalloc tests
  kasan: export kasan_poison as GPL
  kasan: remove SLUB checks for page_alloc fallbacks in tests
  kasan: speed up match_all_mem_tag test for SW_TAGS

 arch/arm64/include/asm/kasan.h  | 22 +--------------
 arch/arm64/include/asm/memory.h | 38 +++++++++++++++++++++-----
 arch/arm64/mm/kasan_init.c      |  5 ++++
 include/linux/kasan.h           |  1 +
 include/linux/mm.h              |  4 +--
 mm/kasan/common.c               | 26 +++++++++++-------
 mm/kasan/hw_tags.c              |  8 ++++++
 mm/kasan/kasan.h                | 48 ++++++++++++++++-----------------
 mm/kasan/kasan_test.c           | 45 ++++++++++++++-----------------
 mm/kasan/report.c               | 34 +++++++++++++----------
 mm/kasan/shadow.c               | 14 +---------
 mm/page_alloc.c                 |  2 +-
 12 files changed, 131 insertions(+), 116 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1703188911.git.andreyknvl%40google.com.
