Return-Path: <kasan-dev+bncBDAOJ6534YNBBE6BSS4QMGQENOXRJQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D36D9B97C8
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 19:40:21 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-539e3cd6b66sf1579289e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 11:40:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730486421; cv=pass;
        d=google.com; s=arc-20240605;
        b=FhhXQN552q5Up4T59Kj80bnv8QJVcwVWnieVdFLsgLo+Znjrl+5qc9RzvewlxvAk7X
         Qc6nlxLYSQyimh7bobWdWifFBaC5gRZfgq6/tZ6DHTom4gSvIZPfBJcxY5G9ZDAY/HiS
         FGuCSh5LE4sga/AYGdVmm79CZTjqbDixaDSLHtTPqQQF+U8bLWHVmxe1O4qcoJgGxR0e
         LFdj8ZV6JubgTIKlYT3R7bGLw55N/ObB/FO3gtK0CFFBWlsP2LScYNTFZN8p7ESEDIRJ
         PQwfCZjHqkMZRBQT2P+s9GhqvKRUXLmJgt3ir/0aeA/js0s/wkKfFz5Mj15qyugDw5cX
         epiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=S1RLkgLmX0x+YQqDZfKTuuIMaj9h7Z8Xg1+EF74GryQ=;
        fh=qNCAsh1CU9KRvmviZLl1mJsJSFL85du2DNAyoA8mrYc=;
        b=ILzMNdl6/z1dGAv6JfiYQVw1bOqwxUrUXTxygevA5ODoshdbNzLPJeSxPTfv5lBY18
         cBVwIMm6qZ5bfs3IXZGzc+Aj4XM/K3KuUB7uytL9vmO5YXjYh2/sFXWmYcs/Rc82BZFr
         PRta5d7M2VS1Uei+ulespXr3AGHtdq77+uDcg+pYbeBdRiuJOnH3Vrb+BnGokmPjTVMw
         EqL/Dhb+EX5oWedA2dfhae6xUCNLFV1ItLLFPhTRLt4WvLCzzGyoQ0YPYd4OBf4JkF2s
         VEd7dRR9v8hH8UCNlogHOEXpvmnVJMnfTyNyxshcmHQOuxWLU3WtkrjilT3azwGETgQq
         lYpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IsFRWBgL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730486420; x=1731091220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S1RLkgLmX0x+YQqDZfKTuuIMaj9h7Z8Xg1+EF74GryQ=;
        b=E6zIyz6UNqggMicDpu4/qNyZ4xQLyYScynn37tN9hxX8icWxDPy0uwXqO58Swqj+TB
         mUJm2pa79pod1/2afhySWNdz+Zig6MyPipbp+H+kOWpcE5t49eerLXdNKAq74a40s+Ip
         aNNxvbLLP0vu0SFs3F9pUAQY5s8Jc7UwwhMkkVu/+LIUV2CLc2/8Srqjg14+I7qyo2qv
         Qn2MQA5HRi1D7Y68DWkted/VsELSKsKQEEbf4PYbHosmqQd4FsTQpzIy2CvTdXmZCSKq
         fMvGRtJRf2M3gZQ4oPUjdNe8UDWOAGtt95vQwAW4LkQ1mCiHdZduTA3slQFVYz9osnQc
         nWLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730486421; x=1731091221; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S1RLkgLmX0x+YQqDZfKTuuIMaj9h7Z8Xg1+EF74GryQ=;
        b=RB+5TO4sjH0wIBdUS9FB8hWGJpNbg7YLwbDOu2R8AlQCYC8bLn9LOdQXTre9a/iFNB
         PLkBS9ASHobqRoG/qIFwHOHPRk95XCBOgdEJVe7KvU/uk8oRaSj7BQhJJGtePwbZOR0N
         qfk5RwejxpnpkT2kk5D7dR1BapDXBPdEGC3wLXuoGbHa030kF8OGypnvrUIQRaFxiwAh
         LsL1vz/nmuHTuHq12lD6gsm0Ipi7UUKHUEQG4Ly6e118Q4MHv2eHMMXkOD20lcYZwyp5
         6raLQFQL6dyzUTbOe4khcZ8MASfZT4MAg0v1oJZr9Kul+uz0e83A1jDYod3wNATp7J/i
         LsqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730486421; x=1731091221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S1RLkgLmX0x+YQqDZfKTuuIMaj9h7Z8Xg1+EF74GryQ=;
        b=pdSNSQATaR4guBdn31ay7Zx80fg56UzL0bFOkrZfMKAifqXuBVJZMXC59y2YGTmeHs
         7yihau6tU8CZTjSf8F+FwzBTRYHDPGLoQwFsUBHmJLTU1uNDVzpl8W7eURiT2NokPAb+
         7Zip/8oUE/Xicz1ypQdfM422A4TnYZ8OfUEgDv9aH84NltbdcY3Ftq4eMjGngqO1uQsj
         2t49fLAi5TVltOp4wQlOwLUSJ6ksGAwV56J+eBJF5rlq/72l0mI20gMpPhspK6B5HSid
         RSQ4OD5NC+XHqruaYK3E8dz4YVC+FMqZ0zwU261C7ePoMDx+SITTLTyFb0AQ5LaDIURB
         Ok0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqxcOKBLKkZHoRAnDWiKObJ2oaLG3FuZbh98cqAZWmPYUSCGU8QW0VEGldwxth76n9hT4i1g==@lfdr.de
X-Gm-Message-State: AOJu0Yw8qR8bQLxMuSzgW0XYUJEnAL7gM2CnhUycjkRuQ6Fc1IwSjtV/
	J6bygiM1PdEoIU77CZK/+nxibZaZSWWmAlQmf0iTU/UNwDu7KHt6
X-Google-Smtp-Source: AGHT+IH2fLxDxPIpkmof7WXYbh+Yuc8AuQtyiAd5NwnB8LWVC20y+bPIjimaqpgmsBtagLUGIRyB4g==
X-Received: by 2002:ac2:5b0d:0:b0:539:f775:c0bc with SMTP id 2adb3069b0e04-53c7bc1d3dbmr2009666e87.29.1730486419810;
        Fri, 01 Nov 2024 11:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b01:b0:53c:75e8:a5f4 with SMTP id
 2adb3069b0e04-53c7950fc52ls588318e87.2.-pod-prod-00-eu; Fri, 01 Nov 2024
 11:40:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5fJKxGj0Ay3zMKEI+JPM+tglU1LMLNRYowL+zwghZKy/HpDuMP//qxG3OND+0BpA16fmvX0tliNs=@googlegroups.com
X-Received: by 2002:a05:6512:3d2a:b0:539:fa32:6c84 with SMTP id 2adb3069b0e04-53d65da442dmr1453993e87.18.1730486417633;
        Fri, 01 Nov 2024 11:40:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730486417; cv=none;
        d=google.com; s=arc-20240605;
        b=Rph8jpkbsR+/r1a4sHcfcJAoM2olC+vUuOZuLahy7WbstaxSl8NGZpKMvvMo+5KS+U
         4QxcyhCaBln1yKa0vLaY39Va5CktTy42R2y4/XX2/iWBUa/rCTMC+xT+YsTYLuxl17hk
         298DMxMCM21MM/8irsTrraSoa+Wz5lkLhtYIkNgH3ptsvfZ6vPntVPUK44QO2UgaWqLx
         lN1QfSDcS9M+kJQQ/6o+DidCOAmXNFu4PGpqNjnSM+yYJDv+m8qQ34Xi5/o7UFWztRsG
         V2DhmR9HwEoe7lBGJIGlDWhLQIRyL/pEJkOuaU6qiuW6XhZR5p8wLQaIu2tVFjugjoal
         4z/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EWC1yOTC5QFlqMhqCf1j0kyrByhgWgxna16p0UGDJ/I=;
        fh=odwlSOkg+tz13r5NAtoUhgxYKbBUzZHXbEeu4cZ0GWs=;
        b=hlLfrkHiC1bMY8YHtncSLSFu7V4QzDIzGO8ya4BkqRgBdT0skcpnVzxT44fGvYUl0V
         MhvZm74mdoHAzNDA1jxDoNzKDzn1w3ylk2F9ulAlNs7rPhxG6p82SeFPGY44CN6Fyl2q
         XBLtNAogA7XNuU8yNDg12IKT0AFG1MbFWELaopP/HbspaAqkgveKTShTQKMQZ+gw4lA+
         RD6LZPuKtRcgjaNIR6UFx39Ne7mvEDI1oMBU885F33sTWMUHdSMY8PmOSRj/f5stQ+rT
         cRDVGuiR4tbGwLC32IYPDhhQwWbHYeGxE/tPMw0yYlxKU+z3no8sG678vIsx/pSY41Hb
         aP7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IsFRWBgL;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fdef8aab2asi918401fa.5.2024.11.01.11.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 11:40:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-539f53973fdso2100554e87.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 11:40:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaIGCcxuyfJ2RfPpModRP6lAxytGety5uQ8fA08elpk+uJIJquku8wuLbL5lNSbL1ACqIbHS2dRi4=@googlegroups.com
X-Received: by 2002:a05:6512:23a7:b0:52f:1b08:d2d8 with SMTP id 2adb3069b0e04-53c7bbdcaa9mr3079453e87.7.1730486416985;
        Fri, 01 Nov 2024 11:40:16 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-53c7bc957cbsm646821e87.60.2024.11.01.11.40.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 11:40:16 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	elver@google.com
Cc: arnd@kernel.org,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	snovitoll@gmail.com
Subject: [PATCH 0/2] kasan: few improvements on kunit tests
Date: Fri,  1 Nov 2024 23:40:09 +0500
Message-Id: <20241101184011.3369247-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IsFRWBgL;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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

This patch series addresses the issue [1] with KASAN symbols used
in the Kunit test, but exported as EXPORT_SYMBOL_GPL.

Also a small tweak of marking kasan_atomics() as KUNIT_CASE_SLOW
to avoid kunit report that the test should be marked as slow.

Both patches have been tested on (CONFIG_KASAN_KUNIT_TEST=y):
- x86_64: CONFIG_KASAN=y
- arm64: CONFIG_KASAN_HW_TAGS=y

[1] https://lore.kernel.org/linux-mm/ZxigQIF59s3_h5PS@infradead.org/T/

EXPORT_SYMBOL_IF_KUNIT

Sabyrzhan Tasbolatov (2):
  kasan: use EXPORT_SYMBOL_IF_KUNIT to export symbols for kunit tests
  kasan: change kasan_atomics kunit test as KUNIT_CASE_SLOW

 mm/kasan/hw_tags.c      |  7 ++++---
 mm/kasan/kasan_test_c.c |  4 +++-
 mm/kasan/report.c       | 17 +++++++++--------
 3 files changed, 16 insertions(+), 12 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241101184011.3369247-1-snovitoll%40gmail.com.
