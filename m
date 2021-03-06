Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQETROBAMGQEW277WPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D657C32F724
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:00 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id v16sf1382481lfg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989760; cv=pass;
        d=google.com; s=arc-20160816;
        b=mD2NKwWKS/rMZT9t1/4C7gxzPrMBgdp9yEv6Qh7o1xNYEPNYQ3jdGqTMDbI7DfjgHx
         D+2asKe/ctSY/qvYvEawez/N8B6ltXWctuaFPzFPj4NqiHAOtWfMKUFDxSmzBSh/isCb
         Aze/y5DcNQZqa89j49fKlOuPQwEoToli/IeCDE3spMZL63c/MJWSEZQtGlIP16ttnXd1
         eYYhv8JXExG/Nx7ShZ38RSxOwoD5+LHPtyU0BS7N3U8P4LaiZI05q5fSE00Yo+kYA1Pp
         d2mzACsq/Un38LmsMPNxeyTTlsonx+oAtt1HWjss0ZY0z4yWwSEhvPdwgkWN3xEDndhz
         1uUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=4X8dTsT89+Fs/+2PCNmDVzN9zawtOsqiRwO2HDckrSs=;
        b=HVeomR8Pb/SKcv+Bnio1Lgxq+HHspxMtznxOKeDU7f3HYUpZ5B9fzgDM3WRKGVhqHY
         c4EDSOs/ZqjLnjomb1axOewgJ+yuVyp13u9Gz5PKSTKMOH915V4Os0xGL8rYuT5wmRYg
         wKLqRqzw1uN3kz+nOO3FdMT2muLY9GmUeBEhgPm1n1TmHqB9HbWSyIlvNa54l2U80sah
         5Q8pgB+V08R1zcNpHxN88k34iHShJfWuQdNoq7GF18LYtblsoe027eC9NWf/95ewiPa3
         l0uLVMFrkGkMy9fUCEUjoo2FdN2NFnuxDJaJuuUTMpicGd2JMBmz4JWPzp06cBnM0afW
         VQfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WOH4/bdP";
       spf=pass (google.com: domain of 3vslcyaokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vslCYAoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4X8dTsT89+Fs/+2PCNmDVzN9zawtOsqiRwO2HDckrSs=;
        b=qnjNfzG1A9mSoMoLYCQjb/6x/12+Pbn3GQcRbDCoMWESSGKAX+5oHZ1iBFjHLzA3tL
         rZ/90Q0G0MijjJ9ReBBCbI7+JVYb+sTBCmPMCA8E2mJI2NWwiLCkd1Xd+ztrdBL1H2G2
         db+eHGrQfL28DBsI/0f2cnYdlOfR0zhdY82UAuFgteZ7JoMz85nZLyJzoS5rN/X0USbm
         pfx2B6fMwnysfzj46Owlw5Fp9qaPf4PzZIX3Ob0sf5NA1fSbzd7sSlIsBzsQKzkaVEuA
         9Xjieh3KYWt94zQwjqQ9oINYAuLonXCIA3gpVcg7k4+8jyGtRiZRMMjQNn2ckfKrqFJP
         5Z6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4X8dTsT89+Fs/+2PCNmDVzN9zawtOsqiRwO2HDckrSs=;
        b=lOLjNM6982R5LCnK0ZuN38rDirCEJjDt+gOYuZIqmRSRDhPgY3a1cPfdgyDlGUu327
         wjMXA8olMyV25UfXL5FK7U3LYKJldwAyCoP6tLWX+mv3Wp3ml5Q5O3E0QBF8pSXx+yPZ
         1r3fUtutmFdMmhCAfq0m0F3sVGEDGNllgoMxX0QAAaldMMhH1CNvYCNYO/jrzbSvthom
         AAee1pQbncs6Twljd/mWFSV6umfWvPORfyEKnKKtCX7+YRDZ/aEOw+iQI3qeY3PPWS1T
         gxeFYxAuW2pOxxWUbp9GrffSlKy2I4MFmYCVbbmV6/HgxNBFRE8mPueHogE3MWfyIQhF
         57LA==
X-Gm-Message-State: AOAM5306j2a0nkLWsGEOsSuwVo+q7npNX8+wMvX21KoWkJz4e9JXmfMT
	QDhp/VzUasKD51PkOrus3w4=
X-Google-Smtp-Source: ABdhPJy6O0hd067BMZy7rCL5Ibem4IpLNVJtDab1pcHas7DspVyk0pvPp07xpOTXGDxtLvzrw4LgGQ==
X-Received: by 2002:a19:2242:: with SMTP id i63mr6727276lfi.643.1614989760472;
        Fri, 05 Mar 2021 16:16:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211f:: with SMTP id a31ls2297833ljq.3.gmail; Fri,
 05 Mar 2021 16:15:59 -0800 (PST)
X-Received: by 2002:a2e:9b99:: with SMTP id z25mr6982711lji.103.1614989759362;
        Fri, 05 Mar 2021 16:15:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989759; cv=none;
        d=google.com; s=arc-20160816;
        b=wEJGDGI1naMt0r5ibvTbhoEIo8j7BT0Yeuj9L5vpYw6xNfK+zpKKi+JsFDIyINSw0D
         oTG1hBD0+p64afk4pxL2vsHwfOWatVvMijFbqzs2KdJlduPSUKq02FwZ3b5SaJQaBPeM
         z3S3DfcP4BX2HUO7MWUprj9EiKXji79PX5rcb//G2R/YV+OJ5uaQd3l2WW/i14cZl9os
         nFl7tSQMkAkIKOSULn7pVyiy9m/YurAs6/xxJimcBDEdWwiR9sDXm80qDV23pgDDIqC6
         XhWgrmXhO+r/PhHa46EWWmG6N1Uu0GIIuVw4NagW9TW6cpuYsDQUDauVZHYsGo1CSePO
         u3tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Vm4vyPpxQ7w8FtG0FaFIYIajGbm/X1qa4ffJxCVDSQc=;
        b=mBQPENXzl41FxqO9kpnzTDSId0QJN5EdDMmut8dcARRPKlxh7vbJ4vOCGbGS190S4H
         PJz7llcv2xWe9ysOoQUX/Jup1JGLU6rYYZKwzceDBq2MdKOuO7UbB+MEZgpw2Q+lpH75
         7FXxa/uIuUiuS8ZlwL+Yxm6Rxj713dY5/+7r1Y/nBCi3PbqsBOB/VNS0y1IynhUatsGJ
         wZnAtUe7RcLOWql+XcGXAQgCrveASGv648sMylpM17v+oElO1APptUsj5kHgBmEPltCf
         CEVNxyvqI0GfZeWLPsmd9I6d+h7vLncxaJ6Tm98XGXDa78PWT0YdzMmgY3UPZfcysh8p
         CHqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WOH4/bdP";
       spf=pass (google.com: domain of 3vslcyaokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vslCYAoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id g12si152365lfu.13.2021.03.05.16.15.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:15:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vslcyaokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h5so1765637wrr.17
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:15:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a1c:f203:: with SMTP id
 s3mr11046868wmc.152.1614989758870; Fri, 05 Mar 2021 16:15:58 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:49 +0100
Message-Id: <cover.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 0/5] kasan: integrate with init_on_alloc/free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="WOH4/bdP";       spf=pass
 (google.com: domain of 3vslcyaokcwudqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vslCYAoKCWUDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This goes on top of:

[v3] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
[v3] mm, kasan: don't poison boot memory with tag-based modes

This patch series integrates HW_TAGS KASAN with init_on_alloc/free
by initializing memory via the same arm64 instruction that sets memory
tags.

This is expected to improve HW_TAGS KASAN performance when
init_on_alloc/free is enabled. The exact perfomance numbers are unknown
as MTE-enabled hardware doesn't exist yet.

Andrey Konovalov (5):
  arm64: kasan: allow to init memory when setting tags
  kasan: init memory in kasan_(un)poison for HW_TAGS
  kasan, mm: integrate page_alloc init with HW_TAGS
  kasan, mm: integrate slab init_on_alloc with HW_TAGS
  kasan, mm: integrate slab init_on_free with HW_TAGS

 arch/arm64/include/asm/memory.h    |  4 +-
 arch/arm64/include/asm/mte-kasan.h | 20 ++++++---
 include/linux/kasan.h              | 34 ++++++++-------
 lib/test_kasan.c                   |  4 +-
 mm/kasan/common.c                  | 45 +++++++++----------
 mm/kasan/generic.c                 | 12 ++---
 mm/kasan/kasan.h                   | 19 ++++----
 mm/kasan/shadow.c                  | 10 ++---
 mm/kasan/sw_tags.c                 |  2 +-
 mm/mempool.c                       |  4 +-
 mm/page_alloc.c                    | 37 +++++++++++-----
 mm/slab.c                          | 43 ++++++++++--------
 mm/slab.h                          | 17 ++++++--
 mm/slub.c                          | 70 +++++++++++++++---------------
 14 files changed, 182 insertions(+), 139 deletions(-)

-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1614989433.git.andreyknvl%40google.com.
