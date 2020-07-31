Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMVVSD4QKGQEZVIOCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6B242346B7
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:20:51 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id a5sf828119ooj.6
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:20:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201650; cv=pass;
        d=google.com; s=arc-20160816;
        b=Le2eFy6ICAAxmMSMfM/M9oQjafvUwsEH0k/p1TDGB0C4eW3KvfsWVSiXV51XFy6sOk
         uiN/lA8/HmnkENYQz5NkxRi+AJ5ZRhXM12MwKkTXmRTxZLSctXpiVU0xtnOyTbQFwa4i
         GQzy9kqsQexUIUWTO6eXQCf4UA2g96NrveWl73hhEysgrRSuVdnava9TrMiKS346bq9H
         GrmV2FvZC7WqbzJAhvjatm7A8TDav8qWRVuq5ghkwPgFzcTM70OtJ1N14+NpLuVJJga4
         zB1ojWv+z+GITgoHCMfiXpyymf3vUc3v35JKH1UTTAOfOxRflsDZPHTL7Vtd7JLB17Uh
         ereQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=BNniYaf5ZGIE3bGhKoPtJwr0Z+5kqoRM7z5wQ6dfQpo=;
        b=ydlvdFKV5z1K1BDRMY7lQf0LyTFnuLHkZwGaS7V1J81x2a1HBHlRroLA0qfyhU0vYQ
         Uj1PIPMTjLhniyNbLs2JQ0Xc0pjj9sbn02xdZRPcobJ04oUEvlfQmhzHoLSq6gUm+deR
         VPxDDS/iUXIdlLyv8xo0Hs/Rfnq4LXLxcqADTmdTl/biBpx1cvl9n+E+aXhn52CQADgQ
         ZtkRVkjtKcqev9Xl6it3xLTY6L95jebsdKApWW8tQ1VsWvpwEMwaGiFGgSRBXfnREg/4
         Chq+l/89zEL4F/EqL8YAQqoTo7w53FkfZDxsIeakdRKo0DabpBOL7BIIQgO2VJ3VT9hd
         eO3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMkS12gy;
       spf=pass (google.com: domain of 3srokxwokcxyuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRokXwoKCXYUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BNniYaf5ZGIE3bGhKoPtJwr0Z+5kqoRM7z5wQ6dfQpo=;
        b=m5lfg1SAkoCKeVyNeNNfVnCaqnzhmUlYdZ7zKMpOsdTtu1IfWvnkwNbByPKnYgIq21
         QIYRBw3NE3Su7WzqPpPl1Ds7dNuQCIe/3VZZznZinQry3dMdH670TWuw8Kj2iVcQqc9s
         24jcXlnp7cFwkb65BmNbeN+Oj4gtm2Hy1bXhYNhdw8//OA/yC5te/yCnED4qCFFg7rey
         dUnLEDVKr0TCMg5ovmblJoWArfWQT3p/SZE/iZguppVwH5OuGbVzdgYJaOrt0c3hJbuQ
         gBM66f8V9t+XnNQAXicyFWo8Vu6lQm0zAsDDJsAOvaJEhy41TVX/3KBJsb38VNdsGzzy
         hleQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BNniYaf5ZGIE3bGhKoPtJwr0Z+5kqoRM7z5wQ6dfQpo=;
        b=XGXFbG3bfZWPTyebRNzx62i4p8JARwBMJB8F8hjNTBCVXCwMIp2QIlXiJG4pfASEgv
         DKPtm6vMw6+VezM1Y9tWebl6nlEsKOecRfXX/SQtPudZ3B0ueyeKOQEBKXf8xL3FhrzM
         Ox32Ov6KodJp2U6/BEuiJ9YVNxc6txAogbQHzSBPzNvvTcG4sBJ7D7J5I98US7YnmgXi
         NW1KII4JBng9TLSNvDCgr2RJxCy3VuWrmvEWN4lZHhrkcVAgmX78L1AYN6mIz1vCXtzS
         /qeUZU++VY5alCjsZg+41HBQ4pNkbH1r2tju9TegqRAam86QiSkYPUXDq4IMxTOWv62b
         Y+Gw==
X-Gm-Message-State: AOAM533wE+bjXN6B5G+/ER89QSgdJL1yKwmDCNYuvW0EWu8Q+f+luOTC
	mz3veguGpJz6lnGU04Wkwhs=
X-Google-Smtp-Source: ABdhPJwd0luW+HTpG7dB02VV/ZFC8gyWQGKbL8afRq8kDzJ68Ub8q7pEeWobejQYiVKjS8/Dv4HKCg==
X-Received: by 2002:aca:cdc4:: with SMTP id d187mr2874887oig.69.1596201650474;
        Fri, 31 Jul 2020 06:20:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5911:: with SMTP id t17ls299258oth.4.gmail; Fri, 31 Jul
 2020 06:20:50 -0700 (PDT)
X-Received: by 2002:a9d:2264:: with SMTP id o91mr3086848ota.52.1596201650111;
        Fri, 31 Jul 2020 06:20:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201650; cv=none;
        d=google.com; s=arc-20160816;
        b=HA2FgyIWkVDudzjL6TAN9iwzAJGUX1CE+IJUzyDmJQ5bHtqnr/xb6aL47dHJwt9wFM
         XfruJ7+ahBRDRKgN6xaKZ0WvAYm6CDxLdgw5hvppDM/yQa1a4eiRzUnwAzZz1cbTOXIo
         2ODgP0N8kg1+TZ4RmmFicq8dmi2+k1zKxNpJyNmgd7LRYsNK1JGhnMGlVYCZ3w+KXrar
         njlOJczPDrGaWghY6zXp/zF+8ldHbOzwn0VlgvQ6Mu6C/nPsKBVEoNG1C6SGHiVN0QZo
         6qk4gyOqi0qKKt3NOoIsGT8hXTSh4bb8RNMDVks1XuxfuKf8MBM/wP9uVx8xnEDRvCpz
         2Ctw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=7/8tDu/TtZiPY9Lz5Bah3CGmQqypIOKTi+NtrfkKjDo=;
        b=y9s8c0bETb2eEtpqSGFjVO8OyROWgptRRn1elmqjBAa0syh2fb++dNPomaFLGdR5w+
         4/kbQRjEL5Pl2ZX+HHTFBw5JyNQwjBmqp+7j6NTiBoWvQh+1LN4thKnukhchO3gEd58i
         HzdOuwz3O/TN8HID3dkD5YeWwr5aftpzKTlGc0BlQgccfqMm2VPm3c693yyT+ikL/DtJ
         nLWVOWquQbLZp4WVgJAhZRZ+1vY9IECpfLFW3Mo+3SIVCi/nzjSwpejxDwGBqEkzmJcL
         xgAWnwK2v2JF4cnb2QxOyvS/S19RXlQ1RZWznFvcGmQ4RFAdxuIFfX5iV7p++0OswmIF
         QV8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMkS12gy;
       spf=pass (google.com: domain of 3srokxwokcxyuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRokXwoKCXYUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r64si371220oor.2.2020.07.31.06.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:20:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3srokxwokcxyuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id u17so18372212qtq.13
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:20:50 -0700 (PDT)
X-Received: by 2002:a0c:ab16:: with SMTP id h22mr4018288qvb.72.1596201649557;
 Fri, 31 Jul 2020 06:20:49 -0700 (PDT)
Date: Fri, 31 Jul 2020 15:20:37 +0200
Message-Id: <cover.1596199677.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 0/4] kasan: support stack instrumentation for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vMkS12gy;       spf=pass
 (google.com: domain of 3srokxwokcxyuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3sRokXwoKCXYUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

This goes on top of Walter's patch titled "kasan: fix KASAN unit tests
for tag-based KASAN" (already in mm tree).

Bugzilla link: https://bugzilla.kernel.org/show_bug.cgi?id=203497

Thanks to Walter Wu for debugging and testing.

Andrey Konovalov (4):
  kasan: don't tag stacks allocated with pagealloc
  kasan, arm64: don't instrument functions that enable kasan
  kasan: allow enabling stack tagging for tag-based mode
  kasan: adjust kasan_stack_oob for tag-based mode

 arch/arm64/kernel/setup.c | 2 +-
 init/main.c               | 2 +-
 kernel/fork.c             | 3 ++-
 lib/test_kasan.c          | 2 +-
 scripts/Makefile.kasan    | 3 ++-
 5 files changed, 7 insertions(+), 5 deletions(-)

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1596199677.git.andreyknvl%40google.com.
