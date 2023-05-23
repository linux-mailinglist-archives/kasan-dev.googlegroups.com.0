Return-Path: <kasan-dev+bncBD52JJ7JXILRB5MPWCRQMGQEBHVRDXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CC5070CF2C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:25:27 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-3f6bb50f250sf1741341cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:25:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684801526; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9iXqhmIubODADOcvhoOiEOASHqcstU7MY3mB1sZ1RtesLXx/3COQ/f32DF3LOirJ7
         i8+tOiLzaEC1u5yYcHnCtC3wRL0zrV3DbUycW2xZEfmYMhSYzqK7fpUaqxF5Y1xWtVeR
         JtVgnxaA7Js8z56Pb48LOWWXX/lQGR/ybbSufILLar6L2UT6OpKNj38JeiWZ0Q4aqQw1
         Y25y37CkzjNen1vDDzvLOiVcz3TECPBDTtkAcvXl/uEJTR7DDgZD2LYGpmH7bVKu++St
         Fm1VANa5fqzwtJTq+4I8itfENNdmyWiKph1ClN04aDufadzXA5C5h9ZSquIJgtq52CRD
         UlIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=I6LmbM3JEvPYTo8l4un1xhZwf/FDQ5VSxS2y2ct0M4k=;
        b=s5hH+0Y+gOr+kaQRH8JpoqxAaGC7RpNyvYL08IzPh4IgY/A49sQDrxByHWlMyV/4Xa
         wGh2CkJFf7Yjn09EdOXEkrcnTDxdhWhYJNQHjmofxvWQzZK19KZicUKLZoA3e3yKLOum
         4fo0O1hPO67G6/cIcEyMND+5DIgN5tdSURkFB0hv+eeuXy6NLphsCsQ/Hh23NcAHA/Ud
         Gl1Q87UELTjNr+05Yke0p+KLkP+hFhfV5a32AIBUa2KnAgUsCiOn/BK/kGVog2x6l7Py
         mxrZynYgn7ipSf5orFKJpMUQlznLH+d3mVjZOrd5ukybEM9Ab1As8sFt3ATyr1GJlVor
         fhnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mquAyoja;
       spf=pass (google.com: domain of 39qdszamkcd4pccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39QdsZAMKCd4PCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684801526; x=1687393526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I6LmbM3JEvPYTo8l4un1xhZwf/FDQ5VSxS2y2ct0M4k=;
        b=TJuBjVnRINQ50uh64cNmeA5A6mYioe5zAqU7f04Exk5JdtjaK2W0/+PlUSwYosYJvz
         H3Ba+w6xCntbnBQ0NxiDDXeBWV+JQ9wgo6pm81mtHn/uXV+xTrVfLYGeHCJfFT2Y4RsN
         HtDignRhApQRyLe4/Oc1HPIOR4bMcsxdQz159d7qiNKLiIWI0j4+qNpR925bf89sOt45
         rzpAcZvfPaE0RCOZCCJp6k0bLAhg7cFX9J5Lsn/abj6kB5dn4jbMZRmfk7AGpxoDTvqu
         tnwGas2b7jVCsX209uXfCy1BxMuxlEh9aIxvanhg0Ezt6xbOrHZTDJptac0Zt0+yT/IM
         hhTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684801526; x=1687393526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I6LmbM3JEvPYTo8l4un1xhZwf/FDQ5VSxS2y2ct0M4k=;
        b=guDbHMz5/KOz7f/t+ra2YOll/VNhvTj1nWPKBYE4FQOszKG3rZnbZThhlNE5zZj+hq
         VwV7iBA528rXleEmXdLfhyYdJO528yJ++xu1/4JXkCoic6RJdNxxhBTxTN6VNNA1gnWy
         jdt6D/XUSO6uPzh2Bdui9jg8KUV7S/zhEyhOi27bQliyW5+FHiQlhHhCV0jQ46JjTBCi
         n7zo/u7pPWbtr+aX+bkCyHv2koJIOP+Bw8jhP0sXYJnoEqUcaVM+EfG8iB2bGqAMjI87
         XZNdYZFfxMGrMMReZErNaj1trFGY46OA1lFxNBgccRPAzNdAU67biO+ScEn0mkzxJW6R
         T4gg==
X-Gm-Message-State: AC+VfDz+3a0h/TkNiQ39zPHFvYZ4MAtxv1RGeLRRTZuvBg8qZfC2ZDKh
	MZSQuzUF1VzcQcaZ28KPH0s=
X-Google-Smtp-Source: ACHHUZ5xNf1fiFKaCnP//Q8kfyNsrLChWyCTp9N3BCPWksIdfSRfewH3aJJ8z3spxUO3T7vDold8nA==
X-Received: by 2002:a05:622a:1aa3:b0:3f5:30fd:a2d1 with SMTP id s35-20020a05622a1aa300b003f530fda2d1mr4459236qtc.10.1684801526078;
        Mon, 22 May 2023 17:25:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:55c3:0:b0:61b:5f28:d4a with SMTP id bt3-20020ad455c3000000b0061b5f280d4als7926214qvb.0.-pod-prod-08-us;
 Mon, 22 May 2023 17:25:25 -0700 (PDT)
X-Received: by 2002:a05:6214:ac8:b0:5ef:6142:cb05 with SMTP id g8-20020a0562140ac800b005ef6142cb05mr24848559qvi.20.1684801525540;
        Mon, 22 May 2023 17:25:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684801525; cv=none;
        d=google.com; s=arc-20160816;
        b=K68ZtpUSOWF+aFt6Urnik3M+63YNLOVl2WSkhRXVKQ2DCnpEw9uNhJyzTPnIwGXJrk
         GwtS+n2sFhFb0ijvLA466z0CItqFK2YAJuOBP0UczGZEVaQIuGXwf8G4ZLAXhA9F/j/Z
         OwwXGnJBw2FJZBm3iGHpU4btoly9/XS/iQwMJF0zhpHLn2DSAU9VhITLePvf5wNkEBtg
         BwSEUegdY4twwg2FuSg464OFcbhWKJ/YpsX6KS9SVrZEMmMkJEsyY2pVXa98w9BNsupl
         uD7LyZ+Zr/r9sQ6ZZw3tq/wr93+bd8CCOOCj17xq/WRpSu1Lo2C1joqgr8UEQejiWBpb
         rMqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=SK35moxCE6AhlCZl4FimQ53XrewZjdQKUPUW9jfTNhI=;
        b=aqDbSjJUxjoQOlwjDsiYsj0KtNKiBVO6JYxGpq2yx4hiDR2DYJVyzyEKeuVrzeZ/cc
         MtNoWzYjxgbKFD9GwMmYuLlDtoeswM1TuMLtCuXnOccAQ/NaWKSzB9+17gw3tkrgI4NI
         hY+w+d+q6TISUBulA4GN/UVdRDBmhT9ZlFa2G/zSwVKgguFxBObEMYZs+gr4qxwH6Hh1
         znuRQwYwIp023Mnmgj25BA9sK8feu7egPFDzcCGFnezMULOfYNwys44heOJGhl4apxdg
         aY+1FchnMIdqXvqCi4w2DafjcEQjKL4b+qJ67q2jKF5P4nI01k9V98r8v/ya8Z+wu5Ly
         QnIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=mquAyoja;
       spf=pass (google.com: domain of 39qdszamkcd4pccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39QdsZAMKCd4PCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id x18-20020ad440d2000000b00624463b6c37si573941qvp.1.2023.05.22.17.25.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 17:25:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39qdszamkcd4pccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-ba83fed50e1so9020027276.1
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 17:25:25 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:3d33:90fe:6f02:afdd])
 (user=pcc job=sendgmr) by 2002:a05:6902:1343:b0:ba8:4d1c:dd04 with SMTP id
 g3-20020a056902134300b00ba84d1cdd04mr7758275ybu.1.1684801525229; Mon, 22 May
 2023 17:25:25 -0700 (PDT)
Date: Mon, 22 May 2023 17:25:14 -0700
Message-Id: <20230523002518.1799481-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.698.g37aff9b760-goog
Subject: [PATCH v4 0/3] mm: Fix bug affecting swapping in MTE tagged pages
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=mquAyoja;       spf=pass
 (google.com: domain of 39qdszamkcd4pccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=39QdsZAMKCd4PCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This patch series reworks the logic that handles swapping in page
metadata to fix a reported bug [1] where metadata can sometimes not
be swapped in correctly after commit c145e0b47c77 ("mm: streamline COW
logic in do_swap_page()").

- Patch 1 fixes the bug itself, but still requires architectures
  to restore metadata in both arch_swap_restore() and set_pte_at().

- Patch 2 makes it so that architectures only need to restore metadata
  in arch_swap_restore().

- Patch 3 changes arm64 to remove support for restoring metadata
  in set_pte_at().

[1] https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/

v4:
- Rebased onto v6.4-rc3
- Reverted change to arch/arm64/mm/mteswap.c; this change was not
  valid because swapcache pages can have arch_swap_restore() called
  on them multiple times

v3:
- Added patch to call arch_swap_restore() from unuse_pte()
- Rebased onto arm64/for-next/fixes

v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

Peter Collingbourne (3):
  mm: Call arch_swap_restore() from do_swap_page()
  mm: Call arch_swap_restore() from unuse_pte()
  arm64: mte: Simplify swap tag restoration logic

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++----------
 arch/arm64/kernel/mte.c          | 37 ++++++--------------------------
 mm/memory.c                      |  7 ++++++
 mm/swapfile.c                    |  7 ++++++
 5 files changed, 25 insertions(+), 44 deletions(-)

-- 
2.40.1.698.g37aff9b760-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230523002518.1799481-1-pcc%40google.com.
