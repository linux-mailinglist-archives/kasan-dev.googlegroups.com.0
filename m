Return-Path: <kasan-dev+bncBD52JJ7JXILRBFNF7ORAMGQEOI3AJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C04B77012D3
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:58:14 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-61b1dbdb2f9sf141814416d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 16:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683935893; cv=pass;
        d=google.com; s=arc-20160816;
        b=OImhtb0BZE59TxnR1XRPGvhkGeO6EuEN6Z9TAwfoR5op4nmCFuBT+hUJlim+W3vlYk
         uGdSy2YSDH3OGHrlxKIc0+bqT988I3TrXFGBye/Fn70kHEoCpZoVvTabIUPyYiq3pqFw
         W7hXvflGwqJIGzXyb1LbFsf+LxnYExqrbboNdBiIb03Px7hXeRVrlLqbnOnGCGQdpL0h
         3gpoad+cvqOFr0TeyUpKUNxF3LxJMNASQptkAUfZnBAHkt8mCx9k7vu/S28O6px30LQN
         B16lis11/HzJB+8C0Gvl08dODWaEWXnJ3Jd1R080yeUfuj2rrvrm+m4a1p3pRU6FNLGg
         +7uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=I++ceXVfPudsbA9mDHIiRvzV8odblGDOP9kVK42/RRg=;
        b=LQWCKUb09WZ1WM9z5caOTRSEvzYa2xBB1sf90XNeXTySyBcoaA0ZDdjkvooPVH2B+v
         /vt3/dRTJ1ZDmqWoKDAd/c9P0/KFzwHuNh7goDDExJE5x43tFXnb1r9Kxx7NtnH9FII5
         yVLvlMB8TB6PUMyZZ5DAWPK1bMZeVdafsMmzFBD7yyluQNEIBg559AqvT1p+78J7gw4y
         zyHh9Bzi198sA7pANf66wlHLW5I21WU9aQ7atNVkCt1n9iNgf8T6xrCr1bvOScQ5U7MG
         VYTNVuDZ8Le3K1FmHoy/A9C4TowjNYlNw3b4dVwJI7XTdy2Omd7+m4PVm5RrUuH/6F5x
         hs+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="MH/xgRcl";
       spf=pass (google.com: domain of 3lnjezamkcd0obbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lNJeZAMKCd0OBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683935893; x=1686527893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I++ceXVfPudsbA9mDHIiRvzV8odblGDOP9kVK42/RRg=;
        b=jawUtlOgBWHjMt0ltv+FeipOyuOd2mCYD0U3JH79KicgyuqLvUBD/WmU6VRyQZa7ww
         ugFoqHC80idI69M+0yKB9Q+2U8P0xWsAxA+HeDFSiCe9PXsANYuZ9syJ9CKTpvfRGbwK
         MrvaXfyYR5I3YI3ynpyWKuexPDSw+3H8qZOTZGQXXmH//i+tsvfyB2SM+o9MQATPMr6S
         PCU1i0t5SddqnkLXOJi2hEBDDOdsr3+5wS9Q1cvf3z4SZQ9vES6DYwJ4eWon+a+I4cYZ
         xSZ4gsScwZakpOtYYCrrXkjpS2fgGd+GNtw9hdgDWu/l3Y7SuKPZYNuL6GFSX8YZf6sR
         CUnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683935893; x=1686527893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I++ceXVfPudsbA9mDHIiRvzV8odblGDOP9kVK42/RRg=;
        b=bzz6DBiEgkBaw90PV8D3IAf494zcNiNazmbvQdVOdGhvxfEQeOhU/30xTS4FrJzSMb
         uD0gY4EdktvV8OM/3gVLs/KobFvSPV4bCM6Ay3V8TVMkA+yCXaWsH6waU/eNR7xE12AA
         Fg7zWjWpMdKFCmVYPVmozAsUrWuxWbVBc5+DlvGqb6slIM+l2OFzm9JHGwZfxYgYewU2
         5LdEoiKJpJUMCIa0vwSbtXWLqUZ6ga04cWuU6q3dyZLiyWTsqVSuxe0nf4DQyZ73gEDK
         rTohBFz5rJg8tw0X09B7CI+T2UAmWL5jACx54Qfp50b/Wo1NY9RXzi4la5aUiNFs/JHt
         qgXw==
X-Gm-Message-State: AC+VfDyKgQFwd/7opAmVDtmGqdUrNRIPV/+r35gguNW9SLVoH67a8trX
	wRVwEXf4mzr/Vebtu88OUc4=
X-Google-Smtp-Source: ACHHUZ7YZkeX6T8eXGxRDFF0ndcuOON1l5UAYvI8CeKH6WvNAZzUYW89hHHTCOoF3sozxoKjwvCCRg==
X-Received: by 2002:ad4:5505:0:b0:61b:637b:41f0 with SMTP id pz5-20020ad45505000000b0061b637b41f0mr4446377qvb.4.1683935893479;
        Fri, 12 May 2023 16:58:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1e87:b0:3f3:93c3:7e8d with SMTP id
 bz7-20020a05622a1e8700b003f393c37e8dls12561748qtb.1.-pod-prod-gmail; Fri, 12
 May 2023 16:58:13 -0700 (PDT)
X-Received: by 2002:a05:622a:1:b0:3f3:a3f5:a3b2 with SMTP id x1-20020a05622a000100b003f3a3f5a3b2mr18505443qtw.8.1683935893010;
        Fri, 12 May 2023 16:58:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683935892; cv=none;
        d=google.com; s=arc-20160816;
        b=w3JniCAZgBh4F7jz0lfAfyZteehjXBh9UtsYyppbUpimyS0VblPT/ljptZ3yU4Yt7i
         JJK/SuX+XcoIRlM7MVu7flGwNXXofu8AkKcTb4ERx00X1XFpmvExx0Ma7/lKRLVkfaVh
         PeRGMGoqy2AtPi7jgAGaMYIa8MD9Cs/RUtHakcd9ZC7jFGKy/PBI8gc66LUaCaI2Fu2X
         0o7M0162e1Nr38Hsw/OZVNDTnHkq/doM4dxyS0m9LZlZbcOkTxvI7Rb/eZEDqsPEKUhF
         P8uRCQxBLPY1P4dxcfoKoM9d9bFHj3WB69V7r7xSBej9FZvZP4HRTs2zDPt7hRlZ3+OF
         +KOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=2B9ylj6BFfnRpivqhld1/fhZhP2W8ss3stfOx6ALHRA=;
        b=W625mt0xKY1UoXS2xNMtK/MMgipGmR+jzD335EOZN8S/JsjPB2J7lyGh1q5dN5mSAw
         bTInJupz65ZwchaDzx5HNbLPJzQ7dmQ+CHJfGxSMO907I0KGKC8Jgng2bdqkx04IWAnF
         Ga3bSV8DZSER9NLWpJe0aVGTshLhdEIUxNZC3NlMoZR/MnRVgMxFMZQodCIuqIQG3K+B
         Pq2uwPdoWkq20Zg3p8CJacaVLrmXvvF/CeqO5rijdSiPk2B+hi30hbOfMMF/PylgeDMS
         Ab6F2cvaQSwLl8dyy6k9L1j1z757S+SjjP4F1huSb2Qx+FMmS8xfonzq96ukt2pIKwpA
         +lEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="MH/xgRcl";
       spf=pass (google.com: domain of 3lnjezamkcd0obbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lNJeZAMKCd0OBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id u14-20020a05622a17ce00b003f395029e21si826792qtk.2.2023.05.12.16.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 16:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lnjezamkcd0obbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9968fb4a8cso19321204276.0
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 16:58:12 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:ff6:108b:739d:6a1c])
 (user=pcc job=sendgmr) by 2002:a05:6902:154b:b0:ba6:db51:a7e4 with SMTP id
 r11-20020a056902154b00b00ba6db51a7e4mr2646213ybu.11.1683935892703; Fri, 12
 May 2023 16:58:12 -0700 (PDT)
Date: Fri, 12 May 2023 16:57:49 -0700
Message-Id: <20230512235755.1589034-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH 0/3] mm: Fix bug affecting swapping in MTE tagged pages
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
 header.i=@google.com header.s=20221208 header.b="MH/xgRcl";       spf=pass
 (google.com: domain of 3lnjezamkcd0obbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3lNJeZAMKCd0OBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
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

[1] https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/

Peter Collingbourne (3):
  mm: Move arch_do_swap_page() call to before swap_free()
  mm: Call arch_swap_restore() from arch_do_swap_page() and deprecate
    the latter
  arm64: mte: Simplify swap tag restoration logic and fix uninitialized
    tag issue

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++------------
 arch/arm64/kernel/mte.c          | 32 +++-----------------------------
 arch/arm64/mm/mteswap.c          |  7 +++----
 include/linux/pgtable.h          | 26 +++++++++++++-------------
 mm/memory.c                      | 26 +++++++++++++-------------
 6 files changed, 36 insertions(+), 73 deletions(-)

-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512235755.1589034-1-pcc%40google.com.
