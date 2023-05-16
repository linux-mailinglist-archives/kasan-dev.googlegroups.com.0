Return-Path: <kasan-dev+bncBD52JJ7JXILRB2OXRORQMGQE2IVARAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id DFF8E704370
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 04:35:22 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-76c365e0114sf1559062539f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 19:35:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684204521; cv=pass;
        d=google.com; s=arc-20160816;
        b=RXL9ehO3Wo4nHTsuRs3ebhsVxF1ELGDrfOdY2KJP7Tv2c2ouTplJThjrpxs3+EnmG8
         SQVrgpKjW3nbMXs/4BiMk+Hb0akiSLZYPdGg+7N6axiznpJAYvhp/+B/DVLLLqGYNtqm
         y0Zot0PjfeD5ms8Fv8juwDuSLv36EVZmaSOSTUW810TKypO2IMmHqlCnlcJxPoZCHpK3
         O6HRoAV2M7t+apYrnVs2oUtQ4dmBvJD03t8ifuJq79D9lCfWkvvQjy26yZvoLA4KDokx
         K1kMZmcktBoCTsWA46WJXMi3Ic/YAjvl/x4UdAsTM0gFGl33K7duwhEupco8Wyg1SMfE
         Q2Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=xtQ+tTJGHNGtN9aUmuej5Vt977l7+02Nzqgd3QMek98=;
        b=DHewMANSOJR0IrEiHNCdz6Y75C99LhHkfGn+zAclRvMii3Yf/UrXvcWQfxup6RuJCg
         n+SNBsW0RGQqsNlsUgGjx1wE42uNbDTre32rrp2R6P5mf9oEi5mC3ozjXO7blanHZA1+
         gb7UIChzaFBehmsSCbhXRu1TJDJ0cmGJhr+BhlwyEwTYLEkpLLHdS0THc6r/H91BlIh/
         EfNHFG419fd5AP2PFyA5+kxuBGjREEurUQzXZYwmWhrMttVYWMxdD5pS8wHX1ddm70eq
         8iL4pbraG4YZEMxazKFZ9WflRm2rGjCQ+n5nMVEZd+qVdp96olu9fNhnGD03Lw2UCf07
         Lf2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="qg1/oXxW";
       spf=pass (google.com: domain of 36otizamkcxuivvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36OtiZAMKCXUiVVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684204521; x=1686796521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xtQ+tTJGHNGtN9aUmuej5Vt977l7+02Nzqgd3QMek98=;
        b=tQDCdrStNErCIXx4QZCeHC8lPMsIm/b7wiGQqxu1RNmQVcPP7JxL3w9vpLLLMS2skV
         HvB+9B/GXXsOqhA3htgaIKjuifmpoZ7GeXaghkjXSKQgtX8aoSz5t+81VHMjm9Zxol5Q
         SsEF3G06Z6I7WQAIlz+6YI9C4mMg/o4HL5duOln6I1IwGhMFiG/3/dyxjF40/DUJNq6q
         sJqvaxDxRnQxAS8a3wpnzFFzPwIg885vB/XanmwQRGohrNcae5BkaDM2DGLfY7sAUDgF
         X0gqDiSDYpD69pGp7LlZqFscw/zXtlZ1mnz5QbdVPh7kuKzu9tqthlcaEJmh0Bu+ZXGR
         eFMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684204521; x=1686796521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xtQ+tTJGHNGtN9aUmuej5Vt977l7+02Nzqgd3QMek98=;
        b=ajo+f0iBsiS1HDJuA6zTt5Ec3Tgv0SASNg6nZkxrmpuaWvF9FkLk4/NwzOWApqyhc0
         8z4E55EZYsfuxt1DB0nLS4rH6Gyo6mo+G+YT7UMisq2QoOhUnfoPaCqNa4SJO59kLkDX
         nI6AXK1e9DFbRUoMaKCKrFZa6FxBGEJ77W2Cq08u8hR6QW8ppNZac1m8f/xfJQwE4ZK4
         SDAwOJz5TqKUdxWagwI/Xp4iGAmZuicKSAOph0nGEZeqAbetEZwVRuxghgjcjpSDDU7k
         K98Hrfe2sm3sIhrkBhxAKSLs6Q26eEdOGTOiJ+VqZRPzo7bc1vubrwcsxjrv7NSr9fJp
         PzLw==
X-Gm-Message-State: AC+VfDwI34LoAw1FjC1KFOEw3Vk6lxwPalYpUNMBtsawHovPQXHvSvux
	Bv1fGGTfi6OAXVGeQTXy8t8=
X-Google-Smtp-Source: ACHHUZ6Vl37yTgJdPWM0PBwWtqjULRAwg8HOr4jeHvHUs3mQr1M2mFx6+acj7MwCVakI2zF2YIy8LA==
X-Received: by 2002:a5e:de01:0:b0:76c:6635:321d with SMTP id e1-20020a5ede01000000b0076c6635321dmr922627iok.4.1684204521641;
        Mon, 15 May 2023 19:35:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c20e:0:b0:335:682:1dd6 with SMTP id j14-20020a92c20e000000b0033506821dd6ls48002ilo.0.-pod-prod-00-us;
 Mon, 15 May 2023 19:35:21 -0700 (PDT)
X-Received: by 2002:a6b:5c09:0:b0:760:ed78:a252 with SMTP id z9-20020a6b5c09000000b00760ed78a252mr974744ioh.9.1684204521135;
        Mon, 15 May 2023 19:35:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684204521; cv=none;
        d=google.com; s=arc-20160816;
        b=oqRrpyI5DosQ7QJsPbkAdodfSUCtCDkdgcGVLdOO8UpPRDHqMdbzAUC/38zPvLOb55
         cafUKOD7BjSwQqP+5pckDqlsVOYWWLw8wIHsudfDk3EEhgwQXJ/rCJKDp6rRWyZ1g1Zl
         4Dua5Dk4mFj6VPe3tmOikoOWCh5Cvq+cKMLtiBSzO1hPO3ZQZ8/cmmfjl+HX4MgS+VdH
         w4lQLCQPnbwowZksasuJ5lzsGyHThhbR1zP5Fxp8yHm3/5AnElLTF5DhqKiLyArhSPvQ
         6vot2WkN743hrPgDrv/Zp1cMZUSjttzSSn+b+YD/kvIqT9FM/rBjcjtvB4oxxtKv7HtX
         6E+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=9idPu53ZjVHtwYigNYCClhylP4MevS6nQx9iaoA1FqE=;
        b=qUw+Dl988hKSm8Sx9iyq2raw+KItjr/uXMA8aLvdvudJrqpuqItIFNW5KMCGYT6OPx
         /jt+RRsMeLlQ6nPitIGxQmREH4MYh4NnDElapoIwnT+nKazgd7Sl09qCS3PHiKBef5Pu
         xRlFZ5ts/EyP+1SM8BhVlOVWekJR6iYgsMezDIvn4m2MGhMn14RK7+hFkMu94ogMo93W
         knNF3r97nYXWIGABI3Yg0M4dYgDXMYTST7Zcb0xlY9VbhOiJ27Oln82YhWv8LYOkMvrQ
         mZD7SqshmYKlB5ESaYsSCQNsu1iq/0a68PMJwvytbMhQYms0iRadGze8l+c8LhAGWeqc
         YzgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="qg1/oXxW";
       spf=pass (google.com: domain of 36otizamkcxuivvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36OtiZAMKCXUiVVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id l19-20020a0566022dd300b0077006b0ddb6si385262iow.3.2023.05.15.19.35.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 19:35:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36otizamkcxuivvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-ba69d93a6b5so13034302276.1
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 19:35:21 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
 (user=pcc job=sendgmr) by 2002:a25:6542:0:b0:b95:4128:bff6 with SMTP id
 z63-20020a256542000000b00b954128bff6mr21566342ybb.1.1684204520689; Mon, 15
 May 2023 19:35:20 -0700 (PDT)
Date: Mon, 15 May 2023 19:35:11 -0700
Message-Id: <20230516023514.2643054-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v2 0/2] mm: Fix bug affecting swapping in MTE tagged pages
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
 header.i=@google.com header.s=20221208 header.b="qg1/oXxW";       spf=pass
 (google.com: domain of 36otizamkcxuivvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36OtiZAMKCXUiVVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--pcc.bounces.google.com;
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

v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

Peter Collingbourne (2):
  mm: Call arch_swap_restore() from do_swap_page()
  arm64: mte: Simplify swap tag restoration logic and fix uninitialized
    tag issue

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++------------
 arch/arm64/kernel/mte.c          | 32 +++-----------------------------
 arch/arm64/mm/mteswap.c          |  7 +++----
 mm/memory.c                      |  7 +++++++
 5 files changed, 17 insertions(+), 47 deletions(-)

-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230516023514.2643054-1-pcc%40google.com.
