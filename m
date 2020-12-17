Return-Path: <kasan-dev+bncBAABBF4Z5X7AKGQEGPJOF4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id BC50F2DD149
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 13:18:32 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id w3sf11099032qti.17
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 04:18:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608207511; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+X3CpyF8nMYvKf1QqNdRSD89/RykDDgbFNGc+woEYlMbJ7+NKZkRtsdiDj33swV8h
         pT7h6AkfRIvckWk6uSkJZt2Kl5UKwvjVzRJcqJTph6LVZTWQJA0v4to+6Bpcxf9Ap24y
         Mea1GIYC1q/4hY1ymLQQGLCJ1fQNsk9d25rLHPlSRbd5e+MPG77QZmk8JSozNIen1gyu
         ibjvmv8BcoxGSXuULhBIcQxy5vWp6Wvkn2zhpwuGGiO4IPDQlULFVqOXOxe7gvF3C11E
         PHtinWMz3hTsqEPTyIkhxMcq4kV2/NpBu8UPnLhoAb3ntsw41B0hKKbepWhj6OL42xJJ
         3/ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=e0tdpZd8Nuf5DcmwTSizVowpB8CqULbxzPg2OHEtJog=;
        b=HXEVfzLEe3pIpf5YFQzahNAcVlXJKGAYFZdbtYRAl2UJgKM5HFtZwDpWvEk5ExzE/u
         itCP2IsE1A+pPPfn8VJfAGJrXVp7c2ypi652j6WlJsN3LLjsQmdHq8nw10LGykG8kDC4
         AcEwI9/iq+iClHXLojKLG4JRBOQDbcMd4hPFS1KTVX4FGQmMhESBM9E5T+Yezu5EBkvp
         tPcObK0+CoqPcd9VJCZ7rImPLeJFZQhXDNk6d1qH6Z/D+V6jl0QHp6u/vSc2kFPGyowe
         TauCNpkBZwPX0gSXxYQctrjqqgjqS6n6/kfXb41Zqao6S19nvgpXj63/5tfiMDiwoKno
         zKNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0tdpZd8Nuf5DcmwTSizVowpB8CqULbxzPg2OHEtJog=;
        b=a6b7MSLKJVrgSyr+Yi4a9Ma2JZlKx/dY++wMhFE1JMi/bRk5Ft5oVtlSXfm/kSq1yS
         Wyksc4YFz7qdS3bGrttGS/GTZMmgm1mHdfUhvPtwlSyrrenyphssvJySurnp6WWfxnKn
         /H+XQq7sRlAuikPGDjzTU1EViHcSTPLdw8rS8tfMIGE9pDvvASmeA5mu9wXNuhGUIVOZ
         3zFc5/IwFNQr8db4XTA/jDsva+jD53CK1+DQ5O6bjMtKG7MIhCdsTBl5p24z1nZMmyad
         WM6k0BrRckGTMFlGooFdk02ExzcdLqK62rVo5co1Vhujngu2HLBlciO8n3ALWPvhBzg0
         A+lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e0tdpZd8Nuf5DcmwTSizVowpB8CqULbxzPg2OHEtJog=;
        b=optzNqhc0XWx+5P679EszWt3z/PvP2FJ3Bd5fiSZUU70YbVwZ8GJNrdSNQoNfIZvoF
         fvFbUvFCWEsn1g2Gox47a/GPK1VtN2bEt9zGa70mS1b01QstDKHzMrJfCwlvDcdvoHgm
         vMd+5YkP7k2KNQKSlT9WFW6kKPDgGGAPXm3K9wQW6uj7bKNjK71UfT5HIVG68gU3hfq8
         z0lSO/OuqBB1D5rbiLpjXJowlyi+Tg08rIy1dUjcYf828h5fhpeXHf5rRN5Pav5lWzUb
         FXOtm8hLq+iXrSOrJOl7XNP4iudBRhJMGenVppDe8El8HuyCC2TMknZkeACSi0E+0bab
         T8iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532K17j+7t2PAohchtYvlOurIo12o4igFFJQojKqWGDSZ7o5DsDT
	RVbvwlN3TxqAFIaQrMLeTeI=
X-Google-Smtp-Source: ABdhPJzSsqUAVr2ZXPkU6rH7XLC1GOB4Yf8d4E/nx2SYdLWQUuN43PmcDM9SR7P2+lNWltAUsk02Iw==
X-Received: by 2002:ac8:7190:: with SMTP id w16mr38803347qto.134.1608207511632;
        Thu, 17 Dec 2020 04:18:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:132f:: with SMTP id p15ls6735985qkj.0.gmail; Thu,
 17 Dec 2020 04:18:31 -0800 (PST)
X-Received: by 2002:a37:a158:: with SMTP id k85mr48572240qke.432.1608207511263;
        Thu, 17 Dec 2020 04:18:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608207511; cv=none;
        d=google.com; s=arc-20160816;
        b=VE5qREX9PV8OF9g6p5fXhcxZlJQaVPTvFl/6Jp345/DK7Ur8KZFOHxxs52slxwD8iW
         8qm7/N8Dyc+BQ7hEGw2ZMApJgA7lIR4NJg0+0r53hXfmRmI9tw2jABswtxzuKswQQt2l
         Vbm+hZ4z3avvrZ5OCCcQkd38LgM/xwx/CsbdyXJc2Araj67e77ijUyBJQleTArRVSbVn
         9fPdWsswqW1wCf5SMa0eOgC9xUIemiexrE/t8dV0L9st7gDnDO6YWKmikmi5FbMbUGsO
         eY4a17pKRwy6k+IqV7CBMkSGnX7oRgX72FU4vre7Soyhx8SFNaGDRaRqB2j+1fUDqggo
         3noQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=kR9WhyJckjkn9rC+fwOQQzTY7bwD9+0hEh/LA6cVtGE=;
        b=SB0dmxYMIlmMOMNHwonvFHCqbApxQpHske2XlNWwzpVm70v1AmpTgG5D1tDYxWDulY
         Dsy9yu2Kf2Aiz9UFE8v2jzZFvw/1boJeRNoLQnUi6RLsm6noPYN3A1eskQuxqF8pNaF5
         d3RuvRqlsyjYzOnUhcg0KT2VpaUcRINM/rgQvtVJE5UeilPZoEkTUPY8/JaC7XzjxLRb
         Nz7uALiyWVrerG+b2MYMu+WY56q0uKjqzLPkMxM/Va9tLtOy0/lj+zRTGzAi46utuySm
         4KaYYIOklBtv9mHF1j3tlRPYYz8h0YyN0bgyMWS7ROOTNhhdwBNguW0T1LJ4upD10pan
         lqgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id f21si601487qtx.5.2020.12.17.04.18.30
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Dec 2020 04:18:30 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6b4ba48dba814d239b82b078ac514b0c-20201217
X-UUID: 6b4ba48dba814d239b82b078ac514b0c-20201217
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1088772760; Thu, 17 Dec 2020 20:18:25 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 17 Dec 2020 20:18:22 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 17 Dec 2020 20:18:22 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<stable@vger.kernel.org>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 0/1] kasan: fix memory leak of kasan quarantine
Date: Thu, 17 Dec 2020 20:18:06 +0800
Message-ID: <1608207487-30537-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

When cpu is going offline, set q->offline as true
and interrupt happened. The interrupt may call the
quarantine_put. But quarantine_put do not free the
the object. The object will cause memory leak.

Add qlink_free() to free the object.

Changes since v2:
 - Add Fixes in the commit message

Kuan-Ying Lee (1):
  kasan: fix memory leak of kasan quarantine

 mm/kasan/quarantine.c | 1 +
 1 file changed, 1 insertion(+)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1608207487-30537-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
