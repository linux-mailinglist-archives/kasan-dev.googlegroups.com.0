Return-Path: <kasan-dev+bncBDY7XDHKR4OBBZ7Z3ODAMGQEIC73CJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF5493B4DE5
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 12:09:44 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 4-20020a6315440000b029022154a87a57sf7704337pgv.13
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 03:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624702183; cv=pass;
        d=google.com; s=arc-20160816;
        b=KlCRP55qNifltD0hgus8p+svtwVRf5hGoviwVT1Ia5qbX4/L+T4/5+kIy+Pbq3PIko
         xi6t1ALlCF+8PhzNfKIto0gVwrKM5RjapV7CqE/Pu4JdUW9+iaSIMxybf0J7ackc+zeE
         c6aV+b16sRrOGCvtBCT8EZh1KiVN37S6jIKgLy2nPgAv5yz7giP6ZQiEfnWXOtZJJRJ6
         Rt+L08TlhY2pAF7J87j/dqAbD6RVF7okSyspzOeUOLdnSsOlkVPaL4Dqsh+5EckS5I99
         ZsAEvLHHKWdYmxlnkCsa79sVkFA2qcu1RSfrw3I49yqAlAQvMiUXzhw+gZOJN/UrXG7a
         RILA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YHGe54cdB41kcxObOomRr2rby2A9hAVU8OqKhy+NqvE=;
        b=jB4aBgRWUiLkgx987WwxY2KjL69lO3NkUuH6Bag03ac9NGwQrarF9imrOikaIhx/vg
         p6TCl5C0hoQ3etmtecJAx2KDbLXETTm5YJxEqGG/Rlc/gFo2OssiA7ti69130gR7SXQn
         zxp4LBUqn1BMHMabzqNPCzIRTenCWn0hVC5qQ05NrkG9JnPsPQi7RNDTU5Ef9S3LesXF
         yaYlsbYZsAiia5E79qYKd5PrH9T6SwK2bRKR9ITx/oz3NwcWCs91GYt18E7yxre+81rD
         BZ9BZ/G8Lx08zo+GK/rYHkXpTp3zSHHEwXKreTYLbGIKn0fKdx7mQFB8fYnXoyT47WPg
         PnYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHGe54cdB41kcxObOomRr2rby2A9hAVU8OqKhy+NqvE=;
        b=Li8OU16G/52UcsFwQtqTcDl8xkUx9oAWpxp2yUbEvkxqsRUkxboHMBaajdGnmz+jmO
         TvHOK0Gq3tyf9anbYcNxINq/FXCZ/nCg54q6Q/QJE1PkCelPdSS52Va32hRkuIAzarQ9
         ul+UegVxsp76ae6GNmvWoktRB5lnk2PPAtyURZ9wmV2vTDQD4alTMEcNDIGrH4JRiVWw
         AefD4ZeFle8XAtDLe/Z49ONWI9LXpFCkXwA4RE1PlZQzLbCZ/kB2NnpWgxkpNKwz4r/d
         J0VxKthHDhdDzQn5YvFAuRhmNtuOdossJAgvv7XHK5HoPc53bx2SLvp9n1ovHFo3npBd
         dx0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHGe54cdB41kcxObOomRr2rby2A9hAVU8OqKhy+NqvE=;
        b=pcmkxeiX8LSu0OLyitjuMdEDqbjZ/v0JkcfNvqdOUjHrbXOvngkM6yh8Cfcmc/0Rv9
         7/JBhs1HI5ZpPfjOcUHL/XIf1WBd0o1UFlG8W0rb1BP6qatRqMOaNfCHu56cmFJjo+V8
         GZExHUFw/xL7bsy7XAlr4CZZ0n/7YcgKovA//SHZMvst99/RF4V7LPVITa24DhvfI89x
         Xa5QuriM1J2sZFjgZI7yKSSrzVtmR3uIcNyyjzkhZdPvnFsjwVExobo3+43VG6JvjXQP
         HZyUBhqd+1lAaBPpIUhmuA78SnzguxiUNwg8h4lBt2aR9bCzNdb9LFTpXKD3ePukuemG
         yWog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uJ00NdD6TBja0YVAhDek3yoG5bbQDbw+BBEDKrhrwAvvTyFaM
	+Dq4FK4IIyzFgC4+otLwmN4=
X-Google-Smtp-Source: ABdhPJzTQdcFf/PNXQuKpObwtAPohM1Zl0He3UKmTrH4dok/QET7aiMCxt2HhYkqAEkGakspsONxLQ==
X-Received: by 2002:a17:902:8681:b029:127:9520:e191 with SMTP id g1-20020a1709028681b02901279520e191mr13111838plo.56.1624702183493;
        Sat, 26 Jun 2021 03:09:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8bd4:: with SMTP id s20ls5326841pfd.4.gmail; Sat, 26 Jun
 2021 03:09:43 -0700 (PDT)
X-Received: by 2002:a65:44cc:: with SMTP id g12mr13400811pgs.227.1624702182981;
        Sat, 26 Jun 2021 03:09:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624702182; cv=none;
        d=google.com; s=arc-20160816;
        b=rjoVen4sLhSDpIMQjizDHZue1vjh2yfe/eEtVYfrr0OMbFheysmNiHWbL5LB5N49wo
         8VzLNVr/ZSSZh1eawBt3Hr/9vEB3eKwUbX95sd2AO7+TnOIs9H4btvZh7R80KiY4B4UP
         KzP9ZA7gB1as0fTnEzAaOWTSxTy6ZMkv1QgV/PkdH3Ld0JTeOpptVFcSRdLEKfo37mSE
         uxDmsvQxSbn9vqbfM0VluJK/hlePonndEqLK4a+6pcky38FCjIwFB7jHcR4mcYvdVdpZ
         qHUJJJWCRgmRApnhYOUP2KWAfShTxlJm5JP7rx2zN9fvS51gm3llP2nVQu7e0V7SLcbq
         uh0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=OBEd1liD/TmfuiGRpQAJF9DRgw6eXsnCIS5fM59Iwz0=;
        b=pO2PuChW37P3YVvj9Wlaq/U0RGa0/jb6EPpS8Y0WCixvixPli0NtPs4QuSgWI8AsfL
         B5CAqzzK0QokQB8yzRohLfCC3GxPovIvctf+5Su71ZAuUQyO0NjjJuIwPt8OOTpfqXXd
         Z4qp9vfiu+CVRS1xP5f/vAAuFMT94DL3Rjy2QbwcsFAE+JqRBxY0f+HAYtI5pDIAHNWG
         ekPj1AaEMuVWh8Eb3AzrsrcF1PHy5ch883AdwpPXAfgh2qCpOMvd2iu5epho6ru6XsIs
         3cS2MxqaYpCLrzaifRtwf5Pl/ix4DNYaSXl5wN9CyJxkYnHzPGks2euUBN31HQTOR6j/
         /TXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id m13si563118pgp.4.2021.06.26.03.09.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jun 2021 03:09:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 4491aa219bdb461f8a170b3e63e34f03-20210626
X-UUID: 4491aa219bdb461f8a170b3e63e34f03-20210626
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2140284229; Sat, 26 Jun 2021 18:09:40 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 26 Jun 2021 18:09:38 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 26 Jun 2021 18:09:38 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v4 3/3] kasan: add memory corruption identification support for hardware tag-based mode
Date: Sat, 26 Jun 2021 18:09:31 +0800
Message-ID: <20210626100931.22794-4-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Add memory corruption identification support for hardware tag-based
mode. We store one old free pointer tag and free backtrace instead
of five because hardware tag-based kasan only has 16 different tags.

If we store as many stacks as SW tag-based kasan does(5 stacks),
there is high probability to find the same tag in the stacks when
out-of-bound issues happened and we will mistake out-of-bound
issue for use-after-free.

Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/Kconfig.kasan | 2 +-
 mm/kasan/kasan.h  | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdb4a08dba83..1e2d10f86011 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -169,7 +169,7 @@ config KASAN_STACK
 
 config KASAN_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-	depends on KASAN_SW_TAGS
+	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
 	help
 	  This option enables best-effort identification of bug type
 	  (use-after-free or out-of-bounds) at the cost of increased
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 952df2db7fdd..f58672f6029a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-4-Kuan-Ying.Lee%40mediatek.com.
