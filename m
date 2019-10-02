Return-Path: <kasan-dev+bncBAABBP4B2HWAKGQENDVCBOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 778FAC4797
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 08:16:33 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id b17sf11726172pfo.23
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 23:16:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569996991; cv=pass;
        d=google.com; s=arc-20160816;
        b=cD+4PeIrWJq8VbN+klbucrp1vXLCRw4yWgybX6Roc/GZ2mnLOkzGYtQxHv25xRbFuZ
         hEkMuerDRe8TM+HSG6aeiKzAP7mqht5FpSzBRBTRuizkmyiVyKEKLpK+uFBwpvtYC9t5
         YZ+HbfF4CGmfQx3jHka1XhAXgnfCK2aTdd0rW2jOLSmq/5zvQE8UIl+3NYIA6FV0bey1
         N8mCYVEJ34/mWxhI27HCH8M3muipgMBWXfFwHQ0o2RTJSecRjLlFCEDHaRx0Rr08hpjP
         +VKZyMp24IUoser8Iho3zWU5Hc9XjNh2GVkjRZiTF6Bayzd45IH5KtvnkTyv6GgaCFze
         5LpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/64iUCZizaOSOPSIuaLDQf9TGVym59vNwgRTXw0yjYQ=;
        b=TWqvrJP2hY3iPC4uY//J+9UXudiIjnZ9A//pFI4Zg5CMBn5TiPHdWgffZvZ+zGI8os
         HsSlJrpWZMluzhJx244KFNcybjYaJcEf3u46R5Qb+hB5idphKp8XjeSg8dF9Antw98NR
         /MtgX0GvXPN/N9hWs3DOgVxvJAirEkoq2M9c9BZP7mxqu2rJbTwXLqdZW/HkttTS3YNm
         aD5ZHhv/jQUK2MOlAcDWe95uoCdkdHqxV+EItMuK+Ng/vTWUQgJ+uVdwPg/gvIh+/zhW
         pfCe2KOF8/itcMg/Uu642Z7L7hGRLkOD417nV7ZKuKSL3zJy96c3NSN8mKX/hN0U/Dyp
         nBdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/64iUCZizaOSOPSIuaLDQf9TGVym59vNwgRTXw0yjYQ=;
        b=ccx7ry8+st4Ul0ZWVLFURcTBxucDuwDns7IHnnr36UWMRafCzyXSn3u5fExWDYorI2
         9vCHTWZlqmlD7kjDrHxHCTm4nu6T4v2/WZpOZL2k1BG+liTvawz9BvYTQ5qGiW33jqNN
         i3lybpIaOFCSZerXUXqMMZ15mYziADwzzwbbybAyUCcoYy8VuUQbqwpk0jBxXGjvUsb9
         SUkFbDjSsgAkON4BYi89tJEqTZuyfTzTu200e0RwtFdDFW6GTcM6D8Y1KxGjIhkHk9MM
         OjnXiFuZf2lGCzBY7K1UsB/9kjyy3Jz1NWpbuA0GdefhaS1rtokU0i9Q5/n4bQs6KUl3
         2Wyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/64iUCZizaOSOPSIuaLDQf9TGVym59vNwgRTXw0yjYQ=;
        b=PAeYT5TMm9c3S05ITFa2KVQweL2KLM9/GgOBamXRCDeJMQhR39Kr9OTSFhbAeaM603
         NBT0RXRREVPH7nZLG6hyydSXUOoVidXw7wDw9kpT3vcUdzODfBCXtANjvKKYhAcl4pZl
         gc+j4tfYK5IW3wS77MGLeGBKR4/RG4MZxMBCUnfuc3BbQnhs/S8xaagJbUQMSai7fAkW
         K3YxfllCrmyyzlD2TWXc+hbEjamK7FFE6SOTIc3OR2bScLtdwZeFcCpU7wLfeAt9iPJv
         0VeZpOiTadoD8BbwpBCifXM747fipFgLr9Ju3gAq5btg6lKDnf3qC2PNjS/UDsAbRbkK
         AdiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXE09DSvIaneuki4nlRP4l8hbu76ClYFa2i5Dfa/N9JZ0mbYgzI
	M7/wCgGHwkm50XG/AJwoWGk=
X-Google-Smtp-Source: APXvYqyhC4XxZzlGR7XAwVFIGlU4Jvfl3x1Xxz2/JGYoVjMAUXvoXgl16LWduIC2qhGTZitGHgK/Vg==
X-Received: by 2002:a17:902:d685:: with SMTP id v5mr1881247ply.15.1569996991653;
        Tue, 01 Oct 2019 23:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b46:: with SMTP id b67ls356570pfb.8.gmail; Tue, 01 Oct
 2019 23:16:31 -0700 (PDT)
X-Received: by 2002:a62:14cb:: with SMTP id 194mr2831322pfu.192.1569996991428;
        Tue, 01 Oct 2019 23:16:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569996991; cv=none;
        d=google.com; s=arc-20160816;
        b=NMgc+uo/hL4x/CdhdO6aQn9BbqrfsJjNWUR/PigoskJTJuFITaNvzwjdJH3NnEkWqQ
         Khg0nTFpEuOlSWY//YLGbvi+MlbL5oQJ4LVawLwNb3rNjUWU+YqTN593Qd/o8mKWibH1
         Uj3MwkaX6opN1thNtAobJVSSslHwnlAzY/02cbBlt3fzGJ2xrrys4lYgze6fycOf+6JQ
         vkZbox1uqFDvlRLCx9wwfY844/ujG1MkkcVjffMdEmjSkWFUE5S3mH4DlvrmCXju/RO7
         JsbMj99aznV+7PuMkhRAZw03eL0Oolu/KjJfBHHGlb6b0IOaPUZUzuGbc2s4IMb1bJQK
         gx2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=f+V57mIuxcU3eo1NssNNzU+w/awJb4VMkV0TFNU8Cyc=;
        b=JgCEvtcvGl8v2WQhtPXPcKejHIvqeD9R+ANpmRWVwgdyhqWB9S5J2nuJ+htJkGngAI
         sFOMLHAxqUuEuuSOlFSe7d6kcsGuhyAkeDq7LXVjw1+DM7zgdd57kBPD2rJk0XnriRrE
         Oo71ZVs0b5p7zceMnklxT0B3WDbhAamiAAHBBveAccGKBqgiUYdwW3zu1ssx2cJ6eB03
         2G/MHLU3xfn0WYacVzY4uE+m3KPOOmAvGuW5iMhjAEOKboqT/5cba0ZGUJOCmQ1B22RI
         fU4O32KNgtXLBVje3MgvDO0UINzzYhCCo+lmHdynMp/d+SZYm8ROPQmioC7ojhwa3xIH
         4UjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id h1si207483pju.1.2019.10.01.23.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 23:16:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9260oNT065606;
	Wed, 2 Oct 2019 14:00:50 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 2 Oct 2019
 14:16:15 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <alexios.zavras@intel.com>,
        <allison@lohutok.net>, <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-riscv@lists.infradead.org>,
        <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v2 1/2] kasan: Archs don't check memmove if not support it.
Date: Wed, 2 Oct 2019 14:16:04 +0800
Message-ID: <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1569995450.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <cover.1569995450.git.nickhu@andestech.com>
References: <cover.1569995450.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9260oNT065606
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Skip the memmove checking for those archs who don't support it.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 mm/kasan/common.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..897f9520bab3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
 	return __memset(addr, c, len);
 }
 
+#ifdef __HAVE_ARCH_MEMMOVE
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
@@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
 
 	return __memmove(dest, src, len);
 }
+#endif
 
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1569995450.git.nickhu%40andestech.com.
