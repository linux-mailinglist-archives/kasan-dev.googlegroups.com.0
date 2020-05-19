Return-Path: <kasan-dev+bncBDGPTM5BQUDRBXEHRX3AKGQEUT54W3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4473C1D8DA0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 04:26:37 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id l14sf7677337ooq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:26:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589855196; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJV/c425VzQKEi+dNgT6ICj3PUIscKBVfnWLMpDO9/0AgQr4R8xz5W6RUUDQsZuxMB
         ooPBWI9XFg1Z80MBVQvzVgOmdQeqXaaJK7CLJMT3x3hhBVy2WFNxUM+/igxKm7qePb/J
         gi75EqPKb866pgXgbpj0Ua4oxAWFNS4TDvy4F8xDWg+4cAONXbNRki/Pc3KYFinyvCYe
         +JOiwYK1iNnvjjjEd9Ia8+rbVd/sIPQAXSBRha8MYBkB05GqAiZY7maQf6CJDsF4rq8b
         stRLWZCPNOSbMadI4Pi9hY6uJViyZWzpj7XSCf9RCMjfHK/yY44kTeOqFkaQaVIJeW2I
         AGoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8630DGI3C8SSWfZqNO9TUFlzI6Ks8k+CsIw6oLHvzBM=;
        b=hr+11GYqCk2tfgcWeItBbGXJMF/UKX3cQf5oSnWfm6+tD+KUk4L9mhjbCnGhGiIj7W
         kT9JokR7u9KhHZ8V2ZAYRvh2Vk9qaCBqkPr4gpmdiaong138O1XRzyiSxdhtPUtDV/Oo
         JebxJxxhWsT0jgZFS6m0GTHrVfbfTaeyvGqcHk17QY9a911M8fHdKDD3pt7IhMSNth5d
         eqekKg2EVlo8CCdOmq4uQwwAQtcxDuYC1iQGufUT3alnBRphnDTDuwH0qS/W6pysDq5H
         hqfQZAOwT3yT/IJmzox+hGCsKzNZr8h0lYvZtSAbJXrLsyF/+ZrkxpJuMb+JwiOr7Nx6
         ts2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="CwEr/lgM";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8630DGI3C8SSWfZqNO9TUFlzI6Ks8k+CsIw6oLHvzBM=;
        b=jX9rxKt8qtUw1YfS+cmpUD1QdTlFq6oiVUaDjq/98fXLTbQnfzm3raoQwmDkMabcv0
         kYCwb+FQ6Ckokb7/9PJeT3orOHLtMoAvdcXcUM220aZvTIadZrVFrIRnuOBygnf3WtI2
         0CzwPHx+jTyM8NrjvmJ3EUJPYFpNwVRpyBQfDYobYgdcPPht7Bz94CS1RFLR8WcO9I1X
         FFC39pMY2tw1pXZ1+5LHGk+cz+aCfHZCPTeIO1afrc7x6+MrAjStvdTjOiTeu712B8O1
         NscdljpwPy8FOXd0CJI6iGOdnCGH8QEfNmkuYNstjG1STwy6E2B3fCzfERUWijy0xIrc
         a1iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8630DGI3C8SSWfZqNO9TUFlzI6Ks8k+CsIw6oLHvzBM=;
        b=rekmtOe7tonVAmqrlV7Mahw3zw1lrTXT/FE2JpSOPPrzWYJLks77GMS74UwkYNsslc
         ENS00EbuT80xAfz53IWMeAyic8lOsbGsYmrt0Uj9OXCRg9BgVNA+WqoUBU9pE0OH7MVH
         L967wE8HL40vJUP7CLVyMDfpeRk2tQumQ+XrbH3ChtmAuc5aQMi8A2gVnJzzito0gp1y
         CnUTrBSLGM7EHDDGQpW5iddNZ7FBplpUSUT1sPFlCYyYsvZ7iPbWet+z8Yn8SBf5KuGx
         EOJrdTESyW9jX9VgOpKx8iA+UsFSd1Mrde5l6myVKZm0iqOGBiSoZvy8DfQRC+P9uKN7
         0UNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OzOQtqDn4zbsNahoAQsmBJ4uxvMvcgRLZ6/yYyr6FezyFPMJT
	MK1amE6hdCQMSed0YcUg5u4=
X-Google-Smtp-Source: ABdhPJwX1uzUNdXptptk0IjaBDvEH5JhBupY+78wXXHAY/zBrSK+jCGRgzvubwmPuCFydXEzrVtsYw==
X-Received: by 2002:aca:518c:: with SMTP id f134mr1740454oib.6.1589855196176;
        Mon, 18 May 2020 19:26:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:10e:: with SMTP id b14ls1047798oie.1.gmail; Mon, 18
 May 2020 19:26:35 -0700 (PDT)
X-Received: by 2002:aca:4889:: with SMTP id v131mr108071oia.83.1589855195905;
        Mon, 18 May 2020 19:26:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589855195; cv=none;
        d=google.com; s=arc-20160816;
        b=hi1u/yTk+jVUO5omt6R2tZIp1FnPndBIcMH+yDqnuxP4741Rp4Ah1TYrlRP2yXTrxX
         gcnGC6I7Wc12no6d33bBdkKczydwnGxNzRusBFNSWeQ8rAxtdE6Ex0uw4Vr8mMa+no7g
         8hniNZVDmLX/qFVV3r8mkIs9hy6s8GrSE6LEIA1oX3G1U49uU+JNXJOQiqq5okSqalGy
         SWvoIlkzl2l8Yx4RuIkA7nOrlw9Zxon6+HlePCv7Vdm7WNeZMMe5eD1rQfdmzgj6i2jM
         B5IJP33WvI0RJ5Elc0mW8ojbuMFx0VjXoiZ5v/USxnXfu1JICs/q7CNQsId1gEBiY2Mh
         HOeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=+1T6h4ks8LG74RTkqrEoFP7s8tKRSn96p/OdYqATlnk=;
        b=FXi2EFd36QlDm+OdcjMxUdOYpwynbwHHUFhh8wqwljbuXbX0d9xrxWL8Xg76VdqKLJ
         aCn+i5pf73m35DP7TcnQ09G9twfM/Mv6fyEfvJaG2FCYU5FRas5lybyXjMLlc1wmhOVT
         +Y14FCgSMRrtvlPE0s197Y4znWi/oChUgcO4+SDN3MdHRUYOfQog8O/tralomy98osMl
         GyBCNAip/I5vWZdUxKA2Lk1+Dz8DjjwgrGOIZNpIa5Qv9IDlecr3khJMhuO6iFTuGs+P
         IHEi8MQVV+bS9TNAdW+nETQ6veVYs45rJE6+gxYZsMdnzs1qjsvZm7VZTRtdk7PH2TtY
         jNSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="CwEr/lgM";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id d4si618727oic.3.2020.05.18.19.26.35
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 19:26:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: c0dc6b65fe6344d4b38801ea0859a674-20200519
X-UUID: c0dc6b65fe6344d4b38801ea0859a674-20200519
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 588687700; Tue, 19 May 2020 10:26:29 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 19 May 2020 10:26:27 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 May 2020 10:26:27 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet
	<corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 4/4] kasan: update documentation for generic kasan
Date: Tue, 19 May 2020 10:26:26 +0800
Message-ID: <20200519022626.24305-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="CwEr/lgM";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

Generic KASAN will support to record the last two call_rcu() call
stacks and print them in KASAN report. So need to update documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..fede42e6536b 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,6 +193,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
+Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
+and the second to last.
+
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022626.24305-1-walter-zh.wu%40mediatek.com.
