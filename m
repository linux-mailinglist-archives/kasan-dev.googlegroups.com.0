Return-Path: <kasan-dev+bncBAABBQ4GZX5QKGQE7GHHIJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3560A27D0FB
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:23:01 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id v187sf3242347pgv.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:23:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601389380; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZSNV7xJZAJc8aQaHU9wcTtSxEaHvQimrm/MsTMsHjMsjGYl/xk1Fn4StVTa2omiTdt
         Tj2IE7Qz13fpQUn3jciDwttyRoPBHVwG1Zgt6vh0wwByRmGkGeURQVE3PnYPsi4SCm3m
         wxWW3H/rRyoHSWITAPf9AP8mcttwtyDP2uADDzasyXnW6VXyN9UNNqF0s8yuWl3ywpe8
         VV/7VGUl9TxnzYDao8nXsdgqFWB8vjsclElHgX8hidAB+mrL7E4zMxUBGX8q2CukaB0N
         EGMvgBcBRrSi/BhPeZVytVvFDAOnMwup2G3VaqLoc1/7POSBJeDjuC7Ykj2edoAONyol
         IEEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TgDZiwc8EY5oIDg/BEZGvVWDE5MLJBmp070voFGjWho=;
        b=q7P+EQsdv8+ZIXFLEhzOm1Tu53boQGvz/HsWYqT6mFOAr2dZTaVBWp0tHroyeRtOxm
         ELTVNP1IqCUo4ab8IAncPzYqzuWUmb2og/MsAdFdepfSTxqCteqjQdvHSl9MSXl7SUcX
         5d+esrecu4z4N5Cm4AY+x+1C8eDYpIQFfPA6mVyMw/b01y5D8cHoXXXi0c40VcRLrI2C
         dbcrPGtS9dtxwdGexpGp0Y3dxivr4T3WA3dZkIJT6fW5tfQR8LsHI1pr76401ztfoRyP
         WNfzsRDBCkk2Bgr/dSNIXMFrqFxgioKg+V8sdgtKBXsrOqgAiAW7mbEZbN1A0qIObmMQ
         7l/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=NuT4zzrj;
       spf=pass (google.com: domain of prvs=5343bc49e=sjpark@amazon.com designates 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=5343bc49e=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgDZiwc8EY5oIDg/BEZGvVWDE5MLJBmp070voFGjWho=;
        b=BNlM2jl40p8ArRkzhYkidmY3+LXJ3t5Vto7AmKZ5Wb/ZlnT/3Zko3evcVAwhqsqumM
         OTToo9zyjBOnxpC1mkICmAydUGxGWX+/4gRTGH2cbvOFOlfINBpIsESx+xo8p9SGS6aT
         3e/PS6BhquKmMcbfkwZ2sBsrT3DQ6dlRYfsfSrs91UFccNEHYx/sKJWiWoxIkODSNj0T
         Gh3qNGmEPG1MAi5vLqfJ+hzTlOoNZtWZiAS2q7MeIAIcBu/1g+fEpfgnG4X202jNkT+G
         +htQ1aWUf3e3hwzLxVSkmykOGcXNb0YiT3aeF5WcClBdrsR6n86HR7DNbmafO+/pi6Bt
         ZycA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TgDZiwc8EY5oIDg/BEZGvVWDE5MLJBmp070voFGjWho=;
        b=pzdQyP40eD1XuG071K3a31b7j3tTIqDCaBeRJmvVF3wh31+uNn0XIadgrCTmYtSi7c
         fTy7hEcgbQ2nAk7AkRvSfsJM6q4MdlohdgoaW1KLsBajZEW8efCljs46cEKj6/DvjmEy
         z1RLp+gzQVPpV1Dg4nJTd/NWBSsSPaXQtZRvD3WkzuL/6JvsvDNrfsyuWFsc/lRjDImJ
         +m4X9YaIVqUFfNukl/ZJ0rKktKOmyms24yx2NVjaWAK7aF7c3uAFLTaLOd3h5nZwEyZw
         7BMb/K6PNcuj2wod0tZzejqygko5II/PswudIxM8AOWc7yr4E+mLqWJN9fJCjxfOloEP
         sHUg==
X-Gm-Message-State: AOAM53072Pgp0XTSq3sVBXb4T/eAA0VQ1nbLyf3sFb4psIEH36vNUvRQ
	MlPHijmo69Y9WPDlpM7Mlbo=
X-Google-Smtp-Source: ABdhPJycQc3fHzQsKWEfA5zgRGpomjbM8KKsLcgId/p5l40koO4vCsaTMMIHFk7T5/m84yIpPXqsfw==
X-Received: by 2002:a17:90a:f695:: with SMTP id cl21mr2389607pjb.117.1601389379721;
        Tue, 29 Sep 2020 07:22:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc89:: with SMTP id x9ls1490051pjr.1.canary-gmail;
 Tue, 29 Sep 2020 07:22:58 -0700 (PDT)
X-Received: by 2002:a17:902:704a:b029:d2:950a:d816 with SMTP id h10-20020a170902704ab02900d2950ad816mr3368140plt.74.1601389378884;
        Tue, 29 Sep 2020 07:22:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601389378; cv=none;
        d=google.com; s=arc-20160816;
        b=aaNIUej12L5oT1fQrxaPMG9U6yESZSjr/roAoeG/eQpWhmsU653zk/yMX+tAvUxiO+
         oskFGRH7IqeTgotoZUzCI+R92fjDMUwOrWmB+4pXH3uNoc8colYSaLj1zXbUCh1daKrz
         MCx0+NTf2VZy3MY1CBCU/LSKpaaiqLEeuEY0VNrvYdxpHCiRNqNDVV5fpkBAJPUgga+A
         7n0e0lCB4PSLjMAVchE5CwkOofV7A059PEEwktSM54FfJY0CXMxruVCsgZASAvzgtJ0I
         D5lhjxq3mFnOCaT6DxOGpZugv1vwaLersbKut5vFcClF8ZLDZ4wASgzb9bzrF6Ilxicm
         Orpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=JACM4vdUV33y9yliaH0/j1OWR+5VHZd1rr/Na9ivV5M=;
        b=e1jcMTfq/u8MnIz17D4m9dRy9XhiH1TtAMUZwdggLRKKyIgPPYxlSNF05Bcg5mO8Vf
         a0z7sycOg0IbNAmPsijuBAnfpC8iFmhcDm7VEc5nsFG2lg3XzGtnpetbNULUY799BOCu
         EcE4Y/JXdhSWOIJil2l5aspf24LK0jglU+KJKfHT92sAl1DcJ36lmT9gscyJW5KvXEBL
         5pVh2RoTlb2zjKsG0oIPR24CoU+RRIlkTskyrpUk0Iok3HTpCN2eIWM+F0LvxqN3Gj2L
         JGotN8PIG/iACb6N2OI8OqE6hQzCSOTULsoXC+SdHRs5YY0bPeBoB+r4f3m/gqnzlT0Y
         JYaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b=NuT4zzrj;
       spf=pass (google.com: domain of prvs=5343bc49e=sjpark@amazon.com designates 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=5343bc49e=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
Received: from smtp-fw-33001.amazon.com (smtp-fw-33001.amazon.com. [207.171.190.10])
        by gmr-mx.google.com with ESMTP id t15si573755pjq.1.2020.09.29.07.22.58
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 07:22:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=5343bc49e=sjpark@amazon.com designates 207.171.190.10 as permitted sender) client-ip=207.171.190.10;
X-IronPort-AV: E=Sophos;i="5.77,318,1596499200"; 
   d="scan'208";a="78932031"
Received: from sea32-co-svc-lb4-vlan3.sea.corp.amazon.com (HELO email-inbound-relay-2b-81e76b79.us-west-2.amazon.com) ([10.47.23.38])
  by smtp-border-fw-out-33001.sea14.amazon.com with ESMTP; 29 Sep 2020 14:21:45 +0000
Received: from EX13D31EUA001.ant.amazon.com (pdx4-ws-svc-p6-lb7-vlan3.pdx.amazon.com [10.170.41.166])
	by email-inbound-relay-2b-81e76b79.us-west-2.amazon.com (Postfix) with ESMTPS id 20059A17E7;
	Tue, 29 Sep 2020 14:21:41 +0000 (UTC)
Received: from u3f2cd687b01c55.ant.amazon.com (10.43.160.185) by
 EX13D31EUA001.ant.amazon.com (10.43.165.15) with Microsoft SMTP Server (TLS)
 id 15.0.1497.2; Tue, 29 Sep 2020 14:21:28 +0000
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: <akpm@linux-foundation.org>, <glider@google.com>, <hpa@zytor.com>,
	<paulmck@kernel.org>, <andreyknvl@google.com>, <aryabinin@virtuozzo.com>,
	<luto@kernel.org>, <bp@alien8.de>, <catalin.marinas@arm.com>, <cl@linux.com>,
	<dave.hansen@linux.intel.com>, <rientjes@google.com>, <dvyukov@google.com>,
	<edumazet@google.com>, <gregkh@linuxfoundation.org>, <hdanton@sina.com>,
	<mingo@redhat.com>, <jannh@google.com>, <Jonathan.Cameron@huawei.com>,
	<corbet@lwn.net>, <iamjoonsoo.kim@lge.com>, <keescook@chromium.org>,
	<mark.rutland@arm.com>, <penberg@kernel.org>, <peterz@infradead.org>,
	<sjpark@amazon.com>, <tglx@linutronix.de>, <vbabka@suse.cz>,
	<will@kernel.org>, <x86@kernel.org>, <linux-doc@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>
Subject: Re: [PATCH v4 11/11] MAINTAINERS: Add entry for KFENCE
Date: Tue, 29 Sep 2020 16:21:13 +0200
Message-ID: <20200929142113.26993-1-sjpark@amazon.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200929133814.2834621-12-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.43.160.185]
X-ClientProxiedBy: EX13D19UWA004.ant.amazon.com (10.43.160.102) To
 EX13D31EUA001.ant.amazon.com (10.43.165.15)
X-Original-Sender: sjpark@amazon.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazon.com header.s=amazon201209 header.b=NuT4zzrj;       spf=pass
 (google.com: domain of prvs=5343bc49e=sjpark@amazon.com designates
 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=5343bc49e=sjpark@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
X-Original-From: SeongJae Park <sjpark@amazon.com>
Reply-To: SeongJae Park <sjpark@amazon.com>
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

On Tue, 29 Sep 2020 15:38:14 +0200 Marco Elver <elver@google.com> wrote:

> Add entry for KFENCE maintainers.
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: SeongJae Park <sjpark@amazon.de>


Thanks,
SeongJae Park

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929142113.26993-1-sjpark%40amazon.com.
