Return-Path: <kasan-dev+bncBAABBE5M6CVQMGQEC2G47LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 47443814418
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Dec 2023 10:02:13 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40c58a71b7csf3918595e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Dec 2023 01:02:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702630932; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQ6L59m7/kkaK3JNmIf8ef3xygWpBhAGA3TpLRQSQQLea2JLU7le7ZexuNJLUzlVy0
         Qk4UO5rRLS66bZ3ci9Y4ynxYj8ArEqKidxbYJiuFgNDQL3qUmj7hSuxCkb3XANaDQRI6
         pU2y4suL8rDgTQZ9k2tNshkz0pQI14M2M3XvHq7PtU/xcCxMnqsSRy3Ypzj9j9VWNqyF
         2AR2VmXCMDy2ViOeQ18m/T0qTL3VyAO8ZCXAH6w6E+FR81p5sb72iL/Es9n152eIHTdF
         Og+6Il7FntCa1HrxTPj1ma6tQviUsz2j3/J5F0/4x5QC0huzpJgFiPlMR7DuxoME7wA9
         mcBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Symnwh9OjHCfcpMUsuuW9/0374hHMyJk3sFyEu7aqdc=;
        fh=S6fFz52YCbsdznBjLtCSQN33hfexsgsFtw/Q3a/cb80=;
        b=XvzzoAsG+Phxggei2HReTa1uonrkK+w2XCE2NI+0843FNW+rhL32A2a5sgUhnhhFwM
         hjCHsprlati9G0R6TyUN8jxw6Fd27uKeeXHhiekBUH7yJ+RiB5x/fsvQrwNvDBsyJ3O9
         zy3lVChmnK5X7meM5CesjCSOPuGBQw4ID3biTHquKpNpiuJ4RXLJ/X2NOcE6AWzkEcX1
         954Ce7/gOKcI2rIPq9SqoY8Ciga+ajc+L/FN8wNKjY3LhKQx+I/MU8IXmtGGEGlW/F1i
         99QTXLBbnJuo4V2LC+4E9S9uvjAUZ/zaJ0iIK5zIv+xou8frKqSqhfoyM52o9yNCmBbR
         JGow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WvhpFINa;
       spf=pass (google.com: domain of aneesh.kumar@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702630932; x=1703235732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Symnwh9OjHCfcpMUsuuW9/0374hHMyJk3sFyEu7aqdc=;
        b=B++ZztU30Z2LVU8XxP86H7stYAWKHMEiQE5D/XoiLDGxJ/KKGRaN5/A/TjivOGSLhk
         oUcLeY6ASOultQVgi6wexqW6zLQXG6HFPTMMQirn85YJf4Qwbsb9d8UBBwB/zkm18h5+
         leyRSErtv2OZ4KVNkwHIAsROsN3RoahhDRUc3Op6JYohxhM2GjCQjutqjEDC4Rq1jXQP
         K+ZruuyOQ0B5RyJo0Lojvn1IsmOv8lwGmea8lw4VtCCmaE38UVhhd/w3WLduTjOTBL1Q
         eL0KUyGugQz8EvoUgjfrcjyAgmRJldSx1JRrzaAcmTMaRfUlLvwYQEh3yxqfM7iV2rf1
         phpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702630932; x=1703235732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Symnwh9OjHCfcpMUsuuW9/0374hHMyJk3sFyEu7aqdc=;
        b=YH2BI51YuyYfEk9D0Ve4xGoDaCLsVQ5f4cZ3Sdwumhb/ydkcKuOzfQpFyUz9kGl29R
         jkQ+dpqFdw51GQAkP73I/UdsDYjGmRnKBF6OMLNZdOAVoV5sSlQnRkiq+ekIpdztirq9
         4ctAfLQ5XasJcV4IixcbT/qccy42OvBMyU+7qgFhNbrGk+GxSwrUvVhvp3eVD7qiqS/k
         52jnyDEewyYleBJ2lygr79ZZ44i6XKXgGD5EOqpBdCP/p5UFigmEiqhQQ3r47BloKxe/
         9rPn+UaVl6z9WOSrniT3lAjX+UWo8xIFAK4hhUorJpd6nBlAEPdVDnYAu3FkEomJRuRG
         iWOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxxWO4zsk59YmSJxSTpZ9zl79bJPMi8Cr9ThqnUOYMVCSw91LCe
	o6W8lAiRgYVeQbIFe+fRo4c=
X-Google-Smtp-Source: AGHT+IECpO8ETiDqlOAb9N2X2A+qwvS2h4QOlEQbdlCLnvQonE57aRG3dn3MrkA5BSU95Sp1t+ZtcQ==
X-Received: by 2002:a05:600c:4d1e:b0:40c:2987:17b9 with SMTP id u30-20020a05600c4d1e00b0040c298717b9mr6497752wmp.94.1702630932117;
        Fri, 15 Dec 2023 01:02:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9a:b0:40b:3977:87e3 with SMTP id
 bg26-20020a05600c3c9a00b0040b397787e3ls331196wmb.0.-pod-prod-05-eu; Fri, 15
 Dec 2023 01:02:11 -0800 (PST)
X-Received: by 2002:a05:600c:746:b0:40c:2c36:2a2d with SMTP id j6-20020a05600c074600b0040c2c362a2dmr5991291wmn.102.1702630930714;
        Fri, 15 Dec 2023 01:02:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702630930; cv=none;
        d=google.com; s=arc-20160816;
        b=ydOfTvSWEQz4zwlVoFDW3QFQzSzvzAWAFWx+ngMDcvuyFboLZ0xMXGx7/hgiIEKM24
         fml7JXDHPuTPgWT/SNBgYNJGKAcFzXAFjpRtrmTWGLzINmpM4iz7KTdBFUIK/dp98zut
         Lpm5Exq2LeANwUpnG6Qr9UYgdP/Oa+B0dTfpuVWHu7Wvov9u5qY9jxCLa/s8Y+VohAPD
         1QlGKVRBSusZ3Lg14QPg315PluV0jBaZ8KKoBOijp5Fhh9lGQFBCkqcR+xGDJWIVPKad
         Sz8QgChaFEbwXej4/qIce3g6l06et8Hmj/xlCX7ctExsdNhWJ2Y6OkYM9nq1XxSZkKlV
         iU3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=GxjorUvjVfFdNsGcr47vxy9wVmeBkGFklppC39F4NSE=;
        fh=S6fFz52YCbsdznBjLtCSQN33hfexsgsFtw/Q3a/cb80=;
        b=mcMwrQ7JLW0l6v1OG22X3xtZMLQRYd/Uvy/jAkhEntTt0hkYgWP48ItH1qxeO4APx3
         lw5Ul0WVCmsy8FU0G2jHADm+CH6juzNmONQL9WhudD0JDZYhvWhWW33m59+vU/A/bRYl
         mKCr/kW6Twu4HzbyDL19B2jiMzTXYzwFQqNX8xY5ZjKum079NQdsjVUkR6VcuOh/S2hy
         zCSM6X87Nxl4hMyjKWBhFahOLJGdhjDen5S7GZZvgTjvQZrwX/CVDQsDKpybJuWEVzTq
         QkSyH8p+0bsz5JvycMYUf1NKdQdfb1IzwD7sLjgzYdz6aQ+nf6jQWqK785v2K8lgPoot
         d1Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WvhpFINa;
       spf=pass (google.com: domain of aneesh.kumar@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id k21-20020a05600c1c9500b0040b2ba73443si29884wms.0.2023.12.15.01.02.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Dec 2023 01:02:10 -0800 (PST)
Received-SPF: pass (google.com: domain of aneesh.kumar@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 4E897B82541;
	Fri, 15 Dec 2023 09:02:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1B06C433C8;
	Fri, 15 Dec 2023 09:02:05 +0000 (UTC)
X-Mailer: emacs 29.1 (via feedmail 11-beta-1 I)
From: Aneesh Kumar K.V <aneesh.kumar@kernel.org>
To: Nicholas Miehlbradt <nicholas@linux.ibm.com>, glider@google.com,
	elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: Re: [PATCH 09/13] powerpc: Disable KMSAN checks on functions which
 walk the stack
In-Reply-To: <20231214055539.9420-10-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-10-nicholas@linux.ibm.com>
Date: Fri, 15 Dec 2023 14:32:02 +0530
Message-ID: <87wmtfu9dh.fsf@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aneesh.kumar@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WvhpFINa;       spf=pass
 (google.com: domain of aneesh.kumar@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=aneesh.kumar@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Nicholas Miehlbradt <nicholas@linux.ibm.com> writes:

> Functions which walk the stack read parts of the stack which cannot be
> instrumented by KMSAN e.g. the backchain. Disable KMSAN sanitization of
> these functions to prevent false positives.
>

Is the annotation needed to avoid uninitialized access check when
reading parts of the stack? Can you provide a false positive example for
the commit message?

-aneesh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wmtfu9dh.fsf%40kernel.org.
