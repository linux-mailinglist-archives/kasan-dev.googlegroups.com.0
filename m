Return-Path: <kasan-dev+bncBC2OPIG4UICBBXH6TWCQMGQEXV4QRFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D2C638C351
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 11:37:34 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id bo19-20020a17090b0913b029015d14c17c54sf6402472pjb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 02:37:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621589853; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYjYup/NMvdi+nRuaOsKcn2yYtWpNaVcM0b7LuJtWfmqul/s6EzfdciWMyz2Bg8gKF
         QXKzET5+knJdOvL9/QUnz5UDNel61aSNi26yhnB4f2hWjR8VxrmI92E5UGOLSqxJnWGy
         k/TH/bRVICZzNfcuspPQgVEV7LWi9OYKOV1ZJbkEHTINFPrlFlDEDDS28Zenf0FFzrSE
         sUHfMC8Ovpx0DlX+sv93Yfq51XzLzfeI507NFKO6wwkM+iZNXR80w12DaaqzWzFOr/+w
         i1OXPEpAod3AbvtIZucOUXCD4iyCSM4X/Rp17LBTFPDOcF7UO1RlzD0N3QhspIbkQx2G
         NLog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HZLIsScAiTIsIIeks9UHhVXPnMJT/zGwfimyHoeLmhI=;
        b=0sGkW5wwkrh1pHRDt4GVsqOteFTnP9gq5C7Hn2Afz21VECp7uhJoC/3YubWwfYd3dZ
         6fIzcpajW/de6Y9Q0vetXfENomK24cR7eUXOx1v/lnJIEvSuZ/pEtQeztsuODwbrqrvR
         HAf5NAWcaoL+uVzW4lHw0nWYflFN9rK8MuIpHzXKaJk97Zo7SPqr+ApQaWah1MU0uoBT
         GhxSBkYNnzphUO4dfb8y91yfiyJSpXZd0iClEjWvxhbwE5xDmMyXNZu8cUiOxhNrPCfp
         H/aPKN3qAHP6rE8BBvM974bDH2W2CwFzlG0Zj3mLnw2EE8K+mkAaFQ1UgWOVfC9722QZ
         58zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HZLIsScAiTIsIIeks9UHhVXPnMJT/zGwfimyHoeLmhI=;
        b=EGBbGTaQ5DmsaKyD1YehDLA5aWNCm1iSarDn3MwbgjVyzibLU3iTIYpU9Kv0G5+4Bo
         qj4oNam5bWNUNPhE8HvbwjnaDUT/H+Khn/s1na7bNI+r3HPBgt1WgUZfmvgyiMB07Yz8
         yGIV85Md/iyIxQRic/gE0Bct6YRxxWKHPgADQR0OgRXP1d/q99L0Am3MIh0f0/Z1vj1j
         zoDmC9pyzhQI1aYbG3BmH1v4uWxFkdHZ0X1hI8rRxaqDIAKwEv2W0D9an3YiDLn3Jo0p
         8qHq+7aYrOQIRzUnZC8bKZjJWBqSoIa9pt4fg0u7X4DrCprcE8I+FiUfzhyn62R7SsNJ
         Dveg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HZLIsScAiTIsIIeks9UHhVXPnMJT/zGwfimyHoeLmhI=;
        b=RKKqh/hVio9dtNJSYsA0zKsk0GLMzWSX4LzhiBdYld7g64HZoSZe+Md3XHPHFZl65w
         b4bGHk4Wcgo9UZbL2y1zpVvdj8wC+Gg00EJoVr/ZSFtGHjJd+eph8HQytutnSXTp4azL
         IzTdqqoAUIutkC8SQLTDRyXHQApkWyNzJLqiYe5v3vbpnJu3sjbJ4NTUCANb1p8XmvvA
         DWtJJlE4JNusXP+jEHMMMDT9HNJ4fS497xlnw3HfpH0+xxRmOH7qIiBGjNnkEt29bxQk
         ncGDF9OamOotO3gvLLvw3ELC35StZ6GbcChd0omGNm2kQFg4Ebjm15TxjemotsOOubsf
         oVvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316zroU09ZblQMJhuHiE4s2kJq61UJDrybMuQjAVVO6/5T8HTzS
	lAq+QlphR7DBSqPpTuTLWlU=
X-Google-Smtp-Source: ABdhPJzp0ixUYQFYJrrA24Yblu6vKyV1FbiOBnPLeH4t7O6TK88lTc0goTpqBwLRypzQXgpiF+UqFQ==
X-Received: by 2002:a17:902:8a86:b029:ef:5161:99e7 with SMTP id p6-20020a1709028a86b02900ef516199e7mr11171708plo.32.1621589853042;
        Fri, 21 May 2021 02:37:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:314b:: with SMTP id x72ls2821083pgx.0.gmail; Fri, 21 May
 2021 02:37:32 -0700 (PDT)
X-Received: by 2002:a63:54d:: with SMTP id 74mr8918939pgf.169.1621589852437;
        Fri, 21 May 2021 02:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621589852; cv=none;
        d=google.com; s=arc-20160816;
        b=bs86dQ2GXVizMtn7Ul6MMzqUoVEQ39omCNJvRwtUphWsubD8xURhJuQg38t1xsRSG+
         2+owjtAUdT/v67lokm0dJMeP7evMLmeAlU8uvADOAVAcgP3NepOsUb0Al3Ml9fKQE45a
         mP431efHTU9HMWy96SU2L6NCQlb3goFrymSfdqC3CBukPgKLcjUb7IP35TvoO0LIAcDN
         tFZN0h746TYmFffoEK14Vj/bs0rVL462eQ69oXJNoMTijhU5LGS9McwnErIhas8uqYZc
         t54VYOd3ThL73tJpY6DSVc0Ywc8D8BZZxVoIrZQxgxuLHcVelFC8URN1rO2Cvvn1ZOe+
         3ymg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=VJLQEFVvKLgYYb72baQQfD3XS7TG/OMG3+kXImejsh0=;
        b=WkG8Fixbdkgw/3nnkF+46Vhi06C2/xEtpuWDRz6321wVktLC7vi0JjoFR35KG4QXZP
         NXd+msi4yATe7WaVmf2qdAJYtqSIVA8gMZs3bXvkVsFx+2uGQrPiSBCxZczBQ1nJvi3i
         aCbs4aUeH3zCdR2MIc6QKUjswigFsujwjzUVD8vQGW570WqgV3uxE31zNgCAXIv/d/y1
         rAyA77NBPycn+jG4msJqBMaHYHtciw/H0V5Y4kQgT//w652kpY0C7uTAuvyPeEVE92Wm
         vgYar11RNfHJKD1IEqMyB1kwYoikSF5RkiEKOoNm7xduLB79Ou5l4jMJ3NUjxx/WgGzB
         yQzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from r3-21.sinamail.sina.com.cn (r3-21.sinamail.sina.com.cn. [202.108.3.21])
        by gmr-mx.google.com with SMTP id j5si1377413pjs.0.2021.05.21.02.37.31
        for <kasan-dev@googlegroups.com>;
        Fri, 21 May 2021 02:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) client-ip=202.108.3.21;
Received: from unknown (HELO localhost.localdomain)([221.199.207.229])
	by sina.com (172.16.97.32) with ESMTP
	id 60A77F51000235E4; Fri, 21 May 2021 17:37:23 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 611910629110
From: Hillf Danton <hdanton@sina.com>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Mel Gorman <mgorman@suse.de>,
	stable@vger.kernel.org
Subject: Re: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Date: Fri, 21 May 2021 17:37:15 +0800
Message-Id: <20210521093715.1813-1-hdanton@sina.com>
In-Reply-To: <20210521083209.3740269-1-elver@google.com>
References: <20210521083209.3740269-1-elver@google.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Fri, 21 May 2021 10:32:09 +0200 Marco Elver wrote:
>Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
>allocation counts towards load. However, for KFENCE, this does not make
>any sense, since there is no busy work we're awaiting.

Because of a blocking wq callback, kfence_timer should be queued on a
unbound workqueue in the first place. Feel free to add a followup to
replace system_power_efficient_wq with system_unbound_wq if it makes
sense to you that kfence behaves as correctly as expected independent of
CONFIG_WQ_POWER_EFFICIENT_DEFAULT given "system_power_efficient_wq is
identical to system_wq if 'wq_power_efficient' is disabled."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210521093715.1813-1-hdanton%40sina.com.
