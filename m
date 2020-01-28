Return-Path: <kasan-dev+bncBCMIZB7QWENRBBFIX7YQKGQEPJZEQSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id BCBFF14AFC8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 07:26:13 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id w11sf832099plp.22
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2020 22:26:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580192772; cv=pass;
        d=google.com; s=arc-20160816;
        b=FygVv47VWnAowMcm8UpaL9ekVerPXvPBeD4FOtXPiQtw1ElI8yvkZpJTjMQFNtOuyB
         bvEpcCpW0PqqUIBQnulxyWlaWqlKcPRNEuqvTh7RVl4Aj7qy+ow/IaO+gHHOmocghG7s
         HkFaYvyZ68bCIb4PV5YGN7JiQijhmTJkPOJxLaqybfULdXmW9y4FpBeJCpOt29E1YXCU
         uBOKb9Px0K8c4931hRhQyyScJ34njlLE4ntu+P8xgP+gZ6wMnczWRfroCvyRrU9mMRvE
         anJ6atG5iPRfE1IJAtYiODc5mwKJUOaCZ+9siS9vzZRxeNi996o47IDT7WI/0ZMO1qQR
         P1Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vcQNobQeZO79Oe0wY5f9G2YRHyW+hb9/kDWkETRLKSQ=;
        b=hsL9zqO2gQT+Stl8ueqgYIsfbjeFbrskfdxu+lEBPF8kR5TdkGgDpQRrqyLCfcHW/z
         rnPbH02CdW5pYlk8jLDrn73OouzHoOhQMGFeurGL5S/fBnLsqOhwQNl6d54wr+Z8OTD7
         QteCKWich0yLa+EkaLEu7tGraZ9B3SxzjdIm+dAC1Na1t2l1bi0gpkIyiPGqYHtWbSku
         TQvlZuzYj3Jh3uvKKuyTYA6c3VfRHA6gtnCPQROye7uZ/l7u+cBd1dca9G5bgBFsK0+W
         AmHjDF6ssLbCrRbPGCeolkekYtWbv82cMNubihKZsR6tYkloKq6w5USa7SmqeYT8QhmZ
         f8bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="umPiQ/Jc";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vcQNobQeZO79Oe0wY5f9G2YRHyW+hb9/kDWkETRLKSQ=;
        b=OquBszxpc0bD7tp3yG1qKX6Mjy9nKGN3PP2Q6P1IcLyyu20e5zw0SXMiRLujqI3jt7
         qcSa8MQWz40Q/tlgEAJIOZ20f2cUHppRNiJEtYGW2sHzSjWkeuTG8qZsain8VPI9Ldnb
         Cv6iCKPUWnE2Q2f8TLPGbzJb66BmGDg1/zxlR7xcn6V4joUPwmlqJX9zA8SVHmTorTBQ
         F5UwLblpABTxE4aFfmE/1gYuG9FKAapeOcD84uiAXeArlVHp6XYhmn1lQI/kSa08MkPu
         hHeBnti1BhHInVGmJJdw8vUro0lZa94A9DQQW1mBPz3+96A9xj16me0Y1X+3eH4dv+Pp
         /rYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vcQNobQeZO79Oe0wY5f9G2YRHyW+hb9/kDWkETRLKSQ=;
        b=LzdzYKNZfd6Nt9txhpMLmN3VnLsK1VUV1hrqmaFtLoiC0yDdNO1UlD2f2heFsiWfYT
         6t7Hu5E7OXNMcuDYyVXAwU4Y/iGl4vfnnHVBfgzahJRMcyXJuQHTms/3+EdcwGSBmIem
         hEvlYE/Po11ODkB61X+5w/KLfRttUMTLjEiooruwmI7a8Rk5qoDsMIOZU+koJ4jZalgS
         dqxGOQzUKlDJZWFN8BYZoJjRSYoVgUVjrPQGtPR9OL5EwmTlpxoWP+K9NaP6WOTPQlSi
         wVGkn+gB8DjvevollyuieY/VmFkhd0HTBvXFncd/ADxxZamcZbBOWX82m7Y8kfOoqTyh
         0x9w==
X-Gm-Message-State: APjAAAWiWhRTqG2INCx9v7vA1DUdDoLECvLEt24YyOacjk6zcOG4JTRH
	97hy2h6h6N98xji9lqxq1/U=
X-Google-Smtp-Source: APXvYqz51wACroFZsyLI16XX+IqnJAY7zGi1Rh6AAt9PZM68LyI3MdTH/Z0pf8bDuK2WFl+NXgMTTg==
X-Received: by 2002:a62:1615:: with SMTP id 21mr2430292pfw.84.1580192772154;
        Mon, 27 Jan 2020 22:26:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9f95:: with SMTP id g21ls5417823plq.5.gmail; Mon, 27
 Jan 2020 22:26:11 -0800 (PST)
X-Received: by 2002:a17:90a:858a:: with SMTP id m10mr2916068pjn.117.1580192771714;
        Mon, 27 Jan 2020 22:26:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580192771; cv=none;
        d=google.com; s=arc-20160816;
        b=zzPm+AyLT6OFMFURKx+oBwG+nMWQX2ADnWtErerIdJfL+GhdpWKRe8cpMHx1UWjh8z
         DNj7TQFd33pmJ3ai2uApCLVJhK+QGOLlYrAu3SK2zsdVf2+jNSuBBGbot3pVxtgpYQCd
         YnEh4SXjvSOWPK0buJUxmBC5ZumalajXPB8Z+QJV9bLSHzmKWDNJZmlqEiSD9NaNcM7+
         HnqvozmToBKCTiSymy6vqW2w9a7DoBYkpmVFrlMLpXQVE8GLDSEx3EH/Pse/g016GFDV
         qDJYYTWdABUFeCPdx+uSqADWhekJ0i+Zk6++0kvNzg6Zu7LICUa88a/ThaBQRAIJgtA9
         ML2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9qvkTLwVKoGDoIQ0qZA+h5T3eIEbfaZcuduwqWx0fOQ=;
        b=vtZRZqGH82pD/Jd1hlAtzj8GqPzOQk4jcJfo/qyhfJmAgRD1+OCrE0EgBiEtXmAZM9
         fXA0wN0zQmMcUOCRmb/kTHwfsCO7fowaOsSTAINoMIMGGGDCFWteIJ0cPGpA9sR8RHV2
         W2U4cdKpa+lmG9aGKZskchOPni1sT0IBPS4bDSNZ1TV8qgCxBR2FgW4FCym8JUFhYigk
         K0HjwziGIg8xpcoeqnA7Vio9IipcoCLWL2Yidn8LMoBhE/x9Oaz9DQgFzsrK9JpdHRxb
         uatOZ0qY4A/uOV2qMC42++H4V5nqjtx3MOJthE91k6K2jEDCg1FQgnkThiXyadUAhyYF
         gSCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="umPiQ/Jc";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id c4si660546plr.4.2020.01.27.22.26.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2020 22:26:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id m5so2621547qvv.4
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2020 22:26:11 -0800 (PST)
X-Received: by 2002:a0c:ee91:: with SMTP id u17mr20061495qvr.22.1580192770479;
 Mon, 27 Jan 2020 22:26:10 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
 <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw>
In-Reply-To: <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jan 2020 07:25:59 +0100
Message-ID: <CACT4Y+a5q1dWrm+PhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA@mail.gmail.com>
Subject: Re: mmotm 2020-01-23-21-12 uploaded (efi)
To: Qian Cai <cai@lca.pw>
Cc: Ard Biesheuvel <ard.biesheuvel@linaro.org>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Brown <broonie@kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Michal Hocko <mhocko@suse.cz>, mm-commits@vger.kernel.org, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Ard Biesheuvel <ardb@kernel.org>, 
	linux-efi <linux-efi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="umPiQ/Jc";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jan 28, 2020 at 7:15 AM Qian Cai <cai@lca.pw> wrote:
> > Should be fixed by
> >
> > https://lore.kernel.org/linux-efi/20200121093912.5246-1-ardb@kernel.org/
>
> Cc kasan-devel@
>
> If everyone has to disable KASAN for the whole subdirectories like this, I am worried about we are losing testing coverage fairly quickly. Is there a bug in compiler?

My understanding is that this is invalid C code in the first place,
no? It just happened to compile with some compilers, some options and
probably only with high optimization level.
There is a known, simple fix that is used throughout the kernel -
provide empty static inline stub, or put whole calls under ifdef.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba5q1dWrm%2BPhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA%40mail.gmail.com.
