Return-Path: <kasan-dev+bncBCL7VCF25QDRBMOUXOUQMGQEMA4Z5LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A2887CCD8D
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 22:10:27 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-27d1ceda666sf5021831a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 13:10:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697573425; cv=pass;
        d=google.com; s=arc-20160816;
        b=uK9Ao0JTa6aQuGEOLyfNRD01wGP+Dh5Fv2sVwGDEUajYz74f0pbvE3loTnl1WM4eVZ
         tsyEc7BfSXVykNxSnr34MO1lo/ButsocuXLt7MnFGr17uWN302o/O6AzY2ASNkO/SHtx
         X3m4eOFZyQ0LecCHnycRcD8Q6wVl3SVFlZ3PtgJ9ny1PSBYqrpbXgILoYRWAq3yLoKlD
         c0CseGYMUsmECPtTQbChJfN/JP5Sf02aU0YC4jFbY0l/oNwRmqro/Yws8pT3bhDmf5cp
         0Q5245BDTdCYSrqt2y8Q5hZuY8eeWauwp13bLCV7tona4CXGF7h+sC3fn9MmyGfcTODp
         biOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BZt8EFWh5xY5+r7S459ryMQGLjiVE7YORF+7Y067k7A=;
        fh=g9SUMMVFv/A5rk+d0/ylcvV2eB1HdNHqn5ghaGlISoc=;
        b=YowaI9o0eBa5tb8T3fEcs3XoMJtFI64XItkJSrHc5BVJ+XVx7HFGlamnUJofPdKuKV
         BM7FBENki4BPc1RBmsfW+wekvnk5oSnDzqbhU66/HzxLFUdKpfITjz3g18U9kj8vVr53
         uO2jh/42Rc/58cgTdBjs+VwggjzRlFIPLtVirpiRwHGLch44FnX4fyF21IAoNEc6zBvv
         TYYr9/nzzoZoYgBOtTKHuJtfw2x80McGeCdHYQ3yfvkdxli7gG/M8Mdqkwm+e4T+4Jzu
         cN0RUyBGnfGZD3GuUU+a95L2OhB+p/iaN3SaY0b3yYGO0ncYYUjm7viKdErl+E9N2lza
         0yrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=temperror (no key for signature) header.i=@marliere.net header.s=2023 header.b="Sd7GNP/b";
       spf=pass (google.com: domain of rbmarliere@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=rbmarliere@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697573425; x=1698178225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BZt8EFWh5xY5+r7S459ryMQGLjiVE7YORF+7Y067k7A=;
        b=fogxcgqVrczVGsQQ/JGYZP8z/gFet+kWmpB+xN2M8xttWcYYKqxGrG6JUjee2PemOK
         pN0lOVgG6jejPaq5d9VR5gYBXizHfsxuOHK5Cuk7PY+dsmdOEr/6JulC4ErLtx537C2K
         Tl5fmYRoyz10dw78w2w5NRqDgqE4PhbGw0rj4C7jJ79/pfGRRRJ5jpRKM7n3ve78xV4k
         iVydRoRke28/05eT4WWfeRumY0ResbrQwzeuql74TWyoOKzeamDy/CwYzDgt8te4TQ6R
         xuMBX7N580Ie3jU4GEm/I5Kx1IuWtWr5FboN4l04dxqA2dILzN6H43jCkWJ3VkwRJF3w
         1TaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697573425; x=1698178225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BZt8EFWh5xY5+r7S459ryMQGLjiVE7YORF+7Y067k7A=;
        b=vg/mqHOZloV1ItCQE+TAFywMZafqoxyopCfEgmYUdc5XrEP6ItKTYtxK1PSkakqa0m
         n+nWFxhz5GDpAjRdBw4zthvvOdcXKHjGEb85Mijr2CWf81ropcYHFbYfv8grXRkcvQqr
         Yr0jly3MGCNPhzT36EXz+HjbMgyyJAp5Jow/rWVq3MPEfvALbscTNQIq+P71w2Z0Cicf
         1BiuavKEHJoDbwluWph4XLjckZ9+zwKHV6LtXb/w5csTwHNgyT5Ru3BvzsyUxJbagWWH
         RJMVwdPtDZ+yttXdxlRmUXorNQR5J9iLAINaS4ccZj7C6Qa6gcR3YVE/kDrZxPs5v2Rj
         RSVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz0fP6/RmetO/0Ub8sAdFiWCTsG6oZ6i5s+y2TROSVp1t5ueqOR
	V+5QAx4R80DfOulr50/jDgg=
X-Google-Smtp-Source: AGHT+IE9CozxHxD5k0gTYa9zsLho+ci9Hq3uXeuHCSeaI3Q96eWGj7rcOJNpmikQ8lH1VbdcLcqHpg==
X-Received: by 2002:a17:90b:e07:b0:27d:5a7:3960 with SMTP id ge7-20020a17090b0e0700b0027d05a73960mr4293944pjb.21.1697573425291;
        Tue, 17 Oct 2023 13:10:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4e86:b0:260:d900:96c with SMTP id
 sr6-20020a17090b4e8600b00260d900096cls1362987pjb.2.-pod-prod-00-us; Tue, 17
 Oct 2023 13:10:24 -0700 (PDT)
X-Received: by 2002:a17:902:f685:b0:1c7:5776:a30f with SMTP id l5-20020a170902f68500b001c75776a30fmr4051265plg.12.1697573424120;
        Tue, 17 Oct 2023 13:10:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697573424; cv=none;
        d=google.com; s=arc-20160816;
        b=DzNN6JfxJ717ZpoUUxgdLdjwoXGFJ06ZEG/caSfmHf3hs35tlxA3WIfJEJfMVcF6AY
         I/eQaZiiAS21Zn5JFIfqjCrA/F4tBVQ/yk3edpa8kEcBuNZbqUJw4VqDA2JMGItTv71l
         4YN6yObH0lu1o7MmtPx6FG/GkTHosbSePDVX4yUCFRdlF7YIzd3+bXs8wBn8yjOEhefS
         zl1FBJ3xSH1UQndlPTDVHN22SyLOko7usZoV7uas9juI+U+J2I3eeVbVNN3iqqK7iOKP
         EPqPu/tjI8wjIWvB6nLNzpExVzRqWp1t53m33MM3k+zXmxPYsWnrnhemLOrlxsbDvsTQ
         zlJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Uj2R21g4EPlt4YZKWi7SG89ievVQJ+iyFG5BwjhrmmE=;
        fh=g9SUMMVFv/A5rk+d0/ylcvV2eB1HdNHqn5ghaGlISoc=;
        b=yCy03MpKwt6KqTwooEDgxfMNaHxBTDp1gMj9Tyh6L8RRpQZ4TmRyvZ/xwUkAUQc6dl
         pEhdmYhKXTZFR6DcaLrh5eLW4grgNxcMVkpcEHEgthmyDQnEsZkWAPPJtVpu9ZbXjhwi
         diBwpiBCWVYeinpdp/vhEpJq4zNguekucD6guD3A071OIQrjG3zktMiYM6SRpjeFBbZX
         r/EJCWRyCe8CLhVHBagtqV45HgXAjH5hprbd22sTW4dUKmuxF+9mcgOs2ctLjn8Vy32d
         zkYcWBMRtYfz+ypSzXoPeHE1GOD/WZqOlJG9kYldEuYU05tI7sykFNUoPblGj7u1ipS0
         9yFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=temperror (no key for signature) header.i=@marliere.net header.s=2023 header.b="Sd7GNP/b";
       spf=pass (google.com: domain of rbmarliere@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=rbmarliere@gmail.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id kc12-20020a17090333cc00b001c093744cbcsi154233plb.9.2023.10.17.13.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Oct 2023 13:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of rbmarliere@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6b77ab73c6fso3023214b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Oct 2023 13:10:23 -0700 (PDT)
X-Received: by 2002:a05:6a00:3408:b0:691:27b:15b4 with SMTP id cn8-20020a056a00340800b00691027b15b4mr3871596pfb.5.1697573423273;
        Tue, 17 Oct 2023 13:10:23 -0700 (PDT)
Received: from mail.marliere.net ([24.199.118.162])
        by smtp.gmail.com with ESMTPSA id z21-20020aa79f95000000b0069323619f69sm1918389pfr.143.2023.10.17.13.10.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Oct 2023 13:10:22 -0700 (PDT)
Date: Tue, 17 Oct 2023 17:10:14 -0300
From: "Ricardo B. Marliere" <ricardo@marliere.net>
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	linux-mm@kvack.org, 
	"linux-kernel-mentees@lists.linuxfoundation.org" <linux-kernel-mentees@lists.linuxfoundation.org>, "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	kasan-dev@googlegroups.com
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
Message-ID: <eqinp4exznpgclzgz3ytjfdbpjffyyfn62dqfiaw2htk4ppa5p@ip25t7yczqc3>
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Original-Sender: ricardo@marliere.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=temperror (no
 key for signature) header.i=@marliere.net header.s=2023 header.b="Sd7GNP/b";
       spf=pass (google.com: domain of rbmarliere@gmail.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=rbmarliere@gmail.com
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

On 23/10/18 03:39AM, Juntong Deng wrote:
> If the free time is slightly before the error time, then there is a
> high probability that this is an error caused by race condition.
> 
> If the free time is long before the error time, then this is obviously
> not caused by race condition, but by something else.

That sounds a bit arbitrary to me. How do you set the threshold for each
case? I mean, the fact remains: an invalid read after the object being
freed. Does it matter what it was caused by? It should be fixed
regardless.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eqinp4exznpgclzgz3ytjfdbpjffyyfn62dqfiaw2htk4ppa5p%40ip25t7yczqc3.
