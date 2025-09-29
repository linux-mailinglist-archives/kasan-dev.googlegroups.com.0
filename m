Return-Path: <kasan-dev+bncBD4YBRE7WQBBBSXB5HDAMGQE3RK5YHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C96BA914D
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 13:43:08 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-57956e61e74sf4082627e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 04:43:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759146188; cv=pass;
        d=google.com; s=arc-20240605;
        b=S8kiStAHJEDetfJPN3Vj2WdLBAaNYiJuM4WIk09kwC/PiLtT1bzKbTJoB5aXeb1Kf3
         hRb4Hyxdtglo+aqtSEBU6k6draL9RU3V1gm/7r1ULZB+Ww6bFtF+rFar+AoTCMfb4iuK
         3tzqJLp2JEn5qFZdy9Z6uaZIPAeV+nPnaYt3dYRDqzSWz4z27gwqo3L1BVOTKE4shBtE
         h4UZQJxB1Fw0XANzu5Pa3XXep5kj2/l2A4O3pcI0hqV72v7Q7mo9CsHIunbD3oOzgu4Z
         0E2RkaoaLsGLJXyrSw7yTxj7pv1plvVU44QrbIQaOHXOaHKusZlTGe9CtW5nWn+dPyAX
         aXSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=QJH5BWvXLylTpYw+4EkkfSKVMrQLGdf7o6S0X1Lpf1U=;
        fh=D7g2GlT3JfncEhuRspZMVljGcQlKLLY73eMPo6yi5Ag=;
        b=IE9tZXQUlt6wa9PZMRjzHDoVM6KRPbSRhWqCCkcwMcB132mDaj40b5D2rfMWWLlhg6
         jiRrZisuviHEzvsVKVdCL+IlC2aHwkxWdi7ZOgvXsoQvOzIyw5MN0k5MIOHN8Zfumyhz
         q2jxzWx8ynN4JFjpYOh5Kqa0bTntwL2eGvlHHpTXY4eketNoxB41SL0gCTCE6w6rqDGF
         snFz9mJxTKKs5yLbIAi+t6EEqmw8FwwTI6aPGA7e0aP9gUvcmp6H83OjtSxebM+aAcqX
         +1z0Z/wtjyRVAm4iSJM8OWEklCbNiURl+FyHwI2jTwg+/XNcBnbSP/9f5QXAgrRcrdQ5
         0Z5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OOal2Dgz;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759146188; x=1759750988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QJH5BWvXLylTpYw+4EkkfSKVMrQLGdf7o6S0X1Lpf1U=;
        b=ASCgNwo9wX8YiyuyFmWS47x8zb7LaB+2yo/XYJV7aC4SDFwgRVwUqPt8rvs/A+Un4w
         93FnZYliVqDm5OAPLTMu8JEoZEprISYjrSXHOsZG90G7nUXHPMBshdH4FOb/HeXwRk+u
         vuQrVTcq9HKGbh32tqVIVD6qMQcETmfzR+UKcIC+RqjsQvn+pqp1oC+ezP+p96I3CWoG
         R8K0+pMlOsYtRXaV+m+mIEbwDiANYVUDf0VIjBCNmBxvU2lSf5uIvYYwaUyfesvW0Cj4
         z8nc3lphGbKK3T5lZ/lvsDp7KA8zOEn2Jw1R4nJgUFF8nZwbagwdZ0pS54s47vt92WO3
         V5nA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759146188; x=1759750988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QJH5BWvXLylTpYw+4EkkfSKVMrQLGdf7o6S0X1Lpf1U=;
        b=GSB7KGJc+xlgYNKDzU+nGFO/EbvvdVKAkgfXhZCdr6M9MIkvt5aUXsMWaXrVEFxI+T
         56i9wrP9TvcK54R9x/AsKxFbPZpqBlalaUJey7XkCIqEQ3sNQTYMPrGmqNf0QbDxP7Ek
         WIoSFEz+7k4xEr/6/1L2DaIdan6PctX1JViH/nmX52VPar7V5EYDKSqaLgt0uEuwqp0P
         0eLPJiT8w0GN4iZ15IXNhWq+m6ve12NleU97lhgyu5EwVrb+WgNEp4o3ql6mkeDw9VZq
         jKadZDPcO+jf2AqFxn1XpGeZh70U6EGw7qKnGOxggA12GxhyPfoZcKlxIzVIKbpQbAE8
         B5Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759146188; x=1759750988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QJH5BWvXLylTpYw+4EkkfSKVMrQLGdf7o6S0X1Lpf1U=;
        b=rhECRa/vkudZmmh2EyFVcEu0D1K+d3Uvflqg335zsEDr7oc0tlb4rYsneHSIDtbbYE
         dfbylUB1gc/jc4hOVefyocyyX+BfdfCrx9O+Ozc5/FMUvUTtwDcmbwqaUBbi3dFUzLU+
         7egndvcv/qaAYyk1BafngZw5GqCVIpo0HgrhOVwbMSy7T3T76ClrUYDPxubjvl4XzRlQ
         T3TyrMKJKxaRtPdvK7hLdon7mrC4G+kEBuaGE6nfW/VrKi1QuZAhFqn3kUjXOnhZ2ZUj
         mx8kfR3hW/+fKK1KOXy0DLTAtkUN/ql0G4dOYFBXHr3H5aGlR+PFd6sQkE2/4GiIQrty
         gHmg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8DbA3PAvHkz3mpP1+KIbI+/J1JYYGN5aWo6hMrtc7x/5MOtiJ9EoBcBufr2CaYJw84bAiBA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/wbI5iAi4d808ZUa51x9Wi+9JdPoWOFbsSoPsinU/gudZ3Qrn
	7ifeevvDV+JGPs1CkN9Iag5Nu+zLqYmVkrONv9rNz+KAOE3yxdHwXy7K
X-Google-Smtp-Source: AGHT+IGLpb6KaVD9aK7yLgeUJxGQcDn+DVGs03APjGNlzXewOnsr7Hhkj/zUMkam0IZkjTiNWEyfSA==
X-Received: by 2002:ac2:547a:0:b0:585:5cb5:590 with SMTP id 2adb3069b0e04-5855cb50898mr2093583e87.11.1759146187557;
        Mon, 29 Sep 2025 04:43:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6eNvi2tBW5lwOBegID3wxCOAco7iorjS4Y+LOlZCE9WQ=="
Received: by 2002:ac2:5b8f:0:b0:55f:5096:7778 with SMTP id 2adb3069b0e04-582cd4aa532ls1451198e87.1.-pod-prod-01-eu;
 Mon, 29 Sep 2025 04:43:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN0uc9jaOrzPLHp5Bo+AL7/PKSpe00oIlYWvTfO7wO8TRzic4JDzRFMxAUzwk5wBpclcXXhO2ejZM=@googlegroups.com
X-Received: by 2002:a05:6512:12d0:b0:585:b05f:9459 with SMTP id 2adb3069b0e04-585b05f96b2mr2226354e87.27.1759146184182;
        Mon, 29 Sep 2025 04:43:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759146184; cv=none;
        d=google.com; s=arc-20240605;
        b=Khw3rK9e/LGYWvJOzKpJ1CJh3hTYyNKPC7iLwnhNltsP7rPSJoQI8KW/s3x1BafyrY
         IrUJXhE5h0rdnyynFxRn+RErIDfshOFhwQGzpzlWg/tylY1cnDBV2+z3sSRi/5+rHnOi
         fasKuQFc9nEm3yQ91CH6AmxDFtfb7wgUie1Eb41Mlvh0TdRAyZ4EDoBNKrCpsqk8Ju9I
         iILCPZ/v1P9X/Moe4mXyqT0ejJ8kNHcF22qTuYZp7RsckCLBMgkprpn1YTi8TkOStxPs
         PIEWGfYqaSPoAKPAdO/vuR4b/C1SidwBREC0bcIfk6Xv4vNTDI929xTqoJi945llvOD0
         FYWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=6mbjVJui29v4n+pWGfvI7ZRvpZGP8q8p7zkZRQub17I=;
        fh=PzSsUqqM55yQoYII1hLkFigz1zNE8X22tsqsBE4uxGA=;
        b=P56VR01tf7b7dpltjf8yaK4NDoUfBwf/wEuNgmHs1E2ydNm2ZO5ExxshQgaTMNp8fv
         f/5VWCAz3v8ktod/UYeuZBtPdttnJcp9hCFTKOpaDxyNV6xZYz0hzTq/xmh8OXg+DoSp
         vV3Ceq8GXkiBWwFjZaidmeI8TVLVR9eEgFCQOZNiXNdv3iJ1EY7eg3Raw124aDoW7mWy
         lGXwvNMtlrZm2Q8T05kXqkeMY01Cqkh229GSWpxyAdBWBAk4K//IhI9D6ZFBaE6xKnYa
         +0QlrZ4vOdiIZ7VbKEp7BVvYVUCTeHlUZpAJFCrjI1Uwz5qMCTQ4wNPVqOz1P3dRbmuf
         VEtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OOal2Dgz;
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-58707ee2341si68602e87.4.2025.09.29.04.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 04:43:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-634a4829c81so7644820a12.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 04:43:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUFb9o36SaqadCsvB3Cg71dBf+FVRi4qxRHFCWpn08pxadCO7SBNKOOgHoloy06X1vq/qmX0w8fYNE=@googlegroups.com
X-Gm-Gg: ASbGncvF7vaGc417zAq34/IQ3+gxVUvdzeQeJdC5yuBwKE63GCAR2wuOCf+1T/7zEfd
	tCcJWXbxIg8EibzjFSMB0edt5q73WKHLARk5q5h0FgyNDMAiA1mUT1w4gssBLiDdh+zkulwVqiZ
	86GKVQPGYchC8ttebrMKlTpGqFX2d4eW3vmVr6wRn26JxYBggG2aTqMeoVpUUwALqsIqDeUrMhM
	1OufZX3UvciQ5aKZTM0uvwPzU47yTtPuZ9gAWGmD2UCafKmSLVeuXaK8bpS27/eoCdSbNIZoTt4
	53DAbgkyGsUcl8iR8ffmISZJsP5SEyVKNS2qQ3a6tjAd2nldZID2ds/+KafMVbUqYOITXqgMcDM
	97StCw4DyRsNRsUzuR0uKDfw232n9oK2CUQgv
X-Received: by 2002:a05:6402:504b:b0:62f:cc4b:7b53 with SMTP id 4fb4d7f45d1cf-6349fa932c5mr14065525a12.37.1759146183418;
        Mon, 29 Sep 2025 04:43:03 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-634a3ae3080sm7873345a12.34.2025.09.29.04.43.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 29 Sep 2025 04:43:02 -0700 (PDT)
Date: Mon, 29 Sep 2025 11:43:02 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: Jianyun Gao <jianyungao89@gmail.com>
Cc: dev.jain@arm.com, Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	baohua@kernel.org, bhe@redhat.com, chengming.zhou@linux.dev,
	chrisl@kernel.org, cl@gentwo.org, damon@lists.linux.dev,
	david@redhat.com, dvyukov@google.com, elver@google.com,
	glider@google.com, harry.yoo@oracle.com, jannh@google.com,
	jgg@ziepe.ca, jhubbard@nvidia.com, kasan-dev@googlegroups.com,
	kasong@tencent.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, lorenzo.stoakes@oracle.com, mhocko@suse.com,
	nphamcs@gmail.com, peterx@redhat.com, pfalcato@suse.de,
	rientjes@google.com, roman.gushchin@linux.dev, rppt@kernel.org,
	shikemeng@huaweicloud.com, sj@kernel.org, surenb@google.com,
	vbabka@suse.cz, xu.xin16@zte.com.cn
Subject: Re: [PATCH v2] mm: Fix some typos in mm module
Message-ID: <20250929114302.eshtdbqkjiuflsib@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <3c3f9032-18ac-4229-b010-b8b95a11d2a4@arm.com>
 <20250929002608.1633825-1-jianyungao89@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250929002608.1633825-1-jianyungao89@gmail.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OOal2Dgz;       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 29, 2025 at 08:26:08AM +0800, Jianyun Gao wrote:
>From: "jianyun.gao" <jianyungao89@gmail.com>
>
>Below are some typos in the code comments:
>
>  intevals ==> intervals
>  addesses ==> addresses
>  unavaliable ==> unavailable
>  facor ==> factor
>  droping ==> dropping
>  exlusive ==> exclusive
>  decription ==> description
>  confict ==> conflict
>  desriptions ==> descriptions
>  otherwize ==> otherwise
>  vlaue ==> value
>  cheching ==> checking
>  exisitng ==> existing
>  modifed ==> modified
>  differenciate ==> differentiate
>  refernece ==> reference
>  permissons ==> permissions
>  indepdenent ==> independent
>  spliting ==> splitting
>
>Just fix it.
>
>Signed-off-by: jianyun.gao <jianyungao89@gmail.com>

LGTM

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250929114302.eshtdbqkjiuflsib%40master.
