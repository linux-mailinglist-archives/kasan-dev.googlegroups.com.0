Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCNPR35QKGQE7LBA37Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 38CA726E1BB
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:06:19 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id e15sf203565pgl.16
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:06:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362377; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/CV46LNxZWMz15C40wT0uC5ONt3TbpMaJ5a07EWW0O0DdQnPyTSifZaq8yfabnU/S
         3uHIhDJD+aHMPyFeVs8QE4l+uqxt23cRyLEyfl3UT8ygUsmIjU3HdtLJ4MvaD29fUolX
         2Xj4ea8AkdtGUFsPHkFobOgwN6EA7+TYno3XoAOnR4a5m1zbCKscjbcVsaxSTkFDQpTl
         AxfMEe9rMAByoluGYvA7vudRELtb6mxyMwqYe3drySMgcV2O4WJg4gra5xm51SGzNfGU
         LcWEqZYgR4icJTX9rXJOyv8KH1n50CLP6WgPgs+u72lqF1cxS7jCjsfjPD2699hjN1gG
         4e8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=phqkbPMM6gKBUs1akfvg1ECrDLk2+2z3/zOz+Z6B3Mw=;
        b=it64n9fuBfRSwzf4mN985AiUu7z5W/a1pe8jCUdaIROFMd+UM2OvG61soQbdP1PRVC
         qwKR3hOvaVqxeLcy/Vex1txEBu2WGGotFxttli757PgDPxZx57gCog+ZSiaSUtMquqxA
         9YaGVwXO82uNNarXywzMIgUJiadZoer89rTMH69MWz3WGKmt83ZeGAv65eRxE9UZBrtG
         HMAB4+Qn93UWWIXRh0IFPh8akHRNQ8VPR6+fp0exXWj/u089tJYsukLBmxRY86E0zG88
         /DHFLnErlXEFYHXu6jhQeeWS9sNxRtZJS+fGShspb1JfC+WlJOJT6y381aVUn/oCSEaT
         BInA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=phqkbPMM6gKBUs1akfvg1ECrDLk2+2z3/zOz+Z6B3Mw=;
        b=mbXeU2qfCkdMoWSPL5V0r3hFfCxvtD2UEuZ/Mh6Na2gC9oVGbaW6BAp77Koc05LgiC
         IjoxIpwAfQK7/d7njNKKJEBV7pTc5nDUIHcoNWVbMCmkprcg3tCU0isL+i5B/f1dlLap
         M3ksgR/b9OmH1LoZA6mzwrf66kchXm+TygG9dn2K+oCo7ghBHm2Njv3z2kLLrMslH6mt
         DrSejLsC5A28MstzQXyQOCbNOChEwn6OfNg890quVLkWhoUb7wUqljOW5bO2dMXnClEZ
         EktfJx8oFFDAgwVmD00t9DUkpRjjRZgbYqB77gNyoiNV9JVJI9H6K8qGYEhnocTrNj4E
         rFnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=phqkbPMM6gKBUs1akfvg1ECrDLk2+2z3/zOz+Z6B3Mw=;
        b=Pk9wfwBN+nw2PHJh7GDRJuQVgVVzlEb6kwHv2O+AJLTiJ/y2w+KMXhuJIALAr9GT2N
         P4UG6EattFtJ4XVlTi7y8ufQKzlJTBihJvjtcxXoh0suUokhXYByTafasE4T7BnwnxKd
         duYh3kasxEYSx07UEv2e4+Wr+OjGN8o0LJEGe9GnSDkleU6tOt2DD2hYKKDlm74qGh2m
         tXeie0pQUVhMQRF4sD5hxXfA7lGQBLFv9YF+EmcmumXNzakEJCYk3s+jSyGma6WE7pho
         JFV8Dnjr6Xvj31bfySF6tQE+ll9WC0I55jZ1p8rKJMYvkG757O03Exk+Cl6CXicTRB/9
         Tkfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533iD8/HwtX7JSgJMmtwYtnKdLUBBZo2wvN56e9t4JvnZkmYNWjA
	DnxLb9eIjpXBoU/yMGFRO6M=
X-Google-Smtp-Source: ABdhPJyEnUrlRMP9Mp4qJSM2GyXRAcMU81LaGN+HRWxCv0WkfjkxGm7QzJGbJPchhSfg2Kypi1fbCg==
X-Received: by 2002:a62:dd02:0:b029:142:2501:398c with SMTP id w2-20020a62dd020000b02901422501398cmr11723470pff.81.1600362377726;
        Thu, 17 Sep 2020 10:06:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8c8b:: with SMTP id t11ls1363357plo.3.gmail; Thu, 17
 Sep 2020 10:06:17 -0700 (PDT)
X-Received: by 2002:a17:90a:71c7:: with SMTP id m7mr9734236pjs.190.1600362377010;
        Thu, 17 Sep 2020 10:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362377; cv=none;
        d=google.com; s=arc-20160816;
        b=TwmpGiiAeZPmY+itXpsopB0on+v4NQ6C+q2/EA2gwQtRWkELBzGCZgPNHM00/A/tre
         gqhhVyK2IfSpfkeL4DgfRWTKm4BQajVIA1xdnGR22ic8uTX+80Uj5c42/VYjBXOvIeq+
         9IMUprK4xbxAkxWDuYbsCT9NZ0CwQmnouC29IMSwiR1G26YVUyHEqwep+kDHr5JqO6i5
         5kQ7iIPHosiYys8C6kO28VFwL9nWiWNCSD4XzMmaS7gntD1ON9ziDXAjZTSKITdSi3Pm
         eMquv6M/SB3LJhupPkIv4ryCUeud638L3g1YSyUTnMDiU3SvvOBBA+oNHDHl/fqeajMr
         zLhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Dpt8+W71ew1Tg8i5QDdHWfL+FOKFIChPlB4HsgC9B6M=;
        b=TpoIwfpqIZULKxsje2wc6HNHAZwRckX8EmfLkmf55CwkKBL0KjuhvILv/IFuvBHbgk
         pqNDf0gtoNEfwqgRQ3YwNhUnNvxDkhetQTah/dcgEMhm+hPMJl98/q26KhIatB3pjlNs
         0J0QT29iYLq6e44yWORx624fd5BiXHHzdmdyiTmFU2s34dhuK+nJoXQYNp+O9R8DJyhS
         15jg2Wo080I1eLBdLTAFNyrM40SjewLNUGHrrmW8PDMhyTN6Su0ymEvBJAYFriaCVOhL
         oMy4F+QTivULhMy5kgwnGs+UTYWo0FBRj/vGcfUVzDTK5mN+mI37RwjB7qLRP6xnX+2M
         a6Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t16si55407pgu.1.2020.09.17.10.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:06:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 12335214D8;
	Thu, 17 Sep 2020 17:06:13 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:06:11 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 29/37] arm64: kasan: Align allocations for HW_TAGS
Message-ID: <20200917170611.GP10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <0845668a82ddd3eeb3f652712597ffd056f97504.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0845668a82ddd3eeb3f652712597ffd056f97504.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:11PM +0200, Andrey Konovalov wrote:
> Hardware tag-based KASAN uses the memory tagging approach, which requires
> all allocations to be aligned to the memory granule size. Align the
> allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
> CONFIG_KASAN_HW_TAGS is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170611.GP10662%40gaia.
