Return-Path: <kasan-dev+bncBDDL3KWR4EBRBR4PTKEQMGQEARBKK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C6E203F7C10
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 20:11:25 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id l8-20020a170903244800b0013517298a26sf42913pls.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:11:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629915079; cv=pass;
        d=google.com; s=arc-20160816;
        b=p4ufcI//ZnrVYW1sv2XRYYl0wLZkBpJXjNSh0qg8q+TdFFKxdnDCzvYRaO30AvSUf2
         1cfmM5aucWRTi4GMcpy1DOD1eU5v6v1Hir0aYwZytpefwoir/WLBNv4jBZOM2MAq8TtW
         0Sox/kIf+GQ2pM3uZSogiiRO1TpaCrcki3J9rpZTa+YvK3LXrtfJcPxdpGzn1qFkIp1f
         iHNicHniAcsG+nDMj/LWJUgPlJ8E02IltL3Sb5C6xdDbq+T/9o5Ebgar3uoLGJkNlEBv
         Y8evb1ye0iZOFEXlcmIpnJc2u4R+dMbRwmvo8oxvw2nXGWJgIjhV1t/gZJJcaXJ+xLoy
         V9RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DBEynplhUtf2OcJHaQW2tmNB6xcJ/ArEMo9nnuxnNXI=;
        b=x6oll9TFfmA2KEEQw4RKd6+SuiQ8JnF73OSiyIo1DxTtT7oXOvh+gLjUxXqvvmOq4z
         YpPKGeaGMas8BpLwlLOocZRTM6hStYDWAKtcE9xeS5LDjLIn3GZCgZGS2I76CALM+GB6
         f9EE4EisyuRz9v6bfMEG5LkNjdbXVEyt6qxmAz6kT/uxZ0jSu46ql4fdx3EaFgZvNWgu
         QY2C3slY+q5ZdBoHg9sVlfjFQmnQo6xjiuDO6GQkLRIDP7XcyfQrCNiP4hPYmB9IMb1V
         78PqJGdkKDwvrXDR8uJvGPNIacCya/wv/k1J8OBRM1jvV2jq0e2TgkKiBD5JTuq5oJi/
         XiKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DBEynplhUtf2OcJHaQW2tmNB6xcJ/ArEMo9nnuxnNXI=;
        b=fuarpy6CYZjCPNyqHm9KlykbpxeuE2zIadzyApI6BnIrCdUahflJA1PVMt5hZXpNCK
         LTNeLktamTHLdXnIgZsrPCwnqLTNBpNY5EcGP7KlshtYANU1uQ8OxZC7nOkVX/LjDdWN
         lbplIg5ntjefSg8/UHAkqgVetrFFkat1Ewr9ocaRHITO2O7pxn1D6xCpwyz+0AqLap76
         u4Jb5FlOXDBSDN1GC6eVt0LYyzNTJG1rUkXY+DR+VcmCz4XNRzP2vDG7mhE2dOmIBxvx
         icTGd8wDeFyH14+s1e5vq+5MQFTbA4uKho2gqO4r4qoGiySkxFBDlTi1dxLvgkDK+ytd
         +RMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DBEynplhUtf2OcJHaQW2tmNB6xcJ/ArEMo9nnuxnNXI=;
        b=T+X8plsiJX0L90SSMI+ol/om9a+G2NbT1MyghGqRjGB1Osoi3nr9/Q/duqQOxd9jdJ
         2/iOE3kx5PYi9YXkzPy2oXoEhSCfiQiVF+MnK+VxrEKmVn+/gfreU0E1ukeLGbw89rEI
         mtnAdnPqrK30TZr4N5eMs5MJmhKl+AnHSR16M6T65UimA9UKUTreYvt9OxRCC//TD/pg
         y5Ci/hcRkzPQg05kCmal0wewdvySAuY+n6MI4nQdiUFpvUyf7Ar1nNKue9VrKG9Ekyan
         JoxKqzqSdmMhMeYHzUQ1KwrRcBC0NPyetnPdQmeX5UaUCEstP4jQhL43ZEEFbwI85fZx
         eOeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ho8XmEkdVg3sXhf03R8oCRVfYR++HjASMhS4oZrHZH2lHjfhL
	Swna6/VP7stf3+Zzh1cNPS4=
X-Google-Smtp-Source: ABdhPJzDFrzu0n/3B+NpBAKBP3uvmShvCBdBoR562t9Uq6Xv7pHST9/Wf0YOs/lJZZ8el+7f47XjQw==
X-Received: by 2002:aa7:8b0a:0:b0:3e1:2df9:d827 with SMTP id f10-20020aa78b0a000000b003e12df9d827mr44944437pfd.67.1629915079308;
        Wed, 25 Aug 2021 11:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:848e:: with SMTP id c14ls1653928plo.1.gmail; Wed, 25
 Aug 2021 11:11:18 -0700 (PDT)
X-Received: by 2002:a17:90b:4a8b:: with SMTP id lp11mr12009097pjb.10.1629915078663;
        Wed, 25 Aug 2021 11:11:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629915078; cv=none;
        d=google.com; s=arc-20160816;
        b=0x5VgCW1WbnbplDh2/LojHLNiBhRenEb8SKnScpdbPnJ476X+4Kj6VyKraOqlFYiag
         z8ybSpvTIpyZP87qBP7XrFXIZxziGdAA5sl9sGru6G/JY3+skAqdUVECzs0M+Z7EuvQq
         1yzX09mdLDJvenvFNcZ5c6NKTXR09zjBw+bh8JTXi/JrvrPBP8y3PLfNIHsf1c068uyk
         uDIQKf6t9w8w4XsUJnr2KFBDdl0hKlQGRixSqxAZ/9H7v81fsDKn50Qw2duuMVDN+WF2
         xwBcT1Td2XmHQ6prhjTz9qXsHincxp2478RRkigxgVjYGm3OkNyrXywLGzWkicvT6xg9
         8UKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=wrGgdcrgJhhoszL8aU+XP96FGA8fa8cVEJGggynWlY8=;
        b=uaG9FFhhyVYapcnBbmlc/SwBXJzM09Cu5qwwL3l775Emgch2lb7IiU1IU0LSDZ0S1P
         UYRFZ3lM3shwSKI65k+UHYW4YOJSbm3eV/L3OEn3aAs9GbbXq1R6XGa5ktzq308xZlVP
         JteObOfozwom0tQIRmGl4G9zDeQNIGBELAUUY/6NQ0U0k43xsioJS1+7r+IX9z55Usav
         RckRB6Rf08OJEL7i7V16/QIiG6jYe3tnHOsYPz33PZ3gBvt5m5MG8/pHlkAdHemHoOJi
         5nsEx5rwnreX2PPu4f9ib3voJahKQ0KfmVF0sTsFfTYzB0zT2GmExbf0qDdbMSj30l5U
         hlcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o5si76320pgv.1.2021.08.25.11.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 11:11:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 84E3F60EBD;
	Wed, 25 Aug 2021 18:11:16 +0000 (UTC)
Date: Wed, 25 Aug 2021 19:11:13 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
	dvyukov@google.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, elver@google.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v3 0/3] arm64: support page mapping percpu first chunk
 allocator
Message-ID: <20210825181112.GK3420@arm.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <9b75f4e5-a675-1227-0476-43fc21509086@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9b75f4e5-a675-1227-0476-43fc21509086@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Aug 12, 2021 at 02:07:36PM +0800, Kefeng Wang wrote:
> The drivers/base/arch_numa.c is only shared by riscv and arm64,
> 
> and the change from patch2 won't broke riscv.
> 
> Could all patches be merged by arm64 tree? or any new comments?

The series touches drivers/ and mm/ but missing acks from both Greg and
Andrew (cc'ing them).

I'm also happy for the series to go in via the mm tree in case Andrew
wants to take it.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825181112.GK3420%40arm.com.
