Return-Path: <kasan-dev+bncBDY3NC743AGBB6UNYL6AKGQEEPNAL4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C2DE2952B3
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 21:07:39 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id g9sf1573457ooq.17
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 12:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603307258; cv=pass;
        d=google.com; s=arc-20160816;
        b=AG78pDtiaBlylE56lbV2M92fV0mRfk2d3MReY+xiFHQlnoNsu0eLF3yeAMGxZVFBep
         WUkfGzKuORf9Psali9jBNwmDFfGuID/PtKDq0L9i2s1fsG//zzzIHxlXp14cl8bDqIJW
         WAJJCj/OY9Li7fVzSmKmygdlEQ7CDLhTAiArq8HbF/UEgdexSm4pMlK5rWhlHQXR1D19
         Ada1dMxoOelI3Ckoyrq2twCzavMXvGrmKmlpbxf+ZVRGdUer31v5eJFmzkxMpmGER9MO
         JtP/v4xTLLs2+pTUgQ47j4osEKvq2WfzVw5QBazqNWRY1wVAmLCRxQImq1GyCBgOaAam
         GE2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=q3I7BYrDV5byeLnGTtgewGXbOjAZdiOnTIXceoG5keI=;
        b=jY0+c9BO7LuDvndBH42i6cba1CdMuwG0IyV7cngsjeYFi0vHi51gD6lkVFFMC/G0pG
         TegEKy6a4KuyGJfGew0sLvyBXoEza3h4bqyzcaDVM01O42l62m9H+pYaR8DbBHvGioex
         z+bPSqGkoRnMSt9g9O6kWHKTRh8I4babKGrhpCSQ7fiBB0M/Yd5cSGJcNm3KS1eDJzJj
         JTQTxW0cF3k98hByUVdUqyjNd5VYVi1ahsKBKBbwNl5M0JOwAmEzaXVmNF5d2Iv3vkJU
         YK70/0DoPCjEYMf9b/FZkGxgnGZCIXh5pa0KJRf6+bdeUjxooQisHydrQpzyXregIY3+
         G9RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.104 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q3I7BYrDV5byeLnGTtgewGXbOjAZdiOnTIXceoG5keI=;
        b=Zi0rxcRzBNiImy+M9+4MppgiJqQx1kRJM8hNKr6Ip9nL0mkDhDL2as1SLSVpe60Knm
         dtgxAtn3kzlKU/6Y/daXd6kEWhP7wI8BoFJ7BFUKtVDPxMcq0PStZn2Dq4GT3heu/hR2
         aB5ukhgrm1rB6IBjYUxtTHpVr0smEoXrC2bXEF4tagPRlkzQJoy81EmmcvoPwiSl2sRd
         Hf9tXxJdiLoDwDdC25IQwKF9jpoIgxu0x3pQ1IEdUYkEbYJ3GJXIKq4GcevKKlK0H89J
         YsO/CW/lH3Hp6T94uG23cTJkdqt4Jlvgb4IlG+j8YkbTj+CSv60XWnTtagsm161BqTfM
         +THw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q3I7BYrDV5byeLnGTtgewGXbOjAZdiOnTIXceoG5keI=;
        b=Bl41D7hnfSMmLTrTImtbKMGZZc60cawHRGg0KEbzqPWf3H7Vyu/TyM5na2KNsgiOW0
         qwIVbUbSMl/tWTWWH187gdLvvktI8IQV27Jjgcmd/lAGrNsr93AuwTbEngyv2x7G9xYc
         sR7LYRMBGN8AW275tGWvu0KPBx5X96onEcq9y4vehgdcgtD+oXG6QIRJds9NZyuysOhV
         imCsuN3mUbNosjVkfQFW9j8BNeHtFCb1UdC6St/apO4TMbc9U5OfCPAQUOFP6Ykhr2AX
         o61jVQAPMQhypV3RyBZtjn0iFOO0QJCSzTdHufGlwmGxAJPOe0BPEHiGSiDjSPrzMFpe
         uXQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uYzk+FTlGSi8ct0nJEyxya952NKVdWlx8d4v0m5R5Nl68Atfu
	qFSQK/d9z+WwEGYCSmKkz9o=
X-Google-Smtp-Source: ABdhPJxbORpw4+9uXbyfRJcVy6wZcaDyMbhjOjjJm52G5De02xj9VNqeilc6Z4LHoSrGaEDFwSpzeA==
X-Received: by 2002:a9d:da7:: with SMTP id 36mr3746901ots.288.1603307258446;
        Wed, 21 Oct 2020 12:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2fc8:: with SMTP id p191ls50922oop.3.gmail; Wed, 21 Oct
 2020 12:07:38 -0700 (PDT)
X-Received: by 2002:a05:6820:549:: with SMTP id n9mr3637745ooj.51.1603307258047;
        Wed, 21 Oct 2020 12:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603307258; cv=none;
        d=google.com; s=arc-20160816;
        b=cLTveRH+fKqU4rofgsmngXPYbCHzNJqEQe72L+lrWJBJCdU/ASNtHRcgIggR0HbkkA
         1KKmPZKfdNBMiWRngg2Xvz7Z4XuQyvLMtV1/yuhArpDCimEietuXnQ4hNMZ4Dcvda8OU
         xQ8gjHb3fHjlRMUrnPO5GVRWnDAvJj9CwWZ1bzbBv4OoxrGdKOBtH8+3Z1OBsOkNd1+e
         SSEhas229Hit8JyeGiO2qm5hCHTT9bLE+8UwSLmlLS71/CbZdiI5yGRPO3GV0/JLvbJn
         Ad0exw9e2JI1NoyzALtoVHtYiYncs4pED23TI7Ds5AGynDoRGp6SP/ydpi6MzhnCzGfL
         fgmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=LxEK4fuz+OGlXomBgPb9Cz5l3/95ySCldzkrvKjJLAc=;
        b=ur5amBz1VkQ+JjBi8SP2G2l88kow0IN/Ptp5NYVkhND6BIyu9IxlevOe5BPkbdNVfD
         /hyfJQuULrro85Hc3jsF2ffESNDsA4ZZsWj0x7PxPc1iLheXjjmmh0K3gKL6b5lVMlHu
         eJNSHn4iKy+0oxVp4Mq5NJKwnc6TWcrQBGgOpZJ+z0o4/7eyIMSB8iGWxpnPQl9rrqnM
         x+DqMABw4lcKeMqzW1u6IP2F6X+AQXs8ed0Z8mrjpA++aGSj6uRSjyI9i9cJlMx2dOft
         ZG6M/2GZwK1jHKl588BmBcmBDNst/HAAZdy+vaGimIMezbbp4di0P5SAdjgFDKfP9evB
         cOHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.104 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0104.hostedemail.com. [216.40.44.104])
        by gmr-mx.google.com with ESMTPS id p17si228464oot.0.2020.10.21.12.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Oct 2020 12:07:37 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.104 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.104;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay04.hostedemail.com (Postfix) with ESMTP id 28C0A180A885F;
	Wed, 21 Oct 2020 19:07:37 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 50,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:800:960:967:968:973:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1538:1593:1594:1711:1714:1730:1747:1777:1792:2198:2199:2393:2525:2553:2560:2563:2682:2685:2828:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3351:3622:3865:3867:3868:3870:3871:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4321:5007:6742:8985:9025:10004:10400:10848:11232:11658:11914:12043:12219:12297:12740:12760:12895:13069:13255:13311:13357:13439:14181:14659:14721:21080:21451:21611:21627:21788:30029:30054:30060:30074:30090:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:28,LUA_SUMMARY:none
X-HE-Tag: roof84_28176e32724a
X-Filterd-Recvd-Size: 2172
Received: from XPS-9350.home (unknown [47.151.133.149])
	(Authenticated sender: joe@perches.com)
	by omf20.hostedemail.com (Postfix) with ESMTPA;
	Wed, 21 Oct 2020 19:07:33 +0000 (UTC)
Message-ID: <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias
 macro definition
From: Joe Perches <joe@perches.com>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
 X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Miguel Ojeda
 <miguel.ojeda.sandonis@gmail.com>, Marco Elver <elver@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>,
 "David S. Miller" <davem@davemloft.net>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Nick Desaulniers
 <ndesaulniers@google.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
 kasan-dev <kasan-dev@googlegroups.com>, Linux Crypto Mailing List
 <linux-crypto@vger.kernel.org>,  linux-mm <linux-mm@kvack.org>
Date: Wed, 21 Oct 2020 12:07:32 -0700
In-Reply-To: <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
	 <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.4-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.104 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Wed, 2020-10-21 at 21:02 +0200, Ard Biesheuvel wrote:
> On Wed, 21 Oct 2020 at 20:58, Joe Perches <joe@perches.com> wrote:
> > Like the __section macro, the __alias macro uses
> > macro # stringification to create quotes around
> > the section name used in the __attribute__.
> > 
> > Remove the stringification and add quotes or a
> > stringification to the uses instead.
> > 
> 
> Why?

Using quotes in __section caused/causes differences
between clang and gcc.

https://lkml.org/lkml/2020/9/29/2187

Using common styles for details like this is good.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel%40perches.com.
