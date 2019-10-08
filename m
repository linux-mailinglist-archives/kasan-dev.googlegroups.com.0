Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBOPM6HWAKGQE23YDTVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id CD281CF8B6
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 13:42:50 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id j5sf18692852qtn.10
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 04:42:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570534970; cv=pass;
        d=google.com; s=arc-20160816;
        b=nFOtXhrLIDlQ2cgNMkQMVm18quYCKLoi5nP5C1But0WMAAPeSPhb1CiD07ur0bnexO
         1j2N3lX0lBgyTbZMjntQFzfc7hklql2KeaG668NgM1fiycH3teUnMcdRL78ALr4nVvXa
         bNNuV7VxFWSaPuJoxY27p91l5JbkuUsI9hus49mMXLfteTLc1zmT2XhOFQQHTfgpBZoS
         +Tj0CeNQ1LgGnMW02u9uevZ7lIHq7x8QSQoDAN6YM9IcW5cJf61iCT9GEUsazivmZ1uZ
         v+ymZL+Dp2/26LZrkmT3/NSFbXpddqRpISFrhszfQl0gAgzSqMMN/9+Up04iCITJPvex
         5utg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=45Jf4crGARjavPRCQupBfD/L+WzG0aeM6lCN20NZN5g=;
        b=iQ8sh7hQFQKNYob3QylOLROKHvWGOJtlxraiNrGqlsDLeblKA2/IxF+8tRp33t72mX
         oowtcoXw//XrmN38X/ixwjyt68F6jVHL5aVabC+apomItvaFrzOfV/7Mq9eri5gHgPkC
         C7xJGtQedENZPTKI589Y0uFQ05AxB7DUkjnX6Z5acvz3/I9mVV22Ol7C0+5JMdIKOcok
         STokyShIepCGCTWblg8opDHDnsM9Bd4BUQI7SJ6RddILqLOOdsPNHgsu8Iw+VVfECFJI
         WXPQh/Gy+ShYO8AAiO3SLWalY9hYxKDPOyaP6fE9HY+JLmug7eG7gebuEdS1c9YXwQmB
         RGyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ft1ONni5;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=45Jf4crGARjavPRCQupBfD/L+WzG0aeM6lCN20NZN5g=;
        b=d3lHpXEBjjXDBsydLKgOuyx/qfUGsFBubNF32UHOiaTzRdSUhlgVAvQUyefYpHndaf
         v+pV6aL/yoGAhXP4S620zsz1UkmNFBR8Ol6mnXUfo3F7BvRivFPqtJbUJA809qQA+glO
         +eLuAT1a0MAxYD6tu+tbCziTXIY12ff2Gm6vXwHTCwlVvwXwpMCTqjpPT5CUYEhwbJkD
         P1jMEE69dj4uRcs9NnO32bV8/8762yUDmn6TEGlkZvJh+pBSVqg/x59pC5WLjyFmdqZa
         007KmAJZJKukjTXNKdPL6BL1kkvD49QtwWlJ/ZLLS/kNhly93NJXRVcYfCoQtCy7SG93
         xttA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=45Jf4crGARjavPRCQupBfD/L+WzG0aeM6lCN20NZN5g=;
        b=UHSavrissgTs/OoOY56Cf5bw2c1gll4aqYZQmJvmZ+gprnwlJEYZPstFEQTsmRPBmO
         AsJRTqK+kFTewTVofpnSlOAZHovKT90FC1eRxwjGAOrMyhR5xAatZOEZRab8P+w96JTD
         YvnpAbsWSVJtby+WFmzVbavRI2xdLQwkkFdxiKLJnrimRNQGUr6jLebmVWAj0xUD4x6I
         cATUA/gViAPP4mKhTiqFN7k5Aba9D6P/qXN7imdF0E+a712kTRr1F+Ah1YxTXTS0iBfj
         7pfjX3RDpz35L+gu9rBKmYf1KWldQjEbrjiOb+hqQOzvmbkCTaY5Ub+xocopKEEoMCqw
         KZlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWt8wPnAChZTV9LimJSyMVqRFxM7tBs+BpBrpQhv0hSmWkJQMyX
	Nxc9z+pjQe3/OZZ8xzVCRpQ=
X-Google-Smtp-Source: APXvYqyFPEpAhSyCjRza8dNZ3r47kwZXQYO7J1XYlkSLYg+m85rEuoTk2Uxv+GALZModuz7NigTQkw==
X-Received: by 2002:ac8:905:: with SMTP id t5mr35040330qth.109.1570534969864;
        Tue, 08 Oct 2019 04:42:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2efb:: with SMTP id i56ls1028800qta.11.gmail; Tue, 08
 Oct 2019 04:42:49 -0700 (PDT)
X-Received: by 2002:ac8:739a:: with SMTP id t26mr35500324qtp.176.1570534969556;
        Tue, 08 Oct 2019 04:42:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570534969; cv=none;
        d=google.com; s=arc-20160816;
        b=j0D90BSmqUpwxsbYdcU2qjeqWDn93PU12RnMwFWggJ/onuuWE3OY8/jyQY64DfNZLV
         X27OcQqEeCFyvcfFuUTXpAnAnaQwDIIMQDXN/vVRHKkcVG+XTTXEVFNFdMWSeeRVbzeF
         yU5Fh6o1rES/hhBEeTzc+g9S7Z8XfPmt4gCErTQ5+4ZtN/I+trXcJ/lidoN2huq4Y0yq
         kMofTCOcFDd94KdQGX7KGP+REtjXEVhzK/6+I3YKdA1XIn7i4I67CxH1EunQcvgs1mQz
         b7TUiqDDIGAbJsDYcTq50gMDmadDOYneDZ2il4Uss8jxUwR5Vw8v2sd5DUFcGSoGYeHS
         QiWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=3JJSHu9FsmPxAujVouhMDsGNkk6sBiZ/QmGwiiONFB4=;
        b=gr8sMfZMwi+wmga+6+YPimkNvXtuziBMTFZnStxowsPv1N4EG1+7cZBjSHcqEXsjZ+
         xUV2C2f3PvjG5Bvl1WYjiGkrhX5U8vlM2a02Ug99sXxX2JtQ/R55wPvHKcSKLv+M0DJ4
         ssp34rxpPHPZqiNAtrIx+ThfglDktKntqBDoxETVkyWjcvZfxmh8cZ2yHbrIeTotejWu
         /I36mofuqb32/d9InX63RrVprEIXnQNhNYBzFUH9htlYcBbSXOvEwQVe1bkqXk616UbM
         DauGKrdCOsrtB7Azmv1FHSxp4QMNdoL9f9Ff/DgFSk5eVdiifH3tonRws+6cRR1cjy2w
         oiEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ft1ONni5;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id t186si526556qkf.3.2019.10.08.04.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 04:42:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id y189so16360935qkc.3
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2019 04:42:49 -0700 (PDT)
X-Received: by 2002:a37:bec1:: with SMTP id o184mr28322315qkf.479.1570534969079;
        Tue, 08 Oct 2019 04:42:49 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id g19sm11133394qtb.2.2019.10.08.04.42.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 04:42:48 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy with CONFIG_KASAN_GENERIC=y
Date: Tue, 8 Oct 2019 07:42:47 -0400
Message-Id: <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
References: <1570532528.4686.102.camel@mtksdccf07>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>
In-Reply-To: <1570532528.4686.102.camel@mtksdccf07>
To: Walter Wu <walter-zh.wu@mediatek.com>
X-Mailer: iPhone Mail (17A860)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ft1ONni5;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Oct 8, 2019, at 7:02 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> 
> I don't know very well in UBSAN, but I try to build ubsan kernel and
> test a negative number in memset and kmalloc_memmove_invalid_size(), it
> look like no check.

It sounds like more important to figure out why the UBSAN is not working in this case rather than duplicating functionality elsewhere.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3%40lca.pw.
