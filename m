Return-Path: <kasan-dev+bncBC7PZX4C3UKBB45BUGQAMGQEGMWKNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CEDE6B0271
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 10:10:12 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id z14-20020a05640235ce00b004e07ddbc2f8sf14233639edc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Mar 2023 01:10:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678266611; cv=pass;
        d=google.com; s=arc-20160816;
        b=YKMg3b0xrCsCXxgsYm+ZlPnN0tG9yXCV2qkLHuRce99buD3ELLr1XXDAsG1VNRq/FN
         p2iUBvMRHfkmKsntY6BG35zlpuHABafwM8L8nnxUAw+nVJbRvXhiwx+D391nec6CKcuU
         PqajB82Jhus+JhdPEXPzqUusvEZeVWHNvbHk+K8pH4PIzy40LxPIJ5tJupxMLDHfSBeu
         R5WH6jqe66maVpqUB5JHuFxepC5G6t4NoV/1qVD+fpbQpnV0Mm4XfZcFAklJ8CBxEYCo
         7nGZ+RsUKuRBeU3lGpP8rj3gFFf2wQe8iDFw3N1Sn9Hm8jjdDZj8FEUK/bf9rrriCq0r
         JxVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NUSoVPvMQclQkrjQQASMKjqNEgpX59cDTI7pobcTb3w=;
        b=jItKw+ctj4e6oC/cVQehsswCnEKZFOfPVFxKPAWQs1u6HDk4GPEolyz0r2muhIK57Y
         E84CTGbEXBolep//kGDgK86l7RJTffCxAbuSr52SNqXOnDkkbEWq7O0ZYGkicr7XlH0X
         Qj7/BsfMmJ3Jf4/1DvrV77A0IP2OWCmR0KkqgyXaZ6Ro+HPtKHiUkQ1Oh10NlKdUkzIa
         eOElsEjwDnETEfLXwtzpRsmjpcO5MZbVCeqGz/4c4bflzZQMTWbLeafcaZ+4xGB9qauE
         Nv9O0PKSOXTgMFJkOsMlV71qtrboUmkSL8u7am7nzH11xtTDC55IFapn451ge9k4JWPB
         aDAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::225 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678266611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NUSoVPvMQclQkrjQQASMKjqNEgpX59cDTI7pobcTb3w=;
        b=dpvjdDJcGqButP3AcG4DRLWEc+KEBe1O8rySdq1Ff64CJzCZ4vaqgI7xuY3IQrj97H
         HMiC9DVRlT4YWVysOsGr+piXswaKIZO5AZsVKW1M/QPq1rfLB1i6c5llB0ucDBoKbfSo
         EWMBiln+hZJtrea8jrCnki+xbjTBNrrc/6qOogoT6mmRpK13IkRha2Bf3TKL2tmFPlB0
         KdTFivXl5Fpj9rgKHj92jcUHllriH2KGHnLmiE6Xr5r5En3PD7G6oxOMLNp5W3PzU//x
         jmqzXFVjA750QdsDug9i+eD03d51aYAs3vC7s1zeVxppxnbAzR2gdMP0F5rwH5DtcF6X
         GwTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678266611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NUSoVPvMQclQkrjQQASMKjqNEgpX59cDTI7pobcTb3w=;
        b=qqFQXep0rnwwdwYhVIzKsGxUOvqbkpDiQhoV2gJrYFNxwBNqehyGCW+SJi5yYC4zs+
         AK7uzOOoO+2EEuYCokC0Q0qcR2ds0n1ntO/1+HU1wlon7GaWNPoV4eu3bR8k6YwUsbCp
         Ol4pkyTjFS7YlWhUyfEPJs2Hts5r6crgv+0ckKsOEonnm5uYmxiqLuLhbxIfMehZDQt/
         pBs4FyQSGDrlCFVLqrzDxlGdafpd0K/1sOl7orpdcOog6fzVwVlvuowkFevVXvXkfTwu
         PpG3RAuNpx/iGto10QU7vCUp4Fo3pGhT98THTLqT0d9sPV2/d4ggxigb/ztPQmTX3EwZ
         Peew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUiwKFby6VCP7iM1rscZtZoHiixEeAQe1n1GC03YFNEQwa9K4BG
	xmwvjdTSf0u1qtkVXCctKls=
X-Google-Smtp-Source: AK7set9WcXOKv/stewaqt33ZRwUtFRCttVu4Vs86zB+dl3adpYoNWJFDimyocMy09twzcK8bocRk/g==
X-Received: by 2002:a17:907:724f:b0:8b1:3c31:efe6 with SMTP id ds15-20020a170907724f00b008b13c31efe6mr12690237ejc.3.1678266611510;
        Wed, 08 Mar 2023 01:10:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:76ce:b0:897:68a7:5262 with SMTP id
 q14-20020a17090676ce00b0089768a75262ls10453419ejn.10.-pod-prod-gmail; Wed, 08
 Mar 2023 01:10:10 -0800 (PST)
X-Received: by 2002:a17:907:728c:b0:8b1:788f:2198 with SMTP id dt12-20020a170907728c00b008b1788f2198mr21732553ejc.19.1678266610077;
        Wed, 08 Mar 2023 01:10:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678266610; cv=none;
        d=google.com; s=arc-20160816;
        b=k/Njw0YsO9HBzaJqQpa/CbHiK9RqSqv4zN4/+K7pdotW50ULAXZ9KE72ZPQuVkVFNE
         0PlRuPmRU4z1RX1iSgRofG6+7NIrSHsyBDBKAU2+sDXBcd1VgNlHYpYUwX73zzaSjdw3
         JsPVP4IEXa7CQu95NjWbsZeDGQXAHSb2mdCRnI3MHsdOK3iZvUDpHlr2gRInQ1Pt2cCP
         G3aGKX0xMwgWKFgjMOF5kDbx70eugmfUJA/j54qIOHmoE934O9r02nKakVz3x+yqDmoY
         w2uAikagQ8ZOPSTLvdS966k0jIfKyrHpjg2HkUdnCKIdRDYKEA+eVg+VzasujQABNp8v
         IkUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=xn98x16UkP34rNQ4zmPGzHb5Q5aSpsbldan7joLE4/4=;
        b=nK1hw98zSBbZTCNIAICbuHhRk/uz9fsW3+8UDwZuOAF0LmpwxK6Br5kdRe5x7YIlp0
         u4xtxVC4UO0KkM/qOQjBdxXS30ABe0oUF8cQ3Tr/5l09VIn94nqzu+JuVtOoF39Q8AYO
         i+aBQriRtHQYIP/beLAkW3KF/WNNRQHEPDkvSuQ7xX72YFlJF6s46efq/0k8lzfkyU8J
         saK0PiWf5LAXDVdE0n1m7YBiUQSIJ351mg9AJinMt6EIAtRzVwzb4VRxrTEEgq5gv6G6
         SZMzVReGMb/CsGTBiJkwTmkyvKdkhiQ+JqQxbK2CKWpSgjTglphRT3cDejX5pdf6+crZ
         4Q5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::225 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [2001:4b98:dc4:8::225])
        by gmr-mx.google.com with ESMTPS id qa18-20020a170907869200b008dbae985b18si494795ejc.0.2023.03.08.01.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 08 Mar 2023 01:10:10 -0800 (PST)
Received-SPF: neutral (google.com: 2001:4b98:dc4:8::225 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=2001:4b98:dc4:8::225;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id 1348C1C0002;
	Wed,  8 Mar 2023 09:10:08 +0000 (UTC)
Message-ID: <45046a6b-78cd-c2a0-6463-0bc40594164c@ghiti.fr>
Date: Wed, 8 Mar 2023 10:10:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: RISC-V Linux kernel not booting up with KASAN enabled
Content-Language: en-US
To: Chathura Rajapaksha <chathura.abeyrathne.lk@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
References: <CAD7mqryyz0PGHotBxvME7Ff4V0zLS+OcL8=9z4TakaKagPBdLw@mail.gmail.com>
 <789371c4-47fd-3de5-d6c0-bb36b2864796@ghiti.fr>
 <CAD7mqrzv-jr_o2U3Kz7vTgcsOYPKgwHW-L=ARAucAPPJgs4HCw@mail.gmail.com>
 <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com>
 <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr>
 <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
 <CAD7mqrxY_BLP3fS0BnZNaGK+4j2cFjPYyWKehh7oe1f95Ca7iA@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CAD7mqrxY_BLP3fS0BnZNaGK+4j2cFjPYyWKehh7oe1f95Ca7iA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2001:4b98:dc4:8::225 is neither permitted nor denied by best
 guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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


On 3/7/23 03:57, Chathura Rajapaksha wrote:
> Thanks, Dmitry and Alex. Let me know if you need anything else from me.
> Please let me know if you have a fix for this bug, I will be happy to verify.
>
> Best regards,
> Chath
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv


I'm about to propose a patch for this issue, if you can test it, that 
would be nice,

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/45046a6b-78cd-c2a0-6463-0bc40594164c%40ghiti.fr.
