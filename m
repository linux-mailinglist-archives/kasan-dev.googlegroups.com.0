Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJ6WS2AAMGQETJI7IAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 132CD2FA4DD
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 16:37:13 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id gj19sf8126725pjb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 07:37:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610984231; cv=pass;
        d=google.com; s=arc-20160816;
        b=As+DklyxPDDEQKRMD+pNDsXdjLYaUle8P0DzIXA2XSETpAjO+FaWtEsxCBO/LGgnRw
         AWdrhBNcz6NJX/IXTIo9Bjgkc/VCyauuz/6mWrUM1MudQkOfVIL7D1FntK710GB5XGB2
         Wo71MPB3Lt7kQl5Q1adoHx+GwxKkNPUEKgt9KzkYKoy40qNbM9SrioCmu3MP0VGE4OyD
         tIyZu+pNvauMrKEsM36kHrpmrY4U9OsTK9mgy2EXjK3Ugr3GHYSSRruW6zAwwPp6fB6Y
         4Aax/Yye7jXE8XmjdeU0g/KE5rTJnbFiv64JcUePveEOtyCGUYC8nTxTzMvC3jPYutI/
         PpSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=sUxV2tceiIV63g6YSmGn+ULxuHgdVF3m7rcww1MJNF8=;
        b=bixc6t4a0WOyUOD3KU3j0DfNzWWZVB9lWCT0A8RX9ADxHCS3UzW5IAyH6m8L9BnHys
         GSXhM9qcEC2CcfsKaZIOVUUmkNbkw5ymbFz01xDLPfayD64eojrRmUYPRJoqAzLQ3KuD
         4GF8XGCBoVYdWQeDcYry0Ogz5+00/bBzCyvRTvnHSn3v5JFJj7Ofjw+ZblID8I3KuN2X
         V+W3RFMvuuE40PdEpKpwEBhaWItsmPs7so4gq/gxs6ZLymv59SQ5DQ6EI0nSMDi3ud70
         X05QKyE5gXg5fcGQj5HOlRnG4kDkHTrRKck+sxfZMEEJK1FUY3f7/xtWNGCE5A85Jr+V
         6WeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sUxV2tceiIV63g6YSmGn+ULxuHgdVF3m7rcww1MJNF8=;
        b=g4/6y5+XP5rG3pOo4WGqgLmksNp+5gEqxLUFJK6Gyle10MeunxJZivMJUEh1Qu60LZ
         H88g8XRENYbhFbVHxA5SYNnzO5MVdQd/w9QKP5JuZYn5cYCPXpeuJhh6strhIHHHaLxP
         bqXpe72w3AVy2aYr6CVRugQbLGfoRmNNK4bSPMrh2MfWWbXmJWiMLHj0MX5VyYTvJsyI
         CibNerXmXAnP5B8bWSfg5hs4kOATm1Phu9qR+9PShDwZJLTZZ8C8TM61yxXrfi8xnC10
         Flm+3ej3gxkZcskINyejlBYNDg5de4wj2NM2Eh9S3v4Q+SjQ5BDiPOq50zlpSu01MgEa
         adeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sUxV2tceiIV63g6YSmGn+ULxuHgdVF3m7rcww1MJNF8=;
        b=LKhJJLFMZ8SXhUMqTl8XTSSmvJnsCQX3DK1iau9bDbweMbQBIW5eDvc8GUR+o2AgOm
         2s8PBY+KefiuGPLnASFr2keIYfnvSOyVfOiNAW8Gk8s0Npmx36qwr4xmBwrJjbckF8kT
         7XG4NOwc3oHe4kBi6L2J2EyaJXFZ8JHvs8yTBa9eHk4yRUj6VEWbaf9fxYy9p3NHx6hv
         tTLJrp07WMKTdPOL2W/fcyYXGiEZ5XZLZnWpwEgHTTRzYOaBGxPnN0zYBT8sTzjjw+lx
         1Wxs6wd2Ulq2xdBL/G6ix3E/gZ/tZQu15QmMnlQPFur4VZV01DUUXAQG/ZHZwBhNvsyg
         hKGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319k4eS77GDsEYwmIYeKNle8XfELAEEmutqhqlFBQYmyltP7Xko
	a6vYFy1PjEk9TxC28ua8KKw=
X-Google-Smtp-Source: ABdhPJwNTeydvsBtWXJItT+76A1P0liZisisb4X2CMHi828c54imMPpNRQGSzrqriYCufby3HgyzXg==
X-Received: by 2002:a17:90a:f2ce:: with SMTP id gt14mr27118811pjb.215.1610984231560;
        Mon, 18 Jan 2021 07:37:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea89:: with SMTP id x9ls8331367plb.2.gmail; Mon, 18
 Jan 2021 07:37:11 -0800 (PST)
X-Received: by 2002:a17:90a:c595:: with SMTP id l21mr11927635pjt.137.1610984230655;
        Mon, 18 Jan 2021 07:37:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610984230; cv=none;
        d=google.com; s=arc-20160816;
        b=l+xKYEhMqoVBEqAb64fYZS/3O1t1P69CLs2E6/D4Qvq7OAeGAXrN+bP1LgSdHj3/1p
         jp+8QgMw9pY+tPWirOZ8ySm6wisV6W8+go1BolqgiaUxTF9mIZ8eLYPRhM1alNl5XJy9
         warHvlEYFI/IqpYzFtwQYj31HUoV75G7hZrt40S6fd0ktTOd+kBwvpTioZf0OUnMgW5b
         OWjGf3jnhMuy/WNkevxgcNh25cWCSMA9Wj52cHB6xyceHH88GtRWn4pQTB9xN8vVexUa
         jPI4rBTmnciXzpUaVUkxFFMXx8kbDMrqhijB8wI+n19Vk2fG2zY8JHj0h8NYex9T59gY
         pJcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=C20zWByDAKZACSCttXLVeMrDHjLRfuViUsutVIY0We8=;
        b=b5XpLACuyPUsfxuyZNiInDfel4x8cf3zQmN3Ou/D+wGMImmlwTuyBkYbEoQdM+fUy7
         pwUbpAvFkUGh3jzlQFqHOoTg9enHzR+C/pWM1xHQ5ra82fiqTeJnSGdN4bMh8V10J8i4
         qgGW74tjraHmE0Z11pUpI+ap08VtV7zino9R0hWcyXvYxWbsooYfO7pUR+SoUWvSAWRp
         pUkz+jr4bhjCdurGV6bXtyUqJkodOloZy98GZwGWNA7/WurIAd0f4N75I7KIxhrLabYy
         ueaEMU0Gzxu5vU2fCWiqktOm5cWgbB3c/IpL4W0e/sBMPVgmnTOciQBRSi2A5dBg0NPq
         ro7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id jz6si1310288pjb.1.2021.01.18.07.37.10
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 07:37:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CA3EC1FB;
	Mon, 18 Jan 2021 07:37:09 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4AB043F68F;
	Mon, 18 Jan 2021 07:37:07 -0800 (PST)
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
 <20210118125715.GA4483@gaia> <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
Message-ID: <330506b9-b7e9-8fda-889a-0827229e1a3d@arm.com>
Date: Mon, 18 Jan 2021 15:40:55 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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


On 1/18/21 1:37 PM, Vincenzo Frascino wrote:
>> If a speculated load is allowed to update this reg, we'd probably need an
>> ISB+DSB (I don't think it does, something to check with the architects).
>>
> I will check this with the architects and let you know.

I spoke to the architects and no speculative load can update TFSR_EL1.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/330506b9-b7e9-8fda-889a-0827229e1a3d%40arm.com.
