Return-Path: <kasan-dev+bncBC447XVYUEMRB34VWGDAMGQEH3SCHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E9B613AC4FF
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 09:27:43 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id nd10-20020a170907628ab02903a324b229bfsf3569194ejc.7
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 00:27:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624001263; cv=pass;
        d=google.com; s=arc-20160816;
        b=sF9BfkBN7pQQNR4AOrKf+pPo+rsPUQI4Qnzm+xF2yNHPXGjp0P9LzzlEZQi0IPNIlp
         1SeY2cV14HBOuqD76GzQvMx3LOUJr2aRcn6h8oMfBtIAoal+0SQfdy4yQzB7uHyiTLo0
         NEiI/7XcyGT5mu2yWyB0bWJusZTUXUPkK1C1a+ZA8VA+q5bCaLrkCroZFTL3VjGHHvmU
         D7rXKohC3ze1WwKEcDmVptbrfkydXHP9R/92Vj3q0kO2XUA4Z37NPpDlsYqQsDIbXd5W
         hTu/cfNvCautnSLrpsnYkpfODF7ButpBfpI9+xlqGCBYLG3rPIA1eVCPDmy0InxBRWqm
         1tsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :user-agent:date:message-id:subject:from:cc:to:sender:dkim-signature;
        bh=g/ke5AvLznwM43ncyMmmtIGln+gUPJG4L/5HoeEPuHA=;
        b=kvXfJSa0dugB1OetXzjXfpCPZHBq4UqCCJbXgLFUdqiMjdXZk+KXncFuPx0v6kibnG
         SNTjzhwFKhCMOEyoJmS55Yk5DEtB4nZrM3YPytBMIsZhFvXHx/XcRFeScGbGijtRuczq
         bOcMRnjuKL9CClsQ5+OupuAwrQE9J1ReXQQFypnnKUXXseyThbktdspm28MLH8nQLGUb
         jk5YSUDstPQrCABSmUPALZTjjsf5zZfJuHbzUWjex5bTxPrafJgwyDlzBQ29KZiiZGBV
         cJhoYTgP1/J/ALYbrk15YwLqcIE2bL+7xSdqhr/49ktqpcbuYrIGzveC1sjRPr3eq6hU
         69jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:from:subject:message-id:date:user-agent:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g/ke5AvLznwM43ncyMmmtIGln+gUPJG4L/5HoeEPuHA=;
        b=mBes1bidCbpsAWi0j7fygYgkloBZIlmrP6kGRAt7VhQE3bZSkNCaRpFooQgZ+Kj9ZG
         AhJhy6R0Avwvvd3u/AAlGG7mB71crCIzZHGoSg4LCLWSORlLtCeHP9Gg+Dnd/kYIgAh6
         1/hRNyetE10EAzmQgC5jET/kLpmngwW4B+KlG8ok92jolVk+Ou7KaF6tDP0eLsiSpflQ
         UlD9rHSpnOZ8TqNr0TGhVrG6AL4lUUV/p1nS73UTuffcuqQl37kbVArvUxWEE9qDYm/x
         FLl/959cXsfcyxssOU/EBMzv50halIrm7jqMouM345HaAX/kDIUPPfzwpTSt7KKxpnSA
         alAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:from:subject:message-id:date
         :user-agent:mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g/ke5AvLznwM43ncyMmmtIGln+gUPJG4L/5HoeEPuHA=;
        b=Cgl65/HhibISp+bsPEx6wvgm0TdJx3iUC5WSI8yW5Np9YGa757dXHSUBBRtaJEimMq
         Lo6JWX+3FndPFdvQytGHOOZNkDK8cxpfAAyWTPwDSau2yTc1MlNJDFyiNsOT1kosGBnv
         Pw3b5HX5h0+wPGXULSP46wtmiyCPTUAE+eqzRiAH2DialxAjR/VXPmAKfek5cyn5Ho56
         JjuCNd07muJK2Z9vnR61lY0r6yQ/RL8tosdtu08ml4FGnf8kEAIdi/6K1H3fu6UmQWz4
         FeiOuBO8WFVNF2nwGgr6bnDXHsqTbx327c+zJR8sMYggAH8g/F7p/qn2S8JNGBQz1VNr
         hEGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316CcWzkaBwUo7bAa7MBVXApdjd5fpaVimuyMjfCPuYocywy7mC
	2V78/aFWZM1klk42zE/3Q4Q=
X-Google-Smtp-Source: ABdhPJyKxWpjFETERHVcWxQa7NuSm3UPlGx3akK+qwvfAHmrwWXJtbwKR1F9NroCwldToc+Vk3ZS9w==
X-Received: by 2002:a17:906:7212:: with SMTP id m18mr251543ejk.351.1624001263719;
        Fri, 18 Jun 2021 00:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4404:: with SMTP id y4ls1678683eda.1.gmail; Fri, 18
 Jun 2021 00:27:42 -0700 (PDT)
X-Received: by 2002:a50:fe8b:: with SMTP id d11mr3125687edt.310.1624001262867;
        Fri, 18 Jun 2021 00:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624001262; cv=none;
        d=google.com; s=arc-20160816;
        b=DQEdAJ4YP8rk6PUXiYQGuM6LecocjgbyPoxWrslnTIcIkejiGUQkVVZRnbBUhGHG2N
         cGQQJEc3wtvbj0X1v00dipJW80HXBV9lAYYqgI14pH99VuapyhPXUZ1e8cTOIn/cP3ws
         xLlBDQ5XYY8BMyACTKA5Ip1pknvSeBMOCwZ8N6fIhQMqe6XfAr/6Qam8oalNXXzLsYVY
         Fph9UMf3SDZt7dZFaSBJMq2NNFDlJaWxH4WZPC2wgtkB0KgyKvNrM5nW1pCX9YfKru6r
         rSmfU2lG47XxzGtddxAqSot4khvfkiqn+hJeC1TcKSCUbWlD5x18RkZtGpOcca0FN2Rt
         orvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version:user-agent
         :date:message-id:subject:from:cc:to;
        bh=oJwFbBWj0BRxkaipnEWIr4R5JZ1fdY28TA/rQe2rz6I=;
        b=MCdP30x6XvLGhai2l5bV1cCBshSiuZmQW9uyNyHzVRe/OqEmu5jYNCnhiY64gtzeCz
         zsZksuscnNk/x3SrwEv3vpsfA0jPDW6e7EgJVf371brCCadqtG/jwY83xs39WZLgVwBc
         lzVKjy8ZHx1A4s03x0EzLUWtDBK8dNafXvWafvsSHRZgnG6A1IuiaLJkrJybL+vQKFOh
         unqUyHpbObb1EwkW9niRF/No19qLZWzhfSTFjV51srdMwlchRmWsheE9nr4HhwUpzvL7
         XyVenNRK6Gw1vk6m57i46hb4k5N6W743VtPnNR3acvahxc+T2MI/IDUsHePJaxbC2msk
         EUjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id s9si394737edw.4.2021.06.18.00.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 18 Jun 2021 00:27:42 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id 30AE410000E;
	Fri, 18 Jun 2021 07:27:41 +0000 (UTC)
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Cc: Jisheng Zhang <jszhang@kernel.org>
From: Alex Ghiti <alex@ghiti.fr>
Subject: BPF calls to modules?
Message-ID: <54bac02c-8c87-a194-c2bc-fdd9bb0959b7@ghiti.fr>
Date: Fri, 18 Jun 2021 09:27:41 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi guys,

First, pardon my ignorance regarding BPF, the following might be silly.

We were wondering here 
https://patchwork.kernel.org/project/linux-riscv/patch/20210615004928.2d27d2ac@xhacker/ 
if BPF programs that now have the capability to call kernel functions 
(https://lwn.net/Articles/856005/) can also call modules function or 
vice-versa?

The underlying important fact is that in riscv, we are limited to 2GB 
offset to call functions and that restricts where we can place modules 
and BPF regions wrt kernel (see Documentation/riscv/vm-layout.rst for 
the current possibly wrong layout).

So should we make sure that modules and BPF lie in the same 2GB region?

Thanks,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/54bac02c-8c87-a194-c2bc-fdd9bb0959b7%40ghiti.fr.
