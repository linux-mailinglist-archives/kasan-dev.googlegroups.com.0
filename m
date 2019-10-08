Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBNFW6HWAKGQE5QJ6DOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 37744CF664
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 11:47:33 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id p66sf13778819yba.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 02:47:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570528052; cv=pass;
        d=google.com; s=arc-20160816;
        b=yu7ub86me86Iy74wm+UwLMdh+8v5csZRkYpjmm+CCesHndWL/Np8ExGM/SSce/7r5n
         hBLRfjYPA2LYGZTwkBqmyZ82SpfUes+BEE68tW9e7TEENkxj6AN64tX/Ty/O4RMWBA2y
         UOs2UTDcQIZ403ax1mvdX4ZxwVFYR9R8f5ELuf0YIGcxCPtMGroE8bWRJO98O9M/9gRl
         +vzGrpG6IpeVV3gKJN1Lrs7YkDtw/hItsIOt4z2Z3HAE2nzAUOxJ8JfD4pt0R9bN64Tv
         ooJcvNHbq0vnPYfbw6T5l866JI77O3Z3G7itPmEOy44YXc+owex4V4qkQXazc7QJOugP
         yplw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=X7NJPN0fXz9hmfAcB+dUkxY1LzRB8CVJJgO9OW9rvw4=;
        b=Mg002fWQq9B/HNvrmnItI0O5PXaD85bqDllvHg31i2+vYDaahfcekpeW7bTHHbm8YC
         lt++UKlYKdhbIBYArL8Hfku1Q+1JsXLZLixqJJMOiGUmwB2gYxD1qmpdQJXY0SsmButB
         +CT8wyPYFY7MbxiPjfrJCONoAbOhxaMhksS7GOYSu+1ecCnrUKuWK4FqAQqMo/mQINw4
         z9X06d9a8y04r5yW14V67iSfeWVdDQou/zxiVJ7pZYl3I2BHlhhW8CWYuApcF3wrrPv2
         hSTXQBBdk6AzLziIXm3TzY8WZnfNXjsbkFfrpD3IAuUl8kGvi/pLmXKQshjlvY+QrzMu
         19Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="cXYZ/yJK";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X7NJPN0fXz9hmfAcB+dUkxY1LzRB8CVJJgO9OW9rvw4=;
        b=EzQylMHAJEFWiwYy95bLu88nkQETzCl1Nh1iJY+NYqRPaX6bokcP4H1Z9O6+YyQ1xR
         qxqsqkgx6hlVQ4am7Yjjv6vuXLBfCBY6rtIHkjKskT5xiXTB2fEm0Mq266x4XQOIK8RZ
         FY6phGKPDt7KIm229UrMahgszxqFz56VzMkThH0RVPXGDMX+DgQPKz8DIDiOT9cSv7TE
         CZQOygsLIg0uRIH771jXFFMtqSqg3FWqF8AhdwxWigrSYziL6hUJwFVIi2FZU39nbcHZ
         JE6poVvNtiD8gBb+9oHujBKYrI56zC2NssdXa+x6KW6Mex920hlHOtlAvQJ6h12qtYHt
         /2/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X7NJPN0fXz9hmfAcB+dUkxY1LzRB8CVJJgO9OW9rvw4=;
        b=Vw2eHxnkMHsiyZRynZKO0s7eoyZyXsZ/e165lBaCWMoTYUNfbifVAEQx8XtayAG989
         Rvd487UCelQhoiGlW3851CJNx8i+mdlRS8CnFRJ9vyR4MJgpfNJcubWyQc9l75xTP9ng
         Fr3UHfLK12zTDnH0Q9GrkjqlMmc2GBPuDfVJM0LlNh4Ou37+ABn1UWBWBgGJU/NV62L+
         /Qq33wH8tw+/2WI6jFU9M82MW5uBBfjD07NLlvZ4P0YMwmjRPy7d9NP7NxEh0cEizcWQ
         yOdcY8zClej/3Y56HJP6qE1p+5eSjRyeebsKCnGBCKCyYxcxWNWzAPqOsYb6k3lcOSFq
         vLwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVdOJDQysFiMCs3A2D+9962Rgrn3FG9VW91uDnT5P+pq8H/RP6G
	YeOhiCEY2tjxcYdwuF96VBQ=
X-Google-Smtp-Source: APXvYqx0zyvF5awqsd3i16oZCMIJBMfbRLsLsNoWYK3VSALlRSkMKDC4m7O83VrLP6VVRfLMI+mnUQ==
X-Received: by 2002:a81:3049:: with SMTP id w70mr24548664yww.254.1570528052255;
        Tue, 08 Oct 2019 02:47:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd08:: with SMTP id d8ls372747ybf.1.gmail; Tue, 08 Oct
 2019 02:47:31 -0700 (PDT)
X-Received: by 2002:a25:9d06:: with SMTP id i6mr14353072ybp.445.1570528051931;
        Tue, 08 Oct 2019 02:47:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570528051; cv=none;
        d=google.com; s=arc-20160816;
        b=nTcpLew5v+HrEFJc1qoOgdJPP9YkBBBx0cZ4qUvLZ5iF5plI6+94oBWxJijlVahux6
         iujfk7fa4/ihP3jxiPVJPuC4VBq3qph5rhPfODGKNNSCvn8T9Kdf6JVFexYH0W3TZKC1
         xYWXEhD9nFN6CMNR56hWADobj+xEXH5gc+CiHGstMv8e+Rez2HRMYWGcvUkAKMD0i18R
         79MxUdSvchnC9dI3CRnLkK3MXnvv4KyvXDDIOSim6OyafiBDDqiYfT+Tirha9mb7A8Pn
         GrICyNe8RrWCWz7nfZgZ6+7deuXtULft0GWcEGKziJAQ5T3+DAfsmyHFQqV452EIlYJD
         Bd7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=qLgfnJa8TF+fqJn6Csm2aNbaRpOd4zDzxzOPf12HbGU=;
        b=c6gHAdRf1k/g9F4hJXQrVebjC7xga/zftP+Vf0Q/TKEydYCqAfxnswjUxeZ3jhiB33
         kn86D4MOCTts7I34khX+y7NUV8L522T+9xil5qv5Q81BiuP3Sia8g3+fcw9PAmqtQhl3
         9P0f1tFMPjtDCGL9qJsR+0ATlA1lJYApQ46U3zYZMQvR3fTLLlmKfykgMQBNT0HqR/34
         hYv7FrbHQzpejRkBmCedCLbeyrfo1ioMD43qGXByqG8mE0E/YDhZY+uU0gMlU7MPuZB5
         BQ+PwQJcD8TMTmbe2r8YLIiq6u4h7CbmU+AIb0G9PQTx9KHhpBINJ+UuZI5khKNno60u
         juGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="cXYZ/yJK";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id x188si639668ywg.0.2019.10.08.02.47.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 02:47:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id f16so16018570qkl.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2019 02:47:31 -0700 (PDT)
X-Received: by 2002:a37:4d4a:: with SMTP id a71mr28591867qkb.327.1570528051524;
        Tue, 08 Oct 2019 02:47:31 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id h68sm8988573qkd.35.2019.10.08.02.47.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 02:47:30 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy with CONFIG_KASAN_GENERIC=y
Date: Tue, 8 Oct 2019 05:47:30 -0400
Message-Id: <B53A3CC0-CEA6-4E1C-BC38-19315D949F38@lca.pw>
References: <1570515358.4686.97.camel@mtksdccf07>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>
In-Reply-To: <1570515358.4686.97.camel@mtksdccf07>
To: Walter Wu <walter-zh.wu@mediatek.com>
X-Mailer: iPhone Mail (17A860)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="cXYZ/yJK";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
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



> On Oct 8, 2019, at 2:16 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>=20
> It is an undefined behavior to pass a negative numbers to
>    memset()/memcpy()/memmove(), so need to be detected by KASAN.

Why can=E2=80=99t this be detected by UBSAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B53A3CC0-CEA6-4E1C-BC38-19315D949F38%40lca.pw.
