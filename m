Return-Path: <kasan-dev+bncBDHYDEMBWALRBYGQ6KOQMGQEUHCVUDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 322226635DE
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:50:58 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id s22-20020a6bdc16000000b006e2d7c78010sf5990875ioc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 15:50:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673308257; cv=pass;
        d=google.com; s=arc-20160816;
        b=B1gxxz8SEKys82f5Ntv1R6Gl6lk6i8MCIx01jPwcKVgW4rkHUvpHqr02Sc1GHUB77S
         WYj/N9tnNwwe2/eePc8hyEMVzD3ScPHqZiNGmWRispjwAENTzaUFKEjuUW6XdmP7vLxv
         6V5WzV5aIL44RBOX36BqPVjabL4mMwjWB5KOtkHAoMw+ufV51dGeZSbjBU/gplPo9abV
         N4AK3lnEQLBx9paI+fXTazONiTX6W7ASHjw6s5sHKoIF188TmTTWtxhZnCGQ0fdiazPE
         CEiwO/grGS6kX9ieQURzsrpJmED/mr3fvFvxJkUtF45JfC8x/S3ZPJ27ca33l1WNVjgk
         c2hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :subject:from:to:content-language:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ExsDxzlI1a9gb9rYv6/EfdszJ4xT4CKh2Ms3j5pgc7c=;
        b=sHYkgEWh/SLR2dxw/yu7vJm1nAOB9E/AYvVu5mjLYJ8X3U3XorXrj/Fxv6r7EEqbiK
         9jSUtOcTy4MWo1km2XJcW20Wxty/pIodrrfrnrJFf7L4+52c/PF7C7NDioL7AwKbS8lL
         0PknE0sPptwT4jlQcH9TBVeoKDfTFA6Pu8EgEguNDhcVR+w63tPZFj9uPiE5mk+9g7O9
         exSN9rvdyv27vJLpFsjiBx7psjQ1tfvVLJqfttUSaWMrjHeFGGitmwzJW4EwDvwj5/po
         BijMF8lQ6Icm7HOjFib5Tv87X8pANw77MPbNG9BnxVHmItc+WKfc4odw3NmusA5rYEXP
         64SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@eskimo.com header.s=default header.b=YbinVSjf;
       spf=pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) smtp.mailfrom=nanook@eskimo.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=eskimo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ExsDxzlI1a9gb9rYv6/EfdszJ4xT4CKh2Ms3j5pgc7c=;
        b=BKs/NKwyux8ABfh2NLAuTyhYBp2Cjj+JEaQ3+XcNXYtZCmRcfN/0JSrXoHvMuJqCvN
         zVAGTRme8ZpFDX9b9pBRT65o7d2FGfHhgQexDcCKa/uyLqZq3nCq2FWpoG/jif/l338w
         K2nny/iTy4lbDBnBU/iHbCCu+4a3e1bPn/NaUsp/6rDTica0Nyy+zPxfYFbt5KZE83hS
         nQWfbogCk/kd6bnyg8XSR1RTOAXEbJ98fjFPAPFUUSQR+n/yS5b8vDiOTI6PardHdY0N
         fBbGReqvsumweye2iHA26K+5IMBFYnqPnLk8RZyl/vGQlvMIpirDgjPMATlp4iLaprrT
         8qDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ExsDxzlI1a9gb9rYv6/EfdszJ4xT4CKh2Ms3j5pgc7c=;
        b=ZylSOYcUVYNRuNWmEyXoM2bLT35a7s26uw1rucHhmE2RyggYyuoZiigDweU8zTsSx/
         pWWq+uj5dWqfFBVKZ4YmaKoS/gWm6vhLaz/4Sk7yd3jauT931PPwi/dYvVUeFiCSUCzd
         R1+ZRq+gu/7MFLEF9pkl4plrd2+2N8THOVbe1lQhBWhc2lENlgRYstSakXAGHA4hLP3n
         d+pAP+G7epX1gg5R+EiGUgLMxjRNfWGdbHS2RH+T66n04yY6sz0O3b9RQCYli1dS1KzI
         ih9TNvyWiSIfv5Cu1yzKHxvo1632/TpXshtDFkHkWdUYIvLDuynC7mDb9S63g8hdGc+0
         aH0A==
X-Gm-Message-State: AFqh2krcBv7GbBTx4RdRfcXeQTjCOZxjCXQw4f6uSmAhWroyhBC6Fvkh
	Uu36ERu6Sjk7Ozknt99NeOg=
X-Google-Smtp-Source: AMrXdXuDVAfnu0YFvpA9hHXs2NBhGLmE4kEmmk1PK8o7VtlsgrIeT2hu0XjygHb1hX5uqffUTfwgtA==
X-Received: by 2002:a02:a696:0:b0:38a:5811:1174 with SMTP id j22-20020a02a696000000b0038a58111174mr6083708jam.85.1673308256862;
        Mon, 09 Jan 2023 15:50:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1348:b0:30d:7b4a:439d with SMTP id
 k8-20020a056e02134800b0030d7b4a439dls2018528ilr.9.-pod-prod-gmail; Mon, 09
 Jan 2023 15:50:56 -0800 (PST)
X-Received: by 2002:a92:c749:0:b0:30c:5d9:8f0f with SMTP id y9-20020a92c749000000b0030c05d98f0fmr36679845ilp.27.1673308256408;
        Mon, 09 Jan 2023 15:50:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673308256; cv=none;
        d=google.com; s=arc-20160816;
        b=zn5hE1DOm89joZ9uTT0wsPi1ppIYRzFxlwd1uLKcBrZX1SYG/op5BCfv54srbP85oR
         00mEEEo3WCJBfyOuZL1wz0fkyqPazfmTOdHFp6Jal7l7pfpPSptYuBjgrr/24iPuGx/W
         YdWwmAMhoawmTOXKugR8W00+wOLMqlDqc/JEAuxhe87H5Nyjj9tQ5l2O4BvZabPf++v/
         Plz0Civ0pHFIOVZeThaTs1Urbe1LfnrcwvQ0At2Q7CTBBF6S4Dcaf4nIkTAJfyBE9k2/
         Q226JW3UgxylcqIKKKRBG6z4TGkXPqliODBxXx2usOBE7s0dP9k0TSHrjzTnlfFIQLD0
         QXXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=ueCBTEiWUMmNdUuHWXtCB7o/wPqctVqUNEQWyROoZrc=;
        b=1LI3BSjflfJMwEQUq+cnYAuc3tqm13u7p9m0WT1mvHeiHXg4Cih9I6K7dFBUt9iMpT
         zcX13lCQj9TaC1pSGBhDqQcY6pkuVEbrsLd6LjW9tXVKX1ri2NdBKfxdOewjjVwjZ7hY
         58p8IiEMveSBH1GbWY3wjRzdUHgLZko8Qzxd50zwBMW1CXRByWQkZrqZnQL+Li0aER0g
         HTom9jP7Uft91SKF7vApfWdTBYgMGaMJUJSYJIUyXMxcDkfCKqfekwHvhgDiwnIruyGu
         W9kfuct8/x7X7weugeV0Mu5JMJelbmaLcygMR2Tk9hWTKU/UERuNnLDD3B9hfr9tVmZ5
         GTNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@eskimo.com header.s=default header.b=YbinVSjf;
       spf=pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) smtp.mailfrom=nanook@eskimo.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=eskimo.com
Received: from mail.eskimo.com (mail.eskimo.com. [204.122.16.14])
        by gmr-mx.google.com with ESMTPS id w2-20020a05663800c200b0038a31b473acsi828176jao.4.2023.01.09.15.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Jan 2023 15:50:56 -0800 (PST)
Received-SPF: pass (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as permitted sender) client-ip=204.122.16.14;
Received: from [50.251.249.49] (nanook.eskimo.com [50.251.249.49])
	by mail.eskimo.com (Postfix) with ESMTPSA id 3293C3CF3AE;
	Mon,  9 Jan 2023 15:50:55 -0800 (PST)
Message-ID: <26cea577-b89a-13fb-7c5f-42c890345bd9@eskimo.com>
Date: Mon, 9 Jan 2023 15:50:54 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Content-Language: en-US
To: kasan-dev@googlegroups.com, linux-mm@kvack.org
From: "'Robert Dinse' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: Can't compile 6.1.4 with gcc 12.2 with KASAN enabled
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Virus-Scanned: clamav-milter 0.103.6 at mail.eskimo.com
X-Virus-Status: Clean
X-Original-Sender: nanook@eskimo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@eskimo.com header.s=default header.b=YbinVSjf;       spf=pass
 (google.com: domain of nanook@eskimo.com designates 204.122.16.14 as
 permitted sender) smtp.mailfrom=nanook@eskimo.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=eskimo.com
X-Original-From: Robert Dinse <nanook@eskimo.com>
Reply-To: Robert Dinse <nanook@eskimo.com>
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

 =C2=A0=C2=A0=C2=A0=C2=A0 Hello, I am trying to assist in the debugging of =
an NFSv3 issue,=20
see ticket #216560, that is a use after free error that is not being=20
picked up by KFENCE.=C2=A0 The developers asked me to enable KASAN but 6.1.=
4=20
will not compile using GCC 12.2 with it enabled. Please see ticket=20
#216905 for details.

 =C2=A0=C2=A0=C2=A0=C2=A0 Thank you in advance for any assistance you may r=
ender.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/26cea577-b89a-13fb-7c5f-42c890345bd9%40eskimo.com.
