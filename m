Return-Path: <kasan-dev+bncBAABBLU43W3AMGQELLYUIHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ECF596A5FE
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 19:58:08 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2f515891a64sf54754761fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 10:58:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725386287; cv=pass;
        d=google.com; s=arc-20240605;
        b=kR+KkfJDZSE9wVKOnJqcY8wQn8udAtofD9yNzEYhISWsK5pcKXgFUzMDh3a5p0h6s+
         nNUtSZXdAyr3W1P9ebTeAqQ1dxvfUuTTSVnHyTX4NtTMGyj/JO8Mod7LwZFGTtL/2PjS
         APeN+oByzuY9P8Lf3NcFWPuukt1OKN461hMUf80U2/+c9q62LKww8eia4vpkOb5bJMtw
         E5+8vOPgJd/VWVbLGPN6H8wVwKLHP1leMnYr9d7QXCyHGSvyFfxzfGhX6d9GCVNfR0np
         BYyzFEfgFFydh3H9Td4gLzAvJ5+lXJoTWcbBrqh8m43EsI8JONJX1s1rWN+TyugoGwzx
         wCUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=2UyVK2kaauj0L1LAQ0HseQtxgDWuLisogMSyinrL5HU=;
        fh=LK2OiTHHVbPRP+RO7JbrKdhSwM/l+3iKUI0CQ83Hz3I=;
        b=BJcbJNRE3kYu2OoENaFXd/BoyKay74U4l9D99B33AHJeLHW2il5l12sV6Bhk2tQo+P
         Tunx40NlfrV/X66yARgxifsFKvaSMeNotzms/hGZkGW71PmedyIwhNGGyVCAHlcOKVwx
         HexIw3wTneXurIQNJveAlb8NdzZ//54HTFF64A1LdwuQrEn+WcV9ruA+s64gLP4+9/kt
         DsPXiuvb0o4bEItTqUdal7mqKZhLg1PoGIhNtTSU2WF3bybV2hHAdrnjYyTwBmjFmvpl
         apvCiPFvBjwhjb1kXUbyXrO3DAlXJSJRS+OJxFG/EZQhnyKOF7KqxgZtVZlSAJP4xqII
         8AdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725386287; x=1725991087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2UyVK2kaauj0L1LAQ0HseQtxgDWuLisogMSyinrL5HU=;
        b=MkoOsT2/vvE24QmKBeNyWpw72UmmMZYjtk1qB8xF1ukURPOA02wPbMHKzXD5fE/8VO
         QFG5oRdgQk/jNgqgB28J+PLA44Srd6JStAXlnzLvekGQktIuhqUY4fDLg70y4KUa4njv
         DSTmoSD0A4L/FheE9mFYQvAUVm6xUWocf2octqisZjgAlXWUMLF/6UsENLCmGzkviUbx
         CI2U6wBJfwTRZ9fmHGB5eMhjkavZZ2qbFeUsz6W/iHzRpAQnHGmjSMQOC0ZjPppK8XTh
         5qB8w84i2ejAOiJRP+2XE1FymGwdQOigAH+b8eIjQ+P2oH4QzXUKexPhwLAjb6aQL6tn
         6XTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725386287; x=1725991087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2UyVK2kaauj0L1LAQ0HseQtxgDWuLisogMSyinrL5HU=;
        b=ad+haDJ74Y5r+Yokk2fgxvMF/8Q1h+K4/tDw6sDey2/leAlN042V/pnlETiAbfEq4n
         9VToaIppyzDF5XNHkoWUWisFn51RbRgkojLF2KFaip4cDffSkDAjqv5JCOMmUKzqBK8+
         vJNfMmBSAfrRgBV3Qu/22+ZcRgoHQ/WVZemvRFGKrhqgjJ7FjSFMI1MCy6N/skisyXKJ
         CxZBQaJF7YQvcdD5NIy9qMXlyHXhQulvH4E1KBnYkX++yb/cgsKSqG9RgBtyaSsOTXJI
         gvhwuKs27kYkfG9dZbqVXY/qjlzwlHbJ2ai8tgSPySOx6SAoXJxbv30evVuay6NDTT72
         brxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPw2RbvL3nbtVRYLyNGlsVFEyV4si4eqvXGnIh8+cdIXsikepuPv08ogmfVhmtrpo/yUpglQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy5Qx3zUVAr1xdSvLxIN6HuabMdUf2aW1RYp4MrvHtULfVuUJ9C
	AmvgY4XqRx6hGVt3md7kbnDbHa87pUIhd8x46EoAzKQG3FYAda04
X-Google-Smtp-Source: AGHT+IHhyRNG8e8efQCUopt+uSDD8AgBdd7AM6exvreeTzwP4rj2n3fyD3e0fGGN4+20S4kL6xV8TQ==
X-Received: by 2002:a2e:a593:0:b0:2f1:6cb0:1414 with SMTP id 38308e7fff4ca-2f636a03310mr58172581fa.1.1725386286548;
        Tue, 03 Sep 2024 10:58:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f09:0:b0:2ef:1eb3:4741 with SMTP id 38308e7fff4ca-2f6501bae6als531561fa.0.-pod-prod-01-eu;
 Tue, 03 Sep 2024 10:58:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPvwcvmt3vXlG7v1VGAGU00IEjml/0QL6xTyFSMDgDsJmHROyzFmEAd0arxKxq6lOGTz1QnmWoVe8=@googlegroups.com
X-Received: by 2002:a05:651c:b11:b0:2f5:6b0:7095 with SMTP id 38308e7fff4ca-2f636ab3648mr53526721fa.42.1725386284632;
        Tue, 03 Sep 2024 10:58:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725386284; cv=none;
        d=google.com; s=arc-20240605;
        b=e1vGgYv+NSxGSxVzeIcYWZM1hnnLbm6VlHitnAgEeLGZoTqjwPpVWKYtDyzqOg4JpD
         qdIFfu9Hx1HW3O46LrAfSMuG6xVdFS3yF52H1RoaAF9l92zW2pXXFzwTfaZg9BUUsi5z
         YZgVIrC8MlGL/WjFu0k15ZS4kJifdwa4WDHIBgXyPTdJKWtwORdvUZEQ0S5cNGcRZfeo
         wkvvM8rADfIrQnh0Gz5xsAqhVXtl6+wh4CE43CyJFDFP7EtYb8xZ7Dt2EW7vRu92ktBs
         kH9o/Ws0MKITOr/432h28NqyzfHKIQLGkBmIKPmf4THabZIuYWVWuNrPU9k68mgUCvbN
         1JCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=YpFjfGUIU15KUylfvzClCeLvQUmaqYx9TNDTxmnY+x4=;
        fh=J4pW0YBnji37G2AOYP2Z6n1LE2QI9vAaeu+s9kABp30=;
        b=GzRHobOFb2/raRXQCSy1ykbQvKNfyFTkGy9rrF0Pp8KlGsjI0/R3eXWCpFuGs399Br
         gGuAUxyshFdzRbtIwblehi6Z/CE7v8RlnPISG7YTTnKOcZ92PFRleUMZO/lfg6JtLDfY
         qVg53CbUYzseVbU92J/W0sI5IxcAZ7YgEYWQhm5IDNIfkReQHySo4QtgJPEXWnlSx+p2
         K533vqdMGySIFog/1CKkui6vKZ96NK9KpVRJzkpN572ro5QBUz4DiZd+HMDf1szdvwj0
         9310QShW93uQXvGxUUSoS1m1OVncE7CHWafqd8S02BhKRqyFcrM5kW0XwpKz22Z3tbfD
         PhnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
Received: from zg8tmja2lje4os4yms4ymjma.icoremail.net (zg8tmja2lje4os4yms4ymjma.icoremail.net. [206.189.21.223])
        by gmr-mx.google.com with ESMTP id 38308e7fff4ca-2f614de8911si2378911fa.0.2024.09.03.10.58.04;
        Tue, 03 Sep 2024 10:58:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.21.223 as permitted sender) client-ip=206.189.21.223;
Received: from hust.edu.cn (unknown [172.16.0.52])
	by app2 (Coremail) with SMTP id HwEQrABXX8_4TddmHG+pAA--.10930S2;
	Wed, 04 Sep 2024 01:57:12 +0800 (CST)
Received: from [198.18.0.1] (unknown [10.12.177.116])
	by gateway (Coremail) with SMTP id _____wB3b772Tddm33b7AA--.43248S2;
	Wed, 04 Sep 2024 01:57:11 +0800 (CST)
Message-ID: <bd647428-f74d-4f89-acd2-0a96c7f0478a@hust.edu.cn>
Date: Wed, 4 Sep 2024 01:57:08 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Marco Elver <elver@google.com>, Dongliang Mu <dzm91@hust.edu.cn>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
 <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
 <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
From: Haoyang Liu <tttturtleruss@hust.edu.cn>
In-Reply-To: <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: HwEQrABXX8_4TddmHG+pAA--.10930S2
X-Coremail-Antispam: 1UD129KBjvJXoW7Cw1kGFWrWFWfAry3uF45Jrb_yoW8uF4kpa
	yfuFyIkw4vqr17K3yIgw40yFW8tF93Xr1UJ3W8J3WFqrsIvFn3trW29w4Fga4UZrZ5CFW2
	vF4j9a4Fv3WDAaUanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUU9Yb7Iv0xC_Cr1lb4IE77IF4wAFc2x0x2IEx4CE42xK8VAvwI8I
	cIk0rVWrJVCq3wA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjx
	v20xvE14v26r4j6ryUM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j6F4UM28EF7xvwVC2
	z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0x
	vYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc02F40EFcxC0VAKzVAq
	x4xG6I80ewAv7VACjcxG62k0Y48FwI0_Gr1j6F4UJwAv7VCjz48v1sIEY20_GFW3Jr1UJw
	Av7VCY1x0262k0Y48FwI0_Gr1j6F4UJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vI
	r41l42xK82IYc2Ij64vIr41l42xK82IY6x8ErcxFaVAv8VW8uFyUJr1UMxC20s026xCaFV
	Cjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWl
	x4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r
	1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAIw20EY4v20xvaj40_Jr0_
	JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVWUJVW8JbIYCT
	nIWIevJa73UjIFyTuYvjxUIiFxUUUUU
X-CM-SenderInfo: rxsqjiqrssiko6kx23oohg3hdfq/1tbiAQkJAmbWg7dAjQAEsO
X-Original-Sender: tttturtleruss@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tttturtleruss@hust.edu.cn designates 206.189.21.223 as
 permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
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


=E5=9C=A8 2024/7/26 16:38, Marco Elver =E5=86=99=E9=81=93:
> On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
>>
>> On 2024/7/26 01:46, Haoyang Liu wrote:
>>> The KTSAN doc has moved to
>>> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
>>> Update the url in kcsan.rst accordingly.
>>>
>>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>> Although the old link is still accessible, I agree to use the newer one.
>>
>> If this patch is merged, you need to change your Chinese version to
>> catch up.
>>
>> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
>>
>>> ---
>>>    Documentation/dev-tools/kcsan.rst | 3 ++-
>>>    1 file changed, 2 insertions(+), 1 deletion(-)
>>>
>>> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tool=
s/kcsan.rst
>>> index 02143f060b22..d81c42d1063e 100644
>>> --- a/Documentation/dev-tools/kcsan.rst
>>> +++ b/Documentation/dev-tools/kcsan.rst
>>> @@ -361,7 +361,8 @@ Alternatives Considered
>>>    -----------------------
>>>
>>>    An alternative data race detection approach for the kernel can be fo=
und in the
>>> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki=
>`_.
>>> +`Kernel Thread Sanitizer (KTSAN)
>>> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_.
>>>    KTSAN is a happens-before data race detector, which explicitly estab=
lishes the
>>>    happens-before order between memory operations, which can then be us=
ed to
>>>    determine data races as defined in `Data Races`_.
> Acked-by: Marco Elver <elver@google.com>
>
> Do you have a tree to take your other patch ("docs/zh_CN: Add
> dev-tools/kcsan Chinese translation") through? If so, I would suggest
> that you ask that maintainer to take both patches, this and the
> Chinese translation patch. (Otherwise, I will queue this patch to be
> remembered but it'll be a while until it reaches mainline.)

Hi, Marco.


The patch "docs/zh_CN: Add dev-tools/kcsan Chinese translation" has been=20
applied, but they didn't take this one. How about you take it into your=20
tree?


Thanks,

Haoyang

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bd647428-f74d-4f89-acd2-0a96c7f0478a%40hust.edu.cn.
