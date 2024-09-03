Return-Path: <kasan-dev+bncBAABBDNA3W3AMGQEVZVMFXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1554596A622
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 20:06:07 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-204e310e050sf62750665ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 11:06:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725386765; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nux8mXYuXWPaS4MruKK/jobwMg+43/H1SseUST8OTuKC2zJZwTQr+nJWElgVNR2a6q
         KIR7hE+3dP6vwQNejXYrwOrA2V6C5ejBRYZIyQPw02OD/XXiIQVmaabVtz+ZJm6+V675
         08XW+ULkLRisywDKq6jUrawVzylMV5wvXIzUUD7REC/M3tpSoz3DsVNCEduCtXav7ic+
         K0STgZckaxG6pH0/pPb4fDXo13Tx4Ps6q7Va+0LLfgoegMfxjqImz+jWP0KqD7ZFz0Iz
         PDVjWTyRu3NJ7/rRJYfLr8cy0+761nhYwxeDsGsuvn0nrtdOdSH4X6LlI2cUYIZyJSzj
         tQkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=ZhXiDaP1ZDqTh4OxrwXJ93Yd2h3UzwMe/jgMbP7e5aE=;
        fh=4oJvnwvIvDxKvGLvGGYWgaiqyKUEEwfRJf16uZAR6Z4=;
        b=MwX9qOw0PW3cr3uTbPLW4/X4A6JWe3RSsIcHi7dasuAbUxMW6FMq7Dt07xlpaetDqR
         NNDaAyEfrCpU3Nl7vvXwXEIb+IWqv5Uiw6sXO567cDu2SiqjKsO6zp/x8+NGPYWTn/UE
         V2TGKiFyzglAh3m4QSv1GAt5jDwIJ6fvAWeW7apkyjiBTTKI/Fg3/5p6GOB5Lzfn72i9
         sw9K4O+a9ockmQXXMCTDLUmwyG4ayFizSSolJPw4itQ1CNSFvN1nB7kfAWMqtMpJy71A
         fDTIWMVFelfEuB61LohWNQsyLFH9uX0e8qsTMe35iWNyoIFgWhda0/BH63pTKQQLtav3
         8FVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 52.237.72.81 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725386765; x=1725991565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZhXiDaP1ZDqTh4OxrwXJ93Yd2h3UzwMe/jgMbP7e5aE=;
        b=IEknMTUYL1GbeDhMj07yd0aAHtkQ42wkrNSiQdoTZd3GRU4GJ/96qyxiR0uaGHvcSz
         wZQts8wfIqXcoScP05Q7CkL+MlCpCt526TfqgHMZg143eYO6M0yr4uKLvP9kYpz4TSOo
         vSxeKy4p/ojiQtl+nyzcgK5/xwafVGwLVD19QG7Ui7GBk/75x3mUNkph7rFkcJ8BsENl
         e0OJcVLMPS6pmiQteGE4tmCUtXiyoReiY8MnmUa7JN8imspGLdcfehkEuY3F7ay2MICB
         wLe+LvR/iyMo+8RMzhrbhY98wjylyvrR9qRP8zCfvH6t9wztJXiE6l1WNOCA8JmQ0zu1
         hxcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725386765; x=1725991565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZhXiDaP1ZDqTh4OxrwXJ93Yd2h3UzwMe/jgMbP7e5aE=;
        b=dCWFPGK2rbWPxIJJf6uKfqyavFR+NvFnfpAuCur7gUKDasOIzw5VCKkPUeVv520fRE
         25rO2Bnwh6HY7pgVE3PTFmb1/ap9S0Emv57+7UnrT4HiSAGSisK2OorBREYBxpmhXq4K
         eTLDGWjA3jV4X6MMyVKP7bnCsW9fkWc8+03Q1/C8QowUYsnb9L8Z+FX0Gs9pcwTAkdDE
         lRumUDUIOW8imCcC6UInr2Z/+SMRWvSt6L4TRt3h+zHOqgIadCNgrZD3+jYY1iGyQ3tL
         u/udUaL3ud9KEBBMhomt033n2BgcVhZbnxQLUr9+RMv+PzDqm8P7Uu7KyT5eZI1QyN6J
         vz8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8Ad1s+ukwI7CngckMVm/NHHzbldqesvjKkfFrYv/npRW7GMtIAFCkeT9l8YcIRmlZZ5tbqA==@lfdr.de
X-Gm-Message-State: AOJu0YzIkl4cl95VZmA61ohIUFSJrRZ7DiUzmvDfxjPRBE+uNS7RFZGD
	u32pZlwk7UHEXbTGviqlNTIZnQl2oIg5nUE4De8Ho3Iu2jMNwNnV
X-Google-Smtp-Source: AGHT+IHRY/gcYf6TEObnP0+idkOseaQLOBLaLFX8VF/1aRxZ0J4WgowpKmjKmpkgarlHYRib8QmtQg==
X-Received: by 2002:a17:903:228c:b0:202:19a0:fcba with SMTP id d9443c01a7336-20546b35b7bmr151073525ad.41.1725386765269;
        Tue, 03 Sep 2024 11:06:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:934b:b0:205:8407:6310 with SMTP id
 d9443c01a7336-205840766aals12730835ad.2.-pod-prod-08-us; Tue, 03 Sep 2024
 11:06:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULw274Ln6mJgO6neN4m0iRWuxKDWzRsRwfJ8SpMvxskSlPBM69QKtZz+HUvXL3ah3c+NBikcKsuCA=@googlegroups.com
X-Received: by 2002:a17:903:228c:b0:202:2fc8:da35 with SMTP id d9443c01a7336-20546b550dfmr141405095ad.55.1725386764236;
        Tue, 03 Sep 2024 11:06:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725386764; cv=none;
        d=google.com; s=arc-20240605;
        b=b1ojlffLMm2AOIqBQTxiDv+pPdMUARDPE/tGvn0nPYn+Gl8cuTuVMpmRFemMhbi1NX
         x2iFkvRQSIj5yLzAUZtztGLhxtvNgSZI38VD5vkz/BreQvntLgE/eILidj2IiOQ8Vorp
         P6z7+haQ6EW8gyet0iy/r4B16KP7gFaJlnn9Rt/OTj1rKq0ddLOLw9owfFq23YT0c3dN
         4D/Cqbreiw6uhPsyt/4P0B62GDWSm7P4cwvS6MaoJSPIXsjQPB6N+cfgTNsSq73GFtJ+
         15tMGgFnuOvO3QRa7oQ8AYOTGZx2X219e1BgZQ7r05WnqoUxjwpD8wOyLjY1JFDjsH+x
         x4AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=4xb0IXqcusmtfnwiQPv05OPwWGef3x/a2JPYS8WSY5U=;
        fh=wgz8k11NjnkKj/39pwDldYcxDfFqMxiP4na/Oj5rpw0=;
        b=krGhcXw5A2faGAhSVOTX9/L6sjmAj2bppDeIbMiGYglSKGlt2G4/STk8MrFGDlG2/0
         RBuScOyNABLSX38COXKjBkO5GI7tgi5lLVBCS4+P2O7cdSZT2gYvgh/ppka2eU6pYQoS
         Y3DdTxnvFvDnfNRuVPURg6pU5n4P0wZmgYAPhk1sHi4pOau20zVuHmREV115dMIcs8Ml
         zDmgiTnQWCo0d/bWa9p3Bdupnh9T9kKtECaJtqXWymwU99qc1Fcap2QAcWSjbEmNcIO6
         gwdwaP6EvXHxLw6ktD0ivdeOUt3QOy8oFw3MMY3Edj3NB/07+p0bNUlCrKc9z1cTiuuY
         gNNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tttturtleruss@hust.edu.cn designates 52.237.72.81 as permitted sender) smtp.mailfrom=tttturtleruss@hust.edu.cn
Received: from azure-sdnproxy.icoremail.net (azure-sdnproxy.icoremail.net. [52.237.72.81])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-206ae8bce7csi143715ad.3.2024.09.03.11.06.03;
        Tue, 03 Sep 2024 11:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of tttturtleruss@hust.edu.cn designates 52.237.72.81 as permitted sender) client-ip=52.237.72.81;
Received: from hust.edu.cn (unknown [172.16.0.50])
	by app2 (Coremail) with SMTP id HwEQrABXX8_mT9dmEHOpAA--.10948S2;
	Wed, 04 Sep 2024 02:05:26 +0800 (CST)
Received: from [198.18.0.1] (unknown [10.12.177.116])
	by gateway (Coremail) with SMTP id _____wB3UbrlT9dmyqAjAA--.30797S2;
	Wed, 04 Sep 2024 02:05:26 +0800 (CST)
Message-ID: <241be3d1-2630-471f-9c04-3b4004b5d832@hust.edu.cn>
Date: Wed, 4 Sep 2024 02:05:23 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Marco Elver <elver@google.com>
Cc: Dongliang Mu <dzm91@hust.edu.cn>, Dmitry Vyukov <dvyukov@google.com>,
 Jonathan Corbet <corbet@lwn.net>, hust-os-kernel-patches@googlegroups.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
 <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn>
 <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
 <bd647428-f74d-4f89-acd2-0a96c7f0478a@hust.edu.cn>
 <CANpmjNMHsbr=1+obzwGHcHT86fqpdPXOs-VayPmB8f2t=AmBbA@mail.gmail.com>
From: Haoyang Liu <tttturtleruss@hust.edu.cn>
In-Reply-To: <CANpmjNMHsbr=1+obzwGHcHT86fqpdPXOs-VayPmB8f2t=AmBbA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: HwEQrABXX8_mT9dmEHOpAA--.10948S2
X-Coremail-Antispam: 1UD129KBjvJXoWxCrW7WFyDtw4fXr1fZr43Jrb_yoW5GF4rpF
	1ruFyIkr4kJr13G342gw4vyFW8tF93tr4UX3WUJw1rXrnIvFn3tr42kw4F9FWDXryxCFW2
	vF4UZa43Xw15AaUanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUB2b7Iv0xC_Cr1lb4IE77IF4wAFc2x0x2IEx4CE42xK8VAvwI8I
	cIk0rVWrJVCq3wA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK6xIIjx
	v20xvE14v26ryj6F1UM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j6F4UM28EF7xvwVC2
	z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0x
	vYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc02F40EFcxC0VAKzVAq
	x4xG6I80ewAv7VACjcxG62k0Y48FwI0_Gr1j6F4UJwAv7VCjz48v1sIEY20_GFW3Jr1UJw
	Av7VCY1x0262k0Y48FwI0_Gr1j6F4UJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vI
	r41l42xK82IYc2Ij64vIr41l42xK82IY6x8ErcxFaVAv8VW8uFyUJr1UMxC20s026xCaFV
	Cjc4AY6r1j6r4UMxCIbckI1I0E14v26r4a6rW5MI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2Iq
	xVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42
	IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY
	6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aV
	CY1x0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxUIiFxUUUUU
X-CM-SenderInfo: rxsqjiqrssiko6kx23oohg3hdfq/1tbiAQkJAmbWg7dAwQAFsD
X-Original-Sender: tttturtleruss@hust.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tttturtleruss@hust.edu.cn designates 52.237.72.81 as
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


=E5=9C=A8 2024/9/4 2:01, Marco Elver =E5=86=99=E9=81=93:
> On Tue, 3 Sept 2024 at 19:58, Haoyang Liu <tttturtleruss@hust.edu.cn> wro=
te:
>>
>> =E5=9C=A8 2024/7/26 16:38, Marco Elver =E5=86=99=E9=81=93:
>>> On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
>>>> On 2024/7/26 01:46, Haoyang Liu wrote:
>>>>> The KTSAN doc has moved to
>>>>> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
>>>>> Update the url in kcsan.rst accordingly.
>>>>>
>>>>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
>>>> Although the old link is still accessible, I agree to use the newer on=
e.
>>>>
>>>> If this patch is merged, you need to change your Chinese version to
>>>> catch up.
>>>>
>>>> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
>>>>
>>>>> ---
>>>>>     Documentation/dev-tools/kcsan.rst | 3 ++-
>>>>>     1 file changed, 2 insertions(+), 1 deletion(-)
>>>>>
>>>>> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-to=
ols/kcsan.rst
>>>>> index 02143f060b22..d81c42d1063e 100644
>>>>> --- a/Documentation/dev-tools/kcsan.rst
>>>>> +++ b/Documentation/dev-tools/kcsan.rst
>>>>> @@ -361,7 +361,8 @@ Alternatives Considered
>>>>>     -----------------------
>>>>>
>>>>>     An alternative data race detection approach for the kernel can be=
 found in the
>>>>> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wi=
ki>`_.
>>>>> +`Kernel Thread Sanitizer (KTSAN)
>>>>> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_=
.
>>>>>     KTSAN is a happens-before data race detector, which explicitly es=
tablishes the
>>>>>     happens-before order between memory operations, which can then be=
 used to
>>>>>     determine data races as defined in `Data Races`_.
>>> Acked-by: Marco Elver <elver@google.com>
>>>
>>> Do you have a tree to take your other patch ("docs/zh_CN: Add
>>> dev-tools/kcsan Chinese translation") through? If so, I would suggest
>>> that you ask that maintainer to take both patches, this and the
>>> Chinese translation patch. (Otherwise, I will queue this patch to be
>>> remembered but it'll be a while until it reaches mainline.)
>> Hi, Marco.
>>
>>
>> The patch "docs/zh_CN: Add dev-tools/kcsan Chinese translation" has been
>> applied, but they didn't take this one. How about you take it into your
>> tree?
> I don't have a tree.
>
> Since this is purely documentation changes, could Jon take it into the
> Documentation tree?
> Otherwise we have to ask Paul to take it into -rcu.
>
> Thanks,
> -- Marco

Ok, I will send this patch to Jon and see if he can take it.


Thanks,

Haoyang

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/241be3d1-2630-471f-9c04-3b4004b5d832%40hust.edu.cn.
