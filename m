Return-Path: <kasan-dev+bncBDA55KXUYEOBBNGZ2LFAMGQEONJKXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E5A9CEB3E4
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 05:55:17 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-64b98593517sf10971714a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 20:55:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767156917; cv=pass;
        d=google.com; s=arc-20240605;
        b=W6x/y6ytEAAN8Hg85RGEDemr6RABPQiUq9PgopcLWPmTd4qHbPuaTGcs0ZNzsEs6FY
         pxmtgrWeFXB55JaSMJ7RTpvomHAnh/ErT4IO5yrdX67cJ6/A+a0jcvGw1KSVqzPVY6Cp
         fwNgTIe95WKfOLMwqlTEXYbl4YzC5mDF6FkzqvA59qSJOVYuCQO1Y3Jlh7GpP4qPQa+F
         gdCy0gkUE6yfpQ9O2oUbaqeOX0mengn2cKaeVhcK39wdUCuUqmaasYIi9KNZrPC98D4N
         meJRi1JISOMyoZyw3LVw0W59tfiXWXuPGyOJc/UjBEwHUAkWK4dXyjCPOycQU9PiV4ag
         H7QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:content-language:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=DWwHM93V9ZwncpmWms7LQDzX/J8eLzV6e0JwvhGTsAU=;
        fh=7eeIL+TfXdjtH0PvOqOTW+LINy3hKAcMPwZJC1yNGNI=;
        b=JoK0ZNdjf8Z8L9IkMzvtpNe2wSMDGTb11URpQcS4zHGlblO2ISe7fBryEQxlO+PICg
         hWmxGbohojnJ7uzp302hAaomljb25MNH8tQs5Csx2pCJ/1UJiUGTO2KL+pIaG4EU3T6q
         UHwyEOMPBGL/gIzjDJGnSSyaRwnjSHzIWt3q3T1oOzVn/1boDE7A8PEjd1FrW0ux4qJ2
         HzpBDvT/PxirPjj6e7ySmZtKScZkmr1SBC5WFRg1eJaDTUo+nk42hjnda9WdtEA8crVe
         0Aj5SQms//NNEHhTllbvYORIQ6FYEoe83ZhuCw0GXpzyOoGM0heLkXT58r888uxjIlri
         +7fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=D+c4cDR1;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767156917; x=1767761717; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=DWwHM93V9ZwncpmWms7LQDzX/J8eLzV6e0JwvhGTsAU=;
        b=Axhf541PpbJw68hCRosZF8ALFbJ0kBq9oW3Juwqf2JjnhQ4jSu8dKzr6q5LG0H2H2q
         krY7TMY1OTeDYu6OFt9HBequ/bLXS5sK5aoWFwXUK5B3IiUOZFFbtYIVQsXw/dcrdLxd
         Eo355ciXhty7tqRCDnWHzHBQt/QzDYmqo8CHKLThHqn4NrWoBgSkspswRRNZDUOwnCYm
         pT5tzhAGKY1Y24W7BMTuV0b8DfDxeuZpUIQb0f/ciAhTJoyTjLgSR/vdF25r61895/U6
         zXXT0embthZWs+nzOiBHU6HwtPxJRaqYWt/AZtiRPIVp1DrflKgOfQRiWHq2LPPLwHbg
         2nNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767156917; x=1767761717;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:x-gm-gg:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DWwHM93V9ZwncpmWms7LQDzX/J8eLzV6e0JwvhGTsAU=;
        b=jiz2yBIpDFtT1NOc43PM8c2iNkygMILhQigN57OlSHeaDiCDCZ1iRHc1ppOB2HfueY
         tp3PiOjWYM5vpe3ysqieGtVUgqHAzW7YZEj9eEp3mYfyNxXnc7VtWed0c3YC1HxRrkxg
         w2wmglMbCyzfInXNNhyaeAZxI4hdgl0IqEtM0KPd6NBmDuia33wkYDtsfsNzOAGjSPFg
         i8NT3ul6ZSjSxFvj71KDi4IJYMsls5STG7pcfz0Kyzhf75p6Faj9CIUY3DKzzomhnHKl
         Py5AZAYvyAqJXaRrNB4M7V29Z5ENUOXULStDde2A8JYbUz8yN2+uwQ3KsEAqIEll0qxJ
         VGDQ==
X-Forwarded-Encrypted: i=2; AJvYcCVk15CysZECBK3+cavZV+cRyzYzGTT5mreZ/5xiXkDpmWYF32NP3j+q4jBeMycZG9wQy219SQ==@lfdr.de
X-Gm-Message-State: AOJu0YySgy9jHNJhS4eRgNAFBETBO7GPcmqQJPzI9tFjmNoS4HZCkVcI
	CQK5fh5U3pPZ1bhGIP3xffBne8ha05umZvdcvrvyhPzpy434bANfQZVJ
X-Google-Smtp-Source: AGHT+IF/Jr/+6mr/QNaHVmP2P+OFSMg6gBOB6k+910+uNIq9iZ25GVg0l5qDGO8FfYAR3EzVECEIIg==
X-Received: by 2002:a05:6402:520d:b0:643:e2d:1d6c with SMTP id 4fb4d7f45d1cf-64b8ea61109mr32210158a12.4.1767156916719;
        Tue, 30 Dec 2025 20:55:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZuVPbH6Xwk3m/9waFh+9cqTje/jQ5XBGRE42SXdvGL5w=="
Received: by 2002:aa7:d796:0:b0:64c:7925:f275 with SMTP id 4fb4d7f45d1cf-64c7925f2cdls6879994a12.1.-pod-prod-09-eu;
 Tue, 30 Dec 2025 20:55:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyQkzDE4MkXkW054/mdfkae/ALAGLro8/VurzIFFyeq+/t37WwG5xiOIcVKbjnBcCNp1lfG4QmwlE=@googlegroups.com
X-Received: by 2002:a05:6402:40cf:b0:64d:5693:3e7c with SMTP id 4fb4d7f45d1cf-64d56934297mr26830635a12.28.1767156914046;
        Tue, 30 Dec 2025 20:55:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767156914; cv=none;
        d=google.com; s=arc-20240605;
        b=AkCbhvWHBRwTBWRY7F56Zi+bfxSvPv7q3F1noZwpu7e6aHBkelSHcuiemKOIAyUswx
         kuA2pnv163N2bYv586GXDMr9zmTrlf1YjbTeh1BxCK/OzBrruCb7Hg0vmaO8r4YRadyO
         mDACnUjPkbvVdRNQ228TKHh+KNVqSdULxX4CZ0ac7/KAL6jCMNC89SBxYNHXcNt5zfkZ
         LGNE5IfVIKGGiCGvA34j+eElImY6hys4MY6cXgPDRQKfqqDaxqiXxazWq3zOEVPi5w9A
         qjx1FdQtKLCZmGiQZc6tDS/XRJf020UAEI4hzsKfB7Gg3SoDtzXGZDalskPdNs/1z4r8
         +mew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=j6JiNX4DyxHQ3Lh71drQeQ4TeiUI1sDQ4EAAd5MGan4=;
        fh=4K1BM0yw0oG2hrZpvKL8f49/wHB+hDtO0peqFRDnqtY=;
        b=VrbOfTaxDYMiCbPlHbfhMUMHkstcXR/fQmC/lo6tHyxnAigXBFM+4BXsaTXVj5yxrP
         V6UkbOIzZb9TT+gstF2myAV5Zc5+F4TtkhuKUsIzh/cgxZJQXeEojQlYS2Quje/hnfV+
         3nxk/2o51sO25zQzGobMdILP6/4Dw+qWEQT3mdi0NGd+JaRwFT7WSNv/EnDGkYNJc41Q
         EohWRyXth93Fyt8F/PO5XF88Usfjx5jJGFffOyyyWUxkD77U2JGHU6q4qHJXvGve/7eP
         Aqa5FMnPnIP0A7I5TuiZW6Qy2tmPRZF3WpO5A/xg7beuyStZg8FI3P6YXUurVaway8PF
         uluw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=D+c4cDR1;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b90f5005asi497863a12.1.2025.12.30.20.55.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 20:55:14 -0800 (PST)
Received-SPF: pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-477770019e4so88365625e9.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 20:55:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVyIqqhXn9MbuP64X99615pr/kiowWp1HrCdNtnD6G82O3FQC51PWkMbkpSx4fG7wXPyGPSKjy0mpY=@googlegroups.com
X-Gm-Gg: AY/fxX5FOyHiK2vaty7NiytbSJ/y/3Po1MJ9mu/A26UyFlSXDGwh0xtEKPcgFKf9mYm
	YZUYV0tYNzi06t5VuTqwMiwopGy4K7htNIYA2zopwIU2K0mFCF27fqYdDjdD3qy0z8k65vjeS+W
	KqsTTKOI6qkcnsgGTmT0miQHCShwKBu6TPRbznjinpP7cW0HgUM2gXJCJNA6T86E7cdRc9oteiO
	cI3p9/Z7CaX5nUjOR+xyraqY1/NCtQvvQN5WADO1G1UMLH/TEdha54+CmsfFDM1Je4tM69LCTT1
	UjLKj8kpQVJTSZze1U8/KSKluCJsRalBWEsjyLxfc8HHPQcrKdt+3HfQrh0s4rulDMfsElu5wYv
	+ZwnCLe3F1e1Vc4tQqHpprFh8iPce2o0T2JBB/CCbyiClS6vyROl701C+WMwuGz3c18NKUrONvf
	FNmqKvCHeBN3rtdIK4qK6hdJE7nB6uL5/zxkj7yno=
X-Received: by 2002:a05:600c:620d:b0:479:1b0f:dfff with SMTP id 5b1f17b1804b1-47d19549f5dmr416579065e9.10.1767156913483;
        Tue, 30 Dec 2025 20:55:13 -0800 (PST)
Received: from ?IPV6:2403:580d:fda1::299? (2403-580d-fda1--299.ip6.aussiebb.net. [2403:580d:fda1::299])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a2f3d4cb25sm319044435ad.56.2025.12.30.20.55.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 20:55:12 -0800 (PST)
Message-ID: <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
Date: Wed, 31 Dec 2025 15:25:08 +1030
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Soft tag and inline kasan triggering NULL pointer dereference,
 but not for hard tag and outline mode (was Re: [6.19-rc3] xxhash invalid
 access during BTRFS mount)
From: "'Qu Wenruo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Daniel J Blueman <daniel@quora.org>
Cc: David Sterba <dsterba@suse.com>, Chris Mason <clm@fb.com>,
 Linux BTRFS <linux-btrfs@vger.kernel.org>, linux-crypto@vger.kernel.org,
 Linux Kernel <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
 ryabinin.a.a@gmail.com
References: <CAMVG2svM0G-=OZidTONdP6V7AjKiLLLYgwjZZC_fU7_pWa=zXQ@mail.gmail.com>
 <01d84dae-1354-4cd5-97ce-4b64a396316a@suse.com>
 <642a3e9a-f3f1-4673-8e06-d997b342e96b@suse.com>
 <CAMVG2suYnp-D9EX0dHB5daYOLT++v_kvyY8wV-r6g36T6DZhzg@mail.gmail.com>
 <17bf8f85-9a9c-4d7d-add7-cd92313f73f1@suse.com>
Content-Language: en-US
Autocrypt: addr=wqu@suse.com; keydata=
 xsBNBFnVga8BCACyhFP3ExcTIuB73jDIBA/vSoYcTyysFQzPvez64TUSCv1SgXEByR7fju3o
 8RfaWuHCnkkea5luuTZMqfgTXrun2dqNVYDNOV6RIVrc4YuG20yhC1epnV55fJCThqij0MRL
 1NxPKXIlEdHvN0Kov3CtWA+R1iNN0RCeVun7rmOrrjBK573aWC5sgP7YsBOLK79H3tmUtz6b
 9Imuj0ZyEsa76Xg9PX9Hn2myKj1hfWGS+5og9Va4hrwQC8ipjXik6NKR5GDV+hOZkktU81G5
 gkQtGB9jOAYRs86QG/b7PtIlbd3+pppT0gaS+wvwMs8cuNG+Pu6KO1oC4jgdseFLu7NpABEB
 AAHNGFF1IFdlbnJ1byA8d3F1QHN1c2UuY29tPsLAlAQTAQgAPgIbAwULCQgHAgYVCAkKCwIE
 FgIDAQIeAQIXgBYhBC3fcuWlpVuonapC4cI9kfOhJf6oBQJnEXVgBQkQ/lqxAAoJEMI9kfOh
 Jf6o+jIH/2KhFmyOw4XWAYbnnijuYqb/obGae8HhcJO2KIGcxbsinK+KQFTSZnkFxnbsQ+VY
 fvtWBHGt8WfHcNmfjdejmy9si2jyy8smQV2jiB60a8iqQXGmsrkuR+AM2V360oEbMF3gVvim
 2VSX2IiW9KERuhifjseNV1HLk0SHw5NnXiWh1THTqtvFFY+CwnLN2GqiMaSLF6gATW05/sEd
 V17MdI1z4+WSk7D57FlLjp50F3ow2WJtXwG8yG8d6S40dytZpH9iFuk12Sbg7lrtQxPPOIEU
 rpmZLfCNJJoZj603613w/M8EiZw6MohzikTWcFc55RLYJPBWQ+9puZtx1DopW2jOwE0EWdWB
 rwEIAKpT62HgSzL9zwGe+WIUCMB+nOEjXAfvoUPUwk+YCEDcOdfkkM5FyBoJs8TCEuPXGXBO
 Cl5P5B8OYYnkHkGWutAVlUTV8KESOIm/KJIA7jJA+Ss9VhMjtePfgWexw+P8itFRSRrrwyUf
 E+0WcAevblUi45LjWWZgpg3A80tHP0iToOZ5MbdYk7YFBE29cDSleskfV80ZKxFv6koQocq0
 vXzTfHvXNDELAuH7Ms/WJcdUzmPyBf3Oq6mKBBH8J6XZc9LjjNZwNbyvsHSrV5bgmu/THX2n
 g/3be+iqf6OggCiy3I1NSMJ5KtR0q2H2Nx2Vqb1fYPOID8McMV9Ll6rh8S8AEQEAAcLAfAQY
 AQgAJgIbDBYhBC3fcuWlpVuonapC4cI9kfOhJf6oBQJnEXWBBQkQ/lrSAAoJEMI9kfOhJf6o
 cakH+QHwDszsoYvmrNq36MFGgvAHRjdlrHRBa4A1V1kzd4kOUokongcrOOgHY9yfglcvZqlJ
 qfa4l+1oxs1BvCi29psteQTtw+memmcGruKi+YHD7793zNCMtAtYidDmQ2pWaLfqSaryjlzR
 /3tBWMyvIeWZKURnZbBzWRREB7iWxEbZ014B3gICqZPDRwwitHpH8Om3eZr7ygZck6bBa4MU
 o1XgbZcspyCGqu1xF/bMAY2iCDcq6ULKQceuKkbeQ8qxvt9hVxJC2W3lHq8dlK1pkHPDg9wO
 JoAXek8MF37R8gpLoGWl41FIUb3hFiu3zhDDvslYM4BmzI18QgQTQnotJH8=
In-Reply-To: <17bf8f85-9a9c-4d7d-add7-cd92313f73f1@suse.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wqu@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=D+c4cDR1;       spf=pass
 (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=wqu@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Qu Wenruo <wqu@suse.com>
Reply-To: Qu Wenruo <wqu@suse.com>
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



=E5=9C=A8 2025/12/31 14:35, Qu Wenruo =E5=86=99=E9=81=93:
>=20
>=20
> =E5=9C=A8 2025/12/31 13:59, Daniel J Blueman =E5=86=99=E9=81=93:
>> On Tue, 30 Dec 2025 at 17:28, Qu Wenruo <wqu@suse.com> wrote:
>>> =E5=9C=A8 2025/12/30 19:26, Qu Wenruo =E5=86=99=E9=81=93:
>>>> =E5=9C=A8 2025/12/30 18:02, Daniel J Blueman =E5=86=99=E9=81=93:
>>>>> When mounting a BTRFS filesystem on 6.19-rc3 on ARM64 using xxhash
>>>>> checksumming and KASAN, I see invalid access:
>>>>
>>>> Mind to share the page size? As aarch64 has 3 different supported page=
s
>>>> size (4K, 16K, 64K).
>>>>
>>>> I'll give it a try on that branch. Although on my rc1 based developmen=
t
>>>> branch it looks OK so far.
>>>
>>> Tried both 4K and 64K page size with KASAN enabled, all on 6.19-rc3 tag=
,
>>> no reproduce on newly created fs with xxhash.
>>>
>>> My environment is aarch64 VM on Orion O6 board.
>>>
>>> The xxhash implementation is the same xxhash64-generic:
>>>
>>> [=C2=A0=C2=A0 17.035933] BTRFS: device fsid 260364b9-d059-410c-92de-562=
43c346d6d
>>> devid 1 transid 8 /dev/mapper/test-scratch1 (253:2) scanned by mount=20
>>> (629)
>>> [=C2=A0=C2=A0 17.038033] BTRFS info (device dm-2): first mount of files=
ystem
>>> 260364b9-d059-410c-92de-56243c346d6d
>>> [=C2=A0=C2=A0 17.038645] BTRFS info (device dm-2): using xxhash64
>>> (xxhash64-generic) checksum algorithm
>>> [=C2=A0=C2=A0 17.041303] BTRFS info (device dm-2): checking UUID tree
>>> [=C2=A0=C2=A0 17.041390] BTRFS info (device dm-2): turning on async dis=
card
>>> [=C2=A0=C2=A0 17.041393] BTRFS info (device dm-2): enabling free space =
tree
>>> [=C2=A0=C2=A0 19.032109] BTRFS info (device dm-2): last unmount of file=
system
>>> 260364b9-d059-410c-92de-56243c346d6d
>>>
>>> So there maybe something else involved, either related to the fs or the
>>> hardware.
>>
>> Thanks for checking Wenruo!
>>
>> With KASAN_GENERIC or KASAN_HW_TAGS, I don't see "kasan:
>> KernelAddressSanitizer initialized", so please ensure you are using
>> KASAN_SW_TAGS, KASAN_OUTLINE and 4KB pages. Full config at
>> https://gist.github.com/dblueman/cb4113f2cf880520081cf3f7c8dae13f
>=20
> Thanks a lot for the detailed configs.
>=20
> Unfortunately with that KASAN_SW_TAGS and KASAN_INLINE, the kernel can=20
> no longer boot, will always crash at boot with the following call trace,=
=20
> thus not even able to reach btrfs:
>=20
> [=C2=A0=C2=A0=C2=A0 3.938722]=20
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [=C2=A0=C2=A0=C2=A0 3.938739] BUG: KASAN: invalid-access in=20
> bpf_patch_insn_data+0x178/0x3b0
[...]
>=20
>=20
> Considering this is only showing up in KASAN_SW_TAGS, not HW_TAGS or the=
=20
> default generic mode, I'm wondering if this is a bug in KASAN itself.
>=20
> Adding KASAN people to the thread, meanwhile I'll check more KASAN +=20
> hardware combinations including x86_64 (since it's still 4K page size).

I tried the following combinations, with a simple workload of mounting a=20
btrfs with xxhash checksum.

According to the original report, the KASAN is triggered as btrfs=20
metadata verification time, thus mount option/workload shouldn't cause=20
any different, as all metadata will use the same checksum algorithm.

x86_64 + generic + inline:	PASS
x86_64 + generic + outline:	PASS
arm64 + soft tag + inline:	KASAN error at boot
arm64 + soft tag + outline:	KASAN error at boot
arm64 + hard tag:		PASS
arm64 + generic + inline:	PASS
arm64 + generic + outline:	PASS

So it looks like it's the software tag based KASAN itself causing false=20
alerts.

Thanks,
Qu

>=20
> Thanks,
> Qu
>=20
>=20
>>
>> Also ensure your mount options resolve similar to
>> "rw,relatime,compress=3Dzstd:3,ssd,discard=3Dasync,space_cache=3Dv2,subv=
olid=3D5,subvol=3D/".
>>
>> Failing that, let me know of any significant filesystem differences from=
:
>> # btrfs inspect-internal dump-super /dev/nvme0n1p5
>> superblock: bytenr=3D65536, device=3D/dev/nvme0n1p5
>> ---------------------------------------------------------
>> csum_type=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1 (xxhash64)
>> csum_size=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 8
>> csum=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0=
x97ec1a3695ae35d0 [match]
>> bytenr=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 65536
>> flags=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
0x1
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 ( WRITTEN )
>> magic=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
_BHRfS_M [match]
>> fsid=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 f=
99f2753-0283-4f93-8f5d-7a9f59f148cc
>> metadata_uuid=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000-0000-00=
00-0000-000000000000
>> label
>> generation=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 34305
>> root=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 5=
86579968
>> sys_array_size=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 129
>> chunk_root_generation=C2=A0=C2=A0=C2=A0 33351
>> root_level=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>> chunk_root=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 19357892608
>> chunk_root_level=C2=A0=C2=A0=C2=A0 0
>> log_root=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>> log_root_transid (deprecated)=C2=A0=C2=A0=C2=A0 0
>> log_root_level=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>> total_bytes=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 83886080000
>> bytes_used=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 14462930944
>> sectorsize=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 4096
>> nodesize=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 16384
>> leafsize (deprecated)=C2=A0=C2=A0=C2=A0 16384
>> stripesize=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 4096
>> root_dir=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 6
>> num_devices=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1
>> compat_flags=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0x0
>> compat_ro_flags=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0x3
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 ( FREE_SPACE_TREE |
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 FREE_SPACE_TREE_VALID )
>> incompat_flags=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0x361
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 ( MIXED_BACKREF |
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 BIG_METADATA |
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 EXTENDED_IREF |
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 SKINNY_METADATA |
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 NO_HOLES )
>> cache_generation=C2=A0=C2=A0=C2=A0 0
>> uuid_tree_generation=C2=A0=C2=A0=C2=A0 34305
>> dev_item.uuid=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 86166b5f-2258-4a=
b9-aac6-0d0e37ffbdb6
>> dev_item.fsid=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 f99f2753-0283-4f=
93-8f5d-7a9f59f148cc [match]
>> dev_item.type=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0
>> dev_item.total_bytes=C2=A0=C2=A0=C2=A0 83886080000
>> dev_item.bytes_used=C2=A0=C2=A0=C2=A0 22624075776
>> dev_item.io_align=C2=A0=C2=A0=C2=A0 4096
>> dev_item.io_width=C2=A0=C2=A0=C2=A0 4096
>> dev_item.sector_size=C2=A0=C2=A0=C2=A0 4096
>> dev_item.devid=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1
>> dev_item.dev_group=C2=A0=C2=A0=C2=A0 0
>> dev_item.seek_speed=C2=A0=C2=A0=C2=A0 0
>> dev_item.bandwidth=C2=A0=C2=A0=C2=A0 0
>> dev_item.generation=C2=A0=C2=A0=C2=A0 0
>>
>> Thanks,
>> =C2=A0=C2=A0 Dan
>> --=20
>> Daniel J Blueman
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
d21022d-5051-4165-b8fa-f77ec7e820ab%40suse.com.
