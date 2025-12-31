Return-Path: <kasan-dev+bncBDA55KXUYEOBBAHA2LFAMGQET2BMN7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFEFCEB481
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 06:09:22 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5959d533486sf7388782e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 21:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767157762; cv=pass;
        d=google.com; s=arc-20240605;
        b=aWYL6qbLGGnf1GqwPo5maWVoWl6W2E6U2mD/Z+5aP/aB3bv8xNMHtIuC7AT3mb6vj1
         qvpPxx7VHUIShEUbNJ9hQkEdDH0n2tz2FemhsxDEv6a97B8W17SjLm1x+RVXBjMdi7e6
         AXGbWaHtKpGCgxpPKSC1g7RKGBWdtZvaNiFo07gqtwtHtYBzKDY4s6lJcQj9ZeA+SSNA
         HGpZCY5ZxxireNgxYhobslin7+o4xFPRLRIe49/sCCn30GEQqsTNauVrRfadLBbWeukl
         vYZaf+Cr3p3HmcR81snEjxNaMUpbb2MIQ8daI9MqqHaul98m92ZTieDH9CtY48FSU7wS
         aVQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=11M+EPmVb2N6u9TUmSVhIVy6CMi5NrH9oz2rLalzX60=;
        fh=2kKE+C55CIBvujOLzra7NCDMp85qyjsQyOj1WZ/UbZA=;
        b=Bw8nOgbxC7SFRjUvqF9zb9sJzKlOBVtx3c0vmx9vwaHyNjwXKq9H4EC54aRxl9UJLY
         QFIcZQWNazXk6oBjH/MhOiNbwJkKkXNIG46T0jx8C0moeSaDh7OslCyWe5dia5QwFO8P
         Urr8lCO3+pdLSYY8k0grq4hsFgdBYXbsfA0PI0O6bQ/SjouD5yWrD6vq3Iu9ucIacyAm
         F6I5an5N2cRh+Xxme3nmv7yQHrEzknYwZtG7xmrPlbeFMJf8L++Dmdqp0i2f7g7jpMrc
         jyQ8SUK+5P+QhJCH3OUGCIteEJv+O+a+ayUCKci4forC7ZCaDRTp/Y/FfGjbhWjourAg
         LdVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=UVbWD64a;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767157762; x=1767762562; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=11M+EPmVb2N6u9TUmSVhIVy6CMi5NrH9oz2rLalzX60=;
        b=C8OnKOFmoVu7lYoFmtylo5R51A8n97Z3GOE5EvrRNW8nYastki/a2Br8rEludO+7Xy
         cIuepd9uTONVF+hAUSPD3XSnkxeiS/zm1UcZeh5fEW+zWs5gxPpfTkVI6jyCvtdDVH8j
         A9/5V3SfLKU3aFrvIHvEtztZbt9YarLawnzIoR/X0QgjVEdDHqZz8HkIQ9n9mkhoVW6U
         OqI8UN696clLDaCG89FC0CeIMaiL/SUL7psxxdSvJ7BEWv/Vqzvrs3+HFmJu8afa+COn
         tzZ23Xtyi8Iua5giSRm9tAkVfqvFvG/4vFfivhgNPjTcOLSF7UsZjoVNrAM8KIc9L3Ks
         WB2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767157762; x=1767762562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-gm-gg:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=11M+EPmVb2N6u9TUmSVhIVy6CMi5NrH9oz2rLalzX60=;
        b=ErDm0KRzlkfq+37w17V2TzZTGy4ormSRG9wHbt7Fpi4Gw0QoXkUrJkQaEWYFZGTeID
         O2LP/Vlfn10NwDsM74omdYSma+Orpjuw+SounVt/27Yu0fy9UjVx20TkNv2mIJAjNt5S
         wUp+gPHGRB6VHDzMy4NHWti4YPgswchWTnrm762XVbgCUW7JcXwB1U+hKswKCydQsziR
         Me27IO3oxDD9AzEkjLmt/Eb+vZbZ+rmFV/xCxXo4JSU9FvqB1z8gAxGx8Sq9/ZRA9Rt4
         RHQNpjDdw2rEqmFqBXq2sBnnssJzZdYKj8JssBbCXikW5qUiJAFy0ql3OqgZfJqZ0c8A
         UCOA==
X-Forwarded-Encrypted: i=2; AJvYcCX+H5JkMG0rURu4Y50VME9vTiEwq3drA3akRqCA8CJLv/tf/Ei8tjjIRz6fVZAhEYm12AGUZQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPrc1MHMQXvmOtBgb3RjGJJN0NXykBiN/yTS06gf2Zdi7ehwpN
	bdZ1Z8yT7YQdb3ta7cCBJKT2wikdCb+G7Hb+AyQgG0ydxwcfssBbImFn
X-Google-Smtp-Source: AGHT+IGUMoyPZ8qopnqSqkM2C7Qb7YfndqTuou1QkjG7qRStVNfA9j5cBDp6vv30MR2nMc0Be7CGjw==
X-Received: by 2002:a05:6512:31d1:b0:598:853e:871f with SMTP id 2adb3069b0e04-59a17de08e2mr12660857e87.51.1767157761399;
        Tue, 30 Dec 2025 21:09:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbCpPK9mBMaWrEuOTUdsutLksSXYJI85asVyXGdjcvv9g=="
Received: by 2002:a05:6512:1113:b0:598:f445:11e4 with SMTP id
 2adb3069b0e04-598fa405c7cls2861883e87.2.-pod-prod-06-eu; Tue, 30 Dec 2025
 21:09:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXmeWIXkXzrGJymFxI16yXg92HYnZahgs/isdSd2Hh5jM9aI0L3BxrxHGC+3XsBFHmgGNXYSpu/Lag=@googlegroups.com
X-Received: by 2002:a05:6512:3c9e:b0:595:9d6b:1175 with SMTP id 2adb3069b0e04-59a17d5905dmr12461631e87.14.1767157758199;
        Tue, 30 Dec 2025 21:09:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767157758; cv=none;
        d=google.com; s=arc-20240605;
        b=LwG4Pr3oYc4gSsMO2JFqNCO5JcHz3w0r9SSsHIWlqkRRzCrLDb1ZCEBhCb879lbD7G
         P9ggVM6a3hRL2ChT04h/5psrdmEUnqS+ARwQ77qix6ktP9XakMi1PoOFWuoLH+HnZB9J
         quJwJeb3TFUU9L8NUTn7C9IRq4TZvUL9NwM6rZiSHWQ1sae8yI/JtiMtJVM0g+Y2eIIT
         ulrYyuInpOvcD5JpHTPpAtrm54fkcMmMaNymWVa4QrlFbfTXKsAUEyyRlfBRRMjz5nZu
         vGjM76LQ3spKvM/+uFott2fK8+JbBuDiTIuoM7HKw6+aKGw6Z3cqVYahG9d5X0IT9qRu
         3LjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=DI0k7hgIOB6FXoBmvQUNmPn4Ay/YstMhbmqFpQgeUc0=;
        fh=NjVKhFabVOhDqMTA9y+BtTNQnKXcZ/TSiXlRsvKy0e8=;
        b=PLHZUgY8r967LsD/UA+Xscu9o71oKgFUSGc7DXyf7RmxSIbd8e2gLYNfTqqZAZuOkr
         Kba2I1kPg5SgYqLOzY2zUPUgF/vc8GRUhPf66bTfTF2fo/HrrLShZKm7XJ9O2lZpjzlF
         0RXcbdYmhScROXI+WDgjQPu9rrzDZP1+8mnYjH8vQsqwZztGRK+1Kfo3v4WwKAkgvrB0
         ASAmZKyKeDXUqo6Is9VBOWImdYCw4f5mNC0Ha8XsbdqDVk9ku4cbd3TaX499cWtZ2qee
         P3wJZzxvLp+CPCJf/9HiPbCqoG8NNwqj3tlPVQFNb3Sf/SB5nJp+diX4i5DmySi7rpvi
         QFKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=UVbWD64a;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1861b956si545717e87.7.2025.12.30.21.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 21:09:18 -0800 (PST)
Received-SPF: pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-47d3ba3a4deso27227155e9.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 21:09:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWgY4UW8oraFvYcsl0TcPggro+wLXFbc7k8KdVtq6Nl9euV+ibyLIf0B0greRJm0ZfFWt2ZnwHMwXE=@googlegroups.com
X-Gm-Gg: AY/fxX60IS2gYpuI8O2cihH8aEKPNzbFRHR+tn7N4E9gLvw0nBQrV5FsWb5d09A4WRv
	qNJY1AgmsKzMPkM/8j5hqZ4NdyLF9+f72ScBS27ALs81l7jer6rF23ERiisNUZCaKFQ/aOWm9w0
	MIwkplxnOuo9HA7dHXstBahpNEcmmdUiMol7DC/MTDChNhx/9LteyAPWq2LsETbuFAqIydoVdpJ
	Viq94nfHITSExtTG6ywOjKYRLiNBkVaAm45vzelTkPoYGNympbyZv8b9qGF+eivhYFiUWs0tCGU
	X5U/YUaQ9RBKLMoZn0dqktMovC6gGbhfyhUMgbp1TB0uJPWww+LSBlsYfDhsEP3m4C6AFep4rBE
	RDTsvNKDz5GXo7EM5mjHNog6jKqxn9aSXpUKf2i3DxYFiW5TuFENg2MVqDG5Yl1jwUiSzI4aqbo
	x+Q9s0UOcOOhpSwQySAT/bxEHlEM+Tl4LDKzgONHU=
X-Received: by 2002:a05:600c:6388:b0:477:63db:c718 with SMTP id 5b1f17b1804b1-47d19557cd2mr408312175e9.16.1767157757357;
        Tue, 30 Dec 2025 21:09:17 -0800 (PST)
Received: from ?IPV6:2403:580d:fda1::299? (2403-580d-fda1--299.ip6.aussiebb.net. [2403:580d:fda1::299])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a2f3c65d71sm320207135ad.17.2025.12.30.21.09.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 21:09:16 -0800 (PST)
Message-ID: <eb8d0d62-f8a3-4198-b230-94f72028ac4e@suse.com>
Date: Wed, 31 Dec 2025 15:39:11 +1030
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Soft tag and inline kasan triggering NULL pointer dereference,
 but not for hard tag and outline mode (was Re: [6.19-rc3] xxhash invalid
 access during BTRFS mount)
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
 <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
 <CAMVG2subBHEZ4e8vFT7cQM5Ub=WfUmLqAQ4WO1B=Gk2bC3BtdQ@mail.gmail.com>
Content-Language: en-US
From: "'Qu Wenruo' via kasan-dev" <kasan-dev@googlegroups.com>
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
In-Reply-To: <CAMVG2subBHEZ4e8vFT7cQM5Ub=WfUmLqAQ4WO1B=Gk2bC3BtdQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wqu@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=UVbWD64a;       spf=pass
 (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::334 as
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



=E5=9C=A8 2025/12/31 15:30, Daniel J Blueman =E5=86=99=E9=81=93:
> On Wed, 31 Dec 2025 at 12:55, Qu Wenruo <wqu@suse.com> wrote:
>> =E5=9C=A8 2025/12/31 14:35, Qu Wenruo =E5=86=99=E9=81=93:
>>> =E5=9C=A8 2025/12/31 13:59, Daniel J Blueman =E5=86=99=E9=81=93:
>>>> On Tue, 30 Dec 2025 at 17:28, Qu Wenruo <wqu@suse.com> wrote:
>>>>> =E5=9C=A8 2025/12/30 19:26, Qu Wenruo =E5=86=99=E9=81=93:
>>>>>> =E5=9C=A8 2025/12/30 18:02, Daniel J Blueman =E5=86=99=E9=81=93:
>>>>>>> When mounting a BTRFS filesystem on 6.19-rc3 on ARM64 using xxhash
>>>>>>> checksumming and KASAN, I see invalid access:
>>>>>>
>>>>>> Mind to share the page size? As aarch64 has 3 different supported pa=
ges
>>>>>> size (4K, 16K, 64K).
>>>>>>
>>>>>> I'll give it a try on that branch. Although on my rc1 based developm=
ent
>>>>>> branch it looks OK so far.
>>>>>
>>>>> Tried both 4K and 64K page size with KASAN enabled, all on 6.19-rc3 t=
ag,
>>>>> no reproduce on newly created fs with xxhash.
>>>>>
>>>>> My environment is aarch64 VM on Orion O6 board.
>>>>>
>>>>> The xxhash implementation is the same xxhash64-generic:
>>>>>
>>>>> [   17.035933] BTRFS: device fsid 260364b9-d059-410c-92de-56243c346d6=
d
>>>>> devid 1 transid 8 /dev/mapper/test-scratch1 (253:2) scanned by mount
>>>>> (629)
>>>>> [   17.038033] BTRFS info (device dm-2): first mount of filesystem
>>>>> 260364b9-d059-410c-92de-56243c346d6d
>>>>> [   17.038645] BTRFS info (device dm-2): using xxhash64
>>>>> (xxhash64-generic) checksum algorithm
>>>>> [   17.041303] BTRFS info (device dm-2): checking UUID tree
>>>>> [   17.041390] BTRFS info (device dm-2): turning on async discard
>>>>> [   17.041393] BTRFS info (device dm-2): enabling free space tree
>>>>> [   19.032109] BTRFS info (device dm-2): last unmount of filesystem
>>>>> 260364b9-d059-410c-92de-56243c346d6d
>>>>>
>>>>> So there maybe something else involved, either related to the fs or t=
he
>>>>> hardware.
>>>>
>>>> Thanks for checking Wenruo!
>>>>
>>>> With KASAN_GENERIC or KASAN_HW_TAGS, I don't see "kasan:
>>>> KernelAddressSanitizer initialized", so please ensure you are using
>>>> KASAN_SW_TAGS, KASAN_OUTLINE and 4KB pages. Full config at
>>>> https://gist.github.com/dblueman/cb4113f2cf880520081cf3f7c8dae13f
>>>
>>> Thanks a lot for the detailed configs.
>>>
>>> Unfortunately with that KASAN_SW_TAGS and KASAN_INLINE, the kernel can
>>> no longer boot, will always crash at boot with the following call trace=
,
>>> thus not even able to reach btrfs:
>>>
>>> [    3.938722]
>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [    3.938739] BUG: KASAN: invalid-access in
>>> bpf_patch_insn_data+0x178/0x3b0
>> [...]
>>> Considering this is only showing up in KASAN_SW_TAGS, not HW_TAGS or th=
e
>>> default generic mode, I'm wondering if this is a bug in KASAN itself.
>>>
>>> Adding KASAN people to the thread, meanwhile I'll check more KASAN +
>>> hardware combinations including x86_64 (since it's still 4K page size).
>>
>> I tried the following combinations, with a simple workload of mounting a
>> btrfs with xxhash checksum.
>>
>> According to the original report, the KASAN is triggered as btrfs
>> metadata verification time, thus mount option/workload shouldn't cause
>> any different, as all metadata will use the same checksum algorithm.
>>
>> x86_64 + generic + inline:      PASS
>> x86_64 + generic + outline:     PASS
> [..]
>> arm64 + hard tag:               PASS
>> arm64 + generic + inline:       PASS
>> arm64 + generic + outline:      PASS
>=20
> Do you see "KernelAddressSanitizer initialized" with KASAN_GENERIC
> and/or KASAN_HW_TAGS?

Yes. For my current running one using generic and inline, it shows at=20
boot time:

[    0.000000] cma: Reserved 64 MiB at 0x00000000fc000000
[    0.000000] crashkernel reserved: 0x00000000dc000000 -=20
0x00000000fc000000 (512 MB)
[    0.000000] KernelAddressSanitizer initialized (generic) <<<
[    0.000000] psci: probing for conduit method from ACPI.
[    0.000000] psci: PSCIv1.3 detected in firmware.


>=20
> I didn't see it in either case, suggesting it isn't implemented or
> supported on my system.
>=20
>> arm64 + soft tag + inline:      KASAN error at boot
>> arm64 + soft tag + outline:     KASAN error at boot
>=20
> Please retry with CONFIG_BPF unset.

I will retry but I believe this (along with your reports about hardware=20
tags/generic not reporting the error) has already proven the problem is=20
inside KASAN itself.

Not to mention the checksum verification/calculation is very critical=20
part of btrfs, although in v6.19 there is a change in the crypto=20
interface, I still doubt about whether we have a out-of-boundary access=20
not exposed in such hot path until now.

Thanks,
Qu

>=20
> Thanks,
>    Dan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
b8d0d62-f8a3-4198-b230-94f72028ac4e%40suse.com.
