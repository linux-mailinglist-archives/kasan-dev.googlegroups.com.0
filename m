Return-Path: <kasan-dev+bncBDA55KXUYEOBBN4V27FAMGQEMJJTTCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DB0BCECBA4
	for <lists+kasan-dev@lfdr.de>; Thu, 01 Jan 2026 02:15:36 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4775d110fabsf95777835e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 17:15:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767230136; cv=pass;
        d=google.com; s=arc-20240605;
        b=IUjUf+F8iaQeuBByK+wLTuWzT6dl2NsussmELbxXJEYPd+MohlR4mWdkdJ7Pc9sSBd
         4KUXrtaqLRgGok2UH5mY1ft80FQzrDze6MOThhwFhjzrJC31dFaQYQKe5hXWVLzTno/q
         JoaStDFiYvcysSYTEavwBwTXZL4dzjH+4RH0Ie+Bjbt4BuOk1mXWdgG0NUKKyA2eD5ao
         o45CNcKSyI9GzfW5nTIKiGSjFQLJO8IP2lq9xeYLsQpakwKJ4+PP+mfII79nAT0CIEpW
         eZ+frxhIQmKRpFToByWGGUiDErzmPk2nlCYFkAUk/xDflb9lMGTsPrTmatiM0wcra1+O
         gNTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:content-language:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=x1RDQG2MZE+DxecMa6+CbjK/zgUxrWoM1m/CmBF3ot8=;
        fh=s+PFYCe7ll4DgwTAf8SfL6iObgBMqkuXMjUqhRDDc5U=;
        b=KDi2yMtAZOe9qu87xdqwPTPt2pieIGPWIDRYMpgy9HSENDaqXJUaItSqyoA2+fvTyu
         92NGrMgBfjuLdDpYlxXeA7HnuPabgP4X4a5/zBsLRA0DGxhX+obPwmZd8Tah4iR+Bf2q
         fg/9+T5YWs9jEqzQojbP7FK4n0CjbQbO53Md58kn5oZ5JDvOwEx8UaMj5ZpU1tfwLXA6
         Ly2obyxMyxTXbc4njFv7igj4EKMYFb9zTjwIz1fstbTbT2vgPq0t7bKXSo1RAAn+phN+
         mI9/m1co6Kj7TDjhjpeeMg14SQIJ3isICb2HBFJdHfJlMZwq79s/513uz5m3OVbS0AVy
         omqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=HyaVcdx4;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767230136; x=1767834936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=x1RDQG2MZE+DxecMa6+CbjK/zgUxrWoM1m/CmBF3ot8=;
        b=pF7lrsYc3dkolYwj6GKmwxX1LN2gOsS9JAvQGDWGz4eC//JcNVMw2FVan1qpB2A8XK
         enXWZu+OtklxV/9eUeMfC6FFXorJu/QdB1/texYe/p0WHvKT6A762Hq789rnFn1IFCoW
         UphD4sVG2zFdRrJ+/Ev8j2uEnpZYWdJjRR+UZ2qkdAr3t4iA+D6Wh6Mi2PwqkS/uO/wI
         nJpx+nehDKsEPmHoRS3u5uT40kU/lQXET19myBI7Nou6MPMDPqF1iiW4X7UDwwZUTWLc
         FrF3tHK1JndQwV4ovqw7MENjaIeOFON0VbAIKuGuAnHuZCej+aXyzmBgC1Nx92U6Z9Ks
         1Xzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767230136; x=1767834936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:x-gm-gg:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x1RDQG2MZE+DxecMa6+CbjK/zgUxrWoM1m/CmBF3ot8=;
        b=gF6cS4Din927o7YtHlDLdyOK+KHnDkONISzIoHvhTCT2KXqkRnT/6TlVJSAU1RHese
         LSHrBJ1FsEwsJv6/xgGQMfHgVrw2hwtj59Uy1jr3/8INOhyb6ojqZ7oANlZ3myLe2CyZ
         GweiGlHb6vum7L5lQW6lUeEx81z0gcEBbE/xh/BEbOI7Gs+VNSqH+JtR6sQrfaUVI3cQ
         Uzqo07EI6MQ+ve0UKW/HahXg+sHNYzlSPm8QBu+2+IHVvvAlyJYqVowg0Y6II4/7GpVa
         Jk7dsuTidlMt9Gn2LwKDzsZ3jBrFmbR3vZduGRtG3xwIeCSvy7sMUlMfF4BvPoP/m29Y
         f4YA==
X-Forwarded-Encrypted: i=2; AJvYcCU8WjFq0dAVK4cjmR5IL10WAIF+XlPQ20O1L/Hd3i13ImNPZWF1mdVIbIljEljepKsvEyI3MA==@lfdr.de
X-Gm-Message-State: AOJu0YxKilxxB/IIFk2LZt/Y7NiUZlc/fTUyGIF3Y9W5BvJTc1x1P5Md
	0vMvTr2ip73FdEtcoYEPfwlrHlp4zq0DPP7oGKhunwxioMrDExj0zlxy
X-Google-Smtp-Source: AGHT+IHdraVO14NLdjVL+etSqdJwj2DyDia+/HD13GMKZmV9nSy6PYGlMaBJ5n5ISGcLco5+wzk1Pw==
X-Received: by 2002:a05:600c:1d1d:b0:477:9eb8:97d2 with SMTP id 5b1f17b1804b1-47d1953b8acmr409004955e9.8.1767230135826;
        Wed, 31 Dec 2025 17:15:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZEFCvAUxYny8neR3b8AXqCoJi2m2mXFr02ackaZPrWRQ=="
Received: by 2002:a05:600c:1389:b0:477:980b:baeb with SMTP id
 5b1f17b1804b1-47d50853995ls25162405e9.2.-pod-prod-09-eu; Wed, 31 Dec 2025
 17:15:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUu9rVQd/HzPPbG8AwKTTHfHJtkeMHDFEPcdkKVgT6jx1XFk5YiSWK9yih0IOvekxObRN4TDaBu9pQ=@googlegroups.com
X-Received: by 2002:a05:600c:3b8f:b0:475:e09c:960e with SMTP id 5b1f17b1804b1-47d19593d0dmr584119955e9.32.1767230132962;
        Wed, 31 Dec 2025 17:15:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767230132; cv=none;
        d=google.com; s=arc-20240605;
        b=EpPzSM3IGpjz2KP/YKCxgMUIHas6AdG4orIQsMIMdeMG9fYIKg1cMOMgE2EscDg6uS
         k56RNn3V3egECbdau/afcIDn3Mv+lcUWq9mCxKIlH1GvzcSQKnIpdZEMC1wEKZONpyRA
         BMQfRBKcgyENvRVH8cKU/VmuV77TZD9qULJYRiER/O1raC7a/0+KH0pRq6E7iEgLh88K
         PltTJc2ir7BMLgok68DMhqeiy/BSzBRfB4ypTziAiHu5tuWGTAPYDd6a4In1jjejBRI0
         JOurEiKc19uRKo3e4/XO5XhFNlGa9kFwCFx20b2EsQqeaV+fFyJ+9gf0j8Wzocz6iFjs
         +QCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=xkwY3h33tWtBnJzkbT/5FUlQ2yKG1xK3b/1V8KgcBKA=;
        fh=D/DIEkpupZXaqUE27bjNsOypmN/1sMcU9AX4Orwy3p8=;
        b=BVO1+JRzmaMhTlQ9Jq6RYUqXIEAO039ovH+3FnSPh5q5rCxoiSQOb8bz9cpbD9cyIp
         +aNtkJc/uIB5O+aTyXPK8VLoMSQqP0CzwyRr9Usr9mS+Tn9RPWGH1CmD2Y+2X2pPmjhC
         LpKmkL7KfsH5265QWx9IHBc303Ll4FNgJeXKhuoWkYzlvbqBISzTUUUkQcq2muw+VyG8
         1R8BwADLXmyEGRbp67NsBTdzgV8qStGrNGHdYWyG78AyTJTszhfXN5OgTePBCvEgm5Dg
         j/Zuma4k6+QIE7hOLuznlBFxKpj0FB71GKdRMJmi33B1+as+qUjA2xgw0WCKIR0hwduV
         UlgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=HyaVcdx4;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47be3a7801fsi5241095e9.3.2025.12.31.17.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Dec 2025 17:15:32 -0800 (PST)
Received-SPF: pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-4779aa4f928so111875115e9.1
        for <kasan-dev@googlegroups.com>; Wed, 31 Dec 2025 17:15:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVzk5sYh9yoGLdiSXk9VhXhKIfNERuxyVad1RK4xOp6MwLvqzXHTNTEOKAqCL0nFHVINiC92aIJAho=@googlegroups.com
X-Gm-Gg: AY/fxX7d/5e5HVOvLuSzFFZ/SysTXBWgy/JDJGKApnh9Vsu3Jo2jAqKgSoGuhQEmLJM
	T6yKxc6rBbC+OOqs9OrHnF7sarMzpyjdatrCHvWVt17RiIHu+opSc85nTGCX9TjmimPNMwWPIGi
	lxM6uwD3XKGYbyBSdLyUQtSqn5HqGF0Kiqy6K1eCtRI5AXNyXQvrdRPi5u4VSSzOi6YrN7iy4W/
	QZhRRnRmjkRKlS23Dsva/y2G+MmOR6+c4Of3WOVeZz9VLupmwUcTcCoWgXDfHfCuOsrJsLUYh8x
	kT0w7Ndvlpqc0MeyuL9UhiY94dud/vzyGWmgTH+uKqR6q4X6I/HbG6SpHBf1p5XbLjvm1djRpw7
	9D/wPCPanj0Pp1Aqea92/AjrhPNC+HqiGqEKo5HE/x4daHRCdN1JOeKGCzfGKeAZXkRZTl8SPn7
	ANUA7M+s0MZs6kwl28YKh2stBz6mVaz7uqbADTDkkvaxjopcis9w==
X-Received: by 2002:a05:600c:4f4a:b0:477:58:7cf4 with SMTP id 5b1f17b1804b1-47d1953b79dmr511779605e9.4.1767230132347;
        Wed, 31 Dec 2025 17:15:32 -0800 (PST)
Received: from ?IPV6:2403:580d:fda1::299? (2403-580d-fda1--299.ip6.aussiebb.net. [2403:580d:fda1::299])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a2f3c8a8e3sm332310245ad.41.2025.12.31.17.15.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Dec 2025 17:15:31 -0800 (PST)
Message-ID: <03cb035e-e34b-4b95-b1df-c8dc6db5a6b0@suse.com>
Date: Thu, 1 Jan 2026 11:45:26 +1030
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
 <9d21022d-5051-4165-b8fa-f77ec7e820ab@suse.com>
 <CAMVG2subBHEZ4e8vFT7cQM5Ub=WfUmLqAQ4WO1B=Gk2bC3BtdQ@mail.gmail.com>
 <eb8d0d62-f8a3-4198-b230-94f72028ac4e@suse.com>
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
In-Reply-To: <eb8d0d62-f8a3-4198-b230-94f72028ac4e@suse.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wqu@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=HyaVcdx4;       spf=pass
 (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32a as
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



=E5=9C=A8 2025/12/31 15:39, Qu Wenruo =E5=86=99=E9=81=93:
>=20
>=20
> =E5=9C=A8 2025/12/31 15:30, Daniel J Blueman =E5=86=99=E9=81=93:
>> On Wed, 31 Dec 2025 at 12:55, Qu Wenruo <wqu@suse.com> wrote:
[...]
>>>
>>> x86_64 + generic + inline:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PASS
>>> x86_64 + generic + outline:=C2=A0=C2=A0=C2=A0=C2=A0 PASS
>> [..]
>>> arm64 + hard tag:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PASS
>>> arm64 + generic + inline:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PASS
>>> arm64 + generic + outline:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PASS
>>
>> Do you see "KernelAddressSanitizer initialized" with KASAN_GENERIC
>> and/or KASAN_HW_TAGS?
>=20
> Yes. For my current running one using generic and inline, it shows at=20
> boot time:
>=20
> [=C2=A0=C2=A0=C2=A0 0.000000] cma: Reserved 64 MiB at 0x00000000fc000000
> [=C2=A0=C2=A0=C2=A0 0.000000] crashkernel reserved: 0x00000000dc000000 -=
=20
> 0x00000000fc000000 (512 MB)
> [=C2=A0=C2=A0=C2=A0 0.000000] KernelAddressSanitizer initialized (generic=
) <<<
> [=C2=A0=C2=A0=C2=A0 0.000000] psci: probing for conduit method from ACPI.
> [=C2=A0=C2=A0=C2=A0 0.000000] psci: PSCIv1.3 detected in firmware.
>=20
>=20
>>
>> I didn't see it in either case, suggesting it isn't implemented or
>> supported on my system.
>>
>>> arm64 + soft tag + inline:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 KASAN error at=
 boot
>>> arm64 + soft tag + outline:=C2=A0=C2=A0=C2=A0=C2=A0 KASAN error at boot
>>
>> Please retry with CONFIG_BPF unset.
>=20
> I will retry but I believe this (along with your reports about hardware=
=20
> tags/generic not reporting the error) has already proven the problem is=
=20
> inside KASAN itself.
>=20
> Not to mention the checksum verification/calculation is very critical=20
> part of btrfs, although in v6.19 there is a change in the crypto=20
> interface, I still doubt about whether we have a out-of-boundary access=
=20
> not exposed in such hot path until now.

BTW, I tried to bisect the cause, and indeed got the same KASAN warning=20
during some runs just mounting a newly created btrfs, and the csum=20
algorithm doesn't seem to matter.
Both xxhash and sha256 can trigger it randomly.

Unfortunately there is no reliable way to reproduce the kasan warning, I=20
have to cancel the bisection.

For now I strongly doubt if this is a bug in software tag-based KASAN=20
itself, and that's the only combination resulting the warning.

If KASAN people has some clue I'm very happy to test, meanwhile I'll=20
keep using hardware tag-based kasan on arm64 and generic one on x86_64=20
to test btrfs, to make sure no obvious bad memory access.

Thanks,
Qu

>=20
> Thanks,
> Qu
>=20
>>
>> Thanks,
>> =C2=A0=C2=A0 Dan
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
3cb035e-e34b-4b95-b1df-c8dc6db5a6b0%40suse.com.
