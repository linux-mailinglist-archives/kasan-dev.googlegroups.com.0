Return-Path: <kasan-dev+bncBDA55KXUYEOBBE6C2LFAMGQEN2MHP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E71F4CEB36B
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Dec 2025 05:05:41 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47d5bd981c8sf12350445e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Dec 2025 20:05:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767153941; cv=pass;
        d=google.com; s=arc-20240605;
        b=KGz1D3YaRwk3EDDaA7NR376p/u709G+ppwU9wBaPe0tn+MlCv8oEbTSAQ9ov2ezaf9
         BLphXq7isRWajVwh0E2Rs7mW1JkjhVMppP7bNpxNRKIEHAe+wfLd7r0Iz3EI+7gC28Ni
         rp7lqJzCgPFXCFaLEjPGxS2azPYTMSeQ04JPOgs0OyuShN9NOMqWe6/0+FNkujlUBTnG
         R5VFTkD0RjSAREgZDklivHiRd5pwpjUMw6k2T4Ql8ksmqvkFi5kN2VyEXXshHqUG0hdu
         dU5MZib8tx282lFa6HXc0bHczjlHE/HmHhE0WfUMeSgDlK4zUbWr2ULZpomkh0uT1AiF
         m6+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=+gsZU6oy/1JyDuUFzjzjs4EzANemc1OLI5NtQUBrIlk=;
        fh=0Czm4lp1MF+etEvFCM4rjwzvHMMSmBO4d30HyVg+JY0=;
        b=QJkoy6EMRoDZK1DBwJ2h9xpwhllD0jWkMWj7InjgpfHrP2FOEsR3oNQPV9AGSgwoxk
         GSPbZYNKtm5yRuG1TVuw/VkpML11hTQmWBUfElCCScqtBlnKl4hF3ufkBlTg+Tt3L1xX
         6it23ouDxtORWYBghCoucBPP/t4ma6Iecir2eMJUX3uONbHxu62KxlLXXMxieiM2/sQ9
         7LHzAv9V3h0wa7JL8NKBokWnrNhQRPttHNk5DR3+lTMhagQX6hhmGw06ari34/gey3u9
         inOnK9gwJX7iuuR49/PvclcebZez/CAJVQ/5MMLMththQNoR59XRAWjClwAyhAzVRIKF
         kPhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=MYpat0uR;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767153941; x=1767758741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=+gsZU6oy/1JyDuUFzjzjs4EzANemc1OLI5NtQUBrIlk=;
        b=Wz0i/8qaop22/kagduxfVq6IPNUfjU2kfeyb/dAt2E4VizFjBzk9F0z8mALOeYeAZ0
         FGqRfhaP8/y6puC2OBB5MC3HDwKHb1YkH+2zCxzD6SoZmFLcAholwC1EeCMwqKswnADS
         5+ylAWv+jn8+QdeWJxHz7BxVkdaQ6Qg+RZz7lLT1AbINCDiSAnLqt9sgtnGhmbSaL9Gi
         dmhXqcjj9FmOlU22JKiliEjw03Mfkfg5k9zm4Fkl75ugKnKyAozM5a2Q/cWB7TvKGQqe
         vTucaU7sIh/M6i5CvBEhQVSYSpLGFU18D90pzq92fIjVyZCrPFFZV8Sq1vEO4tpxYP6e
         5WsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767153941; x=1767758741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-gm-gg:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+gsZU6oy/1JyDuUFzjzjs4EzANemc1OLI5NtQUBrIlk=;
        b=YiUgap5W5FAJEBdxXn1kNpw/15couQGcxcVxMrHtkskZ7Q51lSba6EEg5mLKr+/xP4
         pBClfVcMHAJh91EyF4iMaSx6PEbjBsBcp1lY4/oGa0Yx+2Ji48oFlDhjf940E2FrZvgH
         w7GbFXxRCvfe2+mqXPOh/5rD3inWqXNd1EJXJ+lNHJMmgCtDl5vGs5H3ymswgYM+rKO5
         58z36N7dT9CRt9iIuQz1UNXDJ3Zna3uIPR23mioGMXyRc1JmNTg6r0ZEPo5ZV9Srb6OE
         o+gffa0It7DO6b/FKlui1ltV6zyfPTlPlJEWIk8k2gG4dsjcXEh1xeqYETTXh2xSrn7y
         NVkg==
X-Forwarded-Encrypted: i=2; AJvYcCUSHGPLOyTNmn1VhMfYz0wriLT1vBreMHKv6FEUnfzobNnwKOGxaBMw0Hw8LQ9gpSXRdC33hg==@lfdr.de
X-Gm-Message-State: AOJu0YwWIk0McEgyB3eKRLt6r/8M+mZwc6ol2cavlRu0ogv/SlyrA9K3
	1LaoKi2xM5TuMWh5ONFJHAJBSBfWpBJOuadoWLhCez1mjwNsdb63F9Wx
X-Google-Smtp-Source: AGHT+IH1xc/2/dlbeVjCrNhoifx/LCrsXB0UCxHoxLSP6NpuwdmJurD//CubrEZtqr4i3lodFDunSg==
X-Received: by 2002:a05:600c:1d1d:b0:47a:94fc:d057 with SMTP id 5b1f17b1804b1-47d19538d98mr336211455e9.2.1767153940455;
        Tue, 30 Dec 2025 20:05:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZICeMuZhlc9YnCTFf1uVNTcdflCjqWhkLpO1A9Cu+2Kw=="
Received: by 2002:a05:600c:1c05:b0:477:a1df:48a2 with SMTP id
 5b1f17b1804b1-47d5083858cls23839215e9.2.-pod-prod-04-eu; Tue, 30 Dec 2025
 20:05:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbSOvwxdDppqpW8NTIhfOCwOwp+MFcVQBTzGZZk7lazwX4Z/kg+Q3FXoHSIZVcTYxUjtVgXIpMXUw=@googlegroups.com
X-Received: by 2002:a05:600c:c493:b0:477:8b2e:aa7d with SMTP id 5b1f17b1804b1-47d19586cd4mr400402165e9.30.1767153937494;
        Tue, 30 Dec 2025 20:05:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767153937; cv=none;
        d=google.com; s=arc-20240605;
        b=g1KJBmopT9aVPz74wQaD4rc734tkU1mIg0jRamG3bluZm0NRKYc8i+xcGnV6Oz2Ljj
         KhuMs8i+PYUytJMFqKTRHXtOO5cvz6p4ew1+gZZuPycaz0aBKA7tSRlAvqw0pvy+0DO9
         ppgCOFKT4OBi1tReczhdusEGkbKk1hAbng9lxA6zxvYIpPhP/uX5xM36NaWJmggheeI8
         sY3jL+epbUSOtNs0IOwryLg1WuRDbylM8wHLhxtxgg2cmSH4ln5wLVRzfGlg4CnN2Ltg
         j8kYqYsenHLiAaltuV3xOHgkFoFBe6R3s+M/0DUIB13X3RuqOv+50SVhYv2hjHEnQZy8
         AyEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=QDjH5wbfhxPfj+6uM2hu7o/MrYmh6JDGhunKWeqrN+4=;
        fh=z6etdtOkY0gLYfZNixvaBQaLwQJ2JLk9+Rb1TkxNavE=;
        b=fyU1LpNUoflauUPYEPKqWQvLviEYfy1cSCqWjyfMpebgdXOryOH/WM3ZTvNl35Azu8
         mPSf/fL9GkKfZ0y46hlb3vEpihLM2za+UnDomR1oGLULijq1y1+ZbkfjqxapEG3EF7oV
         CuhRe4LCtFA7jyibgibquZ9UZuoiPKBXuPEICKxcpYftlzUIbsA49dURSACekhzfSg6p
         HsAcq/YYO/d7NgraeZr8ZVZC4i5H42tqEdvg5eVRVDlAWzvymkLdXXjMZiKnMZfp3wq1
         Eil7j3QfmQDIpto8TGW4haeNKlCe627HSfJfaet+g6RtZdLS3jag+g1+vQ0rfhqUDNqv
         BJFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=MYpat0uR;
       spf=pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=wqu@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324ea208c0si522532f8f.3.2025.12.30.20.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 20:05:37 -0800 (PST)
Received-SPF: pass (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-47aa03d3326so66688155e9.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Dec 2025 20:05:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXn+wRn4d1ZE03BavFeSPOp+PPUxcjojDMkWRoMqmvtHbh8mcrx/gieSs1nKg4DAcDV99FhLcInt50=@googlegroups.com
X-Gm-Gg: AY/fxX7kHw4SNbnDCkCPLGjzRJhJU2XZg2A0OiswcvwueJgTZrzX2pBYQxQhj2q9Lba
	NzmKugTTK1ltbJnte0PYuaK3fm9alxCpUzk4ArUDQoqzTdyKJ5OLt3k50Bzwym5fPqe5Q9u3zvV
	AaYtEsnpqYVJX4vG6uescUMYfVy7sy44on6doVtp/zscCNynZfgC3UsB3orjbvYi86K0hJSImTO
	zOBDR6L6KkiM8fuppDeA8A/zmbG9F+5H74ebWBNcJAODTyRNNJsKku7VHDLdaJSQualbkbzHShp
	DKc+TDxh5AA76urW4U7cTGg/X6EUbVvn0eBYjcnjJpy4cAuxSBIpha7IDZoG4UyuIWY1PhHRXGv
	58+sqdgxoLkz2vhGkbNG4uU4LGXYcUNx9O6XYUQcbPawNDOrK694eZ2k+4fYGq48BHlsGeeO/2R
	blIFe7ovCO76t2Ryod5CvXTKhz5XIk5191QKI0/5I=
X-Received: by 2002:a05:600c:3489:b0:477:7ae0:cd6e with SMTP id 5b1f17b1804b1-47d206a9856mr367047315e9.5.1767153936756;
        Tue, 30 Dec 2025 20:05:36 -0800 (PST)
Received: from ?IPV6:2403:580d:fda1::299? (2403-580d-fda1--299.ip6.aussiebb.net. [2403:580d:fda1::299])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-c1e7961fbb9sm28972790a12.2.2025.12.30.20.05.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Dec 2025 20:05:36 -0800 (PST)
Message-ID: <17bf8f85-9a9c-4d7d-add7-cd92313f73f1@suse.com>
Date: Wed, 31 Dec 2025 14:35:31 +1030
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Soft tag and inline kasan triggering NULL pointer dereference, but
 not for hard tag and outline mode (was Re: [6.19-rc3] xxhash invalid access
 during BTRFS mount)
To: Daniel J Blueman <daniel@quora.org>
Cc: David Sterba <dsterba@suse.com>, Chris Mason <clm@fb.com>,
 Linux BTRFS <linux-btrfs@vger.kernel.org>, linux-crypto@vger.kernel.org,
 Linux Kernel <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
 ryabinin.a.a@gmail.com
References: <CAMVG2svM0G-=OZidTONdP6V7AjKiLLLYgwjZZC_fU7_pWa=zXQ@mail.gmail.com>
 <01d84dae-1354-4cd5-97ce-4b64a396316a@suse.com>
 <642a3e9a-f3f1-4673-8e06-d997b342e96b@suse.com>
 <CAMVG2suYnp-D9EX0dHB5daYOLT++v_kvyY8wV-r6g36T6DZhzg@mail.gmail.com>
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
In-Reply-To: <CAMVG2suYnp-D9EX0dHB5daYOLT++v_kvyY8wV-r6g36T6DZhzg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wqu@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=MYpat0uR;       spf=pass
 (google.com: domain of wqu@suse.com designates 2a00:1450:4864:20::32e as
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



=E5=9C=A8 2025/12/31 13:59, Daniel J Blueman =E5=86=99=E9=81=93:
> On Tue, 30 Dec 2025 at 17:28, Qu Wenruo <wqu@suse.com> wrote:
>> =E5=9C=A8 2025/12/30 19:26, Qu Wenruo =E5=86=99=E9=81=93:
>>> =E5=9C=A8 2025/12/30 18:02, Daniel J Blueman =E5=86=99=E9=81=93:
>>>> When mounting a BTRFS filesystem on 6.19-rc3 on ARM64 using xxhash
>>>> checksumming and KASAN, I see invalid access:
>>>
>>> Mind to share the page size? As aarch64 has 3 different supported pages
>>> size (4K, 16K, 64K).
>>>
>>> I'll give it a try on that branch. Although on my rc1 based development
>>> branch it looks OK so far.
>>
>> Tried both 4K and 64K page size with KASAN enabled, all on 6.19-rc3 tag,
>> no reproduce on newly created fs with xxhash.
>>
>> My environment is aarch64 VM on Orion O6 board.
>>
>> The xxhash implementation is the same xxhash64-generic:
>>
>> [   17.035933] BTRFS: device fsid 260364b9-d059-410c-92de-56243c346d6d
>> devid 1 transid 8 /dev/mapper/test-scratch1 (253:2) scanned by mount (62=
9)
>> [   17.038033] BTRFS info (device dm-2): first mount of filesystem
>> 260364b9-d059-410c-92de-56243c346d6d
>> [   17.038645] BTRFS info (device dm-2): using xxhash64
>> (xxhash64-generic) checksum algorithm
>> [   17.041303] BTRFS info (device dm-2): checking UUID tree
>> [   17.041390] BTRFS info (device dm-2): turning on async discard
>> [   17.041393] BTRFS info (device dm-2): enabling free space tree
>> [   19.032109] BTRFS info (device dm-2): last unmount of filesystem
>> 260364b9-d059-410c-92de-56243c346d6d
>>
>> So there maybe something else involved, either related to the fs or the
>> hardware.
>=20
> Thanks for checking Wenruo!
>=20
> With KASAN_GENERIC or KASAN_HW_TAGS, I don't see "kasan:
> KernelAddressSanitizer initialized", so please ensure you are using
> KASAN_SW_TAGS, KASAN_OUTLINE and 4KB pages. Full config at
> https://gist.github.com/dblueman/cb4113f2cf880520081cf3f7c8dae13f

Thanks a lot for the detailed configs.

Unfortunately with that KASAN_SW_TAGS and KASAN_INLINE, the kernel can=20
no longer boot, will always crash at boot with the following call trace,=20
thus not even able to reach btrfs:

[    3.938722]=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    3.938739] BUG: KASAN: invalid-access in bpf_patch_insn_data+0x178/0x3b=
0
[    3.938766] Write of size 6720 at addr 96ff80008024b120 by task systemd/=
1
[    3.938772] Pointer tag: [96], memory tag: [08]
[    3.938775]
[    3.938791] CPU: 5 UID: 0 PID: 1 Comm: systemd Not tainted=20
6.19.0-rc3-custom #159 PREEMPT(voluntary)
[    3.938801] Hardware name: QEMU KVM Virtual Machine, BIOS unknown=20
2/2/2022
[    3.938805] Call trace:
[    3.938808]  show_stack+0x20/0x38 (C)
[    3.938827]  dump_stack_lvl+0x60/0x80
[    3.938846]  print_report+0x17c/0x488
[    3.938860]  kasan_report+0xbc/0x108
[    3.938887]  kasan_check_range+0x7c/0xa0
[    3.938895]  __asan_memmove+0x54/0x98
[    3.938904]  bpf_patch_insn_data+0x178/0x3b0
[    3.938912]  bpf_check+0x2720/0x49d8
[    3.938920]  bpf_prog_load+0xbd0/0x13e8
[    3.938928]  __sys_bpf+0xba0/0x2dc8
[    3.938935]  __arm64_sys_bpf+0x50/0x70
[    3.938943]  invoke_syscall.constprop.0+0x88/0x148
[    3.938957]  el0_svc_common.constprop.0+0x7c/0x148
[    3.938964]  do_el0_svc+0x38/0x50
[    3.938970]  el0_svc+0x3c/0x198
[    3.938984]  el0t_64_sync_handler+0xa0/0xe8
[    3.938993]  el0t_64_sync+0x198/0x1a0
[    3.939001]
[    3.939003] The buggy address belongs to a 2-page vmalloc region=20
starting at 0x96ff80008024b000 allocated at bpf_check+0x158/0x49d8
[    3.939015] The buggy address belongs to the physical page:
[    3.939026] page: refcount:1 mapcount:0 mapping:0000000000000000=20
index:0x0 pfn:0x10cede
[    3.939035] flags: 0x2d600000000000(node=3D0|zone=3D2|kasantag=3D0xd6)
[    3.939047] raw: 002d600000000000 0000000000000000 dead000000000122=20
0000000000000000
[    3.939053] raw: 0000000000000000 0000000000000000 00000001ffffffff=20
0000000000000000
[    3.939057] raw: 00000000000fffff 0000000000000000
[    3.939060] page dumped because: kasan: bad access detected
[    3.939064]
[    3.939065] Memory state around the buggy address:
[    3.939069]  ffff80008024c900: 96 96 96 96 96 96 96 96 96 96 96 96 96=20
96 96 96
[    3.939073]  ffff80008024ca00: 96 96 96 96 96 96 96 96 96 96 96 96 96=20
96 96 96
[    3.939076] >ffff80008024cb00: 08 08 08 08 08 08 fe fe fe fe fe fe fe=20
fe fe fe
[    3.939079]                    ^
[    3.939082]  ffff80008024cc00: fe fe fe fe fe fe fe fe fe fe fe fe fe=20
fe fe fe
[    3.939086]  ffff80008024cd00: fe fe fe fe fe fe fe fe fe fe fe fe fe=20
fe fe fe
[    3.939089]=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    3.939107] Disabling lock debugging due to kernel taint
[    3.939134] Unable to handle kernel NULL pointer dereference at=20
virtual address 0000000000000020


Considering this is only showing up in KASAN_SW_TAGS, not HW_TAGS or the=20
default generic mode, I'm wondering if this is a bug in KASAN itself.

Adding KASAN people to the thread, meanwhile I'll check more KASAN +=20
hardware combinations including x86_64 (since it's still 4K page size).

Thanks,
Qu


>=20
> Also ensure your mount options resolve similar to
> "rw,relatime,compress=3Dzstd:3,ssd,discard=3Dasync,space_cache=3Dv2,subvo=
lid=3D5,subvol=3D/".
>=20
> Failing that, let me know of any significant filesystem differences from:
> # btrfs inspect-internal dump-super /dev/nvme0n1p5
> superblock: bytenr=3D65536, device=3D/dev/nvme0n1p5
> ---------------------------------------------------------
> csum_type        1 (xxhash64)
> csum_size        8
> csum            0x97ec1a3695ae35d0 [match]
> bytenr            65536
> flags            0x1
>              ( WRITTEN )
> magic            _BHRfS_M [match]
> fsid            f99f2753-0283-4f93-8f5d-7a9f59f148cc
> metadata_uuid        00000000-0000-0000-0000-000000000000
> label
> generation        34305
> root            586579968
> sys_array_size        129
> chunk_root_generation    33351
> root_level        0
> chunk_root        19357892608
> chunk_root_level    0
> log_root        0
> log_root_transid (deprecated)    0
> log_root_level        0
> total_bytes        83886080000
> bytes_used        14462930944
> sectorsize        4096
> nodesize        16384
> leafsize (deprecated)    16384
> stripesize        4096
> root_dir        6
> num_devices        1
> compat_flags        0x0
> compat_ro_flags        0x3
>              ( FREE_SPACE_TREE |
>                FREE_SPACE_TREE_VALID )
> incompat_flags        0x361
>              ( MIXED_BACKREF |
>                BIG_METADATA |
>                EXTENDED_IREF |
>                SKINNY_METADATA |
>                NO_HOLES )
> cache_generation    0
> uuid_tree_generation    34305
> dev_item.uuid        86166b5f-2258-4ab9-aac6-0d0e37ffbdb6
> dev_item.fsid        f99f2753-0283-4f93-8f5d-7a9f59f148cc [match]
> dev_item.type        0
> dev_item.total_bytes    83886080000
> dev_item.bytes_used    22624075776
> dev_item.io_align    4096
> dev_item.io_width    4096
> dev_item.sector_size    4096
> dev_item.devid        1
> dev_item.dev_group    0
> dev_item.seek_speed    0
> dev_item.bandwidth    0
> dev_item.generation    0
>=20
> Thanks,
>    Dan
> --
> Daniel J Blueman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
7bf8f85-9a9c-4d7d-add7-cd92313f73f1%40suse.com.
