Return-Path: <kasan-dev+bncBCSL7B6LWYHBB2VXV7FAMGQE52FKACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F592CDC334
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Dec 2025 13:26:20 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-597c376d9a9sf6938515e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Dec 2025 04:26:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766579179; cv=pass;
        d=google.com; s=arc-20240605;
        b=BtMwvZ7yWNu4fcm9CLmbFNtDqkUl7qSFuz8+spy4JKebJA5tUHAaQGD3XxtBvj2pf2
         diTlQsL42gDzZPdCCI9gGHSWole762AQvFZ1X/7Id+HPDwoZb24nHPvYaMno5/mlBqZe
         87RXYDfLN5vtj7xtcXwI/mnK3itBHo96/zfv+wMhWBByuwedFiQtYWEEes9zNn3KGLh8
         jj9BnnfFaiTm6NWND54CjlaGZ0ZBIwfhR4cq/DrJZ8/EwogGfApmS2ZcL0Swo/3nVwb+
         CHS5OouBSVOU44r7UqpdjVcTcKlYQHGtK5opXlAEO+q+tMPPSmUWIrQirytdffy7/slc
         wMSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=lGn6pWTlmDTzucdYmNgxhcdOGjKDWxZ6G+2xPniGZ0Q=;
        fh=WQAnXOjizYNZizw799i9wtFOZMjboIlr9EDLdEEkdH4=;
        b=SjsEgmtaBLbGbIXEcmgUc7kBHWrFdjhmcHBYHP2mfbNPc0xRecV++D/ZX9haO5SDny
         lNgkKKjhyLhEYWDRAc53DAAC8o3F4p6o05HbleJdUMAKPRE9fz4+vpAVIVFou/1HRxVh
         P+SHvQPrnTcWOFrVtiICBArXtmbCvE3FaN0FiP3hnAIot3BEO4Mt+38R2k306D8O3Qug
         g13FwEpPUvdgn6YR9zNfH7Qg6+/bWTs60KNNpt2Xnz6oM5xnTDGo1G+66E3id70WfBNl
         iuzLLrKwy5pVW2B6KPxGiWaTcAiBHpu1gUeJWiBh7i1tB6cO4ieZDCVwsl+eLj2Xj/ZU
         7fdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQLxnbOX;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766579179; x=1767183979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lGn6pWTlmDTzucdYmNgxhcdOGjKDWxZ6G+2xPniGZ0Q=;
        b=kAzlVDHGD8U9lUhwkpciz/P+jQJSWUNVveLPe5MyZlCbnWrof3QKP3tr3kF1H5eeZN
         xl8wTpKFYebn4aZHITygHddi1OtRRt1P6al8odEd3/17Akkfwa/6acULnStIht3ye91A
         01/9iWfg+ISsCwtni4c9rzIHkqnfXGPlqz9s7Nt4+Net4AN78Z9MsijqQD1WEyayHMKo
         1OFWOqoypcUvWIZa1Edv0BPpUj9NVriCjQyC0dIFFyE59CPys6gZ0y83NHrwxwZ+bSXZ
         1XvZcbNEFF3Efp6evlE1aX+FTPHTnPHgckhM4LQ5TtTR3SX7SJkHjRu5TPHRMJyZTiI8
         no3A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1766579179; x=1767183979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=lGn6pWTlmDTzucdYmNgxhcdOGjKDWxZ6G+2xPniGZ0Q=;
        b=OIuwdsf2tM8UGmL5TA2WdurhABObp0rEcyf2Z9MvCxCareLxmU9Ztm5jau2XdyA6zm
         IvfQUUgI7z0i0YwelXCVDiktr/RKHoVPalCXcJDwnjdB0djnFkoJJCxVpsky6dq6h2cD
         bl5X+Yb0FdkgsrAlYnpE7yFxmcqxutAS/rzExwP6q1jYkDqKPKJMmmg2S2nzZzx59ght
         CIJu4+Iy/WJPYznIhbNCetFR1p0r9A6CdDQ8YmK8i4qjMcWCPgZKrXBWvIrUf6U7CjuC
         WH7ZoMYkp6ygCKytWtOYQHV2xj4a0/JI56zBndWWubeLfvxBt9SaY4jzm9tmugnDNZW8
         rjEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766579179; x=1767183979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lGn6pWTlmDTzucdYmNgxhcdOGjKDWxZ6G+2xPniGZ0Q=;
        b=jWk9Cp/oYS3037Ws6qVbS4OeH1Z++hW8TufBtSj6UScamrs9sY7mta6yxmvjE4j1Vv
         KbxcOX5MFeDbFF6oNQ3zcQQFvDIWK+jsiq71MHBdcbUjA8fJuLKmzHTnlNFQv15vKBlB
         WasJpuLhGZ4pHydEK90MCKgTE/hgOanWhKJDd8KUXPZxXEhvN7eX4Fv8l4jhxBQXQc2o
         OT1r9iB5JgLIFkJoZTV1RRbAJyOK96QeMmIgqLPNrWQiC6GDQxw2V2cglTCz/7DIcsG+
         JCcDMUv380uFZDenKToyB4QOFmh5MaZHtDl59e+OCvlaC99nj5z4snkFDM6saQ4bQsWc
         Kjuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcnELwoY4oPOexylVYh4zw4MgQ2GJQi1HtxgtRN1fwr/k3VktAv1BJybJ6rqVb4NXsR4NkuQ==@lfdr.de
X-Gm-Message-State: AOJu0YyE6BbMMYAJG8ygZZUuauz1XINw0J27FqIUvcFR+fVxlTopmegk
	ZFfdmYfM9i0nOXrRtfGp8vd4A++djxJRfTv+fvTqAFkcOl9z6ka1lGRm
X-Google-Smtp-Source: AGHT+IHN5jwaCmjVWgUXot9vTjCKkivXXn5b1LJ3dbjToeaVofB1XyiVKaoFm687XUCeOYQ6WukLHg==
X-Received: by 2002:a05:6512:e93:b0:59a:1272:30d9 with SMTP id 2adb3069b0e04-59a17d667c6mr5266394e87.53.1766579179042;
        Wed, 24 Dec 2025 04:26:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZVVUXmkLnKThepz/BVAkNDhfAtknLDg9i5vX4Ppi2txw=="
Received: by 2002:a05:6512:2389:b0:59a:10df:3574 with SMTP id
 2adb3069b0e04-59a10df362dls1799450e87.2.-pod-prod-02-eu; Wed, 24 Dec 2025
 04:26:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSasdE7OHs3luqSQ3xWIiXeDqps3q8Z1OVq9SrEfMYB/AvfDsMUS70TDqGs3ke850NLYBJIWW+uqg=@googlegroups.com
X-Received: by 2002:a05:651c:19aa:b0:37a:7a9c:5c14 with SMTP id 38308e7fff4ca-38121652283mr54384911fa.34.1766579176060;
        Wed, 24 Dec 2025 04:26:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766579176; cv=none;
        d=google.com; s=arc-20240605;
        b=dglMoAm75CTdxeN+AoKAdnsEhiR9gaLmw2XKnccu9XU50EE6Vxrq7mxz14ku8O2XoN
         xENkXyYRqziPB6nGV6Z/Zu+ICae1TxEjrjmo9s+CO+UqnlZrgRK7nJMfMxkZDlLJTUFz
         JfL0tRXjGeqTGOvfFUeKP72/RfpWlI0oA014jeXGLYkq42S19GAqgjgaMuzViJ6tDEQB
         eEmlSLAlIgrQzkzd14Xc/0IsXkU7zuqnOIr7CCvfXEHwMLb1XJDuATYe8tCc8xRQDuP+
         YPVGmOnqd6r+QKYKJR2X5uyjHIotIYdvqewouhluASXjyfP/hMLc+LNJGgG1iPY6AyFm
         qXdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=kFaMyaLN7ofb8ca0IqdWrpz34r7dd+k0wM2WCDT3KaE=;
        fh=QEI+kcUkGKVbx9raQkg8JuMdWnWDX+/wSpJ/tVdB01s=;
        b=Ho9TX/MShsF+LqMCV5XXHcemYnsJKSfGh3dhpGvUKGia9bnbnOuoM2nby1AYL66ZkO
         EMPzAsmSUiQ3lR0G2CJW8vgqYwWTIsOXoJHnpzpL8eaHXHF47i2Hb9HROsAnC3K8p/aU
         WY31H2GJqNwinOPZ1Pjif3PyJxVSTttkD4BMyQ+OXU4cYk00qD34TARCJ75jNeqLj8KJ
         NtGwCCShr0CM4LbA0Qm3M9fYzpli2n/mOQwoD4ElAZskorRauPjyFAQxCMWXBX45a0eV
         kVHrGUgPrQwJUau34+AmUaWkC/TNRbZ0V8nViOHu5OCPkNYV3Vs/190MkmPRgEuSaOAU
         Ttag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RQLxnbOX;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3812235da7bsi1860881fa.0.2025.12.24.04.26.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Dec 2025 04:26:16 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-4779c9109ceso4678505e9.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Dec 2025 04:26:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWwpaNPqbsRdC1TUllY0IZo/bpuUmTz1SN7afWs/6tkuX4Wa4+3ShS5HB0ZmN+2WZPFTVRzjKLsoAc=@googlegroups.com
X-Gm-Gg: AY/fxX6FjgoAAI6PmxxY0Y9qv0hzUuREbi9TnI8tBzoCuGH1ovltENvIhubTdeFvdw9
	N0NdnwBTvEXLPAg6WL1MdLDgQkv6uxddp146oGE1COZxjU0DITdatrdDf719pVR5v05I34mDbPj
	v6o85aZmu/niFB1AZ4TkKv2Qasmfk1GDftf4kJv//ltMZ434CfUYpE1dDn+BkyO5MmMoFbx5lkx
	noQEK99JabwQzm85DU7UZvhxS7HMlGx5a2GZSfdd2vjnUpFAcKCiLwZRY7iBglTkSoMvLefaOug
	E4qzRswSBz4nOOnpE6M6tWQRyOcjgvNclaVR7YVrGt5ETOIczTMF5K2OExa5H1Du94SkRNUKMc6
	jy2OR7mLtLMMiHEmb/IyNmxveBVP3IZq/24l64uRw/liItm4CI1h0BLCw3gCHmPABgZq8MhyNrj
	w0HUW+c/Yo53cPm2gP3g==
X-Received: by 2002:a05:600c:348e:b0:477:5b01:7d42 with SMTP id 5b1f17b1804b1-47d19599f8cmr103586685e9.5.1766579175264;
        Wed, 24 Dec 2025 04:26:15 -0800 (PST)
Received: from [172.22.153.25] ([80.93.240.67])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47be3a204e9sm132695265e9.2.2025.12.24.04.26.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Dec 2025 04:26:14 -0800 (PST)
Message-ID: <edd6e350-5482-4551-aa94-e1ab8d2f9774@gmail.com>
Date: Wed, 24 Dec 2025 13:25:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
To: Baoquan He <bhe@redhat.com>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, glider@google.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kexec@lists.infradead.org, elver@google.com, sj@kernel.org,
 lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
 <aUtd6es8UC0lNf/9@MiWiFi-R3L-srv>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <aUtd6es8UC0lNf/9@MiWiFi-R3L-srv>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RQLxnbOX;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 12/24/25 4:28 AM, Baoquan He wrote:
> Hi Andrey,
>=20
> On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
>> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrot=
e:
>>>
> ...snip...
>>> Testing:
>>> =3D=3D=3D=3D=3D=3D=3D=3D
>>> - Testing on x86_64 and arm64 for generic mode passed when kasan=3Don o=
r
>>>   kasan=3Doff.
>>>
>>> - Testing on arm64 with sw_tags mode passed when kasan=3Doff is set. Bu=
t
>>>   when I tried to test sw_tags on arm64, the system bootup failed. It's
>>>   not introduced by my patchset, the original code has the bug. I have
>>>   reported it to upstream.
>>>   - System is broken in KASAN sw_tags mode during bootup
>>>     - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#u
>>
>> This will hopefully be fixed soon, so you'll be able to test.
>=20
> Do you have the patch link of the fix on sw_tags breakage?

I think this one  should fix it - https://lkml.kernel.org/r/cover.176597896=
9.git.m.wieczorretman@pm.me

>=20
> I am organizing patches and testing them for reposting, but still see
> the sw_tags breakage during boot on arm64 system. If you have the
> pointer about the fix, I can grab the possible unmature code change to
> make sw_tags mode work to finish my testing.
>=20
> Thanks
> Baoquan
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
dd6e350-5482-4551-aa94-e1ab8d2f9774%40gmail.com.
