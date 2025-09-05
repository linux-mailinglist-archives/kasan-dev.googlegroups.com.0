Return-Path: <kasan-dev+bncBDLKPY4HVQKBBBHQ5TCQMGQEWF5TGIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C075B4637B
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 21:20:37 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3da4c617a95sf2445535f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 12:20:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757100037; cv=pass;
        d=google.com; s=arc-20240605;
        b=cF6qScM3nhnu0IDZWH54LRjkaOEYknU9bG1Mq+4Cg507NHr3F/0JXJLri4xYYkPguD
         GTLs2RFIs19C6PmwEEupzmcBj81dVQAG2iT84c6V0jGOruCPCR7TJ2QJ8OhxW98XDRpS
         SwPs+HB18MQsrMQgenAr91N8mR51jMZmf5yioa6r2f+2G4rL02492aLHtblvDNhhiAU4
         5i6od8iPgFoknh/Mb1jyERDRqZ73cqbYy2X26vg2c/m3v4A4NFLBBd+Mz5ZlOA5JtIVT
         mUGFXrWplVluw6wjH9wKKiAfvkz4EtjdkANtvdtyzXvGfA+97yHf4YzRXVFlFEwFTIh5
         x7ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=iu/1KFW+6D6Sf+Fl6pvYd8J2TNvYV5d7ZLGHhH8WnHI=;
        fh=VN6sp311fsw9SKpwXWGoNhXHBGEGjbhTJw0O9xze6O4=;
        b=djRX6tlAL7g6yhiYePcS7GMdGM6v5TbMQanXANwCd0ydbZUEx5G5/pMEhF9NGsj4R9
         lnnsXlkXBNqZFMqEQasVyJ17qgkmfY/Xy7kpUOlJijKDrbEQFcjUf/WRm6gjzzGwWm3J
         1RW2meqfdwu0EBfXNq5CS6opVlG70zpRlbZfsADBqpQuxFQ/ykWPXy8Y4GlRMNK9jjZ/
         vIs9StBhSSrJWeViWwE5/zF8iKLNZhJHrzK9rt3xjmEX9t0Io+5VhrmBADJ9xjuM8u9F
         Zozy4DodZef4U8p/dcCioOlVzsaUPhJo6DXqmKEA3Vz++wRaz/VC4NZnM/4+I2fffvbl
         DmpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757100037; x=1757704837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iu/1KFW+6D6Sf+Fl6pvYd8J2TNvYV5d7ZLGHhH8WnHI=;
        b=D/L1yHPFHlAEUxs4ELpJ8u+eLmvXdWkfC0ZiBLmTmjOLEVbwq8intIuMd3CWBsgjoY
         j5QXpJdI0gnk+FtED2XRDrrFq7JEWvo6E/Ru1YSV4Eq2yjNAI3dN9sqzzEmv4X+D5kpW
         H/K2FKqytFinQ03c8I/8eKkIDVvr/LdSzRRruTaVyFciIXY0wFPonhb3FilRKpLLc+eX
         7s3C9LJpLMHAhHent0ZRkVH9r0+GkV6lqEVI7hzxQV60svHEgjIZbAhEC15Z3aoTS8i9
         b8xJ4hMGM0TxGWThVwSbk7eHNlwHqrLa2nUg8vai6w9veHY7UfBPL5lWu17cvBJ5LHSp
         hI8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757100037; x=1757704837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iu/1KFW+6D6Sf+Fl6pvYd8J2TNvYV5d7ZLGHhH8WnHI=;
        b=EAiLr6krep+ndvCZUWwo6RAN7qBAlYMRUYZlb/sGzvBVAhBJVgDwhnB2/HkTbiHeLv
         AqkFcj7LRNgBCa6s9q7MR+gpt5kMlsV6EWZsJhnFDvrDKe6ZG+hot6AaZHxdkiI84b/9
         i2qsAhJ3G3rQ/Dj1HgJYPRQC3NUyJEWaK302W+OkznD7cEysOZTOYw8FZmkEGUK78kKo
         qIBsqYPRx8qy8rjjJy0kyHqrp34ADny179Byrof6wdWQMzs+paf/aUnr+flEmjL47TDh
         6coigDzk8BRWlty4xQ5iuLPQ9PjUJIwtr7LZbXx2bjQmaT0pNm7fB0UgWUS1a9ywFxnw
         fshg==
X-Forwarded-Encrypted: i=2; AJvYcCXkcH1DvlKXyCs+7VAlnnr0nji9siHRFA3UWvXjtWwnRyrchzELV+C05j6QNzU0AvnaXqOvfg==@lfdr.de
X-Gm-Message-State: AOJu0YzxJh3+Wn/Jptej/86ssuip0+w4Uq/4uUsIXPwXjMtN6d4hf271
	rXl+ziqATq2sq5y+0BzV3RQMXaAK0Vx8nbFdVFqxnvCE4v/FLanKrict
X-Google-Smtp-Source: AGHT+IEytUHHxan4txZFwVhDYWRtDtlIlEnMOSiSaGXqWEAVHb8cgxgFAwB2J7CygT9+iRchHNXBqQ==
X-Received: by 2002:a5d:64c3:0:b0:3e3:1736:a7d9 with SMTP id ffacd0b85a97d-3e31736a92dmr3162012f8f.18.1757100036824;
        Fri, 05 Sep 2025 12:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcReL5rqtdly43GBpMstPygtpbA/MJJrbY4PXUN6ak++A==
Received: by 2002:a05:6000:2c0a:b0:3e1:d1b0:66c9 with SMTP id
 ffacd0b85a97d-3e3b522d1b1ls732485f8f.1.-pod-prod-09-eu; Fri, 05 Sep 2025
 12:20:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXi0FuZBRAr65RxmYuXoUsqco+6e4GWeh+KmHMX4J8bX4p7h0C8ibivyVaPmUE+FSbyxrZYcYud8+s=@googlegroups.com
X-Received: by 2002:adf:e712:0:b0:3e1:6b:bb17 with SMTP id ffacd0b85a97d-3e1006bbd77mr5825024f8f.48.1757100034194;
        Fri, 05 Sep 2025 12:20:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757100034; cv=none;
        d=google.com; s=arc-20240605;
        b=GJME31airoluW9M6kirxuHhuRrQRVmqjnl79kdTjQCBhw2yGciaWomaK24+cxjLGss
         3wo7JurOalN2d1qpc5ygcpoEjLwTzPsUFh8x6tdDzg+AV6pRpOKwJ//4dOfp29X03Awr
         MamZwQlwUGBc6ONLIg9LgVqWTHql2eZX/Elc5KWIvS3sZ/sGX3R6+ySQIc4ULP+qlP+W
         5VpA0AR27zq/J85nytjv1Td04p6fwID7cJgVOGkN80ZA7l9+7cU68293TveJ3chy3ZYR
         fpZvvuukWAFHDs+Qr47gtSH5+JPxyKFCuaw9HPem0QiU76rL8+I4uAxRBeyJVpIz/H/m
         u7EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=b1MnDfvzkRjUKqLvn44SR8WojgXCXrb2im/5uhar/UE=;
        fh=G6T26c7WgjAPzRJBQyf7OiiPpE73Q44xjmKJesq5EIo=;
        b=L1K4zMtc23UKpegHKKuj+lS0yqgiGE8/AjXCHxd7flq6SKw0peFDS9LiwwWY2Dyotw
         5/Sy/8Q+UlA1Zy1XXM0jd0mobmzzGqEqWAv+orrPUG03/Kb5c0kPcazT42XYMSmcz4Is
         ycRc/dmAbuuMVcC9P/m8mwBxp2E7yxDvxG/NRyATv4/2CxxCn8oQF93ZwjrYfBTFnKq8
         ZBKkRjWZnmDSKvYReHIDYW5ecnUXq0iC5zjGXxpy7uhcnjmnaNAHwUs64MZQue5WRICc
         joU+mVbCSvcvCqZUQtcNiBcDnCOaEylRX1UQxY7Ikr8n+UZA0Nr/tLHNcl/VN3faC1A/
         6KQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTP id ffacd0b85a97d-3e278ac83dasi95841f8f.4.2025.09.05.12.20.34
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Sep 2025 12:20:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cJQx530RBz9sS7;
	Fri,  5 Sep 2025 21:13:29 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id Q8FPsSrEXf2k; Fri,  5 Sep 2025 21:13:29 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cJQx51qPmz9sRy;
	Fri,  5 Sep 2025 21:13:29 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1C7B98B77A;
	Fri,  5 Sep 2025 21:13:29 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 570O8DO0c8e4; Fri,  5 Sep 2025 21:13:29 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6312E8B773;
	Fri,  5 Sep 2025 21:13:28 +0200 (CEST)
Message-ID: <c0bd173c-c84f-41d5-8532-2afb8eca9313@csgroup.eu>
Date: Fri, 5 Sep 2025 21:13:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
To: Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Baoquan He <bhe@redhat.com>, snovitoll@gmail.com, glider@google.com,
 dvyukov@google.com, elver@google.com, linux-mm@kvack.org,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZdWxWD99t9yhmB90VPefi3Gohn8Peo6=cxrvw8Zdz+3qQ@mail.gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <CA+fCnZdWxWD99t9yhmB90VPefi3Gohn8Peo6=cxrvw8Zdz+3qQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 05/09/2025 =C3=A0 20:08, Andrey Konovalov a =C3=A9crit=C2=A0:
> On Fri, Sep 5, 2025 at 7:12=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmai=
l.com> wrote:
>>
>>> But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
>>> CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect this
>>> should causes crashes, as the early shadow is mapped as read-only and
>>> the inline stack instrumentation will try writing into it (or do the
>>> writes into the early shadow somehow get ignored?..).
>>>
>>
>> It's not read-only, otherwise we would crash very early before full shad=
ow
>> setup and won't be able to boot at all. So writes still happen, and shad=
ow
>> checked, but reports are disabled.
>=20
> Hm, I thought it worked like that, but then what threw me off just now
> was seeing that zero_pte_populate()->pte_wrprotect() (on arm64) resets
> the PTE_WRITE bit and sets the PTE_RDONLY bit. So I thought the
> kasan_early_shadow_page is marked as read-only and then the
> instrumentation is disabled for all early code that might write into
> the page before the proper shadow is set up. Or am I reading this
> bit-setting code wrong?

But that zero_pte_populate() is called by kasan_init() when everything=20
is ready.

kasan_init()->kasan_init_shadow()->kasan_populate_early_shadow()->zero_p4d_=
populate()->zero_pud_populate()->zero_pmd_populate()->zero_pte_populate()

Here we are talking about the shadow set at startup kasan_early_init(),=20
aren't we ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
0bd173c-c84f-41d5-8532-2afb8eca9313%40csgroup.eu.
