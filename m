Return-Path: <kasan-dev+bncBCZP5TXROEIKVM5FW4DBUBEA6I5SE@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BAF697AEB5
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 12:27:55 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2781e30e1e8sf4867765fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 03:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726568874; cv=pass;
        d=google.com; s=arc-20240605;
        b=DmPp6U02bXlxoRGDaFIYsk6y6jKOK1yGbd3PDqgf34J6wJJ6mTg3Lam4P9RGtBNA8m
         lEIFawU/oSJKjhaeW0JxFYPnvIojSRVOpxGDufQal8etXHx2zFfz0hLrARQkisEq9EQ2
         Y+C5Obd9Nai5Zgq5kViiIea1PDFjezJ2sqCtSbbvwhVNfuFV7R5TqVPfZ71dzClNUeHY
         ZUkbztUPNmGGitNhoDDaHxE1YX2CseNRgoZ6anRcK3S+MecobTE9P5+CIfRzllEG8xW0
         z4E0CFmpYiSjypRvrFARCEmoqq50Z7QAK1zguxM0L/FwDuUjdv6ahPIiJfbRGI5tKoE8
         g58A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=r36K0FspEEympXjEcSPl2+ZZcQp0MMuBePC08r9zgRA=;
        fh=qHPXyi2oUzzbGc1ewcstQ7u24VTUqSF5MIviXdLIDeA=;
        b=abfYqHWdIVZ5/dhV0BG/jAPhZVvzD5V8LBVi/ubBETVGlj66DVovxMOkytcL8UITKB
         o1hk3GG19cFPRRBtauv1atEEcxD97tdAZSH0jydaEwO9r9zjvY6DjqAPdYyVPcJXMdnD
         70Il3e8ld+jylUwjrkzX2PuFv/ABinewXXyEkvN0T1WyQI6Tb0o6V6wC+enTgoB+m4zI
         F7DjhtSxpEeQbDDTio7cZBUxsxaOLLmgCHSs3fxOiFZZUr2PXszPPn54DyF01h0u+QCh
         XTapDrE8zVLB0ZeGeyXueA8OCjdWpQ92w99sYskkf+/4k+WrjU0/QE5lyutZlj2xUGa/
         /Bvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726568874; x=1727173674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r36K0FspEEympXjEcSPl2+ZZcQp0MMuBePC08r9zgRA=;
        b=jtBxvYBNZkf/rTPQEoLuiCMg3ct82c3mMIrNI/0DDxpHIOZmL/nEcQLoiqyAldR04E
         n4Rgk/Hiyj7TAwZZ7lj7znpW3gUvNiXc4hwp0pV6szWuOJVoVdb8JC4b4MKmWeF5QIso
         Afn051n+p5k2o0cI6OjRiUuoC2+MY6x8aMTvwJzufJIiVmeErC0ME9U3zKVHak6EIdBJ
         Axo9Rtik3mnEy6WhlTN78POgdYioxdhleUXtRj8n19v2LGLPttmYsTvaF7RUD28HPhqO
         zD30UWaGpfe45XowicyFgMaJCHTInwlEhXuFyyzEIGDtQEKuElI2I3v/XPe7Ie/S3bfp
         W+sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726568874; x=1727173674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r36K0FspEEympXjEcSPl2+ZZcQp0MMuBePC08r9zgRA=;
        b=fSylzBILs/Dwvd9Wap+2Yg47IcnCynjTZ0sh8J7VbmM0ITsEHqRVLXNeYIga1XJwbl
         oL34UjdjflBUluRRVGmTE0qXQO9duohxHllUNFh95caOj4YbV7rZJr1NjDwX6qXZF+af
         aC0F6+ZyM5IgbZjvUePcVuTS/x6uGobstFhCsxgujUYp3O7UiekkxwGxQzQLYDqZ6g93
         w37bj7w9RxbZRVTWznqqqHmzfDE85XKNhEOZTx7b3cNOBaNlTgTVnPhTDqzNJdA6TTKw
         N60k6qFKnswzhoR+cSuKwHBoFBRdm5Q/vPCvJkFfLQdJK6NqiCcwb42Y4C9y2CQJvMxQ
         AGPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVs55kiFa+B+dr67MdYzPwTRk09VqFv47WR3gHOgwvlno6vx1ZcvLdOtMHYNzK6t/Tf4IkR8g==@lfdr.de
X-Gm-Message-State: AOJu0YyMoVTtCJ6XqHnz29zgWMVXX3W+7JpeYOIpdewwN7MkV0zXnhJa
	IHY/zEAT+70KHHUCu7BpwxglGJDRCwtNDOl8KbFggaOj5qOMPxKN
X-Google-Smtp-Source: AGHT+IFVYoEDKSSl8Waf2UJ+wGT05Pa9ozhrYzBq+o5wVxJJOefAYTOfHMScLH5oLAwut2h3USYKdA==
X-Received: by 2002:a05:6870:1718:b0:261:13b6:16de with SMTP id 586e51a60fabf-27c3f2c3ae7mr10631866fac.25.1726568874206;
        Tue, 17 Sep 2024 03:27:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:440f:b0:277:f2fe:7da9 with SMTP id
 586e51a60fabf-27c3a835e19ls1490619fac.0.-pod-prod-08-us; Tue, 17 Sep 2024
 03:27:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh+IM++Bs2IDGV0upP0rpcxoG78HgGyD8DNpMe5Y4K+Sh3P+GxobVEuTXSB8WvFBJ1HzNYzVGMco8=@googlegroups.com
X-Received: by 2002:a05:6871:5825:b0:277:eb15:5c60 with SMTP id 586e51a60fabf-27c3f0dc5c9mr11281626fac.10.1726568873494;
        Tue, 17 Sep 2024 03:27:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726568873; cv=none;
        d=google.com; s=arc-20240605;
        b=Uf22TCoayZB/ChSphZfQRtLGtjBDBKzmuh7RbgN+ImhNjEGFyctddIfy6Ah0d5HO2d
         I+Egf1/D6mNNmGm/BvHog0V6lL/jOyaAibid7HhFZVwsO2Jn8cue1UowQzLWsqlXJekJ
         ETd9MJ+3QOsKvhBD4giYBbVrJrkSDIjDo6nxAIPrHAx7YsG2Jy1CR9mz84IEs9Ota4xZ
         t0J75xOVNXL+6VTac8RfnWPgrMeOLkkTxBbtdvnlCoYmQlPAgYXp+KaHEbznbFsZtv6W
         +BEVzFlnNU2JfED+Kgl3/EUfWo/HTc3wcFPo7rGVJxyxrMw21OpsKMuDfDF7Fc7ZlpI1
         SJPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=WnG2JklIx4ZftyYqviFZtN73CZ8K5xVB9xFTJXaRShc=;
        fh=Qs7dsq6fZWr++5KKYxmAzUJB7nta8GKwTiKpqsGb2vg=;
        b=ZUhsIUDDMQ0u2AZ7xhjrecsonlp14CHOWAi3UsxBa+zct0WscunKvYvfvXZD95ZWJm
         GhIJLlwhDk9hL5nkaeD4zZZVAthKDxIH8ZX385zXq8MAhrxUa6K8OKxt2eI58UdpBC0w
         I7Im6kvQpSNOtTs30pKy17Yil3J74yyxdoRyhmW4W+u9Flw3ppsyJBdiWDB2XdEoYKYu
         zmy2u7xQGXMqnu3gsIly3oS2Ndl/LNtLmQSOq4xnLaMjr5muSPcqomiqN0GUkokf7hLq
         BmX77zLRc2RhLHE9dqPNk0giqlhQ+TFLAyVidjsoB6G+jmYdgZVkRdM4G1zZwOXqs29m
         daow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 46e09a7af769-71239e7de06si249709a34.1.2024.09.17.03.27.53
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 03:27:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 49E8F1007;
	Tue, 17 Sep 2024 03:28:22 -0700 (PDT)
Received: from [10.57.83.157] (unknown [10.57.83.157])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D1A063F64C;
	Tue, 17 Sep 2024 03:27:50 -0700 (PDT)
Message-ID: <a35f99b6-1510-443c-bb6f-7e312cbd4f79@arm.com>
Date: Tue, 17 Sep 2024 11:27:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 1/7] m68k/mm: Change pmd_val()
Content-Language: en-GB
To: David Hildenbrand <david@redhat.com>,
 Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 "Mike Rapoport (IBM)" <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 x86@kernel.org, linux-m68k@lists.linux-m68k.org,
 linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 Geert Uytterhoeven <geert@linux-m68k.org>, Guo Ren <guoren@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-2-anshuman.khandual@arm.com>
 <4ced9211-2bd7-4257-a9fc-32c775ceffef@redhat.com>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <4ced9211-2bd7-4257-a9fc-32c775ceffef@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 17/09/2024 11:20, David Hildenbrand wrote:
> On 17.09.24 09:31, Anshuman Khandual wrote:
>> This changes platform's pmd_val() to access the pmd_t element directly l=
ike
>> other architectures rather than current pointer address based dereferenc=
ing
>> that prevents transition into pmdp_get().
>>
>> Cc: Geert Uytterhoeven <geert@linux-m68k.org>
>> Cc: Guo Ren <guoren@kernel.org>
>> Cc: Arnd Bergmann <arnd@arndb.de>
>> Cc: linux-m68k@lists.linux-m68k.org
>> Cc: linux-kernel@vger.kernel.org
>> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
>> ---
>> =C2=A0 arch/m68k/include/asm/page.h | 2 +-
>> =C2=A0 1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/arch/m68k/include/asm/page.h b/arch/m68k/include/asm/page.h
>> index 8cfb84b49975..be3f2c2a656c 100644
>> --- a/arch/m68k/include/asm/page.h
>> +++ b/arch/m68k/include/asm/page.h
>> @@ -19,7 +19,7 @@
>> =C2=A0=C2=A0 */
>> =C2=A0 #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS =3D=3D 3
>> =C2=A0 typedef struct { unsigned long pmd; } pmd_t;
>> -#define pmd_val(x)=C2=A0=C2=A0=C2=A0 ((&x)->pmd)
>> +#define pmd_val(x)=C2=A0=C2=A0=C2=A0 ((x).pmd)
>> =C2=A0 #define __pmd(x)=C2=A0=C2=A0=C2=A0 ((pmd_t) { (x) } )
>> =C2=A0 #endif
>> =C2=A0=20
>=20
> Trying to understand what's happening here, I stumbled over
>=20
> commit ef22d8abd876e805b604e8f655127de2beee2869
> Author: Peter Zijlstra <peterz@infradead.org>
> Date:=C2=A0=C2=A0 Fri Jan 31 13:45:36 2020 +0100
>=20
> =C2=A0=C2=A0=C2=A0 m68k: mm: Restructure Motorola MMU page-table layout
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 The Motorola 68xxx MMUs, 040 (and l=
ater) have a fixed 7,7,{5,6}
> =C2=A0=C2=A0=C2=A0 page-table setup, where the last depends on the page-s=
ize selected (8k
> =C2=A0=C2=A0=C2=A0 vs 4k resp.), and head.S selects 4K pages. For 030 (an=
d earlier) we
> =C2=A0=C2=A0=C2=A0 explicitly program 7,7,6 and 4K pages in %tc.
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 However, the current code implement=
s this mightily weird. What it does
> =C2=A0=C2=A0=C2=A0 is group 16 of those (6 bit) pte tables into one 4k pa=
ge to not waste
> =C2=A0=C2=A0=C2=A0 space. The down-side is that that forces pmd_t to be a=
 16-tuple
> =C2=A0=C2=A0=C2=A0 pointing to consecutive pte tables.
> =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 This breaks the generic code which =
assumes READ_ONCE(*pmd) will be
> =C2=A0=C2=A0=C2=A0 word sized.
>=20
> Where we did
>=20
> =C2=A0#if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS =3D=3D 3
> -typedef struct { unsigned long pmd[16]; } pmd_t;
> -#define pmd_val(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((&x)->pmd[0])
> -#define __pmd(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pmd_t) { { (x) },=
 })
> +typedef struct { unsigned long pmd; } pmd_t;
> +#define pmd_val(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((&x)->pmd)
> +#define __pmd(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pmd_t) { (x) } )
> =C2=A0#endif
>=20
> So I assume this should be fine

I think you're implying that taking the address then using arrow operator w=
as
needed when pmd was an array? I don't really understand that if so? Surely:

  ((x).pmd[0])

would have worked too? I traced back further, and a version of that macro e=
xists
with the "address of" and arrow operator since the beginning of (git) time.

>=20
> Acked-by: David Hildenbrand <david@redhat.com>
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a35f99b6-1510-443c-bb6f-7e312cbd4f79%40arm.com.
