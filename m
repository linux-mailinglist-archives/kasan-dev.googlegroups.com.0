Return-Path: <kasan-dev+bncBCSL7B6LWYHBB357WO6QMGQEBWAQBPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DB10FA32DF0
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 18:52:49 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-ab78d23202csf3052666b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 09:52:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739382769; cv=pass;
        d=google.com; s=arc-20240605;
        b=iY14ekedBN1a0wHFYD4tFegnlQC/2rRs3NnMxJHRELAYoAfJAJtfxW2EiaUZWyiXBn
         EzPjXII/IuO5idKPRSdivp4PRiZTqJVfO5ZPmflssT430N0r6apdem9YfgaYeGe9sbUk
         xGjD0c5oEkqO8A9nY7dwWnbcZ5JY4QS5oQ+a9+bgIvKkFGIpfhPV4qe5Bq9YlTwEk6JU
         4a4LJj5Um/fW4mfb1MMPIwkshDVEColl9rq2O2Rj4yxUnETPDFxWS8bFlNVGwk1I5oN1
         S8ezv5FnkNWtNIdaFhPqJdhKe1k5L42fn/LhcWAAP3k5WpLW1PCimXFzTAL0u4ixhk6k
         zgSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=DVNQxP73JySuHjJb5IFJ37MXRgKp1lCmUSfPRhGQo68=;
        fh=8xahpc4evQwTbkHJIN3cO4PzpLUHESZsWihZaNtSZzk=;
        b=cb/I14jxaTpdHXTjBTdH8XI+5cSe/wgJemW5k7vP8PiJCesdiXDsIPdP3pZf5UEvg3
         zNt4gRDENUEYZPjTHRd/Puh6Ss9FLL3u1doa5KeSk+FoDWFWKd5Bftl+fRf0azyNVRRE
         aLzmedaQsDyOsIEa1jYlYEYdppNeyS15D9R8cp7jJIfMN7/f+dwRQRZ4GFy8xX/0pAm3
         JDDUsrB3lyN7ygZPUyZb0lrxTQZCKSKLTbiVy27Yo9zJXpVlLhiqitAvm42QgcNb1/JP
         B8ZsEn75MzbN8Dn2bgqlBoXJlNFznvOxbujR4e7+L9We502lyLLTbTE5w87pGlPoEM8T
         DiHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=laWjKfxe;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739382769; x=1739987569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DVNQxP73JySuHjJb5IFJ37MXRgKp1lCmUSfPRhGQo68=;
        b=O3GeYfNm81SA0/eKpieypOqmTk7yUs1A/FGBw2dGmtmsc75dOuSe4Ig47ASPxMc9hm
         mZTrMiJJOy4xrQnHoQpfboHvBregZaw5hIoCQnGV6NRWhtKWINW1SK/xXWtvaAhaWg8b
         LjjhKuARAwHwxGtz06UyS5Z2b4K7qfUMs5g+3ndJa0Ai2IB/JOMe/BvaDNh3S7df12A0
         oyKBXeOjBOxWXGgRkaZgH2oGrScWq8yQhY2xaZWPDtqPfjMYsNZsG793brjiiNwN9hpa
         QQEAG0C71uABhAQc+GYoB0+C12r9dsLbaAxqVFv7FuPB2/6SIEecyV/9WQt6c98adZ16
         4Q/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739382769; x=1739987569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=DVNQxP73JySuHjJb5IFJ37MXRgKp1lCmUSfPRhGQo68=;
        b=O2SW/iWsjoJfTexhLY6skSf8605B6xOqFMNzy2BnDc1WXoDeNUE2stsNM3kOHF8LGl
         JGPR1HywIR7sP7xuqWcV3GYSrL4nOSgin+zQC+B+1Y/gepZPG23csZf9cdgtZsNxlsh/
         l6wGr0ol3cYL58MkLn8rYC9WDQSP3NrC1gKnyPoYOoDGsIe1fTkUAgyA7QiUGV9i/ywM
         HglDDsOpzE0GCdkFv2kqHaAV7MW3AWKob3B5P//+vGGS2h0EkyJQ5tllZqcVg4X9Hm/6
         Fnl1336PQTCWZfcu7ziijwb6YiSyRfoHltFkKPQ4nIVQro1pdAbNHEnrs//d4o+uHEj0
         ErUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739382769; x=1739987569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DVNQxP73JySuHjJb5IFJ37MXRgKp1lCmUSfPRhGQo68=;
        b=CLo6Q2rJn+PFZ90Dlw1nqhRpV8d5FdvXVZYfcpK1NvyJf0nEdKgrYpv60HvdV1SgUG
         m7uO2v3+deLeCpGzl77U897rPUXhm1wVgaiM/VTo+gHOmPrxNrDEw5bKgYnXL1blRGto
         okyp1O9gcPcHFhQxBNxF1NHJu8S0N1ZvVwR/8gNES3dLzwgUtDhiE8iZGAOGVqNVh8v2
         /LdGPQaIPWSMTrTgO881fV2+JsA4/MZxp6yXijQPOqpUtOK6rQBAulSynqRGVJx3eadJ
         tEgaW49QNugQk7XnAAnPE4pQZovWbSTV3VJJfCx0g5GuWwXnGAPimtFRyKLTGykLJp63
         qGtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEhOKzSeuVTGkIZEOM1Hiy+cHfhGlpv1LEpvE8F8Vx02k1xMWR7Q/QhK71Rln8EUxXtcs2BQ==@lfdr.de
X-Gm-Message-State: AOJu0YyJq51hFS4xMuH+zUrngsXFs0D6DO4A/Z2Fiq4MaT3/U3Agcboc
	6+tbZzQWGEdc3/nv3induOI69Fto3GKMd90+WyboYOU4o9G0EiqZ
X-Google-Smtp-Source: AGHT+IE50KMvp2Iivdv2zGItpDmQWM6kIH5S05WBxU8iqpkCJ7Pp7grCfdzN1UtOrdaroaJjx+Xurg==
X-Received: by 2002:a05:6402:5285:b0:5dc:5a51:cbfa with SMTP id 4fb4d7f45d1cf-5dec9d2c185mr269463a12.6.1739382767632;
        Wed, 12 Feb 2025 09:52:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGoo1ZmMIql+9qbHFqNgGICD/wu4J3iExmOi2POSs9r7w==
Received: by 2002:a50:fb0b:0:b0:5d0:e410:4698 with SMTP id 4fb4d7f45d1cf-5dec9914a08ls33269a12.1.-pod-prod-05-eu;
 Wed, 12 Feb 2025 09:52:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUBLNSJQ46f6pn6of2N1D1Y1BquHc/TLrw58UlNPEuw/FEnbewo0/dLqQDDgkvYZpC5+XJ3levmgbI=@googlegroups.com
X-Received: by 2002:a05:6402:11d1:b0:5de:4a8b:4c9c with SMTP id 4fb4d7f45d1cf-5dec9faaf39mr87704a12.32.1739382765012;
        Wed, 12 Feb 2025 09:52:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739382764; cv=none;
        d=google.com; s=arc-20240605;
        b=SDn8hQrj6BKzKTDGBXcoHFu4uOIhtlSmLdAebrxZjo9Makg0NZ0wVj6PbMPy4ESzSi
         E8L11yDzhbqIo5g0VGC+SNEBv+Dt2GaMavGFVOCXWKq0gMH+UllMjq8qj+Ohrp3htl82
         S71HPa9rQ5cvuPpa6miTdIUDYCOFeVUwECAv2ADY8efon9df4DjAx0nCHxbKOMqptdBj
         ZHU9eg1qoWfHZjgXDakuz5uY/uB7qIT4FTr0KGRQP+A2tCEa5dQiIx5avfXDF2jQT9Gx
         az1uSG1+4ZUmCijikGiVY9x4e/gP7m1l8i4b7g/c5oiutPdT6cLvnFIShVgUZ7MFjFoS
         93SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=C/kS06FLerC2Af3s6b6Rf5nvMZaz+z4sBVLyAweX+ok=;
        fh=VjmBlkxlpn7kbzvScC1UWrcYGfMFI9CiB3DfR+Vhyb0=;
        b=bvtxXfYyM8KAOrCb/Ld3Db9bnNTeZxU8L9Et6RT8ZVAbcocgIkZQvwKMaZQLeapXqN
         aa6dCDUmvUbagg2MDGZF7SrcfDRHcwAvulTnGea1W9n3C7MmlLg3D7zCCHGBXlkeiVW7
         2QlxgP8YTwxFXnnipBqK4LA/0yJPfvP9hkt8rN1lDBAIN+AKMPflXt6MmqPf3O8cZwqJ
         GF9xxUDuizKeLpjmpxg2cciTdBrYmsWxbY0+MAc8oYy40Hcv51iPyZxqkYnCExbmfyna
         jVi00TDKjaK3P8uUiAc3PSR024sVqgnJyo0wGoDaurDgUo/gJe86UYWoGmyZzeDbn1qC
         vRGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=laWjKfxe;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf5d1bfcbsi417999a12.3.2025.02.12.09.52.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 09:52:44 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-308f7f057b3so2920671fa.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 09:52:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/tgflfodg4viQ012bNFOUY+S3wWxwOyBcrTjgT9TIjviJT9Z935M3VmJIkQ5oNZzuvy0sAJ97skc=@googlegroups.com
X-Gm-Gg: ASbGncujvPwVOcf6JO/rHBtXCsx9P/DxbH8zoqkJIDGjEQW6e+kwI3oPviDuXtIEoGB
	ndXaZrN7DP5XEeQ4Ot4HPf0R7jnfSr67y9EKVw2NQtV9vTiZtjATnjSHhc8GsChvgbviZ6BA8cA
	mumSDVHyJKpX528A84LDykKD/bGi2nPFMMOIWKMsdBErlxiy3VQxQdEXrg2ZHAxp9YbopX+3zn0
	Ak1cofzRykDznGlNV25Pgmk0WqalK2eajnMRSN45VNug75trgBKw7D1BmawKnlVUfB5zHDLS5DZ
	AD46U/i8kLnDjC9qII3GRQ==
X-Received: by 2002:a05:651c:504:b0:302:3356:54e2 with SMTP id 38308e7fff4ca-30904664d33mr5547561fa.10.1739382763893;
        Wed, 12 Feb 2025 09:52:43 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-308d9e1fdfcsm15669701fa.31.2025.02.12.09.52.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 09:52:43 -0800 (PST)
Message-ID: <ef785e05-f52e-4a88-9377-b51b81b228ce@gmail.com>
Date: Wed, 12 Feb 2025 18:52:39 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <llong@redhat.com>
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250211160750.1301353-1-longman@redhat.com>
 <CAPAsAGzk4h3B-LNQdedrk=2aRbPoOJeVv_tQF2QPgzwwUvirEw@mail.gmail.com>
 <cfe70f31-e650-4033-9281-baa4cdc40b96@redhat.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <cfe70f31-e650-4033-9281-baa4cdc40b96@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=laWjKfxe;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22f
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



On 2/12/25 2:34 PM, Waiman Long wrote:
>=20
> On 2/12/25 6:59 AM, Andrey Ryabinin wrote:
>> On Tue, Feb 11, 2025 at 5:08=E2=80=AFPM Waiman Long <longman@redhat.com>=
 wrote:
>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>> index 3fe77a360f1c..e1ee687966aa 100644
>>> --- a/mm/kasan/report.c
>>> +++ b/mm/kasan/report.c
>>> @@ -398,9 +398,20 @@ static void print_address_description(void *addr, =
u8 tag,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("\n");
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (is_vmalloc_addr(addr)) {
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 struct vm_struct *va =3D find_vm_area(addr);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!is_vmalloc_addr(addr))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 goto print_page;
>>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * RT kernel cannot call fin=
d_vm_area() in atomic context.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * For !RT kernel, prevent s=
pinlock_t inside raw_spinlock_t warning
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * by raising wait-type to W=
AIT_SLEEP.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!IS_ENABLED(CONFIG_PREEMPT_RT=
)) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP)=
;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 struct vm_struct *va;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 lock_map_acquire_try(&vmalloc_map);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 va =3D find_vm_area(addr);
>> Can we hide all this logic behind some function like
>> kasan_find_vm_area() which would return NULL for -rt?
> Sure. We can certainly do that.
>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (va) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 pr_err("The buggy address belongs to the virtual mapping at\n"
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 " [%px, %px) created by:\n"
>>> @@ -410,8 +421,13 @@ static void print_address_description(void *addr, =
u8 tag,
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 page =3D vmalloc_to_page(addr);
>> Or does vmalloc_to_page() secretly take=C2=A0 some lock somewhere so we
>> need to guard it with this 'vmalloc_map' too?
>> So my suggestion above wouldn't be enough, if that's the case.
>=20
> AFAICS, vmalloc_to_page() doesn't seem to take any lock.=C2=A0 Even if it=
 takes another spinlock, it will still be under the vmalloc_map protection =
until lock_map_release() is called.
>=20

I meant to do something like bellow, which would leave vmalloc_to_page() ou=
t of vmalloc_map scope.
That's why I raised this question.

---
 mm/kasan/report.c | 17 +++++++++++++++--
 1 file changed, 15 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3fe77a360f1c..f3683215f4ca 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,6 +370,20 @@ static inline bool init_task_stack_addr(const void *ad=
dr)
 			sizeof(init_thread_union.stack));
 }
=20
+static inline struct vm_struct *kasan_find_vm_area(void *addr)
+{
+	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
+	struct vm_struct *va;
+
+	if (IS_ENABLED(CONFIG_PREEMPT_RT))
+		return NULL;
+
+	lock_map_acquire_try(&vmalloc_map);
+	va =3D find_vm_area(addr);
+	lock_map_release(&vmalloc_map);
+	return va;
+}
+
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
@@ -399,8 +413,7 @@ static void print_address_description(void *addr, u8 ta=
g,
 	}
=20
 	if (is_vmalloc_addr(addr)) {
-		struct vm_struct *va =3D find_vm_area(addr);
-
+		struct vm_area *va =3D kasan_find_vm_area(addr);
 		if (va) {
 			pr_err("The buggy address belongs to the virtual mapping at\n"
 			       " [%px, %px) created by:\n"
--=20
2.45.3


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
f785e05-f52e-4a88-9377-b51b81b228ce%40gmail.com.
