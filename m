Return-Path: <kasan-dev+bncBCSL7B6LWYHBBH7ZVDFQMGQETGFWFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CFCE0D31CB8
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:26:56 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-655c20a9fdesf651580a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:26:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570016; cv=pass;
        d=google.com; s=arc-20240605;
        b=HrFVlGXplYwikchK2ZKoQaND/kmq1VVblkLhXol6+VXcRom1geQxqQ24rdQBQG0IRB
         TwArzl1zSuS0g1WyxTTU0KnqaJEMi1qj0mkNrMLuTJEevaqMYNZ8upkCdlcy+O4Q0hd9
         9nL0PGGBBcehhmaPU17WTCKJNwed9RUJwiB9YHKwe7vRf00rq0yF9+efDuA5RqaB+SAS
         FP4yOz1S2gj3nbMm1n5mvlblowTQhfRqBFJrC6UQVfJMrO8kd/jJeFP+s7m+KQaH1CL/
         2Tu2nDKgnJv9RbhaEZWlSXaKO9yuYY2cmF8TzxM0SaZeycqv8//EnvhwzrAL53vmjRv5
         6Hpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=BVVrhjWQyqw0QWEDlYw1w+R/eLxvzopJ8x3HMdpTyTE=;
        fh=hcQ61d7tCThrvy25Ud2OPDnRXBzDAPzzqVHCruvsiOA=;
        b=FzPEgPewQhfvb1bc/EYP7hOay/juN8jf9Qv5Vj9RfTufOfSVSUMqgvLdrJoKaXzY4I
         a8WezyIJ+m5/EAuq/mohKlOiuTyEv0aJ0rYTDHOpc7GoTMd1MWYk7PKJ7f/I7ACYg4e9
         tmQ6P8NDZxspRuirdV6S2c+q8HgfViPWunhqNpH3tliP8Zdy8ZMlXnAayAe+ElbQfDu5
         1VBZBK6Hgh1KxdMRk93iugkj7Rhl21zpCHsAUBgz7Exp6Ptk21DwqNgt58SUCXXxja1k
         ECYaZsENNqsOPydl0I7tmPn4cx2QLV70eIfCYaYRdhSajXBLpkpZcjOJmmbNYQARDfXK
         MJqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CQmtGRGL;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570016; x=1769174816; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BVVrhjWQyqw0QWEDlYw1w+R/eLxvzopJ8x3HMdpTyTE=;
        b=Z3DEhn0MFPQtv4VFH6IhL+nCxF+sZm3KUnFfmUQGxmKExwtfmr1XP8/U0e9xoWP1w4
         luXwQhwFkBfib8BM+2cRhMW+t5zCBHwEDKQxNI3b2FrF0TI6z8DJhzUmciGfKsmiZyvN
         41bcK9Qb4Apu1WQOh8cKsD+y3RIh1+mRsyv2X2Pmd7laEUSyXH/chf9tn6TnXsj0YiaW
         Qgp+vk75hgGBUVe6Q/cWnVw9Ju5uRIKx0LXiY2VYd97wytVb1Ln/5FocorJv71Dsks1g
         htLJsTpQi25dkpnhk8i1Tr0H5DKzKjgPQdshLL8ZC9y047WEeVBwcgKvEBvihm3lS451
         VHxw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570016; x=1769174816; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=BVVrhjWQyqw0QWEDlYw1w+R/eLxvzopJ8x3HMdpTyTE=;
        b=VDxI0kV0xPiBxY29MXUzLffY74jbJSvboi5RG7ZZ4Zs7jj7mubUZUtdou/fT8v5a1h
         yFuvbxw4xIvM2QTu4Dj8wP4auUhBHuQJaJPBFMaTsx9KTc6k36oqS+8X5bu3mETQRW32
         zf7p5AdUuTOxvTjW9RWuk+Av0gbxTTq25QZPeW7ZQVykaf4xi/7oLjYX3HqJ1nGCrhli
         H49Hpa91TxcbhmnEjPv0S4tPqvZKb+RFhrzO3hSLbXRBLAHqIqgS7z24j+Tu5Y8wHalB
         Nv2VqRTqD+sqN+gK8X4wdetouGwnlke5EsvqRgWEz7MpRNeZPeUmwkn+i7H2lQAiOg6n
         +Wzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570016; x=1769174816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BVVrhjWQyqw0QWEDlYw1w+R/eLxvzopJ8x3HMdpTyTE=;
        b=gyHJfL0+cDUbpvqjaw/xcLJSNv8GGAROvpgcc3zCgdn58mFoqyscKRwI7K8F6XUYPU
         kyq+Bz62rrBy6jntwVSGWPDqqlu5ZrYtHe7UgAZNevhWa1jDOWnrIzfAhTGtg0TFscRF
         jC1nkoA5LLXEwYRjA/ynO3wShnb4smzIkI3uUq5egAYTg37CuWcIXsbtbVwTP/64XuEn
         9Avg8xnbsR8WSEiwRkgzlIiMHdgaO4nI1krGeuLCXyaRNUIBk7O0awN/T5r7t/0Q1Vp5
         Ctxz9N81gyWs4m4pn4jwjuzxY5ttFrmynYyDBsryP0j/WXgIv7ngwAD3kbDo8eOHDBVA
         GbJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTcQGZFKl/WE1kM2bemeXC1ehiC+5I+tjSNwpdEMCkamsMj9WVoT9hShDc4jwR1ZbRkA/l/g==@lfdr.de
X-Gm-Message-State: AOJu0YzqKezMdND5VsKEC9VJKF8u5Xr0VDsUN8vjtaub2X00u83q7ywm
	PIhovhkpBktmAfI5RVmaozRvKE68tAGMmhJ/5jxjaKYWSvrrUGfu3r35
X-Received: by 2002:aa7:c918:0:b0:64b:5625:c519 with SMTP id 4fb4d7f45d1cf-65413173f63mr4369405a12.10.1768570016067;
        Fri, 16 Jan 2026 05:26:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GQqtcvnKwpEM1zN0ziyR1FPqvKSDY3Ze8dTY0SZHB1cw=="
Received: by 2002:a05:6402:3048:20b0:640:eec1:949a with SMTP id
 4fb4d7f45d1cf-6541be8db53ls866622a12.0.-pod-prod-00-eu; Fri, 16 Jan 2026
 05:26:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWauyAFRpwZvapqoO0ZiqYVmK3U/8WZrT9U+FhnbfjMZl4GKCCXwTO2RlNQypu9YBWcOTL3qtnYEzQ=@googlegroups.com
X-Received: by 2002:aa7:c2c9:0:b0:64a:86db:526a with SMTP id 4fb4d7f45d1cf-65412e18d72mr4196712a12.4.1768570013467;
        Fri, 16 Jan 2026 05:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570013; cv=none;
        d=google.com; s=arc-20240605;
        b=KyL3E6tLpskbzx9KpIJ4jI5Qaccgh/GWRycc90z9ph2cGUqNQUs8ksmgLlApWgkq0H
         hB6dcecBvZeQy9POhu6MWL/IFtFi8fSmZRvIfyWHFpMsqociN9byZfGM6SdJTuNobkvd
         dbB7SQO6vtkCAyGNJleAWzxCjXzIGvYOY9XbuH3kXGSGbYMk1tcPFetDeuJYw7J613k/
         0i1H+Kb1HgM2UBjD4r0Q2slugDHxriSO4wKVC/3+WmOgunJpNb7OrZGAO2qCWyIwoJNN
         PBgJLV3Sz3RXSu+DLHUugdz6xzlqQ5AY7Rg1JlvEPbX8ouU17enYWmwzqvKUahz8MuK7
         2rBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=v0eA49DHdlAf9Bft0pCk6JLi/3Gfwpf8alD37YhIJQ0=;
        fh=31+ahekS3JGCV6qZ2SZ99OgUNwa4P7+xGMqRULELZkg=;
        b=HszYZqhP6YkRKmq36t5NAx+5NRMMofq5WknAz4qhzXfDyBllT7yoAYAAuFAyxEnrtL
         i+NruQTC+Jjomuhcf7Rrm6rZySw+mcqTYxCpC4dmMyzXilsJMVlbuuiGLdGDPruLe+KY
         F0/lA3YBLkCMJV/0Untmu3GZb1Fmv6hTmiHKHsyQUXvbqkiQFik8nCzljUXhKeRhtTG/
         n4tlotP4krVpUZti8YB402DGd2MgfIs3rdN3DtFueqzxiQNvO//ExTvxzA3iSr66tLH1
         bvwYq9ZoSb/wfv+Jm+kro8ykJC8tj8LfjlK9afFQ1rFHFHkcka1yvX30YpMN+ly/b+Jn
         vcig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CQmtGRGL;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cef9dsi51888a12.6.2026.01.16.05.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:26:53 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-59b75f0b8ecso266508e87.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:26:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXmxwM81IQjSTHJQ1AnJE7eB8RTOsoW7iXJK+UJsgUnZlchGgzmhUBPNUBIydYbAL+UcCrFju4p3eM=@googlegroups.com
X-Gm-Gg: AY/fxX6L/bSn1hSVlyO27iGSCPqSiUdSo4ItBRrZoADmGkEmmDaw1+Z65ejiVEa90vT
	PCKTE9sXH0jPfWNQK18YeU1eRcEfNWUgGBRPtA2ark9Ke9DEet2ide9BSnSF1N2krVNCpXRqsG0
	HXAyAusJLctZiy04Eklz60E8H1Cz6vThYtN8OZcMwOpiwGARcTFzER6zwrE/yP2d0rHk3VTn4rH
	4UsVnRP7q4YJ6v7+9feVlnbqp2SctGn6wZvw5uGOaDLaqMCGQ0w5H/SrZZmJ1hYSXGreR6H6Xme
	dPgvgRi4xlZBfi7VD80cHkvQMQLWC/GvL6aTlQmf8V1VWUCZUBcPBNV5SaPohUcEHESsYUPRD9l
	7ZXFD55AhiAFWz9QVOran8R+DTm4FIJoqm99GWjDTTaqDDf5ERW9z54oEHIVyqM70QTCuBCpM0/
	jr0knLXcxEo4LUZ/v1Ug==
X-Received: by 2002:a05:6512:63d1:20b0:59b:7be4:8c40 with SMTP id 2adb3069b0e04-59baef130e4mr407353e87.8.1768570012429;
        Fri, 16 Jan 2026 05:26:52 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf35273dsm782709e87.39.2026.01.16.05.26.50
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:26:51 -0800 (PST)
Message-ID: <10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com>
Date: Fri, 16 Jan 2026 14:26:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>,
 Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, joonki.min@samsung-slsi.corp-partner.google.com,
 stable@vger.kernel.org
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com>
 <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CQmtGRGL;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::133
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

On 1/15/26 4:56 AM, Andrey Konovalov wrote:
> On Tue, Jan 13, 2026 at 8:16=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:

>> ---
>>  include/linux/kasan.h |  6 ++++++
>>  mm/kasan/shadow.c     | 24 ++++++++++++++++++++++++
>>  mm/vmalloc.c          |  7 ++-----
>>  3 files changed, 32 insertions(+), 5 deletions(-)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 9c6ac4b62eb9..ff27712dd3c8 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -641,6 +641,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, in=
t nr_vms,
>>                 __kasan_unpoison_vmap_areas(vms, nr_vms, flags);
>>  }
>>
>> +void kasan_vrealloc(const void *start, unsigned long old_size,
>> +               unsigned long new_size);
>> +
>>  #else /* CONFIG_KASAN_VMALLOC */
>>
>>  static inline void kasan_populate_early_vm_area_shadow(void *start,
>> @@ -670,6 +673,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, in=
t nr_vms,
>>                           kasan_vmalloc_flags_t flags)
>>  { }
>>
>> +static inline void kasan_vrealloc(const void *start, unsigned long old_=
size,
>> +                               unsigned long new_size) { }
>> +
>>  #endif /* CONFIG_KASAN_VMALLOC */
>>
>>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) &&=
 \
>> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
>> index 32fbdf759ea2..e9b6b2d8e651 100644
>> --- a/mm/kasan/shadow.c
>> +++ b/mm/kasan/shadow.c
>> @@ -651,6 +651,30 @@ void __kasan_poison_vmalloc(const void *start, unsi=
gned long size)
>>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>>  }
>>
>> +void kasan_vrealloc(const void *addr, unsigned long old_size,
>> +               unsigned long new_size)
>> +{
>> +       if (!kasan_enabled())
>> +               return;
>=20
> Please move this check to include/linux/kasan.h and add
> __kasan_vrealloc, similar to other hooks.
>=20
> Otherwise, these kasan_enabled() checks eventually start creeping into
> lower-level KASAN functions, and this makes the logic hard to follow.
> We recently cleaned up most of these checks.
>=20

So something like bellow I guess.
I think this would actually have the opposite effect and make the code hard=
er to follow.
Introducing an extra wrapper adds another layer of indirection and more boi=
lerplate, which
makes the control flow less obvious and the code harder to navigate and gre=
p.

And what's the benefit here? I don't clearly see it.

---
 include/linux/kasan.h | 10 +++++++++-
 mm/kasan/shadow.c     |  5 +----
 2 files changed, 10 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ff27712dd3c8..338a1921a50a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -641,9 +641,17 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int =
nr_vms,
 		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
 }
=20
-void kasan_vrealloc(const void *start, unsigned long old_size,
+void __kasan_vrealloc(const void *start, unsigned long old_size,
 		unsigned long new_size);
=20
+static __always_inline void kasan_vrealloc(const void *start,
+					unsigned long old_size,
+					unsigned long new_size)
+{
+	if (kasan_enabled())
+		__kasan_vrealloc(start, old_size, new_size);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
=20
 static inline void kasan_populate_early_vm_area_shadow(void *start,
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e9b6b2d8e651..29b0d0d38b40 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -651,12 +651,9 @@ void __kasan_poison_vmalloc(const void *start, unsigne=
d long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
=20
-void kasan_vrealloc(const void *addr, unsigned long old_size,
+void __kasan_vrealloc(const void *addr, unsigned long old_size,
 		unsigned long new_size)
 {
-	if (!kasan_enabled())
-		return;
-
 	if (new_size < old_size) {
 		kasan_poison_last_granule(addr, new_size);
=20
--=20
2.52.0


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
0812bb1-58c3-45c9-bae4-428ce2d8effd%40gmail.com.
