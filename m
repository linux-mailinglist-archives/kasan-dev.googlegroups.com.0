Return-Path: <kasan-dev+bncBC32535MUICBBN5UUW3QMGQEHUIS7VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE73E97AEC2
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 12:30:18 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6c5a32ec343sf30264926d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 03:30:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726569015; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uv4tiZuNwhQmPDoVvbV+MCMDPoduUD8oQye7uPz8rn5+PFPhVABuQy9zxHX9gGNvQ6
         4oHlvjGc1W3Uh53I9qsE1m0A0Pw7Z8kIeKwCkfj+JVPOFQRb0Z4IULl6EN/TmWsuw7JU
         IVDUnA6j8DXjAVvQVhAAELLoSdTCS8iAgBL1RDkEM6f5ZQYxOU+xS6YprsrJT2kraaRU
         4MrqomH0W+oXfUNYBBZYxFjI1qVMIsvVU0jc1gOsMry+9lI3m7CIni7la+qW+vUy1xbA
         x6OG5NtLNMB9FYEljPZcHcIWoqBTU+buUt9HhsQHT2UxKvJ9tu95iciU3ZTQ9ufNzyIm
         bsPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=EdvR7DrU3p98cF5KqgmhoPXSa4TEPUGkveAKV3ZkuRs=;
        fh=4vhKtPodutKNRnaSvT+l4xYq/6jM/pmuvqMePSL0+o8=;
        b=BYDrsfFa63QWbqNrXP9psOpKQaz4pgk8T/oTNW+SgyELF9CmkPVo9BKfiqdPHxfuaA
         qpM38l/J08O3aJxyOnLMUWzsDySrdcuePWQlopEciQv7L1m7T5jfsf28zqrHNpDw5POh
         cPJY1ITXoZuNXGj1RYu5NEORr8TFAJ9dfXFOIO+NrYaIWnPVg5Kbk0ZaoMak+RQv4Qo1
         JmWblYcyj9d4m3K/XDuxjYHysg/S5HB36P5NgD3MwubGocZ5LPqjX4Zw59xe9/jreVWs
         tRkphrtZjPPGoY+dDcmjLkrwwM7E8Jf8X6RQDVcKDibC2BtoreZJJBwBUcPnRORsavM6
         tElA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="UmAfT/z0";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726569015; x=1727173815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EdvR7DrU3p98cF5KqgmhoPXSa4TEPUGkveAKV3ZkuRs=;
        b=sp/y2pvgv3MAzTW+AlS9eSB8WyeFbVUHTyrr6ELyWp16Ig0PtbGaZg8t/X3xiUqFv6
         WpNo2HHh0zk7xshD8KnqaEPmxVBUC5WwanQNMyGH1gHgR4oaRgaxul4tsqmhwB9JPGcv
         9W+nbrfjq9crGfwEtx0tBp0uHqwUd74VOxoonfVDzvcePWPMrcr+TgWvfsEXd5sFuYsI
         n+Wwv4LQ0x9YuHzSCwf08LPq5ervzwyu0WhNMw5I5Ze7ybDkMmGpHj90Pu69MKKffecd
         ej3RuHboLIsejnkwnxFJpUpxCD/8lohenKkmOLEesg5GUrF84BU0fimjkuk7YLY2NsmQ
         7cqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726569015; x=1727173815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EdvR7DrU3p98cF5KqgmhoPXSa4TEPUGkveAKV3ZkuRs=;
        b=XYCyidnpkajwkAhoq1kb3I/QmKKog0Zl+fKA2Bme0ir5v5UiLj8zGY6r63WV6cXdaj
         t8evCb0OoL2JpeIcauUmZpbuK3/tutsq4OFaxFBRrWsrlYqMAerQAfN+eudzGOjiojF7
         /qeX8JfQeWiDEp92pQgXtOGSL2o48IUveoBuxCsLYA3JfeBkGRmyaESKPPFyXv4B/F+B
         mj/mVB29jrt80N/xRzKIGcCtkyXWDnOWu0/49U1t3tXJpvcMctBrANyBP2DLgyxe/HJS
         EaN1mxQolQ+dfXKxJKtwI8k0ZPk6PFWAxd1C7z+QIRuuGcT2rL+NKankVxgSGsGT7Tyl
         CT2Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNpWhcOAz0syWYWGljsQBF5hx+9o9SQj5nntn3pT7B1DxKPx7PvkXF0iR7PO6CPNMX40tgDw==@lfdr.de
X-Gm-Message-State: AOJu0YyPj5zxOQ1bDhoTbRwuJLEX07UDXgAmN2PLD3mSk4fVP51KY7Qi
	Oq2BY+0skMjuNXxU0Du22LB9k0nknUaeKtoO1ea3nuKwb4tq0iZx
X-Google-Smtp-Source: AGHT+IFWgUBGxyrHDPhT4EHYBWs9IrmpmE9BBZGLu+pv6A410WX15IL1BRgJrIGRl5x2s6z1uueyeQ==
X-Received: by 2002:a05:6214:2c03:b0:6c5:2747:f458 with SMTP id 6a1803df08f44-6c57351a6d8mr344265426d6.14.1726569015326;
        Tue, 17 Sep 2024 03:30:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1313:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6c573539c41ls4879256d6.2.-pod-prod-03-us; Tue, 17 Sep 2024
 03:30:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZghDWhj8gDfO1mqrSj9hVJrfg/jAWXKRplFeq1gDyrR7glSVodGV9z+dsnwquL3Du3LEtm3sWW2o=@googlegroups.com
X-Received: by 2002:a05:6122:251f:b0:502:bcda:f3fb with SMTP id 71dfb90a1353d-5032d41021amr10752895e0c.6.1726569013684;
        Tue, 17 Sep 2024 03:30:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726569013; cv=none;
        d=google.com; s=arc-20240605;
        b=lvY8iZ8a/KvusnE34kyeh78ndPC89UWqZKYGdermq9Yfqo8EJbGoaBO2CEj2spJuu4
         wtJEDG4ugKm9dArLuevK15fp/Om2BJCk2+Ya/BK637F+FsGvTVPM6uBYkxooFEdcsI6z
         W4EloKUxB9HwXhErMh1sYlBEu+WJso/m8o6wBvmURS4r5cBDO8NqaxUhzrb5FW3CEgcH
         DOHlAhg2yo3tyRbJ5R7jmLrQcMdpwTmAP3Oh8kplK8JSKGluCxZgrE2AlrU3rTfVdvYI
         TyuZXlxzGsuQlUxc1ZJsGEy/t1JFC7f1OXN2Kj2KKwyx49Fwfq0OgRjQNVbOBVqG5LWG
         JRLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Il6/yr79hfIqszHcYXe2ZQwVjF0GnV7MWdNXGzD9hFg=;
        fh=TIjYKnW3t/e6GqyxLfZjpuOc+VYKb3STpDl98bDcZDk=;
        b=H/rmF4bAjYmVKAfE0SfpDyWzsr6015fc4IFmAdTU9tD2YIvWv2lgWRZElkG5/Cz3S3
         A6Ae3tq5cu+D0w53s7ZbjAeKONvPEHE/KGDmDzy10d7V+tMuBrzb/ssH/T2tk1Bxx2eY
         LCVxxu4vFj6yWCHBbVJ/Dyqn5602wJyXiCW6LDdykZnBlIginixEif36VhL2r6gQiwB6
         teW3JlHhWbTYdLD1+j7brkNcc5ZDaOTdGyj8OpIbBnPHSJackjXxpyd/n3lJFVBK9R5W
         p5nTzfJu2NoLkeTJ7J2/xR0i6+7S8D2eoh9JYSBH31RzcOUoQZVS1oc+0xSEWgtBxD3s
         sCBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="UmAfT/z0";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5035bdf88e8si406033e0c.5.2024.09.17.03.30.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 03:30:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-ej1-f71.google.com (mail-ej1-f71.google.com
 [209.85.218.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-325-2HXmklfyMPGdBYuHG7WqQg-1; Tue, 17 Sep 2024 06:30:12 -0400
X-MC-Unique: 2HXmklfyMPGdBYuHG7WqQg-1
Received: by mail-ej1-f71.google.com with SMTP id a640c23a62f3a-a8a8e19833cso468287866b.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 03:30:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqv/Bfjt1fWuWxbSvStzBXnN8eGG0EOpG0o6JSpLs0pXSOs0+MVlTxejFwU+sgybSI8zj0K6JEYls=@googlegroups.com
X-Received: by 2002:a50:cc4b:0:b0:5c0:ba23:a544 with SMTP id 4fb4d7f45d1cf-5c413e11a77mr13969642a12.12.1726569010907;
        Tue, 17 Sep 2024 03:30:10 -0700 (PDT)
X-Received: by 2002:a50:cc4b:0:b0:5c0:ba23:a544 with SMTP id 4fb4d7f45d1cf-5c413e11a77mr13969615a12.12.1726569010313;
        Tue, 17 Sep 2024 03:30:10 -0700 (PDT)
Received: from [192.168.55.136] (tmo-067-108.customers.d1-online.com. [80.187.67.108])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5c42bb89e1fsm3704713a12.72.2024.09.17.03.30.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 03:30:09 -0700 (PDT)
Message-ID: <0419471e-20d5-4db6-ac58-09ae0c0b9c65@redhat.com>
Date: Tue, 17 Sep 2024 12:30:06 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 1/7] m68k/mm: Change pmd_val()
To: Ryan Roberts <ryan.roberts@arm.com>,
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
 <a35f99b6-1510-443c-bb6f-7e312cbd4f79@arm.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <a35f99b6-1510-443c-bb6f-7e312cbd4f79@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="UmAfT/z0";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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


>>  =C2=A0#if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS =3D=3D 3
>> -typedef struct { unsigned long pmd[16]; } pmd_t;
>> -#define pmd_val(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((&x)->pmd[0])
>> -#define __pmd(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pmd_t) { { (x) }=
, })
>> +typedef struct { unsigned long pmd; } pmd_t;
>> +#define pmd_val(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((&x)->pmd)
>> +#define __pmd(x)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ((pmd_t) { (x) } )
>>  =C2=A0#endif
>>
>> So I assume this should be fine
>=20
> I think you're implying that taking the address then using arrow operator=
 was
> needed when pmd was an array? I don't really understand that if so? Surel=
y:
>=20
>    ((x).pmd[0])
>=20
> would have worked too?

I think your right, I guess one suspects that there is more magic to it=20
than there actually is ... :)

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0419471e-20d5-4db6-ac58-09ae0c0b9c65%40redhat.com.
