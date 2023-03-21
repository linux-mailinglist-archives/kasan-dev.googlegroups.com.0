Return-Path: <kasan-dev+bncBAABBHFO4WQAMGQEB22SS5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E9566C2B01
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 08:05:02 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id t17-20020a05651c205100b0029f839410fcsf89569ljo.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 00:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679382301; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2IG7Vg1LtpJeZuhBlEfXb8xr0+QwmwlhI5ei5o51snKHWxa2vG+hr/3lFoaF287QM
         JUXJuesxvq22TfFwPfBpDpWCFub7lqicMG/FCiArsQKUSoS5nZP9gJ6DFHcYTiqLg8LA
         es7lyXtRzD9lhKPqN/eolN4YmpYAD16eHQgKtF5wdpk1An+PIecRJ3LltA4+u92cIA12
         nfVivBtNtIyO9a5sOUvl5gDJQ/qcy3Wzcu9ZQmhofBbpXS1rVbIQ3Czq9S1pElKrdal6
         9lcZrwGPwj8VvXbsIk+0IsajutASMa2VC/WwBq8FAvCXbNZQjAEp2CnHQxwR9pOlkbao
         R1ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:mime-version:date
         :message-id:sender:dkim-signature;
        bh=itePead27ra3j/U7K3uBeGeSB8HV+Vl6/9NLhtLnCRs=;
        b=TZqCs8d603W0wFXOZ/xiSguLDq58n9eGr85vBoHvWZuC5Jsh2RJY8odCS0sYeWEHUh
         uuDVI+AkmoVn9Qm7kRQAoH9lMdlYDD24EGhkrUQnkFAuq3ZYgfvmdng+jfPcL3/s3epL
         61jjSPudsnT71qYHQBwK9XPX6GGSKDbgGnGkITf0xEkxb1GvLglvqH5/RlmFbI6kWBA/
         VsfCago0Yo+sbUH6RS05PCbNMjyFiwpKQeNGUTP4BKnMLktmZ1v1gL9ccoZyWtpcbxAn
         ULk4x2NMtDDrx7fRkZwsi8h5BcPb2SMKVO3QYxJeHHoFXzgTOeIW4gJPKtILuGigRDi3
         meAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CJL06fy9;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::2b as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679382301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=itePead27ra3j/U7K3uBeGeSB8HV+Vl6/9NLhtLnCRs=;
        b=bW+MAxA/BViyircEKnTU6yFKzlTyJ31mWKDN/vpRF5mxWc2DtFQhIpV8bg0CgtmFI5
         wyZEw5aodTP/prxYgPCxn82mVpnuXxIu9giYUEpjj9MoW8yT5cbNz6BzG3xiujNJQ/gc
         /qrfbxiH2wpzbfHs43PPdRqfGiyGdjJQMk+zwSAZUUAoTCQJzbYTFAyfuT4Ojn+Up17h
         RUSjJ3L03cnJ59pS1sdmRHjW4ML87y7eVK+t9PBVd+T3B7wlej10GVehjJXxYqmyYMGg
         jfBw4AOSod8DGLLPNY90u8VGGbHPswDWTCk0nDfL0Ixd3b9kuiXyDhoCb5hSX+Hx7mKi
         5hrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679382301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=itePead27ra3j/U7K3uBeGeSB8HV+Vl6/9NLhtLnCRs=;
        b=OlwBrf874bclnOmJEW6B/x3wjrRua8CF1g2epimWLsZpYa80Cfw8/8O3qLeG9PkJhu
         rO0f0QKmnmQUpzAYkOgR9y10lPuu9yI9tJPj/AHPjuXsdkisyspcQxoRemRY1iXvEu28
         HdN/7rovLE6tJXL0gxqzdVwHVbaPaR0mheMU+VbHWbjwhgXq/o6wayNOT8x8T/RUofbu
         i3Lijro5Av37wT1soM9Fg2aX+Wm/+NN+IP0R+V6i+pM/Ed5Wp7KqSM0mE+F5ksRZ0ZmA
         GYdTfduW8rHhpzMQ+5sFAQ1aOgFDIfZTa4NkditkXOloEUqJ1CKRAS5k6y4+uLusMYsE
         rzRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUk1og4tM2fZ6arqQGQxlcITNeA9Cle6Jzn6N6QlQKYGUk73hZf
	sUBV1ATgjjtu3/diUMqA5Cg=
X-Google-Smtp-Source: AK7set8nGpwsSR0vrPaiPHd5tR/utUOoZjjuHx63BFfcdDBDysr6ebt3aK2M+lXl8KIKIBb2eyDI/Q==
X-Received: by 2002:a2e:9045:0:b0:29b:d4e5:8fd8 with SMTP id n5-20020a2e9045000000b0029bd4e58fd8mr538578ljg.5.1679382301146;
        Tue, 21 Mar 2023 00:05:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:4cf:b0:295:a3ad:f338 with SMTP id
 e15-20020a05651c04cf00b00295a3adf338ls2683074lji.4.-pod-prod-gmail; Tue, 21
 Mar 2023 00:05:00 -0700 (PDT)
X-Received: by 2002:a2e:8457:0:b0:29b:d4d8:4d8c with SMTP id u23-20020a2e8457000000b0029bd4d84d8cmr429488ljh.1.1679382299970;
        Tue, 21 Mar 2023 00:04:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679382299; cv=none;
        d=google.com; s=arc-20160816;
        b=xe0gxcqTUxdMstxeXq7pscmbNTUSs3D7UiB3joIuK6MWiXG09kjAtpr//c7aPi4uKt
         KX1UUAVdSx+P1YVTrMG24IePqO3JTjDIDgbFyI5FXRCrehi+o6LDGZqydrFoNbpbZHBt
         SmOWkUxsKNb7XcDWlDQWLdYl/tvmDdq4ppNQpbTLuDXdyPtre2qW68kah/7TVHxQJfyE
         IwdBEEhCzXax69E/44kWZMqakGpt/fErPjXKpe+0JkgG3T+BEwrFjzY9Q1/Br5UtZQKj
         4IFBNQ99AEzaBCC5C8Dkbk+n8QlTHcC5IIVXp3SDhPWS8ZWwnTfA0JJimHOzCZGRQM/B
         v7FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :mime-version:date:dkim-signature:message-id;
        bh=+McZTV1kAS70sseCFB9E43G9HETXQ3b8ag52JbteiD0=;
        b=W29L3cEhoHkzJNEFkMZaf8Jun6GXqE25Xl0stLr1nANqwdGTqAKAiKidoHFL8Dyzlq
         3WggvVIcm8vwGk1fxcAhiH1JIGA08usYxVl4EqmexxRiWaxA7tz2W1cmrBaMpFpBebw+
         Wq+GS+pJBOLzDMdBIgkhxp9lnjH04pVf/kncJ+YM/8RB0lU0qh6nrtflRprZizhagP56
         NpAGpfVQ7wSluaxtOpNILdXrBaioCEw3/b5V1/YwKz/wdUSQCEmURe7WvkamGautDEAe
         hlSMtn0bNRjfgdg6jr+cNjgYAUQvEzpnZfScyIeK5Iz9tX6NL95nQz4jhq5nuckKYDee
         S7qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CJL06fy9;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::2b as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-43.mta1.migadu.com (out-43.mta1.migadu.com. [2001:41d0:203:375::2b])
        by gmr-mx.google.com with ESMTPS id h1-20020a2ebc81000000b00299a6cef333si563230ljf.0.2023.03.21.00.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Mar 2023 00:04:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::2b as permitted sender) client-ip=2001:41d0:203:375::2b;
Message-ID: <c22e1d58-e16f-fde5-cee7-c13dedbe1656@linux.dev>
Date: Tue, 21 Mar 2023 15:04:46 +0800
MIME-Version: 1.0
Subject: Re: [PATCH] mm: kfence: fix PG_slab and memcg_data clearing
To: Peng Zhang <zhangpeng.00@bytedance.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, dvyukov@google.com, roman.gushchin@linux.dev,
 jannh@google.com, sjpark@amazon.de, akpm@linux-foundation.org,
 elver@google.com, glider@google.com, Muchun Song <songmuchun@bytedance.com>
References: <20230320030059.20189-1-songmuchun@bytedance.com>
 <974ef73e-ab4f-7b24-d070-c981654e8c22@bytedance.com>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <974ef73e-ab4f-7b24-d070-c981654e8c22@bytedance.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CJL06fy9;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:203:375::2b
 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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



On 2023/3/21 12:14, Peng Zhang wrote:
>
> =E5=9C=A8 2023/3/20 11:00, Muchun Song =E5=86=99=E9=81=93:
>> It does not reset PG_slab and memcg_data when KFENCE fails to initialize
>> kfence pool at runtime. It is reporting a "Bad page state" message when
>> kfence pool is freed to buddy. The checking of whether it is a compound
>> head page seems unnecessary sicne we already guarantee this when=20
>> allocating
>> kfence pool, removing the check to simplify the code.
>>
>> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
>> Fixes: 8f0b36497303 ("mm: kfence: fix objcgs vector allocation")
>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>> ---
>> =C2=A0 mm/kfence/core.c | 30 +++++++++++++++---------------
>> =C2=A0 1 file changed, 15 insertions(+), 15 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 79c94ee55f97..d66092dd187c 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -561,10 +561,6 @@ static unsigned long kfence_init_pool(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!i || (i % 2)=
)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 continue;
>> =C2=A0 -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Verify we do not h=
ave a compound head page. */
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (WARN_ON(compound_head(&p=
ages[i]) !=3D &pages[i]))
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn addr;
>> -
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __folio_set_slab(=
slab_folio(slab));
>> =C2=A0 #ifdef CONFIG_MEMCG
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 slab->memcg_data =
=3D (unsigned long)&kfence_metadata[i / 2 -=20
>> 1].objcg |
>> @@ -597,12 +593,26 @@ static unsigned long kfence_init_pool(void)
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Protect=
 the right redzone. */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(!kfe=
nce_protect(addr + PAGE_SIZE)))
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retu=
rn addr;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 goto=
 reset_slab;
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 addr +=3D =
2 * PAGE_SIZE;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> +
>> +reset_slab:
>> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++)=
 {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct slab *slab =3D page_s=
lab(&pages[i]);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!i || (i % 2))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cont=
inue;
>> +#ifdef CONFIG_MEMCG
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 slab->memcg_data =3D 0;
>> +#endif
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __folio_clear_slab(slab_foli=
o(slab));
>> +=C2=A0=C2=A0=C2=A0 }
> Can this loop be simplified to this?
>
> =C2=A0=C2=A0=C2=A0=C2=A0for (i =3D 2; i < KFENCE_POOL_SIZE / PAGE_SIZE; i=
+=3D2) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct slab *slab =3D page_sla=
b(&pages[i]);
> #ifdef CONFIG_MEMCG
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 slab->memcg_data =3D 0;
> #endif
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __folio_clear_slab(slab_folio(=
slab));
> =C2=A0=C2=A0=C2=A0=C2=A0}
>

It's a good simplification. The loop setting Pg_slab before this
also can be simplified in the same way. However, I choose a
consistent way to fix this bug. I'd like to send a separate
simplification patch to simplify both two loops instead of
in a bugfix patch.

Thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c22e1d58-e16f-fde5-cee7-c13dedbe1656%40linux.dev.
