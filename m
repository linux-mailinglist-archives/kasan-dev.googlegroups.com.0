Return-Path: <kasan-dev+bncBAABBZX3ROIQMGQENXOVBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 11E9F4CE338
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 07:06:32 +0100 (CET)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-2dc1ce31261sf83280917b3.6
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Mar 2022 22:06:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646460391; cv=pass;
        d=google.com; s=arc-20160816;
        b=gpbvv8FX8sS+MuXtU0BEzJgXji0h1VR5vWN6YUxyyXf0I+tbkLHB+2xD3yrWbR5Aoa
         P0xngS2gEvV+MAmUdbkrtmorL71z7uH/gKSB6xgxDwU1M4oqD/gTtojBVwM/tULCl2/K
         rINZcYSyJ9M8BG3QdCddZm4bqlExoyWdrMM9RmmEOMdKnqtkQFyqfSn0oPmjmfFPMidJ
         TQoCUvA+ks4mqjL5cvW1k0h3iJJYYAHj30xy9NYOqUHD1na5UhYjtkJQxzz+Tl3Ag0kb
         BZT14HzcsTUCXViN9FtfpoSI2968xbEKs0z9jzApiw6BLlKCS03zHPPGIV1Su/stsiNR
         MYIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=ARSLdztuW6Fg+OpY0OZSib9RVFZnB3bqucCBgukNkrI=;
        b=VL6Wv62qT52CaqpeEla9MmDqYn4Esx2Tl9Ep2V9E96oChXKVJsWSOKnUIr/bqhO8cP
         +zDdoLuIzDXJb9sja6BDzQv1SPoACzmzw5nUZxLZnfq5XJ6KPuMu072HM5W684M5KhBr
         3SYy8TuYQjb7at3foeF4qk5xJUuBpR0ffEjJ1UZ6K2uZE75ktBuIE5DXx9Vmh2Pe1XB4
         U78EX0NWOMSOrYKyYqPFC6Iz8sJLA+nW56ShtKQ/gyVE8lc3cXgCFEMXUnezWmEIKfDh
         M11vk9jsZw2NwITqncJxMuROc2ou9++rFD8q+3iIKCSBb/glf9jYE4TFzwWPhGCcOjdN
         4q+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ARSLdztuW6Fg+OpY0OZSib9RVFZnB3bqucCBgukNkrI=;
        b=OlveLVHtiTmN3gviMGbKzKQORGRebUXvhOBmat2NDuSkMBAZxbNFVNmm50z2CgJGev
         8K7emTpyblgeHk5bak9obqJGbsFwcaSz2fLm6t5pPq8tjgAvLJS+boWzT96tM+C1LSFS
         b9JDxY7FEs5LruGv1JsBIZrTAwr34d9W9j9ok/6g32bGZ/HZAQn++5hufWa+z+o/44YX
         NBt4GhBxFq6snKn2LFUqDBdlBBbl1m1muNE4LTgAANZp0rs87tgwBRpqiEk0gPVPs2zE
         xE49QmwuInzM2ClGzIlHj7H3L0A7pU2julfBPAELESlviTshzxrYIqeCFuCcY/hnIHMK
         ZOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:from:to:cc:references:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ARSLdztuW6Fg+OpY0OZSib9RVFZnB3bqucCBgukNkrI=;
        b=HEv+QPxvtMT+5a/yd7Mr1OhUMJ7lpo48RY0D+/uFUvqD9hLPlBg7Hi5Q1jbmFQebhP
         ApbDIO1BUWAdPz8NrTvpld91iJexL2A2AJXWd7wMSA8AV1vUgstxGAdgnFlJjHK4X48/
         OUxsK38gNGkJRvTiJcEL/Gebdbi8pjkrquw7OkDe0H3w3juMx0l/LxZC/EvW9iRye+87
         234renWeHj7ZLoOObPr4aheZIMOPnINVuFPKXqhg8A4EcS2ea0d4fLF7m5dbd+bVm001
         eAssp4L7B/o63K0N9139PvrV96ZjKiqOIcnkGG7fqiEFN8k0DSTvVeAR02SjChW+/z+i
         9KNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IG76YI8m3D7t+Ii2KKxsRyhJJPqMB7aqn/pmQjL3SvnJ7a5J1
	oIJYXjET4fUpP/FCxsmiSVA=
X-Google-Smtp-Source: ABdhPJxO13hkk37a5JXJuURWZIansJZfgmgiiUuxBTG4MYg3QUDZOE7rhU+UfxFHIUlyhcl330CUMw==
X-Received: by 2002:a5b:20f:0:b0:628:6a2b:ee2c with SMTP id z15-20020a5b020f000000b006286a2bee2cmr1576169ybl.175.1646460390831;
        Fri, 04 Mar 2022 22:06:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:50c:0:b0:628:e822:4ec1 with SMTP id 12-20020a25050c000000b00628e8224ec1ls2373491ybf.1.gmail;
 Fri, 04 Mar 2022 22:06:30 -0800 (PST)
X-Received: by 2002:a25:4945:0:b0:61d:546d:aedb with SMTP id w66-20020a254945000000b0061d546daedbmr1547399yba.147.1646460390399;
        Fri, 04 Mar 2022 22:06:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646460390; cv=none;
        d=google.com; s=arc-20160816;
        b=QqdZ4HJdW+cUxzHXzjzV91ppRHA03ghRQC55GdF+pP9eEsEgJNqoddMFo+4yb7p1RQ
         ZzOCVmLlJ9aLSAYXVIuNZyWfLWA1vdIaj8wMJwesSW3rGFFyUD7pes8/Afc/PpWbqyXw
         2xx5Q4lLxCKCz0xJHsgBU66h5AMzCQsgcWd5dCM1/+d1mmFW5/z0mwwaFXqhQiMDg/hm
         PEPwoKNuxKeM7mVUsJ9vT4tDB9jbmMrBQzwB2LrEt9d4hOx/7EGe38Bt1rtUT5uaYvvT
         4aZYJknPQfYl4yDr7Gnc+fNtQgnz35EPA2jDKnsB7ioGAmoJdo8I5twkj/5xyX54kPky
         hXHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=kgv4chUDyoO8XYZ6izqZ1YrjHCo9smcDeEMtkLpP6J0=;
        b=UbnREUNILijx3ZDRQV3QvAWTDoCEgepgAjbiNeezskJsGdQ58LhRtRYhwT91BGfBB7
         zECJ/MY3GLnf2W7U4/DAv4aTH/QheMQz3pRbfInDcOBVUnooP1cI7vr7HD4aVtu2MAQ0
         G+2XJL5IIylRkUAvo6OCJSKAe9UYTk2vjdmgz92lG5GvWIDABKX4GEf/3HwnymGq4e40
         HDkAmmVA/HsltRuotlFnG2HRyV6V1CSYzl/4dxSXxOnuzbQrXVOU0xVhTeZiJq0IyEV8
         p+8Cfr5K42enBGECOED4oNoN4qvMCGkLJMvVGLR3gzUpbjhs26OJMbcKblPqS92ZO+mp
         TAyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-133.freemail.mail.aliyun.com (out30-133.freemail.mail.aliyun.com. [115.124.30.133])
        by gmr-mx.google.com with ESMTPS id m129-20020a257187000000b00615fdd16445si494313ybc.2.2022.03.04.22.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Mar 2022 22:06:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as permitted sender) client-ip=115.124.30.133;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R651e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04394;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6FfDh8_1646460384;
Received: from 192.168.0.205(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6FfDh8_1646460384)
          by smtp.aliyun-inc.com(127.0.0.1);
          Sat, 05 Mar 2022 14:06:25 +0800
Message-ID: <a293da49-b62e-8ad1-5dde-9dcbdbcf475e@linux.alibaba.com>
Date: Sat, 5 Mar 2022 14:06:23 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.6.1
Subject: Re: [RFC PATCH 1/2] kfence: Allow re-enabling KFENCE after system
 startup
Content-Language: en-US
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
 <20220303031505.28495-2-dtcccc@linux.alibaba.com>
 <CANpmjNOOkg=OUmgwdcRus2gdPXT41Y7GkFrgzuBv+o8KHKXyEA@mail.gmail.com>
 <ea8d18d3-b3bf-dd21-2d79-a54fe4cf5bc4@linux.alibaba.com>
In-Reply-To: <ea8d18d3-b3bf-dd21-2d79-a54fe4cf5bc4@linux.alibaba.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.133 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

On 2022/3/5 13:26, Tianchen Ding wrote:
> On 2022/3/5 02:13, Marco Elver wrote:
>> On Thu, 3 Mar 2022 at 04:15, Tianchen Ding <dtcccc@linux.alibaba.com>=20
>> wrote:
>>>
>>> If once KFENCE is disabled by:
>>> echo 0 > /sys/module/kfence/parameters/sample_interval
>>> KFENCE could never be re-enabled until next rebooting.
>>>
>>> Allow re-enabling it by writing a positive num to sample_interval.
>>>
>>> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
>>
>> The only problem I see with this is if KFENCE was disabled because of
>> a KFENCE_WARN_ON(). See below.
>>
>>> ---
>>> =C2=A0 mm/kfence/core.c | 16 ++++++++++++++--
>>> =C2=A0 1 file changed, 14 insertions(+), 2 deletions(-)
>>>
>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>>> index 13128fa13062..19eb123c0bba 100644
>>> --- a/mm/kfence/core.c
>>> +++ b/mm/kfence/core.c
>>> @@ -55,6 +55,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /*=20
>>> Export for test modules. */
>>> =C2=A0 #endif
>>> =C2=A0 #define MODULE_PARAM_PREFIX "kfence."
>>>
>>> +static int kfence_enable_late(void);
>>> =C2=A0 static int param_set_sample_interval(const char *val, const stru=
ct=20
>>> kernel_param *kp)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long num;
>>> @@ -65,10 +66,11 @@ static int param_set_sample_interval(const char=20
>>> *val, const struct kernel_param
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!num) /* Using 0 t=
o indicate KFENCE is disabled. */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 WRITE_ONCE(kfence_enabled, false);
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else if (!READ_ONCE(kfence_enable=
d) && system_state !=3D=20
>>> SYSTEM_BOOTING)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return -EINVAL; /* Cannot (re-)enable KFENCE=20
>>> on-the-fly. */
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *((unsigned long *)kp-=
>arg) =3D num;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (num && !READ_ONCE(kfence_enab=
led) && system_state !=3D=20
>>> SYSTEM_BOOTING)
>>
>> Should probably have an 'old_sample_interval =3D *((unsigned long
>> *)kp->arg)' somewhere before, and add a '&& !old_sample_interval',
>> because if old_sample_interval!=3D0 then KFENCE was disabled due to a
>> KFENCE_WARN_ON(). Also in this case, it should return -EINVAL. So you
>> want a flow like this:
>>
>> old_sample_interval =3D ...;
>> ...
>> if (num && !READ_ONCE(kfence_enabled) && system_state !=3D SYSTEM_BOOTIN=
G)
>> =C2=A0=C2=A0 return old_sample_interval ? -EINVAL : kfence_enable_late()=
;
>> ...
>>
>=20
> Because sample_interval will used by delayed_work, we must put setting=20
> sample_interval before enabling KFENCE.
> So the order would be:
>=20
> old_sample_interval =3D sample_interval;
> sample_interval =3D num;
> if (...) kfence_enable_late();
>=20
> This may be bypassed after KFENCE_WARN_ON() happens, if we first write=20
> 0, and then write 100 to it.
>=20
> How about this one:
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0if (ret < 0)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ret;
>=20
> +=C2=A0=C2=A0=C2=A0 /* Cannot set sample_interval after KFENCE_WARN_ON().=
 */
> +=C2=A0=C2=A0=C2=A0 if (unlikely(*((unsigned long *)kp->arg) &&=20
> !READ_ONCE(kfence_enabled)))
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
> +
>  =C2=A0=C2=A0=C2=A0=C2=A0if (!num) /* Using 0 to indicate KFENCE is disab=
led. */
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 WRITE_ONCE(kfence_enabled, fa=
lse);
>=20

Hmm...
I found KFENCE_WARN_ON() may be called when sample_interval=3D=3D0. (e.g.,=
=20
kfence_guarded_free())
So it's better to add a bool.

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index ae69b2a113a4..c729be0207e8 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -38,14 +38,17 @@
  #define KFENCE_WARN_ON(cond)=20
          \
  	({                                                                     \
  		const bool __cond =3D WARN_ON(cond);                             \
-		if (unlikely(__cond))                                          \
+		if (unlikely(__cond)) {                                        \
  			WRITE_ONCE(kfence_enabled, false);                     \
+			disabled_by_warn =3D true;                               \
+		}                                                              \
  		__cond;                                                        \
  	})

  /* =3D=3D=3D Data=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D */

  static bool kfence_enabled __read_mostly;
+static bool disabled_by_warn __read_mostly;

  unsigned long kfence_sample_interval __read_mostly =3D=20
CONFIG_KFENCE_SAMPLE_INTERVAL;
  EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
@@ -70,7 +73,7 @@ static int param_set_sample_interval(const char *val,=20
const struct kernel_param
  	*((unsigned long *)kp->arg) =3D num;

  	if (num && !READ_ONCE(kfence_enabled) && system_state !=3D SYSTEM_BOOTIN=
G)
-		return kfence_enable_late();
+		return disabled_by_warn ? -EINVAL : kfence_enable_late();
  	return 0;
  }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a293da49-b62e-8ad1-5dde-9dcbdbcf475e%40linux.alibaba.com.
