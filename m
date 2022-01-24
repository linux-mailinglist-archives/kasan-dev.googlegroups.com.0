Return-Path: <kasan-dev+bncBAABBNVSXKHQMGQEIJWIAEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 73880497F24
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 13:19:03 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id ay18-20020a17090b031200b001b53c85761asf6999130pjb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 04:19:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643026742; cv=pass;
        d=google.com; s=arc-20160816;
        b=I608+cqTVVErypSUsg45IoTQRkjxXuv4hLWx7AGY56UNSzOlbvm9gCbI2ksNH3jmnd
         BQLdzT8h5WmCGwsCwEs4scVN4N6o8pz6NsGXXT+VYd3GqhohbWoaMuiCiZ0WZvwufJd3
         r/hM8+ucGQ0P5NyGm/EzA1DxuOwzgd0ZNNp3vaqt5yZ5nD9SR2VCMGUnx8W2aAHsJ6Ud
         a4tUern5BGCXoyC6PAI+YWLp6HYq85I56b+AR6HgUW4/GIEMUSnSXT30b9aWuuAkwlhP
         HXvyBIt6QD9KOYeYH2Xm7wVVzmuCEUeKB1EdIGZ0uhxFgRB5c9asQRoEbKJih+CR/Uf/
         vpXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Kvgbp9inhe5LC0S1C4sgnWKxzAX1HpCsvv4Rtg4mxkA=;
        b=wWLXEjI8jGaHDuzBaktbAoEFSHbRhr+bUu+Dz3bEogAyXvsfBZQb7tQthJ6PZ9l/Pv
         O4ZrRUwLLm1g+KD+IhhI72nr8VsZb5+dqdXxFmvpb/mS4JDYE0Rv7NEt+QPycBRnMKBG
         5zlrPGk+dDgr5MKbOsmskjEZEOoc+bS1dnuzFhd+8wmrxv054MMHG34UwXHHrv9fSBye
         Qe3uskj0O6/imTCCqUPTJtYYoS0rH7aLtr0BSRjjMiwcZpGhs/56AGVu5sCt32OKMySO
         MYIsft3VE5KF8LVyH7rn/6llYyko7GsnSaYdwnRcsjye05EV+RJBs5v0mK1+j3geAIv9
         Fnxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Kvgbp9inhe5LC0S1C4sgnWKxzAX1HpCsvv4Rtg4mxkA=;
        b=WIdVa9oLwAo0P4iVwTTUu/N5U3P4nKUOjAB7TwhxPdgzs53Je4EmqspSNnXV+o3sfC
         XP6WmKmLJ5TEtmw5MBvEKQDS3QnS4ah4N/vDWa3ij+Af2410/iEyQLNX+oCBKP9yo9Z2
         H/mQqSkYKqT4JBHQlBSqo1bp2zUy7BTWWDxB+bHSYhkE1n2HZK59DRn87oWQrtd+nUbE
         gY2n3Bn/NEnQuhoB393U94/giF/HbtqXRwFKn1wCiiD78VIVy6C91fILK/9uHE0MtKJ5
         Cz5UFgfy09O+DEKNen8hVorqGGHLU2JbBNOTXDBw5LwixPi4Ke54SrNNGUzPBzomoC4O
         zZiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kvgbp9inhe5LC0S1C4sgnWKxzAX1HpCsvv4Rtg4mxkA=;
        b=wiVxZem3PRfGMOFxn+NjP6cdgfpshcRR4fkY8LwD/1/J0P8CpGbiRwxJnmSc93eC5k
         bcnQOiCycoZUQsxV4GZO+FhnKTDPhu4pxRtvxyfsEVN5SvMTEkUMRTNZaFKRvYDvDzzI
         D0uAWxY3h9SjCo18/vqfDVKyREYGS4kcFR8Id6R4MgRc+UzesbOgXP053pjN0qA6IpAF
         4drjDDsGsKm2a2JS1tOLcJEl56t4yWpQht2uq/kL8u9v4a07TiXxD5ZyJwCTcY2g2THT
         jLuzHiYLBmatFfnDi4VFyj5mn/5ukpcMzOMoSryYqwKiHhTejvkqEuvR3AHNA2CWyz2C
         iksQ==
X-Gm-Message-State: AOAM5309evPfx3BlK1xWaALovHl4qgXLJTdA9EufHNc8JKoTxVjIUcH3
	Xw20L6ls/W/y0xf0CbwrvZw=
X-Google-Smtp-Source: ABdhPJxJiFA6JJsDTUNn4kyYGcqmhxMb/zK3/JkK7qlVpYl6E6UEBNo5CC+yhOoq2T3voRYx6gxETQ==
X-Received: by 2002:a17:90a:940e:: with SMTP id r14mr1653975pjo.17.1643026742101;
        Mon, 24 Jan 2022 04:19:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:330f:: with SMTP id z15ls4966160pgz.10.gmail; Mon, 24
 Jan 2022 04:19:01 -0800 (PST)
X-Received: by 2002:a65:5b84:: with SMTP id i4mr11678660pgr.59.1643026741600;
        Mon, 24 Jan 2022 04:19:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643026741; cv=none;
        d=google.com; s=arc-20160816;
        b=lMnvQv6l11E8NM40cZnCj4c0UfTrCvxkjSnpoo0HWcuBqHzWlkjpC8He3XONYdNyNh
         QyuKOfW44NCIk8Nv0PkjFFXe1IM9VdPW8aYRtms+WBKtqEbNnrGa+cqy5MESKk2IqG0u
         iY0SKfhpq3vpdCCdoC8snXp25tHmuHOioITkIFvyZ5PwrEKjOSsoqPPcFjutm4RpyW0B
         r2yRwdZAZXAJCzOnc5SVpSUzb6p/gjO4mfdLJ9FtXUaQ/+pBhN2efXZwt+ZOsW5GOVhI
         FdCwpLlK9chzYwJc20j3r7W68N3Z1mKjePVlItxH19qKU4M6w2NZf5iSQvzHJjkmnHPv
         +0xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id;
        bh=MBZfpGMpiJjQqC55tnU0TJ8oTC6m2hRrAE32s0oHTf0=;
        b=gs8R/LONRDWUiKIECgcKNE4RfvviWBzeO/fhzrS2Lkr9PwSPsC00avHkI+JJHZ1ikT
         ct1yohy+gg/NEhtg7OJSXJqgh2Ej9MNbA/DWLz/sPgaOYG2X7/dT2GHDJkxHJE15brMk
         SYTIB/zXbyelG6K0YkZ99B1cWRfy7/gdUFGJc6l8rqVNiS0HDu+AN6UUj+ZjuFk0+3OZ
         Sg5n5M+qIiHajd3BAY6nMQD6Nhyg1ilsFF4GUlcutjHN45KigBNjzS4azr/bPjX4O97w
         237v5T/Csym85FVRAXiw2NspeM7xDE9IUJsPP1R0bJHprz2PpIrtIMsFwmUMvgD8z3NQ
         xRrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id d23si468539pjw.0.2022.01.24.04.19.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jan 2022 04:19:01 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100026.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4Jj87b3ysNz1FCXK;
	Mon, 24 Jan 2022 20:15:07 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100026.china.huawei.com (7.221.188.60) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 20:18:59 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Mon, 24 Jan 2022 20:18:58 +0800
Content-Type: multipart/alternative;
	boundary="------------LBsQNxmvK3PJv5A2kezHXevh"
Message-ID: <261a5287-af0d-424e-d209-db887d952a74@huawei.com>
Date: Mon, 24 Jan 2022 20:18:57 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH RFC 3/3] kfence: Make test case compatible with run time
 set sample interval
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
	<sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linaro-mm-sig@lists.linaro.org>, <linux-mm@kvack.org>
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-4-liupeng256@huawei.com>
 <CANpmjNNYG=izN12sqaB3dYbGmM=2yQ8gK=8_BMHkuoaKWMmYPw@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNYG=izN12sqaB3dYbGmM=2yQ8gK=8_BMHkuoaKWMmYPw@mail.gmail.com>
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

--------------LBsQNxmvK3PJv5A2kezHXevh
Content-Type: text/plain; charset="UTF-8"; format=flowed


On 2022/1/24 16:25, Marco Elver wrote:
> On Mon, 24 Jan 2022 at 03:37, 'Peng Liu' via kasan-dev
> <kasan-dev@googlegroups.com>  wrote:
>> The parameter kfence_sample_interval can be set via boot parameter
>> and late shell command. However, KFENCE test case just use compile
>> time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE test case
>> not run as user desired. This patch will make KFENCE test case
>> compatible with run-time-set sample interval.
>>
>> Signed-off-by: Peng Liu<liupeng256@huawei.com>
>> ---
>>   include/linux/kfence.h  | 2 ++
>>   mm/kfence/core.c        | 3 ++-
>>   mm/kfence/kfence_test.c | 8 ++++----
>>   3 files changed, 8 insertions(+), 5 deletions(-)
>>
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index bf91b76b87ee..0fc913a7f017 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -19,6 +19,8 @@
>>
>>   extern bool kfence_enabled;
>>   extern unsigned long kfence_num_objects;
>> +extern unsigned long kfence_sample_interval;
>> +
>>   /*
>>    * We allocate an even number of pages, as it simplifies calculations to map
>>    * address to metadata indices; effectively, the very first page serves as an
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 2301923182b8..e2fcae34cc84 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -50,7 +50,8 @@
>>
>>   bool kfence_enabled __read_mostly;
>>
>> -static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>> +unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>> +EXPORT_SYMBOL(kfence_sample_interval); /* Export for test modules. */
> While it would make some situations more convenient, I've wanted to
> avoid exporting a new symbol just for the test. And in most cases it
> only makes sense to run the test on a custom debug kernel.
>
> Why do you need this?

To automatically do more tests.

>
> Should you really need this, I suggest at least using
> EXPORT_SYMBOL_GPL. Should you want it, you can resend this patch
> standalone detached from the rest.
>
> Thanks,
> -- Marco
> .

When KFENCE pool size can be adjusted by boot parameters(assumption),
automatically test and train KFENCE may be useful. So far, exporting
kfence.sample_interval is not necessary.

Thanks,
-- Peng Liu
.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/261a5287-af0d-424e-d209-db887d952a74%40huawei.com.

--------------LBsQNxmvK3PJv5A2kezHXevh
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body>
    <p><br>
    </p>
    <div class=3D"moz-cite-prefix">On 2022/1/24 16:25, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNYG=3DizN12sqaB3dYbGmM=3D2yQ8gK=3D8_BMHkuoaKWMmYPw@mail.=
gmail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, 24 Jan 2022 at 03:37, =
'Peng Liu' via kasan-dev
<a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:kasan-dev@googlegroups.co=
m">&lt;kasan-dev@googlegroups.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">
The parameter kfence_sample_interval can be set via boot parameter
and late shell command. However, KFENCE test case just use compile
time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE test case
not run as user desired. This patch will make KFENCE test case
compatible with run-time-set sample interval.

Signed-off-by: Peng Liu <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:l=
iupeng256@huawei.com">&lt;liupeng256@huawei.com&gt;</a>
---
 include/linux/kfence.h  | 2 ++
 mm/kfence/core.c        | 3 ++-
 mm/kfence/kfence_test.c | 8 ++++----
 3 files changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index bf91b76b87ee..0fc913a7f017 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -19,6 +19,8 @@

 extern bool kfence_enabled;
 extern unsigned long kfence_num_objects;
+extern unsigned long kfence_sample_interval;
+
 /*
  * We allocate an even number of pages, as it simplifies calculations to m=
ap
  * address to metadata indices; effectively, the very first page serves as=
 an
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 2301923182b8..e2fcae34cc84 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -50,7 +50,8 @@

 bool kfence_enabled __read_mostly;

-static unsigned long kfence_sample_interval __read_mostly =3D CONFIG_KFENC=
E_SAMPLE_INTERVAL;
+unsigned long kfence_sample_interval __read_mostly =3D CONFIG_KFENCE_SAMPL=
E_INTERVAL;
+EXPORT_SYMBOL(kfence_sample_interval); /* Export for test modules. */
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
While it would make some situations more convenient, I've wanted to
avoid exporting a new symbol just for the test. And in most cases it
only makes sense to run the test on a custom debug kernel.

Why do you need this?</pre>
    </blockquote>
    <pre>To automatically do more tests.
</pre>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNYG=3DizN12sqaB3dYbGmM=3D2yQ8gK=3D8_BMHkuoaKWMmYPw@mail.=
gmail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">

Should you really need this, I suggest at least using
EXPORT_SYMBOL_GPL. Should you want it, you can resend this patch
standalone detached from the rest.

Thanks,
-- Marco
.</pre>
    </blockquote>
    <pre>When KFENCE pool size can be adjusted by boot parameters(assumptio=
n),
automatically test and train KFENCE may be useful. So far, exporting
kfence.sample_interval is not necessary.=20

Thanks,
-- Peng Liu
.

</pre>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/261a5287-af0d-424e-d209-db887d952a74%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/261a5287-af0d-424e-d209-db887d952a74%40huawei.com</a>.<br />

--------------LBsQNxmvK3PJv5A2kezHXevh--
