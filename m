Return-Path: <kasan-dev+bncBAABBTXVYSHQMGQECH2BJRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 765F349C95A
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 13:13:04 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id ga20-20020a17090b039400b001b536800e04sf10025258pjb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 04:13:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643199183; cv=pass;
        d=google.com; s=arc-20160816;
        b=jTIN8gYX5ep6rwl1oYkpUtOlO7vXtYB50b897UiBtRtzAd4Lgy91lZivbmIsKWFp6g
         FVe7xZMs/NJnQeEq2JAy7k/Um7tlgZfSBVeyiVwq+cG0pkHW3JZeNcXOQcv4z3gtcmDb
         E6wLGk0QHbBn8opeIoh3vtA6rxVNE0A7TDzze9nimTODBVyJ9g3WGSXznxTuG5cNy8uc
         inUNzMxDxLveau7pFhXJgC+ZupFUBDu6Fxm12SmQP0gAgPnyfGu9Eo9nwfEi1DKPVqDV
         S6L8+LomijfNgcPFbTMbYxhrWU3PZ/ovpxb60lNolslTDkZa9q5c8tHfrXxoAkxVd5yi
         dtYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=CjrP/iOS4r1+gVH/6Ac+i3amiFIvT2S2022FHVl1+5Y=;
        b=i34GDP3EC9ezGrtesnPMvtCafBmIUnB+q2zAqefiVzT4eIau5yWdAtcY3dakRwn7Vy
         JkkPR5tS9JOqxphI9jOQZr5PfvSCZ2IQebqKhAK22OoyEzyPmZeJp3gWvAYeDq9MVz6v
         ON2ucsZKuYWvdRaEI5sC6BQXdTlGg49LlZHv+wsbTw+xu9EgNTMLKOz7GC4qHzKBOWIj
         o3iU0UCga/S1XwGEAS+JfkGXdy1BjHl/lEIwLArHnyaC1IQk8cOOO8BTN3cO/sM3mAEf
         /GmGEOFGmv6SKlAQViGVZqR5nD0gM7r9OOAABthpw1HS0uUvfdkIxTdHOErJN9EosYfv
         Jgnw==
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
        bh=CjrP/iOS4r1+gVH/6Ac+i3amiFIvT2S2022FHVl1+5Y=;
        b=S98SxDLv+ziYymzOD42Bkw0lQ38Cyc9Sabet+oE/olEcFo+oovdIavsvW4MEJ2tPTr
         cTsTTBOhIe8UkTtFPaMK8nlp28Dj7/ZJUnp5/4Upqiyte5rLz7G+qBooBv2w0htN2QkT
         XL743ANTxzGJLZU3rCzqsjBsds1ELmpMy3PqqvYn7gplr1KvQ4JMZvpW+di6/v1vFXDo
         o0StgYX0+UQ0dmsj5k+tn4dF+mtEb8WPklnN8UQd8egnK1JeQJ5WjfJP/FhQpnz4EPN+
         OxRV/7jjxc92ovQV/wvt/efBNq+pS3r1lB1hLC1CODVcu3zbvYNUEYWqjJiCOX5wNVF8
         HGGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CjrP/iOS4r1+gVH/6Ac+i3amiFIvT2S2022FHVl1+5Y=;
        b=jiRxF+AcVtXTZRh9m0WjPaL9GgujofVP8xsEpVXYpv2xV37lbsceaiaE29FWRqZRk6
         0cOw7wdXRPAyv4C56wEC+EbLqnUFdTxq8q5+k7GaaxWsz5mN+xnG3X7u3G+GAz5uMYME
         c8DkwWFZrxFycBc5gg5i8H5n/aNYvBpANEZXq/zcHO8MGyIxsXjT1E+M+mVOpmLFoX25
         HDi2s24OfGjSVS4mr9wyCtLqC6QsXc83dTBZ3bBlFgJdaTe2lS735dRs20uoov9Z8lB4
         7Dgho0torO9RISptFs06foU4d6VZkuDrv5NjFtyzOtponDVkVR3RVEmFeli7Mc0bj/wz
         aKqQ==
X-Gm-Message-State: AOAM531qNUpoIRaOu+iHoanuTyKWCZ4R9vGymi+obCrbW3usiIdf6Kye
	QwASuKzNf0uWQhL+ghfvBHQ=
X-Google-Smtp-Source: ABdhPJw7hCKTCwvrv0Ta4KH+TG0VCWQvJ/nBVP768sZPO4eL6cE5GmmcgogwbHRHQhoNaamYc90eMw==
X-Received: by 2002:a17:90a:fa88:: with SMTP id cu8mr8651081pjb.98.1643199182965;
        Wed, 26 Jan 2022 04:13:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c408:: with SMTP id k8ls1348717plk.6.gmail; Wed, 26
 Jan 2022 04:13:02 -0800 (PST)
X-Received: by 2002:a17:902:6b02:b0:149:7c20:c15b with SMTP id o2-20020a1709026b0200b001497c20c15bmr22634734plk.173.1643199182444;
        Wed, 26 Jan 2022 04:13:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643199182; cv=none;
        d=google.com; s=arc-20160816;
        b=awFoj3Jvt8JftEVXfZ08/eKCItVx4/cPkidICE0eYVEwY0vs8LWEzy4fEofy3o5qSF
         AklLgkWkkcukbg1O4WpQ7nQG4zZx4Cnhs2qlO25mZeeJggsOIskGzIVunneOmxzMvsVX
         Qz0jQDfbywwTxBhkp2EKjW7OZ/Yk7B2uFUPhlz+Yk9q3KyaW7EF0FLKvqLTN5cGlOjnL
         3MPyb+CYWYhDssztap2260zKRRYJ+P10cfmba2Wvfjcldv6XkHaHG67X9rn3ImXYF1iz
         SmjEpBix1SmKQU3/7e178D0Lv4q6iCoHHG+31wpjXipaLnYg3pqztIw4QBRhoL5lcVMQ
         jGAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id;
        bh=/ZJiCkVfmAhuE8snrz/rfNQA/msXpNKY3Ddv0Gmdf5w=;
        b=wF4wc3acGcUszkSQ50BeeaIKtphbR0qAyH4qrCerGmcHIGlmxUd7dKF6q95ZNc4wki
         4HRooi5rur1OmTLvB8buqhDb4O4wWNygQUKpzUIwKFFylfQ9nxpI04MMqaWI1HACsr4S
         NUO4/F9nKCqHf+5+N3kPyVijwKOOc0gSpkuINPRTavoboQy5Zkst6flzYOM9mZGYd8FD
         L8rJHyCJVYBiCfXV3rerImMwWrbBD39fUt4ibhp0NPJS/GGKtwyZDR7YDZsFgI1hGlOL
         IRacydGokDxmOZRi3m3w9VwnwOVMbAqmepM+QGafyDb32C1kN6cv2NUO68SlPa0kor+8
         DvUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id q7si109681pfu.6.2022.01.26.04.13.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jan 2022 04:13:02 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100008.china.huawei.com (unknown [172.30.72.53])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4JkMvj3dtXz1FD5B;
	Wed, 26 Jan 2022 20:09:05 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100008.china.huawei.com (7.221.188.57) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 26 Jan 2022 20:12:59 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 26 Jan 2022 20:12:58 +0800
Content-Type: multipart/alternative;
	boundary="------------2sE5CklAQW5Skk0e821jJkdX"
Message-ID: <4bb5e98f-83fe-4406-6a50-f3626af8cebb@huawei.com>
Date: Wed, 26 Jan 2022 20:12:58 +0800
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
 <261a5287-af0d-424e-d209-db887d952a74@huawei.com>
 <CANpmjNNc6F7tRVn=UqLaW0WAgTr67XFm=CUu5X2D0Xbt3nKXwA@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNc6F7tRVn=UqLaW0WAgTr67XFm=CUu5X2D0Xbt3nKXwA@mail.gmail.com>
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
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

--------------2sE5CklAQW5Skk0e821jJkdX
Content-Type: text/plain; charset="UTF-8"; format=flowed


On 2022/1/24 20:21, Marco Elver wrote:
> On Mon, 24 Jan 2022 at 13:19, liupeng (DM)<liupeng256@huawei.com>  wrote:
> [...]
>> When KFENCE pool size can be adjusted by boot parameters(assumption),
>> automatically test and train KFENCE may be useful. So far, exporting
>> kfence.sample_interval is not necessary.
> I'm not opposed to the patch (I've also run into this issue, but not
> too frequently) - feel free to just send it with EXPORT_SYMBOL_GPL.
>
> Thanks,
> -- Marco
> .

Good, I will send a revised patch latter.

Thanks,
-- Peng Liu
.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bb5e98f-83fe-4406-6a50-f3626af8cebb%40huawei.com.

--------------2sE5CklAQW5Skk0e821jJkdX
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
    <div class=3D"moz-cite-prefix">On 2022/1/24 20:21, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNc6F7tRVn=3DUqLaW0WAgTr67XFm=3DCUu5X2D0Xbt3nKXwA@mail.gm=
ail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, 24 Jan 2022 at 13:19, =
liupeng (DM) <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:liupeng256@h=
uawei.com">&lt;liupeng256@huawei.com&gt;</a> wrote:
[...]
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">When KFENCE pool size can be=
 adjusted by boot parameters(assumption),
automatically test and train KFENCE may be useful. So far, exporting
kfence.sample_interval is not necessary.
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
I'm not opposed to the patch (I've also run into this issue, but not
too frequently) - feel free to just send it with EXPORT_SYMBOL_GPL.

Thanks,
-- Marco
.</pre>
    </blockquote>
    <pre>Good, I will send a revised patch latter.

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
om/d/msgid/kasan-dev/4bb5e98f-83fe-4406-6a50-f3626af8cebb%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/4bb5e98f-83fe-4406-6a50-f3626af8cebb%40huawei.com</a>.<br />

--------------2sE5CklAQW5Skk0e821jJkdX--
