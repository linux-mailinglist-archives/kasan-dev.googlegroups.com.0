Return-Path: <kasan-dev+bncBAABBSWZSWIQMGQE3263ZDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E8654CEF96
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 03:24:12 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id 207-20020a3706d8000000b0067b322bef9esf621824qkg.3
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 18:24:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646619851; cv=pass;
        d=google.com; s=arc-20160816;
        b=nYox/peFIAbBfjmOuWMjfh/lYr4hj+1rET0VEu/CSOBUtERKE9qROlaepR192LnF46
         9HlPZ+rP8+98A07zFeqEXu31yCoKHCV5KZYRQqOwMJ/irVGCkQ43sjJGzGMOozP0UlX5
         mIoT/saWn/UBJMbEQjUcJIarG35/jChTcoWZgDQjNBsQ/RFG4tOtr0kMszUm6RhnKYaV
         OaABj+Xo3dA56FbnVDPNfTTaAab/AJKxlDJNTqdhxxKSm8Ei+38N1ACnhBYDNiPx8wvp
         Ykah0C7WK/bUbubQyE4HCegDGZRpLzxITBC1pT53NCA0PnGht7At6O/MyRsTXzXjtfGU
         y3YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=lrSLQluwqMG7c1ABFoODCztJzTXpIYLB/QNOGjCmahs=;
        b=uxribN6DFpYHy547fDoZhMRzOy2IxXBDigCv+umxAf1wLMTq44iLpZTJ2iWXLskDmu
         VnG7XRJ5qKqUNHpDKhf3OpVLTah9bCvxyyx5mDAfZVFEHMVtEnuOmZk/5X5Bu42lBq9j
         wh6tkAyoyEeiMjA9sPiAo81HdSylJfeMU8izHjcFl4WMw+lsu6DHgBqra3XgfH7m8obn
         +We0/p0ZPhlPTvYIisOGRycJRszcy9R1erxR2o9lim+qy1QHJXtVBHEaB4We/revVSjr
         MpxtFZcgaw/S3TbKy7U9aykntT6ig2sDujM/j5/cJrMjOFA7QTitNXvrDVOXfT2hzTKb
         xf3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.6 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lrSLQluwqMG7c1ABFoODCztJzTXpIYLB/QNOGjCmahs=;
        b=evL63EnKHM14Uatwec6vETrxpwwqd8UVh7KACvv7dK3byppASY1YjnK1oGJKG5zOsH
         6EX9BkxP3z0oEAeGuzT4dqgZvNFlUy47jGqEkSMaBCygAXwG0rEiNpiim4ef9vsS2LtK
         v1OujoTi8ErIy74owUBKw9RjyxZudOlaQI02/OMfsF1uymub3XKXSlcmNvICp2DROMJK
         wxQ+/zLDlJi5+Al/vEdBeQf6Qu4I0mX6hGFxQBB8N4CGTzIx4GUEyHXj2FIP77QMVPK5
         /zSLX9piaHle4iQnGZP/1K0t2w/JR4/Pk6wTRrfCb+oXtJO2b+wNgQRerrlofjNtzM2k
         KE7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lrSLQluwqMG7c1ABFoODCztJzTXpIYLB/QNOGjCmahs=;
        b=KLh4hORkkVDIcRhxLB8wN8lzYBHsFDssPbKgmii3ML0Gkjj9QPVkx2uUxF1x3yeu3m
         ABotDxHKB02bwVQHgYoITBr+/UHqnKFS4IdXO0nQVnp4l2sy7uS+LkzukwJoBExKth4M
         XGYbdrVERag22hukDiTTCjk2KzdmQAheoRZqTlI/PTxlKKsMKE7wnHDlY0FcA7REv1EU
         e5XeHC7BDTb5zHAABBpe8Qr2WQIskCVq3XDDxlvrDpojfLqsR5YbNJRV5rmdtAHBY18G
         smB+I7Zi7bCqLd88ENg8eHUTMSlQVDp9LROgNBteWSfWdWcD+ew179YGB/z01/El3BI9
         ph+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303g94GPgW9UGGzl2QLNRbLSSJeSgEP9hLqO/KEj6zWZVC+qNkb
	1B9z4GC35zxKGH3vyyss1kY=
X-Google-Smtp-Source: ABdhPJyokym2lrKBATcl118VN+y8yTjWTP+W6ES+WOFbvIP6cYXxziu+APGioFuvZRv2jlRYlkt9Qw==
X-Received: by 2002:a05:622a:1a22:b0:2e0:68f9:e5fd with SMTP id f34-20020a05622a1a2200b002e068f9e5fdmr919903qtb.24.1646619850847;
        Sun, 06 Mar 2022 18:24:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ef48:0:b0:49b:4a64:98b6 with SMTP id d69-20020ae9ef48000000b0049b4a6498b6ls5832203qkg.4.gmail;
 Sun, 06 Mar 2022 18:24:10 -0800 (PST)
X-Received: by 2002:a05:620a:e1c:b0:47d:87eb:18b2 with SMTP id y28-20020a05620a0e1c00b0047d87eb18b2mr5542961qkm.527.1646619850436;
        Sun, 06 Mar 2022 18:24:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646619850; cv=none;
        d=google.com; s=arc-20160816;
        b=CDtPC1WyuMsB8i3CJmOdqganFoZ4zeLWdlifMbXjBB2g+duCYXr4JbobzYHy8gyCT1
         T7fSPlXd+EwjCNpjrlmF5a7wZwneyUD3wGBBCy3OkjfDnPpK6Zg5MHd+Rkp7y2F8o3PY
         AX4P0E/qa67DsbjLnONAmTRswGJQ3b3z01/TyCktwxnajyp81PN5gzwn84PBgyNsxy8Z
         HGQwzifUXQj+qcWKnm7LtOVfZdHys8ohE0LhZ2dS5Ob2/nQ6GN9hdNWgkw3P4N3IGq/Z
         UPB5N8qjnyClpjnCwUrR1odOtqn/A4K8T7Yu5teHG1zMutFJcO7MIx/OEhW9nlrVq6Vz
         sOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=o2jRwdLQir6VJScraOsG8DZp+LXjqQZrl9iXp50ktdE=;
        b=cV2/1iSgHLSpdJvU0yJ1O9Sbdt2Pqd2YqMhcDO3IH/xUSjxZ39Ez1fjic7w57AE99h
         ySlotncx0JErLdQtRWyxvm3WNWoyGoDf77k5M26lSwNDDw7RuxsBAs/fKPOLAHA4W0+5
         c6l9ztQWv5TNX0hqmMRiihWgQs4CHA/bxONUfAdQ81aRN/TVN8ZFyTpWrzfHUQwRKXAK
         G8qfH2HyKKqkCO+gmYqlhTdouCVa/WBOyc7GCx49a2IzthL1aLgh7wk3n6cceZTEKGYJ
         H241iZXOpT4HdfFLOdL38kScHHcqS1F3xTJUVu0cTt4oVD3TjwZmVzczgnrG7Kd9Rv4C
         IotQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.6 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out199-6.us.a.mail.aliyun.com (out199-6.us.a.mail.aliyun.com. [47.90.199.6])
        by gmr-mx.google.com with ESMTPS id m17-20020a05622a119100b002dcec4472c3si820225qtk.5.2022.03.06.18.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Mar 2022 18:24:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.6 as permitted sender) client-ip=47.90.199.6;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R481e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04357;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6O3uDQ_1646619831;
Received: from 30.97.48.243(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6O3uDQ_1646619831)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 07 Mar 2022 10:23:52 +0800
Message-ID: <fab45904-585b-0c59-a426-9ebecbd9d26f@linux.alibaba.com>
Date: Mon, 7 Mar 2022 10:23:51 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.6.1
Subject: Re: [PATCH v2 2/2] kfence: Alloc kfence_pool after system startup
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
 <20220305144858.17040-3-dtcccc@linux.alibaba.com>
 <CANpmjNM+47dfjLyyuQwUWZyJgsr1Uxd72VPe9Vva3Qr2oiXRHA@mail.gmail.com>
From: Tianchen Ding <dtcccc@linux.alibaba.com>
In-Reply-To: <CANpmjNM+47dfjLyyuQwUWZyJgsr1Uxd72VPe9Vva3Qr2oiXRHA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.6 as
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

On 2022/3/7 07:52, Marco Elver wrote:
> On Sat, 5 Mar 2022 at 15:49, Tianchen Ding <dtcccc@linux.alibaba.com> wro=
te:
> [...]
>> +static int kfence_init_late(void)
>> +{
>> +       const unsigned long nr_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
>> +       struct page *pages;
>> +
>> +       pages =3D alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_=
node, NULL);
>=20
>> mm/kfence/core.c:836:17: error: implicit declaration of function =E2=80=
=98alloc_contig_pages=E2=80=99 [-Werror=3Dimplicit-function-declaration]
>=20
> This doesn't build without CMA. See ifdef CONFIG_CONTIG_ALLOC in
> gfp.h, which declares alloc_contig_pages.
>=20
> Will alloc_pages() work as you expect? If so, perhaps only use
> alloc_contig_pages() #ifdef CONFIG_CONTIG_ALLOC.
>=20

alloc_pages() will be fine. We could free "tail" pages after inited.
Will send v3 soon.

> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fab45904-585b-0c59-a426-9ebecbd9d26f%40linux.alibaba.com.
