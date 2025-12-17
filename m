Return-Path: <kasan-dev+bncBAABBZ7JQ7FAMGQEQIYPYDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id AA986CC58E8
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 01:10:16 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4ed79dd4a47sf117981311cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 16:10:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765930215; cv=pass;
        d=google.com; s=arc-20240605;
        b=ccv6cFJ3v3Uq2E6zi4oPyo8hULsH99oC4E8qcJT4XVRPaObGXfIxt5Q+2oX2uTAM+p
         1+wCQQ54xagT7iDSg/G58ag315Fe9Cp1mSJTIAh/SPZw+X7nrrl81Je4lZ4YIhgv3snh
         NjDH3LxQ7ioSxmZ4Y80r6idLpi3Y/st3vnhGW7MyqV/uvxMzVM1hvM1I4l624gg4sGy7
         yqPVs4u5WYtPp2GXkuluHThmJFuzAyFmXLSezBrw/mespFxQum9oWP+VOxHz1Fad60pY
         sQqTjDkxkvPtTDvB+iH2vRau5sfrPiifK4L3Q5W1tmZiq1m8CIzya3kc5ZSpA2Tynm8m
         noxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=A700hYQ7INHs55szyC4yVa2LHuZzqSIHO+4qxG3b0b8=;
        fh=nyYrOKyzIS9v7aWf4+36ZToDajSHHkPNtkv868MqgTg=;
        b=QTn2SqTzGqqjcN804OLCqN2OB938wzxE5WrVjiak0C+3VB4XIqg7hD9Oh7YGcJKgOV
         JehGlx98/AhEC7D1c+SYpRuUoq4CWAqbkMODUVjHeRi2P2VmFh1q8qxBLwgOunsxF4b8
         KL6HpyUPrdNVALQ3PiunkR/+1MSc9ZZsxahool1+XMSdB30ptcqkDrciy2Ht6k6O7d0d
         ikaCOBl+PZrnafb/MyQfkD15uZfocYir8JMch3Sg5gQjAXHQbKf2Nf3AsMtghl0JiQAT
         vABz2+t3lnhldMkkakfxzXJi8UWbwpDvx6BmTNkTzueVcOe7bU47b673Y4fNJZaED8CI
         4eXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZirnAmXZ;
       spf=pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765930215; x=1766535015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A700hYQ7INHs55szyC4yVa2LHuZzqSIHO+4qxG3b0b8=;
        b=M1or3iOqnn/GvPDLYegAcTdHmZ7bJM4yj0X/nJB8L7Rk2qtrpuVaR3MFsuM0Iy2a5C
         QgwBayBWgoajU/IOVCYDr2gksSr9EDDDraWavTDJZHJbv2qpntGSwj6jB1scBQ1PfvsS
         X7e3jMiAbW93unAaSbjz66t3APPZMLLBqAa5RRsrpCZZSQ6kgwOcXxrHiV3WGvVP3Dc4
         R8Zyj0EhUHuj2zK8zxFeAmzJ6i6+DaABPm50NfOAH2GFxeuCmCbeuXLVScQrXTfckS/N
         +kpJ0F4M24byPSO7RfT08sA74ZMeMQHXENI9O3GGNiw5y8EL20q+IgtJauvoE3BkqTC/
         K+Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765930215; x=1766535015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A700hYQ7INHs55szyC4yVa2LHuZzqSIHO+4qxG3b0b8=;
        b=ZqL6B9EE2ARAw35wKU7zmy2cWmJbC1HoNqrUwsIPrELjbxUvzTV5B3pVNpzwFUvoeE
         zTa3zdmpb+yDeI4XhazUXw5wemGaf0uS7AkPRbF5ql+ppmws754Gx7aw2jOki8DQfccg
         JhlG3bRmTLOOvX594lBjDe3nULsgXJQ4lAa3tIhD7tM09ngEcBZ1jHwZOTLsYCDS8dw5
         /vfswwjfiyHEva1VvP7EKin5gWsUUfBiNuHi2TNdd5hFGIbxSD0t/I7I68rDnAsctOU7
         cb0tVMHX6Px6zboFMN1tdoii4YFjf2BSwux5OwAZbNTKydxXDlG8x1KBYQJTy6qT6k6I
         Y6sQ==
X-Forwarded-Encrypted: i=2; AJvYcCWjfikNpGTxydCO2P9VMooTTDlLMmsCXtSQmyEhRXRG4jdos24ou6xhbauBniKi0bnbambnsw==@lfdr.de
X-Gm-Message-State: AOJu0YzYIejT+GPugRYPchK2r4n6feJzMRx7arsXKrkzPH/UmpXNwG2z
	r+FJrYWOSgBG1ByO25MeViry9VbQoLWT7citWY8p3m0f5UpROCuveAla
X-Google-Smtp-Source: AGHT+IHJSl2dRjK6lESvr1fHk7Uevg1rP+IKmIKqBdznZNXGCy5uIVlIgPmsq3z+tCivstfG70e+qw==
X-Received: by 2002:a05:622a:1f8e:b0:4ee:d9a:8877 with SMTP id d75a77b69052e-4f1d064cb2dmr219031591cf.72.1765930215192;
        Tue, 16 Dec 2025 16:10:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbNt5conJIw3w2n0KrNRXNOlQcyDtjAOBgzsXqdejzriQ=="
Received: by 2002:ac8:5905:0:b0:4ed:7e5c:f41a with SMTP id d75a77b69052e-4f1ced9d068ls89929911cf.2.-pod-prod-03-us;
 Tue, 16 Dec 2025 16:10:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWPCYEx+XakxQoMV3zlErIBEPoEOGlzKw0DrV+8GZfws2egU5h2U/lmtDD8lVIycThIygrJjnbKWJE=@googlegroups.com
X-Received: by 2002:a05:622a:1a9a:b0:4f0:153a:65ec with SMTP id d75a77b69052e-4f1d05e2638mr235586931cf.40.1765930214576;
        Tue, 16 Dec 2025 16:10:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765930214; cv=none;
        d=google.com; s=arc-20240605;
        b=Am4Xdjh74xhXzxJddfz6I4FDSLNTnJMARHTZS+xRGfaA694YCBcPhO7oc4jROUPO3/
         hej81QMzKyn8ZpW3kCHYwGnghQYMWKGNZ3+lF5PLVbAEg7qdaBClmy34PGYwE56lyXo4
         sTDpcRbm2omQdoZUW9ssnRsrDV00IMXzwy3fxoCcEc0zTzVSxaIySpAh2HNEJmq7JqG7
         SDqx2qGpzT0Ssetb7SXF+j67iNO+VhgakZjx/dyfa/nXSFHWwPT/dKOxS+kC/bV00A3C
         SK+q7QXdSrkDFqqbMQ4mMRYIWo0BbNMGsy4uB2AormNJ6PNWXPaQmYoQ8IwEX6G3k+BZ
         2Rkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ps/+fIU65nqR7scg+9ZWzy1STeyunc9uYsM1QEMPaUI=;
        fh=4SdaRA+b1wOq+ljapQKzLns7PscgKxPfxujoF1EJMIA=;
        b=OJ1sBW//eB8jA94t19x0QALLmaRYDjetzyxk40/Rnp0mcbMnlARMrOx/l7slP1VC6H
         /oFCjTaSgj8iam4MBkfnAS/sWsxGV8zNB+IpfvncYE2rkWDfpgCA+5uVxgrLncEND2QD
         z4HDXrKt9PyHotiH93ynbDICGgK4N5Li4rR5nWHuUtvCRPPWlEDJyZ2GbGu75dxKjiN+
         8/AULSd+hBptJ/oksmCKm0RSi7XyN0RJTlvLG3OvmXvin0JZDRRcNmG4yRpAdJ2BKuYA
         OAGkfNdKagIne9CU9491x/DoII4qOjGAvzn33js/W3j+Q5QSQy1WPx23/Kw1F7yWa59e
         O0vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZirnAmXZ;
       spf=pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f345c61898si2051891cf.5.2025.12.16.16.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 16:10:14 -0800 (PST)
Received-SPF: pass (google.com: domain of david@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id F399241697;
	Wed, 17 Dec 2025 00:10:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E25A3C4CEF1;
	Wed, 17 Dec 2025 00:09:56 +0000 (UTC)
Message-ID: <56acbfc1-51d7-4245-91ea-45bd9e4b2e29@kernel.org>
Date: Wed, 17 Dec 2025 01:09:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 05/14] mm, kfence: Describe @slab parameter in
 __kfence_obj_info()
To: Bagas Sanjaya <bagasdotme@gmail.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
 Linux DRI Development <dri-devel@lists.freedesktop.org>,
 Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
 Linux Media <linux-media@vger.kernel.org>, linaro-mm-sig@lists.linaro.org,
 kasan-dev@googlegroups.com,
 Linux Virtualization <virtualization@lists.linux.dev>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux Network Bridge <bridge@lists.linux.dev>,
 Linux Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>,
 Rodrigo Siqueira <siqueira@igalia.com>,
 Alex Deucher <alexander.deucher@amd.com>,
 =?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>,
 David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 Matthew Brost <matthew.brost@intel.com>, Danilo Krummrich <dakr@kernel.org>,
 Philipp Stanner <phasta@kernel.org>, Alexander Viro
 <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>,
 Jan Kara <jack@suse.cz>, Sumit Semwal <sumit.semwal@linaro.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 Nikolay Aleksandrov <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>,
 "David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
 Simon Horman <horms@kernel.org>, Taimur Hassan <Syed.Hassan@amd.com>,
 Wayne Lin <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>,
 Aurabindo Pillai <aurabindo.pillai@amd.com>,
 Dillon Varone <Dillon.Varone@amd.com>, George Shen <george.shen@amd.com>,
 Aric Cyr <aric.cyr@amd.com>, Cruise Hung <Cruise.Hung@amd.com>,
 Mario Limonciello <mario.limonciello@amd.com>,
 Sunil Khatri <sunil.khatri@amd.com>,
 Dominik Kaszewski <dominik.kaszewski@amd.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Max Kellermann <max.kellermann@ionos.com>,
 "Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts <ryan.roberts@arm.com>,
 Alexey Skidanov <alexey.skidanov@intel.com>, Vlastimil Babka
 <vbabka@suse.cz>, Kent Overstreet <kent.overstreet@linux.dev>,
 Vitaly Wool <vitaly.wool@konsulko.se>, Harry Yoo <harry.yoo@oracle.com>,
 Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>,
 Amir Goldstein <amir73il@gmail.com>, Jeff Layton <jlayton@kernel.org>,
 Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>,
 YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang <Hawking.Zhang@amd.com>,
 Lyude Paul <lyude@redhat.com>, Daniel Almeida
 <daniel.almeida@collabora.com>, Luben Tuikov <luben.tuikov@amd.com>,
 Matthew Auld <matthew.auld@intel.com>,
 Roopa Prabhu <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>,
 Shaomin Deng <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>,
 Jilin Yuan <yuanjilin@cdjrlc.com>,
 Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
 George Anthony Vernon <contact@gvernon.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-6-bagasdotme@gmail.com>
From: "'David Hildenbrand (Red Hat)' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <20251215113903.46555-6-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZirnAmXZ;       spf=pass
 (google.com: domain of david@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=david@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "David Hildenbrand (Red Hat)" <david@kernel.org>
Reply-To: "David Hildenbrand (Red Hat)" <david@kernel.org>
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

On 12/15/25 12:38, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./include/linux/kfence.h:220 function parameter 'slab' not described in '__kfence_obj_info'
> 
> Fix it by describing @slab parameter.
> 
> Fixes: 2dfe63e61cc31e ("mm, kfence: support kmem_dump_obj() for KFENCE objects")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>   include/linux/kfence.h | 1 +
>   1 file changed, 1 insertion(+)
> 
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 0ad1ddbb8b996a..e5822f6e7f2794 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -211,6 +211,7 @@ struct kmem_obj_info;
>    * __kfence_obj_info() - fill kmem_obj_info struct
>    * @kpp: kmem_obj_info to be filled
>    * @object: the object
> + * @slab: the slab
>    *
>    * Return:
>    * * false - not a KFENCE object

Acked-by: David Hildenbrand (Red Hat) <david@kernel.org>

-- 
Cheers

David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/56acbfc1-51d7-4245-91ea-45bd9e4b2e29%40kernel.org.
