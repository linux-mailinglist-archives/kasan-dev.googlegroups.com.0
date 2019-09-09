Return-Path: <kasan-dev+bncBC32535MUICBBBXA3DVQKGQE7SSZYFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64EDFAD75F
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2019 12:57:12 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id t10sf7681553plr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2019 03:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568026631; cv=pass;
        d=google.com; s=arc-20160816;
        b=gnMK7RMnY/wmqjGdhbGckwonN1LqyKZm5/Qn3xZTantsBRqZ5+UyT3BS7otHh5CPLZ
         FIX+W1GwBm/W6tg0nxdySkFTecKcqrh6SEHD7YP0tpZyd/2Kn3WCC8h/0B28k0g9uPHl
         Tpn6YgM9PUI84V8zEQBoiG84YNQn839t7BqZ+YxQrvjM3AQ/3gjrbFBu+JfiXlMOF4fE
         CY5hZi0ZXGUY5R7XPyl3czKOoOYtUW+y5eYGhAP2u6FNmX3Exxmc+Gufuoi282blxZX9
         W1qCU3hPoeQbt9TwZlPcZCr3WajGEOS5y3mdDr078ozCGsI1Oeqf9W6fAa6tCaqYiUNR
         FR3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:autocrypt
         :openpgp:from:references:cc:to:subject:sender:dkim-signature;
        bh=HBd5r3/gEFvaCRk6h4Sn+YU9Z5eHHxbL5ssDxSyejmA=;
        b=KqDmVyVhyYK+1imBaB/9qXql+E2WeEcMxPgA6BKI4bl/QJl1YM1s4oN6FaMjccGuLy
         5HcDKZXEODYHdtY6K63upOlQKUwR/R2pf0kJ5uenGWfNdJcJUZEnMG1ryWaHYx9055OX
         vv7KEd/XdWsvi5syqLFfJC6F7KdhIlLFG5oTgiThx8vUqgdRgvV5jdpBSVteutesbPQN
         jDxOeUd4Kgcs4JsRa4M+mRDucWtpZ+Tl8D+itqK5mVjY+SnRELwpRfv6xNHMYV1oazoD
         XZ4bbwoMmrXS7XOfxEDV8p0T7lRh5D163MNH4QiuhjcmmWsacLYmmN2J40R6cYF428nQ
         60nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HBd5r3/gEFvaCRk6h4Sn+YU9Z5eHHxbL5ssDxSyejmA=;
        b=R8+RhUcYXwbr3Ft+Y8ksJQzJnASKLwwtce6Iv+uWN+tEevGeyFCAoN4mTHNRZb/llX
         zI64HKCrPuGWgQnJQTAC/eIKrbtzDqgX3BrqQ9I4Xlf/DRWlEbpbxRAXiEFI9zETcRWD
         uREtU/Qs5LT+qHE7y09ZxWUjhNuGW24UkhwNf0YnQLOINOu9ijexgDLoXu0uFkh/Pi3L
         WEtwz+epjbGpRLnvD8GFSrrv7bl0CjWG12GPLXf1s3MysCB5zEkasy4Dm7Dtnko3qfvQ
         9xyz3+JR+CzytSsvBhkTH2f0R8B5Tu5gvqMmozrq2fGCPwAadZiCWHwzVuximxd3gE+2
         AilQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:organization:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HBd5r3/gEFvaCRk6h4Sn+YU9Z5eHHxbL5ssDxSyejmA=;
        b=Attiq9iC/uCThz2VyTWzWl2sfU5PTpa1zqFj+c0N32E2X/P0cdglfoVsHQovX53Qlk
         1wl78m+tSnq/LA3EdkED1tQ/6ZpY6X0Orh+XeZR6x0vucEwRz17vxqWQCt3Rxk2vUctY
         tc2xHeh0iQQFzuhZamDKFhXxjYIkYzMOsPAVwsDbWhVD88yJRff7FviM924g4ho3IO69
         RN37L/qXb6qvy6PneckL26X43sDmfOXaahukfL9vrWV3POYOzYDyWvmhopg/Wvzkj+DR
         +JVB/i3sSqUob7V8ABs6xam3kE2xBhKf8JSbi1zCIx7JCaOxFKgtDOzaGyty+su3Rrmd
         PPLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVjclbjoMiuy+p4ymRs1cOaOH0Z87dXb/yHF5j5oXQYrpA59YzW
	2hbaet7b8pfjbrNVzlC4N40=
X-Google-Smtp-Source: APXvYqwX011AvIDcUFQzRi8CGCZlkNIoDogRSQq8gZgnk8qiD8IzV1tPYLLw3h1hy0pGfBVQuoFukA==
X-Received: by 2002:a62:3145:: with SMTP id x66mr27191423pfx.186.1568026630925;
        Mon, 09 Sep 2019 03:57:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8687:: with SMTP id x129ls3377889pfd.12.gmail; Mon, 09
 Sep 2019 03:57:10 -0700 (PDT)
X-Received: by 2002:a63:8ac4:: with SMTP id y187mr21610904pgd.412.1568026630558;
        Mon, 09 Sep 2019 03:57:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568026630; cv=none;
        d=google.com; s=arc-20160816;
        b=TMYG/wZ8LCFbWVq85VDUINZMB2fekfoLq8J25jmk3MaSyx4zxVgOaoNjUqUOKgAaVQ
         G5TnrRq+l/ZdF/s96cQnV90REqJ85+XupdSV6nAPq96pfkyE8h5V9ZhuwTrwpxNXsWrq
         hLgtKG6FzIMA7/N0B4EjE+FpnSXctsLp+j85RrKuMoqzDjknPQYhESEqpW9fakWOmyQ9
         kM3qhd3Ww0AFwQ9bxvSFRQkhgk57c+cfW1IrkDNfiMvGA/gfExrd4nHFPZK/AezVl/Zq
         czfCn4GnSicox8goyONQ+YkrML7pT2t4yMM3WVdXlSurfq4zUrF0GOVw3CFICm2hWA+m
         FwJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:autocrypt:openpgp:from
         :references:cc:to:subject;
        bh=6+6Ew7PVhvM0Z3ngcDo1uBXTlaaZipiGO7E+i9H4uek=;
        b=KQBr8ck3biWMQ9ii2jr5RKawbrjwOEAby/c/GGgbpOk1G0zIC0YwAovN4AEPGMnmad
         cO6pmlkQFxkZbEn1df2RnwmPrkgDia4Vzzps2PNAqZHQkrNyTtASEpxkIkcB4B6iKB97
         G5kf3SZ7KpRnQ0VP2nCXr4uavXzJJYW83hciJhQdMpKrzGi4nUttRsszMgv1KUMNd2ku
         uAVXeJb/2OOjOhmwuJA9rTA6k2PdOVihiEJ7urDWI2uGoiuwmmhdvCD2tirApi55rFNt
         EnbwVG4U8EhdWfJrYOhIwvKcq//x0lFTrgFOXXbSthE1brDcmvscw3z7sbd7hqYynoAk
         uhUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from mx1.redhat.com (mx1.redhat.com. [209.132.183.28])
        by gmr-mx.google.com with ESMTPS id g12si639224plm.2.2019.09.09.03.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Sep 2019 03:57:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 209.132.183.28 as permitted sender) client-ip=209.132.183.28;
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mx1.redhat.com (Postfix) with ESMTPS id 08ACB6F686;
	Mon,  9 Sep 2019 10:57:08 +0000 (UTC)
Received: from [10.36.116.173] (ovpn-116-173.ams2.redhat.com [10.36.116.173])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 25B1F5D6B7;
	Mon,  9 Sep 2019 10:57:03 +0000 (UTC)
Subject: Re: [PATCH v2 1/2] mm/page_ext: support to record the last stack of
 page
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Thomas Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>,
 Qian Cai <cai@lca.pw>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
From: David Hildenbrand <david@redhat.com>
Openpgp: preference=signencrypt
Autocrypt: addr=david@redhat.com; prefer-encrypt=mutual; keydata=
 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
 SE+xAvmumFBY
Organization: Red Hat GmbH
Message-ID: <36b5a8e0-2783-4c0e-4fc7-78ea652ba475@redhat.com>
Date: Mon, 9 Sep 2019 12:57:03 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Greylist: Sender IP whitelisted, not delayed by milter-greylist-4.5.16 (mx1.redhat.com [10.5.110.27]); Mon, 09 Sep 2019 10:57:08 +0000 (UTC)
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david@redhat.com designates 209.132.183.28 as
 permitted sender) smtp.mailfrom=david@redhat.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=redhat.com
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

On 09.09.19 10:53, Walter Wu wrote:
> KASAN will record last stack of page in order to help programmer
> to see memory corruption caused by page.
> 
> What is difference between page_owner and our patch?
> page_owner records alloc stack of page, but our patch is to record
> last stack(it may be alloc or free stack of page).
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>  mm/page_ext.c | 3 +++
>  1 file changed, 3 insertions(+)
> 
> diff --git a/mm/page_ext.c b/mm/page_ext.c
> index 5f5769c7db3b..7ca33dcd9ffa 100644
> --- a/mm/page_ext.c
> +++ b/mm/page_ext.c
> @@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
>  #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
>  	&page_idle_ops,
>  #endif
> +#ifdef CONFIG_KASAN
> +	&page_stack_ops,
> +#endif
>  };
>  
>  static unsigned long total_usage;
> 

Are you sure this patch compiles?

t460s: ~/git/linux virtio-mem $ git grep page_stack_ops
t460s: ~/git/linux virtio-mem $

-- 

Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36b5a8e0-2783-4c0e-4fc7-78ea652ba475%40redhat.com.
