Return-Path: <kasan-dev+bncBCS5BWNH3ENRBHMEYORAMGQEDKZ62QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F4956F3E9F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 09:56:14 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4f00d41e0a7sf13697224e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 00:56:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683014174; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mqp0Xp9nmErak1sYwS+VV6MUYa3as+F2g6lb472y/ZIukclS4H7Qro9FRzAZXesYgH
         pFzA/J+UHyJCoSQ8ICTZiFaRqzLUdJ96FDtArF/tmx5oLLkfE4p/1luAciyoKYS7iHD/
         DSUQRoK2Y5x46bD20n8FphKU/Pu2bTsV0trN7aeUeacMmtGK3IjlLuQ3P1cGZu9qClD5
         Es3pLqemMOz6ReUYzlL9ngdI+s3BVHWKq2c7SFLmcVkZjcNhrnFipY9jeeKLGw4xLrWc
         oOnInQ/W63zyjA64B4MyP0Sf75SIvkBMWWWJRbeTs1R4BOL9+V/PjqbWQHZmc6UqAZhz
         s5YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:organization:in-reply-to
         :subject:cc:to:from:sender:dkim-signature;
        bh=RsOpnUtNXx24Z5jeakLynsSxKL8OnM48780bCEKGf4g=;
        b=1Kg4g5TlHF6rMzrIxOP/ngzzFYTMIPqzIDKt6oecNhAbRg095pGblCEUN3f0F5mKxt
         7JQNhXf9wGMKcNE26WLjbdsN9HbNvpSaN4QO8xf99px0IQUhx+hcXyMCtM/PXf2RNwM7
         xXtvTdixLOzSHvrt+QNcSd/tGaObeyn0Q0c3yotvg9LW8cznlSsJbvHC78tEYGIKYxjv
         zrgxtkUkoyKMUuzfjcX2kWKF055Ch3/FKDWFeL1SPYhWS9e4hEqy09f/kABtC227fJ2X
         iuD/wAZJc4TXUpJWn0U3DhQtV+B8CuQUqwnKRKegtP5gkCnAHSjCFPJ69G2u/sZGqyX0
         iHEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=N0kYZVsk;
       spf=pass (google.com: domain of jani.nikula@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683014174; x=1685606174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:organization:in-reply-to:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RsOpnUtNXx24Z5jeakLynsSxKL8OnM48780bCEKGf4g=;
        b=TcTIAt/4ZPckdWkGCfFZK1xnotCerldfOoxXOND5Rh1bIsIn2+HZ5dbvIlT9u41Kdp
         BIPR5Tx/ILUnC8wZkSrDpOFVbe3nq4wXgxjIOBgYF+gZXzJgJUXyalrX72uBYsz3O1nr
         ToXNX30OvKa64i1x+aYpWZ3Kn+R5aodCFUMJp5C0Sm1B16AZebwvIczp48dpLcChDbrc
         B9RdPZHz8qg5Qa1R1KK6UTn1kHsHJA8iM5eTBJfCrVjfArISoKZiI0HVdK5VM884VqeX
         N80QK2U1XWS5LlAzE3HfFPvyJNJXU7ZHsE5bMc09Q8MmeE93h/YyxZYeCFe6duo/BRPo
         55yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683014174; x=1685606174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :organization:in-reply-to:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RsOpnUtNXx24Z5jeakLynsSxKL8OnM48780bCEKGf4g=;
        b=Imdl+4XtrXSLQj/vPe3lE+hQYAqaZKc7CCir1RZoCxZ7SStlmkJnPxCk6Sz0/1px0X
         M9A7waNEg+gJK6KIFLDXVnfhwbVE6S2li7PSR171qTCZvmvOr2VC8lyqUbEU/81MfEVs
         L2A30ZR/5aJZEAtO84O7DWzRc/CuOMqMtyoy6TcWz2OAg7TBRj665e9JtPzlVRZJBkhw
         pS1X+rYms1lMsfOs4ZO7jX9Jet+5hnmwfBeB6+NyXlJtxdDC5Mnye6+nB7M+ZMJF4+Vb
         It5+39DMwRUyGBs6qvT11HD69JBS5mtX5T8HVyKq+PRN25BDmk13be/LgtH7F63D5ptS
         3GRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyhjZBbEkbgwS8d9/ndw0gqBNsGq0LLBrCRjk0iiWRATUjOuQZ0
	p0GBw/gs5oXO1zelVO51qtY=
X-Google-Smtp-Source: ACHHUZ55J1Fxyy1yVKN7UPe9SCEo7HJ/hLi1ccbtMCAfG7kYsPi9sJeujZGgIV5Wlziwo+oJTkHXpg==
X-Received: by 2002:a2e:b60b:0:b0:2a7:8544:1e79 with SMTP id r11-20020a2eb60b000000b002a785441e79mr3664660ljn.3.1683014173713;
        Tue, 02 May 2023 00:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls260840lfb.0.-pod-prod-gmail; Tue, 02
 May 2023 00:56:12 -0700 (PDT)
X-Received: by 2002:a19:f815:0:b0:4ed:c3a1:752a with SMTP id a21-20020a19f815000000b004edc3a1752amr3947274lff.45.1683014172081;
        Tue, 02 May 2023 00:56:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683014172; cv=none;
        d=google.com; s=arc-20160816;
        b=PLJ+8xP3eZ1pgNoqxrhD154oFmrLJsDWKa2gBmtjyEP9dg6f3C9nn1L6C0j44kGf1i
         0VlAITsRv3DV3ZsHhPCN48ltCG2qLp+9xK+0Ukhsx5DlBE+ey9rLJe6zmPTarPeUHZkP
         LV3Ro69jtO94krvSPiP0y+i52Q+b0xj0eebCeMj3Xk1SA09FyYAZ4D1wGL+sG4AM5ZWL
         /XWtWKgdcLZQVCRP9dhMlDi/ql4crLuR5KbeKGKjzuxo55Kw/Ngj3rANHiCY87Hbll15
         Rfxj+yFpA2ECCP1J5YIefVEaPWXzCtNVRN/WBD4sGGxrf+bbL1+RZfA+yOq6mCpd86u/
         O8ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :organization:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=apeaqOGW+aTexMxtULNJKmBXy2F9o3DqQn1p3+VDVEs=;
        b=sx70ZE4QM87KIefB3JmOUIsCvQgmjNTun9wbN7Wf1eA+0UH47brRZPIYtOz5ACSl69
         Wf6vAY27VN1+eQBOeOC8IQkQ/aNF/z+VYDg+tx7Vrgh6OW86W/loSrHoUlYpipKjjgLd
         rYs2FX1pIWc6ZY0VIl32wixub2TNEKaWT5SMg5hblgG5nomaP9wu/jG6RYNUZGA0GIC2
         jESX3zKadRE6ajJmUzmzg8CFF8yIck+p/zZVmOo6L8tbtGdbo2akQcEsdIAyCO4GcY2/
         ggiLs976+Q+/DWXdIkyA1C8yYn1qgSypepLrnvQxRniisStC2823htMQEFxHgqDnXYjM
         RJEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=N0kYZVsk;
       spf=pass (google.com: domain of jani.nikula@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id h6-20020a056512220600b004e9d34ac318si1884206lfu.5.2023.05.02.00.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 May 2023 00:56:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jani.nikula@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10697"; a="332689681"
X-IronPort-AV: E=Sophos;i="5.99,243,1677571200"; 
   d="scan'208";a="332689681"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 May 2023 00:56:09 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10697"; a="807752489"
X-IronPort-AV: E=Sophos;i="5.99,243,1677571200"; 
   d="scan'208";a="807752489"
Received: from xinpan-mobl1.ger.corp.intel.com (HELO localhost) ([10.252.35.163])
  by fmsmga002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 May 2023 00:55:50 -0700
From: Jani Nikula <jani.nikula@linux.intel.com>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Andy Shevchenko
 <andy@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, Benjamin
 Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras
 <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang
 <jasowang@redhat.com>, Noralf =?utf-8?Q?Tr=C3=B8nnes?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
In-Reply-To: <20230501165450.15352-2-surenb@google.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
Date: Tue, 02 May 2023 10:55:47 +0300
Message-ID: <877ctr2mm4.fsf@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jani.nikula@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=N0kYZVsk;       spf=pass
 (google.com: domain of jani.nikula@intel.com designates 134.134.136.126 as
 permitted sender) smtp.mailfrom=jani.nikula@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Mon, 01 May 2023, Suren Baghdasaryan <surenb@google.com> wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> Previously, string_get_size() outputted a space between the number and
> the units, i.e.
>   9.88 MiB
>
> This changes it to
>   9.88MiB
>
> which allows it to be parsed correctly by the 'sort -h' command.

The former is easier for humans to parse, and that should be
preferred. 'sort -h' is supposed to compare "human readable numbers", so
arguably sort does not do its job here.

BR,
Jani.

>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Cc: Andy Shevchenko <andy@kernel.org>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
> Cc: Paul Mackerras <paulus@samba.org>
> Cc: "Michael S. Tsirkin" <mst@redhat.com>
> Cc: Jason Wang <jasowang@redhat.com>
> Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
> Cc: Jens Axboe <axboe@kernel.dk>
> ---
>  lib/string_helpers.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/lib/string_helpers.c b/lib/string_helpers.c
> index 230020a2e076..593b29fece32 100644
> --- a/lib/string_helpers.c
> +++ b/lib/string_helpers.c
> @@ -126,8 +126,7 @@ void string_get_size(u64 size, u64 blk_size, const en=
um string_size_units units,
>  	else
>  		unit =3D units_str[units][i];
> =20
> -	snprintf(buf, len, "%u%s %s", (u32)size,
> -		 tmp, unit);
> +	snprintf(buf, len, "%u%s%s", (u32)size, tmp, unit);
>  }
>  EXPORT_SYMBOL(string_get_size);

--=20
Jani Nikula, Intel Open Source Graphics Center

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/877ctr2mm4.fsf%40intel.com.
