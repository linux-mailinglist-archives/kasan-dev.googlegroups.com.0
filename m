Return-Path: <kasan-dev+bncBAABBNN54SQAMGQEABMPCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D38D36C2877
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 04:04:21 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id o42-20020a05600c512a00b003ed26fa6ebdsf5215204wms.7
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 20:04:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679367861; cv=pass;
        d=google.com; s=arc-20160816;
        b=s3CyNJVCVDQOkhnW9cv/QmyaTiESjLlqroVwxXzqAPdxDunf+Bi2vKEa8goje7qvii
         F1AM40qXEq5A+yaMB/QjJvFP+yGJ9wDTnPq/ooVgf10i4dsI6Il1bLBL/9herFxWWNxd
         OhtyU/nIjfqr5ULOWTgSTPS7v/16t7qVqwTS0Yy+fNtHfVueRToLLkloDiHlVRbZiCqF
         7rQ08Jr6YODNq1rShHFQdlEugEKy7mzAidJ8NjOuF5qWy0XzLgASeWcusvWRVuRjAWNi
         QoimrysgkEJs7x+mvJySpo/n0rZJNugsqxmPrOIZXtK6PnhWuhbOnpoYCaR+7HaI2O7p
         9uUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=53N22uOAOaiT+fyXqC03+ZZrTX8IXScYgrLDBbRflfs=;
        b=F1ulhbYUHIpdo5YkS96W2tMsPaGTncyJm/ClCgVjWnOW4aZBYdJmFaLOhG6QBHKXmx
         pK829UPPghz71kqIdkUe1ziT3mMVeKT+v5wj9oW2Frcn3t25iPUgkKHwGR0HyI1Z/8fu
         Wa09tayZEHg1hLhWxqwn32+AySmUlHJXWGxMEjIxzdWT0SFNB31OPjCi9QLx7vIa/7d8
         rEWYMYe0PglfbH3oYUUDsPNjVeD2n9sSuf0L8ZTPwZxJWgfZKoqvI5e39BI8xad+TwF6
         V5gbog/TsmRfZQ6+54VIzxIEzR6/0iWwNi7Ew9shTogcnb61j+MksG+bBkbS95eF7sXM
         fD/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XRudqie4;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::27 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679367861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=53N22uOAOaiT+fyXqC03+ZZrTX8IXScYgrLDBbRflfs=;
        b=LznfImVDPC6DJ4wJIqacs1UWE1PXERkUbkdGJYlJehlaansMyYvLfXECsYeIks1keS
         nVFebvVrpcIcwDwAITHN74eoa3SalCT7hxKpyUnqxR86eDcVL5DPK6HiOcuerRzqENAP
         8/WYtxqNtG+YhqszfGLoTrBgvBCyylo0hTBVGzLK5mcmM1tfUWqhAmBpNVvaygiv1k58
         M+bykx65HcCb+YKvuPux9GmExkI7DFyCtXATnt8tMTLlaSaIiDDEtgoCAUKU+XQI0O1Q
         nU9eQ6PJ+xrR/xwsTnXqTX98PIjAHSVoFkAsQtzAStAJGewLbLttfc+bwUBe8yUL/pXs
         cDww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679367861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=53N22uOAOaiT+fyXqC03+ZZrTX8IXScYgrLDBbRflfs=;
        b=V1ppwQCA5jR/sWVsvGSgzEaqne5ZJJcHogokwc3vAk4dc74BxPai6fesSTaVwhclM8
         laF+bsT5hfupK+Rztx1OMXdN0SY+72DVF6DY8LU5k9AM14UkviJ7jwy0k2sYGUCcoOPf
         A5KS/eQ47nOZMTMp5cIsF/uqoiPgxpR/eJoDVqi2QXPAm4NiVNLkr0C9c8zcla8+JRjG
         guuwj+1HbK0kEoSwwixfJxuPsX95TOB7FhrD+L8R1AqliJQZmGmjP6OWYoFnMxZpER/o
         ebDAAmfiERq+dmEO8vnEBwGF7I67HN0o3kIh7AnmZhlLp8JNePOk0K7ruSWZ4geBO0ei
         tckA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW436JbplOKIPcdZ9S4B2OL8BPXgYobCDBT+2ASy8/Y0AANLjFh
	Kakh/y35LELYSpfDYS/J3cQ=
X-Google-Smtp-Source: AK7set++uz4qDou8gErGkWvLrNyAT3p9An5eE/h19aP3B8kPTE/PcHCd9ghq+3+M5+R8Sm5p7uq04w==
X-Received: by 2002:a5d:424e:0:b0:2ce:ad09:4d47 with SMTP id s14-20020a5d424e000000b002cead094d47mr242394wrr.4.1679367861208;
        Mon, 20 Mar 2023 20:04:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3ce:b0:2d0:a74b:1d65 with SMTP id
 b14-20020a05600003ce00b002d0a74b1d65ls2363247wrg.1.-pod-prod-gmail; Mon, 20
 Mar 2023 20:04:20 -0700 (PDT)
X-Received: by 2002:a5d:40ce:0:b0:2c7:885:7333 with SMTP id b14-20020a5d40ce000000b002c708857333mr1089808wrq.49.1679367860261;
        Mon, 20 Mar 2023 20:04:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679367860; cv=none;
        d=google.com; s=arc-20160816;
        b=wYbAHYrKzWalL65nH6PR5iNwZI8fHcImQ412FXiO7+m7H2jKbIfSIqlfUdJpm40lt0
         B+07ZCaK1GfNsTbxGKtPZdyUzgtDZPo76A9c2FF26qhsP+Va/EnTWIyIwEt+oavf6EWd
         whQg/p5PzBDgp/FJUgEw4vNd5VxpLf6u/NRwcqshWnBFtMN1Rjr/3h7O3b0kwmyZGrMK
         Z1wpxXxu0R5V9LMoPeA0dhnwChSXywJMO4il+IWZE5DSX1nXlbu252Vg6oD1GZ4Xfo/E
         5WWI/4VuQNkugmzE8c3N2RkmAhkOcUS/Gj7T+bTim3eIuaKf8ueBL4mdKtdizUrh1t84
         wk1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=2CzmygZ3+9dcEEzX9d9IRsXgfDbVX0/dCnDP3lROHyI=;
        b=KYIEEAIPjLdLNyEeUJ+Kg61GAgQ69PX035gdjPQC7Q4EWcZDDp6ryNgHA1z0GVaC3o
         /FiJ1QizBOD1aeVYmxHPtGAHO9RNmf4ZDV7/8Ifr+kzejNyeKffa4BbPbShoJLfN3r+r
         vWrOGE0oDoelM8b0kLSsz8AW5ZD7pYrBxUzjP7sVQbYKWN4k+XYiEHd7cq/hO2dZ4xyz
         41fquq0JiXP8IVg+syiW2i4Y+tzmMh1b53nyL8WUoeVToykVesqPAhn+hGJMSQtpAins
         5zThavHGjNm2c8otRYPir3wBWyytXsCShvNFjRvVM8nC9GfI+UCw4/b3Gq47+u/AWxvd
         n+WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XRudqie4;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::27 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-39.mta0.migadu.com (out-39.mta0.migadu.com. [2001:41d0:1004:224b::27])
        by gmr-mx.google.com with ESMTPS id bn30-20020a056000061e00b002ceac242c41si551641wrb.4.2023.03.20.20.04.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Mar 2023 20:04:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::27 as permitted sender) client-ip=2001:41d0:1004:224b::27;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH] mm: kfence: fix PG_slab and memcg_data clearing
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <20230320142954.fd314c5e46c1d18887ccf8cc@linux-foundation.org>
Date: Tue, 21 Mar 2023 11:03:41 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 elver@google.com,
 dvyukov@google.com,
 sjpark@amazon.de,
 jannh@google.com,
 Roman Gushchin <roman.gushchin@linux.dev>,
 kasan-dev@googlegroups.com,
 Linux Memory Management List <linux-mm@kvack.org>,
 linux-kernel@vger.kernel.org
Message-Id: <962CB717-DF8B-490A-86A0-2ACE90209012@linux.dev>
References: <20230320030059.20189-1-songmuchun@bytedance.com>
 <20230320142954.fd314c5e46c1d18887ccf8cc@linux-foundation.org>
To: Andrew Morton <akpm@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XRudqie4;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::27
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



> On Mar 21, 2023, at 05:29, Andrew Morton <akpm@linux-foundation.org> wrote:
> 
> On Mon, 20 Mar 2023 11:00:59 +0800 Muchun Song <songmuchun@bytedance.com> wrote:
> 
>> It does not reset PG_slab and memcg_data when KFENCE fails to initialize
>> kfence pool at runtime. It is reporting a "Bad page state" message when
>> kfence pool is freed to buddy. The checking of whether it is a compound
>> head page seems unnecessary sicne we already guarantee this when allocating
>> kfence pool, removing the check to simplify the code.
>> 
>> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
>> Fixes: 8f0b36497303 ("mm: kfence: fix objcgs vector allocation")
>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> 
> I'm not sure how the -stable maintainers are to handle two Fixes: tags.
> Can we narrow it down to one please?  I assume 8f0b36497303 triggered
> the bad_page() warning?
> 

Actually, 0ce20dd84089 triggered the PG_slab warning and 8f0b36497303
triggered the "page still charged to cgroup" warning. This patch fixes
both warnings. Moreover, 8f0b36497303 fixes 0ce20dd84089 as well. So I think
we can narrow it down to 0ce20dd84089.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/962CB717-DF8B-490A-86A0-2ACE90209012%40linux.dev.
