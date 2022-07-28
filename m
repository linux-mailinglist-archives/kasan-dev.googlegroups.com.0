Return-Path: <kasan-dev+bncBDV2D5O34IDRBH5DQ6LQMGQEBOPK5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A9795835D3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jul 2022 02:00:33 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-10183296342sf205499fac.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jul 2022 17:00:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658966431; cv=pass;
        d=google.com; s=arc-20160816;
        b=d4Z674awx/9NaYp6ZQFZFHj16ZSkBZb9Pwws5p0YnEiV7QjWh9+CBaSrxCXqIdc+V4
         ylmmkRecmZMiheB8k146OfzWJUmomdSmMHWHRuJKMZP2JZCREQk8LxGaqRpf/vrNP4Uu
         R7FGR34ul9Egx9NUCjFewmu29ADxVA954IkWrrRDdM5sAavTvC3Df2sSiuTclE/iIKR5
         ELZ692H0SibHBYr3bYBWs5S7BDrShMKVsiS9qUhzOSrdmQxcCbB6AtAvCWaPjO3BFTMc
         Sj1m4Wr8PxT0kio8Fa3ytPHDrfR5TM0qKOp3TGqh2s/fxynbjZCRCW4uk6EeFO9cNHkg
         mInA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=tidAbURbdX+Da4vX0tUzRNB90rslMzbawUx9s+BYk6M=;
        b=RjlMJeYT8orBCU9M6LtCgybcMwsOXvA7CJdYdx760f/MCkRn8Z7jqWOJTJCJBvVO+T
         to7RneKpFaE8el1Tg8Wo8Y7oJmUvBRbpqR7sDH3Uj12Vp1nlPvs/M/BQ3xIEFqsw7p+t
         m6BO1fcQjpXxmmXM83+q3iy6KHxM37+UYKevnMyoWaDKR0jQLmrzSqsZ3USq6ukdaq2h
         /f9zzKz5D3YWvD69vAEeTPxZIvBg44zH64ABubfbf9oFUZFVorTYBMiKSDnFPtiWdBz3
         rujCrAWktMFYYWYoXybzoX1XJMi8jL2/+jRgeA9+OQm5opE55wj+EceLIJ+9kyripuhs
         tvHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=rMmanMom;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tidAbURbdX+Da4vX0tUzRNB90rslMzbawUx9s+BYk6M=;
        b=oOznwkFvwyKw4yvVNQ1x/qkfPT3yjLoGOm92Vt35WCoACg00spjnxETk7L8ApE18kh
         6eZMFBBI0kUrpb6CUKkzG6Zp+1kiR43uZzJnMWv4jEWWJBcJE3KR/5FnFMiqa3v5fJPL
         D/rFx/SY1M3pgnDC3m6v++R/yCE0ZbBkkg3j9t3jZG3EsIg4Dl+YMMo1tZ0Kr/MrMC0r
         GH5B5kEosyQeldNOcwpgrvYRnDJEnVWw74l+2m7mjuzAW6m8GW1bU7C39RLVZn0vtRUN
         gwXdKRclCqp10IaaY9WRJBbs8OLg2J9JYSsNN/FDqLe1EkfE9MpYUr4JKl1D4aKyJsDS
         00Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tidAbURbdX+Da4vX0tUzRNB90rslMzbawUx9s+BYk6M=;
        b=g3OSMxZExFAEjkItW3Kmx0mtyjnhsxc8g1iMx8QWSqB/OWTnAprGdhFpRnw06X+NMG
         gqSwuQdFBbLHQOEh++3DiQE/QBwaJrh2+bGXVk9BnzZ8W1PZ5CUey8bfoXLfqgqodCFY
         wIpMF//XUSbfR9LXnMvv+fYnlDgp9Ja3hOSCeOrRmowqctX9UTJ+A6n0WAZhQA2/Y5rS
         bS6zr5KPaQ8NN8dJ2L4NxZi6J0h2WbrFgGWf09/pdyrsVtqctaA84L472P7FrCfX7xXe
         NsTXeoxBqTCCbZMWyZVh+OSp+zAGq4t4X1gabiWqpdYf6ck6aQryeWz0vqLIwQf0NubF
         3N9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/cxvKexJNP4ZiblOzOqIKHXYjqUxcG1hCbYWz6irZyTHwXPFVf
	rPdMokdoByFSJfBL8rQrp0Y=
X-Google-Smtp-Source: AGRyM1tO9duJv/RqDoSXdXPB6JnyM1QxVgKp+6ReTI7AUFb+Lj7LJeyd0fT6atSUa5JkFoQI0sKCzQ==
X-Received: by 2002:a54:410d:0:b0:33b:313:4e01 with SMTP id l13-20020a54410d000000b0033b03134e01mr2922659oic.105.1658966431533;
        Wed, 27 Jul 2022 17:00:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2006:b0:339:f68a:e85c with SMTP id
 q6-20020a056808200600b00339f68ae85cls160557oiw.9.-pod-prod-gmail; Wed, 27 Jul
 2022 17:00:31 -0700 (PDT)
X-Received: by 2002:a05:6808:171c:b0:334:9342:63ef with SMTP id bc28-20020a056808171c00b00334934263efmr3115700oib.63.1658966431050;
        Wed, 27 Jul 2022 17:00:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658966431; cv=none;
        d=google.com; s=arc-20160816;
        b=VYqeXsHnFf9hHD+Z1Avd9A1iWryw73cCLjvORMJy+RZczpxBqlNq7WcnvK14hQFVSc
         zLrlsvkORxk/OQ+kTVeZgiZnGwgMuLQUUmDMrCpYbL3iXZ6eJYGzLAgjakUDZbTOFREv
         Dh0rFY5P3t+4MH5f++jwr8wvxPwYGcZ7XXGwvPYOBWV6b7B01qj5snh90pcc/CWaQQrR
         cpTui1u6RO7Iz+cssi9dexZxu2pLSdTGgCzBDDEoicC+JJ5ugLdOs48h3wCaufD8tyRC
         a+F2ozV5lfER0Lf2tCc4j38DUuEa8kJUiz2uUKNZiZ+Z43m6cp8E3nh47RFGYvwhxrZM
         Jv0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=WTkGwzy7iFB5CID6XuwVfQXOKDRWcxWpB3w1MB3wbdc=;
        b=JAFiTRMJn3hTsN2oHZh4WXMal7DrNIUShDX8Lkrup/wCEC+CbDsksocsq0tZE6A7wh
         6ZfaLaR8iO1I1sEjDUvE8+7UmzwrAa8L5ZocisESj2q3tT6BUs7GYNAeBfLJEu9MwEqY
         wV2mkXPdYnblTGZ+4vwC24e0PLRO4D8hM7GGdJOIa1Jhikd6f4x663NPp6R9sjzdBY6G
         O5KYREeAkyeSiPuSK94aPFsCFMVh29b05ndK1W4iPmNLjX91+fFJXxLkMvKrDs9Z39XK
         LEzFKHr3z3ZwTFtnB9euzPDPgP2EDmIvdvP3soB8ECNKzJelxMU7N2inMFzWpiREYasS
         CxWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=rMmanMom;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id u3-20020a056870d58300b0010c1dbaff11si1795429oao.4.2022.07.27.17.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Jul 2022 17:00:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c0:6280:3f0::a6b3]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oGqwo-001hzo-1q; Thu, 28 Jul 2022 00:00:14 +0000
Message-ID: <08da326f-3fe4-3342-bce8-bbd94bf8be97@infradead.org>
Date: Wed, 27 Jul 2022 17:00:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
Subject: Re: [RFC PATCH] mm/kfence: Introduce kernel parameter for selective
 usage of kfence.
Content-Language: en-US
To: Imran Khan <imran.f.khan@oracle.com>, glider@google.com,
 elver@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org,
 rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
 vbabka@suse.cz, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, corbet@lwn.net
Cc: linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20220727234241.1423357-1-imran.f.khan@oracle.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20220727234241.1423357-1-imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=rMmanMom;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

Hi--

On 7/27/22 16:42, Imran Khan wrote:
> diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
> index 98e5cb91faab..d66f555df7ba 100644
> --- a/Documentation/admin-guide/kernel-parameters.txt
> +++ b/Documentation/admin-guide/kernel-parameters.txt
> @@ -5553,6 +5553,11 @@
>  			last alloc / free. For more information see
>  			Documentation/mm/slub.rst.
>  
> +	slub_kfence[=slabs][,slabs]]...]	[MM, SLUB]

I suppose that 'slabs' are by name?
How can the names be found?  via 'slabinfo -l' or 'ls /sys/kernel/slab/' ?


It seems to me that the boot option should be listed as s/slabs/slab/.
I.e., one uses 'comma' to list multiple slabs.
Or is there a way for multiple slabs to be entered without commas?

> +			Specifies the slabs for which kfence debug mechanism
> +			can be used. For more information about kfence see
> +			Documentation/dev-tools/kfence.rst.
> +

thanks.
-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/08da326f-3fe4-3342-bce8-bbd94bf8be97%40infradead.org.
