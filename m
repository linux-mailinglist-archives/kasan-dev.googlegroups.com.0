Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB2GW3CLQMGQEFUD75II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F9D8590F6F
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Aug 2022 12:28:57 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id m12-20020a19520c000000b0048fea6ac49fsf99355lfb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Aug 2022 03:28:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660300136; cv=pass;
        d=google.com; s=arc-20160816;
        b=neR5hLGWh1eBAEN3st9VZ1ktsXYkzLcQNsc24oIkBBJmSwEmEOv0QPW0ws7TDrvU86
         aAaXKzjGKRkwuJDX3LzdrHPXb5Y2rt/X3eFxLak7w+w6H8v+NgPw0dYPKzhuOzeTS09Y
         wapTkVower7YsFs4pgx7UiWrmvvmSPi8lUqfY+ED0TVPxBVBbW5hTkTHhh2v+0K40pdq
         P1h9L7NO8NC63cViHLLi8ua8x+8iluRSglvWBLao/4ssZgDMRG50Y6B6KnPiDlp7qnIC
         ZeGiFhWYDnfzjTTjrg1mqc+GVVsMrjL/ngU+q34aSleV8RhUIRFb1bZpqlbxOIsqPZIJ
         v3zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=dEEZwJrBBM73FvN+I+jePTJb67ley7Mxqul3Nm+OaRU=;
        b=JNFIj54gB2FdJJEf25h0JAcFtePrpNwf1a+54pqfWJuNJn81/93ju2NfcxXPOiKoJT
         q1iPByu1PM4hxw7ZXzZuYm8vb/HhzAsuhjEDjVTnHcgEoQmzHbXXIxVIZZmPUze19b3S
         E6nIeD4iGZxd2eQ+OX/+nkRpOGR5kY/0yYXFtCfLdSGrKCjh3KoBQTaczZr4JSoWnBck
         X2/is4L/h7GYWl2RGhwcSE1b9h5decsNdWRsaXSjackiGt477dIRIhKA94iYY4Se+uS2
         OrwzVSGOCUR/jj3niUULGRDqP8BOhXzl32DKk5naQq8jHewu3TdNS0IlpaPR8ZiJm5k0
         3C5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qQC2SZ2K;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9KLKbLUp;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc;
        bh=dEEZwJrBBM73FvN+I+jePTJb67ley7Mxqul3Nm+OaRU=;
        b=Ah1qD2okVXUWZ1HNuvDeU/kdUWA4JiGSPVDhxStJW5g8zRl4xupWP0grkBwdXVYmaD
         /3vhuDmfgm62dOJJRJeZNX2iJwWKMA2qt8mub5ZNPRAjKoetqHUa275O9L6m3kQYsiKk
         HyHHF0lgdWIDvegccc+zNDJ6eXtCFk5R7lFChlBxOYx9gE26vFqQAKJ9vXta84Zm+8pK
         y03Zvorj/3ATfa0Dw4hz9FbTD4s1HdY0LWfWXs+RQyPOc7YzRUZeKKw9I6kjxBBx1Vx/
         lav99V8ayyuTQRZpTcLL3tD2QH7PheAPNoZ+zOIHbc42k1gwSAh2FenoNBDTwL48MetF
         8Lug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=dEEZwJrBBM73FvN+I+jePTJb67ley7Mxqul3Nm+OaRU=;
        b=SbDolc21TkdDicAtRyXCgboByvjf5Mil9q55JjeLnC0KIKidY9z/wDzG5mZeaKhIRU
         O065a9DWuyYsF9LnIU4gdRFRreF4AREyJaGADbHynOv6xvinDkQEvp4LcQyc1k9aIteU
         toDb5VWOpI5du0DCFOkoxpSrBo+ZUTZu4XIbUqU45h3Suw3rGAxfWn1BajNAcmpe9p8V
         AqT8+yJJN9Oy7ufIgHtjf2BQUwbJnZ/ESRIS9OQtMXT3W1a9imxGquxQhfjWMcK2JoG7
         8/0hGLoSA9PIny4Xz8HUeNnOYfAldTwbJZmbhVxAvSIsF9SpkIbPdp34BuAu6VWAJWta
         qoIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0kJkdFtqvV8bJIbxZToi6byhMYNeNWrFbhmRM1JIJobuCWehgh
	WcEmEsdAw44htPeftiVATe8=
X-Google-Smtp-Source: AA6agR6hlTq/zI/RqUBVw97iDaoUTzsUrByZyOvx4sanyTbi2suu1gWixg6573aHXCnIHGxHVXv6cw==
X-Received: by 2002:a2e:6e13:0:b0:25e:87b1:fda8 with SMTP id j19-20020a2e6e13000000b0025e87b1fda8mr909211ljc.250.1660300136472;
        Fri, 12 Aug 2022 03:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9183:0:b0:25e:46d8:20cf with SMTP id f3-20020a2e9183000000b0025e46d820cfls738529ljg.4.-pod-prod-gmail;
 Fri, 12 Aug 2022 03:28:54 -0700 (PDT)
X-Received: by 2002:a2e:7a03:0:b0:25e:6557:ed9b with SMTP id v3-20020a2e7a03000000b0025e6557ed9bmr939546ljc.491.1660300134751;
        Fri, 12 Aug 2022 03:28:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660300134; cv=none;
        d=google.com; s=arc-20160816;
        b=LNkroUMM9IYWjHtBn9Q63Nx2k7pbxBsIX1GyO2zDwmN8PLMYs1SEtQD3Mzk5GjjH1b
         7Z2G1TO3HpTI28P8zXxId0BBHzAWSw1dVzzoQwt0HUYoMWr0HWxX65yUYZBym41za9h6
         H9h28H4tyQ1qdNSfqH5SNCyxRhGzNmzVF4JAeT/gE/8UFaVAHlmobeyspRn96cFlA5ok
         2DHxedmpuhD1dT8b/p2ClPJd85P6CDzvDu0hHGSuN4F1Flb7NnaAg771p4JEwpGJudhW
         WVLS9c8sSXnOQhVHCjFZTNtLcedB2++1sUGVj4KYno3zmDAdrBRF0WUCvVXGEdMhAy5E
         sQ7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=3nvTqnT7K3LiWJYUMML5+6yBkFhanW5C2y33qNN7G5I=;
        b=IaC0talSIbiafLSlxfjKXhVAeT5wQUrg7uHWLcd76x/qDOlxGHzI1tKVqN7KiP/+Y+
         OrXGE8OSXheBRXIbEetHbd7uydj46Ktco5jQyrC2Tmg8xnMHsYazLOIaaFMz8lKtLmWY
         yiVatd9HefIrhAjPVJuY4Dkh5UIX4KjwkBisZDfqfURjniUvE1Hw3kJlSdzYoqLeKvy3
         etjnIBCGezwmVvT5MgyjRkMq+VEpDf1czvvaG+UsXyXyLSoiUNrE73hpDo6U8phNiXXv
         sGMUomWB1F7c8uJ6sbESqXLTS9UoqK3SUQ1VUb4RufXlqJcQolMOvzG4kJ0nZ5MOseF4
         c2EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qQC2SZ2K;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9KLKbLUp;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id x9-20020a056512078900b0048d076373d4si58336lfr.13.2022.08.12.03.28.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Aug 2022 03:28:54 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 119EF3EDB7;
	Fri, 12 Aug 2022 10:28:54 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id CFE9B13305;
	Fri, 12 Aug 2022 10:28:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id iK31MWUr9mK2WwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 12 Aug 2022 10:28:53 +0000
Message-ID: <c60897e7-fa5d-a1a9-09a6-c80cfe4b5fd5@suse.cz>
Date: Fri, 12 Aug 2022 12:28:53 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.0
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
Content-Language: en-US
To: Imran Khan <imran.f.khan@oracle.com>, glider@google.com,
 elver@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org,
 rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
 roman.gushchin@linux.dev, 42.hyeyoo@gmail.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20220811085938.2506536-1-imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qQC2SZ2K;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=9KLKbLUp;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/11/22 10:59, Imran Khan wrote:
> By default kfence allocation can happen for any slab object, whose size
> is up to PAGE_SIZE, as long as that allocation is the first allocation
> after expiration of kfence sample interval. But in certain debugging
> scenarios we may be interested in debugging corruptions involving
> some specific slub objects like dentry or ext4_* etc. In such cases
> limiting kfence for allocations involving only specific slub objects
> will increase the probablity of catching the issue since kfence pool
> will not be consumed by other slab objects.
> 
> This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
> to disable kfence for specific slabs. Having the interface work in this
> way does not impact current/default behavior of kfence and allows us to
> use kfence for specific slabs (when needed) as well. The decision to
> skip/use kfence is taken depending on whether kmem_cache.flags has
> (newly introduced) SLAB_SKIP_KFENCE flag set or not.
> 
> Signed-off-by: Imran Khan <imran.f.khan@oracle.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

Nit below:

> ---
> 
> Changes since v1:
>  - Remove RFC tag
> 
>  include/linux/slab.h |  6 ++++++
>  mm/kfence/core.c     |  7 +++++++
>  mm/slub.c            | 27 +++++++++++++++++++++++++++
>  3 files changed, 40 insertions(+)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 0fefdf528e0d..947d912fd08c 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -119,6 +119,12 @@
>   */
>  #define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
>  
> +#ifdef CONFIG_KFENCE
> +#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
> +#else
> +#define SLAB_SKIP_KFENCE            0
> +#endif

The whitespace here (spaces) differs from other flags above (tabs).


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c60897e7-fa5d-a1a9-09a6-c80cfe4b5fd5%40suse.cz.
